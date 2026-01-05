//! Poseidon2 permutation non-primitive operation (one Poseidon2 call per row).
//!
//! This module contains all Poseidon2 permutation related code:
//! - Builder API (`Poseidon2PermCall`, `Poseidon2PermOps`)
//! - Executor (`Poseidon2PermExecutor`)
//! - Execution state (`Poseidon2ExecutionState`, `Poseidon2PermRowRecord`)
//! - Private data (`Poseidon2PermPrivateData`)
//! - Trace generation types (`Poseidon2Params`, `Poseidon2CircuitRow`, `Poseidon2Trace`)
//!
//! This operation is designed to support both standard hashing and specific logic required for
//! Merkle path verification within a circuit. Its features include:
//!
//! - **Hashing**: Performs a standard Poseidon2 permutation.
//! - **Chaining**: Can start a new hash computation or continue from the output of the previous row
//!   (controlled by `new_start`).
//! - **Merkle Path Verification**: When `merkle_path` is enabled, it supports logic for verifying
//!   a path up a Merkle tree. This involves conditionally arranging inputs (sibling vs. computed hash)
//!   based on a direction bit (`mmcs_bit`).
//! - **Index Accumulation**: Supports accumulating path indices (`mmcs_index_sum`) to verify the
//!   leaf's position in the tree.
//!
//! Only supports extension degree D=4 for now.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::any::Any;
use core::fmt::Debug;

use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, PrimeField};
use strum::EnumCount;

use crate::CircuitError;
use crate::builder::{CircuitBuilder, NonPrimitiveOpParams};
use crate::circuit::{Circuit, CircuitField};
use crate::op::{
    ExecutionContext, NonPrimitiveExecutor, NonPrimitiveOpConfig, NonPrimitiveOpPrivateData,
    NonPrimitiveOpType, OpExecutionState, PrimitiveOpType,
};
use crate::tables::NonPrimitiveTrace;
use crate::types::{ExprId, NonPrimitiveOpId, WitnessId};

// ============================================================================
// Configuration
// ============================================================================

/// Type alias for the Poseidon2 permutation execution closure.
///
/// The closure takes 4 extension field limbs and returns 4 output limbs.
pub type Poseidon2PermExec<F> = Arc<dyn Fn(&[F; 4]) -> [F; 4] + Send + Sync>;

/// Configuration for Poseidon2 permutation operations.
///
/// Contains an execution closure that computes the Poseidon2 permutation.
/// The closure takes 4 extension field limbs and returns 4 output limbs.
pub struct Poseidon2PermConfig<F> {
    /// Execution closure: converts [F;4] extension limbs to [Base;16],
    /// runs the permutation, and converts back to [F;4].
    pub exec: Poseidon2PermExec<F>,
}

impl<F> Clone for Poseidon2PermConfig<F> {
    fn clone(&self) -> Self {
        Self {
            exec: Arc::clone(&self.exec),
        }
    }
}

impl<F> Debug for Poseidon2PermConfig<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Poseidon2PermConfig")
            .field("exec", &"<closure>")
            .finish()
    }
}

// ============================================================================
// Private Data
// ============================================================================

/// Private data for Poseidon2 permutation.
/// Only used for Merkle mode operations, contains exactly 2 extension field limbs (the sibling).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Poseidon2PermPrivateData<F> {
    pub sibling: [F; 2],
}

// ============================================================================
// Execution State
// ============================================================================

/// Execution state for Poseidon2 permutation operations.
///
/// Stores:
/// - Chaining state (output of last permutation for input to next)
/// - Circuit rows captured during execution (with extension field values)
///
/// Note: During execution, `Poseidon2CircuitRow<F>::input_values` contains 4 extension
/// field limbs. The trace generator converts these to 16 base field elements.
#[derive(Debug, Default)]
struct Poseidon2ExecutionState<F> {
    /// Output of the last Poseidon2 permutation for chaining.
    /// `None` if no permutation has been executed yet.
    last_output: Option<[F; 4]>,
    /// Circuit rows captured during execution.
    rows: Vec<Poseidon2CircuitRow<F>>,
}

impl<F: Send + Sync + Debug + 'static> OpExecutionState for Poseidon2ExecutionState<F> {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// User-facing arguments for adding a Poseidon2 perm row.
pub struct Poseidon2PermCall {
    /// Flag indicating whether a new chain is started.
    pub new_start: bool,
    /// Flag indicating whether we are verifying a Merkle path
    pub merkle_path: bool,
    /// MMCS direction bit input (base field, boolean).
    ///
    /// Required when `merkle_path = true`. When `merkle_path = false`, this may be omitted and
    /// defaults to 0 (not exposed via CTL).
    pub mmcs_bit: Option<ExprId>,
    /// Optional CTL exposure for each input limb (one extension element).
    /// If `None`, the limb is not exposed via CTL (in_ctl = 0).
    /// Note: For Merkle mode, unexposed limbs are provided via Poseidon2PermPrivateData (the sibling).
    pub inputs: [Option<ExprId>; 4],
    /// Output exposure flags for limbs 0 and 1.
    ///
    /// When `out_ctl[i]` is true, this call allocates an output witness expression for limb `i`
    /// (returned from `add_poseidon2_perm`) and exposes it via CTL. Limbs 2–3 are never exposed.
    pub out_ctl: [bool; 2],
    /// Optional MMCS index accumulator value to expose.
    pub mmcs_index_sum: Option<ExprId>,
}

/// Convenience helpers to build calls with defaults.
impl Default for Poseidon2PermCall {
    fn default() -> Self {
        Self {
            new_start: false,
            merkle_path: false,
            mmcs_bit: None,
            inputs: [None, None, None, None],
            out_ctl: [false, false],
            mmcs_index_sum: None,
        }
    }
}

pub trait Poseidon2PermOps<F: Clone + PrimeCharacteristicRing + Eq> {
    /// Add a Poseidon2 perm row (one permutation).
    ///
    /// - `new_start`: if true, this row starts a new chain (no chaining from previous row).
    /// - `merkle_path`: if true, Merkle-path chaining semantics apply (chained digest placement depends on `mmcs_bit`).
    /// - `mmcs_bit`: Merkle direction bit witness for this row (used when `merkle_path` is true).
    /// - `inputs`: optional CTL exposure per limb (extension element, length 4 if provided).
    ///   Base-component inputs are not supported; unexposed limbs in Merkle mode are
    ///   provided separately via `Poseidon2PermPrivateData`.
    /// - `out_ctl`: whether to allocate/expose output limbs 0–1 via CTL.
    /// - `mmcs_index_sum`: optional exposure of the MMCS index accumulator (base field element).
    fn add_poseidon2_perm(
        &mut self,
        call: Poseidon2PermCall,
    ) -> Result<(NonPrimitiveOpId, [Option<ExprId>; 2]), crate::CircuitBuilderError>;
}

impl<F> Poseidon2PermOps<F> for CircuitBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + Eq + core::hash::Hash,
{
    fn add_poseidon2_perm(
        &mut self,
        call: Poseidon2PermCall,
    ) -> Result<(NonPrimitiveOpId, [Option<ExprId>; 2]), crate::CircuitBuilderError> {
        let op_type = NonPrimitiveOpType::Poseidon2Perm;
        self.ensure_op_enabled(op_type.clone())?;
        if call.merkle_path && call.mmcs_bit.is_none() {
            return Err(crate::CircuitBuilderError::Poseidon2MerkleMissingMmcsBit);
        }
        if !call.merkle_path && call.mmcs_bit.is_some() {
            return Err(crate::CircuitBuilderError::Poseidon2NonMerkleWithMmcsBit);
        }

        // Build input_exprs layout: [in0, in1, in2, in3, mmcs_index_sum, mmcs_bit]
        let mut input_exprs: Vec<Vec<ExprId>> = Vec::with_capacity(6);

        for limb in call.inputs.iter() {
            if let Some(val) = limb {
                input_exprs.push(vec![*val]);
            } else {
                input_exprs.push(Vec::new());
            }
        }

        if let Some(idx_sum) = call.mmcs_index_sum {
            input_exprs.push(vec![idx_sum]);
        } else {
            input_exprs.push(Vec::new());
        }

        if let Some(bit) = call.mmcs_bit {
            input_exprs.push(vec![bit]);
        } else {
            input_exprs.push(Vec::new());
        }

        let output_0 = call.out_ctl.first().copied().unwrap_or(false);
        let output_1 = call.out_ctl.get(1).copied().unwrap_or(false);

        let (op_id, _call_expr_id, outputs) = self.push_non_primitive_op_with_outputs(
            op_type,
            input_exprs,
            vec![
                output_0.then_some("poseidon2_perm_out0"),
                output_1.then_some("poseidon2_perm_out1"),
            ],
            Some(NonPrimitiveOpParams::Poseidon2Perm {
                new_start: call.new_start,
                merkle_path: call.merkle_path,
            }),
            "poseidon2_perm",
        );
        Ok((op_id, [outputs[0], outputs[1]]))
    }
}

/// Executor for Poseidon2 perm operations.
///
#[derive(Debug, Clone)]
pub(crate) struct Poseidon2PermExecutor {
    op_type: NonPrimitiveOpType,
    pub new_start: bool,
    pub merkle_path: bool,
}

impl Poseidon2PermExecutor {
    pub const fn new(new_start: bool, merkle_path: bool) -> Self {
        Self {
            op_type: NonPrimitiveOpType::Poseidon2Perm,
            new_start,
            merkle_path,
        }
    }
}

impl<F: Field + Send + Sync + 'static> NonPrimitiveExecutor<F> for Poseidon2PermExecutor {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        // Input layout: [in0, in1, in2, in3, mmcs_index_sum, mmcs_bit]
        // Output layout: [out0, out1]
        if inputs.len() != 6 {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op_type.clone(),
                expected: "6 input vectors".to_string(),
                got: inputs.len(),
            });
        }
        for limb_inputs in inputs[..4].iter() {
            if limb_inputs.len() > 1 {
                return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                    op: self.op_type.clone(),
                    expected: "0 or 1 witness per input limb (extension-only)".to_string(),
                    got: limb_inputs.len(),
                });
            }
        }
        if inputs[4].len() > 1 {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                op: self.op_type.clone(),
                expected: "0 or 1 element for mmcs_index_sum".to_string(),
                got: inputs[4].len(),
            });
        }
        if inputs[5].len() > 1 {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                op: self.op_type.clone(),
                expected: "0 or 1 element for mmcs_bit".to_string(),
                got: inputs[5].len(),
            });
        }
        if outputs.len() != 2 {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op_type.clone(),
                expected: "2 output vectors".to_string(),
                got: outputs.len(),
            });
        }

        // Get the exec closure from config
        let config = ctx.get_config(&self.op_type)?;
        let exec = match config {
            NonPrimitiveOpConfig::Poseidon2Perm(cfg) => Arc::clone(&cfg.exec),
            NonPrimitiveOpConfig::None => {
                return Err(CircuitError::InvalidNonPrimitiveOpConfiguration {
                    op: self.op_type.clone(),
                });
            }
        };

        // Get private data if available and validate usage rules.
        let private_inputs: Option<&[F]> = match ctx.get_private_data() {
            Ok(NonPrimitiveOpPrivateData::Poseidon2Perm(data)) => {
                if !self.merkle_path || self.new_start {
                    return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                        op: self.op_type.clone(),
                        operation_index: ctx.operation_id(),
                        expected: "no private data (only Merkle mode accepts private data)"
                            .to_string(),
                        got: "private data provided for non-Merkle operation".to_string(),
                    });
                }
                Some(&data.sibling[..])
            }
            Err(_) => None,
        };

        // Get mmcs_bit (required when merkle_path=true; defaults to false otherwise).
        // mmcs_bit is at inputs[5].
        let mmcs_bit = if let Some(&wid) = inputs[5].first() {
            let val = ctx.get_witness(wid)?;
            match val {
                v if v == F::ZERO => false,
                v if v == F::ONE => true,
                v => {
                    return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                        op: self.op_type.clone(),
                        operation_index: ctx.operation_id(),
                        expected: "boolean mmcs_bit (0 or 1)".into(),
                        got: format!("{v:?}"),
                    });
                }
            }
        } else if self.merkle_path {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                op: self.op_type.clone(),
                operation_index: ctx.operation_id(),
                expected: "mmcs_bit must be provided when merkle_path=true".into(),
                got: "missing mmcs_bit".into(),
            });
        } else {
            false
        };

        // Get the previous output for chaining (read from state before mutation)
        let last_output = ctx
            .get_op_state::<Poseidon2ExecutionState<F>>(&self.op_type)
            .and_then(|s| s.last_output);

        // Resolve input limbs
        let mut resolved_inputs = [F::ZERO; 4];
        for (limb, resolved) in resolved_inputs.iter_mut().enumerate() {
            *resolved =
                self.resolve_input_limb(limb, inputs, private_inputs, ctx, last_output, mmcs_bit)?;
        }

        // Execute the permutation
        let output = exec(&resolved_inputs);

        // Build CTL metadata for row record
        let (in_ctl, input_indices) = inputs[..4].iter().enumerate().fold(
            ([false; 4], [0u32; 4]),
            |(mut in_ctl, mut input_indices), (i, inp)| {
                if let Some(&wid) = inp.first() {
                    in_ctl[i] = true;
                    input_indices[i] = wid.0;
                }
                (in_ctl, input_indices)
            },
        );

        let (out_ctl, output_indices) = outputs.iter().enumerate().fold(
            ([false; 2], [0u32; 2]),
            |(mut out_ctl, mut output_indices), (i, out_slot)| {
                if let Some(&wid) = out_slot.first() {
                    out_ctl[i] = true;
                    output_indices[i] = wid.0;
                }
                (out_ctl, output_indices)
            },
        );

        let (mmcs_index_sum, mmcs_index_sum_idx) = if inputs[4].len() == 1 {
            let wid = inputs[4][0];
            let val = ctx.get_witness(wid)?;
            (val, wid.0)
        } else {
            (F::ZERO, 0)
        };

        // Record row for trace generation (input_values contains 4 extension limbs)
        let input_values = resolved_inputs.to_vec();
        debug_assert_eq!(
            input_values.len(),
            4,
            "Execution row must have exactly 4 input limbs"
        );

        let row = Poseidon2CircuitRow {
            new_start: self.new_start,
            merkle_path: self.merkle_path,
            mmcs_bit,
            mmcs_index_sum,
            input_values,
            in_ctl,
            input_indices,
            out_ctl,
            output_indices,
            mmcs_index_sum_idx,
        };

        // Update state: chaining and rows
        let state = ctx.get_op_state_mut::<Poseidon2ExecutionState<F>>(&self.op_type);
        state.last_output = Some(output);
        state.rows.push(row);

        // Write outputs to witness if CTL exposure is requested
        for (out_idx, out_slot) in outputs.iter().enumerate() {
            if out_slot.len() == 1 {
                let wid = out_slot[0];
                ctx.set_witness(wid, output[out_idx])?;
            } else if !out_slot.is_empty() {
                return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                    op: self.op_type.clone(),
                    expected: "0 or 1 witness per output limb".to_string(),
                    got: out_slot.len(),
                });
            }
        }

        Ok(())
    }

    fn op_type(&self) -> &NonPrimitiveOpType {
        &self.op_type
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn preprocess(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        preprocessed_tables: &mut Vec<Vec<F>>,
    ) {
        let witness_table_idx = PrimitiveOpType::Witness as usize;
        let update_witness_table = |witness_ids: &[WitnessId], p_ts: &mut Vec<Vec<F>>| {
            for witness_id in witness_ids {
                let idx = witness_id.0 as usize;
                if idx >= p_ts[witness_table_idx].len() {
                    p_ts[witness_table_idx].resize(idx + 1, F::from_u32(0));
                }
                p_ts[witness_table_idx][idx] += F::ONE;
            }
        };

        // We need to populate in_ctl and out_ctl for this operation.
        let idx = PrimitiveOpType::COUNT + self.op_type.clone() as usize;
        if preprocessed_tables.len() <= idx {
            preprocessed_tables.resize(idx + 1, vec![]);
        }

        // The inputs have shape:
        // inputs[0..3]: input limbs, inputs[4]: mmcs_index_sum, inputs[5]: mmcs_bit
        // The outputs have shape:
        // outputs[0..1]: output limbs exposed via CTL
        // The shape of one preprocessed row is:
        // [in_idx0, in_ctl_0, normal_chain_sel[0], merkle_chain_sel[0], in_idx1, in1_ctl, normal_chain_sel[1], merkle_chain_sel[1], ..., out_idx0, out_ctl_0, out_idx1, out_ctl_1, mmcs_index_sum_ctl_idx, new_start, merkle_path]

        // First, let's add the input indices and `in_ctl` values.
        for (limb_idx, inp) in inputs[0..4].iter().enumerate() {
            if inp.is_empty() {
                // Private input
                preprocessed_tables[idx].push(F::ZERO); // in_idx
                preprocessed_tables[idx].push(F::ZERO); // in_ctl
            } else {
                // Exposed input
                preprocessed_tables[idx].push(F::from_u32(inp[0].0)); // in_idx
                preprocessed_tables[idx].push(F::ONE); // in_ctl

                // In this case, we are reading the input limbs from the witness table,
                // so we need to update the associated witness table multiplicities.
                update_witness_table(inp, preprocessed_tables);
            }
            let normal_chain_sel =
                if !self.new_start && !self.merkle_path && inputs[limb_idx].is_empty() {
                    F::ONE
                } else {
                    F::ZERO
                };

            preprocessed_tables[idx].push(normal_chain_sel);

            let merkle_chain_sel =
                if !self.new_start && self.merkle_path && inputs[limb_idx].is_empty() {
                    F::ONE
                } else {
                    F::ZERO
                };
            preprocessed_tables[idx].push(merkle_chain_sel);
        }

        for out in outputs[0..2].iter() {
            if out.is_empty() {
                // Private output
                preprocessed_tables[idx].push(F::ZERO); // out_idx
                preprocessed_tables[idx].push(F::ZERO); // out_ctl
            } else {
                // Exposed output
                preprocessed_tables[idx].push(F::from_u32(out[0].0)); // out_idx
                preprocessed_tables[idx].push(F::ONE); // out_ctl

                // In this case, we are reading the output limbs from the witness table,
                // so we need to update the associated witness table multiplicities.
                update_witness_table(out, preprocessed_tables);
            }
        }

        // mmcs_index_sum
        if inputs[4].is_empty() {
            preprocessed_tables[idx].push(F::ZERO);
        } else {
            preprocessed_tables[idx].push(F::ONE);
            // In this case, we are reading the MMCS index sum from the witness table,
            // so we need to update the associated witness table multiplicities.
            update_witness_table(&inputs[4], preprocessed_tables);
        }

        // We need to insert `new_start` and `merkle_path` as well.
        preprocessed_tables[idx].push(if self.new_start { F::ONE } else { F::ZERO });
        preprocessed_tables[idx].push(if self.merkle_path { F::ONE } else { F::ZERO });
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}

impl Poseidon2PermExecutor {
    /// Resolve input limb value using a layered priority system:
    /// 1. Layer 1: Private inputs (lowest priority) - sibling placed based on mmcs_bit
    /// 2. Layer 2: Chaining from previous permutation (if new_start=false)
    /// 3. Layer 3: CTL (witness) values (highest priority, overwrites previous layers)
    fn resolve_input_limb<F: Field>(
        &self,
        limb: usize,
        inputs: &[Vec<WitnessId>],
        private_inputs: Option<&[F]>,
        ctx: &ExecutionContext<'_, F>,
        last_output: Option<[F; 4]>,
        mmcs_bit: bool,
    ) -> Result<F, CircuitError> {
        // Build up the input array with layered priorities
        let mut resolved = [None; 4];

        // Layer 1: Private inputs (lowest priority)
        // Private inputs are only used in Merkle mode (merkle_path && !new_start).
        // The sibling (exactly 2 limbs) is placed based on mmcs_bit:
        // - mmcs_bit=0: sibling in 2-3
        // - mmcs_bit=1: sibling in 0-1
        if let Some(private) = private_inputs {
            // Note: validation ensures private_inputs is only provided for Merkle mode
            debug_assert!(self.merkle_path && !self.new_start);
            let start = if mmcs_bit { 0 } else { 2 };
            resolved[start] = Some(private[0]);
            resolved[start + 1] = Some(private[1]);
        }

        // Layer 2: Chaining from previous permutation (medium priority)
        if !self.new_start {
            let prev =
                last_output.ok_or_else(|| CircuitError::Poseidon2ChainMissingPreviousState {
                    operation_index: ctx.operation_id(),
                })?;

            if !self.merkle_path {
                // Normal chaining: all 4 limbs come from previous output
                for i in 0..4 {
                    resolved[i] = Some(prev[i]);
                }
            } else {
                // Merkle path chaining:
                // Previous digest (prev[0..1]) is placed based on mmcs_bit:
                // - mmcs_bit=0: chain into input limbs 0-1
                // - mmcs_bit=1: chain into input limbs 2-3
                if mmcs_bit {
                    resolved[2] = Some(prev[0]);
                    resolved[3] = Some(prev[1]);
                } else {
                    resolved[0] = Some(prev[0]);
                    resolved[1] = Some(prev[1]);
                }
            }
        }

        // Layer 3: CTL (witness) values (highest priority)
        for i in 0..4 {
            if inputs.len() > i && inputs[i].len() == 1 {
                let wid = inputs[i][0];
                let val = ctx.get_witness(wid)?;
                resolved[i] = Some(val);
            }
        }

        // Return the resolved value
        resolved[limb].ok_or_else(|| {
            if self.merkle_path && !self.new_start {
                let is_required_sibling =
                    matches!((mmcs_bit, limb), (false, 2 | 3) | (true, 0 | 1));
                if is_required_sibling {
                    return CircuitError::Poseidon2MerkleMissingSiblingInput {
                        operation_index: ctx.operation_id(),
                        limb,
                    };
                }
            }
            CircuitError::Poseidon2MissingInput {
                operation_index: ctx.operation_id(),
                limb,
            }
        })
    }
}

// ============================================================================
// Trace Types
// ============================================================================

/// Trait to provide Poseidon2 configuration parameters for a field type.
///
/// This allows the trace generator and AIR to work with different Poseidon2 configurations
/// without hardcoding parameters. Implementations should provide the standard
/// parameters for their field type.
pub trait Poseidon2Params {
    type BaseField: PrimeField + PrimeCharacteristicRing;
    /// Extension degree D
    const D: usize;
    /// Total width in base field elements
    const WIDTH: usize;

    /// Rate in extension elements
    const RATE_EXT: usize;
    /// Capacity in extension elements
    const CAPACITY_EXT: usize;
    /// Capacity size in base field elements = CAPACITY_EXT * D
    const CAPACITY_SIZE: usize = Self::CAPACITY_EXT * Self::D;

    /// S-box degree (polynomial degree for the S-box)
    const SBOX_DEGREE: u64;
    /// Number of S-box registers
    const SBOX_REGISTERS: usize;

    /// Number of half full rounds
    const HALF_FULL_ROUNDS: usize;
    /// Number of partial rounds
    const PARTIAL_ROUNDS: usize;

    /// Width in extension elements = RATE_EXT + CAPACITY_EXT
    const WIDTH_EXT: usize = Self::RATE_EXT + Self::CAPACITY_EXT;
}

/// Poseidon2 operation table row.
///
/// This implements the Poseidon Permutation Table specification.
/// See: https://github.com/Plonky3/Plonky3-recursion/discussions/186
///
/// The table has one row per Poseidon call, implementing:
/// - Standard chaining (Challenger-style sponge use)
/// - Merkle-path chaining (MMCS directional hashing)
/// - Selective limb exposure to the witness via CTL
/// - Optional MMCS index accumulator
#[derive(Debug, Clone)]
pub struct Poseidon2CircuitRow<F> {
    /// Control: If 1, row begins a new independent Poseidon chain.
    pub new_start: bool,
    /// Control: 0 → normal sponge/Challenger mode, 1 → Merkle-path mode.
    pub merkle_path: bool,
    /// Control: Direction bit for Merkle left/right hashing (only meaningful when merkle_path = 1).
    pub mmcs_bit: bool,
    /// Value: Optional MMCS accumulator (base field, encodes a u32-like integer).
    pub mmcs_index_sum: F,
    /// Inputs to the Poseidon2 permutation (flattened state).
    /// For execution rows: 4 extension limbs. For trace rows: WIDTH base field elements.
    pub input_values: Vec<F>,
    /// Input exposure flags: for each limb i, if 1, in[i] must match witness lookup at input_indices[i].
    pub in_ctl: [bool; 4],
    /// Input exposure indices: index into the witness table for each limb.
    pub input_indices: [u32; 4],
    /// Output exposure flags: for limbs 0-1 only, if 1, out[i] must match witness lookup at output_indices[i].
    /// Note: limbs 2-3 are never publicly exposed (always private).
    pub out_ctl: [bool; 2],
    /// Output exposure indices: index into the witness table for limbs 0-1.
    pub output_indices: [u32; 2],
    /// MMCS index exposure: index for CTL exposure of mmcs_index_sum.
    pub mmcs_index_sum_idx: u32,
}

/// Poseidon2 trace for all hash operations in the circuit.
#[derive(Debug, Clone)]
pub struct Poseidon2Trace<F> {
    /// All Poseidon2 operations (permutation rows) in this trace.
    pub operations: Vec<Poseidon2CircuitRow<F>>,
}

impl<F> Poseidon2Trace<F> {
    pub const fn total_rows(&self) -> usize {
        self.operations.len()
    }
}

impl<TraceF: Clone + Send + Sync + 'static, CF> NonPrimitiveTrace<CF> for Poseidon2Trace<TraceF> {
    fn id(&self) -> &'static str {
        "poseidon2"
    }

    fn rows(&self) -> usize {
        self.total_rows()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn boxed_clone(&self) -> Box<dyn NonPrimitiveTrace<CF>> {
        Box::new(self.clone())
    }
}

// ============================================================================
// Trace Generation
// ============================================================================

/// Generate the Poseidon2 trace from execution state.
///
/// Converts circuit rows from extension field format (4 limbs) to base field format (16 elements).
///
/// # Type Parameters
/// - `F`: The circuit field type (extension field)
/// - `Config`: A type implementing `Poseidon2Params` that specifies the Poseidon2 configuration
pub fn generate_poseidon2_trace<
    F: CircuitField + ExtensionField<Config::BaseField>,
    Config: Poseidon2Params,
>(
    _circuit: &Circuit<F>,
    _witness: &[Option<F>],
    _non_primitive_data: &[Option<NonPrimitiveOpPrivateData<F>>],
    op_states: &crate::op::OpStateMap,
) -> Result<Option<Box<dyn NonPrimitiveTrace<F>>>, CircuitError> {
    let Some(state) = op_states
        .get(&NonPrimitiveOpType::Poseidon2Perm)
        .and_then(|s| s.as_any().downcast_ref::<Poseidon2ExecutionState<F>>())
    else {
        return Ok(None);
    };

    if state.rows.is_empty() {
        return Ok(None);
    }

    let d = Config::D;

    // Convert extension field rows to base field rows
    let operations: Vec<Poseidon2CircuitRow<Config::BaseField>> = state
        .rows
        .iter()
        .enumerate()
        .map(|(row_index, row)| -> Result<_, CircuitError> {
            // Flatten 4 extension limbs to WIDTH base field elements
            assert_eq!(
                row.input_values.len(),
                4,
                "Source row must have exactly 4 input limbs"
            );
            let mut input_values = vec![Config::BaseField::ZERO; Config::WIDTH];
            assert_eq!(
                input_values.len(),
                Config::WIDTH,
                "Target row must have WIDTH input elements"
            );
            for (limb, ext_val) in row.input_values.iter().enumerate() {
                let coeffs = ext_val.as_basis_coefficients_slice();
                input_values[limb * d..(limb + 1) * d].copy_from_slice(coeffs);
            }

            let mmcs_index_sum = row.mmcs_index_sum.as_base().ok_or_else(|| {
                CircuitError::IncorrectNonPrimitiveOpPrivateData {
                    op: NonPrimitiveOpType::Poseidon2Perm,
                    operation_index: NonPrimitiveOpId(row_index as u32),
                    expected: "base field mmcs_index_sum".to_string(),
                    got: "extension value".to_string(),
                }
            })?;

            Ok(Poseidon2CircuitRow {
                new_start: row.new_start,
                merkle_path: row.merkle_path,
                mmcs_bit: row.mmcs_bit,
                mmcs_index_sum,
                input_values,
                in_ctl: row.in_ctl,
                input_indices: row.input_indices,
                out_ctl: row.out_ctl,
                output_indices: row.output_indices,
                mmcs_index_sum_idx: row.mmcs_index_sum_idx,
            })
        })
        .collect::<Result<Vec<_>, CircuitError>>()?;

    Ok(Some(Box::new(Poseidon2Trace { operations })))
}
