//! Poseidon2 permutation non-primitive operation (one Poseidon2 call per row).
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
use alloc::vec::Vec;
use alloc::{format, vec};

use p3_field::{Field, PrimeCharacteristicRing};
use strum::EnumCount;

use crate::CircuitError;
use crate::builder::{CircuitBuilder, NonPrimitiveOpParams};
use crate::op::{
    ExecutionContext, NonPrimitiveExecutor, NonPrimitiveOpConfig, NonPrimitiveOpPrivateData,
    NonPrimitiveOpType, PrimitiveOpType,
};
use crate::types::{ExprId, NonPrimitiveOpId, WitnessId};

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
    ///   Unexposed limbs in Merkle mode are provided separately via `Poseidon2PermPrivateData`.
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
pub struct Poseidon2PermExecutor {
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

impl<F: Field> NonPrimitiveExecutor<F> for Poseidon2PermExecutor {
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
            NonPrimitiveOpConfig::Poseidon2Perm(cfg) => &cfg.exec,
            NonPrimitiveOpConfig::None => {
                return Err(CircuitError::InvalidNonPrimitiveOpConfiguration {
                    op: self.op_type.clone(),
                });
            }
        };

        // Get private data if available
        let private_data = ctx.get_private_data().ok();
        let private_inputs: Option<&[F]> = private_data.map(|pd| match pd {
            NonPrimitiveOpPrivateData::Poseidon2Perm(data) => &data.sibling[..],
        });

        // Get mmcs_bit (required when merkle_path=true; defaults to false otherwise).
        // mmcs_bit is at inputs[5].
        let mmcs_bit = if inputs[5].len() == 1 {
            let wid = inputs[5][0];
            let val = ctx.get_witness(wid)?;
            if val == F::ZERO {
                false
            } else if val == F::ONE {
                true
            } else {
                return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                    op: self.op_type.clone(),
                    operation_index: ctx.operation_id(),
                    expected: "boolean mmcs_bit (0 or 1)".to_string(),
                    got: format!("{val:?}"),
                });
            }
        } else if self.merkle_path {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                op: self.op_type.clone(),
                operation_index: ctx.operation_id(),
                expected: "mmcs_bit must be provided when merkle_path=true".to_string(),
                got: "missing mmcs_bit".to_string(),
            });
        } else {
            false
        };

        // Resolve input limbs - determine WIDTH_EXT from number of input limbs
        let width_ext = inputs.len().saturating_sub(2); // inputs[0..width_ext] are limbs, inputs[width_ext] is mmcs_index_sum, inputs[width_ext+1] is mmcs_bit
        let mut resolved_inputs = Vec::with_capacity(width_ext);
        for limb in 0..width_ext {
            resolved_inputs.push(self.resolve_input_limb(
                limb,
                inputs,
                private_inputs,
                ctx,
                mmcs_bit,
            )?);
        }

        // Execute the permutation
        let output = exec(&resolved_inputs);

        // Update chaining state
        ctx.set_last_poseidon2(output.clone());

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
            let prev = ctx.last_poseidon2().ok_or_else(|| {
                CircuitError::Poseidon2ChainMissingPreviousState {
                    operation_index: ctx.operation_id(),
                }
            })?;

            if !self.merkle_path {
                // Normal chaining: all WIDTH_EXT limbs come from previous output
                for i in 0..prev.len().min(resolved.len()) {
                    resolved[i] = Some(prev[i]);
                }
            } else {
                // Merkle path chaining:
                // Previous digest (prev[0..DIGEST_EXT]) is placed based on mmcs_bit:
                // - mmcs_bit=0: chain into input limbs 0-1
                // - mmcs_bit=1: chain into input limbs 2-3
                let digest_ext = 2; // TODO: Make this generic based on Config::DIGEST_EXT
                if mmcs_bit {
                    if resolved.len() > 2 && prev.len() >= digest_ext {
                        resolved[2] = Some(prev[0]);
                        resolved[3] = Some(prev[1]);
                    }
                } else {
                    if prev.len() >= digest_ext {
                        resolved[0] = Some(prev[0]);
                        resolved[1] = Some(prev[1]);
                    }
                }
            }
        }

        // Layer 3: CTL (witness) values (highest priority)
        for i in 0..resolved.len() {
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
