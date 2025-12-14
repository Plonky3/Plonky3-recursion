//! Poseidon permutation non-primitive operation (one Poseidon call per row).
//!
//! This operation is designed to support both standard hashing and specific logic required for
//! Merkle path verification within a circuit. Its features include:
//!
//! - **Hashing**: Performs a standard Poseidon permutation.
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
use alloc::vec;
use alloc::vec::Vec;

use p3_field::{Field, PrimeCharacteristicRing};

use crate::CircuitError;
use crate::builder::{CircuitBuilder, NonPrimitiveOpParams};
use crate::op::{
    ExecutionContext, NonPrimitiveExecutor, NonPrimitiveOpConfig, NonPrimitiveOpPrivateData,
    NonPrimitiveOpType,
};
use crate::types::{ExprId, NonPrimitiveOpId, WitnessId};

/// User-facing arguments for adding a Poseidon perm row.
pub struct PoseidonPermCall {
    /// Flag indicating whether a new chain is started.
    pub new_start: bool,
    /// Flag indicating whether we are verifying a Merkle path
    pub merkle_path: bool,
    /// Optional mmcs direction bit input (base field, boolean). If None, defaults to 0/private.
    pub mmcs_bit: Option<ExprId>,
    /// Optional CTL exposure for each input limb (one extension element).
    /// If `None`, the limb is considered private/unexposed (in_ctl = 0).
    pub inputs: [Option<ExprId>; 4],
    /// Optional CTL exposure for output limbs 0 and 1 (one extension element).
    /// Limbs 2–3 are never exposed.
    pub outputs: [Option<ExprId>; 2],
    /// Optional MMCS index accumulator value to expose.
    pub mmcs_index_sum: Option<ExprId>,
}

/// Convenience helpers to build calls with defaults.
impl Default for PoseidonPermCall {
    fn default() -> Self {
        Self {
            new_start: false,
            merkle_path: false,
            mmcs_bit: None,
            inputs: [None, None, None, None],
            outputs: [None, None],
            mmcs_index_sum: None,
        }
    }
}

pub trait PoseidonPermOps<F: Clone + PrimeCharacteristicRing + Eq> {
    /// Add a Poseidon perm row (one permutation).
    ///
    /// - `new_start`: if true, this row starts a new chain (no chaining from previous row).
    /// - `merkle_path`: if true, Merkle chaining semantics apply for limbs 0–1.
    /// - `mmcs_bit`: Merkle direction bit witness for this row (used when `merkle_path` is true).
    /// - `inputs`: optional CTL exposure per limb (extension element, length 4 if provided).
    /// - `outputs`: optional CTL exposure for limbs 0–1 (extension element, length 4 if provided).
    /// - `mmcs_index_sum`: optional exposure of the MMCS index accumulator (base field element).
    fn add_poseidon_perm(
        &mut self,
        call: PoseidonPermCall,
    ) -> Result<NonPrimitiveOpId, crate::CircuitBuilderError>;
}

impl<F> PoseidonPermOps<F> for CircuitBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + Eq + core::hash::Hash,
{
    fn add_poseidon_perm(
        &mut self,
        call: PoseidonPermCall,
    ) -> Result<NonPrimitiveOpId, crate::CircuitBuilderError> {
        let op_type = NonPrimitiveOpType::PoseidonPerm;
        self.ensure_op_enabled(op_type.clone())?;

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

        // Build output_exprs layout: [out0, out1]
        let mut output_exprs: Vec<Vec<ExprId>> = Vec::with_capacity(2);

        for out in call.outputs.iter() {
            if let Some(val) = out {
                output_exprs.push(vec![*val]);
            } else {
                output_exprs.push(Vec::new());
            }
        }

        Ok(self.push_non_primitive_op(
            op_type,
            input_exprs,
            output_exprs,
            Some(NonPrimitiveOpParams::PoseidonPerm {
                new_start: call.new_start,
                merkle_path: call.merkle_path,
            }),
            "poseidon_perm",
        ))
    }
}

/// Executor for Poseidon perm operations.
///
/// This currently does not mutate the witness; the AIR enforces correctness.
#[derive(Debug, Clone)]
pub struct PoseidonPermExecutor {
    op_type: NonPrimitiveOpType,
    pub new_start: bool,
    pub merkle_path: bool,
}

impl PoseidonPermExecutor {
    pub const fn new(new_start: bool, merkle_path: bool) -> Self {
        Self {
            op_type: NonPrimitiveOpType::PoseidonPerm,
            new_start,
            merkle_path,
        }
    }
}

impl<F: Field> NonPrimitiveExecutor<F> for PoseidonPermExecutor {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        // Input layout: [in0, in1, in2, in3, mmcs_index_sum, mmcs_bit]
        // Output layout: [out0, out1]

        // Get the exec closure from config
        let config = ctx.get_config(&self.op_type)?;
        let exec = match config {
            NonPrimitiveOpConfig::PoseidonPerm(cfg) => &cfg.exec,
            NonPrimitiveOpConfig::None => {
                return Err(CircuitError::InvalidNonPrimitiveOpConfiguration {
                    op: self.op_type.clone(),
                });
            }
        };

        // Get private data if available
        let private_data = ctx.get_private_data().ok();
        let private_inputs: Option<&[F]> = private_data.map(|pd| match pd {
            NonPrimitiveOpPrivateData::PoseidonPerm(data) => data.input_values.as_slice(),
        });

        // Get mmcs_bit if provided (default to false if absent)
        // mmcs_bit is at inputs[5]
        let mmcs_bit = if inputs.len() > 5 && inputs[5].len() == 1 {
            let wid = inputs[5][0];
            ctx.get_witness(wid).is_ok_and(|val| val == F::ONE)
        } else {
            false
        };

        // Resolve input limbs
        let mut resolved_inputs = [F::ZERO; 4];
        for (limb, resolved) in resolved_inputs.iter_mut().enumerate() {
            *resolved = self.resolve_input_limb(limb, inputs, private_inputs, ctx, mmcs_bit)?;
        }

        // Execute the permutation
        let output = exec(&resolved_inputs);

        // Update chaining state
        ctx.set_last_poseidon(output);

        // Write outputs to witness if CTL exposure is requested
        for (out_idx, out_slot) in outputs.iter().enumerate() {
            if out_slot.len() == 1 {
                let wid = out_slot[0];
                ctx.set_witness(wid, output[out_idx])?;
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

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}

impl PoseidonPermExecutor {
    /// Resolve input limb value using precedence rules:
    /// 1. CTL (witness) if provided and set
    /// 2. Chaining from previous permutation (if new_start=false)
    ///    - Normal mode: all 4 limbs from chaining
    ///    - Merkle mode: only limbs 0-1 from chaining, limbs 2-3 from private/CTL
    /// 3. Private data as fallback
    fn resolve_input_limb<F: Field>(
        &self,
        limb: usize,
        inputs: &[Vec<WitnessId>],
        private_inputs: Option<&[F]>,
        ctx: &ExecutionContext<'_, F>,
        mmcs_bit: bool,
    ) -> Result<F, CircuitError> {
        // 1. Check CTL (witness) first - highest priority
        if inputs.len() > limb && inputs[limb].len() == 1 {
            let wid = inputs[limb][0];
            if let Ok(val) = ctx.get_witness(wid) {
                return Ok(val);
            }
        }

        // 2. Check chaining from previous permutation (if new_start=false)
        if !self.new_start {
            let prev = ctx.last_poseidon().ok_or_else(|| {
                CircuitError::PoseidonChainMissingPreviousState {
                    operation_index: ctx.operation_id(),
                }
            })?;

            if !self.merkle_path {
                // Normal chaining: all 4 limbs come from previous output
                return Ok(prev[limb]);
            } else {
                // Merkle path chaining:
                // - limbs 0-1 come from prev[0-1] (if bit=0) or prev[2-3] (if bit=1)
                // - limbs 2-3 MUST come from private data or CTL
                match limb {
                    0 => {
                        if !mmcs_bit {
                            return Ok(prev[0]);
                        } else {
                            return Ok(prev[2]);
                        }
                    }
                    1 => {
                        if !mmcs_bit {
                            return Ok(prev[1]);
                        } else {
                            return Ok(prev[3]);
                        }
                    }
                    2 | 3 => {
                        // limbs 2-3 need private data or CTL - continue to check private data below
                    }
                    _ => unreachable!(),
                }
            }
        }

        // 3. Check private data as fallback
        if let Some(private) = private_inputs
            && limb < private.len()
        {
            return Ok(private[limb]);
        }

        // 4. Missing input error
        if self.merkle_path && !self.new_start && (limb == 2 || limb == 3) {
            Err(CircuitError::PoseidonMerkleMissingSiblingInput {
                operation_index: ctx.operation_id(),
                limb,
            })
        } else {
            Err(CircuitError::PoseidonMissingInput {
                operation_index: ctx.operation_id(),
                limb,
            })
        }
    }
}
