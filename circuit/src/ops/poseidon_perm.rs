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
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;

use p3_field::{Field, PrimeCharacteristicRing};

use crate::CircuitError;
use crate::builder::{CircuitBuilder, NonPrimitiveOpParams};
use crate::op::{
    ExecutionContext, NonPrimitiveExecutor, NonPrimitiveOpPrivateData, NonPrimitiveOpType,
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

        // Build witness_exprs layout:
        // [in0, in1, in2, in3, out0, out1, mmcs_index_sum, mmcs_bit]
        let mut witness_exprs: Vec<Vec<ExprId>> = Vec::with_capacity(8);

        for limb in call.inputs.iter() {
            if let Some(val) = limb {
                witness_exprs.push(vec![*val]);
            } else {
                witness_exprs.push(Vec::new());
            }
        }

        for out in call.outputs.iter() {
            if let Some(val) = out {
                witness_exprs.push(vec![*val]);
            } else {
                witness_exprs.push(Vec::new());
            }
        }

        if let Some(idx_sum) = call.mmcs_index_sum {
            witness_exprs.push(vec![idx_sum]);
        } else {
            witness_exprs.push(Vec::new());
        }
        // mmcs_bit
        if let Some(bit) = call.mmcs_bit {
            witness_exprs.push(vec![bit]);
        } else {
            witness_exprs.push(Vec::new());
        }

        Ok(self.push_non_primitive_op(
            op_type,
            witness_exprs,
            Some(NonPrimitiveOpParams::PoseidonPerm {
                new_start: call.new_start,
                merkle_path: call.merkle_path,
            }),
            "poseidon_perm",
        ))
    }
}

/// Type alias for the shared execute function stored in the executor
pub type SharedPermExecuteFn<F> = Arc<dyn Fn(&[F; 4]) -> [F; 4] + Send + Sync>;

/// Executor for Poseidon perm operations.
///
/// This executor computes the Poseidon permutation outputs during `runner.run()`
/// and writes them to the witness table, enabling outputs to be used as inputs
/// to subsequent operations.
pub struct PoseidonPermExecutor<F> {
    op_type: NonPrimitiveOpType,
    pub new_start: bool,
    pub merkle_path: bool,
    /// Execution function for computing outputs during runner.run()
    execute_fn: SharedPermExecuteFn<F>,
}

impl<F> Clone for PoseidonPermExecutor<F> {
    fn clone(&self) -> Self {
        Self {
            op_type: self.op_type.clone(),
            new_start: self.new_start,
            merkle_path: self.merkle_path,
            execute_fn: self.execute_fn.clone(),
        }
    }
}

impl<F> core::fmt::Debug for PoseidonPermExecutor<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PoseidonPermExecutor")
            .field("op_type", &self.op_type)
            .field("new_start", &self.new_start)
            .field("merkle_path", &self.merkle_path)
            .field("execute_fn", &"<fn>")
            .finish()
    }
}

impl<F> PoseidonPermExecutor<F> {
    /// Create a new executor with execution support
    pub fn new(new_start: bool, merkle_path: bool, execute_fn: SharedPermExecuteFn<F>) -> Self {
        Self {
            op_type: NonPrimitiveOpType::PoseidonPerm,
            new_start,
            merkle_path,
            execute_fn,
        }
    }
}

impl<F: Field> NonPrimitiveExecutor<F> for PoseidonPermExecutor<F> {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        // Layout: inputs = [in0, in1, in2, in3, mmcs_index_sum, mmcs_bit]
        //         outputs = [out0, out1]
        if inputs.len() < 4 {
            return Ok(()); // Invalid layout, skip execution
        }

        // Build input state: start with private data (if available), then apply chaining, then CTL
        // This matches the trace builder's semantics: private data is the initial state
        let mut input_limbs: [F; 4] = [F::ZERO; 4];

        // Step 1: Initialize from private data (if available)
        if let Ok(NonPrimitiveOpPrivateData::PoseidonPerm(perm_data)) = ctx.get_private_data() {
            for (i, limb) in perm_data.input_values.iter().enumerate().take(4) {
                input_limbs[i] = *limb;
            }
        }

        // Step 2: For chained operations (new_start=false), apply chaining rules
        // Chaining only applies to limbs that are ZERO (not set by private data)
        // This matches the AIR: chaining is gated by (1 - in_ctl[i]), and private data doesn't set in_ctl
        if !self.new_start {
            if let Some(prev_output) = ctx.get_last_poseidon_output() {
                if self.merkle_path {
                    // Merkle-path mode: chain based on mmcs_bit
                    // Get mmcs_bit from inputs[5] if provided
                    let mmcs_bit = if inputs.len() > 5 && inputs[5].len() == 1 {
                        if let Ok(bit_val) = ctx.get_witness(inputs[5][0]) {
                            bit_val != F::ZERO
                        } else {
                            false
                        }
                    } else {
                        false
                    };

                    // Only chain limbs that are ZERO (not set by private data)
                    if mmcs_bit {
                        // mmcs_bit = 1 (right): chain limbs 0-1 from prev_out[2-3] if not set
                        if input_limbs[0] == F::ZERO {
                            input_limbs[0] = prev_output[2];
                        }
                        if input_limbs[1] == F::ZERO {
                            input_limbs[1] = prev_output[3];
                        }
                    } else {
                        // mmcs_bit = 0 (left): chain limbs 0-1 from prev_out[0-1] if not set
                        if input_limbs[0] == F::ZERO {
                            input_limbs[0] = prev_output[0];
                        }
                        if input_limbs[1] == F::ZERO {
                            input_limbs[1] = prev_output[1];
                        }
                    }
                } else {
                    // Normal sponge mode: chain all 4 limbs if not set by private data
                    for i in 0..4 {
                        if input_limbs[i] == F::ZERO {
                            input_limbs[i] = prev_output[i];
                        }
                    }
                }
            }
        }

        // Override with witness values where explicitly provided (CTL exposure)
        // CTL always overrides chaining and private data
        for (i, limb_wids) in inputs.iter().take(4).enumerate() {
            if limb_wids.len() == 1
                && let Ok(val) = ctx.get_witness(limb_wids[0])
            {
                input_limbs[i] = val;
            }
        }

        // Execute the permutation
        let output_limbs = (self.execute_fn)(&input_limbs);

        // Store output for chaining to next operation
        ctx.set_last_poseidon_output(output_limbs);

        // Write output values to witness where output slots are specified
        // Use set_if_unset_or_equal to allow overwriting ZERO (from default hints) and matching values (for public inputs)
        for (i, output_wids) in outputs.iter().take(2).enumerate() {
            if output_wids.len() == 1 {
                ctx.set_if_unset_or_equal(output_wids[0], output_limbs[i])?;
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
