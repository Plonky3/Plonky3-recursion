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
use crate::op::{ExecutionContext, NonPrimitiveExecutor, NonPrimitiveOpType, PrimitiveOpType};
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
        _inputs: &[Vec<WitnessId>],
        _outputs: &[Vec<WitnessId>],
        _ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        Ok(())
    }

    fn preprocessing(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        preprocessed_tables: &mut Vec<Vec<F>>,
    ) {
        // Update the `Witness` table preprocessing by incrementing the multiplicity of all values read from the `Witness` table.
        // Whenever an input or output is present, it means it is exposed in the `Permutation` table, and its multiplicity should therefore be incremented.
        let witness_table_idx = PrimitiveOpType::Witness as usize;
        for inp in inputs {
            for witness_id in inp {
                let idx = witness_id.0 as usize;
                if idx >= preprocessed_tables[witness_table_idx].len() {
                    preprocessed_tables[witness_table_idx].resize(idx + 1, F::from_u32(0));
                }
                preprocessed_tables[witness_table_idx][idx] += F::ONE;
            }
        }

        for out in outputs {
            for witness_id in out {
                let idx = witness_id.0 as usize;
                if idx >= preprocessed_tables[witness_table_idx].len() {
                    preprocessed_tables[witness_table_idx].resize(idx + 1, F::from_u32(0));
                }
                preprocessed_tables[witness_table_idx][idx] += F::ONE;
            }
        }

        // TODO: Update preprocessing columns for the Permutation table as well.
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
