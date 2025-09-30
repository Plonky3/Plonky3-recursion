use alloc::vec;

use crate::builder::{CircuitBuilder, CircuitBuilderError};
use crate::op::NonPrimitiveOpType;
use crate::types::{ExprId, NonPrimitiveOpId};

/// Extension trait for Merkle-related non-primitive ops.
pub trait MerkleOps<F> {
    /// Add a Merkle verification constraint (non-primitive operation)
    ///
    /// Non-primitive operations are complex constraints that:
    /// - Take existing expressions as inputs (leaf_expr, directions_expr, root_expr)
    /// - Add verification constraints to the circuit
    /// - Don't produce new ExprIds (unlike primitive ops)
    /// - Are kept separate from primitives to avoid disrupting optimization
    ///
    /// Returns an operation ID for setting private data later during execution.
    fn add_merkle_verify(
        &mut self,
        leaf_expr: &[ExprId],
        index_expr: &ExprId,
        root_expr: &[ExprId],
    ) -> Result<NonPrimitiveOpId, CircuitBuilderError>;
}

impl<F> MerkleOps<F> for CircuitBuilder<F>
where
    F: Clone + p3_field::PrimeCharacteristicRing + Eq + core::hash::Hash,
{
    fn add_merkle_verify(
        &mut self,
        leaf_expr: &[ExprId],
        index_expr: &ExprId,
        root_expr: &[ExprId],
    ) -> Result<NonPrimitiveOpId, CircuitBuilderError> {
        self.ensure_op_enabled(NonPrimitiveOpType::MerkleVerify)?;

        let mut witness_exprs = vec![];
        witness_exprs.extend(leaf_expr);
        witness_exprs.push(*index_expr);
        witness_exprs.extend(root_expr);
        Ok(self.push_non_primitive_op(NonPrimitiveOpType::MerkleVerify, witness_exprs))
    }
}
