use crate::builder::{CircuitBuilder, CircuitBuilderError};
use crate::op::NonPrimitiveOpType;
use crate::types::{ExprId, NonPrimitiveOpId};

/// Extension trait for Merkle-related non-primitive ops.
pub trait MerkleOps<F> {
    fn add_fake_merkle_verify(
        &mut self,
        leaf_expr: ExprId,
        root_expr: ExprId,
    ) -> Result<NonPrimitiveOpId, CircuitBuilderError>;
}

impl<F> MerkleOps<F> for CircuitBuilder<F>
where
    F: Clone + p3_field::PrimeCharacteristicRing + Eq + core::hash::Hash,
{
    fn add_fake_merkle_verify(
        &mut self,
        leaf_expr: ExprId,
        root_expr: ExprId,
    ) -> Result<NonPrimitiveOpId, CircuitBuilderError> {
        self.ensure_op_enabled(NonPrimitiveOpType::FakeMerkleVerify)?;

        Ok(self.push_non_primitive_op(
            NonPrimitiveOpType::FakeMerkleVerify,
            alloc::vec![leaf_expr, root_expr],
        ))
    }
}
