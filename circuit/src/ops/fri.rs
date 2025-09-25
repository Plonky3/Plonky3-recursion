use crate::builder::{CircuitBuilder, CircuitBuilderError};
use crate::op::NonPrimitiveOpType;
use crate::types::{ExprId, NonPrimitiveOpId};

/// Extension trait for FRI-related non-primitive ops.
pub trait FriOps<F> {
    fn add_fri_verify(
        &mut self,
        commitment_expr: ExprId,
        query_expr: ExprId,
    ) -> Result<NonPrimitiveOpId, CircuitBuilderError>;
}

impl<F> FriOps<F> for CircuitBuilder<F>
where
    F: Clone + p3_field::PrimeCharacteristicRing + Eq + core::hash::Hash,
{
    fn add_fri_verify(
        &mut self,
        _commitment_expr: ExprId,
        _query_expr: ExprId,
    ) -> Result<NonPrimitiveOpId, CircuitBuilderError> {
        // Currently no concrete FRI op type is wired; reject for now

        // For now, return unsupported error since FRI lowering is not implemented
        Err(CircuitBuilderError::UnsupportedNonPrimitiveOp {
            op: NonPrimitiveOpType::FriVerify,
        })
    }
}
