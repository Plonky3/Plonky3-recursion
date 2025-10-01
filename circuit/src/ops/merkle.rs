use alloc::vec;
use alloc::vec::Vec;

use crate::builder::{CircuitBuilder, CircuitBuilderError};
use crate::op::{NonPrimitiveOpConfig, NonPrimitiveOpType};
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
        directions_expr: &[ExprId],
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
        directions_expr: &[ExprId],
        root_expr: &[ExprId],
    ) -> Result<NonPrimitiveOpId, CircuitBuilderError> {
        self.ensure_op_enabled(NonPrimitiveOpType::MerkleVerify)?;

        let config = self
            .get_op_config(&NonPrimitiveOpType::MerkleVerify)
            .ok_or(CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                op: NonPrimitiveOpType::MerkleVerify,
            })?;
        let config = match config {
            NonPrimitiveOpConfig::MerkleVerifyConfig(config) => config,
            _ => {
                return Err(CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                    op: NonPrimitiveOpType::MerkleVerify,
                });
            }
        };
        // Assert that inputs are consistent with the configuration
        assert_eq!(leaf_expr.len(), config.ext_field_digest_elems);
        assert!(directions_expr.len() <= config.max_tree_height);
        assert_eq!(root_expr.len(), config.ext_field_digest_elems);

        let mut witness_exprs: Vec<ExprId> = vec![];
        witness_exprs.extend(leaf_expr);
        witness_exprs.extend(directions_expr);
        witness_exprs.extend(root_expr);

        Ok(self.push_non_primitive_op(NonPrimitiveOpType::MerkleVerify, witness_exprs))
    }
}
