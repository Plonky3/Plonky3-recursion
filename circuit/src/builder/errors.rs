use alloc::string::String;

use thiserror::Error;

use crate::ExprId;
use crate::op::NonPrimitiveOpType;

/// Errors that can occur during circuit building/lowering.
#[derive(Debug, Error)]
pub enum CircuitBuilderError {
    /// Expression not found in the witness mapping during lowering.
    #[error("Expression {expr_id:?} not found in witness mapping: {context}")]
    MissingExprMapping {
        expr_id: ExprId,
        context: alloc::string::String,
    },

    /// Non-primitive op received an unexpected number of input expressions.
    #[error("{op} expects exactly {expected} witness expressions, got {got}")]
    NonPrimitiveOpArity {
        op: &'static str,
        expected: String,
        got: usize,
    },

    /// Unconstrained op received an unexpected number of input expressions.
    #[error("Expects exactly {expected} witness expressions, got {got}")]
    UnconstrainedeOpArity { expected: String, got: usize },

    /// Non-primitive operation rejected by the active policy/profile.
    #[error("Operation {op:?} is not allowed by the current profile")]
    OpNotAllowed { op: NonPrimitiveOpType },

    /// Non-primitive operation is recognized but not implemented in lowering.
    #[error("Operation {op:?} is not implemented in lowering")]
    UnsupportedNonPrimitiveOp { op: NonPrimitiveOpType },

    /// Mismatched non-primitive operation configuration
    #[error("Invalid configuration for operation {op:?}")]
    InvalidNonPrimitiveOpConfiguration { op: NonPrimitiveOpType },
}
