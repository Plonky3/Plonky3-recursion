use alloc::string::String;
use alloc::vec::Vec;

use thiserror::Error;

use crate::op::NonPrimitiveOpType;
use crate::types::NonPrimitiveOpId;
use crate::{ExprId, WitnessId};

/// Errors that can occur during circuit building/lowering.
#[derive(Debug, Error)]
pub enum CircuitBuilderError {
    /// Expression not found in the witness mapping during lowering.
    #[error("Expression {expr_id:?} not found in witness mapping: {context}")]
    MissingExprMapping { expr_id: ExprId, context: String },

    /// Non-primitive op received an unexpected number of input expressions.
    #[error("{op} expects exactly {expected} witness expressions, got {got}")]
    NonPrimitiveOpArity {
        op: &'static str,
        expected: String,
        got: usize,
    },

    /// Non-primitive operation referenced by id was not found.
    #[error("Non-primitive operation id {op_id:?} not found")]
    MissingNonPrimitiveOp { op_id: NonPrimitiveOpId },

    /// Non-primitive output indices for an op are malformed (duplicates or gaps).
    #[error("Non-primitive output indices malformed for op {op_id:?}: {details}")]
    MalformedNonPrimitiveOutputs {
        op_id: NonPrimitiveOpId,
        details: String,
    },

    /// Non-primitive operation exists in the builder but was never anchored in the expression DAG,
    /// so the lowerer cannot place it in a well-defined execution order.
    #[error("Non-primitive operation {op_id:?} is not anchored in the expression DAG")]
    UnanchoredNonPrimitiveOp { op_id: NonPrimitiveOpId },

    /// Non-primitive operation rejected by the active policy/profile.
    #[error("Operation {op:?} is not allowed by the current profile")]
    OpNotAllowed { op: NonPrimitiveOpType },

    /// Non-primitive operation is recognized but not implemented in lowering.
    #[error("Operation {op:?} is not implemented in lowering")]
    UnsupportedNonPrimitiveOp { op: NonPrimitiveOpType },

    /// Mismatched non-primitive operation configuration
    #[error("Invalid configuration for operation {op:?}")]
    InvalidNonPrimitiveOpConfiguration { op: NonPrimitiveOpType },

    /// Merkle-path Poseidon rows require a direction bit.
    #[error("PoseidonPerm merkle_path=true requires mmcs_bit")]
    PoseidonMerkleMissingMmcsBit,

    /// Non-merkle Poseidon rows should not have mmcs_bit set.
    #[error("PoseidonPerm merkle_path=false must not have mmcs_bit (it has no effect)")]
    PoseidonNonMerkleWithMmcsBit,

    /// A sequence of expressions of type Witness is missing its filler.
    #[error("Missing hint filler for expression {sequence:?}")]
    MissingWitnessFiller { sequence: Vec<WitnessId> },

    /// A sequence of witness hints has no end.
    #[error("Witness hint without last hint {sequence:?}.")]
    MalformedWitnessHintsSequence { sequence: Vec<WitnessId> },

    /// Witness filler without any hints sequence.
    #[error("Witness filler is missing a witness hints sequence")]
    UnmatchedWitnessFiller {},
}
