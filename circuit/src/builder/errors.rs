use alloc::string::String;

use thiserror::Error;

use crate::ExprId;
use crate::ops::NpoTypeId;
use crate::types::NonPrimitiveOpId;

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
    OpNotAllowed { op: NpoTypeId },

    /// Non-primitive operation is recognized but not implemented in lowering.
    #[error("Operation {op:?} is not implemented in lowering")]
    UnsupportedNonPrimitiveOp { op: NpoTypeId },

    /// Mismatched non-primitive operation configuration
    #[error("Invalid configuration for operation {op:?}")]
    InvalidNonPrimitiveOpConfiguration { op: NpoTypeId },

    /// Merkle-path Poseidon2 rows require a direction bit.
    #[error("Poseidon2Perm merkle_path=true requires mmcs_bit")]
    Poseidon2MerkleMissingMmcsBit,

    /// Non-merkle Poseidon2 rows should not have mmcs_bit set.
    #[error("Poseidon2Perm merkle_path=false must not have mmcs_bit (it has no effect)")]
    Poseidon2NonMerkleWithMmcsBit,

    /// Arity-4 compression Merkle rows require a second direction bit.
    #[error("Poseidon2Perm arity-4 merkle_path=true requires mmcs_bit2")]
    Poseidon2Arity4MissingMmcsBit2,

    /// Only arity-4 compression Merkle rows may set the second direction bit.
    #[error("Poseidon2Perm mmcs_bit2 is only valid on arity-4 merkle_path=true rows")]
    Poseidon2UnexpectedMmcsBit2,

    /// Poseidon2 configuration mismatch.
    #[error("Poseidon2 config mismatch: expected {expected}, got {got}")]
    Poseidon2ConfigMismatch { expected: String, got: String },

    /// Merkle-path Poseidon1 rows require a direction bit.
    #[error("Poseidon1Perm merkle_path=true requires mmcs_bit")]
    Poseidon1MerkleMissingMmcsBit,

    /// Non-merkle Poseidon1 rows should not have mmcs_bit set.
    #[error("Poseidon1Perm merkle_path=false must not have mmcs_bit (it has no effect)")]
    Poseidon1NonMerkleWithMmcsBit,

    /// Poseidon1 configuration mismatch.
    #[error("Poseidon1 config mismatch: expected {expected}, got {got}")]
    Poseidon1ConfigMismatch { expected: String, got: String },

    /// Requested bit length exceeds the maximum allowed for binary decomposition.
    #[error("Too many bits for binary decomposition: expected at most {expected}, got {n_bits}")]
    BinaryDecompositionTooManyBits { expected: usize, n_bits: usize },

    /// Missing output
    #[error("An output was expected but none was given")]
    MissingOutput,

    /// Duplicate tag: a tag with this name was already registered.
    #[error("Duplicate tag: '{tag}' is already registered")]
    DuplicateTag { tag: String },

    /// Wrong batch size passed to recursive MMCS verifier: expected one length, got another.
    #[error("Wrong batch size: expected {expected}, got {got}")]
    WrongBatchSize { expected: usize, got: usize },

    /// Failed to format openings for MMCS preprocessing; preserves some context.
    #[error("Failed to format openings for operation {op:?}: {details}")]
    FormatOpeningsFailed { op: NpoTypeId, details: String },

    /// Invalid dimension: expected a specific number of elements.
    #[error("Invalid dimension: expected {expected}, got {actual}")]
    InvalidDimension { expected: usize, actual: usize },
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use super::*;
    use crate::ExprId;
    use crate::ops::NpoTypeId;
    use crate::types::NonPrimitiveOpId;

    #[test]
    fn unit_variants_display_non_empty() {
        assert!(
            !CircuitBuilderError::Poseidon2MerkleMissingMmcsBit
                .to_string()
                .is_empty()
        );
        assert!(
            !CircuitBuilderError::Poseidon2NonMerkleWithMmcsBit
                .to_string()
                .is_empty()
        );
        assert!(
            !CircuitBuilderError::Poseidon2Arity4MissingMmcsBit2
                .to_string()
                .is_empty()
        );
        assert!(
            !CircuitBuilderError::Poseidon2UnexpectedMmcsBit2
                .to_string()
                .is_empty()
        );
        assert!(
            !CircuitBuilderError::Poseidon1MerkleMissingMmcsBit
                .to_string()
                .is_empty()
        );
        assert!(
            !CircuitBuilderError::Poseidon1NonMerkleWithMmcsBit
                .to_string()
                .is_empty()
        );
        assert!(!CircuitBuilderError::MissingOutput.to_string().is_empty());
    }

    #[test]
    fn missing_expr_mapping_display() {
        let err = CircuitBuilderError::MissingExprMapping {
            expr_id: ExprId::ZERO,
            context: "test_context".into(),
        };
        let s = err.to_string();
        assert!(!s.is_empty());
        assert!(s.contains("test_context"));
    }

    #[test]
    fn non_primitive_op_arity_display() {
        let err = CircuitBuilderError::NonPrimitiveOpArity {
            op: "some_op",
            expected: "2".into(),
            got: 3,
        };
        let s = err.to_string();
        assert!(!s.is_empty());
        assert!(s.contains("some_op"));
    }

    #[test]
    fn missing_non_primitive_op_display() {
        let err = CircuitBuilderError::MissingNonPrimitiveOp {
            op_id: NonPrimitiveOpId(0),
        };
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn malformed_non_primitive_outputs_display() {
        let err = CircuitBuilderError::MalformedNonPrimitiveOutputs {
            op_id: NonPrimitiveOpId(1),
            details: "gap at index 2".into(),
        };
        let s = err.to_string();
        assert!(!s.is_empty());
        assert!(s.contains("gap at index 2"));
    }

    #[test]
    fn unanchored_non_primitive_op_display() {
        let err = CircuitBuilderError::UnanchoredNonPrimitiveOp {
            op_id: NonPrimitiveOpId(42),
        };
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn npo_type_id_variants_display_non_empty() {
        let op = NpoTypeId::new("test_op");
        assert!(
            !CircuitBuilderError::OpNotAllowed { op: op.clone() }
                .to_string()
                .is_empty()
        );
        assert!(
            !CircuitBuilderError::UnsupportedNonPrimitiveOp { op: op.clone() }
                .to_string()
                .is_empty()
        );
        assert!(
            !CircuitBuilderError::InvalidNonPrimitiveOpConfiguration { op: op.clone() }
                .to_string()
                .is_empty()
        );
        assert!(
            !CircuitBuilderError::FormatOpeningsFailed {
                op,
                details: "some detail".into(),
            }
            .to_string()
            .is_empty()
        );
    }

    #[test]
    fn simple_field_variants_display_non_empty() {
        assert!(
            !CircuitBuilderError::Poseidon2ConfigMismatch {
                expected: "cfg_a".into(),
                got: "cfg_b".into(),
            }
            .to_string()
            .is_empty()
        );
        assert!(
            !CircuitBuilderError::Poseidon1ConfigMismatch {
                expected: "cfg_a".into(),
                got: "cfg_b".into(),
            }
            .to_string()
            .is_empty()
        );
        assert!(
            !CircuitBuilderError::BinaryDecompositionTooManyBits {
                expected: 32,
                n_bits: 64,
            }
            .to_string()
            .is_empty()
        );
        assert!(
            !CircuitBuilderError::DuplicateTag {
                tag: "my_tag".into()
            }
            .to_string()
            .is_empty()
        );
        assert!(
            !CircuitBuilderError::WrongBatchSize {
                expected: 4,
                got: 8
            }
            .to_string()
            .is_empty()
        );
        assert!(
            !CircuitBuilderError::InvalidDimension {
                expected: 3,
                actual: 5,
            }
            .to_string()
            .is_empty()
        );
    }

    #[test]
    fn all_display_non_empty() {
        let errors = [
            CircuitBuilderError::MissingExprMapping {
                expr_id: ExprId::ZERO,
                context: "ctx".into(),
            },
            CircuitBuilderError::NonPrimitiveOpArity {
                op: "op",
                expected: "1".into(),
                got: 0,
            },
            CircuitBuilderError::MissingNonPrimitiveOp {
                op_id: NonPrimitiveOpId(0),
            },
            CircuitBuilderError::MalformedNonPrimitiveOutputs {
                op_id: NonPrimitiveOpId(0),
                details: "d".into(),
            },
            CircuitBuilderError::UnanchoredNonPrimitiveOp {
                op_id: NonPrimitiveOpId(0),
            },
            CircuitBuilderError::Poseidon2MerkleMissingMmcsBit,
            CircuitBuilderError::Poseidon2NonMerkleWithMmcsBit,
            CircuitBuilderError::Poseidon2Arity4MissingMmcsBit2,
            CircuitBuilderError::Poseidon2UnexpectedMmcsBit2,
            CircuitBuilderError::Poseidon2ConfigMismatch {
                expected: "a".into(),
                got: "b".into(),
            },
            CircuitBuilderError::Poseidon1MerkleMissingMmcsBit,
            CircuitBuilderError::Poseidon1NonMerkleWithMmcsBit,
            CircuitBuilderError::Poseidon1ConfigMismatch {
                expected: "a".into(),
                got: "b".into(),
            },
            CircuitBuilderError::BinaryDecompositionTooManyBits {
                expected: 8,
                n_bits: 16,
            },
            CircuitBuilderError::MissingOutput,
            CircuitBuilderError::DuplicateTag { tag: "t".into() },
            CircuitBuilderError::WrongBatchSize {
                expected: 1,
                got: 2,
            },
            CircuitBuilderError::InvalidDimension {
                expected: 1,
                actual: 2,
            },
        ];
        for err in &errors {
            assert!(!err.to_string().is_empty(), "empty display for {err:?}");
        }
        // NpoTypeId variants (not Clone, so constructed separately)
        assert!(
            !CircuitBuilderError::OpNotAllowed {
                op: NpoTypeId::new("x"),
            }
            .to_string()
            .is_empty()
        );
        assert!(
            !CircuitBuilderError::UnsupportedNonPrimitiveOp {
                op: NpoTypeId::new("x"),
            }
            .to_string()
            .is_empty()
        );
        assert!(
            !CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                op: NpoTypeId::new("x"),
            }
            .to_string()
            .is_empty()
        );
        assert!(
            !CircuitBuilderError::FormatOpeningsFailed {
                op: NpoTypeId::new("x"),
                details: "d".into(),
            }
            .to_string()
            .is_empty()
        );
    }

    #[test]
    fn debug_non_empty() {
        let s = alloc::format!("{:?}", CircuitBuilderError::Poseidon2MerkleMissingMmcsBit);
        assert!(!s.is_empty());
    }
}
