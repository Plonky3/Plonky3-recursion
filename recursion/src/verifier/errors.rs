//! Error types for recursive verification.

use alloc::string::String;

use p3_circuit::{CircuitBuilderError, CircuitError};
use thiserror::Error;

use crate::generation::GenerationError;

/// Errors that can occur during recursive STARK verification.
#[derive(Debug, Error)]
pub enum VerificationError {
    /// The proof structure is invalid (wrong dimensions, missing data, etc.)
    #[error("Invalid proof shape: {0}")]
    InvalidProofShape(String),

    /// ZK randomization is inconsistent (random commitment exists but no opened values)
    #[error("Missing random opened values for existing random commitment")]
    RandomizationError,

    /// Error from the circuit execution layer
    #[error("Circuit error: {0}")]
    Circuit(#[from] CircuitError),

    /// Error from the circuit builder layer
    #[error("Circuit builder error: {0}")]
    CircuitBuilder(#[from] CircuitBuilderError),

    /// Error from challenge generation
    #[error("Generation error: {0}")]
    Generation(#[from] GenerationError),
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;

    use p3_circuit::{CircuitBuilderError, CircuitError};

    use super::*;
    use crate::generation::GenerationError;

    #[test]
    fn test_invalid_proof_shape_display() {
        let msg = VerificationError::InvalidProofShape("bad".into()).to_string();
        assert!(msg.contains("bad") || msg.contains("Invalid"));
    }

    #[test]
    fn test_randomization_error_display() {
        assert!(!VerificationError::RandomizationError.to_string().is_empty());
    }

    #[test]
    fn test_display_contains_descriptive_text() {
        assert!(
            !VerificationError::InvalidProofShape("x".into())
                .to_string()
                .is_empty()
        );
        assert!(!VerificationError::RandomizationError.to_string().is_empty());
        assert!(
            !VerificationError::Circuit(CircuitError::DivisionByZero)
                .to_string()
                .is_empty()
        );
        assert!(
            !VerificationError::CircuitBuilder(CircuitBuilderError::MissingOutput)
                .to_string()
                .is_empty()
        );
        assert!(
            !VerificationError::Generation(GenerationError::MissingParameterError)
                .to_string()
                .is_empty()
        );
    }
}
