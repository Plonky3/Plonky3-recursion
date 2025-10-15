use alloc::string::String;

use thiserror::Error;

use crate::op::NonPrimitiveOpType;
use crate::types::NonPrimitiveOpId;
use crate::{CircuitBuilderError, ExprId, WitnessId};

/// Errors that can occur during circuit execution and trace generation.
#[derive(Debug, Error)]
pub enum CircuitError {
    /// Public input length mismatch.
    #[error("Public input length mismatch: expected {expected}, got {got}")]
    PublicInputLengthMismatch { expected: usize, got: usize },

    /// Circuit missing public_rows mapping.
    #[error("Circuit missing public_rows mapping")]
    MissingPublicRowsMapping,

    /// NonPrimitiveOpId out of range.
    #[error("NonPrimitiveOpId {op_id} out of range (circuit has {max_ops} complex ops)")]
    NonPrimitiveOpIdOutOfRange { op_id: u32, max_ops: usize },

    /// Public input not set for a WitnessId.
    #[error("Public input not set for WitnessId({witness_id})")]
    PublicInputNotSet { witness_id: WitnessId },

    /// Witness not set for a WitnessId.
    #[error("Witness not set for WitnessId({witness_id})")]
    WitnessNotSet { witness_id: WitnessId },

    /// WitnessId out of bounds.
    #[error("WitnessId({witness_id}) out of bounds")]
    WitnessIdOutOfBounds { witness_id: WitnessId },

    /// Witness conflict: trying to reassign to a different value.
    #[error(
        "Witness conflict: WitnessId({witness_id}) already set to {existing}, cannot reassign to {new}"
    )]
    WitnessConflict {
        witness_id: WitnessId,
        existing: String,
        new: String,
    },

    /// Witness not set for an index during trace generation.
    #[error("Witness not set for index {index}")]
    WitnessNotSetForIndex { index: usize },

    /// Non-primitive op attempted to read a witness value that was not set.
    #[error("Witness value not set for non-primitive operation {operation_index}")]
    NonPrimitiveOpWitnessNotSet { operation_index: NonPrimitiveOpId },

    /// Missing private data for a non-primitive operation.
    #[error("Missing private data for non-primitive operation {operation_index}")]
    NonPrimitiveOpMissingPrivateData { operation_index: NonPrimitiveOpId },

    /// Division by zero encountered.
    #[error("Division by zero encountered")]
    DivisionByZero,

    /// Invalid bit value in SampleBits bit decomposition (must be 0 or 1).
    #[error(
        "Invalid bit value in SampleBits bit decomposition for WitnessId({input_witness_id}): {bit_value} (must be 0 or 1)"
    )]
    InvalidBitValue {
        input_witness_id: WitnessId,
        bit_value: String,
    },

    /// Bit decomposition doesn't reconstruct to the input value.
    #[error(
        "Bit decomposition for WitnessId({input_witness_id}) doesn't match input: expected {expected}, reconstructed {reconstructed}"
    )]
    BitDecompositionMismatch {
        input_witness_id: WitnessId,
        expected: String,
        reconstructed: String,
    },

    /// Mismatched non-primitive operation configuration
    #[error("Invalid configuration for operation {op:?}")]
    InvalidNonPrimitiveOpConfiguration { op: NonPrimitiveOpType },

    /// Incorrect size of private data provided for a non-primitive operation.
    #[error(
        "Incorrect size of private data provided for operation {op:?}: expected {expected}, got {got}"
    )]
    IncorrectNonPrimitiveOpPrivateDataSize {
        op: NonPrimitiveOpType,
        expected: usize,
        got: usize,
    },

    /// Non primitive private data is not correct
    #[error(
        "Incorrect private data provided for op {op:?} (operation {operation_index}): expected {expected}, got {got}"
    )]
    IncorrectNonPrimitiveOpPrivateData {
        op: NonPrimitiveOpType,
        operation_index: NonPrimitiveOpId,
        expected: String,
        got: String,
    },

    /// ExprId not found.
    #[error("ExprId {expr_id} not found")]
    ExprIdNotFound { expr_id: ExprId },

    /// Invalid Circuit
    #[error("Failed to build circuit: {error}")]
    InvalidCircuit { error: CircuitBuilderError },
}
