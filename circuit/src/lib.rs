//! Build and run field-generic circuits for the Plonky3 batch STARK prover.
//!
//! [`CircuitBuilder`] defines operations and public inputs. A built [`Circuit`]
//! creates a runner that evaluates witnesses and emits table traces.

#![no_std]
extern crate alloc;
#[cfg(feature = "debugging")]
pub mod alloc_entry;
#[cfg(feature = "debugging")]
pub mod provenance;

pub mod builder;
pub mod circuit;
#[cfg(feature = "debugging")]
pub mod diagnostics;
pub mod errors;
pub mod expr;
pub mod ops;
pub mod statement;
pub mod symbolic;
pub mod tables;
pub mod test_utils;
pub mod types;

// Re-export public API
#[cfg(feature = "debugging")]
pub use alloc_entry::{AllocationEntry, AllocationLog, AllocationType};
pub use builder::{
    CircuitBuilder, CircuitBuilderError, NonPrimitiveOperationData, NpoCircuitPlugin,
    NpoLoweringContext, VerifiedStatementTargets,
};
pub use circuit::{Circuit, PreprocessedColumns};
#[cfg(feature = "debugging")]
pub use diagnostics::{
    CircuitDiagnostic, CompiledOpKind, CompiledOperation, DiagnosticPhase, DiagnosticSource,
};
pub use errors::CircuitError;
pub use expr::Expr;
pub use ops::{AluOpKind, NpoPrivateData, NpoTypeId, Op, PreprocessedWriter};
#[cfg(feature = "debugging")]
pub use provenance::CircuitProvenance;
pub use statement::{
    AggregationStatementLayout, StateTransitionError, StateTransitionLayout, StatementError,
    StatementExport, StatementField, StatementSchema,
};
pub use tables::{CircuitRunner, Traces};
pub use types::{ExprId, NonPrimitiveOpId, WitnessId};
