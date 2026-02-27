#![no_std]
extern crate alloc;
#[cfg(feature = "debugging")]
pub mod alloc_entry;

pub mod builder;
pub mod circuit;
pub mod errors;
pub mod expr;
pub mod op;
pub mod ops;
pub mod policy;
pub mod tables;
pub mod test_utils;
pub mod types;
pub mod utils;

// Re-export public API
#[cfg(feature = "debugging")]
pub use alloc_entry::{AllocationEntry, AllocationType, dump_expr_ids};
pub use builder::{CircuitBuilder, CircuitBuilderError};
pub use circuit::{Circuit, CircuitField, PreprocessedColumns};
pub use errors::CircuitError;
pub use expr::{Expr, ExpressionGraph};
pub use op::{AluOpKind, HintExecutor, NonPrimitiveOpPrivateData, NpoPrivateData, NpoTypeId, Op};
pub use ops::Poseidon2PermOps;
pub use tables::{CircuitRunner, Traces};
pub use types::{ExprId, NonPrimitiveOpId, WitnessAllocator, WitnessId};
