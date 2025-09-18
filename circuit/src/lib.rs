#![no_std]
extern crate alloc;

pub mod builder;
pub mod circuit;
pub mod expr;
pub mod op;
pub mod tables;
pub mod types;
pub mod utils;

// Re-export public API
pub use builder::{CircuitBuilder, CircuitBuilderError};
pub use circuit::Circuit;
pub use expr::{Expr, ExpressionGraph};
pub use op::{NonPrimitiveOp, NonPrimitiveOpPrivateData, Prim};
pub use tables::{CircuitError, CircuitRunner, MerklePrivateData, MerkleTrace, Traces};
pub use types::{ExprId, NonPrimitiveOpId, WitnessAllocator, WitnessId};
