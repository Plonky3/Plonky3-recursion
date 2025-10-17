// #![no_std]
extern crate alloc;

#[cfg(debug_assertions)]
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
#[cfg(debug_assertions)]
pub use alloc_entry::{AllocationEntry, AllocationType};
pub use builder::{CircuitBuilder, CircuitBuilderError};
pub use circuit::{Circuit, CircuitField};
pub use errors::CircuitError;
pub use expr::{Expr, ExpressionGraph};
pub use op::{NonPrimitiveOp, NonPrimitiveOpPrivateData, Prim};
pub use ops::{FriOps, MmcsOps};
pub use tables::{CircuitRunner, MmcsPrivateData, MmcsTrace, Traces};
pub use types::{ExprId, NonPrimitiveOpId, WitnessAllocator, WitnessId};
