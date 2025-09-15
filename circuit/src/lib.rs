#![no_std]
extern crate alloc;

pub mod builder;
pub mod circuit;
pub mod expr;
pub mod op;
pub mod tables;
pub mod transparent;
pub mod types;

// Re-export public API
pub use builder::CircuitBuilder;
pub use circuit::Circuit;
pub use expr::{Expr, ExpressionGraph};
pub use op::{FakeMerklePrivateData, NonPrimitiveOp, NonPrimitiveOpPrivateData, Prim};
pub use tables::{CircuitRunner, FakeMerkleTrace, Traces};
pub use transparent::{
    TransparentBundle, TransparentCommitment, TransparentProvider, TransparentProvingKey,
    TransparentTrace, TransparentTraceInfo, TransparentVerifyingKey,
    setup_default_transparent_indices, setup_transparent_columns,
};
pub use types::{ExprId, NonPrimitiveOpId, WitnessAllocator, WitnessId};
