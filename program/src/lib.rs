pub mod circuit;
pub mod expr;
pub mod prim;
pub mod program;
pub mod tables;
pub mod types;

// Re-export public API
pub use circuit::Circuit;
pub use expr::{Expr, ExpressionGraph};
pub use prim::{ComplexOp, ComplexOpPrivateData, FakeMerklePrivateData, Prim};
pub use program::Program;
pub use tables::{FakeMerkleTrace, ProgramInstance, Traces};
pub use types::{ComplexOpId, ExprId, WitnessAllocator, WitnessIndex};
