pub mod circuit;
pub mod expr;
pub mod prim;
pub mod program;
pub mod tables;
pub mod types;

// Re-export public API
pub use circuit::Circuit;
pub use expr::{Expr, ExprArena};
pub use prim::{ComplexOp, Prim};
pub use program::{Program, VerifierKey};
pub use tables::{ProverInstance, Traces};
pub use types::{ExprId, WIdx, WitnessAllocator};
