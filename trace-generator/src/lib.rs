pub mod types;
pub mod expr;
pub mod prim;
pub mod program;
pub mod circuit;
pub mod tables;

// Re-export public API
pub use types::{WIdx, ExprId, WitnessAllocator};
pub use expr::{ExtExpr, ExprArena};
pub use prim::{Prim, ComplexOp};
pub use program::{Program, VerifierKey};
pub use circuit::Circuit;
pub use tables::{Traces, ProverInstance};