pub mod types;
pub mod expr;
pub mod prim;
pub mod program;

// Re-export public API
pub use types::{WIdx, ExprId, WitnessAllocator};
pub use expr::{ExtExpr, ExprArena};
pub use prim::{Prim, ComplexOp};
pub use program::{Program, VerifierKey};