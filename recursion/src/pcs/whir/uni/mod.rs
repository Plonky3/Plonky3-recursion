//! Bridge from WHIR's multilinear PCS to the univariate STARK machinery.

pub mod bridge;
pub mod pcs;
pub mod plan;

pub use bridge::{univariate_eq_point, univariate_eq_point_circuit};
pub use pcs::{WhirUniPcs, WhirUniPcsError, WhirUniProof, WhirUniProverData};
pub use plan::{StackedPlacement, StackedPlan, StackedSelector, padded_arity};
