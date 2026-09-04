//! Bridge from WHIR's multilinear PCS to the univariate STARK machinery.

pub mod bridge;
pub mod circuit;
pub mod pcs;
pub mod plan;
pub mod recursive_pcs;
pub mod targets;

pub use bridge::{univariate_eq_point, univariate_eq_point_circuit};
pub use circuit::{MatrixOpenings, RoundClaims, build_round_claims};
pub use pcs::{WhirUniPcs, WhirUniPcsError, WhirUniProof, WhirUniProverData};
pub use plan::{StackedPlacement, StackedPlan, StackedSelector, padded_arity};
pub use recursive_pcs::WhirUniVerifierParams;
pub use targets::{WhirRoundTargets, WhirUniProofTargets, packed_digest_len};
