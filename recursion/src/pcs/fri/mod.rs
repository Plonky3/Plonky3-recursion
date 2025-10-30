//! FRI for recursive verification.

mod params;
mod targets;
mod verifier;

pub use params::{FriVerifierParams, MAX_QUERY_INDEX_BITS};
pub use targets::{
    BatchOpeningTargets, CommitPhaseProofStepTargets, FriProofTargets, HashProofTargets,
    HashTargets, InputProofTargets, QueryProofTargets, RecExtensionValMmcs, RecValMmcs,
    TwoAdicFriProofTargets, ValMmcsCommitment, Witness,
};
pub use verifier::verify_fri_circuit;
