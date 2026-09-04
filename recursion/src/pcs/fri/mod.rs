//! FRI for recursive verification.

mod params;
mod targets;
mod verifier;

pub use params::FriVerifierParams;
pub use targets::{
    BatchOpeningTargets, CommitPhaseProofStepTargets, FriProofTargets, HashProofTargets,
    HidingFriProofTargets, HidingHashProofTargets, HidingOpenedValuesTargets, InputProofTargets,
    MerkleCapTargets, MmcsProofTargets, QueryProofTargets, RecExtensionValMmcs,
    RecExtensionValMmcsArity4, RecValHidingMmcs, RecValMmcs, RecValMmcsArity4,
    RecursiveFriInputOpenings, RecursiveMultiProofTargets, TwoAdicFriProofTargets, Witness,
    fri_proof_num_queries,
};
pub use verifier::verify_fri_circuit;
