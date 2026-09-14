//! FRI for recursive verification.

mod context;
mod params;
mod targets;
mod verifier;

pub use context::{ValidatedFriContext, validate_fri_context};
pub use params::{FriInputError, FriVerifierParams, NativeFriParams};
pub use targets::{
    BatchOpeningTargets, CommitPhaseProofStepTargets, FriProofTargets, HashProofTargets,
    HidingFriProofTargets, HidingHashProofTargets, HidingOpenedValuesTargets, InputProofTargets,
    MerkleCapTargets, MmcsProofTargets, PreparedRecursiveFriInputOpenings,
    PreparedRecursiveMultiProofTargets, QueryProofTargets, RecExtensionValMmcs,
    RecExtensionValMmcsArity4, RecValHidingMmcs, RecValMmcs, RecValMmcsArity4,
    RecursiveFriInputOpenings, RecursiveMultiProofTargets, TwoAdicFriProofTargets, Witness,
    fri_proof_num_queries,
};
pub(crate) use verifier::commitment_cap_rows_from_lifted;
pub use verifier::verify_fri_circuit;
