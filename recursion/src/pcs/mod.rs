//! Polynomial Commitment Scheme (PCS) implementations for recursive verification.

pub mod fri;
pub mod mmcs;

pub use fri::{
    BatchOpeningTargets, CommitPhaseProofStepTargets, FriProofTargets, FriVerifierParams,
    HashProofTargets, InputProofTargets, MAX_QUERY_INDEX_BITS, MerkleCapTargets, QueryProofTargets,
    RecExtensionValMmcs, RecValMmcs, TwoAdicFriProofTargets, Witness, verify_fri_circuit,
};
pub use mmcs::{
    set_fri_mmcs_private_data, verify_batch_circuit, verify_batch_circuit_from_extension_opened,
};
