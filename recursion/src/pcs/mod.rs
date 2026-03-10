//! Polynomial Commitment Scheme (PCS) implementations for recursive verification.

pub mod fri;
pub mod mmcs;

pub use fri::{
    BatchOpeningTargets, CommitPhaseProofStepTargets, FriProofTargets, FriVerifierParams,
    HashProofTargets, HidingFriProofTargets, HidingOpenedValuesTargets, InputProofTargets,
    MerkleCapTargets, QueryProofTargets, RecExtensionValMmcs, RecValMmcs, TwoAdicFriProofTargets,
    Witness, verify_fri_circuit,
};
pub use mmcs::{
    extract_4ary_sibling_values_from_fri_proof, set_fri_mmcs_private_data,
    set_hiding_fri_mmcs_private_data, verify_batch_circuit, verify_batch_circuit_4ary,
    verify_batch_circuit_from_extension_opened, verify_batch_circuit_from_extension_opened_4ary,
};
