//! Recursive proof verification for Plonky3 STARKs.

#![no_std]

extern crate alloc;

pub mod challenger;
pub mod generation;
pub mod pcs;
pub mod prelude;
pub mod public_inputs;
pub mod traits;
pub mod types;
pub mod verifier;

pub use challenger::CircuitChallenger;
pub use generation::{
    GenerationError, PcsGeneration, generate_batch_challenges, generate_challenges,
};
pub use pcs::fri::{FriVerifierParams, MAX_QUERY_INDEX_BITS};
pub use public_inputs::{
    BatchStarkVerifierInputsBuilder, CommitmentOpening, FriVerifierInputs, PublicInputBuilder,
    StarkVerifierInputs, StarkVerifierInputsBuilder, construct_batch_stark_verifier_inputs,
    construct_stark_verifier_inputs,
};
pub use traits::{
    Recursive, RecursiveAir, RecursiveChallenger, RecursiveExtensionMmcs, RecursiveMmcs,
    RecursivePcs,
};
pub use types::{
    CommitmentTargets, OpenedValuesTargets, ProofTargets, RecursiveLagrangeSelectors,
    StarkChallenges, Target,
};
pub use verifier::{
    BatchProofTargets, InstanceOpenedValuesTargets, ObservableCommitment, VerificationError,
    verify_batch_circuit, verify_circuit,
};
