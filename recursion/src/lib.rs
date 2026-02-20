//! Recursive proof verification for Plonky3 STARKs.

#![no_std]

extern crate alloc;

pub mod backend;
pub mod challenger;
pub mod generation;
pub mod pcs;
pub mod prelude;
pub mod public_inputs;
pub mod recursion;
pub mod traits;
pub mod types;
pub mod verifier;

/// FRI PCS backend for the unified recursion API. Use with [`prove_next_layer`] and a config implementing [`FriRecursionConfig`].
pub use backend::FriRecursionBackend;
/// Implement for your StarkConfig (or a wrapper holding FRI verifier params) to use [`FriRecursionBackend`].
pub use backend::fri::FriRecursionConfig;
pub use challenger::CircuitChallenger;
pub use generation::{
    GenerationError, PcsGeneration, generate_batch_challenges, generate_challenges,
};
pub use p3_circuit::ops;
pub use p3_circuit::ops::Poseidon2Config;
pub use pcs::fri::{FriVerifierParams, MAX_QUERY_INDEX_BITS};
pub use public_inputs::{
    BatchStarkVerifierInputsBuilder, CommitmentOpening, FriVerifierInputs, PublicInputBuilder,
    StarkVerifierInputs, StarkVerifierInputsBuilder, construct_batch_stark_verifier_inputs,
};
/// Unified recursion API: single entry point for proving the next layer over a uni-stark or batch-stark proof.
pub use recursion::{
    BatchOnly, PcsRecursionBackend, ProveNextLayerParams, RecursionInput, RecursionOutput,
    VerifierCircuitResult, prove_next_layer,
};
pub use traits::{
    Recursive, RecursiveAir, RecursiveChallenger, RecursiveExtensionMmcs, RecursiveMmcs,
    RecursivePcs,
};
pub use types::{
    BatchProofTargets, CommitmentTargets, CommonDataTargets, OpenedValuesTargets, ProofTargets,
    RecursiveLagrangeSelectors, StarkChallenges, Target,
};
pub use verifier::{ObservableCommitment, VerificationError, verify_batch_circuit, verify_circuit};
