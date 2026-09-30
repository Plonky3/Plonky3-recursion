//! Prelude module for common imports.
//!
//! The prelude includes unified recursion and prepared-owner entry points. A trusted
//! owner retains child verifier authority and accepts a caller-supplied statement:
//!
//! ```no_run
//! use p3_recursion::prelude::*;
//! use p3_recursion::builtin_config::KoalaBearD4Poseidon2BinaryConfig as Config;
//! use p3_circuit_prover::{BatchStarkProof, CircuitVerifier};
//! use p3_koala_bear::KoalaBear;
//!
//! fn recurse(
//!     config: Config,
//!     backend: FriRecursionBackendForExt<4>,
//!     child_verifier: CircuitVerifier<Config>,
//!     child_proof: &BatchStarkProof<Config>,
//!     statement: &[KoalaBear],
//! ) -> Result<RecursionOutput<Config>, VerificationError> {
//!     let owner = TrustedPreparedLayer::<Config, Config, BatchOnly, _, 4>::new(
//!         TrustedPreparedSource::BatchStark {
//!             verifier: child_verifier,
//!             proof: child_proof,
//!             statement,
//!         },
//!         config,
//!         backend,
//!         ProveNextLayerParams::default(),
//!     )?;
//!     let output = owner.prove(TrustedPreparedInput::BatchStark {
//!         proof: child_proof,
//!         statement,
//!     })?;
//!     owner.verifier().verify(&output.0, statement).unwrap();
//!     Ok(output)
//! }
//! ```

pub use p3_circuit::{StateTransitionError, StateTransitionLayout};

pub use crate::challenger::{BinaryTower128Challenger, CircuitChallenger};
pub use crate::generation::{GenerationError, PcsGeneration};
pub use crate::pcs::fri::FriVerifierParams;
pub use crate::prepared::{
    PreparedAggregation, PreparedInput, PreparedLayer, PreparedSource, TrustedPreparedAggregation,
    TrustedPreparedInput, TrustedPreparedLayer, TrustedPreparedSource,
};
pub use crate::public_inputs::{
    CommitmentOpening, FriVerifierInputs, PublicInputBuilder, StarkVerifierInputs,
    StarkVerifierInputsBuilder,
};
pub use crate::recursion::{
    BatchOnly, ProveNextLayerParams, RecursionInput, RecursionOutput,
    build_and_prove_aggregation_layer, build_and_prove_next_layer,
};
pub use crate::traits::{
    ComsWithOpeningsTargets, Recursive, RecursiveAir, RecursiveChallenger, RecursiveExtensionMmcs,
    RecursiveMmcs, RecursivePcs,
};
pub use crate::types::{
    CommitmentTargets, OpenedValuesTargets, ProofTargets, RecursiveLagrangeSelectors,
    StarkChallenges,
};
pub use crate::verifier::{ObservableCommitment, VerificationError, verify_p3_uni_proof_circuit};
pub use crate::{
    FriRecursionBackend, FriRecursionBackendForExt, FriRecursionConfig, Poseidon2Config, Target,
};
