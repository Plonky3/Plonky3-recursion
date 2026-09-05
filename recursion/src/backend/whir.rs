//! WHIR PCS backend for the unified recursion API.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_circuit_prover::batch_stark_prover::{
    RecomposeAirBuilder, RecomposeProver, poseidon2_air_builders_for_configs,
    poseidon2_preprocessor, recompose_preprocessor,
};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::config::StarkField;
use p3_circuit_prover::field_params::ExtractBinomialW;
use p3_circuit_prover::{
    ConstraintProfile, Poseidon2Preprocessor, Poseidon2Prover, RecomposePreprocessor, TableProver,
};
use p3_commit::Pcs;
use p3_field::extension::BinomiallyExtendable;
use p3_field::{
    Algebra, BasedVectorSpace, ExtensionField, PrimeCharacteristicRing, PrimeField64, TwoAdicField,
};
use p3_lookup::logup::LogUpGadget;
use p3_uni_stark::{StarkGenericConfig, SymbolicExpressionExt, Val};

use crate::backend::transcript::replay_recursion_input_transcript;
use crate::generation::OpeningTranscript;
use crate::ops::Poseidon2Config;
use crate::public_inputs::StarkVerifierInputsBuilder;
use crate::recursion::{PcsRecursionBackend, RecursionInput, VerifierCircuitResult};
use crate::traits::RecursiveAir;
use crate::verifier::{ObservableCommitment, VerificationError, verify_p3_uni_proof_circuit};
use crate::{ChallengerPermConfig, Recursive, RecursivePcs};

/// Config that uses WHIR with Merkle-tree MMCS. Implement this for your `StarkGenericConfig`
/// to use [`WhirRecursionBackend`]. Mirrors [`crate::backend::fri::FriRecursionConfig`]'s shape
/// exactly — see that trait's own doc comments for the rationale behind each method, which
/// applies here unchanged.
pub trait WhirRecursionConfig: StarkGenericConfig + Sized
where
    Self::Pcs: RecursivePcs<
            Self,
            Self::InputProof,
            Self::OpeningProof,
            Self::Commitment,
            <Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Domain,
        >,
{
    /// Commitment type used in the verifier circuit (e.g. `MerkleCapTargets`).
    type Commitment: Recursive<
            Self::Challenge,
            Input = <Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Commitment,
        > + Clone
        + ObservableCommitment;

    /// Input proof type for the PCS (unit type for WHIR, which needs no per-opening input proof).
    type InputProof: Recursive<Self::Challenge>;

    /// Opening proof type used in the verifier circuit (`WhirUniProofTargets`).
    type OpeningProof: Recursive<
            Self::Challenge,
            Input = <Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Proof,
        >;

    /// Raw WHIR opening proof type (value type, not circuit targets). Used to set private data.
    type RawOpeningProof;

    /// Invoke a closure with the WHIR opening proof extracted from the recursion input.
    fn with_whir_opening_proof<'a, A, R>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> R,
    ) -> R
    where
        A: RecursiveAir<Val<Self>, Self::Challenge, LogUpGadget>;

    /// Prepare the circuit for verification (e.g. enable challenger permutation and NPOs).
    fn prepare_circuit_for_verification(
        &self,
        circuit: &mut CircuitBuilder<Self::Challenge>,
    ) -> Result<(), VerificationError>;

    /// Return the PCS verifier params. The config must hold these and return a reference.
    #[allow(clippy::type_complexity)]
    fn pcs_verifier_params(
        &self,
    ) -> &<Self::Pcs as RecursivePcs<
        Self,
        Self::InputProof,
        Self::OpeningProof,
        Self::Commitment,
        <Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Domain,
    >>::VerifierParams;

    /// Set WHIR Merkle path private data on the runner.
    ///
    /// A WHIR proof authenticates all of a commitment's queries with a pruned multiproof, the
    /// same way FRI's do, while the in-circuit MMCS gadget walks one full authentication path
    /// per query. Implement this by restoring those per-query paths with
    /// [`crate::pcs::whir::uni::restore_whir_recursion_paths`], instantiated with your concrete
    /// MMCS/hasher types, then handing each round's paths to
    /// [`crate::pcs::set_whir_mmcs_private_data`] — mirroring
    /// [`crate::backend::fri::FriRecursionConfig::set_fri_private_data`]'s own doc comment,
    /// which describes the identical pattern for FRI.
    ///
    /// `transcript` is this proof's verifier transcript replayed off-circuit, in the state
    /// [`OpeningTranscript`] documents — produced by
    /// [`crate::backend::replay_recursion_input_transcript`], which the generic backend calls
    /// before invoking this method.
    fn set_whir_private_data(
        config: &Self,
        runner: &mut CircuitRunner<'_, Self::Challenge>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
        transcript: OpeningTranscript<Self>,
    ) -> Result<(), &'static str>;
}

/// WHIR-based recursion backend, holding the challenger permutation config.
#[derive(Clone)]
pub struct WhirRecursionBackend<
    const WIDTH: usize = 16,
    const RATE: usize = 8,
    C: ChallengerPermConfig = Poseidon2Config,
> {
    /// Permutation configuration used for the Fiat-Shamir challenger permutation circuit.
    pub challenger_perm_config: C,
}

impl<const WIDTH: usize, const RATE: usize, C: ChallengerPermConfig>
    WhirRecursionBackend<WIDTH, RATE, C>
{
    /// Create a new backend with the given challenger permutation configuration.
    pub const fn new(challenger_perm_config: C) -> Self {
        Self {
            challenger_perm_config,
        }
    }

    /// Tag this backend for a fixed batch/extension degree `D` (only `4` is supported today).
    pub const fn for_extension_degree<const D: usize>(
        self,
    ) -> WhirRecursionBackendForExt<D, WIDTH, RATE, C> {
        WhirRecursionBackendForExt(self)
    }
}

/// WHIR recursion backend tagged with batch/extension field degree `D` (only `4` is supported).
#[derive(Clone)]
pub struct WhirRecursionBackendForExt<
    const D: usize,
    const WIDTH: usize = 16,
    const RATE: usize = 8,
    C: ChallengerPermConfig = Poseidon2Config,
>(
    /// The inner backend holding the challenger permutation config.
    pub(crate) WhirRecursionBackend<WIDTH, RATE, C>,
);

/// Verifier result from the WHIR backend: the uni-stark builder + op_ids. Unlike an `FRI`-style
/// result, this does NOT cache restored Merkle paths — `set_private_data` derives them itself by
/// calling `SC::set_whir_private_data`, exactly mirroring how FRI's `FriVerifierResult` also
/// carries nothing PCS-specific beyond the builder and op_ids.
pub struct WhirVerifierResult<SC>
where
    SC: WhirRecursionConfig,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
{
    builder: StarkVerifierInputsBuilder<SC, SC::Commitment, SC::OpeningProof>,
    op_ids: Vec<NonPrimitiveOpId>,
}

impl<SC, A> VerifierCircuitResult<SC, A> for WhirVerifierResult<SC>
where
    SC: WhirRecursionConfig,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    Val<SC>: PrimeField64,
    SC::Challenge: BasedVectorSpace<Val<SC>> + From<Val<SC>>,
{
    fn pack_public_inputs(
        &self,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<Vec<SC::Challenge>, VerificationError> {
        match prev {
            RecursionInput::UniStark {
                proof,
                public_inputs,
                preprocessed_commit,
                ..
            } => Ok(self
                .builder
                .pack_public_values(public_inputs, proof, preprocessed_commit)),
            RecursionInput::BatchStark { .. } => Err(VerificationError::InvalidProofShape(
                "WhirRecursionBackend does not yet support batch-STARK inputs".to_string(),
            )),
        }
    }

    fn pack_private_inputs(
        &self,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<Vec<SC::Challenge>, VerificationError> {
        match prev {
            RecursionInput::UniStark { proof, .. } => Ok(self.builder.pack_private_values(proof)),
            RecursionInput::BatchStark { .. } => Err(VerificationError::InvalidProofShape(
                "WhirRecursionBackend does not yet support batch-STARK inputs".to_string(),
            )),
        }
    }

    fn op_ids(&self) -> &[NonPrimitiveOpId] {
        &self.op_ids
    }
}

impl<SC, A, const WIDTH: usize, const RATE: usize, C> PcsRecursionBackend<SC, A, 4>
    for WhirRecursionBackendForExt<4, WIDTH, RATE, C>
where
    SC: WhirRecursionConfig + Send + Sync + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    C: ChallengerPermConfig + Copy + 'static,
    Val<SC>: PrimeField64 + BinomiallyExtendable<4> + StarkField + TwoAdicField,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + PrimeCharacteristicRing
        + ExtractBinomialW<Val<SC>>
        + TwoAdicField,
    Poseidon2Preprocessor: NpoPreprocessor<Val<SC>>,
    RecomposePreprocessor: NpoPreprocessor<Val<SC>>,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain: Clone,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        From<p3_uni_stark::SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
{
    type VerifierResult = WhirVerifierResult<SC>;

    fn prepare_circuit(
        &self,
        config: &SC,
        circuit: &mut CircuitBuilder<SC::Challenge>,
    ) -> Result<(), VerificationError> {
        config.prepare_circuit_for_verification(circuit)
    }

    fn build_verifier_circuit(
        &self,
        prev: &RecursionInput<'_, SC, A>,
        config: &SC,
        circuit: &mut CircuitBuilder<SC::Challenge>,
    ) -> Result<Self::VerifierResult, VerificationError> {
        match prev {
            RecursionInput::UniStark {
                proof,
                air,
                public_inputs,
                preprocessed_commit,
            } => {
                let verifier_inputs =
                    StarkVerifierInputsBuilder::<SC, SC::Commitment, SC::OpeningProof>::allocate(
                        circuit,
                        proof,
                        preprocessed_commit.as_ref(),
                        public_inputs.len(),
                    );
                let op_ids = verify_p3_uni_proof_circuit::<
                    A,
                    SC,
                    SC::Commitment,
                    SC::InputProof,
                    SC::OpeningProof,
                    _,
                    WIDTH,
                    RATE,
                >(
                    config,
                    air,
                    circuit,
                    &verifier_inputs.proof_targets,
                    &verifier_inputs.air_public_targets,
                    &verifier_inputs.preprocessed_commit,
                    config.pcs_verifier_params(),
                    self.0.challenger_perm_config,
                )?;
                Ok(WhirVerifierResult {
                    builder: verifier_inputs,
                    op_ids,
                })
            }
            RecursionInput::BatchStark { .. } => Err(VerificationError::InvalidProofShape(
                "WhirRecursionBackend does not yet support batch-STARK inputs".to_string(),
            )),
        }
    }

    fn set_private_data(
        &self,
        config: &SC,
        runner: &mut CircuitRunner<'_, SC::Challenge>,
        op_ids: &[NonPrimitiveOpId],
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<(), &'static str> {
        match prev {
            RecursionInput::UniStark { .. } => {
                let transcript = replay_recursion_input_transcript(config, prev, &[])
                    .map_err(|_| "Failed to replay the input proof's verifier transcript")?;
                SC::with_whir_opening_proof(prev, move |opening_proof| {
                    SC::set_whir_private_data(config, runner, op_ids, opening_proof, transcript)
                })
            }
            RecursionInput::BatchStark { .. } => {
                Err("WhirRecursionBackend does not yet support batch-STARK inputs")
            }
        }
    }

    fn non_primitive_preprocessors(&self) -> Vec<Box<dyn NpoPreprocessor<Val<SC>>>> {
        vec![
            poseidon2_preprocessor::<Val<SC>>(),
            recompose_preprocessor::<Val<SC>>(true),
        ]
    }

    fn non_primitive_provers(&self, ext_degree: usize) -> Vec<Box<dyn TableProver<SC>>> {
        if ext_degree == 4 {
            let mut provers: Vec<Box<dyn TableProver<SC>>> = vec![Box::new(Poseidon2Prover::new(
                self.0
                    .challenger_perm_config
                    .as_poseidon2()
                    .copied()
                    .unwrap_or_else(|| {
                        panic!("WhirRecursionBackend requires a Poseidon2 challenger config")
                    }),
                ConstraintProfile::Standard,
            ))];
            provers.push(Box::new(RecomposeProver::<4>::new(1, true)));
            provers
        } else {
            Vec::new()
        }
    }

    fn non_primitive_air_builders(&self) -> Vec<Box<dyn NpoAirBuilder<SC, 4>>> {
        let challenger = self
            .0
            .challenger_perm_config
            .as_poseidon2()
            .copied()
            .unwrap_or_else(|| {
                panic!("WhirRecursionBackend requires a Poseidon2 challenger config")
            });
        let mut builders = poseidon2_air_builders_for_configs::<SC, 4>(vec![challenger]);
        builders.push(Box::new(RecomposeAirBuilder::<4>::new(1, true)));
        builders
    }
}
