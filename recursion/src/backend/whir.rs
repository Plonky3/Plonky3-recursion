//! WHIR PCS backend for the unified recursion API.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};

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
use crate::pcs::whir::uni::WhirUniVerifierParams;
use crate::prepared::input::{capture_builtin_input_contract, validate_builtin_prepared_input};
use crate::prepared::{PreparedInput, PreparedPcsRecursionBackend};
use crate::public_inputs::{BatchStarkVerifierInputsBuilder, StarkVerifierInputsBuilder};
use crate::recursion::{PcsRecursionBackend, RecursionInput, VerifierCircuitResult};
use crate::traits::{PreparedRecursive, RecursiveAir};
use crate::verifier::{
    ObservableCommitment, VerificationError, verify_p3_batch_proof_circuit,
    verify_p3_uni_proof_circuit,
};
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
///
/// `C` is bounded by [`ChallengerPermConfig`], which
/// [`crate::ops::Poseidon1Config`] also satisfies, but this backend only supports Poseidon2:
/// its non-primitive provers and AIR builders are Poseidon2 tables, so a non-Poseidon2 `C`
/// panics in [`PcsRecursionBackend::non_primitive_provers`] and
/// [`PcsRecursionBackend::non_primitive_air_builders`].
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

/// Poseidon2 table configs for the challenger's permutation shape: the challenger's own table
/// first, then the table its MMCS and compression rows share. WHIR's MMCS path verification
/// always runs the challenger's own permutation shape, so the two are always shared here (unlike
/// [`crate::backend::fri::FriRecursionBackend`], which can disable sharing for mixed-shape
/// circuits — nothing in this backend's scope needs that).
///
/// A base-field (`D == 1`) challenger has no dedicated table — the compact D=1 layout binds its
/// sponge capacity on the shared table already — so only the shared entry is returned.
fn poseidon2_challenger_shape_configs(config: Poseidon2Config) -> Vec<Poseidon2Config> {
    if config.d() < 2 {
        return vec![config];
    }
    vec![config.for_challenger(), config]
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

/// Verifier result from the WHIR backend: either the uni-stark or the batch-stark builder, plus
/// op_ids. `set_private_data` derives restored Merkle paths itself by calling
/// `SC::set_whir_private_data`, so this type carries nothing PCS-specific beyond the builder and
/// op_ids, exactly mirroring [`crate::backend::fri::FriVerifierResult`]'s shape.
pub enum WhirVerifierResult<SC>
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
    /// Result for a single-instance (uni-STARK) input proof.
    UniStark(
        StarkVerifierInputsBuilder<SC, SC::Commitment, SC::OpeningProof>,
        Vec<NonPrimitiveOpId>,
    ),
    /// Result for a batch-STARK input proof.
    BatchStark(
        BatchStarkVerifierInputsBuilder<SC, SC::Commitment, SC::OpeningProof>,
        Vec<NonPrimitiveOpId>,
    ),
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
        match (self, prev) {
            (
                Self::UniStark(builder, _),
                RecursionInput::UniStark {
                    proof,
                    public_inputs,
                    preprocessed_commit,
                    ..
                },
            ) => Ok(builder.pack_public_values(public_inputs, proof, preprocessed_commit)),
            (
                Self::BatchStark(builder, _),
                RecursionInput::BatchStark {
                    proof,
                    common_data,
                    table_public_inputs,
                },
            ) => Ok(builder.pack_public_values(table_public_inputs, &proof.proof, common_data)),
            _ => Err(VerificationError::InvalidProofShape(
                "RecursionInput variant does not match verifier result".to_string(),
            )),
        }
    }

    fn pack_private_inputs(
        &self,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<Vec<SC::Challenge>, VerificationError> {
        match (self, prev) {
            (Self::UniStark(builder, _), RecursionInput::UniStark { proof, .. }) => {
                Ok(builder.pack_private_values(proof))
            }
            (Self::BatchStark(builder, _), RecursionInput::BatchStark { proof, .. }) => {
                Ok(builder.pack_private_values(&proof.proof))
            }
            _ => Err(VerificationError::InvalidProofShape(
                "RecursionInput variant does not match verifier result".to_string(),
            )),
        }
    }

    fn op_ids(&self) -> &[NonPrimitiveOpId] {
        match self {
            Self::UniStark(_, ids) | Self::BatchStark(_, ids) => ids,
        }
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
            VerifierParams = WhirUniVerifierParams<Val<SC>>,
        >,
{
    type VerifierResult = WhirVerifierResult<SC>;

    /// # Errors
    /// Returns [`VerificationError::InvalidProofShape`] when the config's
    /// [`WhirUniVerifierParams::permutation_config`] is `None`, the arithmetic-only mode that
    /// skips in-circuit MMCS verification entirely; a recursion layer built that way would
    /// accept WHIR openings to arbitrary values.
    fn prepare_circuit(
        &self,
        config: &SC,
        circuit: &mut CircuitBuilder<SC::Challenge>,
    ) -> Result<(), VerificationError> {
        if config.pcs_verifier_params().permutation_config.is_none() {
            return Err(VerificationError::InvalidProofShape(
                "WhirRecursionBackend requires a sound (Some) permutation_config — None is an \
                 unsound, arithmetic-only test mode that skips in-circuit MMCS verification"
                    .to_string(),
            ));
        }
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
                Ok(WhirVerifierResult::UniStark(verifier_inputs, op_ids))
            }
            RecursionInput::BatchStark {
                proof,
                common_data,
                table_public_inputs: _,
            } => {
                if proof.ext_degree != 4 {
                    return Err(VerificationError::InvalidProofShape(format!(
                        "WhirRecursionBackend supports batch proofs of ext_degree 4, got {}",
                        proof.ext_degree
                    )));
                }
                let provers =
                    PcsRecursionBackend::<SC, A, 4>::non_primitive_provers(self, proof.ext_degree);
                let lookup_gadget = LogUpGadget::new();
                let (verifier_inputs, op_ids) = verify_p3_batch_proof_circuit::<
                    SC,
                    SC::Commitment,
                    SC::InputProof,
                    SC::OpeningProof,
                    _,
                    _,
                    WIDTH,
                    RATE,
                    4,
                >(
                    config,
                    circuit,
                    proof,
                    config.pcs_verifier_params(),
                    common_data,
                    &lookup_gadget,
                    self.0.challenger_perm_config,
                    &provers,
                )?;
                Ok(WhirVerifierResult::BatchStark(verifier_inputs, op_ids))
            }
        }
    }

    fn set_private_data(
        &self,
        config: &SC,
        runner: &mut CircuitRunner<'_, SC::Challenge>,
        op_ids: &[NonPrimitiveOpId],
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<(), &'static str> {
        // The same plugin list `build_verifier_circuit` used, so the transcript is replayed
        // against the AIRs the circuit was built for.
        let provers = match prev {
            RecursionInput::BatchStark { proof, .. } => {
                PcsRecursionBackend::<SC, A, 4>::non_primitive_provers(self, proof.ext_degree)
            }
            RecursionInput::UniStark { .. } => Vec::new(),
        };
        let transcript = replay_recursion_input_transcript(config, prev, &provers)
            .map_err(|_| "Failed to replay the input proof's verifier transcript")?;
        SC::with_whir_opening_proof(prev, move |opening_proof| {
            SC::set_whir_private_data(config, runner, op_ids, opening_proof, transcript)
        })
    }

    fn non_primitive_preprocessors(&self) -> Vec<Box<dyn NpoPreprocessor<Val<SC>>>> {
        vec![
            poseidon2_preprocessor::<Val<SC>>(),
            recompose_preprocessor::<Val<SC>>(true),
        ]
    }

    fn non_primitive_provers(&self, ext_degree: usize) -> Vec<Box<dyn TableProver<SC>>> {
        if ext_degree == 4 {
            let challenger = self
                .0
                .challenger_perm_config
                .as_poseidon2()
                .copied()
                .unwrap_or_else(|| {
                    panic!("WhirRecursionBackend requires a Poseidon2 challenger config")
                });
            let mut provers: Vec<Box<dyn TableProver<SC>>> = Vec::new();
            for config in poseidon2_challenger_shape_configs(challenger) {
                provers.push(Box::new(Poseidon2Prover::new(
                    config,
                    ConstraintProfile::Standard,
                )));
            }
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
        let mut builders = poseidon2_air_builders_for_configs::<SC, 4>(
            poseidon2_challenger_shape_configs(challenger),
        );
        builders.push(Box::new(RecomposeAirBuilder::<4>::new(1, true)));
        builders
    }
}

impl<SC, A, const WIDTH: usize, const RATE: usize, C> PreparedPcsRecursionBackend<SC, A, 4>
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
            VerifierParams = WhirUniVerifierParams<Val<SC>>,
        >,
    SC::Commitment: PreparedRecursive<SC::Challenge>,
    SC::OpeningProof: PreparedRecursive<SC::Challenge>,
{
    type InputContract = crate::input_contract::InputContract<
        Val<SC>,
        <SC::Commitment as PreparedRecursive<SC::Challenge>>::Shape,
        <SC::OpeningProof as PreparedRecursive<SC::Challenge>>::Shape,
    >;

    fn capture_input_contract(
        &self,
        config: &SC,
        source: &RecursionInput<'_, SC, A>,
    ) -> Result<Self::InputContract, VerificationError> {
        capture_builtin_input_contract::<SC, A, SC::Commitment, SC::OpeningProof>(
            config,
            source,
            true,
            |degree| PcsRecursionBackend::<SC, A, 4>::non_primitive_provers(self, degree),
        )
    }

    fn validate_prepared_input(
        &self,
        _config: &SC,
        contract: &Self::InputContract,
        input: &PreparedInput<'_, SC>,
    ) -> Result<(), VerificationError> {
        validate_builtin_prepared_input::<SC, SC::Commitment, SC::OpeningProof>(contract, input)
    }
}
