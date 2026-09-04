//! FRI PCS backend for the unified recursion API.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};

use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_circuit_prover::batch_stark_prover::{
    RecomposeAirBuilder, RecomposeProver, poseidon1_air_builders_d5,
    poseidon1_air_builders_for_configs, poseidon1_preprocessor, poseidon1_table_provers_d5,
    poseidon2_air_builders_d5, poseidon2_air_builders_for_configs, poseidon2_preprocessor,
    poseidon2_table_provers_d5, recompose_preprocessor,
};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::config::StarkField;
use p3_circuit_prover::field_params::ExtractBinomialW;
use p3_circuit_prover::{
    ConstraintProfile, Poseidon1Preprocessor, Poseidon1Prover, Poseidon1ProverD2,
    Poseidon2Preprocessor, Poseidon2Prover, Poseidon2ProverD2, RecomposePreprocessor, TableProver,
};
use p3_commit::Pcs;
use p3_field::extension::BinomiallyExtendable;
use p3_field::{Algebra, BasedVectorSpace, ExtensionField, PrimeCharacteristicRing, PrimeField64};
use p3_lookup::logup::LogUpGadget;
use p3_uni_stark::{StarkGenericConfig, SymbolicExpressionExt, Val};

use crate::backend::transcript::replay_recursion_input_transcript;
use crate::generation::OpeningTranscript;
use crate::ops::{Poseidon1Config, Poseidon2Config};
use crate::public_inputs::{BatchStarkVerifierInputsBuilder, StarkVerifierInputsBuilder};
use crate::recursion::{PcsRecursionBackend, RecursionInput, VerifierCircuitResult};
use crate::traits::RecursiveAir;
use crate::verifier::{
    ObservableCommitment, VerificationError, verify_p3_batch_proof_circuit,
    verify_p3_uni_proof_circuit,
};
use crate::{ChallengerPermConfig, Recursive, RecursivePcs};

/// Config that uses FRI with Merkle-tree MMCS and fixed constants (WIDTH, RATE, DIGEST_ELEMS).
/// Implement this for your StarkConfig to use [`FriRecursionBackend`].
pub trait FriRecursionConfig: StarkGenericConfig + Sized
where
    Self::Pcs: RecursivePcs<
            Self,
            Self::InputProof,
            Self::OpeningProof,
            Self::Commitment,
            <Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Domain,
        >,
{
    /// Commitment type used in the verifier circuit (e.g. HashTargets).
    type Commitment: Recursive<
            Self::Challenge,
            Input = <Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Commitment,
        > + Clone
        + ObservableCommitment;

    /// Input proof type for the PCS (e.g. batch opening targets for FRI).
    type InputProof: Recursive<Self::Challenge>;

    /// Opening proof type used in the verifier circuit (e.g. FRI proof targets).
    type OpeningProof: Recursive<
            Self::Challenge,
            Input = <Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Proof,
        >;

    /// Raw FRI opening proof type (value type, not circuit targets). Used to set private data.
    type RawOpeningProof;

    /// Number of field elements in a single Merkle digest (e.g. 8 for BabyBear with Poseidon2).
    const DIGEST_ELEMS: usize;

    /// Invoke a closure with the FRI opening proof extracted from the recursion input.
    fn with_fri_opening_proof<'a, A, R>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> R,
    ) -> R
    where
        A: RecursiveAir<Val<Self>, Self::Challenge, LogUpGadget>;

    /// Prepare the circuit for verification (e.g. enable challenger permutation and NPOs). Called by the backend before building the verifier.
    fn prepare_circuit_for_verification(
        &self,
        circuit: &mut CircuitBuilder<Self::Challenge>,
    ) -> Result<(), VerificationError>;

    /// Return the PCS verifier params (e.g. FRI params). The config must hold these and return a reference.
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

    /// Set FRI Merkle path private data on the runner.
    ///
    /// A FRI proof authenticates all of its queries into one tree with a single pruned
    /// multiproof, while the in-circuit MMCS gadget walks one full authentication path per query.
    /// Implement this by restoring those per-query paths with
    /// [`crate::pcs::restore_fri_query_paths`] and handing them to
    /// [`crate::pcs::set_fri_mmcs_private_data`], both instantiated with your concrete
    /// MMCS/hasher types.
    ///
    /// `transcript` is this proof's verifier transcript replayed off-circuit, in the state
    /// [`p3_commit::Pcs::verify`] is entered with — the restoration needs it because the queried
    /// leaf indices and each commit-phase round's reconstructed row come out of the transcript,
    /// not out of the proof. Advance it with
    /// [`observe_opened_values`](crate::generation::observe_opened_values) (and, for a hiding PCS,
    /// [`merge_hiding_random_openings`](crate::generation::merge_hiding_random_openings) first)
    /// exactly as your PCS's own `verify` does before entering the FRI verifier.
    fn set_fri_private_data(
        config: &Self,
        runner: &mut CircuitRunner<'_, Self::Challenge>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
        transcript: OpeningTranscript<Self>,
    ) -> Result<(), &'static str>;
}

/// FRI-based recursion backend, holding the challenger permutation config.
/// The verifier params come from the config via [`FriRecursionConfig::pcs_verifier_params`].
/// `WIDTH` and `RATE` are the permutation circuit parameters (typically 16 and 8).
/// `C` is the challenger permutation config (e.g. [`Poseidon2Config`] or `Poseidon1Config`).
#[derive(Clone)]
pub struct FriRecursionBackend<
    const WIDTH: usize = 16,
    const RATE: usize = 8,
    C: ChallengerPermConfig = Poseidon2Config,
> {
    /// Permutation configuration used for the Fiat-Shamir challenger permutation circuit.
    pub challenger_perm_config: C,
    /// Additional Poseidon2 table configs that may appear in input proofs verified
    /// by this backend (e.g. a wide MMCS config distinct from the challenger).
    pub extra_poseidon2_table_configs: Vec<Poseidon2Config>,
    /// Number of recompose operations packed per AIR row.
    ///
    /// Increasing this reduces the recompose table height proportionally.
    /// Must be kept in sync between prover and verifier. Defaults to 1.
    pub recompose_lanes: usize,
    /// Whether MMCS and compression rows share the challenger permutation's shape.
    ///
    /// The challenger's duplex rows live on their own table so the AIR can chain their sponge
    /// capacity, which leaves a second table for the rows of the same shape that MMCS and
    /// compression emit. Mixed-shape circuits run those on a separately registered
    /// configuration instead, so that second table carries no rows and must not be expected in
    /// the proof; they clear this with [`Self::without_shared_challenger_perm_table`].
    pub shares_challenger_perm_table: bool,
}

impl<const WIDTH: usize, const RATE: usize, C: ChallengerPermConfig>
    FriRecursionBackend<WIDTH, RATE, C>
{
    /// Create a new backend with the given challenger permutation configuration.
    pub const fn new(challenger_perm_config: C) -> Self {
        Self {
            challenger_perm_config,
            extra_poseidon2_table_configs: Vec::new(),
            recompose_lanes: 1,
            shares_challenger_perm_table: true,
        }
    }

    /// Declare that MMCS and compression rows do not use the challenger's permutation shape.
    ///
    /// Set this for mixed-shape circuits (for example arity-4 recursion, where leaf hashing and
    /// compression run on a wider separately registered configuration), so the shared table for
    /// the challenger's own shape is not expected in the proof.
    pub const fn without_shared_challenger_perm_table(mut self) -> Self {
        self.shares_challenger_perm_table = false;
        self
    }

    /// Ordered Poseidon2 table configurations for the challenger's permutation shape: the
    /// challenger's own table first, then the table its MMCS and compression rows share.
    ///
    /// A base-field (`D == 1`) challenger has no dedicated table — the compact D=1 layout binds
    /// its sponge capacity on the shared table already — so only the shared entry is returned.
    fn poseidon2_challenger_shape_configs(&self, config: Poseidon2Config) -> Vec<Poseidon2Config> {
        let mut configs = Vec::new();
        if config.d() < 2 {
            return vec![config];
        }
        configs.push(config.for_challenger());
        if self.shares_challenger_perm_table {
            configs.push(config);
        }
        configs
    }

    /// Poseidon1 counterpart of [`Self::poseidon2_challenger_shape_configs`].
    fn poseidon1_challenger_shape_configs(&self, config: Poseidon1Config) -> Vec<Poseidon1Config> {
        let mut configs = Vec::new();
        if config.d() < 2 {
            return vec![config];
        }
        configs.push(config.for_challenger());
        if self.shares_challenger_perm_table {
            configs.push(config);
        }
        configs
    }

    /// Register an additional Poseidon2 table config that can appear in proofs
    /// verified by circuits built with this backend (e.g. a wide MMCS config).
    pub fn with_extra_poseidon2_table(mut self, config: Poseidon2Config) -> Self {
        self.extra_poseidon2_table_configs.push(config);
        self
    }

    /// Extra Poseidon2 table configs whose circuit extension degree equals
    /// `table_degree`, de-duplicated and excluding the challenger config.
    fn extra_poseidon2_table_configs_for_degree(
        &self,
        table_degree: usize,
    ) -> Vec<Poseidon2Config> {
        let challenger = self.challenger_perm_config.as_poseidon2().copied();
        let mut configs = Vec::new();
        for &config in &self.extra_poseidon2_table_configs {
            if config.d() == table_degree
                && Some(config) != challenger
                && !configs.contains(&config)
            {
                configs.push(config);
            }
        }
        configs
    }

    /// Full ordered list of Poseidon2 table configs for `table_degree`: the challenger config's
    /// tables (if it is Poseidon2) followed by the extra configs. Order matches
    /// `non_primitive_provers` so the preprocessed AIRs line up one-to-one with the registered
    /// table provers.
    fn poseidon2_air_configs_for_degree(&self, table_degree: usize) -> Vec<Poseidon2Config> {
        let mut configs = Vec::new();
        if let Some(c) = self.challenger_perm_config.as_poseidon2() {
            configs.extend(self.poseidon2_challenger_shape_configs(*c));
        }
        configs.extend(self.extra_poseidon2_table_configs_for_degree(table_degree));
        configs
    }

    /// Override the number of recompose operations packed per AIR row.
    pub const fn with_recompose_lanes(mut self, lanes: usize) -> Self {
        self.recompose_lanes = if lanes < 1 { 1 } else { lanes };
        self
    }

    /// Tag this backend for a fixed batch/extension degree `D` (typically `2` or `4`).
    pub const fn for_extension_degree<const D: usize>(
        self,
    ) -> FriRecursionBackendForExt<D, WIDTH, RATE, C> {
        FriRecursionBackendForExt(self)
    }

    /// For KoalaBear quintic extension (`D = 5`). Use when `SC::Challenge` is
    /// `QuinticTrinomialExtensionField<KoalaBear>`.
    ///
    /// # Panics
    ///
    /// Panics if the challenger config is not D=1. The quintic challenger operates
    /// entirely in the base field, so a D=1 (base-field) permutation config is
    /// required (e.g. `KoalaBearD1Width16`).
    pub fn new_d5(challenger_perm_config: C) -> FriRecursionBackendD5<WIDTH, RATE, C> {
        assert!(
            challenger_perm_config.extension_degree() == 1,
            "new_d5 requires a D=1 (base-field) challenger config; \
             the quintic challenger operates in the base field"
        );
        FriRecursionBackendD5(Self::new(challenger_perm_config))
    }
}

/// FRI recursion backend tagged with batch/extension field degree `D` (e.g. `2` or `4`).
#[derive(Clone)]
pub struct FriRecursionBackendForExt<
    const D: usize,
    const WIDTH: usize = 16,
    const RATE: usize = 8,
    C: ChallengerPermConfig = Poseidon2Config,
>(
    /// The inner backend holding the challenger permutation config.
    pub(crate) FriRecursionBackend<WIDTH, RATE, C>,
);

/// FRI backend for KoalaBear quintic extension (`D = 5`).
#[derive(Clone)]
pub struct FriRecursionBackendD5<
    const WIDTH: usize = 16,
    const RATE: usize = 8,
    C: ChallengerPermConfig = Poseidon2Config,
>(
    /// The inner backend holding the challenger permutation config.
    pub(crate) FriRecursionBackend<WIDTH, RATE, C>,
);

impl<const WIDTH: usize, const RATE: usize, C: ChallengerPermConfig>
    FriRecursionBackendD5<WIDTH, RATE, C>
{
    /// Register an additional D=1 Poseidon2 table config that can appear in
    /// proofs verified by quintic recursive circuits (e.g. a wide MMCS config).
    pub fn with_extra_poseidon2_table(mut self, config: Poseidon2Config) -> Self {
        self.0 = self.0.with_extra_poseidon2_table(config);
        self
    }

    /// See [`FriRecursionBackend::without_shared_challenger_perm_table`].
    pub fn without_shared_challenger_perm_table(mut self) -> Self {
        self.0 = self.0.without_shared_challenger_perm_table();
        self
    }
}

/// Verifier result from the FRI backend: either uni-stark or batch-stark builder + op_ids.
pub enum FriVerifierResult<SC>
where
    SC: FriRecursionConfig,
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

impl<SC, A> VerifierCircuitResult<SC, A> for FriVerifierResult<SC>
where
    SC: FriRecursionConfig,
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

fn build_verifier_circuit_impl<SC, A, const WIDTH: usize, const RATE: usize, C>(
    backend: &FriRecursionBackend<WIDTH, RATE, C>,
    prev: &RecursionInput<'_, SC, A>,
    config: &SC,
    circuit: &mut CircuitBuilder<SC::Challenge>,
    non_primitive_provers: &[Box<dyn TableProver<SC>>],
) -> Result<FriVerifierResult<SC>, VerificationError>
where
    SC: FriRecursionConfig + Send + Sync + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    C: ChallengerPermConfig + Copy,
    Val<SC>: PrimeField64,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + PrimeCharacteristicRing
        + ExtractBinomialW<Val<SC>>,
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
                backend.challenger_perm_config,
            )?;
            Ok(FriVerifierResult::UniStark(verifier_inputs, op_ids))
        }
        RecursionInput::BatchStark {
            proof,
            common_data,
            table_public_inputs: _,
        } => {
            let lookup_gadget = LogUpGadget::new();
            let (verifier_inputs, op_ids) = match proof.ext_degree {
                1 => verify_p3_batch_proof_circuit::<
                    SC,
                    SC::Commitment,
                    SC::InputProof,
                    SC::OpeningProof,
                    _,
                    _,
                    WIDTH,
                    RATE,
                    1,
                >(
                    config,
                    circuit,
                    proof,
                    config.pcs_verifier_params(),
                    common_data,
                    &lookup_gadget,
                    backend.challenger_perm_config,
                    non_primitive_provers,
                )?,
                2 => verify_p3_batch_proof_circuit::<
                    SC,
                    SC::Commitment,
                    SC::InputProof,
                    SC::OpeningProof,
                    _,
                    _,
                    WIDTH,
                    RATE,
                    2,
                >(
                    config,
                    circuit,
                    proof,
                    config.pcs_verifier_params(),
                    common_data,
                    &lookup_gadget,
                    backend.challenger_perm_config,
                    non_primitive_provers,
                )?,
                4 => verify_p3_batch_proof_circuit::<
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
                    backend.challenger_perm_config,
                    non_primitive_provers,
                )?,
                5 => verify_p3_batch_proof_circuit::<
                    SC,
                    SC::Commitment,
                    SC::InputProof,
                    SC::OpeningProof,
                    _,
                    _,
                    WIDTH,
                    RATE,
                    5,
                >(
                    config,
                    circuit,
                    proof,
                    config.pcs_verifier_params(),
                    common_data,
                    &lookup_gadget,
                    backend.challenger_perm_config,
                    non_primitive_provers,
                )?,
                d => {
                    return Err(VerificationError::InvalidProofShape(format!(
                        "unsupported batch proof ext_degree {}",
                        d
                    )));
                }
            };
            Ok(FriVerifierResult::BatchStark(verifier_inputs, op_ids))
        }
    }
}

impl<SC, A, const WIDTH: usize, const RATE: usize, C> PcsRecursionBackend<SC, A, 2>
    for FriRecursionBackendForExt<2, WIDTH, RATE, C>
where
    SC: FriRecursionConfig + Send + Sync + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    C: ChallengerPermConfig + Copy + 'static,
    Val<SC>: PrimeField64 + BinomiallyExtendable<2> + StarkField,
    Poseidon1Preprocessor: NpoPreprocessor<Val<SC>>,
    Poseidon2Preprocessor: NpoPreprocessor<Val<SC>>,
    RecomposePreprocessor: NpoPreprocessor<Val<SC>>,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + PrimeCharacteristicRing
        + ExtractBinomialW<Val<SC>>,
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
    type VerifierResult = FriVerifierResult<SC>;

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
        let provers = match prev {
            RecursionInput::BatchStark { proof, .. } => {
                PcsRecursionBackend::<SC, A, 2>::non_primitive_provers(self, proof.ext_degree)
            }
            _ => Vec::new(),
        };
        build_verifier_circuit_impl(&self.0, prev, config, circuit, &provers)
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
                PcsRecursionBackend::<SC, A, 2>::non_primitive_provers(self, proof.ext_degree)
            }
            _ => Vec::new(),
        };
        let transcript = replay_recursion_input_transcript(config, prev, &provers)
            .map_err(|_| "Failed to replay the input proof's verifier transcript")?;
        SC::with_fri_opening_proof(prev, move |opening_proof| {
            SC::set_fri_private_data(config, runner, op_ids, opening_proof, transcript)
        })
    }

    fn non_primitive_preprocessors(&self) -> Vec<Box<dyn NpoPreprocessor<Val<SC>>>> {
        let perm_prep = if self.0.challenger_perm_config.as_poseidon1().is_some() {
            poseidon1_preprocessor::<Val<SC>>()
        } else {
            poseidon2_preprocessor::<Val<SC>>()
        };
        vec![perm_prep, recompose_preprocessor::<Val<SC>>(true)]
    }

    fn non_primitive_provers(&self, ext_degree: usize) -> Vec<Box<dyn TableProver<SC>>> {
        if ext_degree == 2 {
            // Every extension limb the verifier packs or unpacks goes through the
            // `recompose/coeff` table, which publishes each coefficient on the bus alongside
            // the packed limb. The plain recompose table therefore never carries a row, and a
            // table with no rows is absent from the proof.
            let mut provers: Vec<Box<dyn TableProver<SC>>> = Vec::new();
            match (
                self.0.challenger_perm_config.as_poseidon1(),
                self.0.challenger_perm_config.as_poseidon2(),
            ) {
                (Some(c), _) => {
                    for config in self.0.poseidon1_challenger_shape_configs(*c) {
                        provers.push(Box::new(Poseidon1ProverD2::new(
                            config,
                            ConstraintProfile::Standard,
                        )));
                    }
                }
                (_, Some(c)) => {
                    for config in self.0.poseidon2_challenger_shape_configs(*c) {
                        provers.push(Box::new(Poseidon2ProverD2::new(
                            config,
                            ConstraintProfile::Standard,
                        )));
                    }
                }
                _ => {}
            }
            for config in self.0.extra_poseidon2_table_configs_for_degree(2) {
                provers.push(Box::new(Poseidon2ProverD2::new(
                    config,
                    ConstraintProfile::Standard,
                )));
            }
            provers.push(Box::new(RecomposeProver::<2>::new(
                self.0.recompose_lanes,
                true,
            )));
            provers
        } else {
            Vec::new()
        }
    }

    fn non_primitive_air_builders(&self) -> Vec<Box<dyn NpoAirBuilder<SC, 2>>> {
        let mut builders = self.0.challenger_perm_config.as_poseidon1().map_or_else(
            || {
                poseidon2_air_builders_for_configs::<SC, 2>(
                    self.0.poseidon2_air_configs_for_degree(2),
                )
            },
            |c| {
                poseidon1_air_builders_for_configs::<SC, 2>(
                    self.0.poseidon1_challenger_shape_configs(*c),
                )
            },
        );
        builders.push(Box::new(RecomposeAirBuilder::<2>::new(
            self.0.recompose_lanes,
            true,
        )));
        builders
    }
}

impl<SC, A, const WIDTH: usize, const RATE: usize, C> PcsRecursionBackend<SC, A, 4>
    for FriRecursionBackendForExt<4, WIDTH, RATE, C>
where
    SC: FriRecursionConfig + Send + Sync + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    C: ChallengerPermConfig + Copy + 'static,
    Val<SC>: PrimeField64 + BinomiallyExtendable<4> + StarkField,
    Poseidon1Preprocessor: NpoPreprocessor<Val<SC>>,
    Poseidon2Preprocessor: NpoPreprocessor<Val<SC>>,
    RecomposePreprocessor: NpoPreprocessor<Val<SC>>,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + PrimeCharacteristicRing
        + ExtractBinomialW<Val<SC>>,
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
    type VerifierResult = FriVerifierResult<SC>;

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
        let provers = match prev {
            RecursionInput::BatchStark { proof, .. } => {
                PcsRecursionBackend::<SC, A, 4>::non_primitive_provers(self, proof.ext_degree)
            }
            _ => Vec::new(),
        };
        build_verifier_circuit_impl(&self.0, prev, config, circuit, &provers)
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
            _ => Vec::new(),
        };
        let transcript = replay_recursion_input_transcript(config, prev, &provers)
            .map_err(|_| "Failed to replay the input proof's verifier transcript")?;
        SC::with_fri_opening_proof(prev, move |opening_proof| {
            SC::set_fri_private_data(config, runner, op_ids, opening_proof, transcript)
        })
    }

    fn non_primitive_preprocessors(&self) -> Vec<Box<dyn NpoPreprocessor<Val<SC>>>> {
        let perm_prep = if self.0.challenger_perm_config.as_poseidon1().is_some() {
            poseidon1_preprocessor::<Val<SC>>()
        } else {
            poseidon2_preprocessor::<Val<SC>>()
        };
        vec![perm_prep, recompose_preprocessor::<Val<SC>>(true)]
    }

    fn non_primitive_provers(&self, ext_degree: usize) -> Vec<Box<dyn TableProver<SC>>> {
        if ext_degree == 4 {
            // Every extension limb the verifier packs or unpacks goes through the
            // `recompose/coeff` table, which publishes each coefficient on the bus alongside
            // the packed limb. The plain recompose table therefore never carries a row, and a
            // table with no rows is absent from the proof.
            let mut provers: Vec<Box<dyn TableProver<SC>>> = Vec::new();
            match (
                self.0.challenger_perm_config.as_poseidon1(),
                self.0.challenger_perm_config.as_poseidon2(),
            ) {
                (Some(c), _) => {
                    for config in self.0.poseidon1_challenger_shape_configs(*c) {
                        provers.push(Box::new(Poseidon1Prover::new(
                            config,
                            ConstraintProfile::Standard,
                        )));
                    }
                }
                (_, Some(c)) => {
                    for config in self.0.poseidon2_challenger_shape_configs(*c) {
                        provers.push(Box::new(Poseidon2Prover::new(
                            config,
                            ConstraintProfile::Standard,
                        )));
                    }
                }
                _ => {}
            }
            for config in self.0.extra_poseidon2_table_configs_for_degree(4) {
                provers.push(Box::new(Poseidon2Prover::new(
                    config,
                    ConstraintProfile::Standard,
                )));
            }
            provers.push(Box::new(RecomposeProver::<4>::new(
                self.0.recompose_lanes,
                true,
            )));
            provers
        } else {
            Vec::new()
        }
    }

    fn non_primitive_air_builders(&self) -> Vec<Box<dyn NpoAirBuilder<SC, 4>>> {
        let mut builders = self.0.challenger_perm_config.as_poseidon1().map_or_else(
            || {
                poseidon2_air_builders_for_configs::<SC, 4>(
                    self.0.poseidon2_air_configs_for_degree(4),
                )
            },
            |c| {
                poseidon1_air_builders_for_configs::<SC, 4>(
                    self.0.poseidon1_challenger_shape_configs(*c),
                )
            },
        );
        builders.push(Box::new(RecomposeAirBuilder::<4>::new(
            self.0.recompose_lanes,
            true,
        )));
        builders
    }
}

impl<SC, A, const WIDTH: usize, const RATE: usize, C> PcsRecursionBackend<SC, A, 5>
    for FriRecursionBackendD5<WIDTH, RATE, C>
where
    SC: FriRecursionConfig + Send + Sync + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    C: ChallengerPermConfig + Copy + 'static,
    Val<SC>: PrimeField64 + StarkField + BinomiallyExtendable<4>,
    Poseidon1Preprocessor: NpoPreprocessor<Val<SC>>,
    Poseidon2Preprocessor: NpoPreprocessor<Val<SC>>,
    RecomposePreprocessor: NpoPreprocessor<Val<SC>>,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + PrimeCharacteristicRing
        + ExtractBinomialW<Val<SC>>,
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
    type VerifierResult = FriVerifierResult<SC>;

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
        let provers = match prev {
            RecursionInput::BatchStark { proof, .. } => {
                PcsRecursionBackend::<SC, A, 5>::non_primitive_provers(self, proof.ext_degree)
            }
            _ => Vec::new(),
        };
        build_verifier_circuit_impl(&self.0, prev, config, circuit, &provers)
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
                PcsRecursionBackend::<SC, A, 5>::non_primitive_provers(self, proof.ext_degree)
            }
            _ => Vec::new(),
        };
        let transcript = replay_recursion_input_transcript(config, prev, &provers)
            .map_err(|_| "Failed to replay the input proof's verifier transcript")?;
        SC::with_fri_opening_proof(prev, move |opening_proof| {
            SC::set_fri_private_data(config, runner, op_ids, opening_proof, transcript)
        })
    }

    fn non_primitive_preprocessors(&self) -> Vec<Box<dyn NpoPreprocessor<Val<SC>>>> {
        let perm_prep = if self.0.challenger_perm_config.as_poseidon1().is_some() {
            poseidon1_preprocessor::<Val<SC>>()
        } else {
            poseidon2_preprocessor::<Val<SC>>()
        };
        vec![perm_prep, recompose_preprocessor::<Val<SC>>(true)]
    }

    fn non_primitive_provers(&self, ext_degree: usize) -> Vec<Box<dyn TableProver<SC>>> {
        if ext_degree == 5 {
            // Every extension limb the verifier packs or unpacks goes through the
            // `recompose/coeff` table, which publishes each coefficient on the bus alongside
            // the packed limb. The plain recompose table therefore never carries a row, and a
            // table with no rows is absent from the proof.
            let mut provers = match (
                self.0.challenger_perm_config.as_poseidon1(),
                self.0.challenger_perm_config.as_poseidon2(),
            ) {
                (Some(c), _) => poseidon1_table_provers_d5(*c),
                (_, Some(c)) => poseidon2_table_provers_d5(*c),
                _ => Vec::new(),
            };
            for config in self.0.extra_poseidon2_table_configs_for_degree(1) {
                provers.extend(poseidon2_table_provers_d5::<SC>(config));
            }
            provers.push(Box::new(RecomposeProver::<5>::new(
                self.0.recompose_lanes,
                true,
            )));
            provers
        } else {
            Vec::new()
        }
    }

    fn non_primitive_air_builders(&self) -> Vec<Box<dyn NpoAirBuilder<SC, 5>>> {
        let mut builders = if self.0.challenger_perm_config.as_poseidon1().is_some() {
            poseidon1_air_builders_d5()
        } else if self
            .0
            .extra_poseidon2_table_configs_for_degree(1)
            .is_empty()
        {
            poseidon2_air_builders_d5()
        } else {
            poseidon2_air_builders_for_configs::<SC, 5>(self.0.poseidon2_air_configs_for_degree(1))
        };
        builders.push(Box::new(RecomposeAirBuilder::<5>::new(
            self.0.recompose_lanes,
            true,
        )));
        builders
    }
}
