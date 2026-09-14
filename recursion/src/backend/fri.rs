//! FRI PCS backend for the unified recursion API.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};

use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_circuit_prover::batch_stark_prover::{
    BatchStarkProof, CircuitVerifier, RecomposeAirBuilder, RecomposeProver,
    lookups_for_circuit_table_air, poseidon1_air_builders_d5, poseidon1_air_builders_for_configs,
    poseidon1_preprocessor, poseidon1_table_provers_d5, poseidon2_air_builders_d5,
    poseidon2_air_builders_for_configs, poseidon2_preprocessor, poseidon2_table_provers_d5,
    recompose_preprocessor,
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
use p3_lookup::Lookup;
use p3_lookup::logup::LogUpGadget;
use p3_uni_stark::{StarkGenericConfig, SymbolicExpressionExt, Val};

use crate::backend::CheckedVerifierResult;
use crate::backend::context::{
    StarkLayoutPolicy, StarkPackingAuthority, capture_stark_authority,
    capture_trusted_batch_authority, check_batch_stark_resources,
    check_trusted_batch_stark_resources, check_uni_stark_resources, input_caps,
    validate_stark_replacement,
};
use crate::backend::transcript::{
    replay_recursion_input_transcript, replay_trusted_batch_layer_transcript,
};
use crate::generation::OpeningTranscript;
use crate::input_contract::stark::validate_batch_proof_native;
use crate::ops::{Poseidon1Config, Poseidon2Config};
use crate::pcs::fri::{
    CheckedFriCommitment, CheckedFriOpening, FriVerifierParams, NativeFriParams,
    ValidatedFriContext,
};
use crate::prepared::input::{
    capture_builtin_input_contract, capture_trusted_batch_input_contract,
    validate_builtin_prepared_input, validate_trusted_batch_input,
};
use crate::prepared::{
    ConstrainConstantCommitment, NativeCommitment, PreparedInput, PreparedPcsRecursionBackend,
    TrustedPcsRecursionBackend,
};
use crate::public_inputs::{BatchStarkVerifierInputsBuilder, StarkVerifierInputsBuilder};
use crate::recursion::{PcsRecursionBackend, RecursionInput, VerifierCircuitResult};
use crate::traits::{CheckedRecursive, PreparedRecursive, RecursiveAir};
use crate::verifier::{
    InputResourceUsage, ObservableCommitment, VerificationError, VerifierLimits,
    plan_batch_native_layout, plan_uni_native_layout, reconstruct_batch_tables,
    trusted_batch_tables, verify_p3_batch_proof_circuit, verify_p3_uni_proof_circuit,
    verify_trusted_p3_batch_proof_circuit,
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
    /// Checked scalar metadata copied from the native FRI parameters used by
    /// this config's opaque PCS. Custom configs may leave this unset and stay
    /// on the explicitly trusted legacy entrypoints.
    fn native_fri_validation_params(&self) -> Option<NativeFriParams> {
        None
    }

    /// Commitment type used in the verifier circuit (e.g. HashTargets).
    type Commitment: Recursive<
            Self::Challenge,
            Input = <Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Commitment,
        > + Clone
        + CheckedRecursive<Self::Challenge>
        + ObservableCommitment;

    /// Input proof type for the PCS (e.g. batch opening targets for FRI).
    type InputProof: Recursive<Self::Challenge>;

    /// Opening proof type used in the verifier circuit (e.g. FRI proof targets).
    type OpeningProof: Recursive<
            Self::Challenge,
            Input = <Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Proof,
        > + CheckedRecursive<Self::Challenge>;

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

fn preflight_basic_fri_input<SC, A>(
    limits: &VerifierLimits,
    prev: &RecursionInput<'_, SC, A>,
) -> Result<InputResourceUsage, VerificationError>
where
    SC: FriRecursionConfig,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    SC::Commitment: CheckedFriCommitment<SC::Challenge>,
    SC::OpeningProof: CheckedFriOpening<SC::Challenge, SC::Commitment>,
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
            public_inputs,
            preprocessed_commit,
            ..
        } => {
            let mut usage = check_uni_stark_resources::<SC, SC::Commitment>(
                limits,
                proof,
                public_inputs,
                preprocessed_commit.as_ref(),
                InputResourceUsage::default(),
            )?;
            let pcs_usage = <SC::OpeningProof as CheckedFriOpening<
                SC::Challenge,
                SC::Commitment,
            >>::check_fri_resources(&proof.opening_proof, limits)?;
            usage.merge(limits, pcs_usage)?;
            Ok(usage)
        }
        RecursionInput::BatchStark {
            proof,
            common_data,
            table_public_inputs,
        } => {
            let mut usage = check_batch_stark_resources::<SC, SC::Commitment>(
                limits,
                proof,
                common_data,
                table_public_inputs,
                InputResourceUsage::default(),
            )?;
            let pcs_usage = <SC::OpeningProof as CheckedFriOpening<
                SC::Challenge,
                SC::Commitment,
            >>::check_fri_resources(&proof.proof.opening_proof, limits)?;
            usage.merge(limits, pcs_usage)?;
            Ok(usage)
        }
    }
}

fn preflight_basic_fri_prepared<SC>(
    limits: &VerifierLimits,
    input: &PreparedInput<'_, SC>,
) -> Result<InputResourceUsage, VerificationError>
where
    SC: FriRecursionConfig,
    SC::Commitment: CheckedFriCommitment<SC::Challenge>,
    SC::OpeningProof: CheckedFriOpening<SC::Challenge, SC::Commitment>,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
{
    match input {
        PreparedInput::UniStark {
            proof,
            public_inputs,
            preprocessed_commit,
        } => {
            let mut usage = check_uni_stark_resources::<SC, SC::Commitment>(
                limits,
                proof,
                public_inputs,
                *preprocessed_commit,
                InputResourceUsage::default(),
            )?;
            let pcs_usage = <SC::OpeningProof as CheckedFriOpening<
                SC::Challenge,
                SC::Commitment,
            >>::check_fri_resources(&proof.opening_proof, limits)?;
            usage.merge(limits, pcs_usage)?;
            Ok(usage)
        }
        PreparedInput::BatchStark {
            proof,
            common_data,
            table_public_inputs,
        } => {
            let mut usage = check_batch_stark_resources::<SC, SC::Commitment>(
                limits,
                proof,
                common_data,
                table_public_inputs,
                InputResourceUsage::default(),
            )?;
            let pcs_usage = <SC::OpeningProof as CheckedFriOpening<
                SC::Challenge,
                SC::Commitment,
            >>::check_fri_resources(&proof.proof.opening_proof, limits)?;
            usage.merge(limits, pcs_usage)?;
            Ok(usage)
        }
    }
}

fn check_fri_restoration_budget<SC>(
    config: &SC,
    limits: &VerifierLimits,
    degree_bits: usize,
    usage: &mut InputResourceUsage,
) -> Result<(), VerificationError>
where
    SC: FriRecursionConfig,
    SC::Commitment: CheckedFriCommitment<SC::Challenge>,
    SC::OpeningProof: CheckedFriOpening<SC::Challenge, SC::Commitment>,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
{
    let native = config.native_fri_validation_params().ok_or_else(|| {
        VerificationError::InvalidProofShape(
            "built-in FRI recursion requires native validation parameters".into(),
        )
    })?;
    let depth = degree_bits.checked_add(native.log_blowup()).ok_or(
        VerificationError::ResourceArithmeticOverflow {
            component: "restored authentication-path hashes",
        },
    )?;
    usage.check_log_degree(limits, depth)?;
    let queries = usage.queries;
    usage.add_restored_authentication_path_hashes(limits, queries, depth)
}

fn preflight_fri_input<SC, A>(
    config: &SC,
    limits: &VerifierLimits,
    input: &RecursionInput<'_, SC, A>,
) -> Result<(), VerificationError>
where
    SC: FriRecursionConfig,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    SC::Commitment: CheckedFriCommitment<SC::Challenge>,
    SC::OpeningProof: CheckedFriOpening<SC::Challenge, SC::Commitment>,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
{
    let mut usage = preflight_basic_fri_input(limits, input)?;
    match input {
        RecursionInput::UniStark { proof, .. } => {
            check_fri_restoration_budget(config, limits, proof.degree_bits, &mut usage)
        }
        RecursionInput::BatchStark { proof, .. } => check_fri_restoration_budget(
            config,
            limits,
            proof.proof.degree_bits.iter().copied().max().unwrap_or(0),
            &mut usage,
        ),
    }
}

fn preflight_fri_prepared<SC>(
    config: &SC,
    limits: &VerifierLimits,
    input: &PreparedInput<'_, SC>,
) -> Result<(), VerificationError>
where
    SC: FriRecursionConfig,
    SC::Commitment: CheckedFriCommitment<SC::Challenge>,
    SC::OpeningProof: CheckedFriOpening<SC::Challenge, SC::Commitment>,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
{
    let mut usage = preflight_basic_fri_prepared(limits, input)?;
    match input {
        PreparedInput::UniStark { proof, .. } => {
            check_fri_restoration_budget(config, limits, proof.degree_bits, &mut usage)
        }
        PreparedInput::BatchStark { proof, .. } => check_fri_restoration_budget(
            config,
            limits,
            proof.proof.degree_bits.iter().copied().max().unwrap_or(0),
            &mut usage,
        ),
    }
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
    /// Owned operational policy retained by prepared and uncached verifiers.
    pub(crate) limits: VerifierLimits,
}

impl<const WIDTH: usize, const RATE: usize, C: ChallengerPermConfig>
    FriRecursionBackend<WIDTH, RATE, C>
{
    /// Create a new backend with the given challenger permutation configuration.
    pub fn new(challenger_perm_config: C) -> Self {
        Self {
            challenger_perm_config,
            extra_poseidon2_table_configs: Vec::new(),
            recompose_lanes: 1,
            shares_challenger_perm_table: true,
            limits: VerifierLimits::default(),
        }
    }

    /// Override the finite verifier-owned operational policy.
    #[must_use]
    pub const fn with_limits(mut self, limits: VerifierLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Return the policy retained by this backend.
    pub const fn limits(&self) -> &VerifierLimits {
        &self.limits
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

impl<const D: usize, const WIDTH: usize, const RATE: usize, C: ChallengerPermConfig>
    FriRecursionBackendForExt<D, WIDTH, RATE, C>
{
    /// Override the finite verifier-owned operational policy.
    #[must_use]
    pub fn with_limits(mut self, limits: VerifierLimits) -> Self {
        self.0 = self.0.with_limits(limits);
        self
    }

    /// Return the policy retained by this degree-tagged backend.
    pub const fn limits(&self) -> &VerifierLimits {
        self.0.limits()
    }
}

impl<const WIDTH: usize, const RATE: usize, C: ChallengerPermConfig>
    FriRecursionBackendD5<WIDTH, RATE, C>
{
    /// Override the finite verifier-owned operational policy.
    #[must_use]
    pub fn with_limits(mut self, limits: VerifierLimits) -> Self {
        self.0 = self.0.with_limits(limits);
        self
    }

    /// Return the policy retained by this quintic backend.
    pub const fn limits(&self) -> &VerifierLimits {
        self.0.limits()
    }
}

fn plan_fri_batch_for_degree<SC, A, const TRACE_D: usize>(
    config: &SC,
    prev: &RecursionInput<'_, SC, A>,
    provers: &[Box<dyn TableProver<SC>>],
) -> Result<crate::input_contract::stark_layout::NativeStarkLayout<'static>, VerificationError>
where
    SC: FriRecursionConfig + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    Val<SC>: PrimeField64,
    SC::Challenge: ExtensionField<Val<SC>> + PrimeCharacteristicRing + ExtractBinomialW<Val<SC>>,
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
    let RecursionInput::BatchStark {
        proof,
        common_data,
        table_public_inputs,
    } = prev
    else {
        unreachable!()
    };
    let tables = reconstruct_batch_tables::<SC, TRACE_D>(config, proof, provers)?;
    if tables.public_values.as_slice() != table_public_inputs {
        return Err(VerificationError::InvalidProofShape(
            "batch table public inputs disagree with reconstructed AIR metadata".into(),
        ));
    }
    let lookups: Vec<Vec<Lookup<Val<SC>>>> = tables
        .airs
        .iter()
        .zip(&tables.trace_lens)
        .map(|(air, &trace_len)| {
            lookups_for_circuit_table_air::<SC, TRACE_D>(
                &air.to_table_air(),
                trace_len,
                config.is_zk(),
            )
            .to_vec()
        })
        .collect();
    let public_counts = table_public_inputs.iter().map(Vec::len).collect::<Vec<_>>();
    plan_batch_native_layout(
        config,
        &tables.airs,
        &proof.proof,
        &public_counts,
        common_data,
        &lookups,
        &LogUpGadget,
    )
}

fn preflight_fri_context<SC, A>(
    config: &SC,
    prev: &RecursionInput<'_, SC, A>,
    provers: &[Box<dyn TableProver<SC>>],
) -> Result<
    (
        ValidatedFriContext,
        StarkPackingAuthority<Val<SC>>,
        StarkLayoutPolicy,
    ),
    VerificationError,
>
where
    SC: FriRecursionConfig + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    Val<SC>: PrimeField64,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + ExtensionField<Val<SC>>
        + PrimeCharacteristicRing
        + ExtractBinomialW<Val<SC>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        From<p3_uni_stark::SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    SC::Commitment: CheckedFriCommitment<SC::Challenge>,
    SC::OpeningProof: CheckedFriOpening<SC::Challenge, SC::Commitment>,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
            VerifierParams = FriVerifierParams,
        >,
{
    crate::prepared::input::validate_builtin_input_raw::<SC, A, SC::Commitment, SC::OpeningProof>(
        prev,
    )?;
    let native = config.native_fri_validation_params().ok_or_else(|| {
        VerificationError::InvalidProofShape(
            "built-in FRI recursion requires native validation parameters".into(),
        )
    })?;
    let layout = match prev {
        RecursionInput::UniStark {
            proof,
            air,
            public_inputs,
            preprocessed_commit,
        } => plan_uni_native_layout(
            config,
            *air,
            proof,
            public_inputs.len(),
            preprocessed_commit.as_ref(),
        )?,
        RecursionInput::BatchStark { proof, .. } => match proof.ext_degree {
            1 => plan_fri_batch_for_degree::<SC, A, 1>(config, prev, provers)?,
            2 => plan_fri_batch_for_degree::<SC, A, 2>(config, prev, provers)?,
            4 => plan_fri_batch_for_degree::<SC, A, 4>(config, prev, provers)?,
            5 => plan_fri_batch_for_degree::<SC, A, 5>(config, prev, provers)?,
            degree => {
                return Err(VerificationError::InvalidProofShape(format!(
                    "unsupported batch proof ext_degree {degree}"
                )));
            }
        },
    };
    let caps = input_caps(prev, &layout)?;
    let opening = match prev {
        RecursionInput::UniStark { proof, .. } => &proof.opening_proof,
        RecursionInput::BatchStark { proof, .. } => &proof.proof.opening_proof,
    };
    let context = <SC::OpeningProof as CheckedFriOpening<
        SC::Challenge,
        SC::Commitment,
    >>::validate_fri_context(
        opening,
        &native,
        config.pcs_verifier_params(),
        layout.opening_view(),
        &caps,
    )?;
    let authority = capture_stark_authority(prev);
    let policy = StarkLayoutPolicy::from_config(config);
    Ok((context, authority, policy))
}

fn preflight_trusted_fri_batch<SC, A, const TRACE_D: usize>(
    verifier: &CircuitVerifier<SC>,
    proof: &BatchStarkProof<SC>,
    statement: &[Val<SC>],
) -> Result<
    (
        ValidatedFriContext,
        StarkPackingAuthority<Val<SC>>,
        StarkLayoutPolicy,
    ),
    VerificationError,
>
where
    SC: FriRecursionConfig + Send + Sync + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    Val<SC>: PrimeField64 + StarkField,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + ExtensionField<Val<SC>>
        + PrimeCharacteristicRing
        + ExtractBinomialW<Val<SC>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        From<p3_uni_stark::SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    SC::Commitment: CheckedFriCommitment<SC::Challenge>,
    SC::OpeningProof: CheckedFriOpening<SC::Challenge, SC::Commitment>,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
            VerifierParams = FriVerifierParams,
        >,
{
    verifier
        .verify(proof, statement)
        .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
    let config = verifier.config();
    let native = config.native_fri_validation_params().ok_or_else(|| {
        VerificationError::InvalidProofShape(
            "built-in FRI recursion requires native validation parameters".into(),
        )
    })?;
    let tables = trusted_batch_tables::<SC, TRACE_D>(verifier, statement)?;
    let lookups = tables
        .airs
        .iter()
        .zip(&tables.trace_lens)
        .map(|(air, &trace_len)| {
            lookups_for_circuit_table_air::<SC, TRACE_D>(
                &air.to_table_air(),
                trace_len,
                config.is_zk(),
            )
            .to_vec()
        })
        .collect::<Vec<_>>();
    let public_counts = tables
        .public_values
        .iter()
        .map(Vec::len)
        .collect::<Vec<_>>();
    let layout = plan_batch_native_layout(
        config,
        &tables.airs,
        &proof.proof,
        &public_counts,
        verifier.common_data(),
        &lookups,
        &LogUpGadget,
    )?;
    let prev = RecursionInput::<SC, A>::BatchStark {
        proof,
        common_data: verifier.common_data(),
        table_public_inputs: tables.public_values,
    };
    let caps = input_caps(&prev, &layout)?;
    let context = <SC::OpeningProof as CheckedFriOpening<
        SC::Challenge,
        SC::Commitment,
    >>::validate_fri_context(
        &proof.proof.opening_proof,
        &native,
        config.pcs_verifier_params(),
        layout.opening_view(),
        &caps,
    )?;
    Ok((
        context,
        capture_trusted_batch_authority(verifier, statement)?,
        StarkLayoutPolicy {
            is_zk: config.is_zk(),
            log_max_lde_height: config.pcs().log_max_lde_height(),
        },
    ))
}

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
        VerifierLimits,
    ),
    /// Result for a batch-STARK input proof.
    BatchStark(
        BatchStarkVerifierInputsBuilder<SC, SC::Commitment, SC::OpeningProof>,
        Vec<NonPrimitiveOpId>,
        VerifierLimits,
    ),
}

impl<SC> FriVerifierResult<SC>
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
    const fn limits(&self) -> &VerifierLimits {
        match self {
            Self::UniStark(_, _, limits) | Self::BatchStark(_, _, limits) => limits,
        }
    }
}

/// Checked built-in FRI result. The raw [`FriVerifierResult`] remains an
/// explicitly low-level result without retained contextual authority.
pub type CheckedFriVerifierResult<SC> =
    CheckedVerifierResult<FriVerifierResult<SC>, ValidatedFriContext, Val<SC>>;

impl<SC, A> VerifierCircuitResult<SC, A> for CheckedFriVerifierResult<SC>
where
    SC: FriRecursionConfig,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
            VerifierParams = FriVerifierParams,
        >,
    SC::Commitment: CheckedFriCommitment<SC::Challenge>,
    SC::OpeningProof: CheckedFriOpening<SC::Challenge, SC::Commitment>,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    Val<SC>: PrimeField64,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + PrimeCharacteristicRing,
{
    fn pack_public_inputs(
        &self,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<Vec<SC::Challenge>, VerificationError> {
        preflight_basic_fri_input(self.inner.limits(), prev)?;
        self.validate_replacement(prev)?;
        self.inner.pack_public_inputs(prev)
    }

    fn pack_private_inputs(
        &self,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<Vec<SC::Challenge>, VerificationError> {
        preflight_basic_fri_input(self.inner.limits(), prev)?;
        self.validate_replacement(prev)?;
        self.inner.pack_private_inputs(prev)
    }

    fn op_ids(&self) -> &[NonPrimitiveOpId] {
        <FriVerifierResult<SC> as VerifierCircuitResult<SC, A>>::op_ids(&self.inner)
    }
}

impl<SC> CheckedFriVerifierResult<SC>
where
    SC: FriRecursionConfig,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
            VerifierParams = FriVerifierParams,
        >,
    SC::Commitment: CheckedFriCommitment<SC::Challenge>,
    SC::OpeningProof: CheckedFriOpening<SC::Challenge, SC::Commitment>,
{
    fn validate_config(&self, config: &SC) -> Result<(), VerificationError> {
        self.policy.validate_config(config)?;
        if config.native_fri_validation_params() != Some(self.pcs.native_params())
            || config.pcs_verifier_params() != &self.pcs.recursive_params()
        {
            return Err(VerificationError::PreparedInputMismatch {
                component: "input.fri_params",
            });
        }
        Ok(())
    }

    fn validate_replacement<A>(
        &self,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<(), VerificationError>
    where
        A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
        Val<SC>: PrimeField64,
        SC::Challenge: ExtensionField<Val<SC>> + PrimeCharacteristicRing,
    {
        validate_stark_replacement(&self.stark, self.pcs.layout(), self.policy, prev)?;
        let caps = input_caps(prev, self.pcs.layout())?;
        let opening = match prev {
            RecursionInput::UniStark { proof, .. } => &proof.opening_proof,
            RecursionInput::BatchStark { proof, .. } => &proof.proof.opening_proof,
        };
        <SC::OpeningProof as CheckedFriOpening<SC::Challenge, SC::Commitment>>::validate_fri_replacement(
            opening,
            &self.pcs,
            self.pcs.layout().opening_view(),
            &caps,
        )
    }
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
    SC::Commitment: CheckedFriCommitment<SC::Challenge>,
    SC::OpeningProof: CheckedFriOpening<SC::Challenge, SC::Commitment>,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    Val<SC>: PrimeField64,
    SC::Challenge: BasedVectorSpace<Val<SC>> + From<Val<SC>>,
{
    fn pack_public_inputs(
        &self,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<Vec<SC::Challenge>, VerificationError> {
        preflight_basic_fri_input(self.limits(), prev)?;
        match (self, prev) {
            (
                Self::UniStark(builder, _, limits),
                RecursionInput::UniStark {
                    proof,
                    public_inputs,
                    preprocessed_commit,
                    ..
                },
            ) => {
                let values =
                    builder.try_pack_public_values(public_inputs, proof, preprocessed_commit)?;
                if values.len() > limits.max_total_scalar_elements {
                    return Err(VerificationError::ResourceLimitExceeded {
                        component: "packed scalar elements",
                        actual: values.len(),
                        limit: limits.max_total_scalar_elements,
                    });
                }
                Ok(values)
            }
            (
                Self::BatchStark(builder, _, limits),
                RecursionInput::BatchStark {
                    proof,
                    common_data,
                    table_public_inputs,
                },
            ) => {
                let values = builder.try_pack_public_values(
                    table_public_inputs,
                    &proof.proof,
                    common_data,
                )?;
                if values.len() > limits.max_total_scalar_elements {
                    return Err(VerificationError::ResourceLimitExceeded {
                        component: "packed scalar elements",
                        actual: values.len(),
                        limit: limits.max_total_scalar_elements,
                    });
                }
                Ok(values)
            }
            _ => Err(VerificationError::InvalidProofShape(
                "RecursionInput variant does not match verifier result".to_string(),
            )),
        }
    }

    fn pack_private_inputs(
        &self,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<Vec<SC::Challenge>, VerificationError> {
        preflight_basic_fri_input(self.limits(), prev)?;
        match (self, prev) {
            (Self::UniStark(builder, _, limits), RecursionInput::UniStark { proof, .. }) => {
                let values = builder.try_pack_private_values(proof)?;
                if values.len() > limits.max_total_scalar_elements {
                    return Err(VerificationError::ResourceLimitExceeded {
                        component: "packed scalar elements",
                        actual: values.len(),
                        limit: limits.max_total_scalar_elements,
                    });
                }
                Ok(values)
            }
            (Self::BatchStark(builder, _, limits), RecursionInput::BatchStark { proof, .. }) => {
                let values = builder.try_pack_private_values(&proof.proof)?;
                if values.len() > limits.max_total_scalar_elements {
                    return Err(VerificationError::ResourceLimitExceeded {
                        component: "packed scalar elements",
                        actual: values.len(),
                        limit: limits.max_total_scalar_elements,
                    });
                }
                Ok(values)
            }
            _ => Err(VerificationError::InvalidProofShape(
                "RecursionInput variant does not match verifier result".to_string(),
            )),
        }
    }

    fn op_ids(&self) -> &[NonPrimitiveOpId] {
        match self {
            Self::UniStark(_, ids, _) | Self::BatchStark(_, ids, _) => ids,
        }
    }
}

fn build_verifier_circuit_impl<SC, A, const WIDTH: usize, const RATE: usize, C>(
    backend: &FriRecursionBackend<WIDTH, RATE, C>,
    prev: &RecursionInput<'_, SC, A>,
    config: &SC,
    circuit: &mut CircuitBuilder<SC::Challenge>,
    non_primitive_provers: &[Box<dyn TableProver<SC>>],
) -> Result<CheckedFriVerifierResult<SC>, VerificationError>
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
            VerifierParams = FriVerifierParams,
        >,
    SC::Commitment: CheckedFriCommitment<SC::Challenge>,
    SC::OpeningProof: CheckedFriOpening<SC::Challenge, SC::Commitment>,
{
    let (pcs_context, stark_authority, policy) =
        preflight_fri_context(config, prev, non_primitive_provers)?;
    match prev {
        RecursionInput::UniStark {
            proof,
            air,
            public_inputs,
            preprocessed_commit,
        } => {
            let verifier_inputs =
                StarkVerifierInputsBuilder::<SC, SC::Commitment, SC::OpeningProof>::try_allocate(
                    circuit,
                    proof,
                    preprocessed_commit.as_ref(),
                    public_inputs.len(),
                )?;
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
            Ok(CheckedVerifierResult::new(
                FriVerifierResult::UniStark(verifier_inputs, op_ids, backend.limits),
                pcs_context,
                stark_authority,
                policy,
            ))
        }
        RecursionInput::BatchStark {
            proof,
            common_data,
            table_public_inputs: _,
        } => {
            validate_batch_proof_native::<SC, SC::Commitment, SC::OpeningProof>(&proof.proof)?;
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
            Ok(CheckedVerifierResult::new(
                FriVerifierResult::BatchStark(verifier_inputs, op_ids, backend.limits),
                pcs_context,
                stark_authority,
                policy,
            ))
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
            VerifierParams = FriVerifierParams,
        >,
    SC::Commitment: CheckedFriCommitment<SC::Challenge>,
    SC::OpeningProof: CheckedFriOpening<SC::Challenge, SC::Commitment>,
{
    type VerifierResult = CheckedFriVerifierResult<SC>;

    fn validate_input(
        &self,
        config: &SC,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<(), VerificationError> {
        let provers = match prev {
            RecursionInput::BatchStark { proof, .. } => {
                PcsRecursionBackend::<SC, A, 2>::non_primitive_provers(self, proof.ext_degree)
            }
            _ => Vec::new(),
        };
        preflight_fri_context(config, prev, &provers).map(|_| ())
    }

    fn preflight_input(
        &self,
        config: &SC,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<(), VerificationError> {
        preflight_fri_input(config, &self.0.limits, prev)
    }

    /// # Errors
    /// Propagates any error while enabling the verifier operations required by the config.
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
        preflight_fri_input(config, &self.0.limits, prev)?;
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
        preflight_fri_input(config, &self.0.limits, prev)
            .map_err(|_| "FRI input exceeds verifier resource limits")?;
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

    fn set_private_data_for_result(
        &self,
        config: &SC,
        runner: &mut CircuitRunner<'_, SC::Challenge>,
        result: &Self::VerifierResult,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<(), &'static str> {
        preflight_fri_input(config, &self.0.limits, prev)
            .map_err(|_| "FRI input exceeds verifier resource limits")?;
        result
            .validate_config(config)
            .map_err(|_| "FRI verifier configuration differs from retained authority")?;
        result
            .validate_replacement(prev)
            .map_err(|_| "FRI replacement input failed retained contextual validation")?;
        <Self as PcsRecursionBackend<SC, A, 2>>::set_private_data(
            self,
            config,
            runner,
            <Self::VerifierResult as VerifierCircuitResult<SC, A>>::op_ids(result),
            prev,
        )
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
            VerifierParams = FriVerifierParams,
        >,
    SC::Commitment: CheckedFriCommitment<SC::Challenge>,
    SC::OpeningProof: CheckedFriOpening<SC::Challenge, SC::Commitment>,
{
    type VerifierResult = CheckedFriVerifierResult<SC>;

    fn validate_input(
        &self,
        config: &SC,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<(), VerificationError> {
        let provers = match prev {
            RecursionInput::BatchStark { proof, .. } => {
                PcsRecursionBackend::<SC, A, 4>::non_primitive_provers(self, proof.ext_degree)
            }
            _ => Vec::new(),
        };
        preflight_fri_context(config, prev, &provers).map(|_| ())
    }

    fn preflight_input(
        &self,
        config: &SC,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<(), VerificationError> {
        preflight_fri_input(config, &self.0.limits, prev)
    }

    /// # Errors
    /// Propagates any error while enabling the verifier operations required by the config.
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
        preflight_fri_input(config, &self.0.limits, prev)?;
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
        preflight_fri_input(config, &self.0.limits, prev)
            .map_err(|_| "FRI input exceeds verifier resource limits")?;
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

    fn set_private_data_for_result(
        &self,
        config: &SC,
        runner: &mut CircuitRunner<'_, SC::Challenge>,
        result: &Self::VerifierResult,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<(), &'static str> {
        preflight_fri_input(config, &self.0.limits, prev)
            .map_err(|_| "FRI input exceeds verifier resource limits")?;
        result
            .validate_config(config)
            .map_err(|_| "FRI verifier configuration differs from retained authority")?;
        result
            .validate_replacement(prev)
            .map_err(|_| "FRI replacement input failed retained contextual validation")?;
        <Self as PcsRecursionBackend<SC, A, 4>>::set_private_data(
            self,
            config,
            runner,
            <Self::VerifierResult as VerifierCircuitResult<SC, A>>::op_ids(result),
            prev,
        )
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
            VerifierParams = FriVerifierParams,
        >,
    SC::Commitment: CheckedFriCommitment<SC::Challenge>,
    SC::OpeningProof: CheckedFriOpening<SC::Challenge, SC::Commitment>,
{
    type VerifierResult = CheckedFriVerifierResult<SC>;

    fn validate_input(
        &self,
        config: &SC,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<(), VerificationError> {
        let provers = match prev {
            RecursionInput::BatchStark { proof, .. } => {
                PcsRecursionBackend::<SC, A, 5>::non_primitive_provers(self, proof.ext_degree)
            }
            _ => Vec::new(),
        };
        preflight_fri_context(config, prev, &provers).map(|_| ())
    }

    fn preflight_input(
        &self,
        config: &SC,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<(), VerificationError> {
        preflight_fri_input(config, &self.0.limits, prev)
    }

    /// # Errors
    /// Propagates any error while enabling the verifier operations required by the config.
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
        preflight_fri_input(config, &self.0.limits, prev)?;
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
        preflight_fri_input(config, &self.0.limits, prev)
            .map_err(|_| "FRI input exceeds verifier resource limits")?;
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

    fn set_private_data_for_result(
        &self,
        config: &SC,
        runner: &mut CircuitRunner<'_, SC::Challenge>,
        result: &Self::VerifierResult,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<(), &'static str> {
        preflight_fri_input(config, &self.0.limits, prev)
            .map_err(|_| "FRI input exceeds verifier resource limits")?;
        result
            .validate_config(config)
            .map_err(|_| "FRI verifier configuration differs from retained authority")?;
        result
            .validate_replacement(prev)
            .map_err(|_| "FRI replacement input failed retained contextual validation")?;
        <Self as PcsRecursionBackend<SC, A, 5>>::set_private_data(
            self,
            config,
            runner,
            <Self::VerifierResult as VerifierCircuitResult<SC, A>>::op_ids(result),
            prev,
        )
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

macro_rules! impl_prepared_fri_backend {
    ($backend:ty, $d:literal, $binomial_bound:path) => {
        impl<SC, A, const WIDTH: usize, const RATE: usize, C> PreparedPcsRecursionBackend<SC, A, $d>
            for $backend
        where
            SC: FriRecursionConfig + Send + Sync + 'static,
            A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
            C: ChallengerPermConfig + Copy + 'static,
            Val<SC>: PrimeField64 + StarkField + $binomial_bound,
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
                    VerifierParams = FriVerifierParams,
                >,
            SC::Commitment: CheckedFriCommitment<SC::Challenge>,
            SC::OpeningProof: CheckedFriOpening<SC::Challenge, SC::Commitment>,
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
                preflight_fri_input(config, &self.0.limits, source)?;
                let provers = match source {
                    RecursionInput::BatchStark { proof, .. } => {
                        PcsRecursionBackend::<SC, A, $d>::non_primitive_provers(
                            self,
                            proof.ext_degree,
                        )
                    }
                    _ => Vec::new(),
                };
                capture_builtin_input_contract::<SC, A, SC::Commitment, SC::OpeningProof>(
                    config,
                    source,
                    false,
                    |_| provers,
                )
            }

            fn validate_prepared_input(
                &self,
                config: &SC,
                contract: &Self::InputContract,
                input: &PreparedInput<'_, SC>,
            ) -> Result<(), VerificationError> {
                preflight_fri_prepared(config, &self.0.limits, input)?;
                validate_builtin_prepared_input::<SC, SC::Commitment, SC::OpeningProof>(
                    contract, input,
                )
            }

            fn preflight_input(
                &self,
                config: &SC,
                input: &PreparedInput<'_, SC>,
            ) -> Result<(), VerificationError> {
                preflight_fri_prepared(config, &self.0.limits, input)
            }
        }

        impl<SC, A, const WIDTH: usize, const RATE: usize, C> TrustedPcsRecursionBackend<SC, A, $d>
            for $backend
        where
            SC: FriRecursionConfig + Send + Sync + 'static,
            A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
            C: ChallengerPermConfig + Copy + 'static,
            Val<SC>: PrimeField64 + StarkField + $binomial_bound,
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
                    VerifierParams = FriVerifierParams,
                >,
            SC::Commitment: CheckedFriCommitment<SC::Challenge>
                + PreparedRecursive<SC::Challenge>
                + ConstrainConstantCommitment<SC::Challenge>,
            SC::OpeningProof:
                CheckedFriOpening<SC::Challenge, SC::Commitment> + PreparedRecursive<SC::Challenge>,
        {
            fn preflight_trusted_batch(
                &self,
                verifier: &CircuitVerifier<SC>,
                proof: &BatchStarkProof<SC>,
            ) -> Result<(), VerificationError> {
                let pcs_usage = <SC::OpeningProof as CheckedFriOpening<
                    SC::Challenge,
                    SC::Commitment,
                >>::check_fri_resources(
                    &proof.proof.opening_proof, &self.0.limits
                )?;
                let mut usage = check_trusted_batch_stark_resources::<SC, SC::Commitment>(
                    &self.0.limits,
                    verifier,
                    proof,
                    pcs_usage,
                )?;
                check_fri_restoration_budget(
                    verifier.config(),
                    &self.0.limits,
                    proof.proof.degree_bits.iter().copied().max().unwrap_or(0),
                    &mut usage,
                )
            }

            fn capture_trusted_batch_input_contract(
                &self,
                verifier: &CircuitVerifier<SC>,
                proof: &BatchStarkProof<SC>,
                expected_statement: &[Val<SC>],
            ) -> Result<Self::InputContract, VerificationError> {
                <Self as TrustedPcsRecursionBackend<SC, A, $d>>::preflight_trusted_batch(
                    self, verifier, proof,
                )?;
                capture_trusted_batch_input_contract::<SC, SC::Commitment, SC::OpeningProof>(
                    verifier,
                    proof,
                    expected_statement,
                )
            }

            fn validate_trusted_batch_input(
                &self,
                verifier: &CircuitVerifier<SC>,
                contract: &Self::InputContract,
                proof: &BatchStarkProof<SC>,
                expected_statement: &[Val<SC>],
            ) -> Result<(), VerificationError> {
                <Self as TrustedPcsRecursionBackend<SC, A, $d>>::preflight_trusted_batch(
                    self, verifier, proof,
                )?;
                validate_trusted_batch_input::<SC, SC::Commitment, SC::OpeningProof>(
                    verifier,
                    contract,
                    proof,
                    expected_statement,
                )
            }

            fn build_trusted_batch_verifier_circuit(
                &self,
                verifier: &CircuitVerifier<SC>,
                proof: &BatchStarkProof<SC>,
                statement: &[Val<SC>],
                circuit: &mut CircuitBuilder<SC::Challenge>,
            ) -> Result<Self::VerifierResult, VerificationError> {
                <Self as TrustedPcsRecursionBackend<SC, A, $d>>::preflight_trusted_batch(
                    self, verifier, proof,
                )?;
                let degree = verifier.relation().ext_degree();
                let table_public_inputs = match degree {
                    1 => trusted_batch_tables::<SC, 1>(verifier, statement)?.public_values,
                    2 => trusted_batch_tables::<SC, 2>(verifier, statement)?.public_values,
                    4 => trusted_batch_tables::<SC, 4>(verifier, statement)?.public_values,
                    5 => trusted_batch_tables::<SC, 5>(verifier, statement)?.public_values,
                    degree => {
                        return Err(VerificationError::InvalidProofShape(format!(
                            "unsupported trusted batch verifier ext_degree {degree}"
                        )));
                    }
                };
                preflight_basic_fri_input(
                    &self.0.limits,
                    &RecursionInput::<SC, A>::BatchStark {
                        proof,
                        common_data: verifier.common_data(),
                        table_public_inputs,
                    },
                )?;
                let (pcs_context, stark_authority, policy) = match degree {
                    1 => preflight_trusted_fri_batch::<SC, A, 1>(verifier, proof, statement)?,
                    2 => preflight_trusted_fri_batch::<SC, A, 2>(verifier, proof, statement)?,
                    4 => preflight_trusted_fri_batch::<SC, A, 4>(verifier, proof, statement)?,
                    5 => preflight_trusted_fri_batch::<SC, A, 5>(verifier, proof, statement)?,
                    _ => unreachable!(),
                };
                validate_batch_proof_native::<SC, SC::Commitment, SC::OpeningProof>(&proof.proof)?;
                macro_rules! build_for_degree {
                    ($trace_d:literal) => {
                        verify_trusted_p3_batch_proof_circuit::<
                            SC,
                            SC::Commitment,
                            SC::InputProof,
                            SC::OpeningProof,
                            _,
                            _,
                            WIDTH,
                            RATE,
                            $trace_d,
                        >(
                            verifier,
                            circuit,
                            proof,
                            statement,
                            verifier.config().pcs_verifier_params(),
                            &LogUpGadget::new(),
                            self.0.challenger_perm_config,
                        )
                    };
                }
                let (verifier_inputs, op_ids) = match degree {
                    1 => build_for_degree!(1)?,
                    2 => build_for_degree!(2)?,
                    4 => build_for_degree!(4)?,
                    5 => build_for_degree!(5)?,
                    _ => unreachable!(),
                };
                Ok(CheckedVerifierResult::new(
                    FriVerifierResult::BatchStark(verifier_inputs, op_ids, self.0.limits),
                    pcs_context,
                    stark_authority,
                    policy,
                ))
            }

            fn set_private_data_for_trusted_batch(
                &self,
                verifier: &CircuitVerifier<SC>,
                proof: &BatchStarkProof<SC>,
                statement: &[Val<SC>],
                runner: &mut CircuitRunner<'_, SC::Challenge>,
                op_ids: &[NonPrimitiveOpId],
            ) -> Result<(), VerificationError> {
                <Self as TrustedPcsRecursionBackend<SC, A, $d>>::preflight_trusted_batch(
                    self, verifier, proof,
                )?;
                let (transcript, table_public_inputs) = match verifier.relation().ext_degree() {
                    1 => (
                        replay_trusted_batch_layer_transcript::<SC, 1>(verifier, proof, statement)?,
                        trusted_batch_tables::<SC, 1>(verifier, statement)?.public_values,
                    ),
                    2 => (
                        replay_trusted_batch_layer_transcript::<SC, 2>(verifier, proof, statement)?,
                        trusted_batch_tables::<SC, 2>(verifier, statement)?.public_values,
                    ),
                    4 => (
                        replay_trusted_batch_layer_transcript::<SC, 4>(verifier, proof, statement)?,
                        trusted_batch_tables::<SC, 4>(verifier, statement)?.public_values,
                    ),
                    5 => (
                        replay_trusted_batch_layer_transcript::<SC, 5>(verifier, proof, statement)?,
                        trusted_batch_tables::<SC, 5>(verifier, statement)?.public_values,
                    ),
                    degree => {
                        return Err(VerificationError::InvalidProofShape(format!(
                            "unsupported trusted batch verifier ext_degree {degree}"
                        )));
                    }
                };
                let prev = RecursionInput::<SC, A>::BatchStark {
                    proof,
                    common_data: verifier.common_data(),
                    table_public_inputs,
                };
                SC::with_fri_opening_proof(&prev, |opening_proof| {
                    SC::set_fri_private_data(
                        verifier.config(),
                        runner,
                        op_ids,
                        opening_proof,
                        transcript,
                    )
                })
                .map_err(|message| VerificationError::InvalidProofShape(message.into()))
            }

            fn constrain_trusted_preprocessing(
                &self,
                circuit: &mut CircuitBuilder<SC::Challenge>,
                result: &Self::VerifierResult,
                expected: Option<&NativeCommitment<SC>>,
            ) -> Result<(), VerificationError> {
                let target = match &result.inner {
                    FriVerifierResult::UniStark(builder, ..) => {
                        builder.preprocessed_commit.as_ref()
                    }
                    FriVerifierResult::BatchStark(builder, ..) => builder
                        .common_data
                        .preprocessed
                        .as_ref()
                        .map(|group| &group.commitment),
                };
                match (target, expected) {
                    (None, None) => Ok(()),
                    (Some(target), Some(expected)) => target.constrain_constant(circuit, expected),
                    _ => Err(VerificationError::InvalidProofShape(
                        "trusted child preprocessing commitment presence mismatch".into(),
                    )),
                }
            }
        }
    };
}

impl_prepared_fri_backend!(
    FriRecursionBackendForExt<2, WIDTH, RATE, C>,
    2,
    BinomiallyExtendable<2>
);
impl_prepared_fri_backend!(
    FriRecursionBackendForExt<4, WIDTH, RATE, C>,
    4,
    BinomiallyExtendable<4>
);
impl_prepared_fri_backend!(
    FriRecursionBackendD5<WIDTH, RATE, C>,
    5,
    BinomiallyExtendable<4>
);
