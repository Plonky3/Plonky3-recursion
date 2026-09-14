//! WHIR PCS backend for the unified recursion API.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};

use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_circuit_prover::batch_stark_prover::{
    BatchStarkProof, CircuitVerifier, RecomposeAirBuilder, RecomposeProver,
    lookups_for_circuit_table_air, poseidon2_air_builders_for_configs, poseidon2_preprocessor,
    recompose_preprocessor,
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
use crate::input_contract::{CheckedWhirOpening, ValidatedWhirContext};
use crate::ops::Poseidon2Config;
use crate::pcs::fri::CheckedFriCommitment;
use crate::pcs::whir::uni::WhirUniVerifierParams;
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
        + CheckedRecursive<Self::Challenge>
        + CheckedFriCommitment<Self::Challenge>
        + ObservableCommitment;

    /// Input proof type for the PCS (unit type for WHIR, which needs no per-opening input proof).
    type InputProof: Recursive<Self::Challenge>;

    /// Opening proof type used in the verifier circuit (`WhirUniProofTargets`).
    type OpeningProof: Recursive<
            Self::Challenge,
            Input = <Self::Pcs as Pcs<Self::Challenge, Self::Challenger>>::Proof,
        > + CheckedRecursive<Self::Challenge>;

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
    pub(crate) limits: VerifierLimits,
}

impl<const WIDTH: usize, const RATE: usize, C: ChallengerPermConfig>
    WhirRecursionBackend<WIDTH, RATE, C>
{
    /// Create a new backend with the given challenger permutation configuration.
    pub fn new(challenger_perm_config: C) -> Self {
        Self {
            challenger_perm_config,
            limits: VerifierLimits::default(),
        }
    }

    /// Tag this backend for a fixed batch/extension degree `D` (only `4` is supported today).
    pub const fn for_extension_degree<const D: usize>(
        self,
    ) -> WhirRecursionBackendForExt<D, WIDTH, RATE, C> {
        WhirRecursionBackendForExt(self)
    }

    #[must_use]
    pub const fn with_limits(mut self, limits: VerifierLimits) -> Self {
        self.limits = limits;
        self
    }

    pub const fn limits(&self) -> &VerifierLimits {
        &self.limits
    }
}

fn preflight_basic_whir_input<SC, A>(
    limits: &VerifierLimits,
    prev: &RecursionInput<'_, SC, A>,
) -> Result<InputResourceUsage, VerificationError>
where
    SC: WhirRecursionConfig,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    SC::Commitment: CheckedFriCommitment<SC::Challenge>,
    SC::OpeningProof: CheckedWhirOpening<Val<SC>, SC::Challenge, SC::Commitment>,
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
            let pcs_usage = <SC::OpeningProof as CheckedWhirOpening<
                Val<SC>,
                SC::Challenge,
                SC::Commitment,
            >>::check_whir_resources(&proof.opening_proof, limits)?;
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
            let pcs_usage = <SC::OpeningProof as CheckedWhirOpening<
                Val<SC>,
                SC::Challenge,
                SC::Commitment,
            >>::check_whir_resources(
                &proof.proof.opening_proof, limits
            )?;
            usage.merge(limits, pcs_usage)?;
            Ok(usage)
        }
    }
}

fn preflight_basic_whir_prepared<SC>(
    limits: &VerifierLimits,
    input: &PreparedInput<'_, SC>,
) -> Result<InputResourceUsage, VerificationError>
where
    SC: WhirRecursionConfig,
    SC::Commitment: CheckedFriCommitment<SC::Challenge>,
    SC::OpeningProof: CheckedWhirOpening<Val<SC>, SC::Challenge, SC::Commitment>,
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
            let pcs_usage = <SC::OpeningProof as CheckedWhirOpening<
                Val<SC>,
                SC::Challenge,
                SC::Commitment,
            >>::check_whir_resources(&proof.opening_proof, limits)?;
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
            let pcs_usage = <SC::OpeningProof as CheckedWhirOpening<
                Val<SC>,
                SC::Challenge,
                SC::Commitment,
            >>::check_whir_resources(
                &proof.proof.opening_proof, limits
            )?;
            usage.merge(limits, pcs_usage)?;
            Ok(usage)
        }
    }
}

fn check_whir_restoration_budget<SC>(
    config: &SC,
    limits: &VerifierLimits,
    degree_bits: usize,
    usage: &mut InputResourceUsage,
) -> Result<(), VerificationError>
where
    SC: WhirRecursionConfig,
    Val<SC>: TwoAdicField,
    SC::OpeningProof: CheckedWhirOpening<Val<SC>, SC::Challenge, SC::Commitment>,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
            VerifierParams = WhirUniVerifierParams<Val<SC>>,
        >,
{
    let params = config.pcs_verifier_params();
    let padded_degree = degree_bits.max(params.folding());
    let width_log = if usage.max_whir_opening_width_sum <= 1 {
        0
    } else {
        usize::BITS as usize - (usage.max_whir_opening_width_sum - 1).leading_zeros() as usize
    };
    // A valid WHIR argument stacks each committed matrix column into a
    // separate 2^padded_degree slot. Summing every opening-batch width can
    // repeat a matrix opened at several points, but cannot underestimate the
    // true stack, so this arity safely dominates every restored tree.
    let stacked_num_variables = padded_degree.checked_add(width_log).ok_or(
        VerificationError::ResourceArithmeticOverflow {
            component: "WHIR stacked domain log",
        },
    )?;
    usage.check_log_degree(limits, stacked_num_variables)?;
    let depth = stacked_num_variables
        .checked_add(params.protocol_params().starting_log_inv_rate)
        .ok_or(VerificationError::ResourceArithmeticOverflow {
            component: "restored authentication-path hashes",
        })?;
    usage.check_log_degree(limits, depth)?;
    let queries = usage.queries;
    usage.add_restored_authentication_path_hashes(limits, queries, depth)
}

fn preflight_whir_input<SC, A>(
    config: &SC,
    limits: &VerifierLimits,
    input: &RecursionInput<'_, SC, A>,
) -> Result<(), VerificationError>
where
    SC: WhirRecursionConfig,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    Val<SC>: TwoAdicField,
    SC::OpeningProof: CheckedWhirOpening<Val<SC>, SC::Challenge, SC::Commitment>,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
            VerifierParams = WhirUniVerifierParams<Val<SC>>,
        >,
{
    let mut usage = preflight_basic_whir_input(limits, input)?;
    match input {
        RecursionInput::UniStark { proof, .. } => {
            check_whir_restoration_budget(config, limits, proof.degree_bits, &mut usage)
        }
        RecursionInput::BatchStark { proof, .. } => check_whir_restoration_budget(
            config,
            limits,
            proof.proof.degree_bits.iter().copied().max().unwrap_or(0),
            &mut usage,
        ),
    }
}

fn preflight_whir_prepared<SC>(
    config: &SC,
    limits: &VerifierLimits,
    input: &PreparedInput<'_, SC>,
) -> Result<(), VerificationError>
where
    SC: WhirRecursionConfig,
    Val<SC>: TwoAdicField,
    SC::OpeningProof: CheckedWhirOpening<Val<SC>, SC::Challenge, SC::Commitment>,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
            VerifierParams = WhirUniVerifierParams<Val<SC>>,
        >,
{
    let mut usage = preflight_basic_whir_prepared(limits, input)?;
    match input {
        PreparedInput::UniStark { proof, .. } => {
            check_whir_restoration_budget(config, limits, proof.degree_bits, &mut usage)
        }
        PreparedInput::BatchStark { proof, .. } => check_whir_restoration_budget(
            config,
            limits,
            proof.proof.degree_bits.iter().copied().max().unwrap_or(0),
            &mut usage,
        ),
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

fn plan_whir_batch<SC, A>(
    config: &SC,
    prev: &RecursionInput<'_, SC, A>,
    provers: &[Box<dyn TableProver<SC>>],
) -> Result<crate::input_contract::stark_layout::NativeStarkLayout<'static>, VerificationError>
where
    SC: WhirRecursionConfig + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    Val<SC>: PrimeField64 + TwoAdicField,
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
    if proof.ext_degree != 4 {
        return Err(VerificationError::InvalidProofShape(format!(
            "WhirRecursionBackend supports batch proofs of ext_degree 4, got {}",
            proof.ext_degree
        )));
    }
    let tables = reconstruct_batch_tables::<SC, 4>(config, proof, provers)?;
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
            lookups_for_circuit_table_air::<SC, 4>(&air.to_table_air(), trace_len, config.is_zk())
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

#[allow(clippy::type_complexity)]
fn preflight_whir_context<SC, A>(
    config: &SC,
    prev: &RecursionInput<'_, SC, A>,
    provers: &[Box<dyn TableProver<SC>>],
) -> Result<
    (
        ValidatedWhirContext<Val<SC>>,
        StarkPackingAuthority<Val<SC>>,
        StarkLayoutPolicy,
    ),
    VerificationError,
>
where
    SC: WhirRecursionConfig + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    Val<SC>: PrimeField64 + TwoAdicField,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + ExtensionField<Val<SC>>
        + PrimeCharacteristicRing
        + ExtractBinomialW<Val<SC>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        From<p3_uni_stark::SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    SC::OpeningProof: CheckedWhirOpening<Val<SC>, SC::Challenge, SC::Commitment>,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
            VerifierParams = WhirUniVerifierParams<Val<SC>>,
        >,
{
    crate::prepared::input::validate_builtin_input_raw::<SC, A, SC::Commitment, SC::OpeningProof>(
        prev,
    )?;
    if config.is_zk() != 0 {
        return Err(VerificationError::InvalidProofShape(
            "WhirRecursionBackend supports only non-ZK STARK inputs".into(),
        ));
    }
    if config
        .pcs_verifier_params()
        .permutation_config()
        .is_arity4_shape()
    {
        return Err(VerificationError::InvalidProofShape(
            "WhirRecursionBackend supports only binary Merkle commitments".into(),
        ));
    }
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
        RecursionInput::BatchStark { .. } => plan_whir_batch(config, prev, provers)?,
    };
    let caps = input_caps(prev, &layout)?;
    let opening = match prev {
        RecursionInput::UniStark { proof, .. } => &proof.opening_proof,
        RecursionInput::BatchStark { proof, .. } => &proof.proof.opening_proof,
    };
    let context = <SC::OpeningProof as CheckedWhirOpening<
        Val<SC>,
        SC::Challenge,
        SC::Commitment,
    >>::validate_whir_context(
        opening,
        config.pcs_verifier_params(),
        layout.opening_view(),
        &caps,
    )?;
    let authority = capture_stark_authority(prev);
    let policy = StarkLayoutPolicy::from_config(config);
    Ok((context, authority, policy))
}

fn preflight_trusted_whir_batch<SC, A>(
    verifier: &CircuitVerifier<SC>,
    proof: &BatchStarkProof<SC>,
    statement: &[Val<SC>],
) -> Result<
    (
        ValidatedWhirContext<Val<SC>>,
        StarkPackingAuthority<Val<SC>>,
        StarkLayoutPolicy,
    ),
    VerificationError,
>
where
    SC: WhirRecursionConfig + Send + Sync + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    Val<SC>: PrimeField64 + StarkField + TwoAdicField,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + ExtensionField<Val<SC>>
        + PrimeCharacteristicRing
        + ExtractBinomialW<Val<SC>>
        + TwoAdicField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        From<p3_uni_stark::SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    SC::OpeningProof: CheckedWhirOpening<Val<SC>, SC::Challenge, SC::Commitment>,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
            VerifierParams = WhirUniVerifierParams<Val<SC>>,
        >,
{
    verifier
        .verify(proof, statement)
        .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
    let config = verifier.config();
    if config.is_zk() != 0 {
        return Err(VerificationError::InvalidProofShape(
            "WhirRecursionBackend supports only non-ZK STARK inputs".into(),
        ));
    }
    if config
        .pcs_verifier_params()
        .permutation_config()
        .is_arity4_shape()
    {
        return Err(VerificationError::InvalidProofShape(
            "WhirRecursionBackend supports only binary Merkle commitments".into(),
        ));
    }
    let tables = trusted_batch_tables::<SC, 4>(verifier, statement)?;
    let lookups = tables
        .airs
        .iter()
        .zip(&tables.trace_lens)
        .map(|(air, &trace_len)| {
            lookups_for_circuit_table_air::<SC, 4>(&air.to_table_air(), trace_len, config.is_zk())
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
    let context = <SC::OpeningProof as CheckedWhirOpening<
        Val<SC>,
        SC::Challenge,
        SC::Commitment,
    >>::validate_whir_context(
        &proof.proof.opening_proof,
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

impl<const D: usize, const WIDTH: usize, const RATE: usize, C: ChallengerPermConfig>
    WhirRecursionBackendForExt<D, WIDTH, RATE, C>
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
        VerifierLimits,
    ),
    /// Result for a batch-STARK input proof.
    BatchStark(
        BatchStarkVerifierInputsBuilder<SC, SC::Commitment, SC::OpeningProof>,
        Vec<NonPrimitiveOpId>,
        VerifierLimits,
    ),
}

impl<SC> WhirVerifierResult<SC>
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
    const fn limits(&self) -> &VerifierLimits {
        match self {
            Self::UniStark(_, _, limits) | Self::BatchStark(_, _, limits) => limits,
        }
    }
}

/// Checked built-in WHIR result retaining canonical proof, cap, and packing authority.
pub type CheckedWhirVerifierResult<SC> =
    CheckedVerifierResult<WhirVerifierResult<SC>, ValidatedWhirContext<Val<SC>>, Val<SC>>;

impl<SC, A> VerifierCircuitResult<SC, A> for CheckedWhirVerifierResult<SC>
where
    SC: WhirRecursionConfig,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
            VerifierParams = WhirUniVerifierParams<Val<SC>>,
        >,
    SC::OpeningProof: CheckedWhirOpening<Val<SC>, SC::Challenge, SC::Commitment>,
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
        preflight_basic_whir_input(self.inner.limits(), prev)?;
        self.validate_replacement(prev)?;
        self.inner.pack_public_inputs(prev)
    }

    fn pack_private_inputs(
        &self,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<Vec<SC::Challenge>, VerificationError> {
        preflight_basic_whir_input(self.inner.limits(), prev)?;
        self.validate_replacement(prev)?;
        self.inner.pack_private_inputs(prev)
    }

    fn op_ids(&self) -> &[NonPrimitiveOpId] {
        <WhirVerifierResult<SC> as VerifierCircuitResult<SC, A>>::op_ids(&self.inner)
    }
}

impl<SC> CheckedWhirVerifierResult<SC>
where
    SC: WhirRecursionConfig,
    SC::Pcs: RecursivePcs<
            SC,
            SC::InputProof,
            SC::OpeningProof,
            SC::Commitment,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
            VerifierParams = WhirUniVerifierParams<Val<SC>>,
        >,
    SC::OpeningProof: CheckedWhirOpening<Val<SC>, SC::Challenge, SC::Commitment>,
{
    fn validate_config(&self, config: &SC) -> Result<(), VerificationError>
    where
        Val<SC>: PrimeField64 + TwoAdicField,
        SC::Challenge: ExtensionField<Val<SC>> + TwoAdicField,
    {
        self.policy.validate_config(config)?;
        let params = config.pcs_verifier_params();
        if self.pcs.permutation() != params.permutation_config()
            || self.pcs.verifier_params().len() != self.pcs.layout().commitment_count()
        {
            return Err(VerificationError::PreparedInputMismatch {
                component: "input.whir_params",
            });
        }
        for (ordinal, expected) in self.pcs.verifier_params().iter().enumerate() {
            let stacked = crate::pcs::whir::uni::plan::checked_stacked_num_variables(
                self.pcs
                    .layout()
                    .opening_view()
                    .matrices(ordinal)
                    .map(|matrix| {
                        (
                            crate::pcs::whir::uni::plan::padded_arity(
                                matrix.log_height(),
                                params.folding(),
                            ),
                            matrix.width(),
                        )
                    }),
            )
            .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
            let actual = params
                .round_params::<SC::Challenge, crate::pcs::whir::uni::recursive_pcs::DummyChallenger<Val<SC>>>(stacked)?;
            if actual != *expected {
                return Err(VerificationError::PreparedInputMismatch {
                    component: "input.whir_params",
                });
            }
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
        <SC::OpeningProof as CheckedWhirOpening<
            Val<SC>,
            SC::Challenge,
            SC::Commitment,
        >>::validate_whir_replacement(
            opening,
            &self.pcs,
            self.pcs.layout().opening_view(),
            &caps,
        )
    }
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
    SC::OpeningProof: CheckedWhirOpening<Val<SC>, SC::Challenge, SC::Commitment>,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    Val<SC>: PrimeField64,
    SC::Challenge: BasedVectorSpace<Val<SC>> + From<Val<SC>>,
{
    fn pack_public_inputs(
        &self,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<Vec<SC::Challenge>, VerificationError> {
        preflight_basic_whir_input(self.limits(), prev)?;
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
        preflight_basic_whir_input(self.limits(), prev)?;
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
    SC::OpeningProof: CheckedWhirOpening<Val<SC>, SC::Challenge, SC::Commitment>,
{
    type VerifierResult = CheckedWhirVerifierResult<SC>;

    fn validate_input(
        &self,
        config: &SC,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<(), VerificationError> {
        let provers = match prev {
            RecursionInput::BatchStark { proof, .. } => {
                PcsRecursionBackend::<SC, A, 4>::non_primitive_provers(self, proof.ext_degree)
            }
            RecursionInput::UniStark { .. } => Vec::new(),
        };
        preflight_whir_context(config, prev, &provers).map(|_| ())
    }

    fn preflight_input(
        &self,
        config: &SC,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<(), VerificationError> {
        preflight_whir_input(config, &self.0.limits, prev)
    }

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
        preflight_whir_input(config, &self.0.limits, prev)?;
        let provers = match prev {
            RecursionInput::BatchStark { proof, .. } => {
                PcsRecursionBackend::<SC, A, 4>::non_primitive_provers(self, proof.ext_degree)
            }
            RecursionInput::UniStark { .. } => Vec::new(),
        };
        let (pcs_context, stark_authority, policy) =
            preflight_whir_context(config, prev, &provers)?;
        let inner: WhirVerifierResult<SC> = match prev {
            RecursionInput::UniStark {
                proof,
                air,
                public_inputs,
                preprocessed_commit,
            } => {
                let verifier_inputs = StarkVerifierInputsBuilder::<
                    SC,
                    SC::Commitment,
                    SC::OpeningProof,
                >::try_allocate(
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
                    self.0.challenger_perm_config,
                )?;
                Ok::<_, VerificationError>(WhirVerifierResult::UniStark(
                    verifier_inputs,
                    op_ids,
                    self.0.limits,
                ))
            }
            RecursionInput::BatchStark {
                proof,
                common_data,
                table_public_inputs: _,
            } => {
                validate_batch_proof_native::<SC, SC::Commitment, SC::OpeningProof>(&proof.proof)?;
                if proof.ext_degree != 4 {
                    return Err(VerificationError::InvalidProofShape(format!(
                        "WhirRecursionBackend supports batch proofs of ext_degree 4, got {}",
                        proof.ext_degree
                    )));
                }
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
                Ok::<_, VerificationError>(WhirVerifierResult::BatchStark(
                    verifier_inputs,
                    op_ids,
                    self.0.limits,
                ))
            }
        }?;
        Ok(CheckedVerifierResult::new(
            inner,
            pcs_context,
            stark_authority,
            policy,
        ))
    }

    fn set_private_data(
        &self,
        config: &SC,
        runner: &mut CircuitRunner<'_, SC::Challenge>,
        op_ids: &[NonPrimitiveOpId],
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<(), &'static str> {
        preflight_whir_input(config, &self.0.limits, prev)
            .map_err(|_| "WHIR input exceeds verifier resource limits")?;
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

    fn set_private_data_for_result(
        &self,
        config: &SC,
        runner: &mut CircuitRunner<'_, SC::Challenge>,
        result: &Self::VerifierResult,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<(), &'static str> {
        preflight_whir_input(config, &self.0.limits, prev)
            .map_err(|_| "WHIR input exceeds verifier resource limits")?;
        result
            .validate_config(config)
            .map_err(|_| "WHIR verifier parameters changed after circuit construction")?;
        result
            .validate_replacement(prev)
            .map_err(|_| "WHIR replacement input failed retained validation")?;
        let op_ids =
            <CheckedWhirVerifierResult<SC> as VerifierCircuitResult<SC, A>>::op_ids(result);
        self.set_private_data(config, runner, op_ids, prev)
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

#[cfg(test)]
#[path = "whir/acceptance_counter_tests.rs"]
mod acceptance_counter_tests;

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
    SC::OpeningProof: PreparedRecursive<SC::Challenge>
        + CheckedWhirOpening<Val<SC>, SC::Challenge, SC::Commitment>,
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
        preflight_whir_input(config, &self.0.limits, source)?;
        let provers = match source {
            RecursionInput::BatchStark { proof, .. } => {
                PcsRecursionBackend::<SC, A, 4>::non_primitive_provers(self, proof.ext_degree)
            }
            RecursionInput::UniStark { .. } => Vec::new(),
        };
        capture_builtin_input_contract::<SC, A, SC::Commitment, SC::OpeningProof>(
            config,
            source,
            true,
            |_| provers,
        )
    }

    fn validate_prepared_input(
        &self,
        config: &SC,
        contract: &Self::InputContract,
        input: &PreparedInput<'_, SC>,
    ) -> Result<(), VerificationError> {
        preflight_whir_prepared(config, &self.0.limits, input)?;
        validate_builtin_prepared_input::<SC, SC::Commitment, SC::OpeningProof>(contract, input)
    }

    fn preflight_input(
        &self,
        config: &SC,
        input: &PreparedInput<'_, SC>,
    ) -> Result<(), VerificationError> {
        preflight_whir_prepared(config, &self.0.limits, input)
    }
}

impl<SC, A, const WIDTH: usize, const RATE: usize, C> TrustedPcsRecursionBackend<SC, A, 4>
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
    SC::Commitment: PreparedRecursive<SC::Challenge> + ConstrainConstantCommitment<SC::Challenge>,
    SC::OpeningProof: PreparedRecursive<SC::Challenge>
        + CheckedWhirOpening<Val<SC>, SC::Challenge, SC::Commitment>,
{
    fn preflight_trusted_batch(
        &self,
        verifier: &CircuitVerifier<SC>,
        proof: &BatchStarkProof<SC>,
    ) -> Result<(), VerificationError> {
        let pcs_usage = <SC::OpeningProof as CheckedWhirOpening<
            Val<SC>,
            SC::Challenge,
            SC::Commitment,
        >>::check_whir_resources(
            &proof.proof.opening_proof, &self.0.limits
        )?;
        let mut usage = check_trusted_batch_stark_resources::<SC, SC::Commitment>(
            &self.0.limits,
            verifier,
            proof,
            pcs_usage,
        )?;
        check_whir_restoration_budget(
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
        <Self as TrustedPcsRecursionBackend<SC, A, 4>>::preflight_trusted_batch(
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
        <Self as TrustedPcsRecursionBackend<SC, A, 4>>::preflight_trusted_batch(
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
        <Self as TrustedPcsRecursionBackend<SC, A, 4>>::preflight_trusted_batch(
            self, verifier, proof,
        )?;
        let public_values = trusted_batch_tables::<SC, 4>(verifier, statement)?.public_values;
        preflight_basic_whir_input(
            &self.0.limits,
            &RecursionInput::<SC, A>::BatchStark {
                proof,
                common_data: verifier.common_data(),
                table_public_inputs: public_values,
            },
        )?;
        let (pcs_context, stark_authority, policy) =
            preflight_trusted_whir_batch::<SC, A>(verifier, proof, statement)?;
        validate_batch_proof_native::<SC, SC::Commitment, SC::OpeningProof>(&proof.proof)?;
        let (verifier_inputs, op_ids) = verify_trusted_p3_batch_proof_circuit::<
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
            verifier,
            circuit,
            proof,
            statement,
            verifier.config().pcs_verifier_params(),
            &LogUpGadget::new(),
            self.0.challenger_perm_config,
        )?;
        Ok(CheckedVerifierResult::new(
            WhirVerifierResult::BatchStark(verifier_inputs, op_ids, self.0.limits),
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
        <Self as TrustedPcsRecursionBackend<SC, A, 4>>::preflight_trusted_batch(
            self, verifier, proof,
        )?;
        let transcript =
            replay_trusted_batch_layer_transcript::<SC, 4>(verifier, proof, statement)?;
        let prev = RecursionInput::<SC, A>::BatchStark {
            proof,
            common_data: verifier.common_data(),
            table_public_inputs: trusted_batch_tables::<SC, 4>(verifier, statement)?.public_values,
        };
        SC::with_whir_opening_proof(&prev, |opening_proof| {
            SC::set_whir_private_data(verifier.config(), runner, op_ids, opening_proof, transcript)
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
            WhirVerifierResult::UniStark(builder, ..) => builder.preprocessed_commit.as_ref(),
            WhirVerifierResult::BatchStark(builder, ..) => builder
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
