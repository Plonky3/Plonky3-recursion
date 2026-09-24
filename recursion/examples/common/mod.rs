//! Common code for all recursive examples.

#![allow(unused_imports, dead_code)]

mod prepared_reuse;
pub mod whir;

pub use std::rc::Rc;
pub use std::sync::Arc;

pub use clap::{Args as ClapArgs, Parser, ValueEnum};
pub use p3_air::{SymbolicExpression, SymbolicExpressionExt};
pub use p3_challenger::DuplexChallenger;
pub use p3_circuit::ops::{
    NpoTypeId, Poseidon1Config, generate_poseidon1_trace, generate_poseidon2_trace,
    generate_recompose_trace,
};
pub use p3_circuit::{Circuit, CircuitBuilder, CircuitError, CircuitRunner, NonPrimitiveOpId};
pub use p3_circuit_prover::batch_stark_prover::poseidon2_air_builders;
pub use p3_circuit_prover::common::{NpoPreprocessor, get_airs_and_degrees_with_prep};
pub use p3_circuit_prover::config::StarkField;
pub use p3_circuit_prover::field_params::ExtractBinomialW;
pub use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, Poseidon2Preprocessor, TablePacking,
};
pub use p3_commit::{ExtensionMmcs, Pcs};
pub use p3_dft::Radix2DitParallel;
pub use p3_field::extension::{BinomialExtensionField, QuinticTrinomialExtensionField};
pub use p3_field::{Algebra, ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
pub use p3_fri::{FriParameters, HidingFriPcs, TwoAdicFriPcs};
pub use p3_lookup::logup::LogUpGadget;
pub use p3_matrix::Matrix;
pub use p3_matrix::dense::RowMajorMatrix;
pub use p3_merkle_tree::MerkleTreeMmcs;
pub use p3_recursion::pcs::{
    HidingFriProofTargets, InputProofTargets, MerkleCapTargets, RecExtensionValMmcsArity4,
    RecValMmcs, RecValMmcsArity4, restore_fri_query_paths, set_fri_mmcs_private_data,
    set_fri_mmcs_private_data_arity4,
};
pub use p3_recursion::profile::{
    HashProfile, RecursionLayerProfile, TranscriptKind, solve_fixed_point,
};
pub use p3_recursion::traits::{RecursiveAir, RecursivePcs};
pub use p3_recursion::verifier::VerificationError;
pub use p3_recursion::{
    BatchOnly, BatchStarkVerifierInputsBuilder, FriRecursionBackend, FriRecursionBackendD5,
    FriRecursionConfig, FriVerifierParams, NativeFriParams, OpeningTranscript, PcsRecursionBackend,
    Poseidon2Config, PreparedAggregation, PreparedAggregationCross, PreparedInput, PreparedLayer,
    PreparedSource, ProveNextLayerParams, RecursionInput, RecursionOutput,
    build_aggregation_layer_circuit, build_and_prove_aggregation_layer,
    build_and_prove_aggregation_layer_cross, build_and_prove_next_layer, build_next_layer_circuit,
    merge_hiding_random_openings, observe_opened_values, prove_aggregation_layer,
    prove_aggregation_layer_cross, prove_next_layer, verify_batch_circuit,
};

/// Physical non-primitive tables emitted by a recursive backend.
///
/// Poseidon2 challenger/MMCS shapes use one shared output identity when extension limbs are
/// available. Poseidon1 retains its two-role legacy identities for D>=2; D1 has one physical
/// table because it has no extension-limb challenger role.
pub trait OutputTableConfigs: Copy {
    fn output_table_configs(self) -> Vec<Self>;
}

impl OutputTableConfigs for Poseidon1Config {
    fn output_table_configs(self) -> Vec<Self> {
        if self.d() >= 2 {
            vec![self.for_challenger(), self]
        } else {
            vec![self]
        }
    }
}

impl OutputTableConfigs for Poseidon2Config {
    fn output_table_configs(self) -> Vec<Self> {
        if self.d() >= 2 && !self.is_arity4_shape() {
            vec![self.for_shared_challenger_table()]
        } else if self.d() >= 2 {
            vec![self.for_challenger(), self]
        } else {
            vec![self]
        }
    }
}

#[cfg(test)]
mod output_table_config_tests {
    use super::*;

    #[test]
    fn poseidon1_extension_outputs_retain_both_legacy_roles() {
        let config = Poseidon1Config::KOALA_BEAR_D4_W16;
        let ids: Vec<_> = config
            .output_table_configs()
            .into_iter()
            .map(NpoTypeId::poseidon1_perm)
            .collect();
        assert_eq!(
            ids,
            vec![
                NpoTypeId::poseidon1_perm(config.for_challenger()),
                NpoTypeId::poseidon1_perm(config),
            ]
        );
    }

    #[test]
    fn poseidon1_base_outputs_keep_one_legacy_role() {
        let config = Poseidon1Config::KOALA_BEAR_D1_W16;
        assert_eq!(
            config
                .output_table_configs()
                .into_iter()
                .map(NpoTypeId::poseidon1_perm)
                .collect::<Vec<_>>(),
            vec![NpoTypeId::poseidon1_perm(config)]
        );
    }
}
pub use p3_symmetric::{PaddingFreeSponge, Permutation, TruncatedPermutation};
pub use p3_uni_stark::{StarkConfig, StarkGenericConfig, Val};
pub(crate) use prepared_reuse::is_prepared_input_mismatch;
pub use rand::SeedableRng;
pub use rand::rngs::{SmallRng, StdRng};
pub use serde::Serialize;
pub use tracing::info;
pub use tracing_forest::ForestLayer;
pub use tracing_forest::util::LevelFilter;
pub use tracing_subscriber::layer::SubscriberExt;
pub use tracing_subscriber::util::SubscriberInitExt;
pub use tracing_subscriber::{EnvFilter, Registry};

#[global_allocator]
static GLOBAL: mimalloc::MiMalloc = mimalloc::MiMalloc;

/// Index of `mi_option_purge_delay` in mimalloc's `mi_option_t` enum (same in v2 and v3).
const MI_OPTION_PURGE_DELAY: libmimalloc_sys::mi_option_t = 15;

/// Keep freed memory mapped instead of returning it to the OS.
///
/// Every recursion layer reallocates trace and LDE buffers of the same sizes; purging them in
/// between turns each reuse into fresh page faults.
pub fn keep_freed_memory_mapped() {
    // SAFETY: `mi_option_set` is not thread safe; this runs first thing in `main`, before any
    // other thread exists.
    unsafe { libmimalloc_sys::mi_option_set(MI_OPTION_PURGE_DELAY, -1) };
}

pub fn init_logger() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    let _ = Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .try_init();
}

#[derive(Debug, Clone, Copy)]
pub struct FriParams {
    pub log_blowup: usize,
    pub max_log_arity: usize,
    pub cap_height: usize,
    pub log_final_poly_len: usize,
    pub commit_pow_bits: usize,
    pub query_pow_bits: usize,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FriQueryCountError {
    SecurityLevelTooLow,
    ZeroBlowup,
}

pub(crate) fn checked_num_queries(
    security_level: usize,
    query_pow_bits: usize,
    log_blowup: usize,
) -> Result<usize, FriQueryCountError> {
    let remaining = security_level
        .checked_sub(query_pow_bits)
        .ok_or(FriQueryCountError::SecurityLevelTooLow)?;
    remaining
        .checked_div(log_blowup)
        .ok_or(FriQueryCountError::ZeroBlowup)
}

#[cfg(test)]
mod checked_fri_tests {
    use super::{FriQueryCountError, checked_num_queries};

    #[test]
    fn checked_num_queries_rejects_invalid_security_and_blowup() {
        assert_eq!(
            checked_num_queries(15, 16, 1),
            Err(FriQueryCountError::SecurityLevelTooLow)
        );
        assert_eq!(
            checked_num_queries(16, 16, 0),
            Err(FriQueryCountError::ZeroBlowup)
        );
    }
}

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum FieldOption {
    KoalaBear,
    BabyBear,
    Goldilocks,
}

/// Hash/permutation backing the Fiat-Shamir challenger and MMCS in the recursive
/// verifier. Add new variants here as additional hashes gain circuit support.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum HashOption {
    #[default]
    Poseidon2,
    Poseidon1,
}

/// Panics when `--quintic` is set with a base field that does not support the quintic challenge extension.
#[inline]
pub fn assert_quintic_field(field: FieldOption, quintic: bool) {
    if quintic && !matches!(field, FieldOption::KoalaBear) {
        panic!(
            "--quintic is only supported with --field koala-bear (got {:?})",
            field
        );
    }
}

/// Panics when `--arity4` is set with an unsupported field/hash combination.
///
/// The mixed-config arity-4 aggregation keeps the Fiat-Shamir challenger on the narrow Poseidon2
/// table and runs the leaf hash and 4-to-1 compression on the wide table. KoalaBear and Goldilocks
/// have the wired wide instances (`KOALA_BEAR_D{1,4}_W32`, `GOLDILOCKS_D2_W16`); Poseidon1 has no
/// wide instance.
#[inline]
#[allow(dead_code)]
pub fn assert_arity4_supported(arity4: bool, field: FieldOption, hash: HashOption) {
    if !arity4 {
        return;
    }
    let supported = hash == HashOption::Poseidon2
        && matches!(
            field,
            FieldOption::KoalaBear | FieldOption::BabyBear | FieldOption::Goldilocks
        );
    if !supported {
        panic!(
            "--arity4 is only supported with --hash poseidon2 \
             (got field {:?}, hash {:?})",
            field, hash
        );
    }
}

pub fn default_goldilocks_poseidon2_8() -> p3_goldilocks::Poseidon2Goldilocks<8> {
    use rand::SeedableRng;
    let mut rng = rand::rngs::SmallRng::seed_from_u64(1);
    p3_goldilocks::Poseidon2Goldilocks::<8>::new_from_rng_128(&mut rng)
}

#[allow(dead_code)]
pub fn default_goldilocks_poseidon2_16() -> p3_goldilocks::Poseidon2Goldilocks<16> {
    use rand::SeedableRng;
    let mut rng = rand::rngs::SmallRng::seed_from_u64(1);
    p3_goldilocks::Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng)
}

/// Report the size of the serialized proof.
#[inline]
pub fn report_proof_size<S: Serialize>(proof: &S) {
    let proof_bytes = postcard::to_allocvec(proof).expect("Failed to serialize proof");
    println!("Proof size: {} bytes", proof_bytes.len());
}

/// Build the borrowed batch witness view used by prepared recursion owners.
pub const fn batch_prepared_input<'a, SC>(
    output: &'a RecursionOutput<SC>,
    table_public_inputs: &'a [Vec<Val<SC>>],
) -> PreparedInput<'a, SC>
where
    SC: StarkGenericConfig,
{
    PreparedInput::BatchStark {
        proof: &output.0,
        common_data: &output.0.stark_common,
        table_public_inputs,
    }
}

/// Build a trusted batch source for constructing a prepared recursion owner.
pub const fn batch_prepared_source<'a, SC>(
    output: &'a RecursionOutput<SC>,
    table_public_inputs: &'a [Vec<Val<SC>>],
) -> PreparedSource<'static, 'a, SC, BatchOnly>
where
    SC: StarkGenericConfig,
{
    PreparedSource::batch(&output.0, &output.0.stark_common, table_public_inputs)
}

/// Allocate the empty per-table public-input vectors expected by batch recursion.
pub fn batch_table_public_inputs<SC>(output: &RecursionOutput<SC>) -> Vec<Vec<Val<SC>>>
where
    SC: StarkGenericConfig,
{
    vec![vec![]; output.0.proof.opened_values.instances.len()]
}

/// Mirrors `p3_recursion::profile::solve_fixed_point`'s convergence loop against an
/// already-built verifier circuit, rather than building one itself from a single `prev` proof.
/// `solve_fixed_point` only builds single-input circuits (via `build_next_layer_circuit`), so it
/// cannot solve a fixed point for a 2-to-1 aggregation circuit (built via
/// `build_aggregation_layer_circuit`); this works against either since the circuit is supplied
/// directly.
#[allow(dead_code)]
pub fn solve_fixed_point_for_circuit<SC, A, B, const D: usize>(
    seed: RecursionLayerProfile,
    circuit: &Circuit<SC::Challenge>,
    backend: &B,
    max_iterations: usize,
) -> RecursionLayerProfile
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PcsRecursionBackend<SC, A, D>,
    Val<SC>: PrimeField64 + StarkField,
    SC::Challenge: ExtensionField<Val<SC>> + ExtractBinomialW<Val<SC>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SymbolicExpression<Val<SC>>>,
{
    let preprocessors = backend.non_primitive_preprocessors();
    let air_builders = backend.non_primitive_air_builders();
    let mut table_packing = seed.table_packing.with_strict_heights();

    for _ in 0..max_iterations {
        match get_airs_and_degrees_with_prep::<SC, SC::Challenge, D>(
            circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            seed.constraint_profile,
        ) {
            Ok(_) => {
                return RecursionLayerProfile {
                    table_packing,
                    hash: seed.hash,
                    transcript: seed.transcript,
                    constraint_profile: seed.constraint_profile,
                };
            }
            Err(CircuitError::ProfileOverflow { table, needed, .. }) => {
                table_packing = bump_table_height(table_packing, &table, needed);
            }
            Err(other) => panic!("unexpected error while solving a fixed point: {other:?}"),
        }
    }
    panic!(
        "fixed point did not converge within {max_iterations} iterations, last packing: {table_packing:?}"
    );
}

/// Mirrors `p3_recursion::profile`'s private `bump_table_height` growth rule for a strict
/// `TablePacking` probe; duplicated here since that helper isn't part of the crate's public
/// surface.
#[allow(dead_code)]
fn bump_table_height(packing: TablePacking, table: &str, needed: usize) -> TablePacking {
    match table {
        "ALU" => packing.with_alu_min_height(needed),
        "PUBLIC" => packing.with_public_min_height(needed),
        "CONST" => packing.with_const_min_height(needed),
        other => packing.with_npo_min_height(NpoTypeId::new(other), needed),
    }
}

/// Expands to all shared field-specific types and helper functions used by every
/// recursive example, **without** a surrounding `mod` block.
///
/// Each example's `define_field_module!` wraps a call to this macro inside its
/// own `mod $mod_name { use super::*; ... }` block and then appends the
/// example-specific `run` / `run_zk` functions.
///
/// Defines (inline, no module wrapper):
/// - Type aliases: `F`, `D`, `Challenge`, `Dft`, `Perm`, `MyHash`, `MyCompress`,
///   `MyMmcs`, `ChallengeMmcs`, `Challenger`, `MyPcs`, `MyConfig`, `InnerFri`,
///   `ConfigWithFriParams`
/// - Functions: `create_config`, `create_fri_verifier_params`, `config_with_fri_params`
/// - Trait impls: `Deref`, `StarkGenericConfig`, `FriRecursionConfig` for `ConfigWithFriParams`
///
/// Use `D` as the extension degree for `register_poseidon2_table::<D>`, `register_recompose_table::<D>`,
/// `poseidon2_air_builders::<_, D>()`, and `FriRecursionBackend::for_extension_degree::<D>(...)`.
#[macro_export]
macro_rules! define_field_module_types {
    (
        $field:ty,
        $perm:ty,
        $default_perm:path,
        $poseidon2_config:expr,
        $poseidon2_circuit_config:ty,
        $d:expr,
        $width:expr,
        $rate:expr,
        $digest_elems:expr,
        $enable_poseidon2_fn:ident,
        $default_perm_circuit:path,
        $backend_width:expr,
        $backend_rate:expr,
        $enable_recompose_fn:ident,
        $gen_trace:ident,
        $params_trait:path
    ) => {
        pub type F = $field;
        pub const D: usize = $d;
        const WIDTH: usize = $width;
        const RATE: usize = $rate;
        const DIGEST_ELEMS: usize = $digest_elems;

        type Challenge = BinomialExtensionField<F, D>;
        type Dft = Radix2DitParallel<F>;
        type Perm = $perm;
        type MyHash = PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST_ELEMS>;
        type MyCompress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, WIDTH>;
        type MyMmcs = MerkleTreeMmcs<
            <F as Field>::Packing,
            <F as Field>::Packing,
            MyHash,
            MyCompress,
            2,
            DIGEST_ELEMS,
        >;
        type ChallengeMmcs = ExtensionMmcs<F, Challenge, MyMmcs>;
        type Challenger = DuplexChallenger<F, Perm, WIDTH, RATE>;
        type MyPcs = TwoAdicFriPcs<F, Dft, MyMmcs, ChallengeMmcs>;
        type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;

        type InnerFri = p3_recursion::pcs::FriProofTargets<
            F,
            Challenge,
            p3_recursion::pcs::RecExtensionValMmcs<
                F,
                Challenge,
                DIGEST_ELEMS,
                RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
            >,
            InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
            p3_recursion::pcs::Witness<F>,
        >;

        #[allow(dead_code)]
        type MyPcsZk = HidingFriPcs<F, Dft, MyMmcs, ChallengeMmcs, StdRng>;
        #[allow(dead_code)]
        type MyConfigZk = StarkConfig<MyPcsZk, Challenge, Challenger>;

        #[allow(dead_code)]
        type InnerFriZk = HidingFriProofTargets<
            F,
            Challenge,
            p3_recursion::pcs::RecExtensionValMmcs<
                F,
                Challenge,
                DIGEST_ELEMS,
                RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
            >,
            InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
            p3_recursion::pcs::Witness<F>,
        >;

        #[derive(Clone)]
        struct ConfigWithFriParams {
            config: Arc<MyConfig>,
            fri_verifier_params: FriVerifierParams,
            native_fri_params: NativeFriParams,
            disable_recompose_npo: bool,
            /// The base-field Merkle MMCS and FRI parameters `config` commits with. The PCS does
            /// not expose them, and restoring the per-query Merkle chains a pruned FRI proof
            /// shares needs both.
            fri_instance: Arc<(MyMmcs, FriParameters<ChallengeMmcs>)>,
        }

        #[allow(dead_code)]
        #[derive(Clone)]
        struct ConfigWithFriParamsZk {
            config: Arc<MyConfigZk>,
            fri_verifier_params: FriVerifierParams,
            native_fri_params: NativeFriParams,
            disable_recompose_npo: bool,
            /// See [`ConfigWithFriParams`].
            fri_instance: Arc<(MyMmcs, FriParameters<ChallengeMmcs>)>,
        }

        impl core::ops::Deref for ConfigWithFriParams {
            type Target = MyConfig;
            fn deref(&self) -> &MyConfig {
                &self.config
            }
        }

        impl core::ops::Deref for ConfigWithFriParamsZk {
            type Target = MyConfigZk;
            fn deref(&self) -> &MyConfigZk {
                &self.config
            }
        }

        impl StarkGenericConfig for ConfigWithFriParams {
            type Challenge = Challenge;
            type Challenger = Challenger;
            type Pcs = MyPcs;
            fn pcs(&self) -> &MyPcs {
                self.config.pcs()
            }
            fn initialise_challenger(&self) -> Challenger {
                self.config.initialise_challenger()
            }
        }

        impl StarkGenericConfig for ConfigWithFriParamsZk {
            type Challenge = Challenge;
            type Challenger = Challenger;
            type Pcs = MyPcsZk;
            fn pcs(&self) -> &MyPcsZk {
                self.config.pcs()
            }
            fn initialise_challenger(&self) -> Challenger {
                self.config.initialise_challenger()
            }
        }

        impl FriRecursionConfig for ConfigWithFriParams
        where
            MyPcs: RecursivePcs<
                    ConfigWithFriParams,
                    InputProofTargets<
                        F,
                        Challenge,
                        RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
                    >,
                    InnerFri,
                    MerkleCapTargets<F, DIGEST_ELEMS>,
                    <MyPcs as Pcs<Challenge, Challenger>>::Domain,
                >,
        {
            type Commitment = MerkleCapTargets<F, DIGEST_ELEMS>;
            type InputProof =
                InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>;
            type OpeningProof = InnerFri;
            type RawOpeningProof = <MyPcs as Pcs<Challenge, Challenger>>::Proof;
            const DIGEST_ELEMS: usize = $digest_elems;

            fn native_fri_validation_params(&self) -> Option<NativeFriParams> {
                Some(self.native_fri_params)
            }

            fn with_fri_opening_proof<'a, A, R>(
                prev: &RecursionInput<'a, Self, A>,
                f: impl FnOnce(&Self::RawOpeningProof) -> R,
            ) -> R
            where
                A: RecursiveAir<Val<Self>, Self::Challenge, LogUpGadget>,
            {
                match prev {
                    RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
                    RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
                }
            }

            fn prepare_circuit_for_verification(
                &self,
                circuit: &mut CircuitBuilder<Challenge>,
            ) -> Result<(), VerificationError> {
                let perm = $default_perm_circuit();
                circuit.$enable_poseidon2_fn::<$poseidon2_circuit_config, _>(
                    $gen_trace::<Challenge, $poseidon2_circuit_config>,
                    perm,
                );
                if self.disable_recompose_npo {
                    circuit.noop_enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
                } else {
                    circuit.$enable_recompose_fn::<F>(generate_recompose_trace::<F, Challenge>);
                }
                if <$poseidon2_circuit_config as $params_trait>::D == 1
                    && <Challenge as ::p3_field::BasedVectorSpace<F>>::DIMENSION > 1
                {
                    circuit.set_recompose_coeff_ctl_for_decompose_links(true);
                }
                Ok(())
            }

            fn pcs_verifier_params(
                &self,
            ) -> &<MyPcs as RecursivePcs<
                ConfigWithFriParams,
                InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
                InnerFri,
                MerkleCapTargets<F, DIGEST_ELEMS>,
                <MyPcs as Pcs<Challenge, Challenger>>::Domain,
            >>::VerifierParams {
                &self.fri_verifier_params
            }

            fn set_fri_private_data(
                config: &Self,
                runner: &mut CircuitRunner<'_, Challenge>,
                op_ids: &[NonPrimitiveOpId],
                opening_proof: &Self::RawOpeningProof,
                transcript: OpeningTranscript<Self>,
            ) -> Result<(), &'static str> {
                let OpeningTranscript {
                    mut challenger,
                    commitments_with_opening_points,
                } = transcript;
                observe_opened_values::<Self>(&mut challenger, &commitments_with_opening_points);
                let query_paths = restore_fri_query_paths(
                    &config.fri_instance.1,
                    &config.fri_instance.0,
                    &config.fri_instance.0,
                    opening_proof,
                    &mut challenger,
                    &commitments_with_opening_points,
                )
                .map_err(|_| "Failed to restore the FRI proof's per-query Merkle paths")?;
                set_fri_mmcs_private_data::<F, Challenge, DIGEST_ELEMS>(
                    runner,
                    op_ids,
                    &query_paths,
                    $poseidon2_config,
                )
            }
        }

        impl FriRecursionConfig for ConfigWithFriParamsZk
        where
            MyPcsZk: RecursivePcs<
                    ConfigWithFriParamsZk,
                    InputProofTargets<
                        F,
                        Challenge,
                        RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
                    >,
                    InnerFriZk,
                    MerkleCapTargets<F, DIGEST_ELEMS>,
                    <MyPcsZk as Pcs<Challenge, Challenger>>::Domain,
                >,
        {
            type Commitment = MerkleCapTargets<F, DIGEST_ELEMS>;
            type InputProof =
                InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>;
            type OpeningProof = InnerFriZk;
            type RawOpeningProof = <MyPcsZk as Pcs<Challenge, Challenger>>::Proof;
            const DIGEST_ELEMS: usize = $digest_elems;

            fn native_fri_validation_params(&self) -> Option<NativeFriParams> {
                Some(self.native_fri_params)
            }

            fn with_fri_opening_proof<'a, A, R>(
                prev: &RecursionInput<'a, Self, A>,
                f: impl FnOnce(&Self::RawOpeningProof) -> R,
            ) -> R
            where
                A: RecursiveAir<Val<Self>, Self::Challenge, LogUpGadget>,
            {
                match prev {
                    RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
                    RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
                }
            }

            fn prepare_circuit_for_verification(
                &self,
                circuit: &mut CircuitBuilder<Challenge>,
            ) -> Result<(), VerificationError> {
                let perm = $default_perm_circuit();
                circuit.$enable_poseidon2_fn::<$poseidon2_circuit_config, _>(
                    $gen_trace::<Challenge, $poseidon2_circuit_config>,
                    perm,
                );
                if self.disable_recompose_npo {
                    circuit.noop_enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
                } else {
                    circuit.$enable_recompose_fn::<F>(generate_recompose_trace::<F, Challenge>);
                }
                if <$poseidon2_circuit_config as $params_trait>::D == 1
                    && <Challenge as ::p3_field::BasedVectorSpace<F>>::DIMENSION > 1
                {
                    circuit.set_recompose_coeff_ctl_for_decompose_links(true);
                }
                Ok(())
            }

            fn pcs_verifier_params(
                &self,
            ) -> &<MyPcsZk as RecursivePcs<
                ConfigWithFriParamsZk,
                InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
                InnerFriZk,
                MerkleCapTargets<F, DIGEST_ELEMS>,
                <MyPcsZk as Pcs<Challenge, Challenger>>::Domain,
            >>::VerifierParams {
                &self.fri_verifier_params
            }

            fn set_fri_private_data(
                config: &Self,
                runner: &mut CircuitRunner<'_, Challenge>,
                op_ids: &[NonPrimitiveOpId],
                opening_proof: &Self::RawOpeningProof,
                transcript: OpeningTranscript<Self>,
            ) -> Result<(), &'static str> {
                let OpeningTranscript {
                    mut challenger,
                    mut commitments_with_opening_points,
                } = transcript;
                // A hiding PCS proof is `(random openings, inner FRI proof)`; the inner verifier
                // sees the public openings with the random ones appended.
                merge_hiding_random_openings::<Self>(
                    &mut commitments_with_opening_points,
                    &opening_proof.0,
                )
                .map_err(|_| "Hiding random openings do not match the public ones")?;
                observe_opened_values::<Self>(&mut challenger, &commitments_with_opening_points);
                let query_paths = restore_fri_query_paths(
                    &config.fri_instance.1,
                    &config.fri_instance.0,
                    &config.fri_instance.0,
                    &opening_proof.1,
                    &mut challenger,
                    &commitments_with_opening_points,
                )
                .map_err(|_| "Failed to restore the FRI proof's per-query Merkle paths")?;
                set_fri_mmcs_private_data::<F, Challenge, DIGEST_ELEMS>(
                    runner,
                    op_ids,
                    &query_paths,
                    $poseidon2_config,
                )
            }
        }

        /// The base-field Merkle MMCS and FRI parameters the configs below commit with. The PCS
        /// keeps them private, so they are built here once for both it and the recursive
        /// verifier's Merkle-path restoration.
        fn create_fri_instance(
            fp: &FriParams,
            security_level: usize,
        ) -> Result<(MyMmcs, FriParameters<ChallengeMmcs>), FriQueryCountError> {
            let perm = $default_perm();
            let hash = MyHash::new(perm.clone());
            let compress = MyCompress::new(perm);
            let val_mmcs = MyMmcs::new(hash, compress, fp.cap_height);

            let num_queries =
                checked_num_queries(security_level, fp.query_pow_bits, fp.log_blowup)?;

            let fri_params = FriParameters {
                max_log_arity: fp.max_log_arity,
                log_blowup: fp.log_blowup,
                log_final_poly_len: fp.log_final_poly_len,
                num_queries,
                batch_proof_of_work_bits: 0,
                commit_proof_of_work_bits: fp.commit_pow_bits,
                query_proof_of_work_bits: fp.query_pow_bits,
                mmcs: ChallengeMmcs::new(val_mmcs.clone()),
            };
            Ok((val_mmcs, fri_params))
        }

        #[allow(dead_code)]
        fn create_config(fp: &FriParams, security_level: usize) -> MyConfig {
            let (val_mmcs, fri_params) = create_fri_instance(fp, security_level)
                .expect("FRI example parameters must have a valid query count");
            let pcs = MyPcs::new(Dft::default(), val_mmcs, fri_params);
            MyConfig::new(pcs, Challenger::new($default_perm()))
        }

        fn create_fri_verifier_params(native: NativeFriParams) -> FriVerifierParams {
            FriVerifierParams::with_mmcs(
                native.log_blowup(),
                native.log_final_poly_len(),
                native.max_log_arity(),
                native.commit_pow_bits(),
                native.query_pow_bits(),
                native.num_queries(),
                $poseidon2_config,
            )
        }

        fn config_with_fri_params(
            fp: &FriParams,
            security_level: usize,
            disable_recompose_npo: bool,
        ) -> ConfigWithFriParams {
            let (val_mmcs, fri_params) = create_fri_instance(fp, security_level)
                .expect("FRI example parameters must have a valid query count");
            let native_fri_params = NativeFriParams::try_from_native::<F, _>(&fri_params).unwrap();
            let restore_mmcs = val_mmcs.clone();
            let pcs = MyPcs::new(Dft::default(), val_mmcs, fri_params.clone());
            ConfigWithFriParams {
                config: Arc::new(MyConfig::new(pcs, Challenger::new($default_perm()))),
                fri_verifier_params: create_fri_verifier_params(native_fri_params),
                native_fri_params,
                disable_recompose_npo,
                fri_instance: Arc::new((restore_mmcs, fri_params)),
            }
        }

        #[allow(dead_code)]
        fn create_config_zk(fp: &FriParams, security_level: usize, rng_seed: u64) -> MyConfigZk {
            let (val_mmcs, fri_params) = create_fri_instance(fp, security_level)
                .expect("FRI example parameters must have a valid query count");
            let pcs = MyPcsZk::new(
                Dft::default(),
                val_mmcs,
                fri_params,
                2,
                StdRng::seed_from_u64(rng_seed),
            );
            MyConfigZk::new(pcs, Challenger::new($default_perm()))
        }

        #[allow(dead_code)]
        fn config_with_fri_params_zk(
            fp: &FriParams,
            security_level: usize,
            disable_recompose_npo: bool,
            rng_seed: u64,
        ) -> ConfigWithFriParamsZk {
            let (val_mmcs, fri_params) = create_fri_instance(fp, security_level)
                .expect("FRI example parameters must have a valid query count");
            let native_fri_params = NativeFriParams::try_from_native::<F, _>(&fri_params).unwrap();
            let restore_mmcs = val_mmcs.clone();
            let pcs = MyPcsZk::new(
                Dft::default(),
                val_mmcs,
                fri_params.clone(),
                2,
                StdRng::seed_from_u64(rng_seed),
            );
            ConfigWithFriParamsZk {
                config: Arc::new(MyConfigZk::new(pcs, Challenger::new($default_perm()))),
                fri_verifier_params: create_fri_verifier_params(native_fri_params),
                native_fri_params,
                disable_recompose_npo,
                fri_instance: Arc::new((restore_mmcs, fri_params)),
            }
        }
    };
}

/// Variant of [`define_field_module_types`] for KoalaBear quintic extension (D=5).
///
/// Key differences from the standard macro:
/// - `Challenge = QuinticTrinomialExtensionField<F>` instead of `BinomialExtensionField<F, D>`.
/// - `prepare_circuit_for_verification` uses `enable_poseidon2_perm_base` with a
///   `$perm_circuit_constructor` closure that must produce a
///   `impl Permutation<[Challenge; WIDTH]>`.
///
/// Recursive examples usually call `define_quintic_poseidon_perm_lift_and_types!` instead, which
/// wires in [`p3_test_utils::LiftPermToQuintic`] and then invokes this macro.
#[macro_export]
macro_rules! define_field_module_types_quintic {
    (
        $field:ty,
        $perm:ty,
        $default_perm:path,
        $poseidon2_config:expr,
        $poseidon2_circuit_config:ty,
        $width:expr,
        $rate:expr,
        $digest_elems:expr,
        $perm_circuit_constructor:expr,
        $backend_width:expr,
        $backend_rate:expr,
        $enable_fn:ident,
        $gen_trace:ident,
        $params_trait:path
    ) => {
        pub type F = $field;
        pub const D: usize = 5;
        const WIDTH: usize = $width;
        const RATE: usize = $rate;
        const DIGEST_ELEMS: usize = $digest_elems;

        type Challenge = QuinticTrinomialExtensionField<F>;
        type Dft = Radix2DitParallel<F>;
        type Perm = $perm;
        type MyHash = PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST_ELEMS>;
        type MyCompress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, WIDTH>;
        type MyMmcs = MerkleTreeMmcs<
            <F as Field>::Packing,
            <F as Field>::Packing,
            MyHash,
            MyCompress,
            2,
            DIGEST_ELEMS,
        >;
        type ChallengeMmcs = ExtensionMmcs<F, Challenge, MyMmcs>;
        type Challenger = DuplexChallenger<F, Perm, WIDTH, RATE>;
        type MyPcs = TwoAdicFriPcs<F, Dft, MyMmcs, ChallengeMmcs>;
        type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;

        type InnerFri = p3_recursion::pcs::FriProofTargets<
            F,
            Challenge,
            p3_recursion::pcs::RecExtensionValMmcs<
                F,
                Challenge,
                DIGEST_ELEMS,
                RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
            >,
            InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
            p3_recursion::pcs::Witness<F>,
        >;

        #[derive(Clone)]
        struct ConfigWithFriParams {
            config: Arc<MyConfig>,
            fri_verifier_params: FriVerifierParams,
            native_fri_params: NativeFriParams,
            disable_recompose_npo: bool,
            /// The base-field Merkle MMCS and FRI parameters `config` commits with. The PCS does
            /// not expose them, and restoring the per-query Merkle chains a pruned FRI proof
            /// shares needs both.
            fri_instance: Arc<(MyMmcs, FriParameters<ChallengeMmcs>)>,
        }

        impl core::ops::Deref for ConfigWithFriParams {
            type Target = MyConfig;
            fn deref(&self) -> &MyConfig {
                &self.config
            }
        }

        impl StarkGenericConfig for ConfigWithFriParams {
            type Challenge = Challenge;
            type Challenger = Challenger;
            type Pcs = MyPcs;
            fn pcs(&self) -> &MyPcs {
                self.config.pcs()
            }
            fn initialise_challenger(&self) -> Challenger {
                self.config.initialise_challenger()
            }
        }

        impl FriRecursionConfig for ConfigWithFriParams
        where
            MyPcs: RecursivePcs<
                    ConfigWithFriParams,
                    InputProofTargets<
                        F,
                        Challenge,
                        RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
                    >,
                    InnerFri,
                    MerkleCapTargets<F, DIGEST_ELEMS>,
                    <MyPcs as Pcs<Challenge, Challenger>>::Domain,
                >,
        {
            type Commitment = MerkleCapTargets<F, DIGEST_ELEMS>;
            type InputProof =
                InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>;
            type OpeningProof = InnerFri;
            type RawOpeningProof = <MyPcs as Pcs<Challenge, Challenger>>::Proof;
            const DIGEST_ELEMS: usize = $digest_elems;

            fn native_fri_validation_params(&self) -> Option<NativeFriParams> {
                Some(self.native_fri_params)
            }

            fn with_fri_opening_proof<'a, A, R>(
                prev: &RecursionInput<'a, Self, A>,
                f: impl FnOnce(&Self::RawOpeningProof) -> R,
            ) -> R
            where
                A: RecursiveAir<Val<Self>, Self::Challenge, LogUpGadget>,
            {
                match prev {
                    RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
                    RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
                }
            }

            fn prepare_circuit_for_verification(
                &self,
                circuit: &mut CircuitBuilder<Challenge>,
            ) -> Result<(), VerificationError> {
                let perm = ($perm_circuit_constructor)();
                circuit.$enable_fn::<$poseidon2_circuit_config, _>(
                    $gen_trace::<Challenge, $poseidon2_circuit_config>,
                    perm,
                );
                if self.disable_recompose_npo {
                    circuit.noop_enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
                } else {
                    circuit.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
                }
                if <$poseidon2_circuit_config as $params_trait>::D == 1
                    && <Challenge as ::p3_field::BasedVectorSpace<F>>::DIMENSION > 1
                {
                    circuit.set_recompose_coeff_ctl_for_decompose_links(true);
                }
                Ok(())
            }

            fn pcs_verifier_params(
                &self,
            ) -> &<MyPcs as RecursivePcs<
                ConfigWithFriParams,
                InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
                InnerFri,
                MerkleCapTargets<F, DIGEST_ELEMS>,
                <MyPcs as Pcs<Challenge, Challenger>>::Domain,
            >>::VerifierParams {
                &self.fri_verifier_params
            }

            fn set_fri_private_data(
                config: &Self,
                runner: &mut CircuitRunner<'_, Challenge>,
                op_ids: &[NonPrimitiveOpId],
                opening_proof: &Self::RawOpeningProof,
                transcript: OpeningTranscript<Self>,
            ) -> Result<(), &'static str> {
                let OpeningTranscript {
                    mut challenger,
                    commitments_with_opening_points,
                } = transcript;
                observe_opened_values::<Self>(&mut challenger, &commitments_with_opening_points);
                let query_paths = restore_fri_query_paths(
                    &config.fri_instance.1,
                    &config.fri_instance.0,
                    &config.fri_instance.0,
                    opening_proof,
                    &mut challenger,
                    &commitments_with_opening_points,
                )
                .map_err(|_| "Failed to restore the FRI proof's per-query Merkle paths")?;
                set_fri_mmcs_private_data::<F, Challenge, DIGEST_ELEMS>(
                    runner,
                    op_ids,
                    &query_paths,
                    $poseidon2_config,
                )
            }
        }

        /// The base-field Merkle MMCS and FRI parameters the configs below commit with. The PCS
        /// keeps them private, so they are built here once for both it and the recursive
        /// verifier's Merkle-path restoration.
        fn create_fri_instance(
            fp: &FriParams,
            security_level: usize,
        ) -> Result<(MyMmcs, FriParameters<ChallengeMmcs>), FriQueryCountError> {
            let perm = $default_perm();
            let hash = MyHash::new(perm.clone());
            let compress = MyCompress::new(perm);
            let val_mmcs = MyMmcs::new(hash, compress, fp.cap_height);

            let num_queries =
                checked_num_queries(security_level, fp.query_pow_bits, fp.log_blowup)?;

            let fri_params = FriParameters {
                max_log_arity: fp.max_log_arity,
                log_blowup: fp.log_blowup,
                log_final_poly_len: fp.log_final_poly_len,
                num_queries,
                batch_proof_of_work_bits: 0,
                commit_proof_of_work_bits: fp.commit_pow_bits,
                query_proof_of_work_bits: fp.query_pow_bits,
                mmcs: ChallengeMmcs::new(val_mmcs.clone()),
            };
            Ok((val_mmcs, fri_params))
        }

        #[allow(dead_code)]
        fn create_config(fp: &FriParams, security_level: usize) -> MyConfig {
            let (val_mmcs, fri_params) = create_fri_instance(fp, security_level)
                .expect("FRI example parameters must have a valid query count");
            let pcs = MyPcs::new(Dft::default(), val_mmcs, fri_params);
            MyConfig::new(pcs, Challenger::new($default_perm()))
        }

        fn create_fri_verifier_params(native: NativeFriParams) -> FriVerifierParams {
            FriVerifierParams::with_mmcs(
                native.log_blowup(),
                native.log_final_poly_len(),
                native.max_log_arity(),
                native.commit_pow_bits(),
                native.query_pow_bits(),
                native.num_queries(),
                $poseidon2_config,
            )
        }

        fn config_with_fri_params(
            fp: &FriParams,
            security_level: usize,
            disable_recompose_npo: bool,
        ) -> ConfigWithFriParams {
            let (val_mmcs, fri_params) = create_fri_instance(fp, security_level)
                .expect("FRI example parameters must have a valid query count");
            let native_fri_params = NativeFriParams::try_from_native::<F, _>(&fri_params).unwrap();
            let restore_mmcs = val_mmcs.clone();
            let pcs = MyPcs::new(Dft::default(), val_mmcs, fri_params.clone());
            ConfigWithFriParams {
                config: Arc::new(MyConfig::new(pcs, Challenger::new($default_perm()))),
                fri_verifier_params: create_fri_verifier_params(native_fri_params),
                native_fri_params,
                disable_recompose_npo,
                fri_instance: Arc::new((restore_mmcs, fri_params)),
            }
        }
    };
}

/// Expands [`define_field_module_types_quintic!`] with a circuit permutation constructor that uses
/// [`p3_test_utils::LiftPermToQuintic`].
#[macro_export]
macro_rules! define_quintic_poseidon_perm_lift_and_types {
    (
        $field:ty,
        $perm:ty,
        $default_perm:path,
        $poseidon2_config:expr,
        $poseidon2_circuit_config:ty,
        $width:expr,
        $rate:expr,
        $digest_elems:expr,
        $backend_width:expr,
        $backend_rate:expr
    ) => {
        define_field_module_types_quintic!(
            $field,
            $perm,
            $default_perm,
            $poseidon2_config,
            $poseidon2_circuit_config,
            $width,
            $rate,
            $digest_elems,
            || ::p3_test_utils::LiftPermToQuintic::<$field, $perm, $width>::new($default_perm()),
            $backend_width,
            $backend_rate,
            enable_poseidon2_perm_base,
            generate_poseidon2_trace,
            p3_circuit::ops::Poseidon2Params
        );
    };
}

/// Emits the W32 MMCS-side type aliases for the mixed-config arity-4 recursive verifier.
///
/// The Fiat-Shamir challenger is left on the W16 table (it reuses `Challenger` from the base
/// [`define_field_module_types!`] invocation in the same module); only the leaf hash, 4-to-1
/// compression, and recursive MMCS move to the wide W32 permutation passed here.
///
/// Requires `F`, `Challenge`, and `Dft` to already be in scope.
#[macro_export]
macro_rules! define_field_module_types_arity4 {
    ($perm_arity4:ty, $width_arity4:expr, $rate_arity4:expr, $digest_elems:expr) => {
        type PermArity4 = $perm_arity4;
        type MyHashArity4 =
            PaddingFreeSponge<PermArity4, $width_arity4, $rate_arity4, $digest_elems>;
        type MyCompressArity4 = TruncatedPermutation<PermArity4, 4, $digest_elems, $width_arity4>;
        type MyMmcsArity4 = MerkleTreeMmcs<
            <F as Field>::Packing,
            <F as Field>::Packing,
            MyHashArity4,
            MyCompressArity4,
            4,
            $digest_elems,
        >;
        type ChallengeMmcsArity4 = ExtensionMmcs<F, Challenge, MyMmcsArity4>;
        type MyPcsArity4 = TwoAdicFriPcs<F, Dft, MyMmcsArity4, ChallengeMmcsArity4>;
        type RecInputMmcsArity4 =
            RecValMmcsArity4<F, $digest_elems, MyHashArity4, MyCompressArity4>;
        type InnerFriArity4 = p3_recursion::pcs::FriProofTargets<
            F,
            Challenge,
            RecExtensionValMmcsArity4<F, Challenge, $digest_elems, RecInputMmcsArity4>,
            InputProofTargets<F, Challenge, RecInputMmcsArity4>,
            p3_recursion::pcs::Witness<F>,
        >;
    };
}
