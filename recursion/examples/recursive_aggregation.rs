//! 2-to-1 proof aggregation example (binary tree).
//!
//! Builds a full binary aggregation tree from distinct base proofs:
//! 1. **Leaves**: `2^(N+1)` dummy circuits (each a single distinct constant),
//!    each proved independently with batch STARK.
//! 2. **Levels 1..N+1**: Pairwise 2-to-1 aggregation up the tree until a
//!    single root proof remains.
//!
//! `N` is the `--num-recursive-layers` argument (default 1).
//!
//! ## What this proves
//!
//! The root proof attests that every base proof in the tree is valid.  All
//! base proofs are genuinely distinct (different constant values) so the
//! circuit optimizer cannot collapse the two verifications inside an
//! aggregation node.
//!
//! ## Usage
//!
//! ```bash
//! # 4 base proofs, 2 aggregation levels (default)
//! cargo run --release --example recursive_aggregation -- --field koala-bear
//!
//! # 8 base proofs, 3 aggregation levels, custom FRI parameters
//! cargo run --release --example recursive_aggregation -- \
//!     --field koala-bear \
//!     --num-recursive-layers 2 \
//!     --log-blowup 3 \
//!     --max-log-arity 4 \
//!     --log-final-poly-len 5 \
//!     --query-pow-bits 16
//! ```

use std::sync::Arc;

use clap::{Parser, ValueEnum};
use p3_batch_stark::ProverData;
use p3_challenger::DuplexChallenger;
use p3_circuit::ops::generate_poseidon2_trace;
use p3_circuit::{CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
use p3_circuit_prover::{BatchStarkProver, CircuitProverData, TablePacking};
use p3_commit::{ExtensionMmcs, Pcs};
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing as _};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_lookup::logup::LogUpGadget;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::pcs::{
    InputProofTargets, MerkleCapTargets, RecValMmcs, set_fri_mmcs_private_data,
};
use p3_recursion::traits::{RecursiveAir, RecursivePcs};
use p3_recursion::verifier::VerificationError;
use p3_recursion::{
    AggregationPrepCache, BatchOnly, FriRecursionBackend, FriRecursionConfig, FriVerifierParams,
    Poseidon2Config, ProveNextLayerParams, RecursionInput, RecursionOutput,
    build_and_prove_aggregation_layer,
};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, StarkGenericConfig, Val};
use serde::Serialize;
use tracing::info;
use tracing_forest::ForestLayer;
use tracing_forest::util::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum FieldOption {
    KoalaBear,
    BabyBear,
}

#[derive(Debug, Clone, Copy)]
struct FriParams {
    log_blowup: usize,
    max_log_arity: usize,
    cap_height: usize,
    log_final_poly_len: usize,
    commit_pow_bits: usize,
    query_pow_bits: usize,
}

#[derive(Parser, Debug)]
#[command(version, about = "2-to-1 proof aggregation example")]
struct Args {
    #[arg(short, long, ignore_case = true, value_enum, default_value_t = FieldOption::KoalaBear)]
    field: FieldOption,

    /// Tree depth (total base proofs = 2^(tree_depth)).  (1 = single pair, 2 = 4 leaves, …)
    #[arg(
        long,
        default_value_t = 1,
        help = "Tree depth (total base proofs = 2^(tree_depth))"
    )]
    num_recursive_layers: usize,

    #[arg(
        long,
        default_value_t = 3,
        help = "Logarithmic blowup factor for the LDE"
    )]
    log_blowup: usize,

    #[arg(
        long,
        default_value_t = 4,
        help = "Maximum arity allowed during FRI folding phases"
    )]
    max_log_arity: usize,

    #[arg(long, default_value_t = 0, help = "Height of the Merkle cap to open")]
    cap_height: usize,

    #[arg(
        long,
        default_value_t = 5,
        help = "Log size of final polynomial after FRI folding"
    )]
    log_final_poly_len: usize,

    #[arg(
        long,
        default_value_t = 0,
        help = "PoW grinding bits during FRI commit phase"
    )]
    commit_pow_bits: usize,

    #[arg(
        long,
        default_value_t = 16,
        help = "PoW grinding bits during FRI query phase"
    )]
    query_pow_bits: usize,
}

fn init_logger() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    let _ = Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .try_init();
}

fn main() {
    init_logger();

    let args = Args::parse();
    let fri_params = FriParams {
        log_blowup: args.log_blowup,
        max_log_arity: args.max_log_arity,
        cap_height: args.cap_height,
        log_final_poly_len: args.log_final_poly_len,
        commit_pow_bits: args.commit_pow_bits,
        query_pow_bits: args.query_pow_bits,
    };

    assert!(args.num_recursive_layers >= 1);

    info!(
        "2-to-1 aggregation with field {:?}, {} aggregation recursive layers",
        args.field, args.num_recursive_layers
    );

    match args.field {
        FieldOption::KoalaBear => koala_bear::run(args.num_recursive_layers, &fri_params),
        FieldOption::BabyBear => baby_bear::run(args.num_recursive_layers, &fri_params),
    }
}

macro_rules! define_field_module {
    (
        $mod_name:ident,
        $field:ty,
        $perm:ty,
        $default_perm:path,
        $poseidon2_config:expr,
        $poseidon2_circuit_config:ty
    ) => {
        mod $mod_name {
            use super::*;

            pub type F = $field;
            pub const D: usize = 4;
            const WIDTH: usize = 16;
            const RATE: usize = 8;
            const DIGEST_ELEMS: usize = 8;

            type Challenge = BinomialExtensionField<F, D>;
            type Dft = Radix2DitParallel<F>;
            type Perm = $perm;
            type MyHash = PaddingFreeSponge<Perm, 16, RATE, 8>;
            type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
            type ValMmcs =
                MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, MyHash, MyCompress, 8>;
            type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
            type Challenger = DuplexChallenger<F, Perm, 16, RATE>;
            type MyPcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;
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
                type InputProof = InputProofTargets<
                    F,
                    Challenge,
                    RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
                >;
                type OpeningProof = InnerFri;
                type RawOpeningProof = <MyPcs as Pcs<Challenge, Challenger>>::Proof;
                const DIGEST_ELEMS: usize = 8;

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

                fn enable_poseidon2_on_circuit(
                    &self,
                    circuit: &mut CircuitBuilder<Challenge>,
                ) -> Result<(), VerificationError> {
                    let perm = $default_perm();
                    circuit.enable_poseidon2_perm::<$poseidon2_circuit_config, _>(
                        generate_poseidon2_trace::<Challenge, $poseidon2_circuit_config>,
                        perm,
                    );
                    Ok(())
                }

                fn pcs_verifier_params(
                    &self,
                ) -> &<MyPcs as RecursivePcs<
                    ConfigWithFriParams,
                    InputProofTargets<
                        F,
                        Challenge,
                        RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
                    >,
                    InnerFri,
                    MerkleCapTargets<F, DIGEST_ELEMS>,
                    <MyPcs as Pcs<Challenge, Challenger>>::Domain,
                >>::VerifierParams {
                    &self.fri_verifier_params
                }

                fn set_fri_private_data(
                    runner: &mut CircuitRunner<Challenge>,
                    op_ids: &[NonPrimitiveOpId],
                    opening_proof: &Self::RawOpeningProof,
                ) -> Result<(), &'static str> {
                    set_fri_mmcs_private_data::<
                        F,
                        Challenge,
                        ChallengeMmcs,
                        ValMmcs,
                        MyHash,
                        MyCompress,
                        DIGEST_ELEMS,
                    >(runner, op_ids, opening_proof)
                }
            }

            fn create_config(fp: &FriParams) -> MyConfig {
                let perm = $default_perm();
                let hash = MyHash::new(perm.clone());
                let compress = MyCompress::new(perm.clone());
                let val_mmcs = ValMmcs::new(hash, compress, fp.cap_height);
                let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
                let dft = Dft::default();

                let num_queries = (100 - fp.query_pow_bits) / fp.log_blowup;

                let fri_params = FriParameters {
                    max_log_arity: fp.max_log_arity,
                    log_blowup: fp.log_blowup,
                    log_final_poly_len: fp.log_final_poly_len,
                    num_queries,
                    commit_proof_of_work_bits: fp.commit_pow_bits,
                    query_proof_of_work_bits: fp.query_pow_bits,
                    mmcs: challenge_mmcs,
                };
                let pcs = MyPcs::new(dft, val_mmcs, fri_params);
                let challenger = Challenger::new(perm);
                MyConfig::new(pcs, challenger)
            }

            const fn create_fri_verifier_params(fp: &FriParams) -> FriVerifierParams {
                FriVerifierParams::with_mmcs(
                    fp.log_blowup,
                    fp.log_final_poly_len,
                    fp.commit_pow_bits,
                    fp.query_pow_bits,
                    $poseidon2_config,
                )
            }

            fn config_with_fri_params(fp: &FriParams) -> ConfigWithFriParams {
                ConfigWithFriParams {
                    config: Arc::new(create_config(fp)),
                    fri_verifier_params: create_fri_verifier_params(fp),
                }
            }

            /// Build a dummy circuit with a single constant and prove it.
            fn prove_dummy_circuit(
                constant_value: u32,
                config: &ConfigWithFriParams,
                table_packing: TablePacking,
            ) -> RecursionOutput<ConfigWithFriParams> {
                let mut builder = CircuitBuilder::new();
                let c = builder.alloc_const(F::from_u32(constant_value), "dummy_const");
                let expected = builder.alloc_public_input("expected");
                builder.connect(c, expected);

                let circuit = builder.build().unwrap();
                let (airs_degrees, preprocessed_columns) = get_airs_and_degrees_with_prep::<
                    ConfigWithFriParams,
                    _,
                    1,
                >(&circuit, table_packing, None)
                .unwrap();
                let (mut airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();

                let mut runner = circuit.runner();
                runner
                    .set_public_inputs(&[F::from_u32(constant_value)])
                    .unwrap();
                let traces = runner.run().unwrap();

                let prover_data = ProverData::from_airs_and_degrees(config, &mut airs, &degrees);
                let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);
                let prover =
                    BatchStarkProver::new(config.clone()).with_table_packing(table_packing);

                let proof = prover
                    .prove_all_tables(&traces, &circuit_prover_data)
                    .expect("Failed to prove dummy circuit");
                report_proof_size(&proof);

                prover
                    .verify_all_tables(&proof, circuit_prover_data.common_data())
                    .expect("Failed to verify dummy proof");

                RecursionOutput(proof, std::rc::Rc::new(circuit_prover_data))
            }

            pub fn run(num_recursive_layers: usize, fri_params: &FriParams) {
                let config = config_with_fri_params(fri_params);
                let base_table_packing = TablePacking::new(1, 1, 1)
                    .with_fri_params(fri_params.log_final_poly_len, fri_params.log_blowup);
                let backend = FriRecursionBackend::<WIDTH, RATE>::new($poseidon2_config);

                let tree_depth = num_recursive_layers;
                let num_leaves = 1usize << tree_depth;
                info!("Binary aggregation tree: {num_leaves} base proofs, {tree_depth} levels");

                // --- Leaf layer: produce distinct base proofs ---
                let mut proofs: Vec<RecursionOutput<ConfigWithFriParams>> = (0..num_leaves)
                    .map(|i| {
                        let val = (i + 1) as u32;
                        info!("Base proof {i} (const = {val})");
                        prove_dummy_circuit(val, &config, base_table_packing)
                    })
                    .collect();

                // --- Aggregate pairwise, bottom-up ---
                let mut level = 0u32;
                while proofs.len() > 1 {
                    level += 1;
                    let pairs = proofs.len() / 2;
                    info!(
                        "Aggregation level {level}: {} proofs -> {pairs}",
                        proofs.len()
                    );

                    let agg_params = ProveNextLayerParams {
                        table_packing: if level == 1 {
                            TablePacking::new(3, 1, 2)
                        } else {
                            TablePacking::new(4, 4, 2)
                        }
                        .with_fri_params(fri_params.log_final_poly_len, fri_params.log_blowup),
                        use_poseidon2_in_circuit: true,
                    };

                    let mut next_level = Vec::with_capacity(pairs);
                    let mut prep_cache: Option<AggregationPrepCache<ConfigWithFriParams>> = None;
                    for pair_idx in 0..pairs {
                        let li = pair_idx * 2;
                        let left = proofs[li].into_recursion_input::<BatchOnly>();
                        let right = proofs[li + 1].into_recursion_input::<BatchOnly>();

                        let out =
                            build_and_prove_aggregation_layer::<ConfigWithFriParams, _, _, _, D>(
                                &left,
                                &right,
                                &config,
                                &backend,
                                &agg_params,
                                Some(&mut prep_cache),
                            )
                            .unwrap_or_else(|e| {
                                panic!("Failed at level {level}, pair {pair_idx}: {e:?}")
                            });

                        report_proof_size(&out.0);

                        let mut verifier = BatchStarkProver::new(config.clone())
                            .with_table_packing(agg_params.table_packing);
                        verifier.register_poseidon2_table($poseidon2_config);
                        verifier
                            .verify_all_tables(&out.0, out.1.common_data())
                            .unwrap_or_else(|e| {
                                panic!(
                                    "Verification failed at level {level}, pair {pair_idx}: {e:?}"
                                )
                            });

                        next_level.push(out);
                    }
                    proofs = next_level;
                }

                info!("All levels verified successfully");
            }
        }
    };
}

define_field_module!(
    koala_bear,
    p3_koala_bear::KoalaBear,
    p3_koala_bear::Poseidon2KoalaBear<16>,
    p3_koala_bear::default_koalabear_poseidon2_16,
    Poseidon2Config::KoalaBearD4Width16,
    p3_poseidon2_circuit_air::KoalaBearD4Width16
);

define_field_module!(
    baby_bear,
    p3_baby_bear::BabyBear,
    p3_baby_bear::Poseidon2BabyBear<16>,
    p3_baby_bear::default_babybear_poseidon2_16,
    Poseidon2Config::BabyBearD4Width16,
    p3_poseidon2_circuit_air::BabyBearD4Width16
);

#[inline]
pub fn report_proof_size<S: Serialize>(proof: &S) {
    let proof_bytes = postcard::to_allocvec(proof).expect("Failed to serialize proof");
    println!("Proof size: {} bytes", proof_bytes.len());
}
