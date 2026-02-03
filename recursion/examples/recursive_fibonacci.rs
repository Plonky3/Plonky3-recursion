//! Recursive Fibonacci proof verification example.
//!
//! This example demonstrates end-to-end recursive verification:
//! 1. **Layer 0 (Base)**: Create a Fibonacci(n) circuit and prove it with Plonky3 STARK
//! 2. **Layer 1 (Recursive)**: Build a verification circuit that checks the Layer 0 proof,
//!    then prove this circuit itself
//!
//! ## What this proves
//!
//! The final proof (Layer 1) attests that:
//! - The original Fibonacci(n) computation was performed correctly
//! - The Plonky3 STARK verification of that computation succeeded
//!
//! ## Multi-layer recursion
//!
//! Further recursive layers would verify this proof inside another circuit.
//! This requires extending `verify_p3_recursion_proof_circuit` to handle
//! non-primitive AIR tables (like Poseidon2).
//!
//! Run with: cargo run --release --example recursive_fibonacci -- --field koala-bear --n 100

use clap::{Parser, ValueEnum};
use p3_batch_stark::CommonData;
use p3_challenger::DuplexChallenger;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::generate_poseidon2_trace;
use p3_circuit_prover::common::{NonPrimitiveConfig, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{BatchStarkProver, TablePacking};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_lookup::logup::LogUpGadget;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::Poseidon2Config;
use p3_recursion::pcs::fri::{FriVerifierParams, HashTargets, InputProofTargets, RecValMmcs};
use p3_recursion::pcs::set_fri_mmcs_private_data;
use p3_recursion::verifier::verify_p3_recursion_proof_circuit;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;
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

#[derive(Parser, Debug)]
#[command(version, about = "Recursive Fibonacci proof verification example")]
struct Args {
    /// The field to use for the proof.
    #[arg(short, long, ignore_case = true, value_enum, default_value_t = FieldOption::KoalaBear)]
    field: FieldOption,

    /// The Fibonacci index to compute (F(n)).
    #[arg(short, long, default_value_t = 100)]
    n: usize,
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

    match args.field {
        FieldOption::KoalaBear => koala_bear::run(args.n),
        FieldOption::BabyBear => baby_bear::run(args.n),
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

            // =====================================================================
            // FRI Parameters - customize these for recursion efficiency
            // =====================================================================
            // Benchmark-inspired config with higher log_final_poly_len for smaller proofs.
            // Traces must be padded to meet: log_trace_height > log_final_poly_len + log_blowup
            const LOG_BLOWUP: usize = 1;
            const LOG_FINAL_POLY_LEN: usize = 0;
            const NUM_QUERIES: usize = 100;
            const COMMIT_POW_BITS: usize = 0;
            const QUERY_POW_BITS: usize = 16;

            /// Create a STARK config with benchmark-inspired FRI params.
            fn create_config() -> MyConfig {
                let perm = $default_perm();
                let hash = MyHash::new(perm.clone());
                let compress = MyCompress::new(perm.clone());
                let val_mmcs = ValMmcs::new(hash, compress);
                let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
                let dft = Dft::default();
                let fri_params = FriParameters {
                    log_blowup: LOG_BLOWUP,
                    log_final_poly_len: LOG_FINAL_POLY_LEN,
                    num_queries: NUM_QUERIES,
                    commit_proof_of_work_bits: COMMIT_POW_BITS,
                    query_proof_of_work_bits: QUERY_POW_BITS,
                    mmcs: challenge_mmcs,
                };
                let pcs = MyPcs::new(dft, val_mmcs, fri_params);
                let challenger = Challenger::new(perm);
                MyConfig::new(pcs, challenger)
            }

            /// Create FRI verifier params for the in-circuit verifier.
            /// MUST match the FRI params used by the native prover.
            fn create_fri_verifier_params() -> FriVerifierParams {
                FriVerifierParams::with_mmcs(
                    LOG_BLOWUP,
                    LOG_FINAL_POLY_LEN,
                    COMMIT_POW_BITS,
                    QUERY_POW_BITS,
                    $poseidon2_config,
                )
            }

            fn compute_fibonacci(n: usize) -> F {
                if n == 0 {
                    return F::ZERO;
                }
                if n == 1 {
                    return F::ONE;
                }
                let mut a = F::ZERO;
                let mut b = F::ONE;
                for _ in 2..=n {
                    let next = a + b;
                    a = b;
                    b = next;
                }
                b
            }

            pub fn run(n: usize) {
                // =================================================================
                // LAYER 0: Create and prove Fibonacci(n)
                // =================================================================

                let mut builder = CircuitBuilder::new();
                let expected_result = builder.alloc_public_input("expected_result");

                let mut a = builder.alloc_const(F::ZERO, "F(0)");
                let mut b = builder.alloc_const(F::ONE, "F(1)");

                for _ in 2..=n {
                    let next = builder.add(a, b);
                    a = b;
                    b = next;
                }

                builder.connect(b, expected_result);

                let base_circuit = builder.build().unwrap();
                // (witness_lanes, public_lanes, add_lanes, mul_lanes)
                // Using mul_lanes=2 for a circuit with no multiplications will trigger
                // automatic lane reduction to mul_lanes=1 with a warning.
                let table_packing_0 = TablePacking::new(1, 1, 1, 2);

                // Layer 0 prover config
                let config_0 = create_config();
                let (airs_degrees_0, witness_mults_0) =
                    get_airs_and_degrees_with_prep::<MyConfig, _, 1>(
                        &base_circuit,
                        table_packing_0,
                        None,
                    )
                    .unwrap();
                let (mut airs_0, degrees_0): (Vec<_>, Vec<_>) = airs_degrees_0.into_iter().unzip();

                let mut runner_0 = base_circuit.runner();
                let expected_fib = compute_fibonacci(n);
                runner_0.set_public_inputs(&[expected_fib]).unwrap();

                let traces_0 = runner_0.run().unwrap();
                let common_0 =
                    CommonData::from_airs_and_degrees(&config_0, &mut airs_0, &degrees_0);

                let prover_0 = BatchStarkProver::new(config_0).with_table_packing(table_packing_0);
                let proof_0 = prover_0
                    .prove_all_tables(&traces_0, &common_0, witness_mults_0)
                    .expect("Failed to prove base circuit");

                prover_0
                    .verify_all_tables(&proof_0, &common_0)
                    .expect("Failed to verify base proof");

                let num_tables_0 = airs_0.len();

                // =================================================================
                // LAYER 1: Recursively verify the base proof
                // =================================================================

                // In-circuit verifier params MUST match layer 0's FRI params
                let fri_verifier_params = create_fri_verifier_params();
                let lookup_gadget_1 = LogUpGadget::new();

                let mut circuit_builder_1 = CircuitBuilder::new();
                let perm_1 = $default_perm();
                circuit_builder_1.enable_poseidon2_perm::<$poseidon2_circuit_config, _>(
                    generate_poseidon2_trace::<Challenge, $poseidon2_circuit_config>,
                    perm_1,
                );

                const TRACE_D_LAYER0: usize = 1;
                let pis_0: Vec<Vec<F>> = vec![vec![]; num_tables_0];

                // Layer 1 prover config (same FRI params as layer 0)
                let config_1 = create_config();

                let (verifier_inputs_1, mmcs_op_ids_1) = verify_p3_recursion_proof_circuit::<
                    MyConfig,
                    HashTargets<F, DIGEST_ELEMS>,
                    InputProofTargets<
                        F,
                        Challenge,
                        RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
                    >,
                    InnerFri,
                    LogUpGadget,
                    WIDTH,
                    RATE,
                    TRACE_D_LAYER0,
                >(
                    &config_1,
                    &mut circuit_builder_1,
                    &proof_0,
                    &fri_verifier_params,
                    &common_0,
                    &lookup_gadget_1,
                    $poseidon2_config,
                )
                .expect("Failed to build verification circuit for layer 1");

                let verification_circuit_1 = circuit_builder_1.build().unwrap();
                let num_ops_1 = verification_circuit_1.ops.len();
                let public_inputs_1 =
                    verifier_inputs_1.pack_values(&pis_0, &proof_0.proof, &common_0);

                info!("Verification circuit built with {num_ops_1} operations");

                let table_packing_1 = TablePacking::new(64, 8, 32, 32);

                let (airs_degrees_1, witness_mults_1) =
                    get_airs_and_degrees_with_prep::<MyConfig, _, D>(
                        &verification_circuit_1,
                        table_packing_1,
                        Some(&[NonPrimitiveConfig::Poseidon2($poseidon2_config)]),
                    )
                    .expect("Failed to get AIRs for layer 1");
                let (mut airs_1, degrees_1): (Vec<_>, Vec<_>) = airs_degrees_1.into_iter().unzip();

                let mut runner_1 = verification_circuit_1.runner();
                runner_1.set_public_inputs(&public_inputs_1).unwrap();

                set_fri_mmcs_private_data::<
                    F,
                    Challenge,
                    ChallengeMmcs,
                    ValMmcs,
                    MyHash,
                    MyCompress,
                    DIGEST_ELEMS,
                >(&mut runner_1, &mmcs_op_ids_1, &proof_0.proof.opening_proof)
                .expect("Failed to set MMCS private data for layer 1");

                let traces_1 = runner_1.run().expect("Failed to run layer 1 circuit");

                let common_1 =
                    CommonData::from_airs_and_degrees(&config_1, &mut airs_1, &degrees_1);

                let mut prover_1 =
                    BatchStarkProver::new(config_1).with_table_packing(table_packing_1);
                prover_1.register_poseidon2_table($poseidon2_config);

                let proof_1 = prover_1
                    .prove_all_tables(&traces_1, &common_1, witness_mults_1)
                    .expect("Failed to prove layer 1 circuit");

                prover_1
                    .verify_all_tables(&proof_1, &common_1)
                    .expect("Failed to verify layer 1 proof");
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
