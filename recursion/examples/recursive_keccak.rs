//! Recursive Keccak proof verification example.
//!
//! This example demonstrates end-to-end recursive verification:
//! 1. **Layer 0 (Base)**: Create a Keccak AIR proof with Plonky3 STARK
//! 2. **Layer 1 (Recursive)**: Build a verification circuit that checks the Layer 0 proof,
//!    then prove this circuit itself
//!
//! ## Note on Performance
//!
//! The Keccak AIR produces a large verification circuit due to the complexity of Keccak
//! constraints (~1700 columns). Recursive verification is computationally intensive.
//!
//! Run with: cargo run --release --example recursive_keccak -- --field koala-bear --num-hashes 4

use clap::{Parser, ValueEnum};
use p3_batch_stark::CommonData;
use p3_challenger::DuplexChallenger;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::generate_poseidon2_trace;
use p3_circuit_prover::common::{NonPrimitiveConfig, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{BatchStarkProver, TablePacking};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{TwoAdicFriPcs, create_test_fri_params};
use p3_keccak_air::KeccakAir;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::pcs::{HashTargets, InputProofTargets, RecValMmcs, set_fri_mmcs_private_data};
use p3_recursion::{
    FriVerifierParams, Poseidon2Config, StarkVerifierInputsBuilder, verify_circuit,
};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, prove, verify};
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
#[command(version, about = "Recursive Keccak proof verification example")]
struct Args {
    /// The field to use for the proof.
    #[arg(short, long, ignore_case = true, value_enum, default_value_t = FieldOption::KoalaBear)]
    field: FieldOption,

    /// Number of Keccak permutations to prove.
    #[arg(short, long, default_value_t = 4)]
    num_hashes: usize,
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
        FieldOption::KoalaBear => koala_bear::run(args.num_hashes),
        FieldOption::BabyBear => baby_bear::run(args.num_hashes),
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

            /// FRI params for layer 0 (base proof).
            /// The in-circuit verifier MUST use the same params.
            const LOG_FINAL_POLY_LEN_LAYER0: usize = 1;

            /// FRI params for layer 1 (recursive proof).
            /// Can be different from layer 0.
            const LOG_FINAL_POLY_LEN_LAYER1: usize = 1;

            /// Create a STARK config with the given log_final_poly_len.
            fn create_config(log_final_poly_len: usize) -> MyConfig {
                let perm = $default_perm();
                let hash = MyHash::new(perm.clone());
                let compress = MyCompress::new(perm.clone());
                let val_mmcs = ValMmcs::new(hash, compress);
                let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
                let dft = Dft::default();
                let fri_params = create_test_fri_params(challenge_mmcs, log_final_poly_len);
                let pcs = MyPcs::new(dft, val_mmcs, fri_params);
                let challenger = Challenger::new(perm);
                MyConfig::new(pcs, challenger)
            }

            /// Create FRI verifier params for the in-circuit verifier.
            /// MUST match the FRI params used by the native prover being verified.
            fn create_fri_verifier_params(log_final_poly_len: usize) -> FriVerifierParams {
                let perm = $default_perm();
                let hash = MyHash::new(perm.clone());
                let compress = MyCompress::new(perm.clone());
                let val_mmcs = ValMmcs::new(hash, compress);
                let challenge_mmcs = ChallengeMmcs::new(val_mmcs);
                let fri_params = create_test_fri_params(challenge_mmcs, log_final_poly_len);
                FriVerifierParams::with_mmcs(
                    fri_params.log_blowup,
                    fri_params.log_final_poly_len,
                    fri_params.commit_proof_of_work_bits,
                    fri_params.query_proof_of_work_bits,
                    $poseidon2_config,
                )
            }

            pub fn run(num_hashes: usize) {
                // =================================================================
                // LAYER 0: Create and prove Keccak permutations
                // =================================================================

                let keccak_air = KeccakAir {};
                let trace = keccak_air.generate_trace_rows(num_hashes, 0);

                // Layer 0 prover config
                let config_0 = create_config(LOG_FINAL_POLY_LEN_LAYER0);
                let pis: Vec<F> = vec![];

                let proof_0 = prove(&config_0, &keccak_air, trace, &pis);

                verify(&config_0, &keccak_air, &proof_0, &pis)
                    .expect("Failed to verify Keccak proof natively");

                // =================================================================
                // LAYER 1: Recursively verify the Keccak proof
                // =================================================================

                // In-circuit verifier params MUST match layer 0's FRI params
                let fri_verifier_params = create_fri_verifier_params(LOG_FINAL_POLY_LEN_LAYER0);

                // Layer 1 prover config
                let config_1 = create_config(LOG_FINAL_POLY_LEN_LAYER1);
                let perm_1 = $default_perm();

                let mut circuit_builder_1 = CircuitBuilder::new();
                circuit_builder_1.enable_poseidon2_perm::<$poseidon2_circuit_config, _>(
                    generate_poseidon2_trace::<Challenge, $poseidon2_circuit_config>,
                    perm_1,
                );

                let verifier_inputs_1 = StarkVerifierInputsBuilder::<
                    MyConfig,
                    HashTargets<F, DIGEST_ELEMS>,
                    InnerFri,
                >::allocate(
                    &mut circuit_builder_1, &proof_0, None, pis.len()
                );

                let mmcs_op_ids_1 = verify_circuit::<
                    KeccakAir,
                    MyConfig,
                    HashTargets<F, DIGEST_ELEMS>,
                    InputProofTargets<
                        F,
                        Challenge,
                        RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>,
                    >,
                    InnerFri,
                    WIDTH,
                    RATE,
                >(
                    &config_1,
                    &keccak_air,
                    &mut circuit_builder_1,
                    &verifier_inputs_1.proof_targets,
                    &verifier_inputs_1.air_public_targets,
                    &None,
                    &fri_verifier_params,
                    $poseidon2_config,
                )
                .expect("Failed to build verification circuit");

                let verification_circuit_1 = circuit_builder_1.build().unwrap();
                let num_ops_1 = verification_circuit_1.ops.len();
                let public_inputs_1 = verifier_inputs_1.pack_values(&pis, &proof_0, &None);

                info!("Verification circuit built with {num_ops_1} operations");

                let table_packing_1 = TablePacking::new(16, 1, 8, 8);

                let (airs_degrees_1, witness_mults_1) =
                    get_airs_and_degrees_with_prep::<MyConfig, _, D>(
                        &verification_circuit_1,
                        table_packing_1,
                        Some(&[NonPrimitiveConfig::Poseidon2($poseidon2_config)]),
                    )
                    .expect("Failed to get AIRs");
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
                >(&mut runner_1, &mmcs_op_ids_1, &proof_0.opening_proof)
                .expect("Failed to set MMCS private data");

                let traces_1 = runner_1.run().expect("Failed to run verification circuit");

                let common_1 =
                    CommonData::from_airs_and_degrees(&config_1, &mut airs_1, &degrees_1);

                let mut prover_1 =
                    BatchStarkProver::new(config_1).with_table_packing(table_packing_1);
                prover_1.register_poseidon2_table($poseidon2_config);

                let proof_1 = prover_1
                    .prove_all_tables(&traces_1, &common_1, witness_mults_1)
                    .expect("Failed to prove verification circuit");

                prover_1
                    .verify_all_tables(&proof_1, &common_1)
                    .expect("Failed to verify recursive proof");
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
