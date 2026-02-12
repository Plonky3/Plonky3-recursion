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
use p3_batch_stark::ProverData;
use p3_challenger::DuplexChallenger;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::generate_poseidon2_trace;
use p3_circuit_prover::common::{NonPrimitiveConfig, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{BatchStarkProver, CircuitProverData, TablePacking};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{FriParameters, TwoAdicFriPcs};
use p3_keccak_air::KeccakAir;
use p3_lookup::logup::LogUpGadget;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::pcs::{HashTargets, InputProofTargets, RecValMmcs, set_fri_mmcs_private_data};
use p3_recursion::verifier::verify_p3_recursion_proof_circuit;
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

    info!(
        "Recursively proving {} Keccak hashes with field {:?}",
        args.num_hashes, args.field
    );

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

            // ===============
            // FRI Parameters
            // ===============
            const LOG_BLOWUP: usize = 3;
            const MAX_LOG_ARITY: usize = 4;
            const LOG_FINAL_POLY_LEN: usize = 5;
            const COMMIT_POW_BITS: usize = 0;
            const QUERY_POW_BITS: usize = 16;

            /// Create a STARK config with benchmark-inspired FRI params.
            fn create_config(log_blowup: usize) -> MyConfig {
                let perm = $default_perm();
                let hash = MyHash::new(perm.clone());
                let compress = MyCompress::new(perm.clone());
                let val_mmcs = ValMmcs::new(hash, compress);
                let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
                let dft = Dft::default();

                let num_queries = (100 - QUERY_POW_BITS) / log_blowup;

                let fri_params = FriParameters {
                    max_log_arity: MAX_LOG_ARITY,
                    log_blowup,
                    log_final_poly_len: LOG_FINAL_POLY_LEN,
                    num_queries,
                    commit_proof_of_work_bits: COMMIT_POW_BITS,
                    query_proof_of_work_bits: QUERY_POW_BITS,
                    mmcs: challenge_mmcs,
                };
                let pcs = MyPcs::new(dft, val_mmcs, fri_params);
                let challenger = Challenger::new(perm);
                MyConfig::new(pcs, challenger)
            }

            /// Create FRI verifier params for the in-circuit verifier.
            /// MUST match the FRI params used by the native prover being verified.
            const fn create_fri_verifier_params() -> FriVerifierParams {
                FriVerifierParams::with_mmcs(
                    LOG_BLOWUP,
                    LOG_FINAL_POLY_LEN,
                    COMMIT_POW_BITS,
                    QUERY_POW_BITS,
                    $poseidon2_config,
                )
            }

            pub fn run(num_hashes: usize) {
                // =================================================================
                // LAYER 0: Create and prove Keccak permutations
                // =================================================================

                let keccak_air = KeccakAir {};
                let min_trace_rows = 1 << (LOG_FINAL_POLY_LEN + LOG_BLOWUP + 1);
                let min_keccak_hashes = (min_trace_rows + p3_keccak_air::NUM_ROUNDS - 1)
                    / p3_keccak_air::NUM_ROUNDS;
                let effective_num_hashes = num_hashes.max(min_keccak_hashes);
                if effective_num_hashes != num_hashes {
                    tracing::warn!("Number of equivalent Keccak hashes after mandatory padding: {effective_num_hashes}");
                }
                let trace =
                    keccak_air.generate_trace_rows(effective_num_hashes, LOG_BLOWUP);

                // Layer 0 prover config
                let config_0 = create_config(LOG_BLOWUP);
                let pis: Vec<F> = vec![];

                let proof_0 = prove(&config_0, &keccak_air, trace, &pis);

                verify(&config_0, &keccak_air, &proof_0, &pis)
                    .expect("Failed to verify Keccak proof natively");

                // =================================================================
                // LAYER 1: Recursively verify the Keccak proof
                // =================================================================

                // In-circuit verifier params MUST match layer 0's FRI params
                let fri_verifier_params = create_fri_verifier_params();

                // Layer 1 prover config
                let config_1 = create_config(LOG_BLOWUP);
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

                let table_packing_1 = TablePacking::new(17, 3, 8);

                let (airs_degrees_1, preprocessed_columns_1) =
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

                let prover_data_1 =
                    ProverData::from_airs_and_degrees(&config_1, &mut airs_1, &degrees_1);
                let circuit_prover_data_1 =
                    CircuitProverData::new(prover_data_1, preprocessed_columns_1);

                let common_1 = circuit_prover_data_1.common_data();

                let mut prover_1 =
                    BatchStarkProver::new(config_1).with_table_packing(table_packing_1);
                prover_1.register_poseidon2_table($poseidon2_config);

                let proof_1 = prover_1
                    .prove_all_tables(&traces_1, &circuit_prover_data_1)
                    .expect("Failed to prove verification circuit");

                prover_1
                    .verify_all_tables(&proof_1, &common_1)
                    .expect("Failed to verify recursive proof");

                let num_tables_1 = airs_1.len();

                // =================================================================
                // LAYER 2: Recursively verify the recursive proof
                // =================================================================

                // In-circuit verifier params MUST match layer 0's FRI params
                let fri_verifier_params = create_fri_verifier_params();
                let lookup_gadget_2 = LogUpGadget::new();

                let mut circuit_builder_2 = CircuitBuilder::new();
                let perm_2 = $default_perm();
                circuit_builder_2.enable_poseidon2_perm::<$poseidon2_circuit_config, _>(
                    generate_poseidon2_trace::<Challenge, $poseidon2_circuit_config>,
                    perm_2,
                );

                const TRACE_D_LAYER1: usize = 4;
                let pis_1: Vec<Vec<F>> = vec![vec![]; num_tables_1];

                // Layer 2 prover config
                let config_2 = create_config(LOG_BLOWUP);

                let (verifier_inputs_2, mmcs_op_ids_2) = verify_p3_recursion_proof_circuit::<
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
                    TRACE_D_LAYER1,
                >(
                    &config_2,
                    &mut circuit_builder_2,
                    &proof_1,
                    &fri_verifier_params,
                    &common_1,
                    &lookup_gadget_2,
                    $poseidon2_config,
                )
                .expect("Failed to build verification circuit for layer 2");

                let verification_circuit_2 = circuit_builder_2.build().unwrap();
                let num_ops_2 = verification_circuit_2.ops.len();
                let public_inputs_2 =
                    verifier_inputs_2.pack_values(&pis_1, &proof_1.proof, &common_1);

                info!("Verification circuit built with {num_ops_2} operations");

                let table_packing_2 =
                    TablePacking::new(6, 2, 3).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);

                let (airs_degrees_2, preprocessed_columns_2) =
                    get_airs_and_degrees_with_prep::<MyConfig, _, D>(
                        &verification_circuit_2,
                        table_packing_2,
                        Some(&[NonPrimitiveConfig::Poseidon2($poseidon2_config)]),
                    )
                    .expect("Failed to get AIRs for layer 2");
                let (mut airs_2, degrees_2): (Vec<_>, Vec<_>) = airs_degrees_2.into_iter().unzip();

                let mut runner_2 = verification_circuit_2.runner();
                runner_2.set_public_inputs(&public_inputs_2).unwrap();

                set_fri_mmcs_private_data::<
                    F,
                    Challenge,
                    ChallengeMmcs,
                    ValMmcs,
                    MyHash,
                    MyCompress,
                    DIGEST_ELEMS,
                >(&mut runner_2, &mmcs_op_ids_2, &proof_1.proof.opening_proof)
                .expect("Failed to set MMCS private data for layer 2");

                let traces_2 = runner_2.run().expect("Failed to run layer 2 circuit");

                let prover_data_2 =
                    ProverData::from_airs_and_degrees(&config_2, &mut airs_2, &degrees_2);
                let circuit_prover_data_2 =
                    CircuitProverData::new(prover_data_2, preprocessed_columns_2);

                let common_2 = circuit_prover_data_2.common_data();

                let mut prover_2 =
                    BatchStarkProver::new(config_2).with_table_packing(table_packing_2);
                prover_2.register_poseidon2_table($poseidon2_config);

                let proof_2 = prover_2
                    .prove_all_tables(&traces_2, &circuit_prover_data_2)
                    .expect("Failed to prove layer 2 circuit");

                prover_2
                    .verify_all_tables(&proof_2, &common_2)
                    .expect("Failed to verify layer 2 proof");
                let num_tables_2 = airs_2.len();

                // =================================================================
                // LAYER 3: Recursively verify the recursive proof
                // =================================================================

                // In-circuit verifier params MUST match layer 0's FRI params
                let fri_verifier_params = create_fri_verifier_params();
                let lookup_gadget_3 = LogUpGadget::new();

                let mut circuit_builder_3 = CircuitBuilder::new();
                let perm_3 = $default_perm();
                circuit_builder_3.enable_poseidon2_perm::<$poseidon2_circuit_config, _>(
                    generate_poseidon2_trace::<Challenge, $poseidon2_circuit_config>,
                    perm_3,
                );

                const TRACE_D_LAYER2: usize = 4;
                let pis_2: Vec<Vec<F>> = vec![vec![]; num_tables_2];

                // Layer 3 prover config
                let config_3 = create_config(LOG_BLOWUP);

                let (verifier_inputs_3, mmcs_op_ids_3) = verify_p3_recursion_proof_circuit::<
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
                    TRACE_D_LAYER2,
                >(
                    &config_3,
                    &mut circuit_builder_3,
                    &proof_2,
                    &fri_verifier_params,
                    &common_2,
                    &lookup_gadget_3,
                    $poseidon2_config,
                )
                .expect("Failed to build verification circuit for layer 3");

                let verification_circuit_3 = circuit_builder_3.build().unwrap();
                let num_ops_3 = verification_circuit_3.ops.len();
                let public_inputs_3 =
                    verifier_inputs_3.pack_values(&pis_2, &proof_2.proof, &common_2);

                info!("Verification circuit built with {num_ops_3} operations");

                let table_packing_3 =
                    TablePacking::new(6, 2, 3).with_fri_params(LOG_FINAL_POLY_LEN, LOG_BLOWUP);

                let (airs_degrees_3, preprocessed_columns_3) =
                    get_airs_and_degrees_with_prep::<MyConfig, _, D>(
                        &verification_circuit_3,
                        table_packing_3,
                        Some(&[NonPrimitiveConfig::Poseidon2($poseidon2_config)]),
                    )
                    .expect("Failed to get AIRs for layer 3");

                let (mut airs_3, degrees_3): (Vec<_>, Vec<_>) = airs_degrees_3.into_iter().unzip();

                let mut runner_3 = verification_circuit_3.runner();
                runner_3.set_public_inputs(&public_inputs_3).unwrap();

                set_fri_mmcs_private_data::<
                    F,
                    Challenge,
                    ChallengeMmcs,
                    ValMmcs,
                    MyHash,
                    MyCompress,
                    DIGEST_ELEMS,
                >(&mut runner_3, &mmcs_op_ids_3, &proof_2.proof.opening_proof)
                .expect("Failed to set MMCS private data for layer 3");

                let traces_3 = runner_3.run().expect("Failed to run layer 3 circuit");

                let prover_data_3 =
                    ProverData::from_airs_and_degrees(&config_3, &mut airs_3, &degrees_3);
                let circuit_prover_data_3 =
                    CircuitProverData::new(prover_data_3, preprocessed_columns_3);

                let common_3 = circuit_prover_data_3.common_data();

                let mut prover_3 =
                    BatchStarkProver::new(config_3).with_table_packing(table_packing_3);
                prover_3.register_poseidon2_table($poseidon2_config);

                let proof_3 = prover_3
                    .prove_all_tables(&traces_3, &circuit_prover_data_3)
                    .expect("Failed to prove layer 3 circuit");

                prover_3
                    .verify_all_tables(&proof_3, &common_3)
                    .expect("Failed to verify layer 3 proof");

                info!("Recursive proof verified successfully");
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
