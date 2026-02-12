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
    log_final_poly_len: usize,
    commit_pow_bits: usize,
    query_pow_bits: usize,
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

    /// Number of recursive verification layers (1 = verify base once, 3 = base + 3 recursive layers).
    #[arg(
        long,
        default_value_t = 3,
        help = "Number of recursive verification layers"
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
        log_final_poly_len: args.log_final_poly_len,
        commit_pow_bits: args.commit_pow_bits,
        query_pow_bits: args.query_pow_bits,
    };

    if args.num_recursive_layers < 1 {
        panic!("Number of recursive layers should be at least 1");
    }

    info!(
        "Recursively proving {} Keccak hashes with field {:?}",
        args.num_hashes, args.field
    );

    match args.field {
        FieldOption::KoalaBear => {
            koala_bear::run(args.num_hashes, args.num_recursive_layers, &fri_params);
        }
        FieldOption::BabyBear => {
            baby_bear::run(args.num_hashes, args.num_recursive_layers, &fri_params);
        }
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

            fn create_config(fp: &super::FriParams) -> MyConfig {
                let perm = $default_perm();
                let hash = MyHash::new(perm.clone());
                let compress = MyCompress::new(perm.clone());
                let val_mmcs = ValMmcs::new(hash, compress);
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

            const fn create_fri_verifier_params(fp: &super::FriParams) -> FriVerifierParams {
                FriVerifierParams::with_mmcs(
                    fp.log_blowup,
                    fp.log_final_poly_len,
                    fp.commit_pow_bits,
                    fp.query_pow_bits,
                    $poseidon2_config,
                )
            }

            pub fn run(num_hashes: usize, num_recursive_layers: usize, fri_params: &super::FriParams) {
                // =================================================================
                // LAYER 0: Create and prove Keccak permutations
                // =================================================================

                let keccak_air = KeccakAir {};
                let min_trace_rows: usize = 1 << (fri_params.log_final_poly_len + fri_params.log_blowup + 1);
                let min_keccak_hashes = min_trace_rows.div_ceil(p3_keccak_air::NUM_ROUNDS);
                let effective_num_hashes = num_hashes.max(min_keccak_hashes);
                if effective_num_hashes != num_hashes {
                    tracing::warn!("Number of equivalent Keccak hashes after mandatory padding: {effective_num_hashes}");
                }
                let trace =
                    keccak_air.generate_trace_rows(effective_num_hashes, fri_params.log_blowup);

                let config_0 = create_config(fri_params);
                let pis: Vec<F> = vec![];

                let proof_0 = prove(&config_0, &keccak_air, trace, &pis);
                report_proof_size(&proof_0);

                verify(&config_0, &keccak_air, &proof_0, &pis)
                    .expect("Failed to verify Keccak proof natively");

                let mut proof_chain: Vec<(
                    p3_circuit_prover::BatchStarkProof<MyConfig>,
                    CircuitProverData<MyConfig>,
                )> = Vec::new();

                let mut prev_num_tables = if num_recursive_layers >= 1 {
                    let fri_verifier_params = create_fri_verifier_params(fri_params);
                    let config_1 = create_config(fri_params);
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

                    info!("Layer 1 verification circuit built with {num_ops_1} operations");

                    let table_packing_1 = TablePacking::new(17, 3, 8)
                        .with_fri_params(fri_params.log_final_poly_len, fri_params.log_blowup);

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
                        .expect("Failed to prove layer 1 circuit");
                    report_proof_size(&proof_1);

                    prover_1
                        .verify_all_tables(&proof_1, common_1)
                        .expect("Failed to verify layer 1 proof");

                    proof_chain.push((proof_1, circuit_prover_data_1));

                    airs_1.len() // prev_num_tables
                } else {
                    0
                };

                for layer in 2..=num_recursive_layers {
                    let (prev_proof, prev_cp_data) = proof_chain.last().unwrap();
                    let prev_common = prev_cp_data.common_data();

                    let fri_verifier_params = create_fri_verifier_params(fri_params);
                    let lookup_gadget = LogUpGadget::new();

                    let mut circuit_builder = CircuitBuilder::new();
                    let perm = $default_perm();
                    circuit_builder.enable_poseidon2_perm::<$poseidon2_circuit_config, _>(
                        generate_poseidon2_trace::<Challenge, $poseidon2_circuit_config>,
                        perm,
                    );

                    const TRACE_D_LAYER_REC: usize = 4;
                    let table_packing = TablePacking::new(6, 2, 3)
                        .with_fri_params(fri_params.log_final_poly_len, fri_params.log_blowup);
                    let pis: Vec<Vec<F>> = vec![vec![]; prev_num_tables];
                    let config = create_config(fri_params);

                    let (verifier_inputs, mmcs_op_ids) = verify_p3_recursion_proof_circuit::<
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
                        TRACE_D_LAYER_REC,
                    >(
                        &config,
                        &mut circuit_builder,
                        prev_proof,
                        &fri_verifier_params,
                        prev_common,
                        &lookup_gadget,
                        $poseidon2_config,
                    )
                    .expect(&format!("Failed to build verification circuit for layer {layer}"));

                    let verification_circuit = circuit_builder.build().unwrap();
                    let num_ops = verification_circuit.ops.len();
                    let public_inputs =
                        verifier_inputs.pack_values(&pis, &prev_proof.proof, prev_common);

                    info!("Layer {layer} verification circuit built with {num_ops} operations");

                    let (airs_degrees, preprocessed_columns) =
                        get_airs_and_degrees_with_prep::<MyConfig, _, D>(
                            &verification_circuit,
                            table_packing,
                            Some(&[NonPrimitiveConfig::Poseidon2($poseidon2_config)]),
                        )
                        .expect(&format!("Failed to get AIRs for layer {layer}"));
                    let (mut airs, degrees): (Vec<_>, Vec<_>) =
                        airs_degrees.into_iter().unzip();

                    let mut runner = verification_circuit.runner();
                    runner.set_public_inputs(&public_inputs).unwrap();

                    set_fri_mmcs_private_data::<
                        F,
                        Challenge,
                        ChallengeMmcs,
                        ValMmcs,
                        MyHash,
                        MyCompress,
                        DIGEST_ELEMS,
                    >(&mut runner, &mmcs_op_ids, &prev_proof.proof.opening_proof)
                    .expect(&format!("Failed to set MMCS private data for layer {layer}"));

                    let traces = runner.run().expect(&format!("Failed to run layer {layer} circuit"));

                    let prover_data =
                        ProverData::from_airs_and_degrees(&config, &mut airs, &degrees);
                    let circuit_prover_data =
                        CircuitProverData::new(prover_data, preprocessed_columns);

                    let common = circuit_prover_data.common_data();

                    let mut prover =
                        BatchStarkProver::new(config).with_table_packing(table_packing);
                    prover.register_poseidon2_table($poseidon2_config);

                    let proof = prover
                        .prove_all_tables(&traces, &circuit_prover_data)
                        .expect(&format!("Failed to prove layer {layer} circuit"));
                    report_proof_size(&proof);

                    prover
                        .verify_all_tables(&proof, common)
                        .expect(&format!("Failed to verify layer {layer} proof"));

                    proof_chain.push((proof, circuit_prover_data));
                    prev_num_tables = airs.len();
                }

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

/// Report the size of the serialized proof.
///
/// Serializes the given proof instance using postcard and prints the size in bytes.
/// Panics if serialization fails.
#[inline]
pub fn report_proof_size<S>(proof: &S)
where
    S: Serialize,
{
    let proof_bytes = postcard::to_allocvec(proof).expect("Failed to serialize proof");
    println!("Proof size: {} bytes", proof_bytes.len());
}
