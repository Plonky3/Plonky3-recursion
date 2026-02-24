mod common;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::ProverData;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::generate_poseidon2_trace;
use p3_circuit_prover::common::{NonPrimitiveConfig, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking};
use p3_field::PrimeCharacteristicRing;
use p3_fri::create_test_fri_params;
use p3_lookup::logup::LogUpGadget;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::Poseidon2Config;
use p3_recursion::pcs::fri::{FriVerifierParams, InputProofTargets, MerkleCapTargets, RecValMmcs};
use p3_recursion::pcs::set_fri_mmcs_private_data;
use p3_recursion::verifier::verify_p3_batch_proof_circuit;
use tracing_forest::ForestLayer;
use tracing_forest::util::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

use crate::common::baby_bear_params::*;

fn init_logger() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();
}

#[test]
fn test_fibonacci_batch_verifier() {
    init_logger();

    let n: usize = 100;

    let mut builder = CircuitBuilder::new();

    // Public input: expected F(n)
    let expected_result = builder.alloc_public_input("expected_result");

    // Compute F(n) iteratively
    let mut a = builder.alloc_const(F::ZERO, "F(0)");
    let mut b = builder.alloc_const(F::ONE, "F(1)");

    for _i in 2..=n {
        let next = builder.add(a, b);
        a = b;
        b = next;
    }

    // Assert computed F(n) equals expected result
    builder.connect(b, expected_result);

    builder.dump_allocation_log();

    let table_packing = TablePacking::new(2, 4);

    // Use the default permutation for proving to match circuit's Fiat-Shamir challenger
    let perm = default_babybear_poseidon2_16();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();

    // Create test FRI params with log_final_poly_len = 0
    let fri_params = create_test_fri_params(challenge_mmcs, 0);

    // Create config for proving
    let pcs_proving = MyPcs::new(dft, val_mmcs, fri_params);
    let challenger_proving = Challenger::new(perm);
    let config_proving = MyConfig::new(pcs_proving, challenger_proving);

    let circuit = builder.build().unwrap();
    let (airs_degrees, preprocessed_columns) = get_airs_and_degrees_with_prep::<MyConfig, _, 1>(
        &circuit,
        table_packing,
        None,
        ConstraintProfile::Standard,
    )
    .unwrap();
    let (mut airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();

    // Set public input
    let expected_fib = compute_fibonacci_classical(n);
    runner.set_public_inputs(&[expected_fib]).unwrap();

    let traces = runner.run().unwrap();

    // Create prover data for proving and verifying.
    let prover_data = ProverData::from_airs_and_degrees(&config_proving, &mut airs, &degrees);
    let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);

    let prover = BatchStarkProver::new(config_proving).with_table_packing(table_packing);

    let lookup_gadget = LogUpGadget::new();
    let batch_stark_proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();

    let common = circuit_prover_data.common_data();
    prover
        .verify_all_tables(&batch_stark_proof, common)
        .unwrap();

    // Now verify the batch STARK proof recursively
    // Use same permutation as proving to ensure Fiat-Shamir transcript compatibility
    let dft2 = Dft::default();
    let perm2 = default_babybear_poseidon2_16();
    let hash2 = MyHash::new(perm2.clone());
    let compress2 = MyCompress::new(perm2.clone());
    let val_mmcs2 = ValMmcs::new(hash2, compress2, 0);
    let challenge_mmcs2 = ChallengeMmcs::new(val_mmcs2.clone());
    let fri_params2 = create_test_fri_params(challenge_mmcs2, 0);
    let fri_verifier_params = FriVerifierParams::with_mmcs(
        fri_params2.log_blowup,
        fri_params2.log_final_poly_len,
        fri_params2.commit_proof_of_work_bits,
        fri_params2.query_proof_of_work_bits,
        Poseidon2Config::BabyBearD4Width16,
    );
    let pcs_verif = MyPcs::new(dft2, val_mmcs2, fri_params2);
    let challenger_verif = Challenger::new(perm2);
    let config = MyConfig::new(pcs_verif, challenger_verif);

    // Extract proof components
    let batch_proof = &batch_stark_proof.proof;

    const TRACE_D: usize = 1; // Proof traces are in base field

    // Public values (empty for all 5 circuit tables: Witness, Const, Public, Alu, Poseidon2)
    let pis: Vec<Vec<F>> = vec![vec![]; 5];

    // Build the recursive verification circuit
    let mut circuit_builder = CircuitBuilder::new();
    let poseidon2_perm = default_babybear_poseidon2_16();
    circuit_builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        poseidon2_perm,
    );

    // Attach verifier without manually building circuit_airs
    let (verifier_inputs, mmcs_op_ids) = verify_p3_batch_proof_circuit::<
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
        InnerFri,
        LogUpGadget,
        WIDTH,
        RATE,
        TRACE_D,
    >(
        &config,
        &mut circuit_builder,
        &batch_stark_proof,
        &fri_verifier_params,
        common,
        &lookup_gadget,
        Poseidon2Config::BabyBearD4Width16,
    )
    .unwrap();

    // Build the circuit
    let verification_circuit = circuit_builder.build().unwrap();
    let expected_public_input_len = verification_circuit.public_flat_len;

    // Pack values using the builder
    let public_inputs = verifier_inputs.pack_values(&pis, batch_proof, common);

    assert_eq!(public_inputs.len(), expected_public_input_len);
    assert!(!public_inputs.is_empty());

    let verification_table_packing = TablePacking::new(1, 8);
    let poseidon2_config = Poseidon2Config::BabyBearD4Width16;
    let (verification_airs_degrees, verification_preprocessed_columns) =
        get_airs_and_degrees_with_prep::<MyConfig, _, 4>(
            &verification_circuit,
            verification_table_packing,
            Some(&[NonPrimitiveConfig::Poseidon2(poseidon2_config)]),
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (mut verification_airs, verification_degrees): (Vec<_>, Vec<usize>) =
        verification_airs_degrees.into_iter().unzip();

    // Now run the circuit to generate traces
    let mut runner = verification_circuit.runner();
    runner.set_public_inputs(&public_inputs).unwrap();

    // Set MMCS private data for the verification circuit
    set_fri_mmcs_private_data::<
        F,
        Challenge,
        ChallengeMmcs,
        ValMmcs,
        MyHash,
        MyCompress,
        DIGEST_ELEMS,
    >(
        &mut runner,
        &mmcs_op_ids,
        &batch_stark_proof.proof.opening_proof,
    )
    .unwrap();

    // Run the circuit to generate traces
    let verification_traces = runner.run().unwrap();

    // Create a new config and prover for the verification circuit
    let dft3 = Dft::default();
    let perm3 = default_babybear_poseidon2_16();
    let hash3 = MyHash::new(perm3.clone());
    let compress3 = MyCompress::new(perm3.clone());
    let val_mmcs3 = ValMmcs::new(hash3, compress3, 0);
    let challenge_mmcs3 = ChallengeMmcs::new(val_mmcs3.clone());
    let fri_params3 = create_test_fri_params(challenge_mmcs3, 0);
    let pcs3 = MyPcs::new(dft3, val_mmcs3, fri_params3);
    let challenger3 = Challenger::new(perm3);
    let config3 = MyConfig::new(pcs3, challenger3);

    let verification_prover_data =
        ProverData::from_airs_and_degrees(&config3, &mut verification_airs, &verification_degrees);
    let verification_circuit_prover_data =
        CircuitProverData::new(verification_prover_data, verification_preprocessed_columns);

    let mut verification_prover =
        BatchStarkProver::new(config3).with_table_packing(verification_table_packing);
    verification_prover.register_poseidon2_table(poseidon2_config);

    // Prove the verification circuit
    let verification_proof = verification_prover
        .prove_all_tables(&verification_traces, &verification_circuit_prover_data)
        .expect("Failed to prove verification circuit");

    // Verify the proof of the verification circuit
    verification_prover
        .verify_all_tables(
            &verification_proof,
            verification_circuit_prover_data.common_data(),
        )
        .expect("Failed to verify proof of verification circuit");
}

fn compute_fibonacci_classical(n: usize) -> F {
    if n == 0 {
        return F::ZERO;
    }
    if n == 1 {
        return F::ONE;
    }

    let mut a = F::ZERO;
    let mut b = F::ONE;

    for _i in 2..=n {
        let next = a + b;
        a = b;
        b = next;
    }

    b
}
