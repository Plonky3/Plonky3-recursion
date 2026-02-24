mod common;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_batch_stark::{CommonData, ProverData};
use p3_circuit::op::PrimitiveOpType;
use p3_circuit::ops::{Poseidon2PermCall, generate_poseidon2_trace};
use p3_circuit::{CircuitBuilder, Poseidon2PermOps};
use p3_circuit_prover::air::{AluAir, ConstAir, PublicAir, WitnessAir};
use p3_circuit_prover::batch_stark_prover::PrimitiveTable;
use p3_circuit_prover::common::{NonPrimitiveConfig, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{
    BatchStarkProof, BatchStarkProver, CircuitProverData, ConstraintProfile, Poseidon2Config,
    TablePacking,
};
use p3_field::PrimeCharacteristicRing;
use p3_fri::create_test_fri_params;
use p3_lookup::logup::LogUpGadget;
use p3_lookup::lookup_traits::LookupData;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::generation::generate_batch_challenges;
use p3_recursion::pcs::fri::{FriVerifierParams, InputProofTargets, MerkleCapTargets, RecValMmcs};
use p3_recursion::verifier::{CircuitTablesAir, verify_p3_batch_proof_circuit};
use p3_recursion::{BatchStarkVerifierInputsBuilder, GenerationError, VerificationError};
const TRACE_D: usize = 1; // Proof traces are in base field

use crate::common::baby_bear_params::*;

fn setup_circuit_builder() -> CircuitBuilder<Challenge> {
    let mut circuit_builder = CircuitBuilder::new();
    let poseidon2_perm = default_babybear_poseidon2_16();
    circuit_builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        poseidon2_perm,
    );
    circuit_builder
}

// In this file, the circuits compute the following function.
fn repeated_arith(a: usize, b: usize, x: usize, n: usize) -> usize {
    let mut y = a * x + b;
    for _i in 0..n {
        y = a * y + b;
    }
    y
}

#[test]
fn test_arith_lookups() {
    let TestCircuitProofData {
        mut batch_stark_proof,
        circuit_prover_data,
        lookup_gadget,
        config,
        params,
        pis,
        prover,
    } = get_test_circuit_proof();
    let common = circuit_prover_data.common_data();

    prover
        .verify_all_tables(&batch_stark_proof, common)
        .unwrap();

    // Build the recursive verification circuit
    let mut circuit_builder = setup_circuit_builder();

    let (verifier_inputs, _all_challenges) = get_verifier_inputs_and_challenges(
        &mut circuit_builder,
        &config,
        &params,
        &mut batch_stark_proof,
        common,
        &pis,
        None,
        &lookup_gadget,
    );

    // Build the circuit
    let verification_circuit = circuit_builder.build().unwrap();
    let expected_public_input_len = verification_circuit.public_flat_len;

    // Pack values using the builder
    let batch_proof = &batch_stark_proof.proof;
    let public_inputs = verifier_inputs
        .unwrap()
        .pack_values(&pis, batch_proof, common);

    assert_eq!(public_inputs.len(), expected_public_input_len);
    assert!(!public_inputs.is_empty());

    // Actually run the circuit to ensure constraints are satisfiable
    let mut runner = verification_circuit.runner();
    runner.set_public_inputs(&public_inputs).unwrap();
    let _traces = runner.run().unwrap();
}

#[test]
#[should_panic]
fn test_wrong_multiplicities() {
    let n = 10;

    // Get a circuit that computes arithmetic operations.
    let builder = get_circuit(n);

    let table_packing = TablePacking::new(1, 4, 4);

    let config_proving = get_proving_config();

    let circuit = builder.build().unwrap();
    let (airs_degrees, mut preprocessed_columns) =
        get_airs_and_degrees_with_prep::<MyConfig, _, 1>(
            &circuit,
            table_packing,
            None,
            ConstraintProfile::Standard,
        )
        .unwrap();

    // Introduce an error in the witness multiplicities.
    preprocessed_columns.primitive[PrimitiveOpType::Witness as usize]
        [PrimitiveTable::Alu as usize] += F::ONE;
    let (mut airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();

    let init_a = 3;
    let init_b = 5;
    let init_x = 7;
    let expected_result = F::from_usize(repeated_arith(init_a, init_b, init_x, n));

    runner
        .set_public_inputs(&[
            F::from_usize(init_x),
            F::from_usize(init_a),
            F::from_usize(init_b),
            expected_result,
        ])
        .unwrap();

    let traces = runner.run().unwrap();

    // Create prover data for proving and verifying.
    let prover_data = ProverData::from_airs_and_degrees(&config_proving, &mut airs, &degrees);
    let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);

    let prover = BatchStarkProver::new(config_proving).with_table_packing(table_packing);

    // Prove the circuit.
    let lookup_gadget = LogUpGadget::new();
    let mut batch_stark_proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    let common = circuit_prover_data.common_data();

    // Now verify the batch STARK proof recursively
    let (config, fri_verifier_params, pow_bits, log_height_max) = get_recursive_config_and_params();

    // Build the recursive verification circuit
    let mut circuit_builder = setup_circuit_builder();

    // Public values (empty for all 4 circuit tables, using base field)
    let pis: Vec<Vec<F>> = vec![vec![]; 4];

    // Attach verifier without manually building circuit_airs
    let params = Parameters {
        fri_verifier_params,
        pow_bits,
        log_height_max,
    };
    let (verifier_inputs, _all_challenges) = get_verifier_inputs_and_challenges(
        &mut circuit_builder,
        &config,
        &params,
        &mut batch_stark_proof,
        common,
        &pis,
        None,
        &lookup_gadget,
    );

    // Build the circuit
    let verification_circuit = circuit_builder.build().unwrap();
    let expected_public_input_len = verification_circuit.public_flat_len;

    // Pack values using the builder
    let batch_proof = &batch_stark_proof.proof;
    let public_inputs = verifier_inputs
        .unwrap()
        .pack_values(&pis, batch_proof, common);

    assert_eq!(public_inputs.len(), expected_public_input_len);
    assert!(!public_inputs.is_empty());

    // Actually run the circuit to ensure constraints are satisfiable
    let mut runner = verification_circuit.runner();
    runner.set_public_inputs(&public_inputs).unwrap();

    // This line fails because the proof was generated with wrong multiplicities.
    // Thus, we have an OOD evaluation mismatch, resulting in a `WitnessConflict` in the circuit.
    let _traces = runner.run().unwrap();
}

#[test]
#[should_panic(expected = "WitnessConflict")]
fn test_wrong_expected_cumulated() {
    let TestCircuitProofData {
        mut batch_stark_proof,
        circuit_prover_data,
        lookup_gadget,
        config,
        params,
        pis,
        ..
    } = get_test_circuit_proof();
    let common = circuit_prover_data.common_data();

    // Introduce an error in the global expected cumulated values for the first lookup.
    // This leads to the sum of all expected cumulated values being off by 1,
    // which causes a WitnessConflict during recursive verification.
    batch_stark_proof.proof.global_lookup_data[0][0].expected_cumulated += F::ONE;
    // Introduce an error in the expected cumulated values for the first lookup.
    assert!(batch_stark_proof.proof.global_lookup_data.len() == 4);

    // Build the recursive verification circuit
    let mut circuit_builder = setup_circuit_builder();

    let (verifier_inputs, _all_challenges) = get_verifier_inputs_and_challenges(
        &mut circuit_builder,
        &config,
        &params,
        &mut batch_stark_proof,
        common,
        &pis,
        None,
        &lookup_gadget,
    );

    // Build the circuit
    let verification_circuit = circuit_builder.build().unwrap();
    let expected_public_input_len = verification_circuit.public_flat_len;

    // Pack values using the builder
    let public_inputs =
        verifier_inputs
            .unwrap()
            .pack_values(&pis, &batch_stark_proof.proof, common);

    assert_eq!(public_inputs.len(), expected_public_input_len);
    assert!(!public_inputs.is_empty());

    // Actually run the circuit to ensure constraints are satisfiable
    let mut runner = verification_circuit.runner();
    runner.set_public_inputs(&public_inputs).unwrap();

    // This line fails because the verifier gets wrong global lookup data.
    // This leads to the sum of all expected cumulated values being off by 1,
    // which causes a WitnessConflict during recursive verification.
    let _traces = runner.run().unwrap();
}

#[test]
#[should_panic(expected = "WitnessConflict")]
fn test_inconsistent_lookup_name() {
    let TestCircuitProofData {
        mut batch_stark_proof,
        circuit_prover_data,
        lookup_gadget,
        config,
        params,
        pis,
        ..
    } = get_test_circuit_proof();
    let common = circuit_prover_data.common_data();

    let real_lookup_data = batch_stark_proof.proof.global_lookup_data.clone();
    // First, modify the first global lookup data's name.
    assert!(real_lookup_data.len() == 4);
    let mut fake_global_lookup_data = real_lookup_data.clone();
    fake_global_lookup_data[0][0].name = "ModifiedLookup".to_string();

    // Build the recursive verification circuit
    let mut circuit_builder = setup_circuit_builder();

    // Attach verifier without manually building circuit_airs. Generation fails because of the fake lookup data.
    // First, only challenges use the fake lookup data.
    let (_verifier_inputs, all_challenges) = get_verifier_inputs_and_challenges(
        &mut circuit_builder,
        &config,
        &params,
        &mut batch_stark_proof,
        common,
        &pis,
        Some(&fake_global_lookup_data),
        &lookup_gadget,
    );

    match all_challenges {
        Err(GenerationError::InvalidProofShape(msg)) => {
            assert_eq!(msg, "Global lookups are inconsistent with lookups");
        }
        Err(_) => panic!("Expected InvalidProofShape"),
        Ok(_) => panic!("Expected error due to inconsistent lookup shape"),
    }

    // Second, only the verifier uses the fake lookup data with a modified name.
    // Since global permutation challenges are generated based on the `name`,
    // this leads to a `WitnessConflict` during recursive verification due to failed constraints.
    batch_stark_proof.proof.global_lookup_data = fake_global_lookup_data;

    let mut circuit_builder = setup_circuit_builder();
    let (verifier_inputs, _all_challenges) = get_verifier_inputs_and_challenges(
        &mut circuit_builder,
        &config,
        &params,
        &mut batch_stark_proof,
        common,
        &pis,
        Some(real_lookup_data.as_slice()),
        &lookup_gadget,
    );

    // Build the circuit
    let verification_circuit = circuit_builder.build().unwrap();
    let expected_public_input_len = verification_circuit.public_flat_len;

    // Pack values using the builder
    let public_inputs =
        verifier_inputs
            .unwrap()
            .pack_values(&pis, &batch_stark_proof.proof, common);

    assert_eq!(public_inputs.len(), expected_public_input_len);
    assert!(!public_inputs.is_empty());

    // Actually run the circuit to ensure constraints are satisfiable
    let mut runner = verification_circuit.runner();
    runner.set_public_inputs(&public_inputs).unwrap();

    // This line fails because the verifier gets wrong global lookup data.
    // This leads to the sum of all expected cumulated values being off by 1,
    // which causes a WitnessConflict during recursive verification.
    let _traces = runner.run().unwrap();
}

#[test]
fn test_inconsistent_lookup_commitment_shape() {
    let TestCircuitProofData {
        mut batch_stark_proof,
        circuit_prover_data,
        lookup_gadget,
        config,
        params,
        pis,
        ..
    } = get_test_circuit_proof();
    let common = circuit_prover_data.common_data();

    let real_lookup_data = batch_stark_proof.proof.global_lookup_data.clone();
    batch_stark_proof.proof.global_lookup_data = real_lookup_data;
    batch_stark_proof.proof.commitments.permutation = None;

    // Build the recursive verification circuit
    let mut circuit_builder = setup_circuit_builder();

    let (verifier_inputs, _all_challenges) = get_verifier_inputs_and_challenges(
        &mut circuit_builder,
        &config,
        &params,
        &mut batch_stark_proof,
        common,
        &pis,
        None,
        &lookup_gadget,
    );

    match verifier_inputs {
        Err(VerificationError::InvalidProofShape(msg)) => {
            assert_eq!(msg, "Mismatch between lookup commitment and lookup data");
        }
        Err(_) => panic!("Expected InvalidProofShape"),
        Ok(_) => panic!("Expected error due to inconsistent lookup shape"),
    }
}

#[test]
#[should_panic(expected = "Expected cumulated values not sorted by auxiliary index")]
fn test_inconsistent_lookup_order_shape() {
    let TestCircuitProofData {
        mut batch_stark_proof,
        circuit_prover_data,
        lookup_gadget,
        config,
        params,
        pis,
        ..
    } = get_test_circuit_proof();
    let common = circuit_prover_data.common_data();

    let real_lookup_data = batch_stark_proof.proof.global_lookup_data.clone();
    let mut fake_global_lookup_data = real_lookup_data.clone();
    assert!(fake_global_lookup_data[3].len() > 1);
    fake_global_lookup_data[3].swap(0, 1);

    // Build the recursive verification circuit
    let mut circuit_builder = setup_circuit_builder();

    // First, only challenges use the fake lookup data.
    let (_verifier_inputs, all_challenges) = get_verifier_inputs_and_challenges(
        &mut circuit_builder,
        &config,
        &params,
        &mut batch_stark_proof,
        common,
        &pis,
        Some(&fake_global_lookup_data),
        &lookup_gadget,
    );

    match all_challenges {
        Err(GenerationError::InvalidProofShape(msg)) => {
            assert_eq!(msg, "Global lookups are inconsistent with lookups");
        }
        Err(_) => panic!("Expected InvalidProofShape"),
        Ok(_) => panic!("Expected error due to inconsistent lookup shape"),
    }

    // Second, only the verifier uses the fake lookup data.
    batch_stark_proof.proof.global_lookup_data = fake_global_lookup_data;

    let mut circuit_builder = setup_circuit_builder();
    let _ = get_verifier_inputs_and_challenges(
        &mut circuit_builder,
        &config,
        &params,
        &mut batch_stark_proof,
        common,
        &pis,
        Some(real_lookup_data.as_slice()),
        &lookup_gadget,
    );
}

#[test]
#[should_panic(expected = "Too many expected cumulated values provided")]
fn test_extra_global_lookup() {
    let TestCircuitProofData {
        mut batch_stark_proof,
        circuit_prover_data,
        lookup_gadget,
        config,
        params,
        pis,
        ..
    } = get_test_circuit_proof();
    let common = circuit_prover_data.common_data();

    let real_lookup_data = batch_stark_proof.proof.global_lookup_data.clone();
    let fake_lookup = LookupData {
        name: "FakeLookup".to_string(),
        aux_idx: 0,
        expected_cumulated: Challenge::ZERO,
    };
    let mut fake_global_lookup_data = real_lookup_data.clone();
    fake_global_lookup_data[0].push(fake_lookup);

    // Build the recursive verification circuit
    let mut circuit_builder = setup_circuit_builder();

    // First, only challenges use the fake lookup data with an extra global lookup.
    let (_verifier_inputs, all_challenges) = get_verifier_inputs_and_challenges(
        &mut circuit_builder,
        &config,
        &params,
        &mut batch_stark_proof,
        common,
        &pis,
        Some(&fake_global_lookup_data),
        &lookup_gadget,
    );

    match all_challenges {
        Err(GenerationError::InvalidProofShape(msg)) => {
            assert_eq!(msg, "Global lookups are inconsistent with lookups");
        }
        Err(_) => panic!("Expected InvalidProofShape"),
        Ok(_) => panic!("Expected error due to inconsistent lookup shape"),
    }

    // Second, only the verifier uses the fake lookup data.
    batch_stark_proof.proof.global_lookup_data = fake_global_lookup_data;

    let mut circuit_builder = setup_circuit_builder();
    let _ = get_verifier_inputs_and_challenges(
        &mut circuit_builder,
        &config,
        &params,
        &mut batch_stark_proof,
        common,
        &pis,
        Some(real_lookup_data.as_slice()),
        &lookup_gadget,
    );
}

#[test]
#[should_panic(expected = "Expected cumulated value missing")]
fn test_missing_global_lookup() {
    let TestCircuitProofData {
        mut batch_stark_proof,
        circuit_prover_data,
        lookup_gadget,
        config,
        params,
        pis,
        ..
    } = get_test_circuit_proof();
    let common = circuit_prover_data.common_data();

    let real_lookup_data = batch_stark_proof.proof.global_lookup_data.clone();
    let mut fake_global_lookup_data = real_lookup_data.clone();
    assert!(!fake_global_lookup_data[0].is_empty());
    fake_global_lookup_data[0].pop();

    // Build the recursive verification circuit
    let mut circuit_builder = setup_circuit_builder();

    // First, only challenges use the fake lookup data with a missing global lookup.
    let (_verifier_inputs, all_challenges) = get_verifier_inputs_and_challenges(
        &mut circuit_builder,
        &config,
        &params,
        &mut batch_stark_proof,
        common,
        &pis,
        Some(&fake_global_lookup_data),
        &lookup_gadget,
    );

    match all_challenges {
        Err(GenerationError::InvalidProofShape(msg)) => {
            assert_eq!(msg, "Global lookups are inconsistent with lookups");
        }
        Err(_) => panic!("Expected InvalidProofShape"),
        Ok(_) => panic!("Expected error due to inconsistent lookup shape"),
    }

    // Second, only the verifier uses the fake lookup data.
    batch_stark_proof.proof.global_lookup_data = fake_global_lookup_data;

    let mut circuit_builder = setup_circuit_builder();
    let (verifier_inputs, _all_challenges) = get_verifier_inputs_and_challenges(
        &mut circuit_builder,
        &config,
        &params,
        &mut batch_stark_proof,
        common,
        &pis,
        Some(real_lookup_data.as_slice()),
        &lookup_gadget,
    );

    match verifier_inputs {
        Err(VerificationError::InvalidProofShape(msg)) => {
            assert_eq!(msg, "Expected cumulated value missing");
        }
        Err(_) => panic!("Expected InvalidProofShape"),
        Ok(_) => panic!("Expected error due to inconsistent lookup shape"),
    }
}

struct TestCircuitProofData {
    batch_stark_proof: BatchStarkProof<MyConfig>,
    circuit_prover_data: CircuitProverData<MyConfig>,
    lookup_gadget: LogUpGadget,
    config: MyConfig,
    params: Parameters,
    pis: Vec<Vec<F>>,
    prover: BatchStarkProver<MyConfig>,
}

fn get_test_circuit_proof() -> TestCircuitProofData {
    let n = 10;

    // Get a circuit that computes arithmetic operations.
    let builder = get_circuit(n);

    let table_packing = TablePacking::new(1, 4, 4);

    let config_proving = get_proving_config();

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

    let init_a = 3;
    let init_b = 5;
    let init_x = 7;
    let expected_result = F::from_usize(repeated_arith(init_a, init_b, init_x, n));

    runner
        .set_public_inputs(&[
            F::from_usize(init_x),
            F::from_usize(init_a),
            F::from_usize(init_b),
            expected_result,
        ])
        .unwrap();

    let traces = runner.run().unwrap();

    // Create prover data for proving and verifying.
    let prover_data = ProverData::from_airs_and_degrees(&config_proving, &mut airs, &degrees);
    let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);

    let lookup_gadget = LogUpGadget::new();
    let prover = BatchStarkProver::new(config_proving).with_table_packing(table_packing);
    let batch_stark_proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();

    let (config, fri_verifier_params, pow_bits, log_height_max) = get_recursive_config_and_params();
    let params = Parameters {
        fri_verifier_params,
        pow_bits,
        log_height_max,
    };
    let pis = vec![vec![]; 4];

    TestCircuitProofData {
        batch_stark_proof,
        circuit_prover_data,
        lookup_gadget,
        config,
        params,
        pis,
        prover,
    }
}

// Returns the proving configuration for the initial circuit.
// Uses the default permutation to match the circuit's Fiat-Shamir challenger.
fn get_proving_config() -> MyConfig {
    let perm = default_babybear_poseidon2_16();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();

    let fri_params = create_test_fri_params(challenge_mmcs, 0);

    let pcs_proving = MyPcs::new(dft, val_mmcs, fri_params);
    let challenger_proving = Challenger::new(perm);
    MyConfig::new(pcs_proving, challenger_proving)
}

// Returns the configuration and FRI verifier params for recursive verification.
// Uses the default permutation to match the circuit's Fiat-Shamir challenger.
fn get_recursive_config_and_params() -> (MyConfig, FriVerifierParams, usize, usize) {
    let dft2 = Dft::default();
    let perm2 = default_babybear_poseidon2_16();
    let hash2 = MyHash::new(perm2.clone());
    let compress2 = MyCompress::new(perm2.clone());
    let val_mmcs2 = ValMmcs::new(hash2, compress2, 0);
    let challenge_mmcs2 = ChallengeMmcs::new(val_mmcs2.clone());
    let fri_params2 = create_test_fri_params(challenge_mmcs2, 0);
    let fri_verifier_params = FriVerifierParams::from(&fri_params2);
    let pow_bits = fri_params2.query_proof_of_work_bits;
    let log_height_max = fri_params2.log_final_poly_len + fri_params2.log_blowup;
    let pcs_verif = MyPcs::new(dft2, val_mmcs2, fri_params2);
    let challenger_verif = Challenger::new(perm2);
    (
        MyConfig::new(pcs_verif, challenger_verif),
        fri_verifier_params,
        pow_bits,
        log_height_max,
    )
}

type ResultVerifierInputsAndChallenges = (
    Result<
        BatchStarkVerifierInputsBuilder<MyConfig, MerkleCapTargets<F, DIGEST_ELEMS>, InnerFri>,
        VerificationError,
    >,
    Result<Vec<Challenge>, GenerationError>,
);

struct Parameters {
    fri_verifier_params: FriVerifierParams,
    pow_bits: usize,
    log_height_max: usize,
}

// Gets the verifier inputs and generates all necessary challenges for the recursive verification circuit.
#[allow(clippy::too_many_arguments)]
fn get_verifier_inputs_and_challenges(
    circuit_builder: &mut CircuitBuilder<Challenge>,
    config: &MyConfig,
    params: &Parameters,
    batch_stark_proof: &mut BatchStarkProof<MyConfig>,
    common: &CommonData<MyConfig>,
    pis: &[Vec<F>],
    optional_global_lookups: Option<&[Vec<LookupData<Challenge>>]>,
    lookup_gadget: &LogUpGadget,
) -> ResultVerifierInputsAndChallenges {
    // Extract proof components
    let rows = batch_stark_proof.rows;
    let packing = batch_stark_proof.table_packing;

    // Base field AIRs for native challenge generation
    let native_airs = vec![
        CircuitTablesAir::Witness(WitnessAir::<F, TRACE_D>::new(
            rows[PrimitiveTable::Witness],
            packing.witness_lanes(),
        )),
        CircuitTablesAir::Const(ConstAir::<F, TRACE_D>::new(rows[PrimitiveTable::Const])),
        CircuitTablesAir::Public(PublicAir::<F, TRACE_D>::new(
            rows[PrimitiveTable::Public],
            packing.public_lanes(),
        )),
        CircuitTablesAir::Alu(AluAir::<F, TRACE_D>::new(
            rows[PrimitiveTable::Alu],
            packing.alu_lanes(),
        )),
    ];

    // Attach verifier without manually building circuit_airs
    let verifier_inputs = verify_p3_batch_proof_circuit::<
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
        InnerFri,
        LogUpGadget,
        WIDTH,
        RATE,
        TRACE_D,
    >(
        config,
        circuit_builder,
        batch_stark_proof,
        &params.fri_verifier_params,
        common,
        lookup_gadget,
        Poseidon2Config::BabyBearD4Width16,
    )
    .map(|(inputs, _mmcs_op_ids)| inputs);

    // If provided, override the global lookups in the proof used for challenge generation
    if let Some(global_lookups) = optional_global_lookups {
        batch_stark_proof.proof.global_lookup_data = global_lookups.to_vec();
    }

    let batch_proof = &batch_stark_proof.proof;

    // Generate all the challenge values for batch proof (uses base field AIRs)
    let all_challenges = generate_batch_challenges(
        &native_airs,
        config,
        batch_proof,
        pis,
        Some(&[params.pow_bits, params.log_height_max]),
        common,
        lookup_gadget,
    );

    (verifier_inputs, all_challenges)
}

// Creates a circuit builder and builds a circuit that computes the following function:
// - y = a * x + b
// - repeated n times:
//   for i in 0..n {
//     y = a * y + b
//   }
fn get_circuit(n: usize) -> CircuitBuilder<F> {
    let mut builder = CircuitBuilder::<F>::new();

    let x = builder.public_input();
    let a = builder.public_input();
    let b = builder.public_input();
    let expected_result = builder.public_input();

    // y = a * x + b
    let mut y = builder.mul(a, x);
    y = builder.add(b, y);
    for _i in 0..n {
        y = builder.mul(a, y);
        y = builder.add(b, y);
    }

    builder.connect(y, expected_result);

    builder
}

/// Test Poseidon2 with input/output CTL lookups enabled.
/// This is a minimal test to verify that CTL lookups work correctly
/// with Poseidon2 operations, similar to how MMCS uses them.
#[test]
fn test_poseidon2_ctl_lookups() {
    let mut builder: CircuitBuilder<Challenge> = CircuitBuilder::new();
    let poseidon2_perm = default_babybear_poseidon2_16();
    let poseidon2_config = Poseidon2Config::BabyBearD4Width16;
    builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        poseidon2_perm,
    );

    // Create public inputs that will also serve as witnesses for the Poseidon2 inputs
    let input0 = builder.public_input();
    let input1 = builder.public_input();

    // Create a Poseidon2 operation with input CTL enabled for limbs 0 and 1
    let (_op_id, outputs) = builder
        .add_poseidon2_perm(Poseidon2PermCall {
            config: poseidon2_config,
            new_start: true,
            merkle_path: false,
            mmcs_bit: None,
            inputs: [Some(input0), Some(input1), None, None],
            out_ctl: [true, true], // Enable output CTL
            return_all_outputs: false,
            mmcs_index_sum: None,
        })
        .unwrap();

    // The outputs should be witnesses that can be used
    let output0 = outputs[0].unwrap();
    let output1 = outputs[1].unwrap();

    // Create another Poseidon2 operation that uses these outputs as inputs
    let (_op_id2, _) = builder
        .add_poseidon2_perm(Poseidon2PermCall {
            config: poseidon2_config,
            new_start: true,
            merkle_path: false,
            mmcs_bit: None,
            inputs: [Some(output0), Some(output1), None, None],
            out_ctl: [false, false],
            return_all_outputs: false,
            mmcs_index_sum: None,
        })
        .unwrap();

    let table_packing = TablePacking::new(1, 1, 4);
    let config_proving = get_proving_config();

    let circuit = builder.build().unwrap();

    let (airs_degrees, preprocessed_columns) = get_airs_and_degrees_with_prep::<MyConfig, _, 4>(
        &circuit,
        table_packing,
        Some(&[NonPrimitiveConfig::Poseidon2(poseidon2_config)]),
        ConstraintProfile::Standard,
    )
    .unwrap();

    let (mut airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();

    // Set the public inputs
    let input_val0 = Challenge::from_u32(12345);
    let input_val1 = Challenge::from_u32(67890);
    runner.set_public_inputs(&[input_val0, input_val1]).unwrap();

    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&config_proving, &mut airs, &degrees);
    let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);

    let common = circuit_prover_data.common_data();

    let mut prover = BatchStarkProver::new(config_proving).with_table_packing(table_packing);
    prover.register_poseidon2_table(poseidon2_config);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();

    prover
        .verify_all_tables(&proof, common)
        .expect("Poseidon2 CTL lookup verification should succeed");
}

/// Test Poseidon2 with chained operations and CTL lookups.
/// This tests a chain of Poseidon2 operations where:
/// - First operation: CTL inputs from witness
/// - Middle operation: chained from previous (no explicit inputs)
/// - Last operation: CTL outputs to witness
#[test]
fn test_poseidon2_chained_ctl_lookups() {
    use p3_circuit::Poseidon2PermOps;
    use p3_circuit::ops::Poseidon2PermCall;
    use p3_poseidon2_circuit_air::BabyBearD4Width16;

    let mut builder: CircuitBuilder<Challenge> = CircuitBuilder::new();
    let poseidon2_perm = default_babybear_poseidon2_16();
    let poseidon2_config = Poseidon2Config::BabyBearD4Width16;
    builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        poseidon2_perm,
    );

    // Create public inputs for the first operation's inputs
    let input0 = builder.public_input();
    let input1 = builder.public_input();

    // First Poseidon2 operation: new_start=true, inputs from witness
    let (_op_id, _outputs) = builder
        .add_poseidon2_perm(Poseidon2PermCall {
            config: poseidon2_config,
            new_start: true,
            merkle_path: false, // Sponge mode
            mmcs_bit: None,
            inputs: [Some(input0), Some(input1), None, None],
            out_ctl: [false, false], // Not exposing outputs yet
            return_all_outputs: false,
            mmcs_index_sum: None,
        })
        .unwrap();

    // Second Poseidon2 operation: new_start=false, chained from first
    let (_op_id2, _outputs2) = builder
        .add_poseidon2_perm(Poseidon2PermCall {
            config: poseidon2_config,
            new_start: false, // Chained
            merkle_path: false,
            mmcs_bit: None,
            inputs: [None, None, None, None], // Chained from previous output
            out_ctl: [false, false],
            return_all_outputs: false,
            mmcs_index_sum: None,
        })
        .unwrap();

    // Third Poseidon2 operation: new_start=false, chained, with output CTL
    let (_op_id3, outputs3) = builder
        .add_poseidon2_perm(Poseidon2PermCall {
            config: poseidon2_config,
            new_start: false,
            merkle_path: false,
            mmcs_bit: None,
            inputs: [None, None, None, None],
            out_ctl: [true, true], // Expose outputs via CTL
            return_all_outputs: false,
            mmcs_index_sum: None,
        })
        .unwrap();

    // Fourth operation: new_start=true to signal end of previous chain
    // This operation uses the exposed outputs from op3 as inputs
    let (_op_id4, _) = builder
        .add_poseidon2_perm(Poseidon2PermCall {
            config: poseidon2_config,
            new_start: true,
            merkle_path: false,
            mmcs_bit: None,
            inputs: [outputs3[0], outputs3[1], None, None],
            out_ctl: [false, false],
            return_all_outputs: false,
            mmcs_index_sum: None,
        })
        .unwrap();

    let table_packing = TablePacking::new(1, 1, 4);
    let config_proving = get_proving_config();

    let circuit = builder.build().unwrap();

    let (airs_degrees, preprocessed_columns) = get_airs_and_degrees_with_prep::<MyConfig, _, 4>(
        &circuit,
        table_packing,
        Some(&[NonPrimitiveConfig::Poseidon2(poseidon2_config)]),
        ConstraintProfile::Standard,
    )
    .unwrap();

    let (mut airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();

    // Set the public inputs
    let input_val0 = Challenge::from_u32(111);
    let input_val1 = Challenge::from_u32(222);
    runner.set_public_inputs(&[input_val0, input_val1]).unwrap();

    let traces = runner.run().unwrap();

    let prover_data = ProverData::from_airs_and_degrees(&config_proving, &mut airs, &degrees);
    let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);

    let common = circuit_prover_data.common_data();

    let mut prover = BatchStarkProver::new(config_proving).with_table_packing(table_packing);
    prover.register_poseidon2_table(poseidon2_config);

    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();

    prover
        .verify_all_tables(&proof, common)
        .expect("Chained Poseidon2 CTL lookup verification should succeed");
}
