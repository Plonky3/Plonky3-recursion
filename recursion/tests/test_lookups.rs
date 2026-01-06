mod common;

use p3_batch_stark::CommonData;
use p3_circuit::CircuitBuilder;
use p3_circuit_prover::air::{AddAir, ConstAir, MulAir, PublicAir, WitnessAir};
use p3_circuit_prover::batch_stark_prover::PrimitiveTable;
use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
use p3_circuit_prover::{BatchStarkProof, BatchStarkProver, TablePacking};
use p3_field::PrimeCharacteristicRing;
use p3_fri::create_test_fri_params;
use p3_lookup::logup::LogUpGadget;
use p3_lookup::lookup_traits::LookupData;
use p3_recursion::generation::generate_batch_challenges;
use p3_recursion::pcs::fri::{FriVerifierParams, HashTargets, InputProofTargets, RecValMmcs};
use p3_recursion::verifier::{CircuitTablesAir, verify_p3_recursion_proof_circuit};
use p3_recursion::{BatchStarkVerifierInputsBuilder, GenerationError, VerificationError};
use rand::SeedableRng;
use rand::rngs::SmallRng;
const TRACE_D: usize = 1; // Proof traces are in base field

use crate::common::baby_bear_params::*;

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
    let n = 10;

    let builder = get_circuit(n);

    let table_packing = TablePacking::new(1, 4, 6);

    let config_proving = get_proving_config();

    let circuit = builder.build().unwrap();
    let (airs_degrees, witness_multiplicities) =
        get_airs_and_degrees_with_prep::<_, _, 1>(&config_proving, &circuit, table_packing, None)
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

    // Create common data for proving and verifying.
    let common = CommonData::from_airs_and_degrees(&config_proving, &mut airs, &degrees);

    let prover = BatchStarkProver::new(config_proving).with_table_packing(table_packing);

    let lookup_gadget = LogUpGadget::new();
    let batch_stark_proof = prover
        .prove_all_tables(&traces, &common, witness_multiplicities, &lookup_gadget)
        .unwrap();

    prover
        .verify_all_tables(&batch_stark_proof, &common, &lookup_gadget)
        .unwrap();

    // Now verify the batch STARK proof recursively
    let (config, fri_verifier_params, pow_bits, log_height_max) = get_recursive_config_and_params();

    // Build the recursive verification circuit
    let mut circuit_builder = CircuitBuilder::new();

    // Public values (empty for all 5 circuit tables, using base field)
    let pis: Vec<Vec<F>> = vec![vec![]; 5];

    // Attach verifier without manually building circuit_airs
    let params = Parameters {
        fri_verifier_params,
        pow_bits,
        log_height_max,
    };
    let (verifier_inputs, all_challenges) = get_verifier_inputs_and_challenges(
        &mut circuit_builder,
        &config,
        &params,
        &batch_stark_proof,
        &common,
        &pis,
        &lookup_gadget,
    );

    // Build the circuit
    let verification_circuit = circuit_builder.build().unwrap();
    let expected_public_input_len = verification_circuit.public_flat_len;

    // Pack values using the builder
    let batch_proof = &batch_stark_proof.proof;
    let public_inputs =
        verifier_inputs
            .unwrap()
            .pack_values(&pis, batch_proof, &common, &all_challenges.unwrap());

    assert_eq!(public_inputs.len(), expected_public_input_len);
    assert!(!public_inputs.is_empty());

    // Actually run the circuit to ensure constraints are satisfiable
    let mut runner = verification_circuit.runner();
    runner.set_public_inputs(&public_inputs).unwrap();
    let _traces = runner.run().unwrap();
}

#[test]
#[should_panic(expected = "WitnessConflict")]
fn test_wrong_multiplicities() {
    let n = 10;

    // Get a circuit that computes arithmetic operations.
    let builder = get_circuit(n);

    let table_packing = TablePacking::new(1, 4, 6);

    let config_proving = get_proving_config();

    let circuit = builder.build().unwrap();
    let (airs_degrees, mut witness_multiplicities) =
        get_airs_and_degrees_with_prep::<_, _, 1>(&config_proving, &circuit, table_packing, None)
            .unwrap();

    // Introduce an error in the witness multiplicities.
    witness_multiplicities[PrimitiveTable::Add as usize] += F::ONE;
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

    // Create common data for proving and verifying.
    let common = CommonData::from_airs_and_degrees(&config_proving, &mut airs, &degrees);

    let prover = BatchStarkProver::new(config_proving).with_table_packing(table_packing);

    // Prove the circuit.
    let lookup_gadget = LogUpGadget::new();
    let batch_stark_proof = prover
        .prove_all_tables(&traces, &common, witness_multiplicities, &lookup_gadget)
        .unwrap();

    // Now verify the batch STARK proof recursively
    let (config, fri_verifier_params, pow_bits, log_height_max) = get_recursive_config_and_params();

    // Build the recursive verification circuit
    let mut circuit_builder = CircuitBuilder::new();

    // Public values (empty for all 5 circuit tables, using base field)
    let pis: Vec<Vec<F>> = vec![vec![]; 5];

    // Attach verifier without manually building circuit_airs
    let params = Parameters {
        fri_verifier_params,
        pow_bits,
        log_height_max,
    };
    let (verifier_inputs, all_challenges) = get_verifier_inputs_and_challenges(
        &mut circuit_builder,
        &config,
        &params,
        &batch_stark_proof,
        &common,
        &pis,
        &lookup_gadget,
    );

    // Build the circuit
    let verification_circuit = circuit_builder.build().unwrap();
    let expected_public_input_len = verification_circuit.public_flat_len;

    // Pack values using the builder
    let batch_proof = &batch_stark_proof.proof;
    let public_inputs =
        verifier_inputs
            .unwrap()
            .pack_values(&pis, batch_proof, &common, &all_challenges.unwrap());

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
    let n = 10;

    // Get a circuit that computes arithmetic operations.
    let builder = get_circuit(n);

    let table_packing = TablePacking::new(1, 4, 6);

    let config_proving = get_proving_config();

    let circuit = builder.build().unwrap();
    let (airs_degrees, witness_multiplicities) =
        get_airs_and_degrees_with_prep::<_, _, 1>(&config_proving, &circuit, table_packing, None)
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

    // Create common data for proving and verifying.
    let common = CommonData::from_airs_and_degrees(&config_proving, &mut airs, &degrees);

    let prover = BatchStarkProver::new(config_proving).with_table_packing(table_packing);

    // Prove the circuit with wrong witness multiplicities.
    let lookup_gadget = LogUpGadget::new();
    let mut batch_stark_proof = prover
        .prove_all_tables(&traces, &common, witness_multiplicities, &lookup_gadget)
        .unwrap();

    // Now verify the batch STARK proof recursively
    let (config, fri_verifier_params, pow_bits, log_height_max) = get_recursive_config_and_params();

    // Introduce an error in the global expected cumulated values for the first lookup.
    // This leads to the sum of all expected cumulated values being off by 1,
    // which causes a WitnessConflict during recursive verification.
    batch_stark_proof.proof.global_lookup_data[0][0].expected_cumulated += F::ONE;
    // Introduce an error in the expected cumulated values for the first lookup.
    assert!(batch_stark_proof.proof.global_lookup_data.len() == 5);

    // Build the recursive verification circuit
    let mut circuit_builder = CircuitBuilder::new();

    // Public values (empty for all 5 circuit tables, using base field)
    let pis: Vec<Vec<F>> = vec![vec![]; 5];

    // Attach verifier without manually building circuit_airs
    let params = Parameters {
        fri_verifier_params,
        pow_bits,
        log_height_max,
    };
    let (verifier_inputs, all_challenges) = get_verifier_inputs_and_challenges(
        &mut circuit_builder,
        &config,
        &params,
        &batch_stark_proof,
        &common,
        &pis,
        &lookup_gadget,
    );

    // Build the circuit
    let verification_circuit = circuit_builder.build().unwrap();
    let expected_public_input_len = verification_circuit.public_flat_len;

    // Pack values using the builder
    let public_inputs = verifier_inputs.unwrap().pack_values(
        &pis,
        &batch_stark_proof.proof,
        &common,
        &all_challenges.unwrap(),
    );

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
fn test_inconsistent_lookup_shape() {
    let n = 10;

    // Get a circuit that computes arithmetic operations.
    let builder = get_circuit(n);

    let table_packing = TablePacking::new(1, 4, 6);

    let config_proving = get_proving_config();

    let circuit = builder.build().unwrap();
    let (airs_degrees, witness_multiplicities) =
        get_airs_and_degrees_with_prep::<_, _, 1>(&config_proving, &circuit, table_packing, None)
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

    // Create common data for proving and verifying.
    let common = CommonData::from_airs_and_degrees(&config_proving, &mut airs, &degrees);

    let prover = BatchStarkProver::new(config_proving).with_table_packing(table_packing);

    // Prove the circuit with wrong witness multiplicities.
    let lookup_gadget = LogUpGadget::new();
    let mut batch_stark_proof = prover
        .prove_all_tables(&traces, &common, witness_multiplicities, &lookup_gadget)
        .unwrap();

    // Now verify the batch STARK proof recursively
    let (config, fri_verifier_params, pow_bits, log_height_max) = get_recursive_config_and_params();

    // Public values (empty for all 5 circuit tables, using base field)
    let pis: Vec<Vec<F>> = vec![vec![]; 5];

    let real_lookup_data = batch_stark_proof.proof.global_lookup_data.clone();
    // First, modify the first global lookup data's name.
    assert!(batch_stark_proof.proof.global_lookup_data.len() == 5);
    batch_stark_proof.proof.global_lookup_data[0][0].name = "ModifiedLookup".to_string();

    // Build the recursive verification circuit
    let mut circuit_builder = CircuitBuilder::new();

    // Attach verifier without manually building circuit_airs. Generation fails because of the fake lookup data.
    let params = Parameters {
        fri_verifier_params,
        pow_bits,
        log_height_max,
    };
    let (verifier_inputs, all_challenges) = get_verifier_inputs_and_challenges(
        &mut circuit_builder,
        &config,
        &params,
        &batch_stark_proof,
        &common,
        &pis,
        &lookup_gadget,
    );

    match (verifier_inputs, all_challenges) {
        (Err(v_e), Err(g_e)) => {
            match v_e {
                VerificationError::InvalidProofShape(msg) => {
                    assert_eq!(msg, "Global lookups are inconsistent with lookups");
                }
                _ => panic!("Expected InvalidProofShape"),
            }
            match g_e {
                GenerationError::InvalidProofShape(msg) => {
                    assert_eq!(msg, "Global lookups are inconsistent with lookups");
                }
                _ => panic!("Expected InvalidProofShape"),
            }
        }
        _ => panic!("Expected error due to inconsistent lookup shape"),
    }

    // Second, introduce an extra lookup data entry to make the lookup data inconsistent.
    let fake_lookup = LookupData {
        name: "FakeLookup".to_string(),
        aux_idx: 0,
        expected_cumulated: Challenge::ZERO,
    };
    batch_stark_proof.proof.global_lookup_data = real_lookup_data.clone();
    batch_stark_proof.proof.global_lookup_data[0].push(fake_lookup);

    // Build the recursive verification circuit
    let mut circuit_builder = CircuitBuilder::new();

    // Attach verifier without manually building circuit_airs. Generation fails because of the fake lookup data.
    let params = Parameters {
        fri_verifier_params,
        pow_bits,
        log_height_max,
    };
    let (verifier_inputs, all_challenges) = get_verifier_inputs_and_challenges(
        &mut circuit_builder,
        &config,
        &params,
        &batch_stark_proof,
        &common,
        &pis,
        &lookup_gadget,
    );

    match (verifier_inputs, all_challenges) {
        (Err(v_e), Err(g_e)) => {
            match v_e {
                VerificationError::InvalidProofShape(msg) => {
                    assert_eq!(msg, "Global lookups are inconsistent with lookups");
                }
                _ => panic!("Expected InvalidProofShape"),
            }
            match g_e {
                GenerationError::InvalidProofShape(msg) => {
                    assert_eq!(msg, "Global lookups are inconsistent with lookups");
                }
                _ => panic!("Expected InvalidProofShape"),
            }
        }
        _ => panic!("Expected error due to inconsistent lookup shape"),
    }

    // Third, provide an empty lookup commitment.
    batch_stark_proof.proof.global_lookup_data = real_lookup_data;
    batch_stark_proof.proof.commitments.permutation = None;

    // Build the recursive verification circuit
    let mut circuit_builder = CircuitBuilder::new();

    let params = Parameters {
        fri_verifier_params,
        pow_bits,
        log_height_max,
    };
    // Attach verifier without manually building circuit_airs. Generation fails because of the fake lookup data.
    let (verifier_inputs, _all_challenges) = get_verifier_inputs_and_challenges(
        &mut circuit_builder,
        &config,
        &params,
        &batch_stark_proof,
        &common,
        &pis,
        &lookup_gadget,
    );

    match verifier_inputs {
        Err(v_e) => match v_e {
            VerificationError::InvalidProofShape(msg) => {
                assert_eq!(msg, "Mismatch between lookup commitment and lookup data");
            }
            _ => panic!("Expected InvalidProofShape"),
        },
        _ => panic!("Expected error due to inconsistent lookup shape"),
    }
}

// Returns the proving configration for the initial circuit.
fn get_proving_config() -> MyConfig {
    // Use a seeded RNG for deterministic permutations
    let mut rng = SmallRng::seed_from_u64(2026);
    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();

    // Create test FRI params with log_final_poly_len = 0
    let fri_params = create_test_fri_params(challenge_mmcs, 0);

    // Create config for proving
    let pcs_proving = MyPcs::new(dft, val_mmcs, fri_params);
    let challenger_proving = Challenger::new(perm);
    MyConfig::new(pcs_proving, challenger_proving)
}

// Returns the configuration and FRI verifier params for recursive verification.
fn get_recursive_config_and_params() -> (MyConfig, FriVerifierParams, usize, usize) {
    // Now verify the batch STARK proof recursively
    let dft2 = Dft::default();
    let mut rng2 = SmallRng::seed_from_u64(2026);
    let perm2 = Perm::new_from_rng_128(&mut rng2);
    let hash2 = MyHash::new(perm2.clone());
    let compress2 = MyCompress::new(perm2.clone());
    let val_mmcs2 = ValMmcs::new(hash2, compress2);
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
        BatchStarkVerifierInputsBuilder<MyConfig, HashTargets<F, DIGEST_ELEMS>, InnerFri>,
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
fn get_verifier_inputs_and_challenges(
    circuit_builder: &mut CircuitBuilder<Challenge>,
    config: &MyConfig,
    params: &Parameters,
    batch_stark_proof: &BatchStarkProof<MyConfig>,
    common: &CommonData<MyConfig>,
    pis: &[Vec<F>],
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
        CircuitTablesAir::Public(PublicAir::<F, TRACE_D>::new(rows[PrimitiveTable::Public])),
        CircuitTablesAir::Add(AddAir::<F, TRACE_D>::new(
            rows[PrimitiveTable::Add],
            packing.add_lanes(),
        )),
        CircuitTablesAir::Mul(MulAir::<F, TRACE_D>::new(
            rows[PrimitiveTable::Mul],
            packing.mul_lanes(),
        )),
    ];

    // Attach verifier without manually building circuit_airs
    let verifier_inputs = verify_p3_recursion_proof_circuit::<
        MyConfig,
        HashTargets<F, DIGEST_ELEMS>,
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
        InnerFri,
        LogUpGadget,
        RATE,
        TRACE_D,
    >(
        config,
        circuit_builder,
        batch_stark_proof,
        &params.fri_verifier_params,
        common,
        lookup_gadget,
    );

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

    let x = builder.add_public_input();
    let a = builder.add_public_input();
    let b = builder.add_public_input();
    let expected_result = builder.add_public_input();

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
