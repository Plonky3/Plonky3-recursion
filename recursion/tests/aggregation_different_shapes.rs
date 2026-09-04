//! Integration test: 2-to-1 aggregation of proofs with different FRI shapes.
//! Left: Uni-Stark (Fibonacci) with log_blowup=2, max_arity_log=3.
//! Right: Batch-Stark (dummy circuit) with log_blowup=3, max_arity_log=4.

mod common;

use p3_batch_stark::ProverData;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
use p3_circuit_prover::{BatchStarkProver, CircuitProverData, ConstraintProfile, TablePacking};
use p3_lookup::logup::LogUpGadget;
use p3_poseidon2_circuit_air::KoalaBearD4Width16;
use p3_recursion::pcs::fri::{FriVerifierParams, InputProofTargets, MerkleCapTargets, RecValMmcs};
use p3_recursion::pcs::{restore_fri_query_paths, set_fri_mmcs_private_data};
use p3_recursion::verifier::{verify_p3_batch_proof_circuit, verify_p3_uni_proof_circuit};
use p3_recursion::{
    OpeningTranscript, Poseidon2Config, StarkVerifierInputsBuilder, VerificationError,
    observe_opened_values, replay_batch_layer_transcript, replay_uni_stark_transcript,
};
use p3_test_utils::koala_bear_params::*;
use p3_uni_stark::{prove, verify};

use crate::common::InnerFriGeneric;

type InnerFri = InnerFriGeneric<MyConfig, MyHash, MyCompress, DIGEST_ELEMS>;

const TRACE_D: usize = 1;

fn fri_verifier_params(log_blowup: usize) -> FriVerifierParams {
    let num_queries = (100 - 16) / log_blowup;
    FriVerifierParams::with_mmcs(
        log_blowup,
        0,
        0,
        16,
        num_queries,
        Poseidon2Config::KOALA_BEAR_D4_W16,
    )
}

#[test]
fn test_aggregation_with_different_shapes() -> Result<(), VerificationError> {
    let perm = default_koalabear_poseidon2_16();

    // Uni-Stark (Fibonacci) with log_blowup=2, max_arity_log=3.
    let left_config = make_test_config_with_fri(&perm, 2, 3);
    // Batch-Stark (dummy circuit) with log_blowup=3, max_arity_log=4.
    let right_config = make_test_config_with_fri(&perm, 3, 4);
    let right_config_verif = right_config.clone();

    // Generate the Fibonacci trace.
    let n = 1 << 3;
    let x = 21u64;
    let pis = vec![F::ZERO, F::ONE, F::from_u64(x)];
    let air = FibonacciAir {};
    let trace = generate_trace_rows::<F>(0, 1, n);

    // Prove the Fibonacci trace with the Uni-Stark.
    let uni_proof = prove(&left_config, &air, trace, &pis);
    assert!(verify(&left_config, &air, &uni_proof, &pis).is_ok());

    // Prove the dummy circuit with the Batch-Stark.
    let mut builder = CircuitBuilder::new();
    let c = builder.alloc_const(F::from_u32(42), "dummy");
    let expected = builder.alloc_public_input("expected");
    builder.connect(c, expected);
    let circuit = builder.build().unwrap();
    let table_packing = TablePacking::new(1, 1).with_fri_params(0, 3);
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<MyConfig, F, 1>(
            &circuit,
            &table_packing,
            &[],
            &[],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&[F::from_u32(42)]).unwrap();
    let traces = runner.run().unwrap();
    let prover_data = ProverData::from_airs_and_degrees(&right_config, &airs, &degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let prover = BatchStarkProver::new(right_config).with_table_packing(table_packing);
    let batch_stark_proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    let common = circuit_prover_data.common_data();
    prover.verify_all_tables::<F>(&batch_stark_proof).unwrap();

    // Build the verification circuit.
    let mut circuit_builder = CircuitBuilder::new();
    circuit_builder.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, KoalaBearD4Width16>,
        perm.clone(),
    );
    circuit_builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    // Build the verifier inputs for the Uni-Stark.
    let left_fri_params = fri_verifier_params(2);
    let right_fri_params = fri_verifier_params(3);

    let left_verifier_inputs = StarkVerifierInputsBuilder::<
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InnerFri,
    >::allocate(&mut circuit_builder, &uni_proof, None, pis.len());

    // Verify the Uni-Stark proof.
    let left_op_ids = verify_p3_uni_proof_circuit::<
        FibonacciAir,
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
        InnerFri,
        _,
        WIDTH,
        RATE,
    >(
        &left_config,
        &air,
        &mut circuit_builder,
        &left_verifier_inputs.proof_targets,
        &left_verifier_inputs.air_public_targets,
        &None,
        &left_fri_params,
        Poseidon2Config::KOALA_BEAR_D4_W16,
    )?;

    // Build the verifier inputs for the Batch-Stark.
    let lookup_gadget = LogUpGadget::new();
    let batch_proof = &batch_stark_proof.proof;
    let right_pis: Vec<Vec<F>> = vec![vec![]; 5];

    // Verify the Batch-Stark proof.
    let (right_verifier_inputs, right_op_ids) = verify_p3_batch_proof_circuit::<
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
        InnerFri,
        LogUpGadget,
        Poseidon2Config,
        WIDTH,
        RATE,
        TRACE_D,
    >(
        &right_config_verif,
        &mut circuit_builder,
        &batch_stark_proof,
        &right_fri_params,
        common,
        &lookup_gadget,
        Poseidon2Config::KOALA_BEAR_D4_W16,
        &[],
    )?;

    // Build the verification circuit.
    let verification_circuit = circuit_builder.build().unwrap();
    let mut runner = verification_circuit.runner();

    // Pack the public and private inputs.
    let (mut public_inputs, mut private_inputs) =
        left_verifier_inputs.pack_values(&pis, &uni_proof, &None);
    let (right_public_inputs, right_private_inputs) =
        right_verifier_inputs.pack_values(&right_pis, batch_proof, common);
    public_inputs.extend(right_public_inputs);
    private_inputs.extend(right_private_inputs);
    runner
        .set_public_inputs(&public_inputs)
        .map_err(VerificationError::Circuit)?;
    runner
        .set_private_inputs(&private_inputs)
        .map_err(VerificationError::Circuit)?;

    // Set the MMCS private data for the Uni-Stark. Each proof shares one pruned Merkle
    // multiproof across its queries, so the per-query chains the circuit walks come from
    // replaying that proof's own transcript — under its own FRI shape.
    let (left_val_mmcs, left_fri) = test_fri_instance_with_fri(&perm, 2, 3);
    let OpeningTranscript {
        mut challenger,
        commitments_with_opening_points,
    } = replay_uni_stark_transcript(&left_config, &air, &uni_proof, &pis, None)
        .map_err(|e| VerificationError::InvalidProofShape(e.to_string()))?;
    observe_opened_values::<MyConfig>(&mut challenger, &commitments_with_opening_points);
    let left_query_paths = restore_fri_query_paths(
        &left_fri,
        &left_val_mmcs,
        &left_val_mmcs,
        &uni_proof.opening_proof,
        &mut challenger,
        &commitments_with_opening_points,
    )
    .map_err(|e| VerificationError::InvalidProofShape(format!("{e:?}")))?;
    set_fri_mmcs_private_data::<F, Challenge, DIGEST_ELEMS>(
        &mut runner,
        &left_op_ids,
        &left_query_paths,
        Poseidon2Config::KOALA_BEAR_D4_W16,
    )
    .map_err(|e| VerificationError::InvalidProofShape(e.to_string()))?;

    // Set the MMCS private data for the Batch-Stark.
    let (right_val_mmcs, right_fri) = test_fri_instance_with_fri(&perm, 3, 4);
    let OpeningTranscript {
        mut challenger,
        commitments_with_opening_points,
    } = replay_batch_layer_transcript::<MyConfig, TRACE_D>(
        &right_config_verif,
        &batch_stark_proof,
        common,
        &[],
    )?;
    observe_opened_values::<MyConfig>(&mut challenger, &commitments_with_opening_points);
    let right_query_paths = restore_fri_query_paths(
        &right_fri,
        &right_val_mmcs,
        &right_val_mmcs,
        &batch_stark_proof.proof.opening_proof,
        &mut challenger,
        &commitments_with_opening_points,
    )
    .map_err(|e| VerificationError::InvalidProofShape(format!("{e:?}")))?;
    set_fri_mmcs_private_data::<F, Challenge, DIGEST_ELEMS>(
        &mut runner,
        &right_op_ids,
        &right_query_paths,
        Poseidon2Config::KOALA_BEAR_D4_W16,
    )
    .map_err(|e| VerificationError::InvalidProofShape(e.to_string()))?;

    // Run the verification circuit.
    let _traces = runner.run().map_err(VerificationError::Circuit)?;
    Ok(())
}
