//! Test for recursive STARK verification with a multiplication AIR.

mod common;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_matrix::Matrix;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::pcs::fri::{FriVerifierParams, MerkleCapTargets};
use p3_recursion::pcs::{restore_fri_query_paths, set_fri_mmcs_private_data};
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::{
    OpeningTranscript, Poseidon2Config, VerificationError, observe_opened_values,
    replay_uni_stark_transcript, verify_p3_uni_proof_circuit,
};
use p3_test_utils::baby_bear_params::*;
use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use p3_util::log2_ceil_usize;

use crate::common::{InnerFriGeneric, LocalOnlyMulAir, MulAir};

type InnerFri = InnerFriGeneric<MyConfig, MyHash, MyCompress, DIGEST_ELEMS>;

#[test]
fn test_mul_verifier_circuit() -> Result<(), VerificationError> {
    let n = 1 << 3;

    let scalars = test_fri_scalars();
    let fri_verifier_params = FriVerifierParams::with_mmcs(
        scalars.log_blowup,
        scalars.log_final_poly_len,
        scalars.max_log_arity,
        scalars.commit_pow_bits,
        scalars.query_pow_bits,
        scalars.num_queries,
        Poseidon2Config::BABY_BEAR_D4_W16,
    );
    let config = make_test_config();
    let (val_mmcs, fri_params) = test_fri_instance();
    // Same default permutation make_test_config uses, for the recursive verifier circuit.
    let perm = default_babybear_poseidon2_16();
    let pis = vec![];

    // Create AIR and generate valid trace
    let air: MulAir = MulAir { degree: 2, rows: n };
    let (trace, _) = air.random_valid_trace(true);

    // Setup preprocessed data
    let (preprocessed_prover_data, preprocessed_vk) =
        setup_preprocessed(&config, &air, log2_ceil_usize(trace.height()))
            .unwrap()
            .unzip();
    // Generate and verify proof
    let mut proof = prove_with_preprocessed(
        &config,
        &air,
        trace,
        &pis,
        preprocessed_prover_data.as_ref(),
    )
    .unwrap();
    assert!(
        verify_with_preprocessed(&config, &air, &proof, &pis, preprocessed_vk.as_ref()).is_ok()
    );
    let replay = replay_uni_stark_transcript(
        &config,
        &air,
        &proof,
        &pis,
        preprocessed_vk.as_ref().map(|vk| &vk.commitment),
    )
    .unwrap();
    let pre_round = replay.commitments_with_opening_points.last().unwrap();
    assert_eq!(pre_round.1.len(), 1);
    assert_eq!(pre_round.1[0].1.len(), 2);

    // The next-row-using control must reject a missing required opening. This
    // target check occurs after input allocation; Stage5D preflight is separate.
    let required_next = proof
        .opened_values
        .preprocessed
        .as_mut()
        .expect("preprocessed openings")
        .next
        .take();
    proof
        .opened_values
        .preprocessed
        .as_mut()
        .expect("preprocessed openings")
        .next = None;
    let mut shape_builder = CircuitBuilder::new();
    shape_builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    shape_builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
    let shape_inputs = StarkVerifierInputsBuilder::<
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InnerFri,
    >::allocate(
        &mut shape_builder,
        &proof,
        preprocessed_vk.as_ref().map(|vk| &vk.commitment),
        pis.len(),
    );
    let missing = verify_p3_uni_proof_circuit::<_, _, _, _, _, _, WIDTH, RATE>(
        &config,
        &air,
        &mut shape_builder,
        &shape_inputs.proof_targets,
        &shape_inputs.air_public_targets,
        &shape_inputs.preprocessed_commit,
        &fri_verifier_params,
        Poseidon2Config::BABY_BEAR_D4_W16,
    );
    assert!(matches!(
        missing,
        Err(VerificationError::InvalidProofShape(message))
            if message.contains("preprocessed") && message.contains("width")
    ));
    proof
        .opened_values
        .preprocessed
        .as_mut()
        .expect("preprocessed openings")
        .next = required_next;

    let mut circuit_builder = CircuitBuilder::new();
    circuit_builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        perm,
    );
    circuit_builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    // Allocate all targets
    let verifier_inputs = StarkVerifierInputsBuilder::<
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InnerFri,
    >::allocate(
        &mut circuit_builder,
        &proof,
        preprocessed_vk.as_ref().map(|vk| &vk.commitment),
        pis.len(),
    );

    // Add the verification circuit to the builder
    let mmcs_op_ids = verify_p3_uni_proof_circuit::<_, _, _, _, _, _, WIDTH, RATE>(
        &config,
        &air,
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &verifier_inputs.preprocessed_commit,
        &fri_verifier_params,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )?;

    // Build the circuit
    let circuit = circuit_builder.build()?;

    let mut runner = circuit.runner();

    // Pack values using the same builder
    let (public_inputs, private_inputs) =
        verifier_inputs.pack_values(&pis, &proof, &preprocessed_vk.map(|vk| vk.commitment));

    runner
        .set_public_inputs(&public_inputs)
        .map_err(VerificationError::Circuit)?;
    runner
        .set_private_inputs(&private_inputs)
        .map_err(VerificationError::Circuit)?;

    let OpeningTranscript {
        mut challenger,
        commitments_with_opening_points,
    } = replay;
    observe_opened_values::<MyConfig>(
        &mut challenger,
        &commitments_with_opening_points,
        fri_params.batch_proof_of_work_bits,
    );
    let claims: Vec<_> = commitments_with_opening_points
        .iter()
        .cloned()
        .map(Into::into)
        .collect();
    let query_paths = restore_fri_query_paths(
        &fri_params,
        &val_mmcs,
        &val_mmcs,
        &proof.opening_proof,
        &mut challenger,
        &claims,
    )
    .map_err(|error| VerificationError::InvalidProofShape(format!("{error:?}")))?;
    set_fri_mmcs_private_data::<F, Challenge, DIGEST_ELEMS>(
        &mut runner,
        &mmcs_op_ids,
        &query_paths,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
    .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;

    let _traces = runner.run().map_err(VerificationError::Circuit)?;

    Ok(())
}

#[test]
fn test_local_only_mul_verifier_circuit_uses_one_preprocessed_point()
-> Result<(), VerificationError> {
    let n = 1 << 3;
    let scalars = test_fri_scalars();
    let fri_verifier_params = FriVerifierParams::with_mmcs(
        scalars.log_blowup,
        scalars.log_final_poly_len,
        scalars.max_log_arity,
        scalars.commit_pow_bits,
        scalars.query_pow_bits,
        scalars.num_queries,
        Poseidon2Config::BABY_BEAR_D4_W16,
    );
    let config = make_test_config();
    let (val_mmcs, fri_params) = test_fri_instance();
    let air = LocalOnlyMulAir { degree: 2, rows: n };
    let pis = vec![];
    let (trace, _) = air.random_valid_trace(true);
    let (preprocessed_prover_data, preprocessed_vk) =
        setup_preprocessed(&config, &air, log2_ceil_usize(trace.height()))
            .unwrap()
            .unzip();
    let mut proof = prove_with_preprocessed(
        &config,
        &air,
        trace,
        &pis,
        preprocessed_prover_data.as_ref(),
    )
    .unwrap();
    verify_with_preprocessed(&config, &air, &proof, &pis, preprocessed_vk.as_ref()).unwrap();
    let replay = replay_uni_stark_transcript(
        &config,
        &air,
        &proof,
        &pis,
        preprocessed_vk.as_ref().map(|vk| &vk.commitment),
    )
    .unwrap();
    let pre_round = replay.commitments_with_opening_points.last().unwrap();
    assert_eq!(pre_round.1.len(), 1);
    assert_eq!(pre_round.1[0].1.len(), 1);

    // A zero-width next opening may be encoded as `Some(empty)`; a nonempty
    // extra opening must still be rejected by the actual target verifier.
    let original_next = proof
        .opened_values
        .preprocessed
        .as_mut()
        .expect("preprocessed openings")
        .next
        .take();
    proof
        .opened_values
        .preprocessed
        .as_mut()
        .expect("preprocessed openings")
        .next = Some(Vec::new());
    // Upstream native verification currently accepts the canonical `None`
    // encoding but panics on `Some(empty)` while building its constraint
    // window.  Keep the production native positive on that safe encoding and
    // exercise the raw `Some(empty)` representation through recursive shape
    // validation and the runner below.
    proof
        .opened_values
        .preprocessed
        .as_mut()
        .expect("preprocessed openings")
        .next = None;
    verify_with_preprocessed(&config, &air, &proof, &pis, preprocessed_vk.as_ref()).unwrap();
    proof
        .opened_values
        .preprocessed
        .as_mut()
        .expect("preprocessed openings")
        .next = Some(Vec::new());
    let mut shape_builder = CircuitBuilder::new();
    shape_builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    shape_builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
    let shape_inputs = StarkVerifierInputsBuilder::<
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InnerFri,
    >::allocate(
        &mut shape_builder,
        &proof,
        preprocessed_vk.as_ref().map(|vk| &vk.commitment),
        pis.len(),
    );
    let mmcs_op_ids = verify_p3_uni_proof_circuit::<_, _, _, _, _, _, WIDTH, RATE>(
        &config,
        &air,
        &mut shape_builder,
        &shape_inputs.proof_targets,
        &shape_inputs.air_public_targets,
        &shape_inputs.preprocessed_commit,
        &fri_verifier_params,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
    .unwrap();
    proof
        .opened_values
        .preprocessed
        .as_mut()
        .expect("preprocessed openings")
        .next = Some(vec![Challenge::ZERO]);
    let mut extra_builder = CircuitBuilder::new();
    extra_builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        default_babybear_poseidon2_16(),
    );
    extra_builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
    let extra_inputs = StarkVerifierInputsBuilder::<
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InnerFri,
    >::allocate(
        &mut extra_builder,
        &proof,
        preprocessed_vk.as_ref().map(|vk| &vk.commitment),
        pis.len(),
    );
    let extra = verify_p3_uni_proof_circuit::<_, _, _, _, _, _, WIDTH, RATE>(
        &config,
        &air,
        &mut extra_builder,
        &extra_inputs.proof_targets,
        &extra_inputs.air_public_targets,
        &extra_inputs.preprocessed_commit,
        &fri_verifier_params,
        Poseidon2Config::BABY_BEAR_D4_W16,
    );
    assert!(matches!(
        extra,
        Err(VerificationError::InvalidProofShape(message))
            if message.contains("preprocessed") && message.contains("width")
    ));
    proof
        .opened_values
        .preprocessed
        .as_mut()
        .expect("preprocessed openings")
        .next = Some(Vec::new());

    let perm = default_babybear_poseidon2_16();
    let mut circuit_builder = CircuitBuilder::new();
    circuit_builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        perm,
    );
    circuit_builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
    let verifier_inputs = StarkVerifierInputsBuilder::<
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InnerFri,
    >::allocate(
        &mut circuit_builder,
        &proof,
        preprocessed_vk.as_ref().map(|vk| &vk.commitment),
        pis.len(),
    );
    verify_p3_uni_proof_circuit::<_, _, _, _, _, _, WIDTH, RATE>(
        &config,
        &air,
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &verifier_inputs.preprocessed_commit,
        &fri_verifier_params,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )?;
    let circuit = circuit_builder.build()?;
    let mut runner = circuit.runner();
    let (public_inputs, private_inputs) =
        verifier_inputs.pack_values(&pis, &proof, &preprocessed_vk.map(|vk| vk.commitment));
    runner
        .set_public_inputs(&public_inputs)
        .map_err(VerificationError::Circuit)?;
    runner
        .set_private_inputs(&private_inputs)
        .map_err(VerificationError::Circuit)?;
    let OpeningTranscript {
        mut challenger,
        commitments_with_opening_points,
    } = replay;
    observe_opened_values::<MyConfig>(
        &mut challenger,
        &commitments_with_opening_points,
        fri_params.batch_proof_of_work_bits,
    );
    let claims: Vec<_> = commitments_with_opening_points
        .iter()
        .cloned()
        .map(Into::into)
        .collect();
    let query_paths = restore_fri_query_paths(
        &fri_params,
        &val_mmcs,
        &val_mmcs,
        &proof.opening_proof,
        &mut challenger,
        &claims,
    )
    .map_err(|error| VerificationError::InvalidProofShape(format!("{error:?}")))?;
    set_fri_mmcs_private_data::<F, Challenge, DIGEST_ELEMS>(
        &mut runner,
        &mmcs_op_ids,
        &query_paths,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
    .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
    runner.run().map_err(VerificationError::Circuit)?;
    proof
        .opened_values
        .preprocessed
        .as_mut()
        .expect("preprocessed openings")
        .next = original_next;
    Ok(())
}
