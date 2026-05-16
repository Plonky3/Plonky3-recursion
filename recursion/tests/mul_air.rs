//! Test for recursive STARK verification with a multiplication AIR.

mod common;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_matrix::Matrix;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::pcs::fri::{FriVerifierParams, MerkleCapTargets};
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::{Poseidon2Config, VerificationError, verify_p3_uni_proof_circuit};
use p3_test_utils::baby_bear_params::*;
use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use p3_util::log2_ceil_usize;

use crate::common::{InnerFriGeneric, MulAir};

type InnerFri = InnerFriGeneric<MyConfig, MyHash, MyCompress, DIGEST_ELEMS>;

#[test]
fn test_mul_verifier_circuit() -> Result<(), VerificationError> {
    let n = 1 << 3;

    let scalars = test_fri_scalars();
    let fri_verifier_params = FriVerifierParams::unsafe_arithmetic_only_for_tests(
        scalars.log_blowup,
        scalars.log_final_poly_len,
        scalars.commit_pow_bits,
        scalars.query_pow_bits,
    );
    let config = make_test_config();
    // Same default permutation make_test_config uses, for the recursive verifier circuit.
    let perm = default_babybear_poseidon2_16();
    let pis = vec![];

    // Create AIR and generate valid trace
    let air: MulAir = MulAir { degree: 2, rows: n };
    let (trace, _) = air.random_valid_trace(true);

    // Setup preprocessed data
    let (preprocessed_prover_data, preprocessed_vk) =
        setup_preprocessed(&config, &air, log2_ceil_usize(trace.height())).unzip();
    // Generate and verify proof
    let proof = prove_with_preprocessed(
        &config,
        &air,
        trace,
        &pis,
        preprocessed_prover_data.as_ref(),
    );
    assert!(
        verify_with_preprocessed(&config, &air, &proof, &pis, preprocessed_vk.as_ref()).is_ok()
    );

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

    let _traces = runner.run().map_err(VerificationError::Circuit)?;

    Ok(())
}
