//! Test for recursive STARK verification with a multiplication AIR.

mod common;

use p3_circuit::CircuitBuilder;
use p3_fri::create_test_fri_params;
use p3_lookup::lookup_traits::AirNoLookup;
use p3_matrix::Matrix;
use p3_recursion::pcs::fri::{FriVerifierParams, HashTargets};
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::{VerificationError, generate_challenges, verify_circuit};
use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
use p3_util::log2_ceil_usize;
use rand::SeedableRng;
use rand::rngs::SmallRng;

use crate::common::MulAir;
use crate::common::baby_bear_params::{
    ChallengeMmcs, Challenger, DIGEST_ELEMS, Dft, F, InnerFri, MyCompress, MyConfig, MyHash, MyPcs,
    Perm, RATE, ValMmcs,
};

#[test]
fn test_mul_verifier_circuit() -> Result<(), VerificationError> {
    let mut rng = SmallRng::seed_from_u64(1);
    let n = 1 << 3;

    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();

    let log_final_poly_len = 0;
    let fri_params = create_test_fri_params(challenge_mmcs, log_final_poly_len);
    let fri_verifier_params = FriVerifierParams::from(&fri_params);
    let log_height_max = fri_params.log_final_poly_len + fri_params.log_blowup;
    let pow_bits = fri_params.query_proof_of_work_bits;
    let pcs = MyPcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);

    let config = MyConfig::new(pcs, challenger);
    let pis = vec![];

    // Create AIR and generate valid trace
    let inner_air = MulAir { degree: 2, rows: n };
    let air = AirNoLookup::new(inner_air);
    let (trace, _) = inner_air.random_valid_trace(true);

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

    // Allocate all targets
    let verifier_inputs =
        StarkVerifierInputsBuilder::<MyConfig, HashTargets<F, DIGEST_ELEMS>, InnerFri>::allocate(
            &mut circuit_builder,
            &proof,
            preprocessed_vk.as_ref().map(|vk| &vk.commitment),
            pis.len(),
        );

    // Add the verification circuit to the builder
    verify_circuit::<_, _, _, _, _, RATE>(
        &config,
        &air,
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &verifier_inputs.preprocessed_commit,
        &fri_verifier_params,
    )?;

    // Build the circuit
    let circuit = circuit_builder.build()?;

    let mut runner = circuit.runner();
    // Generate all the challenge values
    let all_challenges = generate_challenges(
        &air,
        &config,
        &proof,
        &pis,
        Some(&[pow_bits, log_height_max]),
    )?;

    // Pack values using the same builder
    let num_queries = proof.opening_proof.query_proofs.len();
    let public_inputs = verifier_inputs.pack_values(
        &pis,
        &proof,
        &preprocessed_vk.map(|vk| vk.commitment),
        &all_challenges,
        num_queries,
    );

    runner
        .set_public_inputs(&public_inputs)
        .map_err(VerificationError::Circuit)?;

    let _traces = runner.run().map_err(VerificationError::Circuit)?;

    Ok(())
}
