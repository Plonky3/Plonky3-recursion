mod common;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::generate_poseidon2_trace;
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_field::PrimeCharacteristicRing;
use p3_fri::create_test_fri_params;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::pcs::fri::{FriVerifierParams, HashTargets, InputProofTargets, RecValMmcs};
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::{Poseidon2Config, VerificationError, verify_circuit};
use p3_uni_stark::{prove, verify};

use crate::common::baby_bear_params::*;

#[test]
fn test_fibonacci_verifier() -> Result<(), VerificationError> {
    let n = 1 << 3;
    let x = 21;

    // Use the default permutation for both proving and circuit verification
    // to ensure the Fiat-Shamir challengers match
    let perm = default_babybear_poseidon2_16();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let trace = generate_trace_rows::<F>(0, 1, n);
    let log_final_poly_len = 0;
    let fri_params = create_test_fri_params(challenge_mmcs, log_final_poly_len);
    let fri_verifier_params = FriVerifierParams::from(&fri_params);
    let _log_height_max = fri_params.log_final_poly_len + fri_params.log_blowup;
    let _pow_bits = fri_params.query_proof_of_work_bits;
    let pcs = MyPcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm.clone());

    let config = MyConfig::new(pcs, challenger);
    let pis = vec![BabyBear::ZERO, BabyBear::ONE, BabyBear::from_u64(x)];

    let air = FibonacciAir {};
    let proof = prove(&config, &air, trace, &pis);
    assert!(verify(&config, &air, &proof, &pis).is_ok());

    let mut circuit_builder = CircuitBuilder::new();
    circuit_builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        perm, // Use the same permutation as the prover
    );

    // Allocate all targets
    let verifier_inputs = StarkVerifierInputsBuilder::<
        MyConfig,
        HashTargets<F, DIGEST_ELEMS>,
        InnerFri,
    >::allocate(&mut circuit_builder, &proof, None, pis.len());

    // Add the verification circuit to the builder.
    verify_circuit::<
        FibonacciAir,
        MyConfig,
        HashTargets<F, DIGEST_ELEMS>,
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
        InnerFri,
        WIDTH,
        RATE,
    >(
        &config,
        &air,
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &None,
        &fri_verifier_params,
        Poseidon2Config::BabyBearD4Width16,
    )?;

    // Build the circuit.
    let circuit = circuit_builder.build()?;

    let mut runner = circuit.runner();

    // Pack values using the same builder
    let public_inputs = verifier_inputs.pack_values(&pis, &proof, &None);

    runner
        .set_public_inputs(&public_inputs)
        .map_err(VerificationError::Circuit)?;

    let _traces = runner.run().map_err(VerificationError::Circuit)?;

    Ok(())
}
