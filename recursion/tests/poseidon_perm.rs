mod common;

use p3_baby_bear::{BabyBear as F, default_babybear_poseidon2_16};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{Poseidon2CircuitRow, generate_poseidon2_trace};
use p3_field::PrimeCharacteristicRing;
use p3_fri::create_test_fri_params;
use p3_poseidon2::ExternalLayerConstants;
use p3_poseidon2_air::RoundConstants;
use p3_poseidon2_circuit_air::{
    BabyBearD4Width16, Poseidon2CircuitAirBabyBearD4Width16, extract_preprocessed_from_operations,
};
use p3_recursion::pcs::fri::{
    FriProofTargets, FriVerifierParams, HashTargets, InputProofTargets, RecExtensionValMmcs,
    RecValMmcs, Witness,
};
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::{Poseidon2Config, VerificationError, verify_circuit};
use p3_uni_stark::{
    StarkGenericConfig, prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed,
};
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use tracing_forest::ForestLayer;
use tracing_forest::util::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

/// Initializes a global logger with default parameters.
fn init_logger() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();
}

use crate::common::baby_bear_params::*;

// Use base field challenges for this test to keep proof size manageable.
// The common module uses extension field challenges (D=4), which would
// create 4x more observations and circuit operations.
type Challenge = F;
type ChallengeMmcs = p3_commit::ExtensionMmcs<F, Challenge, ValMmcs>;
type MyPcs = p3_fri::TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = p3_uni_stark::StarkConfig<MyPcs, Challenge, Challenger>;

#[test]
fn test_poseidon2_perm_verifier() -> Result<(), VerificationError> {
    init_logger();

    let mut rng = SmallRng::seed_from_u64(1);
    let beginning_full_constants = rng.random();
    let partial_constants = rng.random();
    let ending_full_constants = rng.random();
    let constants = RoundConstants::new(
        beginning_full_constants,
        partial_constants,
        ending_full_constants,
    );
    let perm = Poseidon2BabyBear::<16>::new(
        ExternalLayerConstants::new(
            beginning_full_constants.to_vec(),
            ending_full_constants.to_vec(),
        ),
        partial_constants.to_vec(),
    );

    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    // Keep a small final poly length; with enough rows we still get FRI fold phases.
    let log_final_poly_len = 0;
    let fri_params = create_test_fri_params(challenge_mmcs, log_final_poly_len);
    let fri_verifier_params = FriVerifierParams::from(&fri_params);
    let _log_height_max = fri_params.log_final_poly_len + fri_params.log_blowup;
    let _pow_bits = fri_params.query_proof_of_work_bits;
    let pcs = MyPcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    let config = MyConfig::new(pcs, challenger);

    // Build a trace with enough rows to satisfy FRI height constraints.
    let n_rows: usize = 32;
    let ops: Vec<_> = (0..n_rows)
        .map(|row| {
            let input_values: Vec<F> = (0..16_u32)
                .map(|i| F::from_u32(i + 5 + row as u32))
                .collect();
            Poseidon2CircuitRow {
                new_start: true,
                merkle_path: false,
                mmcs_bit: false,
                mmcs_index_sum: F::ZERO,
                input_values,
                in_ctl: [false; 4],
                input_indices: [0; 4],
                out_ctl: [false; 2],
                output_indices: [0; 2],
                mmcs_index_sum_idx: 0,
            }
        })
        .collect();

    let preprocessed = extract_preprocessed_from_operations(&ops);
    let air = Poseidon2CircuitAirBabyBearD4Width16::new_with_preprocessed(
        constants.clone(),
        preprocessed,
    );

    let (prover_data, verifier_data) = setup_preprocessed(&config, &air, 5).unwrap();

    let trace = air.generate_trace_rows(&ops, &constants, 0);

    let public_inputs: Vec<F> = vec![];
    let proof = prove_with_preprocessed(&config, &air, trace, &public_inputs, Some(&prover_data));
    assert!(
        verify_with_preprocessed(&config, &air, &proof, &public_inputs, Some(&verifier_data))
            .is_ok()
    );

    type InnerFri = FriProofTargets<
        p3_uni_stark::Val<MyConfig>,
        <MyConfig as StarkGenericConfig>::Challenge,
        RecExtensionValMmcs<
            p3_uni_stark::Val<MyConfig>,
            <MyConfig as StarkGenericConfig>::Challenge,
            DIGEST_ELEMS,
            RecValMmcs<p3_uni_stark::Val<MyConfig>, DIGEST_ELEMS, MyHash, MyCompress>,
        >,
        InputProofTargets<
            p3_uni_stark::Val<MyConfig>,
            <MyConfig as StarkGenericConfig>::Challenge,
            RecValMmcs<p3_uni_stark::Val<MyConfig>, DIGEST_ELEMS, MyHash, MyCompress>,
        >,
        Witness<p3_uni_stark::Val<MyConfig>>,
    >;

    let mut circuit_builder = CircuitBuilder::new();
    let poseidon2_perm = default_babybear_poseidon2_16();
    circuit_builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        poseidon2_perm,
    );
    let verifier_inputs =
        StarkVerifierInputsBuilder::<MyConfig, HashTargets<F, DIGEST_ELEMS>, InnerFri>::allocate(
            &mut circuit_builder,
            &proof,
            Some(&verifier_data.commitment),
            public_inputs.len(),
        );

    verify_circuit::<
        Poseidon2CircuitAirBabyBearD4Width16,
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
        &verifier_inputs.preprocessed_commit,
        &fri_verifier_params,
        Poseidon2Config::BabyBearD4Width16,
    )?;

    let circuit = circuit_builder.build()?;
    let mut runner = circuit.runner();

    let packed_publics =
        verifier_inputs.pack_values(&public_inputs, &proof, &Some(verifier_data.commitment));

    runner
        .set_public_inputs(&packed_publics)
        .map_err(VerificationError::Circuit)?;
    let _ = runner.run().map_err(VerificationError::Circuit)?;

    Ok(())
}
