mod common;

use p3_baby_bear::{BabyBear as F, Poseidon2BabyBear};
use p3_circuit::CircuitBuilder;
use p3_circuit::tables::Poseidon2CircuitRow;
use p3_commit::ExtensionMmcs;
use p3_field::PrimeCharacteristicRing;
use p3_fri::{TwoAdicFriPcs, create_test_fri_params};
use p3_poseidon2::ExternalLayerConstants;
use p3_poseidon2_air::RoundConstants;
use p3_poseidon2_circuit_air::{
    Poseidon2CircuitAirBabyBearD4Width16, extract_preprocessed_from_operations,
};
use p3_recursion::pcs::fri::{
    FriProofTargets, FriVerifierParams, HashTargets, InputProofTargets, RecExtensionValMmcs,
    RecValMmcs, Witness,
};
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::{VerificationError, generate_challenges, verify_circuit};
use p3_uni_stark::{
    StarkConfig, StarkGenericConfig, prove_with_preprocessed, setup_preprocessed,
    verify_with_preprocessed,
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

type Challenge = F;
type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
type MyPcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;
type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;

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
    let perm_for_trace = perm.clone();

    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    // Keep a small final poly length; with enough rows we still get FRI fold phases.
    let log_final_poly_len = 0;
    let fri_params = create_test_fri_params(challenge_mmcs, log_final_poly_len);
    let fri_verifier_params = FriVerifierParams::from(&fri_params);
    let log_height_max = fri_params.log_final_poly_len + fri_params.log_blowup;
    let pow_bits = fri_params.query_proof_of_work_bits;
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

    let trace = air.generate_trace_rows(&ops, &constants, 0, &perm_for_trace);

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
        RATE,
    >(
        &config,
        &air,
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &verifier_inputs.preprocessed_commit,
        &fri_verifier_params,
    )?;

    let circuit = circuit_builder.build()?;
    let mut runner = circuit.runner();

    let all_challenges = generate_challenges(
        &air,
        &config,
        &proof,
        &public_inputs,
        Some(&[pow_bits, log_height_max]),
    )?;
    let num_queries = proof.opening_proof.query_proofs.len();
    let packed_publics = verifier_inputs.pack_values(
        &public_inputs,
        &proof,
        &Some(verifier_data.commitment),
        &all_challenges,
        num_queries,
    );

    runner
        .set_public_inputs(&packed_publics)
        .map_err(VerificationError::Circuit)?;
    let _ = runner.run().map_err(VerificationError::Circuit)?;

    Ok(())
}
