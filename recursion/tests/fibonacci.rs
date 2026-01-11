mod common;

use std::collections::HashMap;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_challenger::{CanObserve, CanSample};
use p3_circuit::ops::generate_poseidon2_trace;
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_circuit::{CircuitBuilder, WitnessId};
use p3_circuit_prover::Poseidon2Config;
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace as _, ExtensionField, PackedValue, PrimeCharacteristicRing};
use p3_fri::create_test_fri_params;
use p3_poseidon2_circuit_air::{BabyBearD4Width16, BabyBearD4Width24};
use p3_recursion::pcs::fri::{FriVerifierParams, HashTargets, InputProofTargets, RecValMmcs};
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::{VerificationError, generate_challenges, verify_circuit};
use p3_uni_stark::{StarkGenericConfig, prove, verify};
use rand::SeedableRng;
use rand::rngs::SmallRng;
use tracing::{debug, info, trace};
use tracing_forest::ForestLayer;
use tracing_forest::util::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

use crate::common::baby_bear_params::*;
type Ext4 = BinomialExtensionField<BabyBear, 4>;

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

#[test]
fn test_fibonacci_verifier() -> Result<(), VerificationError> {
    init_logger();

    let mut rng = SmallRng::seed_from_u64(1);
    let n = 1 << 3;
    let x = 21;

    let perm = Perm::new_from_rng_128(&mut rng);
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let trace = generate_trace_rows::<F>(0, 1, n);
    let log_final_poly_len = 0;
    let fri_params = create_test_fri_params(challenge_mmcs, log_final_poly_len);
    let fri_verifier_params = FriVerifierParams::from(&fri_params);
    let log_height_max = fri_params.log_final_poly_len + fri_params.log_blowup;
    let pow_bits = fri_params.proof_of_work_bits;
    let pcs = MyPcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm.clone());

    let config = MyConfig::new(pcs, challenger);
    let pis = vec![BabyBear::ZERO, BabyBear::ONE, BabyBear::from_u64(x)];

    let air = FibonacciAir {};
    let proof = prove(&config, &air, trace, &pis);
    assert!(verify(&config, &air, &proof, &pis).is_ok());

    let mut circuit_builder = CircuitBuilder::<Ext4>::new();
    circuit_builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Ext4, BabyBearD4Width16>,
        perm,
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
        RATE_EXT,
    >(
        &config,
        &air,
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &None,
        Poseidon2Config::BabyBearD4Width16,
        &fri_verifier_params,
    )?;

    circuit_builder.dump_allocation_log();

    // Build the circuit.
    let circuit = circuit_builder.build()?;

    let mut widx_to_expr = HashMap::new();
    for (expr, widx) in circuit.expr_to_widx.iter() {
        let exprs = widx_to_expr.entry(*widx).or_insert_with(Vec::new);
        exprs.push(*expr);
    }

    info!("Widx 1049 exprs: {:?}", widx_to_expr.get(&WitnessId(1049)));
    info!("Widx 1057 exprs: {:?}", widx_to_expr.get(&WitnessId(1057)));
    info!("Widx 388 exprs: {:?}", widx_to_expr.get(&WitnessId(388)));

    let mut runner = circuit.runner();

    let mut challenger = config.initialise_challenger();
    // challenger.observe(BabyBear::ONE);
    // let sample: Ext4 = challenger.sample();
    // debug!("Sampled challenge: {:?}", sample);

    // Generate all the challenge values.BinomialExtensionField
    info!("Generating all challenges with external challenger...");
    let all_challenges = generate_challenges(
        &air,
        &config,
        &proof,
        &pis,
        Some(&[pow_bits, log_height_max]),
    )?;

    info!("All challenges: {:?}", all_challenges);

    // Pack values using the same builder
    let num_queries = proof.opening_proof.query_proofs.len();
    let public_inputs = verifier_inputs.pack_values(&pis, &proof, &None, num_queries);

    runner
        .set_public_inputs(&public_inputs)
        .map_err(VerificationError::Circuit)?;

    let _traces = runner.run().map_err(VerificationError::Circuit)?;

    Ok(())
}
