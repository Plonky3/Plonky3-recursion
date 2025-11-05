use std::env;

/// Fibonacci circuit: Compute F(n) and prove correctness
/// Public input: expected_result (F(n))
use p3_baby_bear::BabyBear;
use p3_circuit::CircuitBuilder;
use p3_circuit_prover::{BatchStarkProver, TablePacking, config};
use p3_field::PrimeCharacteristicRing;
use tracing_forest::ForestLayer;
use tracing_forest::util::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

type F = BabyBear;

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
fn test_fibonacci_batch_verifier() {
    init_logger();

    let n = env::args()
        .nth(1)
        .and_then(|s| s.parse().ok())
        .unwrap_or(100);

    let mut builder = CircuitBuilder::new();

    // Public input: expected F(n)
    let expected_result = builder.alloc_public_input("expected_result");

    // Compute F(n) iteratively
    let mut a = builder.alloc_const(F::ZERO, "F(0)");
    let mut b = builder.alloc_const(F::ONE, "F(1)");

    // TODO: remove this once we always have non-empty MUL tables
    builder.mul(a, b);
    for _i in 2..=n {
        let next = builder.add(a, b);
        a = b;
        b = next;
    }

    // Assert computed F(n) equals expected result
    builder.connect(b, expected_result);

    builder.dump_allocation_log();

    let circuit = builder.build().unwrap();
    let mut runner = circuit.runner();

    // Set public input
    let expected_fib = compute_fibonacci_classical(n);
    runner.set_public_inputs(&[expected_fib]).unwrap();

    let traces = runner.run().unwrap();
    let config = config::baby_bear().build();
    let table_packing = TablePacking::from_counts(4, 1);
    let prover = BatchStarkProver::new(config).with_table_packing(table_packing);
    let proof = prover.prove_all_tables(&traces).unwrap();
    prover.verify_all_tables(&proof).unwrap();

    // let mut circuit_builder = CircuitBuilder::new();

    // // Allocate all targets
    // let verifier_inputs = BatchStarkVerifierInputsBuilder::<
    //     MyConfig,
    //     HashTargets<F, DIGEST_ELEMS>,
    //     InnerFri,
    // >::allocate(&mut circuit_builder, &proof, pis.len());

    // // Add the verification circuit to the builder.
    // verify_batch_stark_circuit::<
    //     BatchStarkAir,
    //     MyConfig,
    //     HashTargets<F, DIGEST_ELEMS>,
    //     InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
    //     InnerFri,
    //     RATE,
    // >(
    //     &config,
    //     &air,
    //     &mut circuit_builder,
    //     &verifier_inputs.proof_targets,
    //     &verifier_inputs.air_public_targets,
    //     &fri_verifier_params,
    // )?;

    // // Build the circuit.
    // let circuit = circuit_builder.build()?;

    // let mut runner = circuit.runner();

    // // Generate all the challenge values.
    // let all_challenges = generate_challenges(
    //     &air,
    //     &config,
    //     &proof,
    //     &pis,
    //     Some(&[pow_bits, log_height_max]),
    // )?;

    // // Pack values using the same builder
    // let num_queries = proof.opening_proof.query_proofs.len();
    // let public_inputs = verifier_inputs.pack_values(&pis, &proof, &all_challenges, num_queries);

    // runner
    //     .set_public_inputs(&public_inputs)
    //     .map_err(VerificationError::Circuit)?;

    // let _traces = runner.run().map_err(VerificationError::Circuit)?;
}

fn compute_fibonacci_classical(n: usize) -> F {
    if n == 0 {
        return F::ZERO;
    }
    if n == 1 {
        return F::ONE;
    }

    let mut a = F::ZERO;
    let mut b = F::ONE;

    for _i in 2..=n {
        let next = a + b;
        a = b;
        b = next;
    }

    b
}
