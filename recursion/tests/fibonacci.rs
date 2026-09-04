mod common;

use p3_baby_bear::default_babybear_poseidon2_16;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_field::PrimeCharacteristicRing;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::pcs::fri::{FriVerifierParams, InputProofTargets, MerkleCapTargets, RecValMmcs};
use p3_recursion::pcs::{FriQueryPaths, restore_fri_query_paths, set_fri_mmcs_private_data};
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::{
    OpeningTranscript, Poseidon2Config, VerificationError, observe_opened_values,
    replay_uni_stark_transcript, verify_p3_uni_proof_circuit,
};
use p3_test_utils::baby_bear_params::*;
use p3_uni_stark::{prove, verify};
use tracing_forest::ForestLayer;
use tracing_forest::util::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

use crate::common::InnerFriGeneric;

type InnerFri = InnerFriGeneric<MyConfig, MyHash, MyCompress, DIGEST_ELEMS>;

fn init_logger() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();
}

struct FibonacciTestSetup {
    config: MyConfig,
    perm: Perm,
    fri_verifier_params: FriVerifierParams,
    proof: p3_uni_stark::Proof<MyConfig>,
    pis: Vec<F>,
    air: FibonacciAir,
}

fn build_fibonacci_test_setup() -> FibonacciTestSetup {
    let n = 1 << 3;
    let x = 21;

    let trace = generate_trace_rows::<F>(0, 1, n);

    let config = make_test_config();
    // Same default permutation make_test_config uses, for the recursive verifier circuit.
    let perm = default_babybear_poseidon2_16();

    // Enable MMCS verification
    let scalars = test_fri_scalars();
    let fri_verifier_params = FriVerifierParams::with_mmcs(
        scalars.log_blowup,
        scalars.log_final_poly_len,
        scalars.commit_pow_bits,
        scalars.query_pow_bits,
        scalars.num_queries,
        Poseidon2Config::BABY_BEAR_D4_W16,
    );
    let pis = vec![F::ZERO, F::ONE, F::from_u64(x)];
    let air = FibonacciAir {};
    let proof = prove(&config, &air, trace, &pis);

    FibonacciTestSetup {
        config,
        perm,
        fri_verifier_params,
        proof,
        pis,
        air,
    }
}

/// Restores the per-query Merkle authentication chains the in-circuit MMCS gadget consumes.
///
/// A FRI proof shares one pruned multiproof across all queries into a tree, so the chains have to
/// be rebuilt from the verifier's own transcript — replayed here exactly as `p3_uni_stark::verify`
/// would drive it.
fn restore_query_paths(
    setup: &FibonacciTestSetup,
    proof: &p3_uni_stark::Proof<MyConfig>,
    pis: &[F],
) -> Vec<FriQueryPaths<F, DIGEST_ELEMS>> {
    let (val_mmcs, fri_params) = test_fri_instance();
    let OpeningTranscript {
        mut challenger,
        commitments_with_opening_points,
    } = replay_uni_stark_transcript(&setup.config, &setup.air, proof, pis, None)
        .expect("the proof's transcript replays");
    observe_opened_values::<MyConfig>(&mut challenger, &commitments_with_opening_points);
    restore_fri_query_paths(
        &fri_params,
        &val_mmcs,
        &val_mmcs,
        &proof.opening_proof,
        &mut challenger,
        &commitments_with_opening_points,
    )
    .expect("an honest proof's Merkle paths restore")
}

/// Runs the recursive verifier circuit over `proof` and `pis`, with `query_paths` supplied as the
/// MMCS private data.
///
/// The paths are a parameter rather than restored here so a tampering test can hand the circuit
/// genuine Merkle witnesses for the honest proof alongside a tampered statement: the circuit, not
/// the witness generation, is then what has to reject.
fn run_recursive_verifier(
    setup: &FibonacciTestSetup,
    proof: &p3_uni_stark::Proof<MyConfig>,
    pis: &[F],
    query_paths: &[FriQueryPaths<F, DIGEST_ELEMS>],
) -> Result<(), VerificationError> {
    let mut circuit_builder = CircuitBuilder::new();
    circuit_builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        setup.perm.clone(),
    );
    circuit_builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    // Allocate all targets
    let verifier_inputs = StarkVerifierInputsBuilder::<
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InnerFri,
    >::allocate(&mut circuit_builder, proof, None, pis.len());

    // Add the verification circuit to the builder.
    let mmcs_op_ids = verify_p3_uni_proof_circuit::<
        FibonacciAir,
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
        InnerFri,
        _,
        WIDTH,
        RATE,
    >(
        &setup.config,
        &setup.air,
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &None,
        &setup.fri_verifier_params,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )?;

    // Build the circuit.
    let circuit = circuit_builder.build()?;

    let mut runner = circuit.runner();

    // Pack values using the same builder
    let (public_inputs, private_inputs) = verifier_inputs.pack_values(pis, proof, &None);
    runner
        .set_public_inputs(&public_inputs)
        .map_err(VerificationError::Circuit)?;
    runner
        .set_private_inputs(&private_inputs)
        .map_err(VerificationError::Circuit)?;

    // Set MMCS private data from the FRI proof
    set_fri_mmcs_private_data::<F, Challenge, DIGEST_ELEMS>(
        &mut runner,
        &mmcs_op_ids,
        query_paths,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
    .map_err(|e| VerificationError::InvalidProofShape(e.to_string()))?;

    runner.run().map_err(VerificationError::Circuit)?;

    Ok(())
}

#[test]
fn test_fibonacci_verifier() -> Result<(), VerificationError> {
    init_logger();
    let setup = build_fibonacci_test_setup();
    assert!(verify(&setup.config, &setup.air, &setup.proof, &setup.pis).is_ok());
    let query_paths = restore_query_paths(&setup, &setup.proof, &setup.pis);
    run_recursive_verifier(&setup, &setup.proof, &setup.pis, &query_paths)
}

/// A tampered trace commitment causes the Fiat-Shamir transcript to diverge from the
/// values used during proving, so the OOD evaluation check fails as a `WitnessConflict`.
#[test]
#[should_panic(expected = "WitnessConflict")]
fn test_tampered_trace_commitment() {
    let mut setup = build_fibonacci_test_setup();
    // Genuine Merkle witnesses for the honest proof, so only the statement is tampered with.
    let query_paths = restore_query_paths(&setup, &setup.proof, &setup.pis);

    // The cap at height 0 contains a single digest; corrupt its first word.
    let mut roots = setup.proof.commitments.trace.into_roots();
    roots[0][0] += F::ONE;
    setup.proof.commitments.trace = roots.into();

    run_recursive_verifier(&setup, &setup.proof, &setup.pis, &query_paths).unwrap();
}

/// Flipping a coefficient in the FRI final polynomial breaks the low-degree test,
/// causing a WitnessConflict when the verifier circuit checks the folding equations.
#[test]
#[should_panic(expected = "WitnessConflict")]
fn test_tampered_fri_final_poly() {
    let mut setup = build_fibonacci_test_setup();
    // Genuine Merkle witnesses for the honest proof, so only the statement is tampered with.
    let query_paths = restore_query_paths(&setup, &setup.proof, &setup.pis);

    setup.proof.opening_proof.final_poly[0] += Challenge::ONE;

    run_recursive_verifier(&setup, &setup.proof, &setup.pis, &query_paths).unwrap();
}

/// Feeding wrong public inputs to the verifier circuit means the constraint
/// enforcing the Fibonacci output value is not satisfied, yielding a `WitnessConflict`.
#[test]
#[should_panic(expected = "WitnessConflict")]
fn test_wrong_public_inputs() {
    let setup = build_fibonacci_test_setup();
    // Genuine Merkle witnesses for the honest proof, so only the claimed inputs are wrong.
    let query_paths = restore_query_paths(&setup, &setup.proof, &setup.pis);

    let mut wrong_pis = setup.pis.clone();
    // Corrupt the claimed output value.
    wrong_pis[2] += F::ONE;

    run_recursive_verifier(&setup, &setup.proof, &wrong_pis, &query_paths).unwrap();
}

/// Modifying an OOD trace evaluation changes the quotient-consistency check
/// inside the verifier circuit, which results in a `WitnessConflict` at run time.
#[test]
#[should_panic(expected = "WitnessConflict")]
fn test_tampered_ood_evaluation() {
    let mut setup = build_fibonacci_test_setup();
    // Genuine Merkle witnesses for the honest proof, so only the statement is tampered with.
    let query_paths = restore_query_paths(&setup, &setup.proof, &setup.pis);

    setup.proof.opened_values.trace_local[0] += Challenge::ONE;

    run_recursive_verifier(&setup, &setup.proof, &setup.pis, &query_paths).unwrap();
}

/// Fewer restored query paths than the circuit has MMCS operations causes
/// `set_fri_mmcs_private_data` to report a shape mismatch, returned as
/// VerificationError::InvalidProofShape, rather than leaving those operations without private
/// data.
#[test]
fn test_truncated_fri_proof() {
    let setup = build_fibonacci_test_setup();

    // Build the circuit against the valid proof so op_ids match the full shape.
    let mut circuit_builder = CircuitBuilder::new();
    circuit_builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        setup.perm.clone(),
    );
    circuit_builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);
    // Allocate all targets
    let verifier_inputs = StarkVerifierInputsBuilder::<
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InnerFri,
    >::allocate(&mut circuit_builder, &setup.proof, None, setup.pis.len());
    // Add the verification circuit to the builder.
    let mmcs_op_ids = verify_p3_uni_proof_circuit::<
        FibonacciAir,
        MyConfig,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
        InnerFri,
        _,
        WIDTH,
        RATE,
    >(
        &setup.config,
        &setup.air,
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &None,
        &setup.fri_verifier_params,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
    .unwrap();
    // Build the circuit.
    let circuit = circuit_builder.build().unwrap();
    let mut runner = circuit.runner();
    // Pack values using the same builder
    let (public_inputs, private_inputs) =
        verifier_inputs.pack_values(&setup.pis, &setup.proof, &None);

    runner.set_public_inputs(&public_inputs).unwrap();
    runner.set_private_inputs(&private_inputs).unwrap();

    // Now drop one query's restored chains — this gives fewer siblings than op_ids expects.
    let mut query_paths = restore_query_paths(&setup, &setup.proof, &setup.pis);
    assert!(
        query_paths.pop().is_some(),
        "need at least one query to truncate"
    );

    let result = set_fri_mmcs_private_data::<F, Challenge, DIGEST_ELEMS>(
        &mut runner,
        &mmcs_op_ids,
        &query_paths,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
    .map_err(|e| VerificationError::InvalidProofShape(e.to_string()));

    assert!(
        matches!(result, Err(VerificationError::InvalidProofShape(_))),
        "expected InvalidProofShape for a truncated FRI proof, got: {result:?}",
    );
}
