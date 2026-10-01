//! A custom Goldilocks D2 WHIR backend and real recursive proof fixture.

use std::sync::Arc;

#[path = "common/goldilocks_whir_config.rs"]
mod goldilocks_whir_config;

use goldilocks_whir_config::{GoldEF, GoldF, GoldWhirConfig, gold_whir_config};
use p3_circuit::ops::NpoTypeId;
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_circuit::{CircuitBuilder, CircuitError};
use p3_circuit_prover::batch_stark_prover::StatementProver;
use p3_circuit_prover::{BatchStarkProver, CircuitVerifier};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_recursion::backend::whir::{
    CheckedWhirVerifierResult, WhirRecursionBackend, WhirRecursionBackendForExt,
};
use p3_recursion::pcs::whir::uni::packed_digest_len;
use p3_recursion::{
    BatchOnly, PcsRecursionBackend, Poseidon2Config, PreparedPcsRecursionBackend,
    ProveNextLayerParams, RecursionInput, RecursionOutput, TrustedPcsRecursionBackend,
    TrustedPreparedInput, TrustedPreparedLayer, TrustedPreparedSource, VerificationError,
    VerifierCircuitResult, build_and_prove_next_layer, build_next_layer_circuit,
};
use p3_uni_stark::{prove, verify};
use p3_whir::pcs::proof::QueryOpenings;

type GoldBackend = WhirRecursionBackendForExt<2, 8, 4>;

fn gold_backend() -> GoldBackend {
    WhirRecursionBackend::<8, 4>::new(Poseidon2Config::GOLDILOCKS_D2_W8).for_extension_degree::<2>()
}

fn fibonacci_output(a: u64, b: u64, n: usize) -> GoldF {
    let (mut a, mut b) = (GoldF::from_u64(a), GoldF::from_u64(b));
    for _ in 1..n {
        (a, b) = (b, a + b);
    }
    b
}

fn verify_native_recursive_output(
    config: &GoldWhirConfig,
    params: &ProveNextLayerParams,
    owner_verifier: &CircuitVerifier<GoldWhirConfig>,
    output: &RecursionOutput<GoldWhirConfig>,
) {
    assert_eq!(output.0.ext_degree, 2);
    let mut verifier =
        BatchStarkProver::new(config.clone()).with_table_packing(params.table_packing.clone());
    verifier.register_poseidon2_table::<2>(
        Poseidon2Config::GOLDILOCKS_D2_W8.for_shared_challenger_table(),
    );
    verifier.register_recompose_table::<2>(true);
    verifier.register_table_prover(Box::new(StatementProver::<2>::new(
        owner_verifier.statement_layout().schema().clone(),
    )));
    verifier
        .verify_all_tables::<GoldEF>(&output.0)
        .expect("the full Goldilocks D2 batch proof must verify natively");
}

fn verify_native_ordinary_output(
    config: &GoldWhirConfig,
    params: &ProveNextLayerParams,
    output: &RecursionOutput<GoldWhirConfig>,
) {
    assert_eq!(output.0.ext_degree, 2);
    let mut verifier =
        BatchStarkProver::new(config.clone()).with_table_packing(params.table_packing.clone());
    verifier.register_poseidon2_table::<2>(
        Poseidon2Config::GOLDILOCKS_D2_W8.for_shared_challenger_table(),
    );
    verifier.register_recompose_table::<2>(true);
    verifier
        .verify_all_tables::<GoldEF>(&output.0)
        .expect("the ordinary Goldilocks D2 parent must verify natively");
}

fn assert_expected_two_got_four<T>(result: Result<T, VerificationError>) {
    match result {
        Err(VerificationError::InvalidProofShape(message)) => assert_eq!(
            message,
            "WhirRecursionBackend supports batch proofs of ext_degree 2, got 4"
        ),
        Err(other) => panic!("wrong typed degree rejection: {other:?}"),
        Ok(_) => panic!("degree-four metadata must be rejected by the D2 backend"),
    }
}

#[test]
fn goldilocks_d2_backend_implements_all_three_recursion_traits() {
    fn require_all_three<B>()
    where
        B: PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>
            + PreparedPcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>
            + TrustedPcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>,
    {
    }
    require_all_three::<GoldBackend>();
}

#[test]
fn goldilocks_d2_manifests_select_shared_output_and_legacy_input() {
    let backend = gold_backend();
    let shared =
        NpoTypeId::poseidon2_perm(Poseidon2Config::GOLDILOCKS_D2_W8.for_shared_challenger_table());
    let challenger = NpoTypeId::poseidon2_perm(Poseidon2Config::GOLDILOCKS_D2_W8.for_challenger());
    let ordinary = NpoTypeId::poseidon2_perm(Poseidon2Config::GOLDILOCKS_D2_W8);
    let coefficient_bound = NpoTypeId::recompose_with_coeff_lookups();

    let output = <GoldBackend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
        non_primitive_provers(&backend, 2);
    assert_eq!(
        output
            .iter()
            .map(|prover| prover.op_type())
            .collect::<Vec<_>>(),
        vec![shared.clone(), coefficient_bound.clone()]
    );

    let shared_input = <GoldBackend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
        non_primitive_input_provers(&backend, 2, &[shared.clone(), coefficient_bound.clone()]);
    assert_eq!(
        shared_input
            .iter()
            .map(|prover| prover.op_type())
            .collect::<Vec<_>>(),
        vec![shared, coefficient_bound.clone()]
    );

    let legacy_input = <GoldBackend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
        non_primitive_input_provers(&backend, 2, &[challenger.clone(), ordinary.clone()]);
    assert_eq!(
        legacy_input
            .iter()
            .map(|prover| prover.op_type())
            .collect::<Vec<_>>(),
        vec![challenger, ordinary, coefficient_bound]
    );

    let air_builders = <GoldBackend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
        non_primitive_air_builders(&backend);
    assert_eq!(air_builders.len(), 2);
    assert_eq!(
        <GoldBackend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
            non_primitive_preprocessors(&backend).len(),
        2
    );
    assert!(
        <GoldBackend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
            non_primitive_provers(&backend, 4).is_empty()
    );
    assert!(
        <GoldBackend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
            non_primitive_input_provers(
                &backend,
                4,
                &[NpoTypeId::poseidon2_perm(Poseidon2Config::GOLDILOCKS_D2_W8)]
            )
            .is_empty()
    );
}

#[test]
fn goldilocks_d2_whir_leaf_verifies_natively_and_in_recursive_circuit()
-> Result<(), VerificationError> {
    const N: usize = 1 << 10;
    const FIRST: u64 = (1 << 33) + 7;
    const SECOND: u64 = (1 << 34) + 11;
    let config = gold_whir_config();
    let backend = gold_backend();
    let air = FibonacciAir {};
    let statement = vec![
        GoldF::from_u64(FIRST),
        GoldF::from_u64(SECOND),
        fibonacci_output(FIRST, SECOND, N),
    ];
    assert_eq!(statement[0].as_canonical_u64(), FIRST);
    assert_eq!(statement[1].as_canonical_u64(), SECOND);
    let proof = prove(
        &config,
        &air,
        generate_trace_rows::<GoldF>(FIRST, SECOND, N),
        &statement,
    )
    .expect("Goldilocks WHIR leaf proof");
    verify(&config, &air, &proof, &statement).expect("native Goldilocks WHIR verification");

    assert_eq!(packed_digest_len(4, 2), 2);
    let trace_roots = proof.commitments.trace.clone().into_roots();
    assert_eq!(trace_roots.len(), 1);
    assert!(trace_roots.iter().all(|root| root.len() == 4));

    let input = RecursionInput::UniStark {
        proof: &proof,
        air: &air,
        public_inputs: statement,
        preprocessed_commit: None,
    };
    let (circuit, result) = build_next_layer_circuit::<GoldWhirConfig, FibonacciAir, GoldBackend, 2>(
        &input, &config, &backend,
    )?;
    assert!(
        !<CheckedWhirVerifierResult<GoldWhirConfig> as VerifierCircuitResult<
            GoldWhirConfig,
            FibonacciAir,
        >>::op_ids(&result)
        .is_empty(),
        "WHIR Merkle checking must be enabled"
    );
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&result.pack_public_inputs(&input)?)
        .map_err(VerificationError::Circuit)?;
    runner
        .set_private_inputs(&result.pack_private_inputs(&input)?)
        .map_err(VerificationError::Circuit)?;
    <GoldBackend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
        set_private_data_for_result(&backend, &config, &mut runner, &result, &input)
            .map_err(|message| VerificationError::InvalidProofShape(message.into()))?;
    runner.run().map_err(VerificationError::Circuit)?;
    Ok(())
}

#[test]
fn goldilocks_d2_two_parents_and_trusted_grandparent_bind_high_statements()
-> Result<(), VerificationError> {
    const N: usize = 1 << 10;
    const FIRST: (u64, u64) = ((1 << 33) + 7, (1 << 34) + 11);
    const SECOND: (u64, u64) = ((1 << 63) + 17, (1 << 62) + 31);
    let config = gold_whir_config();
    let backend = gold_backend();
    let params = ProveNextLayerParams::default();
    let air = FibonacciAir {};
    let first_statement = vec![
        GoldF::from_u64(FIRST.0),
        GoldF::from_u64(FIRST.1),
        fibonacci_output(FIRST.0, FIRST.1, N),
    ];
    let second_statement = vec![
        GoldF::from_u64(SECOND.0),
        GoldF::from_u64(SECOND.1),
        fibonacci_output(SECOND.0, SECOND.1, N),
    ];
    assert_eq!(second_statement[0].as_canonical_u64(), SECOND.0);
    assert_eq!(second_statement[1].as_canonical_u64(), SECOND.1);
    assert_ne!(first_statement, second_statement);

    let mut first_leaf = prove(
        &config,
        &air,
        generate_trace_rows::<GoldF>(FIRST.0, FIRST.1, N),
        &first_statement,
    )
    .expect("first native Goldilocks WHIR leaf");
    let second_leaf = prove(
        &config,
        &air,
        generate_trace_rows::<GoldF>(SECOND.0, SECOND.1, N),
        &second_statement,
    )
    .expect("second native Goldilocks WHIR leaf");
    verify(&config, &air, &first_leaf, &first_statement).unwrap();
    verify(&config, &air, &second_leaf, &second_statement).unwrap();

    let owner = TrustedPreparedLayer::<GoldWhirConfig, GoldWhirConfig, FibonacciAir, _, 2>::new(
        TrustedPreparedSource::UniStark {
            config: config.clone(),
            air: &air,
            preprocessed_commit: None,
            proof: &first_leaf,
            public_inputs: &first_statement,
        },
        config.clone(),
        backend.clone(),
        params.clone(),
    )?;
    let mut first_parent = owner.prove(TrustedPreparedInput::UniStark {
        proof: &first_leaf,
        public_inputs: &first_statement,
    })?;
    let second_parent = owner.prove(TrustedPreparedInput::UniStark {
        proof: &second_leaf,
        public_inputs: &second_statement,
    })?;
    assert!(Arc::ptr_eq(&first_parent.1, &second_parent.1));
    let parent_verifier = owner.verifier();
    assert_eq!(parent_verifier.statement_layout().schema().base_len(), 3);
    parent_verifier
        .verify(&first_parent.0, &first_statement)
        .unwrap();
    parent_verifier
        .verify(&second_parent.0, &second_statement)
        .unwrap();
    assert!(
        parent_verifier
            .verify(&first_parent.0, &second_statement)
            .is_err()
    );
    assert!(
        parent_verifier
            .verify(&second_parent.0, &first_statement)
            .is_err()
    );
    let mut wrong_high = second_statement.clone();
    wrong_high[0] += GoldF::from_u64(1 << 40);
    assert!(
        parent_verifier
            .verify(&second_parent.0, &wrong_high)
            .is_err()
    );
    verify_native_recursive_output(&config, &params, &parent_verifier, &first_parent);
    verify_native_recursive_output(&config, &params, &parent_verifier, &second_parent);

    // An ordinary first-layer parent has the two-table WHIR output manifest. A trusted parent
    // additionally carries its owner-bound Statement sink, which the ordinary path must reject.
    let mut ordinary_parent =
        build_and_prove_next_layer::<GoldWhirConfig, FibonacciAir, GoldBackend, 2>(
            &RecursionInput::UniStark {
                proof: &first_leaf,
                air: &air,
                public_inputs: first_statement.clone(),
                preprocessed_commit: None,
            },
            &config,
            &backend,
            &params,
        )?;
    let ordinary_manifest = ordinary_parent
        .0
        .non_primitives
        .iter()
        .map(|entry| entry.op_type.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        ordinary_manifest,
        vec![
            NpoTypeId::poseidon2_perm(
                Poseidon2Config::GOLDILOCKS_D2_W8.for_shared_challenger_table()
            ),
            NpoTypeId::recompose_with_coeff_lookups(),
        ]
    );
    verify_native_ordinary_output(&config, &params, &ordinary_parent);
    let trusted_as_ordinary = first_parent.into_recursion_input::<BatchOnly>();
    match <GoldBackend as PcsRecursionBackend<GoldWhirConfig, BatchOnly, 2>>::validate_input(
        &backend,
        &config,
        &trusted_as_ordinary,
    ) {
        Err(VerificationError::InvalidProofShape(message)) => assert_eq!(
            message,
            "non-primitive table count mismatch: expected 2, got 3"
        ),
        Err(other) => panic!("wrong trusted-parent ordinary rejection: {other:?}"),
        Ok(()) => panic!("ordinary batch reconstruction must reject a trusted Statement sink"),
    }

    // Exercise ordinary witness-manifest reconstruction and checked D2 batch verification.
    let ordinary_input = ordinary_parent.into_recursion_input::<BatchOnly>();
    let (ordinary_circuit, ordinary_result) = build_next_layer_circuit::<
        GoldWhirConfig,
        BatchOnly,
        GoldBackend,
        2,
    >(&ordinary_input, &config, &backend)?;
    let mut ordinary_runner = ordinary_circuit.runner();
    ordinary_runner
        .set_public_inputs(&ordinary_result.pack_public_inputs(&ordinary_input)?)
        .map_err(VerificationError::Circuit)?;
    ordinary_runner
        .set_private_inputs(&ordinary_result.pack_private_inputs(&ordinary_input)?)
        .map_err(VerificationError::Circuit)?;
    <GoldBackend as PcsRecursionBackend<GoldWhirConfig, BatchOnly, 2>>::
        set_private_data_for_result(
            &backend,
            &config,
            &mut ordinary_runner,
            &ordinary_result,
            &ordinary_input,
        )
        .map_err(|message| VerificationError::InvalidProofShape(message.into()))?;
    ordinary_runner.run().map_err(VerificationError::Circuit)?;

    // The next owner retains the first parent's actual native verifier relation.
    let second_owner =
        TrustedPreparedLayer::<GoldWhirConfig, GoldWhirConfig, BatchOnly, _, 2>::new(
            TrustedPreparedSource::BatchStark {
                verifier: owner.verifier(),
                proof: &first_parent.0,
                statement: &first_statement,
            },
            config.clone(),
            backend.clone(),
            params.clone(),
        )?;
    let grandparent = second_owner.prove(TrustedPreparedInput::BatchStark {
        proof: &second_parent.0,
        statement: &second_statement,
    })?;
    let grandparent_verifier = second_owner.verifier();
    grandparent_verifier
        .verify(&grandparent.0, &second_statement)
        .unwrap();
    assert!(
        grandparent_verifier
            .verify(&grandparent.0, &first_statement)
            .is_err()
    );
    verify_native_recursive_output(&config, &params, &grandparent_verifier, &grandparent);

    // Change only real ordinary-parent metadata; the checked and prepared paths must reject before
    // reconstruction, challenger work, or verifier-target allocation.
    ordinary_parent.0.ext_degree = 4;
    let wrong_degree = ordinary_parent.into_recursion_input::<BatchOnly>();
    assert_expected_two_got_four(<GoldBackend as PcsRecursionBackend<
        GoldWhirConfig,
        BatchOnly,
        2,
    >>::validate_input(&backend, &config, &wrong_degree));
    assert_expected_two_got_four(build_next_layer_circuit::<
        GoldWhirConfig,
        BatchOnly,
        GoldBackend,
        2,
    >(&wrong_degree, &config, &backend));
    assert_expected_two_got_four(<GoldBackend as PreparedPcsRecursionBackend<
        GoldWhirConfig,
        BatchOnly,
        2,
    >>::capture_input_contract(
        &backend, &config, &wrong_degree
    ));
    let mut empty_builder = CircuitBuilder::<GoldEF>::new();
    assert_expected_two_got_four(<GoldBackend as PcsRecursionBackend<
        GoldWhirConfig,
        BatchOnly,
        2,
    >>::build_verifier_circuit(
        &backend, &wrong_degree, &config, &mut empty_builder
    ));
    let empty_circuit = empty_builder
        .build()
        .map_err(VerificationError::CircuitBuilder)?;
    let untouched_circuit = CircuitBuilder::<GoldEF>::new()
        .build()
        .map_err(VerificationError::CircuitBuilder)?;
    assert_eq!(empty_circuit.public_flat_len, 0);
    assert_eq!(empty_circuit.private_flat_len, 0);
    assert_eq!(empty_circuit.ops.len(), untouched_circuit.ops.len());
    assert_eq!(empty_circuit.witness_count, untouched_circuit.witness_count);
    ordinary_parent.0.ext_degree = 2;

    // The retained child verifier independently rejects wrong metadata on a trusted parent.
    first_parent.0.ext_degree = 4;
    let wrong_trusted = TrustedPreparedInput::BatchStark {
        proof: &first_parent.0,
        statement: &first_statement,
    };
    assert!(matches!(
        second_owner.check_input(&wrong_trusted),
        Err(VerificationError::InvalidProofShape(_))
    ));
    assert!(matches!(
        second_owner.prove(wrong_trusted),
        Err(VerificationError::InvalidProofShape(_))
    ));
    first_parent.0.ext_degree = 2;

    // This is an authenticated WHIR query leaf, not a sumcheck-only perturbation.
    match &mut first_leaf.opening_proof.rounds[0].whir.rounds[0].openings {
        QueryOpenings::Base(opening) => opening.rows[0][0] += GoldF::ONE,
        QueryOpenings::Extension(opening) => opening.rows[0][0] += GoldEF::ONE,
    }
    assert!(verify(&config, &air, &first_leaf, &first_statement).is_err());
    let rejection = owner
        .prove(TrustedPreparedInput::UniStark {
            proof: &first_leaf,
            public_inputs: &first_statement,
        })
        .err()
        .expect("tampered authenticated leaf must be rejected");
    assert!(
        matches!(
            rejection,
            VerificationError::Circuit(CircuitError::WitnessConflict { .. })
                | VerificationError::InvalidProofShape(_)
        ),
        "unexpected authenticated leaf rejection: {rejection:?}"
    );
    Ok(())
}
