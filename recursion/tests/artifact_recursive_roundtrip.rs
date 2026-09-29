use std::boxed::Box;

use p3_circuit::{
    Circuit, CircuitBuilder, StateTransitionError, StateTransitionLayout, StatementExport,
};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::{
    BatchStarkProof, BatchStarkProver, ConstraintProfile, PreparedCircuitProver,
    StatementAirBuilder, StatementPreprocessor, StatementProver, TablePacking,
};
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::KoalaBear;
use p3_recursion::artifact::{
    ArtifactError, ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact,
    PortableArtifactExport, PortableVerifier,
};
use p3_recursion::builtin_config::{
    FriConfigV1, KoalaBearD4Poseidon2BinaryConfig, SuiteIdV1, koala_bear_d4_poseidon2_binary,
};
use p3_recursion::verifier::VerificationError;
use p3_recursion::{
    BatchOnly, FriRecursionBackend, Poseidon2Config, ProveNextLayerParams,
    TrustedPreparedAggregation, TrustedPreparedInput, TrustedPreparedSource,
};

type F = KoalaBear;
type Challenge = BinomialExtensionField<F, 4>;
type Config = KoalaBearD4Poseidon2BinaryConfig;

const fn descriptor(
    num_queries: u32,
    input_cap_height: u32,
    commit_cap_height: u32,
) -> FriConfigV1 {
    FriConfigV1::new(
        SuiteIdV1::KoalaBearD4Poseidon2BinaryFri,
        1,
        0,
        2,
        num_queries,
        0,
        0,
        input_cap_height,
        commit_cap_height,
        0,
        0,
    )
}

fn prepare_statement_circuit(
    config: Config,
) -> (Circuit<Challenge>, PreparedCircuitProver<Config>) {
    let mut builder = CircuitBuilder::<Challenge>::new();
    let first = builder.public_input();
    let second = builder.public_input();
    let schema = builder
        .set_statement_exports::<F>(&[StatementExport::Base(first), StatementExport::Base(second)])
        .unwrap();
    let circuit = builder.build().unwrap();
    let preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> =
        vec![Box::new(StatementPreprocessor::new(schema.clone()))];
    let air_builders: Vec<Box<dyn NpoAirBuilder<Config, 4>>> =
        vec![Box::new(StatementAirBuilder::<4>::new(schema.clone()))];
    let mut prover = BatchStarkProver::new(config)
        .with_table_packing(TablePacking::new(4, 4).with_min_trace_height(32));
    prover.register_table_prover(Box::new(StatementProver::<4>::new(schema)));
    let prepared = prover
        .prepare_circuit::<Challenge, 4>(
            &circuit,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();
    (circuit, prepared)
}

fn prove_statement(
    circuit: &Circuit<Challenge>,
    prepared: &PreparedCircuitProver<Config>,
    statement: [u32; 2],
) -> BatchStarkProof<Config> {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&statement.map(|value| Challenge::from(F::from_u32(value))))
        .unwrap();
    prepared.prove(&runner.run().unwrap()).unwrap()
}

fn canonical_statement(values: &[u32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

fn prepare_transition_leaf(config: Config) -> (Circuit<Challenge>, PreparedCircuitProver<Config>) {
    let mut builder = CircuitBuilder::<Challenge>::new();
    let slots = (0..5).map(|_| builder.public_input()).collect::<Vec<_>>();
    let one = builder.add(slots[0], slots[4]);
    let twice = builder.add(slots[4], slots[4]);
    let two = builder.add(slots[1], twice);
    builder.connect(slots[2], one);
    builder.connect(slots[3], two);
    let schema = builder
        .set_statement_exports::<F>(
            &slots
                .into_iter()
                .map(StatementExport::Base)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    let circuit = builder.build().unwrap();
    let preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> =
        vec![Box::new(StatementPreprocessor::new(schema.clone()))];
    let air_builders: Vec<Box<dyn NpoAirBuilder<Config, 4>>> =
        vec![Box::new(StatementAirBuilder::<4>::new(schema.clone()))];
    let mut prover = BatchStarkProver::new(config)
        .with_table_packing(TablePacking::new(4, 4).with_min_trace_height(32));
    prover.register_table_prover(Box::new(StatementProver::<4>::new(schema)));
    let prepared = prover
        .prepare_circuit::<Challenge, 4>(
            &circuit,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();
    (circuit, prepared)
}

fn prove_transition_leaf(
    circuit: &Circuit<Challenge>,
    prepared: &PreparedCircuitProver<Config>,
    statement: [u32; 5],
) -> BatchStarkProof<Config> {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&statement.map(|value| Challenge::from(F::from_u32(value))))
        .unwrap();
    prepared.prove(&runner.run().unwrap()).unwrap()
}

#[test]
fn trusted_transition_reuses_preparation_and_portably_verifies_two_levels() {
    let limits = ArtifactLimits::default();
    let leaf_config =
        koala_bear_d4_poseidon2_binary(&descriptor(2, 1, 0), &limits.verifier).unwrap();
    let (leaf_circuit, leaf_prepared) = prepare_transition_leaf(leaf_config);
    let leaf_verifier = leaf_prepared.verifier();
    let leaves = [
        [10, 20, 11, 22, 1],
        [11, 22, 13, 26, 2],
        [13, 26, 16, 32, 3],
        [16, 32, 20, 40, 4],
    ];
    let leaf_proofs =
        leaves.map(|statement| prove_transition_leaf(&leaf_circuit, &leaf_prepared, statement));
    let field_leaves = leaves.map(|statement| statement.map(F::from_u32));
    let layout = StateTransitionLayout::base(2, 4).unwrap();
    let backend = FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
        .for_extension_degree::<4>();
    let first_config =
        koala_bear_d4_poseidon2_binary(&descriptor(1, 0, 1), &limits.verifier).unwrap();
    let first_owner = TrustedPreparedAggregation::<Config, Config, BatchOnly, BatchOnly, _, 4>::new_state_transition(
        TrustedPreparedSource::BatchStark { verifier: leaf_verifier.clone(), proof: &leaf_proofs[0], statement: &field_leaves[0] },
        TrustedPreparedSource::BatchStark { verifier: leaf_verifier.clone(), proof: &leaf_proofs[1], statement: &field_leaves[1] },
        first_config,
        backend,
        ProveNextLayerParams::default(),
        layout.clone(),
    ).unwrap();
    let first_left = first_owner
        .prove(
            TrustedPreparedInput::BatchStark {
                proof: &leaf_proofs[0],
                statement: &field_leaves[0],
            },
            TrustedPreparedInput::BatchStark {
                proof: &leaf_proofs[1],
                statement: &field_leaves[1],
            },
        )
        .unwrap();
    let first_right = first_owner
        .prove(
            TrustedPreparedInput::BatchStark {
                proof: &leaf_proofs[2],
                statement: &field_leaves[2],
            },
            TrustedPreparedInput::BatchStark {
                proof: &leaf_proofs[3],
                statement: &field_leaves[3],
            },
        )
        .unwrap();
    assert_eq!(first_owner.state_transition_layout(), Some(&layout));
    let first_verifier = first_owner.verifier();
    let first_left_statement = [10, 20, 13, 26, 3].map(F::from_u32);
    let first_right_statement = [13, 26, 20, 40, 7].map(F::from_u32);
    first_verifier
        .verify(&first_left.0, &first_left_statement)
        .unwrap();
    first_verifier
        .verify(&first_right.0, &first_right_statement)
        .unwrap();
    assert_eq!(first_verifier.statement_layout().schema().base_len(), 5);
    assert!(first_verifier.aggregation_statement_layout().is_none());

    let disconnected_values = [14, 26, 15, 28, 1];
    let disconnected = disconnected_values.map(F::from_u32);
    let disconnected_proof =
        prove_transition_leaf(&leaf_circuit, &leaf_prepared, disconnected_values);
    assert!(matches!(
        first_owner.check_inputs(
            &TrustedPreparedInput::BatchStark {
                proof: &leaf_proofs[0],
                statement: &field_leaves[0]
            },
            &TrustedPreparedInput::BatchStark {
                proof: &disconnected_proof,
                statement: &disconnected
            },
        ),
        Err(VerificationError::StateTransition(
            StateTransitionError::DiscontinuousState { coefficient: 0 }
        ))
    ));
    let wide_left_values = [10, 20, 18, 36, 8];
    let wide_right_values = [18, 36, 26, 52, 8];
    let wide_left = wide_left_values.map(F::from_u32);
    let wide_right = wide_right_values.map(F::from_u32);
    let wide_left_proof = prove_transition_leaf(&leaf_circuit, &leaf_prepared, wide_left_values);
    let wide_right_proof = prove_transition_leaf(&leaf_circuit, &leaf_prepared, wide_right_values);
    assert!(matches!(
        first_owner.check_inputs(
            &TrustedPreparedInput::BatchStark {
                proof: &wide_left_proof,
                statement: &wide_left
            },
            &TrustedPreparedInput::BatchStark {
                proof: &wide_right_proof,
                statement: &wide_right
            },
        ),
        Err(VerificationError::StateTransition(
            StateTransitionError::CountOverflow { sum: 16, max: 15 }
        ))
    ));

    let second_config =
        koala_bear_d4_poseidon2_binary(&descriptor(1, 0, 1), &limits.verifier).unwrap();
    let second_backend = FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
        .for_extension_degree::<4>();
    let second_owner = TrustedPreparedAggregation::<Config, Config, BatchOnly, BatchOnly, _, 4>::new_state_transition(
        TrustedPreparedSource::BatchStark { verifier: first_verifier.clone(), proof: &first_left.0, statement: &first_left_statement },
        TrustedPreparedSource::BatchStark { verifier: first_verifier.clone(), proof: &first_right.0, statement: &first_right_statement },
        second_config,
        second_backend,
        ProveNextLayerParams::default(),
        layout,
    ).unwrap();
    let root = second_owner
        .prove(
            TrustedPreparedInput::BatchStark {
                proof: &first_left.0,
                statement: &first_left_statement,
            },
            TrustedPreparedInput::BatchStark {
                proof: &first_right.0,
                statement: &first_right_statement,
            },
        )
        .unwrap();
    let root_verifier = second_owner.verifier();
    let independent_expected_root = [10, 20, 20, 40, 10];
    root_verifier
        .verify(&root.0, &independent_expected_root.map(F::from_u32))
        .unwrap();
    assert_eq!(root_verifier.statement_layout().schema().base_len(), 5);
    assert!(root_verifier.aggregation_statement_layout().is_none());
    let root_verifier_bytes = root_verifier.encode_verifier_artifact(limits).unwrap();
    let root_proof_bytes = root_verifier
        .encode_proof_artifact(&root.0, limits)
        .unwrap();
    drop(root_verifier);
    drop(root);
    drop(second_owner);
    drop(first_verifier);
    drop(first_left);
    drop(first_right);
    drop(first_owner);
    drop(leaf_verifier);
    drop(leaf_proofs);
    drop(leaf_prepared);
    drop(leaf_circuit);

    let portable = PortableVerifier::decode(
        &root_verifier_bytes,
        ExpectedVerifierArtifact::from_trusted_bytes(&root_verifier_bytes),
        limits,
    )
    .unwrap();
    assert_eq!(portable.schema().base_len(), 5);
    portable
        .verify_encoded(
            &root_proof_bytes,
            CanonicalStatement::new(&canonical_statement(&independent_expected_root), 5),
        )
        .unwrap();
    for wrong in [
        [11, 20, 20, 40, 10],
        [10, 20, 21, 40, 10],
        [10, 20, 20, 40, 9],
    ] {
        assert!(
            portable
                .verify_encoded(
                    &root_proof_bytes,
                    CanonicalStatement::new(&canonical_statement(&wrong), 5)
                )
                .is_err()
        );
    }
}

#[test]
fn builtin_recursion_roundtrips_two_ordered_pairs_after_all_native_owners_drop() {
    let limits = ArtifactLimits::default();
    let child_config =
        koala_bear_d4_poseidon2_binary(&descriptor(2, 1, 0), &limits.verifier).unwrap();
    let (child_circuit, child_prepared) = prepare_statement_circuit(child_config);
    let child_verifier = child_prepared.verifier();
    let statements = [[7, 9], [11, 13], [17, 19], [23, 29]];
    let child_proofs =
        statements.map(|statement| prove_statement(&child_circuit, &child_prepared, statement));
    let field_statements = statements.map(|statement| statement.map(F::from_u32));

    let output_config =
        koala_bear_d4_poseidon2_binary(&descriptor(1, 0, 1), &limits.verifier).unwrap();
    let backend = FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
        .for_extension_degree::<4>();
    let owner = TrustedPreparedAggregation::<Config, Config, BatchOnly, BatchOnly, _, 4>::new(
        TrustedPreparedSource::BatchStark {
            verifier: child_verifier.clone(),
            proof: &child_proofs[0],
            statement: &field_statements[0],
        },
        TrustedPreparedSource::BatchStark {
            verifier: child_verifier.clone(),
            proof: &child_proofs[1],
            statement: &field_statements[1],
        },
        output_config,
        backend,
        ProveNextLayerParams::default(),
    )
    .unwrap();
    let first = owner
        .prove(
            TrustedPreparedInput::BatchStark {
                proof: &child_proofs[0],
                statement: &field_statements[0],
            },
            TrustedPreparedInput::BatchStark {
                proof: &child_proofs[1],
                statement: &field_statements[1],
            },
        )
        .unwrap();
    let second = owner
        .prove(
            TrustedPreparedInput::BatchStark {
                proof: &child_proofs[2],
                statement: &field_statements[2],
            },
            TrustedPreparedInput::BatchStark {
                proof: &child_proofs[3],
                statement: &field_statements[3],
            },
        )
        .unwrap();

    let parent_verifier = owner.verifier();
    let verifier_bytes = parent_verifier.encode_verifier_artifact(limits).unwrap();
    let first_bytes = parent_verifier
        .encode_proof_artifact(&first.0, limits)
        .unwrap();
    let second_bytes = parent_verifier
        .encode_proof_artifact(&second.0, limits)
        .unwrap();
    let child_verifier_bytes = child_verifier.encode_verifier_artifact(limits).unwrap();

    drop(first);
    drop(second);
    drop(parent_verifier);
    drop(owner);
    drop(child_proofs);
    drop(child_verifier);
    drop(child_prepared);
    drop(child_circuit);

    let imported = PortableVerifier::decode(
        &verifier_bytes,
        ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
        limits,
    )
    .unwrap();
    let first_statement = canonical_statement(&[7, 9, 11, 13]);
    let second_statement = canonical_statement(&[17, 19, 23, 29]);
    imported
        .verify_encoded(&first_bytes, CanonicalStatement::new(&first_statement, 4))
        .unwrap();
    imported
        .verify_encoded(&second_bytes, CanonicalStatement::new(&second_statement, 4))
        .unwrap();

    let swapped_statement = canonical_statement(&[11, 13, 7, 9]);
    assert!(
        imported
            .verify_encoded(&first_bytes, CanonicalStatement::new(&swapped_statement, 4))
            .is_err()
    );
    assert!(
        imported
            .verify_encoded(&second_bytes, CanonicalStatement::new(&first_statement, 4))
            .is_err()
    );
    assert!(matches!(
        PortableVerifier::decode(
            &child_verifier_bytes,
            ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
            limits,
        ),
        Err(ArtifactError::TrustedArtifactMismatch)
    ));
}
