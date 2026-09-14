use std::boxed::Box;

use p3_circuit::{Circuit, CircuitBuilder, StatementExport};
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
