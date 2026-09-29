use std::boxed::Box;

use p3_circuit::{CircuitBuilder, StatementExport};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::{
    BatchStarkProver, ConstraintProfile, StatementAirBuilder, StatementPreprocessor,
    StatementProver, TablePacking,
};
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::KoalaBear;
use p3_recursion::artifact::{
    ArtifactError, ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact,
    PortableArtifactExport, PortableArtifactImport, TypedArtifactVerifier,
};
use p3_recursion::builtin_config::{
    FriConfigV1, KoalaBearD4Poseidon2BinaryConfig, SuiteIdV1, baby_bear_d4_poseidon2_binary,
    koala_bear_d4_poseidon2_binary,
};
use p3_recursion::{BatchOnly, TrustedPreparedInput, TrustedPreparedSource};

type F = KoalaBear;
type Challenge = BinomialExtensionField<F, 4>;
type Config = KoalaBearD4Poseidon2BinaryConfig;

const fn descriptor(queries: u32) -> FriConfigV1 {
    FriConfigV1::new(
        SuiteIdV1::KoalaBearD4Poseidon2BinaryFri,
        1,
        0,
        2,
        queries,
        0,
        0,
        0,
        0,
        0,
        0,
    )
}

fn statement_bytes(values: [u32; 2]) -> Vec<u8> {
    values.into_iter().flat_map(u32::to_le_bytes).collect()
}

struct Artifacts {
    verifier: Vec<u8>,
    proof: Vec<u8>,
    expected_statement: Vec<u8>,
}

fn produce() -> Artifacts {
    let limits = ArtifactLimits::default();
    let config = koala_bear_d4_poseidon2_binary(&descriptor(1), &limits.verifier).unwrap();
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
    let verifier = prepared.verifier();
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[
            Challenge::from(F::from_u32(4)),
            Challenge::from(F::from_u32(9)),
        ])
        .unwrap();
    let proof = prepared.prove(&runner.run().unwrap()).unwrap();
    Artifacts {
        verifier: verifier.encode_verifier_artifact(limits).unwrap(),
        proof: verifier.encode_proof_artifact(&proof, limits).unwrap(),
        expected_statement: statement_bytes([4, 9]),
    }
}

fn generic_import<V: PortableArtifactImport<Config = Config>>(
    config: Config,
    verifier: &[u8],
    proof: &[u8],
    statement: &[u8],
) -> p3_recursion::artifact::VerifiedArtifactProof<Config> {
    V::decode_with_config(
        config,
        verifier,
        ExpectedVerifierArtifact::from_trusted_bytes(verifier),
        ArtifactLimits::default(),
    )
    .unwrap()
    .import_proof(proof, CanonicalStatement::new(statement, 2))
    .unwrap()
}

#[test]
fn import_owns_verified_native_proof_statement_and_authority_after_buffers_drop() {
    let artifacts = produce();
    let config =
        koala_bear_d4_poseidon2_binary(&descriptor(1), &ArtifactLimits::default().verifier)
            .unwrap();
    let trusted_identity = artifacts.verifier.clone();
    let imported = generic_import::<TypedArtifactVerifier<Config>>(
        config,
        &artifacts.verifier,
        &artifacts.proof,
        &artifacts.expected_statement,
    );
    drop(artifacts);

    assert_eq!(imported.statement(), &[F::from_u32(4), F::from_u32(9)]);
    assert_eq!(imported.trusted_identity_bytes(), trusted_identity);
    let TrustedPreparedSource::BatchStark {
        verifier,
        proof,
        statement,
    } = imported.as_source()
    else {
        panic!("expected batch source")
    };
    assert!(proof.stark_common.preprocessed.is_none());
    assert!(proof.stark_common.lookups.is_empty());
    verifier.verify(proof, statement).unwrap();
    assert_eq!(verifier.statement_layout().schema().base_len(), 2);
    let TrustedPreparedInput::BatchStark { proof, statement } = imported.as_input() else {
        panic!("expected batch input")
    };
    verifier.verify(proof, statement).unwrap();
    let _: TrustedPreparedSource<'static, '_, Config, BatchOnly> = imported.as_source();
}

#[test]
fn typed_identity_and_descriptor_checks_precede_native_import() {
    let artifacts = produce();
    let limits = ArtifactLimits::default();
    let config = || koala_bear_d4_poseidon2_binary(&descriptor(1), &limits.verifier).unwrap();
    let wrong_pin = vec![0_u8; artifacts.verifier.len()];
    assert!(matches!(
        TypedArtifactVerifier::decode_with_config(
            config(),
            &artifacts.verifier,
            ExpectedVerifierArtifact::from_trusted_bytes(&wrong_pin),
            limits,
        ),
        Err(ArtifactError::TrustedArtifactMismatch)
    ));

    let other_config = koala_bear_d4_poseidon2_binary(&descriptor(2), &limits.verifier).unwrap();
    assert!(matches!(
        TypedArtifactVerifier::decode_with_config(
            other_config,
            &artifacts.verifier,
            ExpectedVerifierArtifact::from_trusted_bytes(&artifacts.verifier),
            limits,
        ),
        Err(ArtifactError::TypedConfigMismatch)
    ));

    let baby_suite = SuiteIdV1::BabyBearD4Poseidon2BinaryFri;
    let baby_descriptor = FriConfigV1::new(baby_suite, 1, 0, 2, 1, 0, 0, 0, 0, 0, 0);
    let baby_config = baby_bear_d4_poseidon2_binary(&baby_descriptor, &limits.verifier).unwrap();
    let mismatched_pin = vec![0_u8; artifacts.verifier.len()];
    assert!(matches!(
        TypedArtifactVerifier::decode_with_config(
            baby_bear_d4_poseidon2_binary(&baby_descriptor, &limits.verifier).unwrap(),
            &artifacts.verifier,
            ExpectedVerifierArtifact::from_trusted_bytes(&mismatched_pin),
            limits,
        ),
        Err(ArtifactError::TrustedArtifactMismatch)
    ));
    assert!(matches!(
        TypedArtifactVerifier::decode_with_config(
            baby_config,
            &artifacts.verifier,
            ExpectedVerifierArtifact::from_trusted_bytes(&artifacts.verifier),
            limits,
        ),
        Err(ArtifactError::TypedSuiteMismatch {
            expected: 0x0101,
            actual: 0x0103
        })
    ));

    let typed = TypedArtifactVerifier::decode_with_config(
        config(),
        &artifacts.verifier,
        ExpectedVerifierArtifact::from_trusted_bytes(&artifacts.verifier),
        limits,
    )
    .unwrap();
    assert!(matches!(
        typed.import_proof(
            &artifacts.proof,
            CanonicalStatement::new(&statement_bytes([4, 8]), 2)
        ),
        Err(ArtifactError::VerificationRejected)
    ));
    assert!(matches!(
        typed.import_proof(
            &artifacts.proof,
            CanonicalStatement::new(&artifacts.expected_statement, 1)
        ),
        Err(ArtifactError::Statement(_))
    ));
    let mut trailing_proof = artifacts.proof.clone();
    trailing_proof.push(0);
    assert!(matches!(
        typed.import_proof(
            &trailing_proof,
            CanonicalStatement::new(&artifacts.expected_statement, 2)
        ),
        Err(ArtifactError::TrailingBytes)
    ));

    let mut trailing_verifier = artifacts.verifier;
    trailing_verifier.push(0);
    assert!(matches!(
        TypedArtifactVerifier::decode_with_config(
            config(),
            &trailing_verifier,
            ExpectedVerifierArtifact::from_trusted_bytes(&trailing_verifier),
            limits,
        ),
        Err(ArtifactError::TrailingBytes)
    ));
}

#[test]
fn typed_import_respects_current_decoder_limits() {
    let artifacts = produce();
    let original = ArtifactLimits::default();
    let config = koala_bear_d4_poseidon2_binary(&descriptor(1), &original.verifier).unwrap();
    let limits = ArtifactLimits {
        max_decoded_bytes: 1,
        ..original
    };
    assert!(matches!(
        TypedArtifactVerifier::decode_with_config(
            config,
            &artifacts.verifier,
            ExpectedVerifierArtifact::from_trusted_bytes(&artifacts.verifier),
            limits,
        ),
        Err(ArtifactError::DecodeLimitExceeded { .. })
    ));

    let config = koala_bear_d4_poseidon2_binary(&descriptor(1), &original.verifier).unwrap();
    assert!(matches!(
        TypedArtifactVerifier::decode_with_config(
            config,
            &artifacts.verifier,
            ExpectedVerifierArtifact::from_trusted_bytes(&artifacts.verifier),
            ArtifactLimits {
                max_container_entries: 0,
                ..original
            },
        ),
        Err(ArtifactError::DecodeLimitExceeded { .. })
    ));

    let config = koala_bear_d4_poseidon2_binary(&descriptor(1), &original.verifier).unwrap();
    let mut limited_descriptor = original;
    limited_descriptor.verifier.max_queries_per_round = 0;
    assert!(matches!(
        TypedArtifactVerifier::decode_with_config(
            config,
            &artifacts.verifier,
            ExpectedVerifierArtifact::from_trusted_bytes(&artifacts.verifier),
            limited_descriptor,
        ),
        Err(ArtifactError::BuiltinConfig(_))
    ));

    let config = koala_bear_d4_poseidon2_binary(&descriptor(1), &original.verifier).unwrap();
    let typed = TypedArtifactVerifier::decode_with_config(
        config,
        &artifacts.verifier,
        ExpectedVerifierArtifact::from_trusted_bytes(&artifacts.verifier),
        ArtifactLimits {
            max_proof_bytes: artifacts.proof.len() - 1,
            ..original
        },
    )
    .unwrap();
    assert!(matches!(
        typed.import_proof(
            &artifacts.proof,
            CanonicalStatement::new(&artifacts.expected_statement, 2)
        ),
        Err(ArtifactError::DecodeLimitExceeded {
            component: "artifact bytes",
            ..
        })
    ));
}
