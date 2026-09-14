use std::boxed::Box;

use p3_baby_bear::BabyBear;
use p3_circuit::{CircuitBuilder, StatementExport, StatementField, StatementSchema};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::{
    BatchStarkProver, ConstraintProfile, StatementAirBuilder, StatementPreprocessor,
    StatementProver, TablePacking,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_koala_bear::KoalaBear;
use p3_recursion::artifact::{
    ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact, PortableArtifactExport,
    PortableVerifier,
};
use p3_recursion::builtin_config::{
    BabyBearD4Poseidon2BinaryConfig, FriConfigV1, SuiteIdV1, WhirConfigV1, WhirRateModeV1,
    WhirSecurityAssumptionV1, baby_bear_d4_poseidon2_binary, baby_bear_d4_poseidon2_quaternary,
    baby_bear_d4_poseidon2_random_codeword, baby_bear_d4_poseidon2_whir,
    goldilocks_d2_poseidon2_binary, koala_bear_d4_poseidon2_salted, koala_bear_d4_poseidon2_whir,
    koala_bear_d5_poseidon2_binary,
};
use rand::SeedableRng;
use rand::rngs::StdRng;

const fn fri_descriptor(suite: SuiteIdV1) -> FriConfigV1 {
    let spec = suite.spec();
    FriConfigV1::new(
        suite,
        1,
        0,
        2,
        2,
        0,
        0,
        0,
        0,
        if spec.is_hiding() { 2 } else { 0 },
        spec.salt_elements as u32,
    )
}

const fn whir_descriptor(suite: SuiteIdV1) -> WhirConfigV1 {
    WhirConfigV1::new(
        suite,
        1,
        WhirRateModeV1::Auto,
        4,
        WhirSecurityAssumptionV1::UniqueDecoding.as_u16(),
        32,
        0,
        20,
        0,
    )
}

macro_rules! portable_roundtrip {
    ($field:ty, $config:expr, $min_height:expr) => {{
        let limits = ArtifactLimits::default();
        let config = $config;
        let mut builder = CircuitBuilder::<$field>::new();
        let input = builder.public_input();
        let two = builder.define_const(<$field>::from_u32(2));
        let output = builder.public_input();
        let product = builder.mul(input, two);
        builder.connect(product, output);
        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&[<$field>::from_u32(4), <$field>::from_u32(8)])
            .unwrap();
        let traces = runner.run().unwrap();
        let prepared = BatchStarkProver::new(config)
            .with_table_packing(TablePacking::new(4, 4).with_min_trace_height($min_height))
            .prepare_circuit::<$field, 1>(&circuit, &[], &[], ConstraintProfile::Standard)
            .unwrap();
        let verifier = prepared.verifier();
        let proof = prepared.prove(&traces).unwrap();
        let verifier_bytes = verifier.encode_verifier_artifact(limits).unwrap();
        let proof_bytes = verifier.encode_proof_artifact(&proof, limits).unwrap();

        drop(proof);
        drop(verifier);
        drop(prepared);
        drop(traces);
        drop(circuit);

        let imported = PortableVerifier::decode(
            &verifier_bytes,
            ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
            limits,
        )
        .unwrap();
        assert_eq!(imported.trusted_identity_bytes(), verifier_bytes);
        imported
            .verify_encoded(&proof_bytes, CanonicalStatement::new(&[], 0))
            .unwrap();
    }};
}

#[test]
fn representative_native_proofs_roundtrip_each_physical_format_and_field_dimension() {
    let limits = ArtifactLimits::default();

    let descriptor = fri_descriptor(SuiteIdV1::BabyBearD4Poseidon2BinaryFri);
    portable_roundtrip!(
        BabyBear,
        baby_bear_d4_poseidon2_binary(&descriptor, &limits.verifier).unwrap(),
        32
    );

    let descriptor = fri_descriptor(SuiteIdV1::GoldilocksD2Poseidon2BinaryFri);
    portable_roundtrip!(
        Goldilocks,
        goldilocks_d2_poseidon2_binary(&descriptor, &limits.verifier).unwrap(),
        32
    );

    let descriptor = fri_descriptor(SuiteIdV1::KoalaBearD5Poseidon2BinaryFri);
    portable_roundtrip!(
        KoalaBear,
        koala_bear_d5_poseidon2_binary(&descriptor, &limits.verifier).unwrap(),
        32
    );

    let descriptor = fri_descriptor(SuiteIdV1::BabyBearD4Poseidon2QuaternaryFri);
    portable_roundtrip!(
        BabyBear,
        baby_bear_d4_poseidon2_quaternary(&descriptor, &limits.verifier).unwrap(),
        32
    );

    let descriptor = fri_descriptor(SuiteIdV1::BabyBearD4Poseidon2RandomCodewordFri);
    portable_roundtrip!(
        BabyBear,
        baby_bear_d4_poseidon2_random_codeword(
            &descriptor,
            &limits.verifier,
            StdRng::seed_from_u64(11),
        )
        .unwrap(),
        32
    );

    let descriptor = fri_descriptor(SuiteIdV1::KoalaBearD4Poseidon2SaltedFri);
    portable_roundtrip!(
        KoalaBear,
        koala_bear_d4_poseidon2_salted(
            &descriptor,
            &limits.verifier,
            StdRng::seed_from_u64(21),
            StdRng::seed_from_u64(22),
            StdRng::seed_from_u64(23),
        )
        .unwrap(),
        32
    );

    let descriptor = whir_descriptor(SuiteIdV1::BabyBearD4Poseidon2Whir);
    portable_roundtrip!(
        BabyBear,
        baby_bear_d4_poseidon2_whir(&descriptor, &limits.verifier).unwrap(),
        64
    );

    let descriptor = whir_descriptor(SuiteIdV1::KoalaBearD4Poseidon2Whir);
    portable_roundtrip!(
        KoalaBear,
        koala_bear_d4_poseidon2_whir(&descriptor, &limits.verifier).unwrap(),
        64
    );
}

fn canonical_baby_bear_statement(values: &[u32]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.to_le_bytes())
        .collect()
}

#[test]
fn one_preparation_exports_two_ordered_runtime_statements_after_all_native_owners_drop() {
    let limits = ArtifactLimits::default();
    let descriptor = fri_descriptor(SuiteIdV1::BabyBearD4Poseidon2BinaryFri);
    let config = baby_bear_d4_poseidon2_binary(&descriptor, &limits.verifier).unwrap();

    let left_schema = StatementSchema::try_new(vec![StatementField::Base]).unwrap();
    let right_schema = StatementSchema::try_new(vec![StatementField::Base]).unwrap();
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let left = builder.public_input();
    let right = builder.public_input();
    let schema = builder
        .set_statement_exports::<BabyBear>(&[
            StatementExport::Base(left),
            StatementExport::Base(right),
        ])
        .unwrap();
    let aggregation = builder
        .set_aggregation_statement_layout(left_schema.clone(), right_schema.clone())
        .unwrap();
    assert_eq!(aggregation.left(), &left_schema);
    assert_eq!(aggregation.right(), &right_schema);
    assert_eq!(aggregation.split_at(), 1);
    let circuit = builder.build().unwrap();

    let preprocessors: Vec<Box<dyn NpoPreprocessor<BabyBear>>> =
        vec![Box::new(StatementPreprocessor::new(schema.clone()))];
    let air_builders: Vec<Box<dyn NpoAirBuilder<BabyBearD4Poseidon2BinaryConfig, 1>>> =
        vec![Box::new(StatementAirBuilder::<1>::new(schema.clone()))];
    let mut prover = BatchStarkProver::new(config)
        .with_table_packing(TablePacking::new(4, 4).with_min_trace_height(32));
    prover.register_table_prover(Box::new(StatementProver::<1>::new(schema)));
    let prepared = prover
        .prepare_circuit::<BabyBear, 1>(
            &circuit,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();
    let prove = |statement: [u32; 2]| {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&statement.map(BabyBear::from_u32))
            .unwrap();
        prepared.prove(&runner.run().unwrap()).unwrap()
    };
    let first_proof = prove([7, 9]);
    let second_proof = prove([11, 13]);
    let native_verifier = prepared.verifier();
    let verifier_bytes = native_verifier.encode_verifier_artifact(limits).unwrap();
    let first_bytes = native_verifier
        .encode_proof_artifact(&first_proof, limits)
        .unwrap();
    let second_bytes = native_verifier
        .encode_proof_artifact(&second_proof, limits)
        .unwrap();

    drop(first_proof);
    drop(second_proof);
    drop(native_verifier);
    drop(prepared);
    drop(air_builders);
    drop(preprocessors);
    drop(circuit);

    let imported = PortableVerifier::decode(
        &verifier_bytes,
        ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
        limits,
    )
    .unwrap();
    let retained = imported.clone();
    drop(imported);
    assert_eq!(
        retained.schema().fields(),
        &[StatementField::Base, StatementField::Base]
    );
    let first_statement = canonical_baby_bear_statement(&[7, 9]);
    let second_statement = canonical_baby_bear_statement(&[11, 13]);
    let swapped_statement = canonical_baby_bear_statement(&[9, 7]);
    retained
        .verify_encoded(&first_bytes, CanonicalStatement::new(&first_statement, 2))
        .unwrap();
    retained
        .verify_encoded(&second_bytes, CanonicalStatement::new(&second_statement, 2))
        .unwrap();
    assert!(
        retained
            .verify_encoded(&second_bytes, CanonicalStatement::new(&first_statement, 2),)
            .is_err()
    );
    assert!(
        retained
            .verify_encoded(&first_bytes, CanonicalStatement::new(&swapped_statement, 2),)
            .is_err()
    );
    let modulus = (BabyBear::ORDER_U64 as u32).to_le_bytes();
    let mut non_canonical = modulus.to_vec();
    non_canonical.extend(9_u32.to_le_bytes());
    assert!(
        retained
            .verify_encoded(&first_bytes, CanonicalStatement::new(&non_canonical, 2),)
            .is_err()
    );
    assert!(
        retained
            .verify_encoded(&first_bytes, CanonicalStatement::new(&first_statement, 1),)
            .is_err()
    );
}
