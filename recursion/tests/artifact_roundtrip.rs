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
use p3_keccak::Keccak256Hash;
use p3_koala_bear::KoalaBear;
use p3_recursion::artifact::{
    ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact, PortableArtifactExport,
    PortableVerifier,
};
use p3_recursion::builtin_config::{
    baby_bear_d4_poseidon2_binary, baby_bear_d4_poseidon2_quaternary,
    baby_bear_d4_poseidon2_random_codeword, baby_bear_d4_poseidon2_whir,
    goldilocks_d2_poseidon2_binary, koala_bear_d4_poseidon2_salted, koala_bear_d4_poseidon2_whir,
    koala_bear_d5_poseidon2_binary, BabyBearD4Poseidon2BinaryConfig, FriConfigV1,
    KoalaBearD4Poseidon2SaltedConfig, SuiteIdV1, WhirConfigV1, WhirRateModeV1,
    WhirSecurityAssumptionV1,
};
use p3_symmetric::CryptographicHasher;
use rand::rngs::StdRng;
use rand::SeedableRng;

#[derive(Clone, Copy)]
struct ArtifactGolden {
    verifier_len: usize,
    verifier_digest: [u8; 32],
    proof_len: usize,
    proof_digest: [u8; 32],
}

fn keccak256(bytes: &[u8]) -> [u8; 32] {
    Keccak256Hash.hash_slice(bytes)
}

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
    ($field:ty, $config:expr, $min_height:expr, $golden:expr) => {
        portable_roundtrip!($field, $config, $min_height, $golden, |_| {})
    };
    ($field:ty, $config:expr, $min_height:expr, $golden:expr, $setup_check:expr) => {{
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
        let golden = $golden;
        assert_eq!(verifier_bytes.len(), golden.verifier_len);
        assert_eq!(keccak256(&verifier_bytes), golden.verifier_digest);
        assert_eq!(proof_bytes.len(), golden.proof_len);
        assert_eq!(keccak256(&proof_bytes), golden.proof_digest);
        ($setup_check)(&verifier);

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

const BABY_BEAR_D4_BINARY_GOLDEN: ArtifactGolden = ArtifactGolden {
    verifier_len: 235,
    verifier_digest: [
        0xe3, 0x02, 0xfe, 0x94, 0xb1, 0x6a, 0xe6, 0xdc, 0xe8, 0xab, 0x2c, 0x1f, 0x65, 0xb1, 0x4a,
        0xb3, 0xd4, 0xe4, 0xad, 0x2b, 0xd3, 0x76, 0x5e, 0xd6, 0x7d, 0x64, 0x7d, 0xdb, 0xbc, 0xa3,
        0xb4, 0x66,
    ],
    proof_len: 6051,
    proof_digest: [
        0xde, 0xad, 0xb6, 0x5e, 0x04, 0x62, 0x6f, 0x43, 0xc7, 0x8c, 0x8c, 0xda, 0xa5, 0x14, 0xaa,
        0x60, 0x8d, 0xbe, 0x79, 0x4d, 0x49, 0x96, 0x22, 0x68, 0xe5, 0xf5, 0x25, 0x64, 0xc7, 0xf4,
        0xce, 0x22,
    ],
};

const GOLDILOCKS_D2_BINARY_GOLDEN: ArtifactGolden = ArtifactGolden {
    verifier_len: 235,
    verifier_digest: [
        0x2c, 0x1b, 0x9c, 0x24, 0xca, 0xc7, 0xaf, 0x29, 0x8c, 0x2f, 0x5f, 0x15, 0xc6, 0xdc, 0x12,
        0xb3, 0xac, 0x1e, 0xcc, 0x32, 0xa1, 0xc5, 0x33, 0xfe, 0x56, 0x42, 0x01, 0x03, 0x61, 0x1c,
        0x13, 0x9d,
    ],
    proof_len: 5131,
    proof_digest: [
        0x1f, 0xd5, 0x52, 0xa1, 0xce, 0x5f, 0x79, 0xbf, 0xb0, 0xf7, 0x04, 0xb8, 0x6f, 0xdf, 0xf9,
        0xf8, 0x7a, 0x0c, 0xda, 0x75, 0xd9, 0xdc, 0xaa, 0x99, 0x1a, 0x5a, 0x85, 0x43, 0x46, 0xcc,
        0x10, 0x36,
    ],
};

const KOALA_BEAR_D5_BINARY_GOLDEN: ArtifactGolden = ArtifactGolden {
    verifier_len: 235,
    verifier_digest: [
        0x57, 0x31, 0xa2, 0x52, 0x36, 0x9a, 0xd0, 0x85, 0xb7, 0xcb, 0x0b, 0x4a, 0x38, 0xe6, 0xe0,
        0x82, 0xa8, 0xe0, 0xc3, 0x6b, 0x1e, 0x8d, 0xe3, 0x68, 0xcf, 0x31, 0x5d, 0xc2, 0x32, 0xd2,
        0x87, 0x0e,
    ],
    proof_len: 7299,
    proof_digest: [
        0x2c, 0x5c, 0x02, 0xc0, 0x10, 0xaf, 0x5b, 0x42, 0x37, 0x72, 0x8a, 0xaf, 0x2c, 0xd6, 0xce,
        0x03, 0x08, 0x19, 0xd1, 0x75, 0x23, 0x76, 0x77, 0xbe, 0xa7, 0x89, 0x59, 0xdc, 0x3c, 0x6f,
        0x0a, 0xd2,
    ],
};

const BABY_BEAR_QUATERNARY_GOLDEN: ArtifactGolden = ArtifactGolden {
    verifier_len: 235,
    verifier_digest: [
        0x34, 0x2c, 0x63, 0x62, 0xd9, 0xfe, 0xdc, 0xc8, 0x04, 0x7a, 0x03, 0xf0, 0xee, 0x50, 0x34,
        0x90, 0x58, 0xa2, 0x2b, 0x07, 0x13, 0xeb, 0xed, 0xd6, 0xfe, 0x34, 0xc7, 0xb6, 0xa7, 0xf4,
        0xef, 0x80,
    ],
    proof_len: 6275,
    proof_digest: [
        0xc3, 0x64, 0x3e, 0xc7, 0xc2, 0x70, 0x19, 0xa1, 0x4d, 0xf7, 0x2c, 0xbc, 0x8a, 0xec, 0xfd,
        0x38, 0xe6, 0x94, 0x0e, 0x58, 0xac, 0x17, 0xd8, 0xd2, 0xf2, 0x1a, 0x90, 0xdf, 0x8d, 0xbf,
        0xf7, 0xa1,
    ],
};

const BABY_BEAR_RANDOM_CODEWORD_GOLDEN: ArtifactGolden = ArtifactGolden {
    verifier_len: 235,
    verifier_digest: [
        0x36, 0x59, 0xff, 0xbb, 0xa5, 0xe8, 0xdc, 0x79, 0x8f, 0x43, 0x15, 0x6e, 0x0a, 0x61, 0x07,
        0x16, 0xa6, 0xc3, 0x3e, 0xe9, 0xde, 0x6c, 0x6e, 0xbd, 0xb0, 0xf4, 0x77, 0x4d, 0x5c, 0xa4,
        0xaf, 0xe5,
    ],
    proof_len: 9575,
    proof_digest: [
        0xa6, 0x8c, 0x8b, 0x33, 0xd1, 0x7e, 0x22, 0xa6, 0x84, 0xab, 0xb2, 0x86, 0x0a, 0x6a, 0xa1,
        0xe9, 0x3a, 0xb2, 0x95, 0x68, 0x25, 0xb4, 0xea, 0xa7, 0x9c, 0xa0, 0x30, 0xfb, 0x4d, 0x00,
        0xa8, 0xa6,
    ],
};

const KOALA_BEAR_SALTED_GOLDEN: ArtifactGolden = ArtifactGolden {
    verifier_len: 235,
    verifier_digest: [
        0xb8, 0x21, 0xc4, 0xc9, 0x39, 0x08, 0x8d, 0x41, 0xf2, 0xbe, 0xdc, 0x99, 0xc2, 0x97, 0xe2,
        0x26, 0x81, 0x2a, 0x33, 0x0e, 0xf7, 0x43, 0xe4, 0x54, 0x06, 0xd4, 0xc4, 0xf0, 0xe6, 0x60,
        0xea, 0xc4,
    ],
    proof_len: 11_327,
    proof_digest: [
        0xf7, 0xcb, 0x8a, 0xfc, 0x35, 0x24, 0xe2, 0xef, 0xac, 0x1f, 0x21, 0x10, 0xe5, 0xd3, 0xa8,
        0xa4, 0x52, 0x3f, 0x4c, 0x5f, 0x85, 0x7e, 0x66, 0xc4, 0xf3, 0x45, 0x7a, 0x2e, 0xff, 0xed,
        0x79, 0x2a,
    ],
};

const BABY_BEAR_WHIR_GOLDEN: ArtifactGolden = ArtifactGolden {
    verifier_len: 222,
    verifier_digest: [
        0xf8, 0x2f, 0x1f, 0x2b, 0xe6, 0xb6, 0x65, 0x31, 0x1b, 0x12, 0x8e, 0x60, 0xab, 0x22, 0x71,
        0x01, 0x0e, 0xc0, 0xf5, 0xb6, 0x25, 0x2a, 0x5b, 0x21, 0x5e, 0x46, 0x00, 0x68, 0x32, 0x0a,
        0xdb, 0x30,
    ],
    proof_len: 65_244,
    proof_digest: [
        0xb9, 0x0e, 0xcd, 0x8f, 0x85, 0x34, 0xcf, 0x95, 0x64, 0x07, 0x90, 0x61, 0x3e, 0x3b, 0xca,
        0xb1, 0xbb, 0xc7, 0xd3, 0x4f, 0xea, 0x76, 0xc6, 0xd6, 0xe7, 0xf2, 0x14, 0x17, 0x5e, 0x8a,
        0x4a, 0xf2,
    ],
};

const KOALA_BEAR_WHIR_GOLDEN: ArtifactGolden = ArtifactGolden {
    verifier_len: 222,
    verifier_digest: [
        0x3e, 0x9c, 0xf6, 0xce, 0x7d, 0x06, 0x99, 0xc4, 0xb5, 0xa4, 0xc0, 0x00, 0xf4, 0x1a, 0x7d,
        0x86, 0x25, 0x31, 0xb8, 0x39, 0xe1, 0xfd, 0x7a, 0x15, 0x3c, 0xd9, 0x10, 0xea, 0x26, 0x18,
        0x89, 0x36,
    ],
    proof_len: 65_660,
    proof_digest: [
        0x6e, 0xe3, 0x26, 0x15, 0x08, 0x7d, 0x2e, 0xd4, 0x04, 0xe4, 0xc4, 0xc0, 0x99, 0x2a, 0xe8,
        0x39, 0xe6, 0xc8, 0x1f, 0xd9, 0x03, 0xae, 0xed, 0x20, 0x70, 0x2c, 0x95, 0x83, 0xc2, 0xef,
        0x54, 0xb9,
    ],
};

#[test]
fn representative_native_proofs_roundtrip_each_physical_format_and_field_dimension() {
    let limits = ArtifactLimits::default();

    let descriptor = fri_descriptor(SuiteIdV1::BabyBearD4Poseidon2BinaryFri);
    portable_roundtrip!(
        BabyBear,
        baby_bear_d4_poseidon2_binary(&descriptor, &limits.verifier).unwrap(),
        32,
        BABY_BEAR_D4_BINARY_GOLDEN
    );

    let descriptor = fri_descriptor(SuiteIdV1::GoldilocksD2Poseidon2BinaryFri);
    portable_roundtrip!(
        Goldilocks,
        goldilocks_d2_poseidon2_binary(&descriptor, &limits.verifier).unwrap(),
        32,
        GOLDILOCKS_D2_BINARY_GOLDEN
    );

    let descriptor = fri_descriptor(SuiteIdV1::KoalaBearD5Poseidon2BinaryFri);
    portable_roundtrip!(
        KoalaBear,
        koala_bear_d5_poseidon2_binary(&descriptor, &limits.verifier).unwrap(),
        32,
        KOALA_BEAR_D5_BINARY_GOLDEN
    );

    let descriptor = fri_descriptor(SuiteIdV1::BabyBearD4Poseidon2QuaternaryFri);
    portable_roundtrip!(
        BabyBear,
        baby_bear_d4_poseidon2_quaternary(&descriptor, &limits.verifier).unwrap(),
        32,
        BABY_BEAR_QUATERNARY_GOLDEN
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
        32,
        BABY_BEAR_RANDOM_CODEWORD_GOLDEN
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
        32,
        KOALA_BEAR_SALTED_GOLDEN,
        |verifier: &p3_circuit_prover::CircuitVerifier<
            KoalaBearD4Poseidon2SaltedConfig<StdRng>,
        >| {
            let preprocessed = verifier
                .common_data()
                .preprocessed
                .as_ref()
                .expect("salted verifier must retain trusted setup common data");
            assert!(!preprocessed.commitment.roots().is_empty());
            assert!(preprocessed
                .commitment
                .roots()
                .iter()
                .any(|root| root.iter().any(|limb| *limb != KoalaBear::ZERO)));
        }
    );

    let descriptor = whir_descriptor(SuiteIdV1::BabyBearD4Poseidon2Whir);
    portable_roundtrip!(
        BabyBear,
        baby_bear_d4_poseidon2_whir(&descriptor, &limits.verifier).unwrap(),
        64,
        BABY_BEAR_WHIR_GOLDEN
    );

    let descriptor = whir_descriptor(SuiteIdV1::KoalaBearD4Poseidon2Whir);
    portable_roundtrip!(
        KoalaBear,
        koala_bear_d4_poseidon2_whir(&descriptor, &limits.verifier).unwrap(),
        64,
        KOALA_BEAR_WHIR_GOLDEN
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
    assert!(retained
        .verify_encoded(&second_bytes, CanonicalStatement::new(&first_statement, 2),)
        .is_err());
    assert!(retained
        .verify_encoded(&first_bytes, CanonicalStatement::new(&swapped_statement, 2),)
        .is_err());
    let modulus = (BabyBear::ORDER_U64 as u32).to_le_bytes();
    let mut non_canonical = modulus.to_vec();
    non_canonical.extend(9_u32.to_le_bytes());
    assert!(retained
        .verify_encoded(&first_bytes, CanonicalStatement::new(&non_canonical, 2),)
        .is_err());
    assert!(retained
        .verify_encoded(&first_bytes, CanonicalStatement::new(&first_statement, 1),)
        .is_err());
}
