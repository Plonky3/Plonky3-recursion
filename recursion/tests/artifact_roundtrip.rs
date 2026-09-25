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
    BabyBearD4Poseidon2BinaryConfig, FriConfigV1, KoalaBearD4Poseidon2SaltedConfig, SuiteIdV1,
    WhirConfigV1, WhirRateModeV1, WhirSecurityAssumptionV1, baby_bear_d4_poseidon2_binary,
    baby_bear_d4_poseidon2_quaternary, baby_bear_d4_poseidon2_random_codeword,
    baby_bear_d4_poseidon2_whir, goldilocks_d2_poseidon2_binary, koala_bear_d4_poseidon2_salted,
    koala_bear_d4_poseidon2_whir, koala_bear_d5_poseidon2_binary,
};
use p3_symmetric::CryptographicHasher;
use rand::SeedableRng;
use rand::rngs::StdRng;

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
        if spec.is_hiding() { 4 } else { 0 },
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
        0x60, 0x4b, 0x15, 0x65, 0xc8, 0xe0, 0x40, 0x3f, 0xfc, 0xaf, 0x56, 0x5a, 0x1b, 0x8c, 0xe5,
        0xa9, 0x37, 0xcd, 0x12, 0x28, 0x29, 0xd3, 0x9a, 0xa9, 0x6f, 0x82, 0xc3, 0x0d, 0xc8, 0xcd,
        0x33, 0x76,
    ],
    proof_len: 6061,
    proof_digest: [
        0xc0, 0xd4, 0x67, 0x7f, 0x99, 0xbf, 0x15, 0xc8, 0xdc, 0x59, 0xaa, 0xa7, 0xc3, 0x59, 0x5d,
        0x21, 0xf1, 0xc2, 0x33, 0xae, 0xcd, 0xb5, 0xe0, 0xbf, 0x71, 0x6a, 0x09, 0x5c, 0xe3, 0xa8,
        0x82, 0x44,
    ],
};

const GOLDILOCKS_D2_BINARY_GOLDEN: ArtifactGolden = ArtifactGolden {
    verifier_len: 235,
    verifier_digest: [
        0xed, 0x92, 0xa2, 0x36, 0x42, 0x50, 0xc6, 0x69, 0x5e, 0x8b, 0xb1, 0x99, 0x8e, 0x0e, 0x39,
        0x69, 0x8b, 0xdf, 0xb2, 0xb5, 0xcc, 0x75, 0x28, 0x60, 0x37, 0xf7, 0x8c, 0x58, 0xca, 0x1f,
        0x5c, 0xad,
    ],
    proof_len: 5601,
    proof_digest: [
        0x38, 0x2b, 0x20, 0x66, 0x02, 0xc6, 0x75, 0xbc, 0x72, 0x44, 0xc7, 0x3d, 0x90, 0x69, 0xe3,
        0x17, 0x5e, 0x36, 0x14, 0x6e, 0x2f, 0xc4, 0x25, 0x58, 0xb6, 0xe2, 0x8e, 0x5d, 0x05, 0x9f,
        0x84, 0x8c,
    ],
};

const KOALA_BEAR_D5_BINARY_GOLDEN: ArtifactGolden = ArtifactGolden {
    verifier_len: 235,
    verifier_digest: [
        0x2c, 0xaf, 0x85, 0xa3, 0x07, 0xb8, 0xd7, 0x86, 0xf0, 0x82, 0x38, 0xd7, 0xf1, 0x06, 0xa9,
        0x5e, 0xed, 0x62, 0x99, 0xbb, 0x63, 0x2d, 0xb5, 0xf0, 0x42, 0xeb, 0x94, 0x38, 0x26, 0xdc,
        0xc3, 0x39,
    ],
    proof_len: 7309,
    proof_digest: [
        0xfc, 0xf0, 0x92, 0xb1, 0xad, 0x4d, 0x9f, 0x0a, 0x8c, 0xda, 0x58, 0xa5, 0xf3, 0x79, 0xd8,
        0xb6, 0x37, 0xc0, 0xd7, 0xe8, 0x26, 0x29, 0xbd, 0x7e, 0x1a, 0x2c, 0xdd, 0x75, 0x26, 0xe2,
        0xc9, 0x8e,
    ],
};

const BABY_BEAR_QUATERNARY_GOLDEN: ArtifactGolden = ArtifactGolden {
    verifier_len: 235,
    verifier_digest: [
        0xdd, 0xaf, 0x5a, 0x38, 0x10, 0x66, 0x2b, 0x60, 0x11, 0xe3, 0x8f, 0x09, 0x27, 0x2f, 0xc0,
        0x06, 0xac, 0x91, 0xe6, 0x7c, 0x61, 0x50, 0xea, 0xeb, 0x0c, 0x8d, 0xe0, 0x7b, 0x2f, 0xf3,
        0x18, 0x27,
    ],
    proof_len: 6701,
    proof_digest: [
        0xa8, 0xc1, 0x40, 0x27, 0x30, 0xfb, 0x27, 0x45, 0x52, 0x9f, 0xc7, 0x43, 0xd8, 0xf7, 0x9a,
        0x08, 0xb4, 0x71, 0xd7, 0xd0, 0xc1, 0x7f, 0x01, 0xf9, 0xc2, 0xa1, 0xb3, 0x03, 0xa3, 0x21,
        0x72, 0x22,
    ],
};

const BABY_BEAR_RANDOM_CODEWORD_GOLDEN: ArtifactGolden = ArtifactGolden {
    verifier_len: 235,
    verifier_digest: [
        0x90, 0x4f, 0x6c, 0x36, 0x60, 0xf0, 0xc4, 0x06, 0xc5, 0xbe, 0x7a, 0x30, 0x66, 0x64, 0x42,
        0x21, 0x1b, 0x91, 0x11, 0x63, 0xc1, 0x87, 0x44, 0xf8, 0xba, 0xd8, 0x8d, 0x8c, 0xf0, 0x0f,
        0xde, 0x9f,
    ],
    proof_len: 11_329,
    proof_digest: [
        0x08, 0x5d, 0xd8, 0x5c, 0x61, 0xca, 0xda, 0xc6, 0x10, 0x76, 0x1f, 0x35, 0x4e, 0xb1, 0x47,
        0xaa, 0x61, 0xcd, 0x4c, 0xa5, 0xae, 0x77, 0x02, 0x4a, 0x64, 0xaf, 0xec, 0xf1, 0xb4, 0x9f,
        0x27, 0xe6,
    ],
};

const KOALA_BEAR_SALTED_GOLDEN: ArtifactGolden = ArtifactGolden {
    verifier_len: 235,
    verifier_digest: [
        0x4b, 0x16, 0xc1, 0x3f, 0x3d, 0x90, 0x42, 0xa7, 0x77, 0xc2, 0x67, 0xd6, 0x14, 0x5f, 0x69,
        0xdd, 0x3f, 0x26, 0xe0, 0x42, 0x5b, 0x78, 0x9a, 0x64, 0x2b, 0x24, 0x81, 0x78, 0x09, 0x21,
        0x2b, 0xe3,
    ],
    proof_len: 12_665,
    proof_digest: [
        0x30, 0xa8, 0xff, 0xa2, 0x75, 0xc5, 0x69, 0x50, 0xdc, 0xf5, 0x46, 0xa3, 0xc0, 0x33, 0x3d,
        0x56, 0x08, 0xbf, 0x8f, 0xca, 0xdb, 0xda, 0xc8, 0x82, 0xce, 0x98, 0x25, 0x8b, 0x76, 0xdb,
        0x53, 0x83,
    ],
};

const BABY_BEAR_WHIR_GOLDEN: ArtifactGolden = ArtifactGolden {
    verifier_len: 222,
    verifier_digest: [
        0xb0, 0x45, 0xad, 0x3f, 0x55, 0x9a, 0xab, 0xcf, 0x4d, 0xf7, 0x22, 0x00, 0x89, 0x9b, 0xda,
        0xb5, 0x60, 0x16, 0xc5, 0x0f, 0x34, 0xf2, 0xaa, 0xb9, 0xff, 0x43, 0xb1, 0xef, 0xd2, 0x12,
        0x62, 0x8b,
    ],
    proof_len: 65_829,
    proof_digest: [
        0xdf, 0x8a, 0x6d, 0x57, 0x12, 0x8a, 0xe2, 0x57, 0xbf, 0xce, 0xf3, 0x96, 0x6d, 0xa1, 0x7e,
        0x16, 0x62, 0xc6, 0xc6, 0x80, 0xdc, 0xde, 0x6c, 0x7b, 0x64, 0x62, 0x28, 0x22, 0x50, 0x5c,
        0x9c, 0x59,
    ],
};

const KOALA_BEAR_WHIR_GOLDEN: ArtifactGolden = ArtifactGolden {
    verifier_len: 222,
    verifier_digest: [
        0xe6, 0x88, 0x55, 0x0f, 0x33, 0xeb, 0xe4, 0xca, 0x4e, 0xdc, 0x89, 0xb9, 0x55, 0x95, 0x18,
        0x0f, 0x0a, 0xe9, 0xcb, 0xd5, 0x1c, 0x0b, 0xed, 0x38, 0xad, 0xdf, 0x17, 0x0b, 0x08, 0x2d,
        0x1e, 0x5b,
    ],
    proof_len: 66_213,
    proof_digest: [
        0x99, 0xf8, 0xbf, 0x78, 0x09, 0xf0, 0x23, 0xe8, 0x95, 0x0f, 0x40, 0x4d, 0x5d, 0x49, 0x12,
        0x45, 0x1d, 0x07, 0x18, 0x52, 0xe4, 0xdd, 0x2d, 0xa7, 0xdd, 0xdc, 0xef, 0x2b, 0x2b, 0xea,
        0x68, 0x73,
    ],
};

/// The golden bytes need reproducible proofs. The hiding configurations draw their masks from a
/// seeded RNG, but the batch prover computes instance quotients in parallel and each one draws
/// from that shared RNG, so under the `parallel` feature the draw order, and with it the proof,
/// depends on thread scheduling. One worker thread restores the sequential order.
#[test]
fn representative_native_proofs_roundtrip_each_physical_format_and_field_dimension() {
    rayon::ThreadPoolBuilder::new()
        .num_threads(1)
        .build()
        .unwrap()
        .install(roundtrip_representative_native_proofs);
}

fn roundtrip_representative_native_proofs() {
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
            assert!(
                preprocessed
                    .commitment
                    .roots()
                    .iter()
                    .any(|root| root.iter().any(|limb| *limb != KoalaBear::ZERO))
            );
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
