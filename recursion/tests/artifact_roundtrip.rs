use p3_baby_bear::BabyBear;
use p3_circuit::CircuitBuilder;
use p3_circuit_prover::{BatchStarkProver, ConstraintProfile, TablePacking};
use p3_field::PrimeCharacteristicRing;
use p3_goldilocks::Goldilocks;
use p3_koala_bear::KoalaBear;
use p3_recursion::artifact::{
    ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact, PortableArtifactExport,
    PortableVerifier,
};
use p3_recursion::builtin_config::{
    FriConfigV1, SuiteIdV1, WhirConfigV1, WhirRateModeV1, WhirSecurityAssumptionV1,
    baby_bear_d4_poseidon2_binary, baby_bear_d4_poseidon2_quaternary,
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
