use std::sync::Arc;

use p3_baby_bear::BabyBear;
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_koala_bear::KoalaBear;
use p3_recursion::artifact::{
    ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact, PortableArtifactExport,
    PortableArtifactImport, PortableVerifier, TypedArtifactVerifier,
};
use p3_recursion::backend::whir::WhirRecursionBackend;
use p3_recursion::builtin_config::{
    BabyBearD4Poseidon2WhirConfig, KoalaBearD4Poseidon2WhirConfig, SuiteIdV1, WhirConfigV1,
    WhirRateModeV1, WhirSecurityAssumptionV1, baby_bear_d4_poseidon2_whir,
    koala_bear_d4_poseidon2_whir,
};
use p3_recursion::{
    BatchOnly, Poseidon2Config, ProveNextLayerParams, TrustedPreparedInput, TrustedPreparedLayer,
    TrustedPreparedSource,
};
use p3_uni_stark::{prove, verify};

fn fibonacci_output<F: PrimeCharacteristicRing + Copy>(a: u64, b: u64, n: usize) -> F {
    let (mut a, mut b) = (F::from_u64(a), F::from_u64(b));
    for _ in 1..n {
        (a, b) = (b, a + b);
    }
    b
}

fn statement_bytes<F: PrimeField32>(statement: &[F]) -> Vec<u8> {
    statement
        .iter()
        .flat_map(|value| value.as_canonical_u32().to_le_bytes())
        .collect()
}

macro_rules! whir_lifecycle {
    ($name:ident, $field:ty, $config:ty, $factory:path, $suite:expr, $poseidon:expr) => {
        #[test]
        fn $name() {
            const N: usize = 1 << 10;
            let limits = ArtifactLimits::default();
            let descriptor = |cap| {
                WhirConfigV1::new(
                    $suite,
                    1,
                    WhirRateModeV1::Auto,
                    4,
                    WhirSecurityAssumptionV1::CapacityBound.as_u16(),
                    32,
                    0,
                    20,
                    cap,
                )
            };
            let child = $factory(&descriptor(1), &limits.verifier).unwrap();
            let output = $factory(&descriptor(0), &limits.verifier).unwrap();
            let backend = WhirRecursionBackend::<16, 8>::new($poseidon).for_extension_degree::<4>();
            let params = ProveNextLayerParams::default();
            let air = FibonacciAir {};
            let first_statement = vec![
                <$field>::from_u64(0),
                <$field>::from_u64(1),
                fibonacci_output::<$field>(0, 1, N),
            ];
            let second_statement = vec![
                <$field>::from_u64(2),
                <$field>::from_u64(3),
                fibonacci_output::<$field>(2, 3, N),
            ];
            assert_ne!(first_statement, second_statement);
            let first_leaf = prove(
                &child,
                &air,
                generate_trace_rows::<$field>(0, 1, N),
                &first_statement,
            )
            .unwrap();
            let second_leaf = prove(
                &child,
                &air,
                generate_trace_rows::<$field>(2, 3, N),
                &second_statement,
            )
            .unwrap();
            verify(&child, &air, &first_leaf, &first_statement).unwrap();
            verify(&child, &air, &second_leaf, &second_statement).unwrap();

            let owner = TrustedPreparedLayer::<$config, $config, FibonacciAir, _, 4>::new(
                TrustedPreparedSource::UniStark {
                    config: child,
                    air: &air,
                    preprocessed_commit: None,
                    proof: &first_leaf,
                    public_inputs: &first_statement,
                },
                output,
                backend.clone(),
                params.clone(),
            )
            .unwrap();
            // The prepared owner is the trusted source of this verifier identity. Retain its
            // bytes separately from the later transported verifier artifact.
            let trusted_pin = owner.verifier().encode_verifier_artifact(limits).unwrap();
            let first = owner
                .prove(TrustedPreparedInput::UniStark {
                    proof: &first_leaf,
                    public_inputs: &first_statement,
                })
                .unwrap();
            let second = owner
                .prove(TrustedPreparedInput::UniStark {
                    proof: &second_leaf,
                    public_inputs: &second_statement,
                })
                .unwrap();
            assert!(Arc::ptr_eq(&first.1, &second.1));
            let verifier = owner.verifier();
            assert_eq!(verifier.statement_layout().schema().base_len(), 3);
            verifier.verify(&first.0, &first_statement).unwrap();
            verifier.verify(&second.0, &second_statement).unwrap();
            assert!(verifier.verify(&second.0, &first_statement).is_err());

            let candidate_bytes = verifier.encode_verifier_artifact(limits).unwrap();
            let first_bytes = verifier.encode_proof_artifact(&first.0, limits).unwrap();
            let second_bytes = verifier.encode_proof_artifact(&second.0, limits).unwrap();
            let first_expected = statement_bytes(&first_statement);
            let second_expected = statement_bytes(&second_statement);
            drop(first);
            drop(second);
            drop(verifier);
            drop(owner);
            drop(first_leaf);
            drop(second_leaf);

            let importer = TypedArtifactVerifier::<$config>::decode_with_config(
                $factory(&descriptor(0), &limits.verifier).unwrap(),
                &candidate_bytes,
                ExpectedVerifierArtifact::from_trusted_bytes(&trusted_pin),
                limits,
            )
            .unwrap();
            let imported_first = importer
                .import_proof(&first_bytes, CanonicalStatement::new(&first_expected, 3))
                .unwrap();
            let imported_second = importer
                .import_proof(&second_bytes, CanonicalStatement::new(&second_expected, 3))
                .unwrap();
            assert_eq!(imported_first.statement(), &first_statement);
            assert_eq!(imported_second.statement(), &second_statement);
            drop(importer);
            drop(first_bytes);
            drop(second_bytes);
            drop(candidate_bytes);
            drop(trusted_pin);

            let second_owner = TrustedPreparedLayer::<$config, $config, BatchOnly, _, 4>::new(
                imported_first.as_source(),
                $factory(&descriptor(0), &limits.verifier).unwrap(),
                backend,
                params,
            )
            .unwrap();
            let final_pin = second_owner
                .verifier()
                .encode_verifier_artifact(limits)
                .unwrap();
            let final_output = second_owner.prove(imported_second.as_input()).unwrap();
            let final_verifier = second_owner.verifier();
            final_verifier
                .verify(&final_output.0, &second_statement)
                .unwrap();
            assert!(
                final_verifier
                    .verify(&final_output.0, &first_statement)
                    .is_err()
            );
            let final_candidate = final_verifier.encode_verifier_artifact(limits).unwrap();
            let final_proof = final_verifier
                .encode_proof_artifact(&final_output.0, limits)
                .unwrap();
            drop(final_output);
            drop(final_verifier);
            drop(second_owner);
            drop(imported_first);
            drop(imported_second);

            let portable = PortableVerifier::decode(
                &final_candidate,
                ExpectedVerifierArtifact::from_trusted_bytes(&final_pin),
                limits,
            )
            .unwrap();
            portable
                .verify_encoded(&final_proof, CanonicalStatement::new(&second_expected, 3))
                .unwrap();
            assert!(
                portable
                    .verify_encoded(&final_proof, CanonicalStatement::new(&first_expected, 3))
                    .is_err()
            );
            let mut changed = second_expected.clone();
            changed[0] ^= 1;
            assert!(
                portable
                    .verify_encoded(&final_proof, CanonicalStatement::new(&changed, 3))
                    .is_err()
            );
        }
    };
}

whir_lifecycle!(
    baby_bear_builtin_whir_lifecycle,
    BabyBear,
    BabyBearD4Poseidon2WhirConfig,
    baby_bear_d4_poseidon2_whir,
    SuiteIdV1::BabyBearD4Poseidon2Whir,
    Poseidon2Config::BABY_BEAR_D4_W16
);

whir_lifecycle!(
    koala_bear_builtin_whir_lifecycle,
    KoalaBear,
    KoalaBearD4Poseidon2WhirConfig,
    koala_bear_d4_poseidon2_whir,
    SuiteIdV1::KoalaBearD4Poseidon2Whir,
    Poseidon2Config::KOALA_BEAR_D4_W16
);
