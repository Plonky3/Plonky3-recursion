// Shared by the concrete built-in FRI matrix. Each expansion keeps its native factory and
// backend visible at the call site; the proof lifecycle itself is identical across suites.
macro_rules! fri_lifecycle_case {
    (
        $name:ident,
        field: $field:ty,
        wire_bytes: $wire_bytes:literal,
        config: $config:ty,
        degree: $degree:literal,
        suite: $suite:expr,
        factory: $factory:expr,
        backend: $backend:expr
        $(, final_poly_log: $final_poly_log:literal, commit_pow_bits: $commit_pow_bits:literal)?
    ) => {
        #[test]
        fn $name() {
            use p3_field::{PrimeCharacteristicRing, PrimeField64};
            use p3_recursion::artifact::{
                ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact,
                PortableArtifactExport, PortableArtifactImport, PortableVerifier,
                TypedArtifactVerifier,
            };
            use p3_recursion::builtin_config::FriConfigV1;
            use p3_recursion::{
                BatchOnly, ProveNextLayerParams, TrustedPreparedInput, TrustedPreparedLayer,
                TrustedPreparedSource,
            };

            const N: usize = 32;
            let limits = ArtifactLimits::default();
            let descriptor = FriConfigV1::new(
                $suite,
                1, // log blowup
                fri_lifecycle_case!(@zero_or $($final_poly_log)?),
                2, // max log arity
                2, // queries
                fri_lifecycle_case!(@zero_or $($commit_pow_bits)?),
                0, // query grinding
                1, // input cap height
                2, // commit cap height
                if $suite.spec().is_hiding() { 4 } else { 0 },
                $suite.spec().salt_elements as u32,
            );
            let make_config = $factory;
            let make_backend = || $backend;
            let params = ProveNextLayerParams {
                table_packing: p3_circuit_prover::TablePacking::new(4, 4).with_min_trace_height(32),
                ..ProveNextLayerParams::default()
            };

            fn expected_output<F: PrimeCharacteristicRing + Copy>(
                start_a: u64,
                start_b: u64,
                n: usize,
            ) -> Vec<F> {
                let mut a = F::from_u64(start_a);
                let mut b = F::from_u64(start_b);
                for _ in 1..n {
                    let next = a + b;
                    a = b;
                    b = next;
                }
                vec![F::from_u64(start_a), F::from_u64(start_b), b]
            }

            fn encode_statement<F: PrimeField64>(statement: &[F], wire_bytes: usize) -> Vec<u8> {
                assert!(matches!(wire_bytes, 4 | 8));
                statement
                    .iter()
                    .flat_map(|value| {
                        value.as_canonical_u64().to_le_bytes()[..wire_bytes].to_vec()
                    })
                    .collect()
            }

            let expected_first = expected_output::<$field>(1, 2, N);
            let expected_second = expected_output::<$field>(3, 5, N);
            assert_ne!(expected_first, expected_second);
            let expected_first_bytes = encode_statement(&expected_first, $wire_bytes);
            let expected_second_bytes = encode_statement(&expected_second, $wire_bytes);

            // All source proofs and owners go out of scope before typed import. The statements
            // above are computed from the Fibonacci recurrence, never read from an attachment.
            let (expected_identity, verifier_bytes, first_bytes, second_bytes) = {
                let air = p3_circuit::test_utils::FibonacciAir {};
                let leaf_config = make_config(&descriptor, &limits.verifier).unwrap();
                let first_proof = p3_uni_stark::prove(
                    &leaf_config,
                    &air,
                    p3_circuit::test_utils::generate_trace_rows::<$field>(1, 2, N),
                    &expected_first,
                )
                .unwrap();
                let second_proof = p3_uni_stark::prove(
                    &leaf_config,
                    &air,
                    p3_circuit::test_utils::generate_trace_rows::<$field>(3, 5, N),
                    &expected_second,
                )
                .unwrap();
                p3_uni_stark::verify(&leaf_config, &air, &first_proof, &expected_first).unwrap();
                p3_uni_stark::verify(&leaf_config, &air, &second_proof, &expected_second).unwrap();

                let owner = TrustedPreparedLayer::<$config, $config, _, _, $degree>::new(
                    TrustedPreparedSource::UniStark {
                        config: leaf_config,
                        air: &air,
                        preprocessed_commit: None,
                        proof: &first_proof,
                        public_inputs: &expected_first,
                    },
                    make_config(&descriptor, &limits.verifier).unwrap(),
                    make_backend(),
                    params.clone(),
                )
                .unwrap();
                // The prepared owner is the trusted authority. Pin its verifier before either
                // recursive proof is made, then retain that pin when the owner goes out of scope.
                let verifier = owner.verifier();
                let expected_identity = verifier
                    .encode_verifier_artifact(limits)
                    .expect("first prepared verifier identity encodes");
                let first = owner
                    .prove(TrustedPreparedInput::UniStark {
                        proof: &first_proof,
                        public_inputs: &expected_first,
                    })
                    .unwrap();
                let second = owner
                    .prove(TrustedPreparedInput::UniStark {
                        proof: &second_proof,
                        public_inputs: &expected_second,
                    })
                .unwrap();
                assert!(std::sync::Arc::ptr_eq(&first.1, &second.1));
                verifier.verify(&first.0, &expected_first).unwrap();
                verifier.verify(&second.0, &expected_second).unwrap();
                assert!(verifier.verify(&second.0, &expected_first).is_err());
                let verifier_bytes = verifier
                    .encode_verifier_artifact(limits)
                    .expect("first verifier candidate encodes");
                let first_bytes = verifier
                    .encode_proof_artifact(&first.0, limits)
                    .expect("first recursive proof encodes");
                let second_bytes = verifier
                    .encode_proof_artifact(&second.0, limits)
                    .expect("second recursive proof encodes");
                (
                    expected_identity,
                    verifier_bytes,
                    first_bytes,
                    second_bytes,
                )
            };

            // The retained pin, rather than the received candidate bytes, anchors both imports.
            let typed = TypedArtifactVerifier::<$config>::decode_with_config(
                make_config(&descriptor, &limits.verifier).unwrap(),
                &verifier_bytes,
                ExpectedVerifierArtifact::from_trusted_bytes(&expected_identity),
                limits,
            )
            .expect("first verifier typed import");
            let imported_first = typed
                .import_proof(
                    &first_bytes,
                    CanonicalStatement::new(&expected_first_bytes, expected_first.len()),
                )
                .expect("first recursive proof typed import");
            let imported_second = typed
                .import_proof(
                    &second_bytes,
                    CanonicalStatement::new(&expected_second_bytes, expected_second.len()),
                )
                .expect("second recursive proof typed import");
            assert_eq!(imported_first.statement(), expected_first.as_slice());
            assert_eq!(imported_second.statement(), expected_second.as_slice());
            assert_eq!(imported_first.trusted_identity_bytes(), expected_identity.as_slice());
            assert_eq!(imported_second.trusted_identity_bytes(), expected_identity.as_slice());
            drop(typed);
            drop(first_bytes);
            drop(second_bytes);
            drop(verifier_bytes);

            let second_owner =
                TrustedPreparedLayer::<$config, $config, BatchOnly, _, $degree>::new(
                    imported_first.as_source(),
                    make_config(&descriptor, &limits.verifier).unwrap(),
                    make_backend(),
                    params,
                )
                .unwrap();
            let final_verifier = second_owner.verifier();
            let final_expected_identity = final_verifier
                .encode_verifier_artifact(limits)
                .expect("final prepared verifier identity encodes");
            let final_output = second_owner.prove(imported_second.as_input()).unwrap();
            final_verifier
                .verify(&final_output.0, &expected_second)
                .unwrap();
            assert!(
                final_verifier
                    .verify(&final_output.0, &expected_first)
                    .is_err()
            );
            let final_verifier_bytes = final_verifier
                .encode_verifier_artifact(limits)
                .expect("final verifier candidate encodes");
            let final_proof_bytes = final_verifier
                .encode_proof_artifact(&final_output.0, limits)
                .expect("final recursive proof encodes");
            drop(final_verifier);
            drop(final_output);
            drop(second_owner);
            drop(imported_first);
            drop(imported_second);

            TypedArtifactVerifier::<$config>::decode_with_config(
                make_config(&descriptor, &limits.verifier).unwrap(),
                &final_verifier_bytes,
                ExpectedVerifierArtifact::from_trusted_bytes(&final_expected_identity),
                limits,
            )
            .expect("final verifier typed import before portable");
            let portable = PortableVerifier::decode(
                &final_verifier_bytes,
                ExpectedVerifierArtifact::from_trusted_bytes(&final_expected_identity),
                limits,
            )
            .expect("final verifier portable import");
            portable
                .verify_encoded(
                    &final_proof_bytes,
                    CanonicalStatement::new(&expected_second_bytes, expected_second.len()),
                )
                .expect("final proof portable verification");
            assert!(
                portable
                    .verify_encoded(
                        &final_proof_bytes,
                        CanonicalStatement::new(&expected_first_bytes, expected_first.len()),
                    )
                    .is_err()
            );
        }
    };
    (@zero_or) => { 0 };
    (@zero_or $value:literal) => { $value };
}
