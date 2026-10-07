//! Real custom Poseidon1 WHIR recursion in BabyBear D4 and Goldilocks D2.

use std::sync::Arc;

#[path = "common/poseidon1_whir_config.rs"]
#[allow(clippy::duplicate_mod)]
mod poseidon1_whir_config;

use p3_circuit::ops::{NpoTypeId, Poseidon1Config};
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_circuit::{CircuitBuilder, CircuitError};
use p3_circuit_prover::batch_stark_prover::StatementProver;
use p3_circuit_prover::{BatchStarkProver, CircuitVerifier};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_recursion::backend::whir::{WhirRecursionBackend, WhirRecursionBackendForExt};
use p3_recursion::pcs::whir::uni::packed_digest_len;
use p3_recursion::{
    BatchOnly, PcsRecursionBackend, Poseidon2Config, PreparedInput, PreparedPcsRecursionBackend,
    ProveNextLayerParams, RecursionInput, RecursionOutput, TrustedPcsRecursionBackend,
    TrustedPreparedInput, TrustedPreparedLayer, TrustedPreparedSource, VerificationError,
    VerifierCircuitResult, build_and_prove_next_layer, build_next_layer_circuit,
};
use p3_uni_stark::{prove, verify};
use p3_whir::pcs::proof::QueryOpenings;
use poseidon1_whir_config::{
    BabyEF, BabyF, BabyP1WhirConfig, GoldEF, GoldF, GoldP1WhirConfig, baby_p1_whir_config,
    gold_p1_whir_config,
};

macro_rules! p1_whir_lifecycle {
    (
        $module:ident,
        config: $config_ty:ty = $config_fn:path,
        field: $field:ty,
        extension: $extension:ty,
        degree: $degree:literal,
        width: $width:literal,
        rate: $rate:literal,
        digest: $digest:literal,
        p1: $p1:expr,
        p2: $p2:expr,
        first: ($first_a:expr, $first_b:expr),
        second: ($second_a:expr, $second_b:expr)
    ) => {
        mod $module {
            use super::*;

            type Config = $config_ty;
            type F = $field;
            type EF = $extension;
            type Backend = WhirRecursionBackendForExt<$degree, $width, $rate, Poseidon1Config>;
            type WrongBackend = WhirRecursionBackendForExt<$degree, $width, $rate, Poseidon2Config>;
            const P1: Poseidon1Config = $p1;
            const P2: Poseidon2Config = $p2;
            const N: usize = 1 << 10;

            fn config() -> Config {
                $config_fn()
            }

            fn backend() -> Backend {
                WhirRecursionBackend::<$width, $rate, _>::new(P1)
                    .for_extension_degree::<$degree>()
            }

            fn wrong_backend() -> WrongBackend {
                WhirRecursionBackend::<$width, $rate, _>::new(P2)
                    .for_extension_degree::<$degree>()
            }

            fn fibonacci_output(a: u64, b: u64) -> F {
                let (mut a, mut b) = (F::from_u64(a), F::from_u64(b));
                for _ in 1..N {
                    (a, b) = (b, a + b);
                }
                b
            }

            fn statement(a: u64, b: u64) -> Vec<F> {
                vec![F::from_u64(a), F::from_u64(b), fibonacci_output(a, b)]
            }

            fn ordinary_manifest() -> Vec<NpoTypeId> {
                vec![
                    NpoTypeId::poseidon1_perm(P1.for_challenger()),
                    NpoTypeId::poseidon1_perm(P1),
                    NpoTypeId::recompose_with_coeff_lookups(),
                ]
            }

            fn manifest(output: &RecursionOutput<Config>) -> Vec<NpoTypeId> {
                output
                    .0
                    .non_primitives
                    .iter()
                    .map(|entry| entry.op_type.clone())
                    .collect()
            }

            fn native_verifier(
                config: &Config,
                params: &ProveNextLayerParams,
                owner: Option<&CircuitVerifier<Config>>,
            ) -> BatchStarkProver<Config> {
                let mut verifier = BatchStarkProver::new(config.clone())
                    .with_table_packing(params.table_packing.clone());
                verifier.register_poseidon1_table::<$degree>(P1.for_challenger());
                verifier.register_poseidon1_table::<$degree>(P1);
                verifier.register_recompose_table::<$degree>(true);
                if let Some(owner) = owner {
                    verifier.register_table_prover(Box::new(StatementProver::<$degree>::new(
                        owner.statement_layout().schema().clone(),
                    )));
                }
                verifier
            }

            fn assert_native_output(
                config: &Config,
                params: &ProveNextLayerParams,
                owner: Option<&CircuitVerifier<Config>>,
                output: &RecursionOutput<Config>,
            ) {
                assert_eq!(output.0.ext_degree, $degree);
                let mut expected = ordinary_manifest();
                if owner.is_some() {
                    expected.push(NpoTypeId::statement());
                }
                let actual = manifest(output);
                assert_eq!(actual, expected);
                assert!(actual.iter().all(|id| !id.as_str().starts_with("poseidon2_perm/")));
                native_verifier(config, params, owner)
                    .verify_all_tables::<EF>(&output.0)
                    .expect("native Poseidon1 WHIR recursion proof");
            }

            fn assert_shape_error<T>(result: Result<T, VerificationError>) {
                assert!(
                    matches!(result, Err(VerificationError::InvalidProofShape(_))),
                    "expected a typed invalid proof shape error"
                );
            }

            fn assert_wrong_degree<T>(result: Result<T, VerificationError>, got: usize) {
                match result {
                    Err(VerificationError::InvalidProofShape(message)) => assert_eq!(
                        message,
                        format!(
                            "WhirRecursionBackend supports batch proofs of ext_degree {}, got {got}",
                            $degree
                        )
                    ),
                    Err(other) => panic!("wrong typed degree rejection: {other:?}"),
                    Ok(_) => panic!("wrong extension degree must be rejected"),
                }
            }

            #[test]
            fn real_poseidon1_whir_lifecycle() -> Result<(), VerificationError> {
                let config = config();
                let backend = backend();
                let params = ProveNextLayerParams::default();
                let air = FibonacciAir {};
                let first = statement($first_a, $first_b);
                let second = statement($second_a, $second_b);
                assert_ne!(first, second);
                if $degree == 2 {
                    assert!(first[0].as_canonical_u64() > u32::MAX as u64);
                    assert!(second[0].as_canonical_u64() > u32::MAX as u64);
                }

                let mut first_leaf = prove(
                    &config,
                    &air,
                    generate_trace_rows::<F>($first_a, $first_b, N),
                    &first,
                )
                .expect("first native Poseidon1 WHIR leaf");
                let second_leaf = prove(
                    &config,
                    &air,
                    generate_trace_rows::<F>($second_a, $second_b, N),
                    &second,
                )
                .expect("second native Poseidon1 WHIR leaf");
                verify(&config, &air, &first_leaf, &first).expect("first native leaf verifies");
                verify(&config, &air, &second_leaf, &second).expect("second native leaf verifies");
                assert_eq!(packed_digest_len($digest, $degree), $digest / $degree);
                let roots = first_leaf.commitments.trace.clone().into_roots();
                assert_eq!(roots.len(), 1);
                assert!(roots.iter().all(|root| root.len() == $digest));

                let owner = TrustedPreparedLayer::<Config, Config, FibonacciAir, _, $degree>::new(
                    TrustedPreparedSource::UniStark {
                        config: config.clone(),
                        air: &air,
                        preprocessed_commit: None,
                        proof: &first_leaf,
                        public_inputs: &first,
                    },
                    config.clone(),
                    backend.clone(),
                    params.clone(),
                )?;
                let mut first_parent = owner.prove(TrustedPreparedInput::UniStark {
                    proof: &first_leaf,
                    public_inputs: &first,
                })?;
                let second_parent = owner.prove(TrustedPreparedInput::UniStark {
                    proof: &second_leaf,
                    public_inputs: &second,
                })?;
                assert!(Arc::ptr_eq(&first_parent.1, &second_parent.1));
                let parent_verifier = owner.verifier();
                assert_eq!(parent_verifier.statement_layout().schema().base_len(), 3);
                parent_verifier.verify(&first_parent.0, &first).unwrap();
                parent_verifier.verify(&second_parent.0, &second).unwrap();
                assert!(parent_verifier.verify(&first_parent.0, &second).is_err());
                assert!(parent_verifier.verify(&second_parent.0, &first).is_err());
                let mut wrong = second.clone();
                wrong[2] += F::ONE;
                assert!(parent_verifier.verify(&second_parent.0, &wrong).is_err());
                assert_native_output(&config, &params, Some(&parent_verifier), &first_parent);
                assert_native_output(&config, &params, Some(&parent_verifier), &second_parent);

                let mut ordinary_parent = build_and_prove_next_layer::<Config, FibonacciAir, Backend, $degree>(
                    &RecursionInput::UniStark {
                        proof: &first_leaf,
                        air: &air,
                        public_inputs: first.clone(),
                        preprocessed_commit: None,
                    },
                    &config,
                    &backend,
                    &params,
                )?;
                assert_native_output(&config, &params, None, &ordinary_parent);

                let trusted_as_ordinary = first_parent.into_recursion_input::<BatchOnly>();
                match <Backend as PcsRecursionBackend<Config, BatchOnly, $degree>>::validate_input(
                    &backend,
                    &config,
                    &trusted_as_ordinary,
                ) {
                    Err(VerificationError::InvalidProofShape(message)) => assert_eq!(
                        message,
                        "non-primitive table count mismatch: expected 3, got 4"
                    ),
                    Err(other) => panic!("wrong trusted-parent ordinary rejection: {other:?}"),
                    Ok(()) => panic!("ordinary route accepted a retained Statement table"),
                }

                let ordinary_input = ordinary_parent.into_recursion_input::<BatchOnly>();
                let (ordinary_circuit, ordinary_result) =
                    build_next_layer_circuit::<Config, BatchOnly, Backend, $degree>(
                        &ordinary_input,
                        &config,
                        &backend,
                    )?;
                let mut runner = ordinary_circuit.runner();
                runner
                    .set_public_inputs(&ordinary_result.pack_public_inputs(&ordinary_input)?)
                    .map_err(VerificationError::Circuit)?;
                runner
                    .set_private_inputs(&ordinary_result.pack_private_inputs(&ordinary_input)?)
                    .map_err(VerificationError::Circuit)?;
                <Backend as PcsRecursionBackend<Config, BatchOnly, $degree>>::set_private_data_for_result(
                    &backend,
                    &config,
                    &mut runner,
                    &ordinary_result,
                    &ordinary_input,
                )
                .map_err(|message| VerificationError::InvalidProofShape(message.into()))?;
                runner.run().map_err(VerificationError::Circuit)?;

                // Change only the honest ordinary parent's degree metadata, then restore it.
                let wrong_degree = if $degree == 2 { 4 } else { 2 };
                ordinary_parent.0.ext_degree = wrong_degree;
                let wrong_ordinary = ordinary_parent.into_recursion_input::<BatchOnly>();
                assert_wrong_degree(
                    <Backend as PcsRecursionBackend<Config, BatchOnly, $degree>>::validate_input(
                        &backend,
                        &config,
                        &wrong_ordinary,
                    ),
                    wrong_degree,
                );
                assert_wrong_degree(
                    build_next_layer_circuit::<Config, BatchOnly, Backend, $degree>(
                        &wrong_ordinary,
                        &config,
                        &backend,
                    ),
                    wrong_degree,
                );
                assert_wrong_degree(
                    <Backend as PreparedPcsRecursionBackend<Config, BatchOnly, $degree>>::capture_input_contract(
                        &backend,
                        &config,
                        &wrong_ordinary,
                    ),
                    wrong_degree,
                );
                let mut empty_builder = CircuitBuilder::<EF>::new();
                assert_wrong_degree(
                    <Backend as PcsRecursionBackend<Config, BatchOnly, $degree>>::build_verifier_circuit(
                        &backend,
                        &wrong_ordinary,
                        &config,
                        &mut empty_builder,
                    ),
                    wrong_degree,
                );
                let empty = empty_builder.build().map_err(VerificationError::CircuitBuilder)?;
                let baseline = CircuitBuilder::<EF>::new()
                    .build()
                    .map_err(VerificationError::CircuitBuilder)?;
                assert_eq!(empty.public_flat_len, 0);
                assert_eq!(empty.private_flat_len, 0);
                assert_eq!(empty.ops.len(), baseline.ops.len());
                assert_eq!(empty.witness_count, baseline.witness_count);
                ordinary_parent.0.ext_degree = $degree;

                let second_owner = TrustedPreparedLayer::<Config, Config, BatchOnly, _, $degree>::new(
                    TrustedPreparedSource::BatchStark {
                        verifier: parent_verifier.clone(),
                        proof: &first_parent.0,
                        statement: &first,
                    },
                    config.clone(),
                    backend.clone(),
                    params.clone(),
                )?;
                let grandparent = second_owner.prove(TrustedPreparedInput::BatchStark {
                    proof: &second_parent.0,
                    statement: &second,
                })?;
                let grandparent_verifier = second_owner.verifier();
                grandparent_verifier.verify(&grandparent.0, &second).unwrap();
                assert!(grandparent_verifier.verify(&grandparent.0, &first).is_err());
                assert_native_output(&config, &params, Some(&grandparent_verifier), &grandparent);

                // The retained batch relation rejects bad metadata on its Statement parent.
                first_parent.0.ext_degree = wrong_degree;
                let wrong_trusted = TrustedPreparedInput::BatchStark {
                    proof: &first_parent.0,
                    statement: &first,
                };
                assert_shape_error(second_owner.check_input(&wrong_trusted));
                assert_shape_error(second_owner.prove(wrong_trusted));
                first_parent.0.ext_degree = $degree;

                // A real authenticated query leaf changes, with the surrounding proof shape intact.
                match &mut first_leaf.opening_proof.rounds[0].whir.rounds[0].openings {
                    QueryOpenings::Base(opening) => opening.rows[0][0] += F::ONE,
                    QueryOpenings::Extension(opening) => opening.rows[0][0] += EF::ONE,
                }
                assert!(verify(&config, &air, &first_leaf, &first).is_err());
                let rejection = owner
                    .prove(TrustedPreparedInput::UniStark {
                        proof: &first_leaf,
                        public_inputs: &first,
                    })
                    .err()
                    .expect("authenticated leaf mutation must be rejected");
                assert!(matches!(
                    rejection,
                    VerificationError::Circuit(CircuitError::WitnessConflict { .. })
                        | VerificationError::InvalidProofShape(_)
                ));
                Ok(())
            }

            #[test]
            fn valid_native_poseidon1_input_rejects_poseidon2_backend_before_allocation()
            -> Result<(), VerificationError> {
                let config = config();
                let good_backend = backend();
                let wrong_backend = wrong_backend();
                let air = FibonacciAir {};
                let values = statement($first_a, $first_b);
                let leaf = prove(
                    &config,
                    &air,
                    generate_trace_rows::<F>($first_a, $first_b, N),
                    &values,
                )
                .expect("honest Poseidon1 WHIR leaf");
                verify(&config, &air, &leaf, &values).unwrap();
                let input = RecursionInput::UniStark {
                    proof: &leaf,
                    air: &air,
                    public_inputs: values.clone(),
                    preprocessed_commit: None,
                };

                assert_shape_error(<WrongBackend as PcsRecursionBackend<Config, FibonacciAir, $degree>>::validate_input(
                    &wrong_backend, &config, &input,
                ));
                assert_shape_error(build_next_layer_circuit::<Config, FibonacciAir, WrongBackend, $degree>(
                    &input, &config, &wrong_backend,
                ));
                let mut builder = CircuitBuilder::<EF>::new();
                assert_shape_error(<WrongBackend as PcsRecursionBackend<Config, FibonacciAir, $degree>>::build_verifier_circuit(
                    &wrong_backend, &input, &config, &mut builder,
                ));
                let empty = builder.build().map_err(VerificationError::CircuitBuilder)?;
                let baseline = CircuitBuilder::<EF>::new()
                    .build()
                    .map_err(VerificationError::CircuitBuilder)?;
                assert_eq!(empty.public_flat_len, 0);
                assert_eq!(empty.private_flat_len, 0);
                assert_eq!(empty.ops.len(), baseline.ops.len());
                assert_eq!(empty.witness_count, baseline.witness_count);

                let mut prepare_builder = CircuitBuilder::<EF>::new();
                assert_shape_error(<WrongBackend as PcsRecursionBackend<Config, FibonacciAir, $degree>>::prepare_circuit(
                    &wrong_backend, &config, &mut prepare_builder,
                ));
                let prepared_contract = <Backend as PreparedPcsRecursionBackend<Config, FibonacciAir, $degree>>::capture_input_contract(
                    &good_backend, &config, &input,
                )?;
                assert_shape_error(<WrongBackend as PreparedPcsRecursionBackend<Config, FibonacciAir, $degree>>::capture_input_contract(
                    &wrong_backend, &config, &input,
                ));
                let prepared_input = PreparedInput::UniStark {
                    proof: &leaf,
                    public_inputs: &values,
                    preprocessed_commit: None,
                };
                assert_shape_error(<WrongBackend as PreparedPcsRecursionBackend<Config, FibonacciAir, $degree>>::validate_prepared_input(
                    &wrong_backend, &config, &prepared_contract, &prepared_input,
                ));

                let params = ProveNextLayerParams::default();
                let owner = TrustedPreparedLayer::<Config, Config, FibonacciAir, _, $degree>::new(
                    TrustedPreparedSource::UniStark {
                        config: config.clone(),
                        air: &air,
                        preprocessed_commit: None,
                        proof: &leaf,
                        public_inputs: &values,
                    },
                    config.clone(),
                    good_backend.clone(),
                    params,
                )?;
                let trusted_parent = owner.prove(TrustedPreparedInput::UniStark {
                    proof: &leaf,
                    public_inputs: &values,
                })?;
                let parent_verifier = owner.verifier();
                assert_shape_error(<WrongBackend as TrustedPcsRecursionBackend<Config, BatchOnly, $degree>>::capture_trusted_batch_input_contract(
                    &wrong_backend, &parent_verifier, &trusted_parent.0, &values,
                ));
                let trusted_contract = <Backend as TrustedPcsRecursionBackend<Config, BatchOnly, $degree>>::capture_trusted_batch_input_contract(
                    &good_backend, &parent_verifier, &trusted_parent.0, &values,
                )?;
                assert_shape_error(<WrongBackend as TrustedPcsRecursionBackend<Config, BatchOnly, $degree>>::validate_trusted_batch_input(
                    &wrong_backend, &parent_verifier, &trusted_contract, &trusted_parent.0, &values,
                ));
                Ok(())
            }
        }
    };
}

p1_whir_lifecycle!(
    baby,
    config: BabyP1WhirConfig = baby_p1_whir_config,
    field: BabyF,
    extension: BabyEF,
    degree: 4,
    width: 16,
    rate: 8,
    digest: 8,
    p1: Poseidon1Config::BABY_BEAR_D4_W16,
    p2: Poseidon2Config::BABY_BEAR_D4_W16,
    first: (0, 1),
    second: (2, 3)
);

p1_whir_lifecycle!(
    gold,
    config: GoldP1WhirConfig = gold_p1_whir_config,
    field: GoldF,
    extension: GoldEF,
    degree: 2,
    width: 8,
    rate: 4,
    digest: 4,
    p1: Poseidon1Config::GOLDILOCKS_D2_W8,
    p2: Poseidon2Config::GOLDILOCKS_D2_W8,
    first: ((1 << 33) + 7, (1 << 34) + 11),
    second: ((1 << 63) + 17, (1 << 62) + 31)
);
