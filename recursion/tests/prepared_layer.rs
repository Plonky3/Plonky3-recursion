mod common;

#[path = "../examples/common/prepared_reuse.rs"]
mod example_prepared_reuse;

use std::rc::Rc;

use common::whir_config::{BbEF, BbF, BbWhirConfig, bb_whir_config};
use example_prepared_reuse::is_prepared_input_mismatch;
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_circuit_prover::batch_stark_prover::BatchStarkProver;
use p3_circuit_prover::{ConstraintProfile, TablePacking};
use p3_field::PrimeCharacteristicRing;
use p3_recursion::backend::whir::{WhirRecursionBackend, WhirRecursionBackendForExt};
use p3_recursion::profile::{HashProfile, RecursionLayerProfile, TranscriptKind};
use p3_recursion::{
    BatchOnly, Poseidon2Config, PreparedInput, PreparedLayer, PreparedSource, ProveNextLayerParams,
    RecursionInput, RecursionOutput, TrustedPreparedInput, TrustedPreparedLayer,
    TrustedPreparedSource, VerificationError, build_and_prove_next_layer,
};
use p3_test_utils::koala_bear_params::{Challenge, F};
use p3_uni_stark::{prove, verify};

fn fibonacci_output<Fld: PrimeCharacteristicRing + Copy>(
    start_a: u64,
    start_b: u64,
    n: usize,
) -> Fld {
    let mut a = Fld::from_u64(start_a);
    let mut b = Fld::from_u64(start_b);
    if n == 0 {
        return a;
    }
    for _ in 1..n {
        let next = a + b;
        a = b;
        b = next;
    }
    b
}

fn assert_preprocessing_is_retained<SC>(output: &RecursionOutput<SC>)
where
    SC: p3_uni_stark::StarkGenericConfig,
    <SC::Pcs as p3_commit::Pcs<SC::Challenge, SC::Challenger>>::Commitment: PartialEq,
{
    assert!(
        output
            .0
            .stark_common
            .preprocessed
            .as_ref()
            .map(|data| &data.commitment)
            == output
                .1
                .common_data()
                .preprocessed
                .as_ref()
                .map(|data| &data.commitment)
    );
}

fn verify_fri_output(
    config: common::KoalaBearD4RecursionConfig,
    params: &ProveNextLayerParams,
    output: &RecursionOutput<common::KoalaBearD4RecursionConfig>,
) {
    let mut verifier =
        BatchStarkProver::new(config).with_table_packing(params.table_packing.clone());
    verifier.register_poseidon2_table::<4>(Poseidon2Config::KOALA_BEAR_D4_W16.for_challenger());
    verifier.register_poseidon2_table::<4>(Poseidon2Config::KOALA_BEAR_D4_W16);
    verifier.register_recompose_table::<4>(true);
    verifier
        .verify_all_tables::<Challenge>(&output.0)
        .expect("the recursive proof verifies");
    assert_preprocessing_is_retained(output);
}

fn verify_whir_output(
    config: BbWhirConfig,
    params: &ProveNextLayerParams,
    output: &RecursionOutput<BbWhirConfig>,
) {
    let mut verifier =
        BatchStarkProver::new(config).with_table_packing(params.table_packing.clone());
    verifier.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16.for_challenger());
    verifier.register_poseidon2_table::<4>(Poseidon2Config::BABY_BEAR_D4_W16);
    verifier.register_recompose_table::<4>(true);
    verifier
        .verify_all_tables::<BbEF>(&output.0)
        .expect("the recursive proof verifies");
    assert_preprocessing_is_retained(output);
}

fn build_whir_first_layer(
    config: &BbWhirConfig,
    backend: &WhirRecursionBackendForExt<4>,
    params: &ProveNextLayerParams,
    start_a: u64,
    start_b: u64,
) -> RecursionOutput<BbWhirConfig> {
    let n = 1 << 10;
    let air = FibonacciAir {};
    let pis = vec![
        BbF::from_u64(start_a),
        BbF::from_u64(start_b),
        fibonacci_output::<BbF>(start_a, start_b, n),
    ];
    let proof = prove(
        config,
        &air,
        generate_trace_rows::<BbF>(start_a, start_b, n),
        &pis,
    );
    verify(config, &air, &proof, &pis).expect("the native WHIR proof verifies");
    build_and_prove_next_layer(
        &RecursionInput::UniStark {
            proof: &proof,
            air: &air,
            public_inputs: pis,
            preprocessed_commit: None,
        },
        config,
        backend,
        params,
    )
    .expect("the first WHIR recursion layer proves")
}

#[test]
fn fri_uni_prepared_layer_reuses_varied_witnesses_after_reference_drop() {
    let log_n = 10;
    let n = 1 << log_n;
    let air = FibonacciAir {};
    let (config, backend) = common::koala_bear_d4_recursion_config_and_backend();
    let params = ProveNextLayerParams::default();

    let (prepared, out1) = {
        let pis = vec![F::ZERO, F::ONE, fibonacci_output::<F>(0, 1, n)];
        let proof = prove(&config, &air, generate_trace_rows::<F>(0, 1, n), &pis);
        verify(&config, &air, &proof, &pis).expect("the trusted reference proof verifies");
        let prepared = PreparedLayer::<
            common::KoalaBearD4RecursionConfig,
            FibonacciAir,
            common::KoalaBearD4Backend,
            4,
        >::new(
            PreparedSource::UniStark {
                air: &air,
                proof: &proof,
                public_inputs: &pis,
                preprocessed_commit: None,
            },
            config.clone(),
            backend,
            params.clone(),
        )
        .expect("the trusted reference prepares");
        let out = prepared
            .prove(PreparedInput::UniStark {
                proof: &proof,
                public_inputs: &pis,
                preprocessed_commit: None,
            })
            .expect("the reference witness proves");
        (prepared, out)
    };

    let second_pis = vec![
        F::from_u64(2),
        F::from_u64(3),
        fibonacci_output::<F>(2, 3, n),
    ];
    let second = prove(
        &config,
        &air,
        generate_trace_rows::<F>(2, 3, n),
        &second_pis,
    );
    verify(&config, &air, &second, &second_pis).expect("the varied native proof verifies");
    let out2 = prepared
        .prove(PreparedInput::UniStark {
            proof: &second,
            public_inputs: &second_pis,
            preprocessed_commit: None,
        })
        .expect("the varied witness proves with the prepared owner");

    let verifier = prepared.verifier();
    verifier.verify(&out1.0, &[]).unwrap();
    verifier.verify(&out2.0, &[]).unwrap();
    assert!(Rc::ptr_eq(&out1.1, &out2.1));
    assert!(prepared.profile().is_none());
    assert_eq!(
        prepared.params().table_packing,
        params.table_packing,
        "the owner retains its resolved parameters"
    );
    verify_fri_output(config.clone(), &params, &out1);
    verify_fri_output(config, &params, &out2);
}

#[test]
fn fri_uni_profile_prepared_layer_reuses_varied_witnesses() {
    let log_n = 10;
    let n = 1 << log_n;
    let air = FibonacciAir {};
    let (config, backend) = common::koala_bear_d4_recursion_config_and_backend();
    let profile = RecursionLayerProfile {
        table_packing: TablePacking::default().with_horner_pack_k(4),
        hash: HashProfile::default(),
        transcript: TranscriptKind::default(),
        constraint_profile: ConstraintProfile::Standard,
    };

    let first_pis = vec![F::ZERO, F::ONE, fibonacci_output::<F>(0, 1, n)];
    let first = prove(&config, &air, generate_trace_rows::<F>(0, 1, n), &first_pis);
    let prepared = PreparedLayer::<
        common::KoalaBearD4RecursionConfig,
        FibonacciAir,
        common::KoalaBearD4Backend,
        4,
    >::new_with_profile(
        PreparedSource::UniStark {
            air: &air,
            proof: &first,
            public_inputs: &first_pis,
            preprocessed_commit: None,
        },
        config.clone(),
        backend,
        profile.clone(),
    )
    .expect("the profile-owned verifier prepares");

    let first_output = prepared
        .prove(PreparedInput::UniStark {
            proof: &first,
            public_inputs: &first_pis,
            preprocessed_commit: None,
        })
        .expect("the first profile-owned witness proves");
    let second_pis = vec![
        F::from_u64(2),
        F::from_u64(3),
        fibonacci_output::<F>(2, 3, n),
    ];
    let second = prove(
        &config,
        &air,
        generate_trace_rows::<F>(2, 3, n),
        &second_pis,
    );
    let second_output = prepared
        .prove(PreparedInput::UniStark {
            proof: &second,
            public_inputs: &second_pis,
            preprocessed_commit: None,
        })
        .expect("the second profile-owned witness proves");

    assert_eq!(prepared.profile(), Some(&profile));
    assert_eq!(prepared.params().table_packing, profile.table_packing);
    assert_eq!(
        prepared.params().constraint_profile,
        profile.constraint_profile
    );
    assert!(Rc::ptr_eq(&first_output.1, &second_output.1));
}

#[test]
fn fri_uni_profile_owner_matches_params_owner_bytes() {
    let n = 1 << 10;
    let air = FibonacciAir {};
    // Parallel PoW grinding may choose different valid nonzero witnesses. This byte-for-byte
    // ownership comparison needs a deterministic transcript, so disable PoW for this fixture.
    let (config, backend) = common::koala_bear_d4_recursion_config_and_backend_with_pow_bits(0);
    let pis = vec![F::ZERO, F::ONE, fibonacci_output::<F>(0, 1, n)];
    let proof = prove(&config, &air, generate_trace_rows::<F>(0, 1, n), &pis);
    let params = ProveNextLayerParams {
        table_packing: TablePacking::default(),
        constraint_profile: ConstraintProfile::Standard,
    };
    let profile = RecursionLayerProfile {
        table_packing: params.table_packing.clone(),
        hash: HashProfile::default(),
        transcript: TranscriptKind::default(),
        constraint_profile: params.constraint_profile,
    };
    let source = || PreparedSource::UniStark {
        air: &air,
        proof: &proof,
        public_inputs: &pis,
        preprocessed_commit: None,
    };
    let input = || PreparedInput::UniStark {
        proof: &proof,
        public_inputs: &pis,
        preprocessed_commit: None,
    };

    let params_owner = PreparedLayer::<
        common::KoalaBearD4RecursionConfig,
        FibonacciAir,
        common::KoalaBearD4Backend,
        4,
    >::new(source(), config.clone(), backend.clone(), params)
    .expect("the params-owned verifier prepares");
    let profile_owner = PreparedLayer::<
        common::KoalaBearD4RecursionConfig,
        FibonacciAir,
        common::KoalaBearD4Backend,
        4,
    >::new_with_profile(source(), config, backend, profile)
    .expect("the profile-owned verifier prepares");

    let params_output = params_owner
        .prove(input())
        .expect("the params-owned witness proves");
    let profile_output = profile_owner
        .prove(input())
        .expect("the profile-owned witness proves");
    assert_eq!(
        postcard::to_allocvec(&params_output.0).expect("serialize params-owned proof"),
        postcard::to_allocvec(&profile_output.0).expect("serialize profile-owned proof"),
        "identical ordinary-FRI owners must produce byte-identical proofs"
    );
}

#[test]
fn fri_batch_prepared_layer_reuses_prover_data() {
    let fixture = common::build_koala_bear_d4_first_layer_input_with_starts(0, 1);
    let second = common::build_koala_bear_d4_first_layer_input_with_starts(2, 3);
    let table_public_inputs = vec![vec![]; fixture.base_proof.proof.opened_values.instances.len()];
    let params = ProveNextLayerParams::default();
    let config = fixture.layer_config.clone();
    let (prepared, out1) = {
        let prepared = PreparedLayer::<_, BatchOnly, _, 4>::new(
            PreparedSource::batch(
                &fixture.base_proof,
                &fixture.base_proof.stark_common,
                &table_public_inputs,
            ),
            config.clone(),
            fixture.backend.clone(),
            params.clone(),
        )
        .expect("an honest batch proof prepares");
        let out = prepared
            .prove(PreparedInput::BatchStark {
                proof: &fixture.base_proof,
                common_data: &fixture.base_proof.stark_common,
                table_public_inputs: &table_public_inputs,
            })
            .expect("the first witness proves");
        (prepared, out)
    };
    drop(fixture);
    let out2 = prepared
        .prove(PreparedInput::BatchStark {
            proof: &second.base_proof,
            common_data: &second.base_proof.stark_common,
            table_public_inputs: &table_public_inputs,
        })
        .expect("the prepared verifier can be reused");
    assert!(Rc::ptr_eq(&out1.1, &out2.1));
    verify_fri_output(config.clone(), &params, &out1);
    verify_fri_output(config, &params, &out2);
}

#[test]
fn fri_batch_trusted_layer_uses_retained_child_verifier_and_witness_only_inputs() {
    let first = common::build_koala_bear_d4_first_layer_input_with_starts(0, 1);
    let second = common::build_koala_bear_d4_first_layer_input_with_starts(2, 3);
    first
        .verifier
        .verify(&second.base_proof, &[])
        .expect("the varied witness has the retained child relation");
    assert!(
        first
            .base_proof
            .stark_common
            .preprocessed
            .as_ref()
            .map(|g| &g.commitment)
            == first
                .verifier
                .common_data()
                .preprocessed
                .as_ref()
                .map(|g| &g.commitment)
    );
    let params = ProveNextLayerParams::default();
    let output_config = first.layer_config.clone();
    let owner = TrustedPreparedLayer::<_, _, BatchOnly, _, 4>::new(
        TrustedPreparedSource::BatchStark {
            verifier: first.verifier.clone(),
            proof: &first.base_proof,
            statement: &[],
        },
        output_config.clone(),
        first.backend.clone(),
        params.clone(),
    )
    .expect("the retained child verifier prepares");

    let first_output = owner
        .prove(TrustedPreparedInput::BatchStark {
            proof: &first.base_proof,
            statement: &[],
        })
        .expect("the representative witness proves");
    let second_output = owner
        .prove(TrustedPreparedInput::BatchStark {
            proof: &second.base_proof,
            statement: &[],
        })
        .expect("a varied witness proves without replacement authority");

    owner.verifier().verify(&first_output.0, &[]).unwrap();
    owner.verifier().verify(&second_output.0, &[]).unwrap();
    verify_fri_output(output_config.clone(), &params, &first_output);
    verify_fri_output(output_config, &params, &second_output);
}

#[test]
fn batch_example_policy_rebuilds_only_on_contract_mismatch() {
    // This mirrors the examples' retained-owner branch: validate a borrowed input first,
    // reuse the owner on a matching contract, and rebuild only for PreparedInputMismatch.
    let first = common::build_koala_bear_d4_first_layer_input_with_starts(0, 1);
    let second = common::build_koala_bear_d4_first_layer_input_with_starts(2, 3);
    let mut mismatch = common::build_koala_bear_d4_first_layer_input();
    let table_public_inputs = vec![vec![]; first.base_proof.proof.opened_values.instances.len()];
    let mismatch_table = vec![vec![]; mismatch.base_proof.proof.opened_values.instances.len()];
    let config = first.layer_config.clone();
    let backend = first.backend.clone();
    let params = ProveNextLayerParams::default();

    let mut owner = Some(
        PreparedLayer::<_, BatchOnly, _, 4>::new(
            PreparedSource::batch(
                &first.base_proof,
                &first.base_proof.stark_common,
                &table_public_inputs,
            ),
            config.clone(),
            backend.clone(),
            params.clone(),
        )
        .expect("the first trusted input prepares"),
    );
    let mut rebuilds = 1;

    let first_input = PreparedInput::BatchStark {
        proof: &first.base_proof,
        common_data: &first.base_proof.stark_common,
        table_public_inputs: &table_public_inputs,
    };
    owner
        .as_ref()
        .unwrap()
        .check_input(&first_input)
        .expect("the first input matches the retained contract");
    let first_output = owner
        .as_ref()
        .unwrap()
        .prove(first_input)
        .expect("the first matching input proves");

    let second_input = PreparedInput::BatchStark {
        proof: &second.base_proof,
        common_data: &second.base_proof.stark_common,
        table_public_inputs: &table_public_inputs,
    };
    match owner.as_ref().unwrap().check_input(&second_input) {
        Ok(()) => {}
        Err(error) if is_prepared_input_mismatch(&error) => {
            panic!("matching native contracts must reuse the retained owner")
        }
        Err(error) => panic!("unexpected matching-input validation error: {error:?}"),
    }
    let second_output = owner
        .as_ref()
        .unwrap()
        .prove(second_input)
        .expect("the second matching input proves");
    assert!(Rc::ptr_eq(&first_output.1, &second_output.1));
    assert_eq!(rebuilds, 1, "matching calls must not rebuild preparation");

    let mismatched_input = PreparedInput::BatchStark {
        proof: &mismatch.base_proof,
        common_data: &mismatch.base_proof.stark_common,
        table_public_inputs: &mismatch_table,
    };
    match owner.as_ref().unwrap().check_input(&mismatched_input) {
        Err(error) if is_prepared_input_mismatch(&error) => {
            owner = Some(
                PreparedLayer::new(
                    PreparedSource::batch(
                        &mismatch.base_proof,
                        &mismatch.base_proof.stark_common,
                        &mismatch_table,
                    ),
                    config.clone(),
                    backend.clone(),
                    params,
                )
                .expect("the mismatched contract can be explicitly reprepared"),
            );
            rebuilds += 1;
        }
        Ok(()) => panic!("the deliberately different contract must not match"),
        Err(error) => panic!("unexpected mismatch validation error: {error:?}"),
    }
    assert_eq!(
        rebuilds, 2,
        "only the explicit mismatch may rebuild preparation"
    );

    mismatch.base_proof.proof.degree_bits.pop();
    let malformed_input = PreparedInput::BatchStark {
        proof: &mismatch.base_proof,
        common_data: &mismatch.base_proof.stark_common,
        table_public_inputs: &mismatch_table,
    };
    let error = owner.as_ref().unwrap().check_input(&malformed_input);
    match error {
        Err(error) if is_prepared_input_mismatch(&error) => rebuilds += 1,
        Err(VerificationError::InvalidProofShape(_)) => {}
        Err(error) => panic!("unexpected malformed-input error: {error:?}"),
        Ok(()) => panic!("malformed input must be rejected"),
    }
    assert_eq!(rebuilds, 2, "malformed input must not rebuild preparation");
}

#[test]
fn whir_uni_prepared_layer_reuses_varied_witnesses_after_reference_drop() {
    let n = 1 << 10;
    let air = FibonacciAir {};
    let config = bb_whir_config(vec![]);
    let backend = WhirRecursionBackend::<16, 8>::new(Poseidon2Config::BABY_BEAR_D4_W16)
        .for_extension_degree::<4>();
    let params = ProveNextLayerParams::default();

    let (prepared, out1) = {
        let pis = vec![BbF::ZERO, BbF::ONE, fibonacci_output::<BbF>(0, 1, n)];
        let proof = prove(&config, &air, generate_trace_rows::<BbF>(0, 1, n), &pis);
        verify(&config, &air, &proof, &pis).expect("the trusted WHIR proof verifies");
        let prepared = PreparedLayer::<BbWhirConfig, FibonacciAir, _, 4>::new(
            PreparedSource::UniStark {
                air: &air,
                proof: &proof,
                public_inputs: &pis,
                preprocessed_commit: None,
            },
            config.clone(),
            backend,
            params.clone(),
        )
        .expect("the trusted WHIR proof prepares");
        let out = prepared
            .prove(PreparedInput::UniStark {
                proof: &proof,
                public_inputs: &pis,
                preprocessed_commit: None,
            })
            .expect("the reference WHIR witness proves");
        (prepared, out)
    };

    let second_pis = vec![
        BbF::from_u64(2),
        BbF::from_u64(3),
        fibonacci_output::<BbF>(2, 3, n),
    ];
    let second = prove(
        &config,
        &air,
        generate_trace_rows::<BbF>(2, 3, n),
        &second_pis,
    );
    verify(&config, &air, &second, &second_pis).expect("the varied WHIR proof verifies");
    let out2 = prepared
        .prove(PreparedInput::UniStark {
            proof: &second,
            public_inputs: &second_pis,
            preprocessed_commit: None,
        })
        .expect("the varied WHIR witness proves with the prepared owner");

    assert!(Rc::ptr_eq(&out1.1, &out2.1));
    verify_whir_output(config.clone(), &params, &out1);
    verify_whir_output(config, &params, &out2);
}

#[test]
fn whir_batch_prepared_layer_reuses_varied_witnesses_after_reference_drop() {
    let config = bb_whir_config(vec![]);
    let backend = WhirRecursionBackend::<16, 8>::new(Poseidon2Config::BABY_BEAR_D4_W16)
        .for_extension_degree::<4>();
    let params = ProveNextLayerParams::default();
    let first = build_whir_first_layer(&config, &backend, &params, 0, 1);
    let second = build_whir_first_layer(&config, &backend, &params, 2, 3);
    verify_whir_output(config.clone(), &params, &first);
    verify_whir_output(config.clone(), &params, &second);
    let table_public_inputs = vec![vec![]; first.0.proof.opened_values.instances.len()];

    let (prepared, out1) = {
        let prepared = PreparedLayer::<BbWhirConfig, BatchOnly, _, 4>::new(
            PreparedSource::batch(&first.0, &first.0.stark_common, &table_public_inputs),
            config.clone(),
            backend,
            params.clone(),
        )
        .expect("the first honest WHIR batch proof prepares");
        let out = prepared
            .prove(PreparedInput::BatchStark {
                proof: &first.0,
                common_data: &first.0.stark_common,
                table_public_inputs: &table_public_inputs,
            })
            .expect("the first WHIR batch witness proves");
        (prepared, out)
    };
    drop(first);
    let out2 = prepared
        .prove(PreparedInput::BatchStark {
            proof: &second.0,
            common_data: &second.0.stark_common,
            table_public_inputs: &table_public_inputs,
        })
        .expect("the varied WHIR batch witness proves with the prepared owner");

    assert!(Rc::ptr_eq(&out1.1, &out2.1));
    verify_whir_output(config.clone(), &params, &out1);
    verify_whir_output(config, &params, &out2);
}
