mod common;

use std::rc::Rc;

use common::whir_config::{BbEF, BbF, BbWhirConfig, bb_whir_config};
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_circuit_prover::batch_stark_prover::BatchStarkProver;
use p3_field::PrimeCharacteristicRing;
use p3_recursion::backend::whir::{WhirRecursionBackend, WhirRecursionBackendForExt};
use p3_recursion::{
    BatchOnly, Poseidon2Config, PreparedInput, PreparedLayer, PreparedSource, ProveNextLayerParams,
    RecursionInput, RecursionOutput, build_and_prove_next_layer,
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
            backend.clone(),
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
            backend.clone(),
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
