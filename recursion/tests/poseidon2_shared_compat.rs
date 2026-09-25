mod common;

use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    NpoTypeId, Poseidon2Config, Poseidon2PermCall, generate_poseidon2_trace,
    generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::batch_stark_prover::{
    BatchStarkProver, poseidon2_air_builders_for_configs, recompose_air_builders,
};
use p3_circuit_prover::common::{NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{
    CircuitProverData, ConstraintProfile, Poseidon2Preprocessor, RecomposePreprocessor,
    TablePacking,
};
use p3_field::PrimeCharacteristicRing;
use p3_koala_bear::{KoalaBear, default_koalabear_poseidon2_16};
use p3_poseidon2_circuit_air::KoalaBearD4Width16;
use p3_recursion::challenger::CircuitChallenger;
use p3_recursion::recursion::{
    BatchOnly, ProveNextLayerParams, RecursionInput, build_and_prove_next_layer,
};
use p3_recursion::traits::RecursiveChallenger;
use p3_recursion::{FriRecursionBackend, PreparedInput, PreparedLayer, PreparedSource};
use p3_test_utils::koala_bear_params::Challenge;

type F = KoalaBear;
type Config = common::KoalaBearD4RecursionConfig;
type Backend = common::KoalaBearD4Backend;
const CFG: Poseidon2Config = Poseidon2Config::KOALA_BEAR_D4_W16;

struct LegacyFixture {
    config: Config,
    backend: Backend,
    proof: p3_circuit_prover::BatchStarkProof<Config>,
}

fn build_legacy_fixture(include_ordinary: bool) -> LegacyFixture {
    let (config, default_backend) =
        common::koala_bear_d4_recursion_config_and_backend_with_pow_bits(0);
    let backend = if include_ordinary {
        default_backend
    } else {
        FriRecursionBackend::<16, 8, _>::new(CFG)
            .without_shared_challenger_perm_table()
            .for_extension_degree::<4>()
    };
    let mut circuit = CircuitBuilder::<Challenge>::new();
    circuit.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, KoalaBearD4Width16>,
        default_koalabear_poseidon2_16(),
    );
    circuit.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    // This is a real CircuitChallenger lowering, so its rows use the dedicated legacy
    // challenger identity. The ordinary call below deliberately uses the same shape/config
    // without the challenger role, producing the second legacy physical table.
    let mut challenger = CircuitChallenger::<16, 8, Poseidon2Config>::new_koalabear();
    for i in 0..8 {
        let value = circuit.alloc_const(Challenge::from_u64(i as u64 + 1), "observe");
        RecursiveChallenger::<F, Challenge>::observe(&mut challenger, &mut circuit, value);
    }
    for _ in 0..=8 {
        let _ = RecursiveChallenger::<F, Challenge>::sample(&mut challenger, &mut circuit);
    }

    if include_ordinary {
        let ordinary_inputs: Vec<ExprId> = (0..CFG.width_ext())
            .map(|i| circuit.alloc_const(Challenge::from_u64(100 + i as u64), "ordinary_input"))
            .collect();
        circuit
            .add_poseidon2_perm(&Poseidon2PermCall {
                config: CFG,
                new_start: true,
                merkle_path: false,
                mmcs_bit: None,
                mmcs_bit2: None,
                inputs: ordinary_inputs.into_iter().map(Some).collect(),
                out_ctl: vec![true; CFG.rate_ext()],
                return_all_outputs: false,
                mmcs_index_sum: None,
                absorb_len: 0,
            })
            .expect("ordinary same-shape permutation operation is enabled");
    }
    let circuit = circuit.build().expect("legacy fixture circuit builds");
    let traces = circuit
        .runner()
        .run()
        .expect("legacy fixture witnesses run");

    let table_packing = TablePacking::new(1, 1);
    let preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
        Box::new(Poseidon2Preprocessor),
        Box::new(RecomposePreprocessor::new(true)),
    ];
    let mut configs = vec![CFG.for_challenger()];
    if include_ordinary {
        configs.push(CFG);
    }
    let mut air_builders = poseidon2_air_builders_for_configs::<Config, 4>(configs);
    air_builders.extend(recompose_air_builders::<Config, 4>(1, true));
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<Config, Challenge, 4>(
            &circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("legacy fixture preprocessing succeeds");
    let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
    let prover_data = ProverData::from_airs_and_degrees(&config, &airs, &degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let mut prover = BatchStarkProver::new(config.clone()).with_table_packing(table_packing);
    prover.register_poseidon2_table::<4>(CFG.for_challenger());
    if include_ordinary {
        prover.register_poseidon2_table::<4>(CFG);
    }
    prover.register_recompose_table::<4>(true);
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .expect("legacy separated proof proves");
    prover
        .verify_all_tables::<Challenge>(&proof)
        .expect("legacy separated proof verifies natively");

    let ids: Vec<_> = proof
        .non_primitives
        .iter()
        .map(|entry| entry.op_type.clone())
        .collect();
    assert!(ids.contains(&NpoTypeId::poseidon2_perm(CFG.for_challenger())));
    if include_ordinary {
        let expected = [
            NpoTypeId::poseidon2_perm(CFG.for_challenger()),
            NpoTypeId::poseidon2_perm(CFG),
        ];
        assert!(ids.windows(2).any(|window| window == expected.as_slice()));
    } else {
        assert!(!ids.contains(&NpoTypeId::poseidon2_perm(CFG)));
    }

    LegacyFixture {
        config,
        backend,
        proof,
    }
}

fn legacy_input<'a>(
    proof: &'a p3_circuit_prover::BatchStarkProof<Config>,
) -> RecursionInput<'a, Config, BatchOnly> {
    RecursionInput::BatchStark {
        proof,
        common_data: &proof.stark_common,
        table_public_inputs: vec![vec![]; proof.proof.opened_values.instances.len()],
    }
}

#[test]
fn legacy_separated_input_recurses_into_combined_output_twice() {
    let mut fixture = build_legacy_fixture(true);
    let params = ProveNextLayerParams::default();
    let table_public_inputs = vec![vec![]; fixture.proof.proof.opened_values.instances.len()];
    let prepared = PreparedLayer::<_, BatchOnly, _, 4>::new(
        PreparedSource::batch(
            &fixture.proof,
            &fixture.proof.stark_common,
            &table_public_inputs,
        ),
        fixture.config.clone(),
        fixture.backend.clone(),
        params.clone(),
    )
    .expect("the real legacy proof captures a prepared input contract");
    prepared
        .check_input(&PreparedInput::BatchStark {
            proof: &fixture.proof,
            common_data: &fixture.proof.stark_common,
            table_public_inputs: &table_public_inputs,
        })
        .expect("the honest legacy proof passes prepared preflight and capture");
    let input = legacy_input(&fixture.proof);
    let first = build_and_prove_next_layer(&input, &fixture.config, &fixture.backend, &params)
        .expect("legacy separated input recurses into combined output");
    assert_eq!(
        first
            .0
            .non_primitives
            .iter()
            .filter(|entry| entry.op_type
                == NpoTypeId::poseidon2_perm(CFG.for_shared_challenger_table()))
            .count(),
        1
    );

    let second_input = first.into_recursion_input::<BatchOnly>();
    let second =
        build_and_prove_next_layer(&second_input, &fixture.config, &fixture.backend, &params)
            .expect("combined output recurses into combined output");
    let mut verifier = BatchStarkProver::new(fixture.config.clone())
        .with_table_packing(params.table_packing.clone());
    verifier.register_poseidon2_table::<4>(CFG.for_shared_challenger_table());
    verifier.register_recompose_table::<4>(true);
    verifier
        .verify_all_tables::<Challenge>(&second.0)
        .expect("second combined output verifies");

    // Mutate only real proof manifests. Each malformed input is rejected before proving a layer.
    let challenger = NpoTypeId::poseidon2_perm(CFG.for_challenger());
    let ordinary = NpoTypeId::poseidon2_perm(CFG);
    let shared = NpoTypeId::poseidon2_perm(CFG.for_shared_challenger_table());
    let pair = fixture
        .proof
        .non_primitives
        .windows(2)
        .position(|window| window[0].op_type == challenger && window[1].op_type == ordinary)
        .expect("legacy pair is present");

    let removed = fixture.proof.non_primitives.remove(pair + 1);
    assert!(
        prepared
            .check_input(&PreparedInput::BatchStark {
                proof: &fixture.proof,
                common_data: &fixture.proof.stark_common,
                table_public_inputs: &table_public_inputs,
            })
            .is_err()
    );
    assert!(
        build_and_prove_next_layer(
            &legacy_input(&fixture.proof),
            &fixture.config,
            &fixture.backend,
            &params
        )
        .is_err()
    );
    fixture.proof.non_primitives.insert(pair + 1, removed);

    fixture.proof.non_primitives.swap(pair, pair + 1);
    assert!(
        prepared
            .check_input(&PreparedInput::BatchStark {
                proof: &fixture.proof,
                common_data: &fixture.proof.stark_common,
                table_public_inputs: &table_public_inputs,
            })
            .is_err()
    );
    assert!(
        build_and_prove_next_layer(
            &legacy_input(&fixture.proof),
            &fixture.config,
            &fixture.backend,
            &params
        )
        .is_err()
    );
    fixture.proof.non_primitives.swap(pair, pair + 1);

    let original = fixture.proof.non_primitives[pair + 1].op_type.clone();
    fixture.proof.non_primitives[pair + 1].op_type = shared;
    assert!(
        prepared
            .check_input(&PreparedInput::BatchStark {
                proof: &fixture.proof,
                common_data: &fixture.proof.stark_common,
                table_public_inputs: &table_public_inputs,
            })
            .is_err()
    );
    assert!(
        build_and_prove_next_layer(
            &legacy_input(&fixture.proof),
            &fixture.config,
            &fixture.backend,
            &params
        )
        .is_err()
    );
    fixture.proof.non_primitives[pair + 1].op_type = original;
}

#[test]
fn challenger_only_legacy_input_recurses_with_mixed_manifest_policy() {
    let fixture = build_legacy_fixture(false);
    let params = ProveNextLayerParams::default();
    let output = build_and_prove_next_layer(
        &legacy_input(&fixture.proof),
        &fixture.config,
        &fixture.backend,
        &params,
    )
    .expect("challenger-only legacy input recurses under mixed manifest policy");

    let mut verifier =
        BatchStarkProver::new(fixture.config).with_table_packing(params.table_packing);
    verifier.register_poseidon2_table::<4>(CFG.for_shared_challenger_table());
    verifier.register_recompose_table::<4>(true);
    verifier
        .verify_all_tables::<Challenge>(&output.0)
        .expect("challenger-only legacy input's combined output verifies natively");
    assert_eq!(
        output
            .0
            .non_primitives
            .iter()
            .filter(|entry| entry.op_type
                == NpoTypeId::poseidon2_perm(CFG.for_shared_challenger_table()))
            .count(),
        1
    );
}
