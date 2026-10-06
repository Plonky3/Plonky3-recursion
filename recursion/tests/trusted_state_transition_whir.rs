use std::boxed::Box;

use common::whir_config::{BbEF, BbF, BbWhirConfig, bb_whir_config};
use p3_circuit::{CircuitBuilder, StateTransitionLayout, StatementExport};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::{
    BatchStarkProver, ConstraintProfile, StatementAirBuilder, StatementPreprocessor,
    StatementProver,
};
use p3_field::PrimeCharacteristicRing;
use p3_recursion::backend::whir::WhirRecursionBackend;
use p3_recursion::{
    BatchOnly, Poseidon2Config, ProveNextLayerParams, TrustedPreparedAggregation,
    TrustedPreparedInput, TrustedPreparedSource,
};

use crate::common;

#[test]
fn whir_trusted_transition_reuses_one_owner_for_distinct_chains() {
    let config = bb_whir_config(vec![]);
    let mut builder = CircuitBuilder::<BbEF>::new();
    let start = builder.public_input();
    let end = builder.public_input();
    let count = builder.public_input();
    let computed_end = builder.add(start, count);
    builder.connect(end, computed_end);
    let schema = builder
        .set_statement_exports::<BbF>(&[
            StatementExport::Base(start),
            StatementExport::Base(end),
            StatementExport::Base(count),
        ])
        .unwrap();
    let circuit = builder.build().unwrap();
    let preprocessors: Vec<Box<dyn NpoPreprocessor<BbF>>> =
        vec![Box::new(StatementPreprocessor::new(schema.clone()))];
    let air_builders: Vec<Box<dyn NpoAirBuilder<BbWhirConfig, 4>>> =
        vec![Box::new(StatementAirBuilder::<4>::new(schema.clone()))];
    let mut prover = BatchStarkProver::new(config.clone());
    prover.register_table_prover(Box::new(StatementProver::<4>::new(schema)));
    let prepared = prover
        .prepare_circuit::<BbEF, 4>(
            &circuit,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();
    let leaves = [[1, 2, 1], [2, 4, 2], [5, 8, 3], [8, 9, 1]];
    let statements = leaves.map(|values| values.map(BbF::from_u32));
    let proofs = statements.map(|statement| {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&statement.map(BbEF::from))
            .unwrap();
        prepared.prove(&runner.run().unwrap()).unwrap()
    });
    let verifier = prepared.verifier();
    let backend = WhirRecursionBackend::<16, 8>::new(Poseidon2Config::BABY_BEAR_D4_W16)
        .for_extension_degree::<4>();
    let owner = TrustedPreparedAggregation::<
        BbWhirConfig,
        BbWhirConfig,
        BatchOnly,
        BatchOnly,
        _,
        4,
    >::new_state_transition(
        TrustedPreparedSource::BatchStark {
            verifier: verifier.clone(),
            proof: &proofs[0],
            statement: &statements[0],
        },
        TrustedPreparedSource::BatchStark {
            verifier,
            proof: &proofs[1],
            statement: &statements[1],
        },
        config,
        backend,
        ProveNextLayerParams::default(),
        StateTransitionLayout::base(1, 4).unwrap(),
    )
    .unwrap();
    let outputs = [0, 2].map(|index| {
        owner
            .prove(
                TrustedPreparedInput::BatchStark {
                    proof: &proofs[index],
                    statement: &statements[index],
                },
                TrustedPreparedInput::BatchStark {
                    proof: &proofs[index + 1],
                    statement: &statements[index + 1],
                },
            )
            .unwrap()
    });
    let parent = owner.verifier();
    assert_eq!(parent.statement_layout().schema().base_len(), 3);
    assert!(parent.aggregation_statement_layout().is_none());
    parent
        .verify(&outputs[0].0, &[1, 4, 3].map(BbF::from_u32))
        .unwrap();
    parent
        .verify(&outputs[1].0, &[5, 9, 4].map(BbF::from_u32))
        .unwrap();
}
