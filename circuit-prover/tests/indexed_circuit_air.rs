//! Compact circuit wiring must be pinned to the compiled graph.

use p3_air::{BaseAir, check_constraints};
use p3_circuit::CircuitBuilder;
use p3_circuit::tables::WitnessTrace;
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::indexed::{IndexedCircuit, IndexedCircuitError};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use p3_test_utils::binary_field_params::{BinaryField128, TowerLevel};

type F = BinaryField128;

#[test]
fn compact_shapes_fixed_positions_padding_and_public_aliases() {
    let mut builder = CircuitBuilder::<F>::new();
    let input = builder.public_input();
    let alias = builder.public_input();
    builder.connect(input, alias);
    let expected = builder.public_input();
    let factor = builder.alloc_private_input("factor");
    let product = builder.mul(input, factor);
    let reused = builder.mul_add(product, input, factor);
    builder.connect(reused, expected);
    let circuit = builder.build().unwrap();
    let prepared = IndexedCircuit::new(&circuit).unwrap();
    let [a, b] = [0xabcde, 0xfedcb].map(F::from_repr);
    let public = [a, a, a * b * a + b];
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    runner.set_private_inputs(&[b]).unwrap();
    let traces = prepared
        .traces(&runner.run().unwrap().witness_trace)
        .unwrap();
    let public_by_air = prepared.public_values(&public).unwrap();
    assert_eq!(prepared.airs().len(), 3);
    assert_eq!(prepared.airs()[0].width(), 1);
    assert_eq!(prepared.airs()[1].width(), 10);
    assert_eq!(prepared.airs()[2].width(), 6);
    for (air, trace) in prepared.airs().iter().zip(&traces) {
        assert!(air.main_next_row_columns().is_empty());
        assert!(air.preprocessed_next_row_columns().is_empty());
        let pp = air.preprocessed_trace();
        assert_eq!(
            pp.as_ref().map_or(0, |t| t.width()),
            air.preprocessed_width()
        );
        if let Some(pp) = pp {
            assert_eq!(pp.height(), trace.height());
        }
    }
    for ((air, trace), public) in prepared.airs().iter().zip(&traces).zip(&public_by_air) {
        check_constraints(air, trace, public);
    }
    // Row-local checks deliberately ignore indexed obligations, but still
    // catch a prover-selected position even when the gate payload is unchanged.
    let mut rewired = traces[1].clone();
    rewired.values[0] += F::ONE;
    assert!(
        std::panic::catch_unwind(|| check_constraints(&prepared.airs()[1], &rewired, &[])).is_err()
    );
    let mut wrong = public_by_air[2].clone();
    wrong[1] += F::ONE;
    assert!(
        std::panic::catch_unwind(|| check_constraints(&prepared.airs()[2], &traces[2], &wrong))
            .is_err()
    );
    let mut bad_sentinel = traces[0].clone();
    bad_sentinel.values[0] = F::ONE;
    assert!(
        std::panic::catch_unwind(|| check_constraints(&prepared.airs()[0], &bad_sentinel, &[]))
            .is_err()
    );
    assert!(prepared.traces(&WitnessTrace::new(vec![])).is_err());
    assert!(prepared.public_values(&[]).is_err());
}

#[test]
fn unsupported_indexed_position_capacity_is_rejected() {
    use p3_test_utils::binary_field_params::Gf2;
    let mut builder = CircuitBuilder::<Gf2>::new();
    let _input = builder.public_input();
    let circuit = builder.build().unwrap();
    assert!(matches!(
        IndexedCircuit::new(&circuit),
        Err(IndexedCircuitError::PositionCapacity { .. })
    ));
}

#[test]
fn fused_intermediate_and_horner_use_the_canonical_witness_assignment() {
    use p3_circuit::Circuit;
    use p3_circuit::ops::{AluOpKind, Op};
    use p3_circuit::types::WitnessId;
    let mut circuit = Circuit::<F>::new(7, Default::default());
    circuit.ops = vec![
        Op::Alu {
            kind: AluOpKind::MulAdd,
            a: WitnessId(0),
            b: WitnessId(1),
            c: Some(WitnessId(2)),
            out: WitnessId(3),
            intermediate_out: Some(WitnessId(4)),
        },
        Op::Alu {
            kind: AluOpKind::HornerAcc,
            a: WitnessId(0),
            b: WitnessId(1),
            c: Some(WitnessId(2)),
            out: WitnessId(5),
            intermediate_out: Some(WitnessId(3)),
        },
        Op::Alu {
            kind: AluOpKind::BoolCheck,
            a: WitnessId(6),
            b: WitnessId(6),
            c: Some(WitnessId(6)),
            out: WitnessId(6),
            intermediate_out: None,
        },
    ];
    let [a, b, c] = [7, 19, 43].map(F::from_repr);
    let witness = WitnessTrace::new(vec![
        a,
        b,
        c,
        a * b + c,
        a * b,
        (a * b + c) * b + c - a,
        F::ONE,
    ]);
    let prepared = IndexedCircuit::new(&circuit).unwrap();
    let traces = prepared.traces(&witness).unwrap();
    for (air, trace) in prepared.airs().iter().zip(&traces) {
        check_constraints(air, trace, &[]);
    }
    for row in 0..4 {
        let mut altered = traces[1].clone();
        altered.values[row * 10 + 9] += F::ONE;
        assert!(
            std::panic::catch_unwind(|| check_constraints(&prepared.airs()[1], &altered, &[]))
                .is_err()
        );
    }
    assert!(
        IndexedCircuit::with_limits(
            &circuit,
            DirectCircuitLimits {
                max_trace_cells: 1,
                ..Default::default()
            }
        )
        .is_err()
    );
}

#[test]
fn public_only_relation_omits_the_gate_and_preprocessing_tables() {
    use p3_circuit::Circuit;
    use p3_circuit::ops::Op;
    use p3_circuit::types::WitnessId;
    let mut circuit = Circuit::<F>::new(1, Default::default());
    circuit.public_rows = vec![WitnessId(0)];
    circuit.public_flat_len = 1;
    circuit.ops = vec![Op::Public {
        out: WitnessId(0),
        public_pos: 0,
    }];
    let prepared = IndexedCircuit::new(&circuit).unwrap();
    assert_eq!(prepared.airs().len(), 2);
    assert!(prepared.preprocessed_variables().is_none());
    let traces = prepared.traces(&WitnessTrace::new(vec![F::ONE])).unwrap();
    let public = prepared.public_values(&[F::ONE]).unwrap();
    for ((air, trace), public) in prepared.airs().iter().zip(&traces).zip(&public) {
        check_constraints(air, trace, public);
    }
}
