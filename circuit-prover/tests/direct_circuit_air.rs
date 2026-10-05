//! A circuit's primitive relation must be enforced by its AIR, not its runner.

use p3_air::{BaseAir, check_constraints};
use p3_circuit::ops::{AluOpKind, Op};
use p3_circuit::tables::WitnessTrace;
use p3_circuit::types::WitnessId;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_circuit_prover::direct::{DirectCircuitAir, DirectCircuitError};
use p3_field::PrimeCharacteristicRing;
use p3_test_utils::binary_field_params::{BinaryField128, TowerLevel};

type F = BinaryField128;

fn circuit() -> Circuit<F> {
    let mut builder = CircuitBuilder::new();
    let input = builder.public_input();
    let output = builder.public_input();
    let private = builder.alloc_private_input("factor");
    let product = builder.mul(input, private);
    builder.connect(product, output);
    builder.build().unwrap()
}

#[test]
fn honest_binary_circuit_and_independent_public_statement_satisfy_air() {
    let circuit = circuit();
    let a = F::from_repr(0xfedc_ba98_7654_3210);
    let b = F::from_repr(0xdead_beef_9876_5432);
    let public = [a, a * b];
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    runner.set_private_inputs(&[b]).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let air = DirectCircuitAir::new(&circuit).unwrap();
    let trace = air.trace(&witness, 2).unwrap();
    assert_eq!(air.width(), circuit.witness_count as usize);
    assert_eq!(air.num_public_values(), 2);
    assert!(air.main_next_row_columns().is_empty());
    check_constraints(&air, &trace, &public);
    let mut wrong = public;
    wrong[1] += F::ONE;
    assert!(std::panic::catch_unwind(|| check_constraints(&air, &trace, &wrong)).is_err());
    let mut changed = trace;
    changed.values[circuit.public_rows[1].0 as usize] += F::ONE;
    assert!(std::panic::catch_unwind(|| check_constraints(&air, &changed, &public)).is_err());
}

#[test]
fn connected_public_aliases_bind_every_expected_slot() {
    let mut builder = CircuitBuilder::<F>::new();
    let a = builder.public_input();
    let b = builder.public_input();
    builder.connect(a, b);
    let circuit = builder.build().unwrap();
    let air = DirectCircuitAir::new(&circuit).unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&[F::ONE; 2]).unwrap();
    let trace = air.trace(&runner.run().unwrap().witness_trace, 1).unwrap();
    check_constraints(&air, &trace, &[F::ONE; 2]);
    assert!(
        std::panic::catch_unwind(|| {
            check_constraints(&air, &trace, &[F::ONE, F::ZERO]);
        })
        .is_err()
    );
}

#[test]
fn frozen_air_owns_relation_and_rejects_bad_trace_shapes() {
    let mut circuit = circuit();
    let air = DirectCircuitAir::new(&circuit).unwrap();
    circuit.public_rows.clear();
    circuit.ops.clear();
    assert_eq!(air.num_public_values(), 2);
    assert!(matches!(
        air.trace(&WitnessTrace::new(vec![]), 1),
        Err(DirectCircuitError::WitnessLength { .. })
    ));
    let witness = WitnessTrace::new(vec![F::ZERO; air.width()]);
    assert!(matches!(
        air.trace(&witness, 0),
        Err(DirectCircuitError::InvalidHeight)
    ));
    assert!(matches!(
        air.trace(&witness, usize::BITS as usize),
        Err(DirectCircuitError::InvalidHeight)
    ));
}

#[test]
fn malformed_metadata_is_rejected_before_air_construction() {
    let mut circuit = circuit();
    circuit.public_rows[0] = WitnessId(circuit.witness_count);
    assert!(matches!(
        DirectCircuitAir::new(&circuit),
        Err(DirectCircuitError::WitnessOutOfBounds { .. })
    ));
    let mut circuit = self::circuit();
    circuit.public_flat_len += 1;
    assert!(matches!(
        DirectCircuitAir::new(&circuit),
        Err(DirectCircuitError::PublicMapping)
    ));
    let mut circuit = self::circuit();
    circuit.ops.push(Op::Alu {
        kind: AluOpKind::HornerAcc,
        a: WitnessId(0),
        b: WitnessId(0),
        c: Some(WitnessId(0)),
        out: WitnessId(0),
        intermediate_out: None,
    });
    assert!(matches!(
        DirectCircuitAir::new(&circuit),
        Err(DirectCircuitError::MalformedAlu { .. })
    ));
}

#[test]
fn fused_product_and_horner_accumulator_are_independently_constrained() {
    let mut circuit = Circuit::<F>::new(6, Default::default());
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
    ];
    let [a, b, c] = [7, 19, 43].map(F::from_repr);
    let product = a * b;
    let fused = product + c;
    let witness = WitnessTrace::new(vec![a, b, c, fused, product, fused * b + c - a]);
    let air = DirectCircuitAir::new(&circuit).unwrap();
    let trace = air.trace(&witness, 1).unwrap();
    check_constraints(&air, &trace, &[]);
    for column in [3, 4, 5] {
        let mut changed = trace.clone();
        changed.values[column] += F::ONE;
        assert!(std::panic::catch_unwind(|| check_constraints(&air, &changed, &[])).is_err());
    }
}

#[test]
fn booleanity_is_proved_even_when_runner_accepts_a_non_bit() {
    let mut builder = CircuitBuilder::<F>::new();
    let bit = builder.public_input();
    builder.assert_bool(bit);
    let circuit = builder.build().unwrap();
    let air = DirectCircuitAir::new(&circuit).unwrap();
    let non_bit = F::from_repr(2);
    let mut runner = circuit.runner();
    runner.set_public_inputs(&[non_bit]).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let trace = air.trace(&witness, 1).unwrap();
    assert!(std::panic::catch_unwind(|| check_constraints(&air, &trace, &[non_bit])).is_err());
}

#[test]
fn table_backed_operations_are_rejected_instead_of_dropped() {
    use p3_baby_bear::BabyBear;
    use p3_circuit::StatementExport;
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let value = builder.public_input();
    builder
        .set_statement_exports::<BabyBear>(&[StatementExport::Base(value)])
        .unwrap();
    let circuit = builder.build().unwrap();
    assert!(matches!(
        DirectCircuitAir::new(&circuit),
        Err(DirectCircuitError::UnsupportedOperation { .. })
    ));
}
