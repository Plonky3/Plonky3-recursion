//! Construction budgets stop oversized graphs before lowering or NPO validation.

use p3_baby_bear::BabyBear as F;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, CircuitConstructionLimits, NpoTypeId};
use p3_field::PrimeCharacteristicRing;

fn generous() -> CircuitConstructionLimits {
    CircuitConstructionLimits {
        max_expression_nodes: 1024,
        max_pending_connects: 1024,
        max_non_primitive_calls: 1024,
        max_non_primitive_slots: 1024,
    }
}

#[test]
fn initial_zero_counts_and_ignored_checkpoint_errors_cannot_compile() {
    assert!(matches!(
        CircuitBuilder::<F>::with_construction_limits(CircuitConstructionLimits {
            max_expression_nodes: 0,
            ..generous()
        }),
        Err(CircuitBuilderError::ConstructionLimitExceeded {
            actual: 1,
            limit: 0,
            ..
        })
    ));
    let mut b = CircuitBuilder::<F>::with_construction_limits(CircuitConstructionLimits {
        max_expression_nodes: 1,
        ..generous()
    })
    .unwrap();
    assert_eq!(b.construction_usage().unwrap().expression_nodes, 1);
    b.check_construction_limits().unwrap();
    b.public_input();
    assert!(b.check_construction_limits().is_err());
    assert!(matches!(
        b.build(),
        Err(CircuitBuilderError::ConstructionLimitExceeded {
            actual: 2,
            limit: 1,
            ..
        })
    ));
}

#[test]
fn cse_and_self_connects_do_not_consume_retained_entries() {
    let mut b = CircuitBuilder::<F>::with_construction_limits(generous()).unwrap();
    let a = b.public_input();
    let other = b.alloc_private_input("other");
    let sum = b.add(a, other);
    let before = b.construction_usage().unwrap();
    assert_eq!(b.add(a, other), sum);
    b.connect(a, a);
    assert_eq!(b.construction_usage().unwrap(), before);
    b.connect(a, other);
    assert_eq!(
        b.construction_usage().unwrap().pending_connects,
        before.pending_connects + 1
    );
    b.check_construction_limits().unwrap();
}

#[test]
fn both_build_entry_points_check_connections_before_lowering() {
    for with_mapping in [false, true] {
        let mut b = CircuitBuilder::<F>::with_construction_limits(CircuitConstructionLimits {
            max_pending_connects: 0,
            ..generous()
        })
        .unwrap();
        let a = b.public_input();
        let other = b.alloc_private_input("other");
        b.connect(a, other);
        let result = if with_mapping {
            b.build_with_public_mapping().map(|_| ())
        } else {
            b.build().map(|_| ())
        };
        assert!(matches!(
            result,
            Err(CircuitBuilderError::ConstructionLimitExceeded {
                actual: 1,
                limit: 0,
                ..
            })
        ));
    }
}

#[test]
fn npo_budgets_count_empty_slots_and_precede_operation_validation() {
    for (max_calls, max_slots) in [(0, 1024), (1024, 8)] {
        let mut b = CircuitBuilder::<F>::with_construction_limits(CircuitConstructionLimits {
            max_non_primitive_calls: max_calls,
            max_non_primitive_slots: max_slots,
            ..generous()
        })
        .unwrap();
        let a = b.public_input();
        b.push_non_primitive_op_with_outputs(
            NpoTypeId::new("unregistered-budget-test"),
            vec![vec![], vec![a, a]],
            vec![None, Some("first"), Some("second")],
            None,
            "budget test",
        );
        let usage = b.construction_usage().unwrap();
        assert_eq!(usage.non_primitive_calls, 1);
        assert_eq!(usage.non_primitive_slots, 9);
        assert!(matches!(
            b.build(),
            Err(CircuitBuilderError::ConstructionLimitExceeded { .. })
        ));
    }
}

#[test]
fn sufficient_and_default_budgets_preserve_execution() {
    let build = |bounded| {
        let mut b = if bounded {
            CircuitBuilder::<F>::with_construction_limits(generous()).unwrap()
        } else {
            CircuitBuilder::<F>::new()
        };
        let a = b.public_input();
        let factor = b.alloc_private_input("factor");
        let expected = b.public_input();
        let one = b.define_const(F::ONE);
        let out = b.mul_add(a, factor, one);
        b.connect(out, expected);
        b.check_construction_limits().unwrap();
        b.build().unwrap()
    };
    let unlimited = build(false);
    let limited = build(true);
    assert_eq!(limited.witness_count, unlimited.witness_count);
    assert_eq!(limited.ops.len(), unlimited.ops.len());
    for circuit in [&limited, &unlimited] {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&[F::from_u8(3), F::from_u8(16)])
            .unwrap();
        runner.set_private_inputs(&[F::from_u8(5)]).unwrap();
        assert!(runner.run().is_ok());
    }
}
