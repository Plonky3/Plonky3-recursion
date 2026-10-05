//! Native helpers honor optional budgets inside checked construction calls.

use p3_binary_field::Poly64 as F;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, CircuitConstructionLimits, ExprId};

fn limits(nodes: usize) -> CircuitConstructionLimits {
    CircuitConstructionLimits {
        max_expression_nodes: nodes,
        max_pending_connects: 1024,
        max_non_primitive_calls: 1024,
        max_non_primitive_slots: 4096,
    }
}
fn budget_error<T>(result: Result<T, CircuitBuilderError>) -> bool {
    matches!(
        result,
        Err(CircuitBuilderError::ConstructionLimitExceeded { .. })
    )
}

#[test]
fn decomposition_checks_before_reconstruction_and_cached_return() {
    let mut b = CircuitBuilder::<F>::with_construction_limits(limits(16)).unwrap();
    let value = b.public_input();
    assert!(budget_error(b.binary_decompose_coordinates(value, 64)));
    assert!(b.construction_usage().unwrap().expression_nodes <= 82);
    assert!(b.build().is_err());

    let mut b = CircuitBuilder::<F>::with_construction_limits(limits(256)).unwrap();
    let value = b.public_input();
    b.binary_decompose_coordinates(value, 8).unwrap();
    while b.construction_usage().unwrap().expression_nodes <= 256 {
        b.alloc_private_input("cross budget");
    }
    let before = b.construction_usage().unwrap();
    assert!(budget_error(b.binary_decompose_coordinates(value, 0)));
    assert_eq!(b.construction_usage().unwrap(), before);
}

#[test]
fn coordinate_recomposition_stops_inside_the_bit_loop() {
    let mut b = CircuitBuilder::<F>::with_construction_limits(limits(80)).unwrap();
    let bits = b.alloc_private_input_array::<64>("coordinates");
    assert!(budget_error(b.binary_recompose_coordinates(&bits)));
    assert!(b.construction_usage().unwrap().expression_nodes <= 84);
}

#[test]
fn native_keccak_checks_call_and_slot_budgets_before_returning_outputs() {
    for (calls, slots) in [(0, 4096), (1024, 399)] {
        let mut b = CircuitBuilder::<F>::with_construction_limits(CircuitConstructionLimits {
            max_non_primitive_calls: calls,
            max_non_primitive_slots: slots,
            ..limits(1024)
        })
        .unwrap();
        b.enable_native_keccak_f1600().unwrap();
        assert!(budget_error(
            b.add_native_keccak_f1600(&[ExprId::ZERO; 100])
        ));
        let usage = b.construction_usage().unwrap();
        assert_eq!(usage.non_primitive_calls, 1);
        assert_eq!(usage.non_primitive_slots, 400);
        assert!(b.build().is_err());
    }
    let mut b = CircuitBuilder::<F>::with_construction_limits(CircuitConstructionLimits {
        max_non_primitive_calls: 1,
        max_non_primitive_slots: 400,
        ..limits(1024)
    })
    .unwrap();
    b.enable_native_keccak_f1600().unwrap();
    b.add_native_keccak_f1600(&[ExprId::ZERO; 100]).unwrap();
    assert!(b.build().is_ok());
}
