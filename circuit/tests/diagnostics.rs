#![cfg(feature = "debugging")]

use std::error::Error as _;

use hashbrown::HashMap;
use p3_baby_bear::BabyBear;
use p3_circuit::ops::OpStateMap;
use p3_circuit::tables::NonPrimitiveTrace;
use p3_circuit::{
    AllocationType, AluOpKind, Circuit, CircuitBuilder, CircuitError, CompiledOpKind,
    DiagnosticPhase, NpoTypeId, Op, WitnessId,
};
use p3_field::PrimeCharacteristicRing;

#[test]
fn missing_public_input_reports_its_source_and_keeps_the_typed_error() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    builder.push_scope("user_inputs");
    let amount = builder.alloc_public_input("amount");
    builder.pop_scope();
    let circuit = builder.build().unwrap();

    let source = circuit
        .provenance()
        .and_then(|provenance| provenance.allocation(amount))
        .expect("builder circuits retain input allocations");
    assert_eq!(source.label, "amount");
    assert_eq!(source.scope.as_deref(), Some("user_inputs"));
    let public_op_index = circuit
        .ops
        .iter()
        .position(
            |op| matches!(op, Op::Public { out, .. } if *out == circuit.expr_to_widx[&amount]),
        )
        .expect("the public input is compiled into an operation");
    assert_eq!(
        circuit
            .provenance()
            .unwrap()
            .operation_origins(public_op_index),
        &[amount]
    );

    let diagnostic = circuit.runner().run_with_diagnostics().unwrap_err();
    assert!(matches!(
        diagnostic.error(),
        CircuitError::PublicInputNotSet { .. }
    ));
    assert_eq!(
        diagnostic.phase(),
        &DiagnosticPhase::Execution {
            compiled_op_index: public_op_index
        }
    );
    let compiled = diagnostic.compiled_operation().unwrap();
    assert_eq!(compiled.compiled_op_index, public_op_index);
    assert_eq!(compiled.kind, CompiledOpKind::Public);
    assert_eq!(diagnostic.operation_origins().len(), 1);
    assert_eq!(diagnostic.operation_origins()[0].expr_id, amount);
    assert!(matches!(
        diagnostic
            .source()
            .and_then(|error| error.downcast_ref::<CircuitError>()),
        Some(CircuitError::PublicInputNotSet { .. })
    ));
    let display = diagnostic.to_string();
    assert!(display.contains("amount"), "{display}");
    assert!(display.contains("user_inputs"), "{display}");
    assert!(matches!(
        diagnostic.into_error(),
        CircuitError::PublicInputNotSet { .. }
    ));
}

#[test]
fn backward_division_by_zero_reports_original_division() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let numerator = builder.alloc_public_input("numerator");
    let denominator = builder.alloc_public_input("denominator");
    builder.push_scope("rate_calculation");
    let quotient = builder.alloc_div(numerator, denominator, "quotient");
    builder.pop_scope();
    let circuit = builder.build().unwrap();

    let source = circuit
        .provenance()
        .and_then(|provenance| provenance.allocation(quotient))
        .expect("division allocation survives compilation");
    assert_eq!(source.label, "quotient");
    assert_eq!(
        source.dependencies,
        vec![vec![numerator], vec![denominator]]
    );
    let division_op_index = circuit
        .ops
        .iter()
        .position(|op| matches!(op, Op::Alu { .. }))
        .unwrap();
    assert!(
        circuit
            .provenance()
            .unwrap()
            .operation_origins(division_op_index)
            .contains(&quotient)
    );

    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[BabyBear::from_u64(7), BabyBear::ZERO])
        .unwrap();
    let diagnostic = runner.run_with_diagnostics().unwrap_err();
    assert!(matches!(diagnostic.error(), CircuitError::DivisionByZero));
    assert_eq!(
        diagnostic.phase(),
        &DiagnosticPhase::Execution {
            compiled_op_index: division_op_index
        }
    );
    assert_eq!(
        diagnostic.compiled_operation().unwrap().kind,
        CompiledOpKind::Alu(AluOpKind::Mul)
    );
    let origins = diagnostic.operation_origins();
    assert_eq!(origins.len(), 1);
    assert_eq!(origins[0].expr_id, quotient);
    assert_eq!(
        origins[0]
            .dependencies
            .iter()
            .map(|group| group
                .iter()
                .map(|source| source.expr_id)
                .collect::<Vec<_>>())
            .collect::<Vec<_>>(),
        vec![vec![numerator], vec![denominator]]
    );
    let display = diagnostic.to_string();
    assert!(display.contains("quotient"), "{display}");
    assert!(display.contains("rate_calculation"), "{display}");
    assert!(display.contains("Div"), "{display}");
}

#[test]
fn backward_subtraction_conflict_reports_original_subtraction() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let lhs = builder.alloc_public_input("lhs");
    let rhs = builder.alloc_public_input("rhs");
    let supplied_difference = builder.alloc_private_input("supplied_difference");
    builder.push_scope("difference_check");
    let difference = builder.alloc_sub(lhs, rhs, "difference");
    builder.connect(difference, supplied_difference);
    builder.pop_scope();
    let circuit = builder.build().unwrap();
    let subtraction_op_index = circuit
        .ops
        .iter()
        .position(|op| {
            matches!(
                op,
                Op::Alu {
                    kind: AluOpKind::Add,
                    ..
                }
            )
        })
        .unwrap();
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[BabyBear::from_u64(5), BabyBear::from_u64(2)])
        .unwrap();
    runner
        .set_private_inputs(&[BabyBear::from_u64(10)])
        .unwrap();

    let diagnostic = runner.run_with_diagnostics().unwrap_err();
    assert!(matches!(
        diagnostic.error(),
        CircuitError::WitnessConflict { .. }
    ));
    assert_eq!(
        diagnostic.phase(),
        &DiagnosticPhase::Execution {
            compiled_op_index: subtraction_op_index
        }
    );
    assert_eq!(
        diagnostic.compiled_operation().unwrap().kind,
        CompiledOpKind::Alu(AluOpKind::Add)
    );
    assert!(
        diagnostic
            .operation_origins()
            .iter()
            .any(|source| source.expr_id == difference)
    );
    let display = diagnostic.to_string();
    assert!(display.contains("difference_check"), "{display}");
    assert!(display.contains("difference"), "{display}");
    assert!(display.contains("Sub"), "{display}");
}

#[test]
fn missing_private_operand_reports_both_the_input_and_the_arithmetic_source() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    builder.push_scope("calculation");
    let secret = builder.alloc_private_input("secret");
    let public = builder.alloc_public_input("public_term");
    let sum = builder.alloc_add(secret, public, "sum");
    builder.pop_scope();
    let circuit = builder.build().unwrap();
    let add_op_index = circuit
        .ops
        .iter()
        .position(|op| {
            matches!(
                op,
                Op::Alu {
                    kind: AluOpKind::Add,
                    ..
                }
            )
        })
        .unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&[BabyBear::ONE]).unwrap();

    let diagnostic = runner.run_with_diagnostics().unwrap_err();
    assert!(matches!(
        diagnostic.error(),
        CircuitError::WitnessNotSet { .. }
    ));
    assert_eq!(
        diagnostic.phase(),
        &DiagnosticPhase::Execution {
            compiled_op_index: add_op_index
        }
    );
    assert_eq!(diagnostic.operation_origins()[0].expr_id, sum);
    let private_alias = diagnostic
        .witness_aliases()
        .iter()
        .find(|source| source.expr_id == secret)
        .expect("the missing private operand is an implicated witness alias");
    assert!(matches!(
        private_alias
            .allocation
            .as_ref()
            .map(|entry| &entry.alloc_type),
        Some(AllocationType::PrivateInput)
    ));
    let display = diagnostic.to_string();
    assert!(display.contains("secret"), "{display}");
    assert!(display.contains("sum"), "{display}");
    assert!(display.contains("calculation"), "{display}");
}

#[test]
fn diagnostic_keeps_its_source_after_the_circuit_is_dropped() {
    let diagnostic = {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let _input = builder.alloc_public_input("ephemeral_input");
        let circuit = builder.build().unwrap();
        circuit.runner().run_with_diagnostics().unwrap_err()
    };

    assert!(matches!(
        diagnostic.error(),
        CircuitError::PublicInputNotSet { .. }
    ));
    assert!(matches!(
        diagnostic.phase(),
        DiagnosticPhase::Execution { .. }
    ));
    assert_eq!(diagnostic.operation_origins().len(), 1);
    assert!(diagnostic.to_string().contains("ephemeral_input"));
}

#[test]
fn setter_error_can_be_diagnosed_without_inventing_an_executing_operation() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let _input = builder.alloc_public_input("input");
    let circuit = builder.build().unwrap();
    let mut runner = circuit.runner();
    let error = runner.set_public_inputs(&[]).unwrap_err();

    let diagnostic = circuit.diagnose_error(error);
    assert_eq!(diagnostic.phase(), &DiagnosticPhase::Caller);
    assert!(diagnostic.compiled_operation().is_none());
    assert!(diagnostic.operation_origins().is_empty());
    assert!(matches!(
        diagnostic.error(),
        CircuitError::PublicInputLengthMismatch {
            expected: 1,
            got: 0
        }
    ));
    assert!(matches!(
        diagnostic.into_error(),
        CircuitError::PublicInputLengthMismatch {
            expected: 1,
            got: 0
        }
    ));
}

#[test]
fn connected_input_conflict_has_both_canonical_aliases_in_numeric_order() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let left = builder.alloc_public_input("left_alias");
    let right = builder.alloc_public_input("right_alias");
    builder.connect(left, right);
    let circuit = builder.build().unwrap();
    let canonical = circuit.expr_to_widx[&left];
    assert_eq!(canonical, circuit.expr_to_widx[&right]);
    assert_eq!(
        circuit.provenance().unwrap().witness_origins(canonical),
        &[left, right]
    );

    let mut runner = circuit.runner();
    let error = runner
        .set_public_inputs(&[BabyBear::ONE, BabyBear::ZERO])
        .unwrap_err();
    let diagnostic = circuit.diagnose_error(error);
    assert_eq!(diagnostic.phase(), &DiagnosticPhase::Caller);
    assert!(diagnostic.compiled_operation().is_none());
    assert_eq!(
        diagnostic
            .witness_aliases()
            .iter()
            .map(|source| source.expr_id)
            .collect::<Vec<_>>(),
        vec![left, right]
    );
    let CircuitError::WitnessConflict { expr_ids, .. } = diagnostic.error() else {
        panic!("expected a typed witness conflict");
    };
    assert!(expr_ids.contains(&left));
    assert!(expr_ids.contains(&right));
    assert!(expr_ids.windows(2).all(|pair| pair[0] < pair[1]));
    let display = diagnostic.to_string();
    assert!(display.contains("left_alias"), "{display}");
    assert!(display.contains("right_alias"), "{display}");
}

#[test]
fn connected_conflict_display_is_stable_across_fresh_builds() {
    fn render() -> String {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let a = builder.alloc_public_input("alpha");
        let b = builder.alloc_public_input("beta");
        let c = builder.alloc_public_input("gamma");
        builder.connect(a, b);
        builder.connect(b, c);
        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();
        let error = runner
            .set_public_inputs(&[BabyBear::ONE, BabyBear::ZERO, BabyBear::ONE])
            .unwrap_err();
        circuit.diagnose_error(error).to_string()
    }

    let expected = render();
    assert!(expected.contains("alpha"), "{expected}");
    assert!(expected.contains("beta"), "{expected}");
    assert!(expected.contains("gamma"), "{expected}");
    for _ in 0..8 {
        assert_eq!(render(), expected);
    }
}

#[test]
fn large_connected_class_keeps_every_alias_with_bounded_display() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let inputs = builder.alloc_public_inputs(20, "connected_input");
    for pair in inputs.windows(2) {
        builder.connect(pair[0], pair[1]);
    }
    let circuit = builder.build().unwrap();
    let mut runner = circuit.runner();
    let mut values = vec![BabyBear::ONE; inputs.len()];
    values[1] = BabyBear::ZERO;
    let diagnostic = circuit.diagnose_error(runner.set_public_inputs(&values).unwrap_err());

    assert_eq!(diagnostic.witness_aliases().len(), inputs.len());
    assert_eq!(
        diagnostic
            .witness_aliases()
            .iter()
            .map(|source| source.expr_id)
            .collect::<Vec<_>>(),
        inputs
    );
    let CircuitError::WitnessConflict { expr_ids, .. } = diagnostic.error() else {
        panic!("expected a typed witness conflict");
    };
    assert_eq!(expr_ids.len(), inputs.len());
    let display = diagnostic.to_string();
    assert!(display.contains("(+12 more)"), "{display}");
    assert!(display.len() < 2000, "{display}");
}

#[test]
fn failing_zero_assertion_reports_the_arithmetic_that_violated_it() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let left = builder.alloc_public_input("left");
    let right = builder.alloc_public_input("right");
    builder.push_scope("balance_check");
    let sum = builder.alloc_add(left, right, "balance");
    builder.assert_zero(sum);
    builder.pop_scope();
    let circuit = builder.build().unwrap();
    let add_op_index = circuit
        .ops
        .iter()
        .position(|op| {
            matches!(
                op,
                Op::Alu {
                    kind: AluOpKind::Add,
                    ..
                }
            )
        })
        .unwrap();
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[BabyBear::from_u64(2), BabyBear::from_u64(3)])
        .unwrap();

    let diagnostic = runner.run_with_diagnostics().unwrap_err();
    assert!(matches!(
        diagnostic.error(),
        CircuitError::WitnessConflict { .. }
    ));
    assert_eq!(
        diagnostic.phase(),
        &DiagnosticPhase::Execution {
            compiled_op_index: add_op_index
        }
    );
    assert_eq!(diagnostic.operation_origins()[0].expr_id, sum);
    assert!(
        diagnostic
            .witness_aliases()
            .iter()
            .any(|source| source.expr_id == sum)
    );
    let display = diagnostic.to_string();
    assert!(display.contains("balance"), "{display}");
    assert!(display.contains("balance_check"), "{display}");
}

#[test]
fn compiled_dedup_retains_both_distinct_add_sources() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let lhs = builder.alloc_public_input("lhs");
    let lhs_alias = builder.alloc_public_input("lhs_alias");
    let rhs = builder.alloc_const(BabyBear::from_u64(9), "rhs");
    let supplied_output = builder.alloc_private_input("supplied_output");
    builder.connect(lhs, lhs_alias);
    let canonical = builder.alloc_add(lhs, rhs, "canonical_add");
    let duplicate = builder.alloc_add(lhs_alias, rhs, "duplicate_add");
    assert_ne!(canonical, duplicate);
    builder.connect(supplied_output, duplicate);
    let circuit = builder.build().unwrap();

    let add_indices: Vec<_> = circuit
        .ops
        .iter()
        .enumerate()
        .filter_map(|(index, op)| {
            matches!(
                op,
                Op::Alu {
                    kind: AluOpKind::Add,
                    ..
                }
            )
            .then_some(index)
        })
        .collect();
    assert_eq!(add_indices.len(), 1, "the duplicate must be optimized away");
    assert_eq!(
        circuit
            .provenance()
            .unwrap()
            .operation_origins(add_indices[0]),
        &[canonical, duplicate]
    );
}

#[test]
fn fused_multiply_add_retains_each_source_without_shifting_later_origins() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let a = builder.alloc_public_input("a");
    let b = builder.alloc_public_input("b");
    let c = builder.alloc_public_input("c");
    let product = builder.alloc_mul(a, b, "product");
    let sum = builder.alloc_add(product, c, "sum");
    let later = builder.alloc_add(sum, c, "later");
    let circuit = builder.build().unwrap();

    let fused_index = circuit
        .ops
        .iter()
        .position(|op| {
            matches!(
                op,
                Op::Alu {
                    kind: AluOpKind::MulAdd,
                    ..
                }
            )
        })
        .expect("the single-use multiply is fused with its add");
    let provenance = circuit.provenance().unwrap();
    assert_eq!(provenance.operation_origins(fused_index), &[product, sum]);
    let later_index = circuit
        .ops
        .iter()
        .position(|op| {
            matches!(
                op,
                Op::Alu {
                    kind: AluOpKind::Add,
                    ..
                }
            )
        })
        .expect("the later add remains separate");
    assert_eq!(provenance.operation_origins(later_index), &[later]);
}

#[test]
fn reused_expression_keeps_first_label_and_innermost_scope() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let a = builder.alloc_public_input("a");
    let b = builder.alloc_public_input("b");
    builder.push_scope("outer");
    builder.push_scope("inner");
    let first = builder.alloc_add(a, b, "first_label");
    builder.pop_scope();
    let reused = builder.alloc_add(a, b, "later_label");
    builder.pop_scope();
    assert_eq!(first, reused, "the builder reuses the same expression");

    let circuit = builder.build().unwrap();
    let source = circuit.provenance().unwrap().allocation(first).unwrap();
    assert_eq!(source.label, "first_label");
    assert_eq!(source.scope.as_deref(), Some("inner"));
}

#[test]
fn changed_operation_count_invalidates_builder_source_context() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    builder.push_scope("original_scope");
    let input = builder.alloc_public_input("original_input");
    let _constant = builder.alloc_const(BabyBear::from_u64(7), "removable_constant");
    builder.pop_scope();
    let mut circuit = builder.build().unwrap();

    assert_eq!(
        circuit
            .provenance()
            .unwrap()
            .allocation(input)
            .unwrap()
            .label,
        "original_input"
    );
    let constant_index = circuit
        .ops
        .iter()
        .position(|op| matches!(op, Op::Const { val, .. } if *val == BabyBear::from_u64(7)))
        .expect("the builder compiled the distinct constant");
    circuit.ops.remove(constant_index);
    assert!(circuit.provenance().is_none());

    let public_op_index = circuit
        .ops
        .iter()
        .position(|op| matches!(op, Op::Public { out, .. } if *out == circuit.expr_to_widx[&input]))
        .expect("the missing public input remains compiled");
    let diagnostic = circuit.runner().run_with_diagnostics().unwrap_err();
    assert!(matches!(
        diagnostic.error(),
        CircuitError::PublicInputNotSet { .. }
    ));
    assert_eq!(
        diagnostic.phase(),
        &DiagnosticPhase::Execution {
            compiled_op_index: public_op_index
        }
    );
    assert_eq!(
        diagnostic.compiled_operation().unwrap().kind,
        CompiledOpKind::Public
    );
    assert!(diagnostic.operation_origins().is_empty());
    assert_eq!(
        diagnostic
            .witness_aliases()
            .iter()
            .map(|source| source.expr_id)
            .collect::<Vec<_>>(),
        vec![input]
    );
    assert!(
        diagnostic
            .witness_aliases()
            .iter()
            .all(|source| source.allocation.is_none())
    );
    let display = diagnostic.to_string();
    assert!(display.contains("original operation origins: unavailable"));
    assert!(!display.contains("original_input"), "{display}");
    assert!(!display.contains("original_scope"), "{display}");
}

#[test]
fn manually_constructed_circuit_still_reports_a_typed_failure() {
    let mut circuit = Circuit::<BabyBear>::new(1, HashMap::new());
    circuit.ops.push(Op::Public {
        out: WitnessId(0),
        public_pos: 0,
    });
    assert!(circuit.provenance().is_none());

    let diagnostic = circuit.runner().run_with_diagnostics().unwrap_err();
    assert!(matches!(
        diagnostic.error(),
        CircuitError::PublicInputNotSet {
            witness_id: WitnessId(0)
        }
    ));
    assert_eq!(
        diagnostic.phase(),
        &DiagnosticPhase::Execution {
            compiled_op_index: 0
        }
    );
    assert_eq!(
        diagnostic.compiled_operation().unwrap().kind,
        CompiledOpKind::Public
    );
    assert!(diagnostic.operation_origins().is_empty());
    assert!(diagnostic.to_string().contains("Public"));
}

#[test]
fn diagnostic_trace_generators_choose_the_first_sorted_failure() {
    fn fail_alpha(
        _: &OpStateMap,
    ) -> Result<Option<Box<dyn NonPrimitiveTrace<BabyBear>>>, CircuitError> {
        Err(CircuitError::UnknownTag {
            tag: "alpha".into(),
        })
    }
    fn fail_beta(
        _: &OpStateMap,
    ) -> Result<Option<Box<dyn NonPrimitiveTrace<BabyBear>>>, CircuitError> {
        Err(CircuitError::UnknownTag { tag: "beta".into() })
    }

    let mut circuit = Circuit::<BabyBear>::new(0, HashMap::new());
    let alpha = NpoTypeId::new("alpha");
    let beta = NpoTypeId::new("beta");
    circuit
        .non_primitive_trace_generators
        .insert(beta.clone(), fail_beta);
    circuit
        .non_primitive_trace_generators
        .insert(alpha.clone(), fail_alpha);
    circuit.non_primitive_trace_generator_order = vec![alpha, beta];

    for _ in 0..8 {
        let diagnostic = circuit.runner().run_with_diagnostics().unwrap_err();
        assert!(matches!(
            diagnostic.error(),
            CircuitError::UnknownTag { tag } if tag == "alpha"
        ));
        assert_eq!(
            diagnostic.phase(),
            &DiagnosticPhase::NonPrimitiveTrace {
                op_type: NpoTypeId::new("alpha")
            }
        );
        assert!(diagnostic.compiled_operation().is_none());
    }
}

#[test]
fn labels_and_scopes_do_not_change_successful_traces_or_preprocessed_data() {
    fn build(label: &'static str, scope: &'static str) -> Circuit<BabyBear> {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        builder.push_scope(scope);
        let input = builder.alloc_public_input(label);
        let one = builder.alloc_const(BabyBear::ONE, label);
        let _sum = builder.alloc_add(input, one, label);
        builder.pop_scope();
        builder.build().unwrap()
    }

    let first = build("first", "first_scope");
    let second = build("second", "second_scope");
    assert_eq!(first.ops, second.ops);
    assert_eq!(first.expr_to_widx, second.expr_to_widx);
    assert_eq!(
        first.generate_preprocessed_columns::<1>().unwrap(),
        second.generate_preprocessed_columns::<1>().unwrap()
    );

    let run = |circuit: &Circuit<BabyBear>, with_diagnostics: bool| {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[BabyBear::from_u64(9)]).unwrap();
        if with_diagnostics {
            runner.run_with_diagnostics().unwrap()
        } else {
            runner.run().unwrap()
        }
    };
    assert_eq!(run(&first, false), run(&first, true));
    assert_eq!(run(&first, true), run(&second, true));
}
