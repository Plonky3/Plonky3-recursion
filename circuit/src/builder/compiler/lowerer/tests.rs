use alloc::vec;

use hashbrown::HashMap;
use p3_field::PrimeCharacteristicRing;
use p3_test_utils::baby_bear_params::BabyBear;

use super::ExpressionLowerer;
use crate::AluOpKind;
use crate::expr::{Expr, ExpressionGraph};
use crate::ops::Op;
use crate::types::{ExprId, WitnessAllocator, WitnessId};

/// Helper to create an expression graph with a zero constant pre-allocated.
fn create_graph_with_zero() -> ExpressionGraph<BabyBear> {
    let mut graph = ExpressionGraph::new();
    // The zero constant must be at index 0 — the lowerer relies on this for boolean checks.
    graph.add_expr(Expr::Const(BabyBear::ZERO));
    graph
}

#[test]
fn test_lowering() {
    // Build a graph: (p0 + p1) * 3 - 7, then divide by p2.
    let mut graph = create_graph_with_zero();

    // Add constant nodes.
    let c_zero = ExprId::ZERO;
    let c_one = graph.add_expr(Expr::Const(BabyBear::ONE));
    let c_three = graph.add_expr(Expr::Const(BabyBear::from_u64(3)));
    let c_seven = graph.add_expr(Expr::Const(BabyBear::from_u64(7)));

    // Add three public input nodes.
    let p0 = graph.add_expr(Expr::Public(0));
    let p1 = graph.add_expr(Expr::Public(1));
    let p2 = graph.add_expr(Expr::Public(2));

    // Build the arithmetic chain.
    let sum = graph.add_expr(Expr::Add { lhs: p0, rhs: p1 });
    let prod = graph.add_expr(Expr::Mul {
        lhs: sum,
        rhs: c_three,
    });
    let diff = graph.add_expr(Expr::Sub {
        lhs: prod,
        rhs: c_seven,
    });
    let quot = graph.add_expr(Expr::Div { lhs: diff, rhs: p2 });

    // Run the lowerer with no connects and no non-primitive ops.
    let connects = vec![];
    let alloc = WitnessAllocator::new();
    let registry = HashMap::new();

    let lowerer = ExpressionLowerer::new(&graph, &[], &connects, 3, 0, alloc, &registry);
    let result = lowerer.lower().unwrap();

    // 4 constants + 3 publics + 1 add + 1 mul + 1 neg-const + 1 sub-as-add + 1 div-as-mul = 12.
    assert_eq!(result.ops.len(), 12);

    // Verify Phase A: constants emitted first (positions 0..4).
    match &result.ops[0] {
        Op::Const { out, val } => {
            assert_eq!(out.0, 0);
            assert_eq!(*val, BabyBear::ZERO);
        }
        _ => panic!("Expected Const at position 0"),
    }
    match &result.ops[1] {
        Op::Const { out, val } => {
            assert_eq!(out.0, 1);
            assert_eq!(*val, BabyBear::ONE);
        }
        _ => panic!("Expected Const at position 1"),
    }
    match &result.ops[2] {
        Op::Const { out, val } => {
            assert_eq!(out.0, 2);
            assert_eq!(*val, BabyBear::from_u64(3));
        }
        _ => panic!("Expected Const at position 2"),
    }
    match &result.ops[3] {
        Op::Const { out, val } => {
            assert_eq!(out.0, 3);
            assert_eq!(*val, BabyBear::from_u64(7));
        }
        _ => panic!("Expected Const at position 3"),
    }

    // Verify Phase B: public inputs emitted next (positions 4..7).
    match &result.ops[4] {
        Op::Public { out, public_pos } => {
            assert_eq!(out.0, 4);
            assert_eq!(*public_pos, 0);
        }
        _ => panic!("Expected Public at position 4"),
    }
    match &result.ops[5] {
        Op::Public { out, public_pos } => {
            assert_eq!(out.0, 5);
            assert_eq!(*public_pos, 1);
        }
        _ => panic!("Expected Public at position 5"),
    }
    match &result.ops[6] {
        Op::Public { out, public_pos } => {
            assert_eq!(out.0, 6);
            assert_eq!(*public_pos, 2);
        }
        _ => panic!("Expected Public at position 6"),
    }

    // Verify Phase C: arithmetic operations in DAG order.
    // Position 7: add (p0 + p1).
    match &result.ops[7] {
        Op::Alu {
            kind: AluOpKind::Add,
            a,
            b,
            out,
            ..
        } => {
            assert_eq!(*a, WitnessId(4));
            assert_eq!(*b, WitnessId(5));
            assert_eq!(out.0, 7);
        }
        _ => panic!("Expected ALU Add at position 7"),
    }

    // Position 8: multiply (sum * 3).
    match &result.ops[8] {
        Op::Alu {
            kind: AluOpKind::Mul,
            a,
            b,
            out,
            ..
        } => {
            assert_eq!(*a, WitnessId(7));
            assert_eq!(*b, WitnessId(2));
            assert_eq!(out.0, 8);
        }
        _ => panic!("Expected ALU Mul at position 8"),
    }

    // Position 9: synthetic negated constant for the subtraction fast path.
    match &result.ops[9] {
        Op::Const { out: _, val } => {
            assert_eq!(*val, -BabyBear::from_u64(7));
        }
        _ => panic!("Expected Const(-7) at position 9"),
    }

    // Position 10: subtraction encoded as forward add (prod + (-7)).
    match &result.ops[10] {
        Op::Alu {
            kind: AluOpKind::Add,
            a,
            b: _,
            out,
            ..
        } => {
            assert_eq!(*a, WitnessId(8));
            assert_eq!(*out, WitnessId(9));
        }
        _ => panic!("Expected ALU Add (Sub encoding) at position 10"),
    }

    // Position 11: division encoded as constraint (p2 * quot = diff).
    match &result.ops[11] {
        Op::Alu {
            kind: AluOpKind::Mul,
            a,
            b: _,
            out,
            ..
        } => {
            assert_eq!(*a, WitnessId(6));
            assert_eq!(*out, WitnessId(9));
        }
        _ => panic!("Expected ALU Mul (Div encoding) at position 10"),
    }

    // Verify public rows: each public input maps to its sequential witness slot.
    assert_eq!(result.public_rows.len(), 3);
    assert_eq!(result.public_rows[0], WitnessId(4));
    assert_eq!(result.public_rows[1], WitnessId(5));
    assert_eq!(result.public_rows[2], WitnessId(6));

    // Verify the expression-to-witness map covers all 11 nodes (10 graph + 1 synthetic neg).
    assert_eq!(result.expr_to_widx.len(), 11);
    assert_eq!(result.expr_to_widx[&c_zero], WitnessId(0));
    assert_eq!(result.expr_to_widx[&c_one], WitnessId(1));
    assert_eq!(result.expr_to_widx[&c_three], WitnessId(2));
    assert_eq!(result.expr_to_widx[&c_seven], WitnessId(3));
    assert_eq!(result.expr_to_widx[&p0], WitnessId(4));
    assert_eq!(result.expr_to_widx[&p1], WitnessId(5));
    assert_eq!(result.expr_to_widx[&p2], WitnessId(6));
    assert_eq!(result.expr_to_widx[&sum], WitnessId(7));
    assert_eq!(result.expr_to_widx[&prod], WitnessId(8));
    assert_eq!(result.expr_to_widx[&diff], WitnessId(9));
    assert_eq!(result.expr_to_widx[&quot], WitnessId(11));

    // Verify public-only mapping mirrors the public rows.
    assert_eq!(result.public_mappings.len(), 3);
    assert_eq!(result.public_mappings[&p0], WitnessId(4));
    assert_eq!(result.public_mappings[&p1], WitnessId(5));
    assert_eq!(result.public_mappings[&p2], WitnessId(6));

    // Total witness count: 4 consts + 3 pubs + 1 add + 1 mul + 1 neg + 1 sub + 1 quot = 12.
    assert_eq!(result.witness_count, 12);
}

#[test]
fn test_witness_sharing() {
    // Build a graph with connect pairs that force witness sharing:
    // - c_42 and p0 share a witness (connect pair).
    // - p1, p2, p3 share a witness (transitive chain).
    // - sum and p4 share a witness (connect pair).
    let mut graph = create_graph_with_zero();

    let c_zero = ExprId::ZERO;
    let c_one = graph.add_expr(Expr::Const(BabyBear::ONE));
    let c_42 = graph.add_expr(Expr::Const(BabyBear::from_u64(42)));
    let c_99 = graph.add_expr(Expr::Const(BabyBear::from_u64(99)));

    let p0 = graph.add_expr(Expr::Public(0));
    let p1 = graph.add_expr(Expr::Public(1));
    let p2 = graph.add_expr(Expr::Public(2));
    let p3 = graph.add_expr(Expr::Public(3));
    let p4 = graph.add_expr(Expr::Public(4));

    let sum = graph.add_expr(Expr::Add {
        lhs: p0,
        rhs: c_one,
    });

    // Declare the connect pairs that enforce witness sharing.
    let connects = vec![(c_42, p0), (p1, p2), (p2, p3), (sum, p4)];
    let alloc = WitnessAllocator::new();
    let registry = HashMap::new();

    let lowerer = ExpressionLowerer::new(&graph, &[], &connects, 5, 0, alloc, &registry);
    let result = lowerer.lower().unwrap();

    // 4 constants + 5 publics + 1 add + 1 deferred-const-connect equality (MulAdd) = 11 ops.
    // The `connect(c_42, p0)` pair is a value↔const equality: it is NO LONGER aliased into the
    // constant's slot (the unsound representation). Instead `p0` keeps its OWN witness and a
    // `MulAdd(p0, ZERO, c_42, p0)` row binds `p0 == 42`. The value↔value chains (p1/p2/p3 and
    // sum/p4) still alias normally.
    assert_eq!(result.ops.len(), 11);

    match &result.ops[0] {
        Op::Const { out, val } => {
            assert_eq!(out.0, 0);
            assert_eq!(*val, BabyBear::ZERO);
        }
        _ => panic!("Expected Const(0) at position 0"),
    }
    match &result.ops[1] {
        Op::Const { out, val } => {
            assert_eq!(out.0, 1);
            assert_eq!(*val, BabyBear::ONE);
        }
        _ => panic!("Expected Const(1) at position 1"),
    }
    match &result.ops[2] {
        Op::Const { out, val } => {
            assert_eq!(out.0, 2);
            assert_eq!(*val, BabyBear::from_u64(42));
        }
        _ => panic!("Expected Const(42) at position 2"),
    }
    match &result.ops[3] {
        Op::Const { out, val } => {
            assert_eq!(out.0, 3);
            assert_eq!(*val, BabyBear::from_u64(99));
        }
        _ => panic!("Expected Const(99) at position 3"),
    }

    // p0 NO LONGER shares c_42's witness 2 — the const-connect is a deferred equality, so p0
    // gets its OWN fresh witness (4). The `MulAdd` at the end binds it to 42.
    match &result.ops[4] {
        Op::Public { out, public_pos } => {
            assert_eq!(out.0, 4);
            assert_eq!(*public_pos, 0);
        }
        _ => panic!("Expected Public(0) at position 4"),
    }
    // p1, p2, p3 all share witness 5 (transitive value↔value connect chain).
    match &result.ops[5] {
        Op::Public { out, public_pos } => {
            assert_eq!(out.0, 5);
            assert_eq!(*public_pos, 1);
        }
        _ => panic!("Expected Public(1) at position 5"),
    }
    match &result.ops[6] {
        Op::Public { out, public_pos } => {
            assert_eq!(out.0, 5);
            assert_eq!(*public_pos, 2);
        }
        _ => panic!("Expected Public(2) at position 6"),
    }
    match &result.ops[7] {
        Op::Public { out, public_pos } => {
            assert_eq!(out.0, 5);
            assert_eq!(*public_pos, 3);
        }
        _ => panic!("Expected Public(3) at position 7"),
    }
    // p4 shares witness 6 with the sum result (value↔value connect pair).
    match &result.ops[8] {
        Op::Public { out, public_pos } => {
            assert_eq!(out.0, 6);
            assert_eq!(*public_pos, 4);
        }
        _ => panic!("Expected Public(4) at position 8"),
    }

    // The add reads p0 (witness 4) and c_one (witness 1), writes to witness 6 (shared with p4).
    match &result.ops[9] {
        Op::Alu {
            kind: AluOpKind::Add,
            a,
            b,
            out,
            ..
        } => {
            assert_eq!(*a, WitnessId(4));
            assert_eq!(*b, WitnessId(1));
            assert_eq!(*out, WitnessId(6));
        }
        _ => panic!("Expected Add at position 9"),
    }

    // The deferred `connect(c_42, p0)` equality: MulAdd(p0, ZERO, c_42, p0) ⇔ p0 == 42, keeping
    // p0 in its OWN slot (4) and never aliasing it into c_42's constant slot (2).
    match &result.ops[10] {
        Op::Alu {
            kind: AluOpKind::MulAdd,
            a,
            b,
            c,
            out,
            ..
        } => {
            assert_eq!(*a, WitnessId(4)); // p0 (value)
            assert_eq!(*b, WitnessId(0)); // ZERO
            assert_eq!(*c, Some(WitnessId(2))); // c_42 (the constant)
            assert_eq!(*out, WitnessId(4)); // out == p0's own slot
        }
        _ => panic!("Expected MulAdd (deferred const-connect equality) at position 10"),
    }

    // Verify public rows reflect the new witnesses.
    assert_eq!(result.public_rows.len(), 5);
    assert_eq!(result.public_rows[0], WitnessId(4)); // p0 has its own slot now
    assert_eq!(result.public_rows[1], WitnessId(5));
    assert_eq!(result.public_rows[2], WitnessId(5));
    assert_eq!(result.public_rows[3], WitnessId(5));
    assert_eq!(result.public_rows[4], WitnessId(6));

    // Verify the expression-to-witness map.
    assert_eq!(result.expr_to_widx.len(), 10);
    // c_42 keeps its own constant slot (2); p0 is NOT aliased to it.
    assert_eq!(result.expr_to_widx[&c_42], WitnessId(2));
    assert_eq!(result.expr_to_widx[&p0], WitnessId(4));
    // p1, p2, p3 share witness 5.
    assert_eq!(result.expr_to_widx[&p1], WitnessId(5));
    assert_eq!(result.expr_to_widx[&p2], WitnessId(5));
    assert_eq!(result.expr_to_widx[&p3], WitnessId(5));
    // sum and p4 share witness 6.
    assert_eq!(result.expr_to_widx[&sum], WitnessId(6));
    assert_eq!(result.expr_to_widx[&p4], WitnessId(6));
    // Unconnected constants each have their own witness.
    assert_eq!(result.expr_to_widx[&c_zero], WitnessId(0));
    assert_eq!(result.expr_to_widx[&c_one], WitnessId(1));
    assert_eq!(result.expr_to_widx[&c_99], WitnessId(3));

    assert_eq!(result.public_mappings.len(), 5);
    assert_eq!(result.public_mappings[&p0], WitnessId(4));
    assert_eq!(result.public_mappings[&p1], WitnessId(5));
    assert_eq!(result.public_mappings[&p2], WitnessId(5));
    assert_eq!(result.public_mappings[&p3], WitnessId(5));
    assert_eq!(result.public_mappings[&p4], WitnessId(6));

    // 7 unique witnesses now: 0 (zero), 1 (one), 2 (42), 3 (99), 4 (p0), 5 (p1/p2/p3), 6 (sum/p4).
    assert_eq!(result.witness_count, 7);
}

#[test]
fn test_error_handling() {
    use crate::builder::CircuitBuilderError;

    // An add node referencing a non-existent expression should fail during lowering.
    let mut graph = create_graph_with_zero();
    graph.add_expr(Expr::Add {
        lhs: ExprId(99),
        rhs: ExprId::ZERO,
    });

    let connects = vec![];
    let alloc = WitnessAllocator::new();
    let registry = HashMap::new();
    let lowerer = ExpressionLowerer::new(&graph, &[], &connects, 0, 0, alloc, &registry);
    let result = lowerer.lower();

    // Should report the missing left operand with a diagnostic context.
    assert!(result.is_err());
    match result {
        Err(CircuitBuilderError::MissingExprMapping { expr_id, context }) => {
            assert_eq!(expr_id, ExprId(99));
            assert!(context.contains("Add lhs"));
        }
        _ => panic!("Expected MissingExprMapping error for Add lhs"),
    }

    // A mul node referencing a non-existent right operand should also fail.
    let mut graph = create_graph_with_zero();
    graph.add_expr(Expr::Mul {
        lhs: ExprId::ZERO,
        rhs: ExprId(88),
    });

    let connects = vec![];
    let alloc = WitnessAllocator::new();
    let registry = HashMap::new();
    let lowerer = ExpressionLowerer::new(&graph, &[], &connects, 0, 0, alloc, &registry);
    let result = lowerer.lower();

    // Should report the missing right operand.
    assert!(result.is_err());
    match result {
        Err(CircuitBuilderError::MissingExprMapping { expr_id, context }) => {
            assert_eq!(expr_id, ExprId(88));
            assert!(context.contains("Mul rhs"));
        }
        _ => panic!("Expected MissingExprMapping error for Mul rhs"),
    }
}

#[test]
fn test_private_input_lowering() {
    // Private inputs allocate witness slots but do not emit operations.
    let mut graph = create_graph_with_zero();
    let priv0 = graph.add_expr(Expr::PrivateInput(0));
    let priv1 = graph.add_expr(Expr::PrivateInput(1));

    let connects = vec![];
    let alloc = WitnessAllocator::new();
    let registry = HashMap::new();
    let lowerer = ExpressionLowerer::new(&graph, &[], &connects, 0, 2, alloc, &registry);
    let result = lowerer.lower().unwrap();

    // Only the zero constant emits an op; private inputs are witness-only.
    assert_eq!(result.ops.len(), 1);
    // Both private inputs should have distinct witness slots recorded in the positional vector.
    assert_eq!(result.private_input_rows.len(), 2);
    assert_eq!(result.expr_to_widx[&priv0], result.private_input_rows[0]);
    assert_eq!(result.expr_to_widx[&priv1], result.private_input_rows[1]);
    assert_ne!(result.private_input_rows[0], result.private_input_rows[1]);
}

#[test]
fn test_bool_check_lowering() {
    // A boolean check on a public input should emit a single BoolCheck ALU op.
    let mut graph = create_graph_with_zero();
    let p0 = graph.add_expr(Expr::Public(0));
    let bc = graph.add_expr(Expr::BoolCheck { val: p0 });

    let connects = vec![];
    let alloc = WitnessAllocator::new();
    let registry = HashMap::new();
    let lowerer = ExpressionLowerer::new(&graph, &[], &connects, 1, 0, alloc, &registry);
    let result = lowerer.lower().unwrap();

    // Verify that exactly one BoolCheck op was emitted.
    let bc_op = result.ops.iter().find(|op| {
        matches!(
            op,
            Op::Alu {
                kind: AluOpKind::BoolCheck,
                ..
            }
        )
    });
    assert!(bc_op.is_some(), "expected a BoolCheck op");
    // The check node should have its own witness slot.
    assert!(result.expr_to_widx.contains_key(&bc));
}

#[test]
fn test_mul_add_lowering() {
    // Fused multiply-add: result = 1 * 2 + 3.
    let mut graph = create_graph_with_zero();
    let c1 = graph.add_expr(Expr::Const(BabyBear::ONE));
    let c2 = graph.add_expr(Expr::Const(BabyBear::from_u64(2)));
    let c3 = graph.add_expr(Expr::Const(BabyBear::from_u64(3)));
    let ma = graph.add_expr(Expr::MulAdd {
        a: c1,
        b: c2,
        c: c3,
    });

    let connects = vec![];
    let alloc = WitnessAllocator::new();
    let registry = HashMap::new();
    let lowerer = ExpressionLowerer::new(&graph, &[], &connects, 0, 0, alloc, &registry);
    let result = lowerer.lower().unwrap();

    // Verify that exactly one MulAdd op was emitted.
    let ma_op = result.ops.iter().find(|op| {
        matches!(
            op,
            Op::Alu {
                kind: AluOpKind::MulAdd,
                ..
            }
        )
    });
    assert!(ma_op.is_some(), "expected a MulAdd op");
    assert!(result.expr_to_widx.contains_key(&ma));

    // Verify operand wiring: a, b, c should point to the constant witnesses.
    if let Op::Alu {
        a,
        b,
        c: Some(c_w),
        out,
        ..
    } = ma_op.unwrap()
    {
        assert_eq!(*a, result.expr_to_widx[&c1]);
        assert_eq!(*b, result.expr_to_widx[&c2]);
        assert_eq!(*c_w, result.expr_to_widx[&c3]);
        assert_eq!(*out, result.expr_to_widx[&ma]);
    }
}

#[test]
fn test_horner_acc_lowering() {
    // Horner accumulator: result = 1 * 2 + 3 - 4.
    let mut graph = create_graph_with_zero();
    let acc = graph.add_expr(Expr::Const(BabyBear::ONE));
    let alpha = graph.add_expr(Expr::Const(BabyBear::from_u64(2)));
    let p_at_z = graph.add_expr(Expr::Const(BabyBear::from_u64(3)));
    let p_at_x = graph.add_expr(Expr::Const(BabyBear::from_u64(4)));
    let ha = graph.add_expr(Expr::HornerAcc {
        acc,
        alpha,
        p_at_z,
        p_at_x,
    });

    let connects = vec![];
    let alloc = WitnessAllocator::new();
    let registry = HashMap::new();
    let lowerer = ExpressionLowerer::new(&graph, &[], &connects, 0, 0, alloc, &registry);
    let result = lowerer.lower().unwrap();

    // Verify that exactly one HornerAcc op was emitted.
    let ha_op = result.ops.iter().find(|op| {
        matches!(
            op,
            Op::Alu {
                kind: AluOpKind::HornerAcc,
                ..
            }
        )
    });
    assert!(ha_op.is_some(), "expected a HornerAcc op");
    assert!(result.expr_to_widx.contains_key(&ha));
}

#[test]
fn test_backfill_connect_unvisited_member() {
    // Verify that VALUE↔VALUE connect-class members all share the same witness, even if some
    // members would not be directly visited during lowering (the backfill pass is the safety
    // net). A VALUE↔CONST connect is NOT aliased: the const keeps its own slot and a deferred
    // equality constraint binds the value to it.
    let mut graph = create_graph_with_zero();
    let c1 = graph.add_expr(Expr::Const(BabyBear::ONE));
    let p0 = graph.add_expr(Expr::Public(0));
    let p1 = graph.add_expr(Expr::Public(1));
    // (c1, p0) is a value↔const equality (deferred); (p0, p1) is value↔value (aliased).
    let connects = vec![(c1, p0), (p0, p1)];
    let alloc = WitnessAllocator::new();
    let registry = HashMap::new();
    let lowerer = ExpressionLowerer::new(&graph, &[], &connects, 2, 0, alloc, &registry);
    let result = lowerer.lower().unwrap();

    // p0 and p1 (value↔value) share one witness.
    let w = result.expr_to_widx[&p0];
    assert_eq!(result.expr_to_widx[&p1], w);
    // c1 (the constant) keeps its OWN slot — NOT aliased into the p0/p1 class.
    assert_ne!(result.expr_to_widx[&c1], w);
    // The deferred const-connect equality (MulAdd binding p0 == c1) was emitted.
    let has_eq = result.ops.iter().any(|op| {
        matches!(
            op,
            Op::Alu { kind: AluOpKind::MulAdd, c: Some(cw), out, .. }
                if *out == w && *cw == result.expr_to_widx[&c1]
        )
    });
    assert!(has_eq, "expected a deferred const-connect MulAdd binding p0 == c1");
}
