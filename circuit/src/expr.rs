use alloc::vec::Vec;

use crate::types::{ExprId, NonPrimitiveOpId};

/// Expression DAG for field operations
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Expr<F> {
    /// Constant field element
    Const(F),
    /// Public input at declaration position
    Public(usize),
    /// Witness hints — allocates a `WitnessId` representing a
    /// non-deterministic hint. The boolean flag indicates whether
    /// this is the last witness in a sequence of related hints,
    /// where each sequence is produced through a shared generation process.
    Hint { is_last_hint: bool },
    /// Addition of two expressions
    Add { lhs: ExprId, rhs: ExprId },
    /// Subtraction of two expressions
    Sub { lhs: ExprId, rhs: ExprId },
    /// Multiplication of two expressions
    Mul { lhs: ExprId, rhs: ExprId },
    /// Division of two expressions
    Div { lhs: ExprId, rhs: ExprId },
    /// Anchor node for a non-primitive operation in the expression DAG.
    ///
    /// This node has no witness value itself, but it fixes the relative execution order
    /// of non-primitive ops w.r.t. other expressions during lowering.
    ///
    /// The `inputs` field contains all input expressions (flattened from witness_exprs),
    /// making dependencies explicit in the DAG structure. This enables proper topological
    /// analysis and ensures the lowerer emits ops after their inputs are available.
    ///
    /// For stateful ops (e.g., Poseidon perm chaining with `in_ctl=false`), `inputs` may
    /// be empty since chained values flow internally and are not materialized in the
    /// witness table. Execution order for such ops is determined by their position in
    /// the ops list during lowering.
    NonPrimitiveCall {
        op_id: NonPrimitiveOpId,
        inputs: Vec<ExprId>,
    },
    /// Output of a non-primitive operation.
    ///
    /// This node represents a value produced by a non-primitive op. The `call` field
    /// points to the `NonPrimitiveCall` expression node, making the dependency explicit
    /// in the DAG structure. `output_idx` selects which output of that op this refers to.
    NonPrimitiveOutput { call: ExprId, output_idx: u32 },
}

/// Graph for storing expression DAG nodes
#[derive(Debug, Clone, Default)]
pub struct ExpressionGraph<F> {
    nodes: Vec<Expr<F>>,
}

impl<F> ExpressionGraph<F> {
    pub const fn new() -> Self {
        Self { nodes: Vec::new() }
    }

    /// Add an expression to the graph, returning its ID
    pub fn add_expr(&mut self, expr: Expr<F>) -> ExprId {
        let id = ExprId(self.nodes.len() as u32);
        self.nodes.push(expr);
        id
    }

    /// Get an expression by ID
    pub fn get_expr(&self, id: ExprId) -> &Expr<F> {
        &self.nodes[id.0 as usize]
    }

    /// Get all nodes in the graph
    pub fn nodes(&self) -> &[Expr<F>] {
        &self.nodes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock extension field element for testing
    #[derive(Debug, Clone, PartialEq, Eq, Hash)]
    struct MockExtField(u64);

    #[test]
    fn test_expression_graph() {
        let mut graph = ExpressionGraph::<MockExtField>::new();

        let const_expr = Expr::Const(MockExtField(42));
        let public_expr = Expr::Public(0);

        let const_id = graph.add_expr(const_expr.clone());
        let public_id = graph.add_expr(public_expr.clone());

        assert_eq!(const_id, ExprId::ZERO);
        assert_eq!(public_id, ExprId(1));

        assert_eq!(graph.get_expr(const_id), &const_expr);
        assert_eq!(graph.get_expr(public_id), &public_expr);

        let add_expr = Expr::Add {
            lhs: const_id,
            rhs: public_id,
        };
        let add_id = graph.add_expr(add_expr.clone());
        assert_eq!(add_id, ExprId(2));
        assert_eq!(graph.get_expr(add_id), &add_expr);
    }

    #[cfg(test)]
    mod proptests {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #[test]
            fn expr_get_returns_added(vals in prop::collection::vec(any::<u64>().prop_map(MockExtField), 1..30)) {
                let mut graph = ExpressionGraph::<MockExtField>::new();
                let mut ids = Vec::new();

                for val in &vals {
                    let expr = Expr::Const(val.clone());
                    let id = graph.add_expr(expr.clone());
                    ids.push(id);
                }

                for (id, val) in ids.iter().zip(vals.iter()) {
                    let retrieved = graph.get_expr(*id);
                    prop_assert_eq!(retrieved, &Expr::Const(val.clone()), "get should return added expression");
                }
            }

            #[test]
            fn expr_primitive_ops(val1 in any::<u64>().prop_map(MockExtField), val2 in any::<u64>().prop_map(MockExtField)) {
                let mut graph = ExpressionGraph::<MockExtField>::new();

                let id1 = graph.add_expr(Expr::Const(val1));
                let id2 = graph.add_expr(Expr::Const(val2));

                let add_id = graph.add_expr(Expr::Add { lhs: id1, rhs: id2 });
                match graph.get_expr(add_id) {
                    Expr::Add { lhs, rhs } => {
                        prop_assert_eq!(*lhs, id1);
                        prop_assert_eq!(*rhs, id2);
                    }
                    _ => prop_assert!(false, "expected Add expr"),
                }

                let sub_id = graph.add_expr(Expr::Sub { lhs: id1, rhs: id2 });
                match graph.get_expr(sub_id) {
                    Expr::Sub { lhs, rhs } => {
                        prop_assert_eq!(*lhs, id1);
                        prop_assert_eq!(*rhs, id2);
                    }
                    _ => prop_assert!(false, "expected Sub expr"),
                }

                let mul_id = graph.add_expr(Expr::Mul { lhs: id1, rhs: id2 });
                match graph.get_expr(mul_id) {
                    Expr::Mul { lhs, rhs } => {
                        prop_assert_eq!(*lhs, id1);
                        prop_assert_eq!(*rhs, id2);
                    }
                    _ => prop_assert!(false, "expected Mul expr"),
                }

                let div_id = graph.add_expr(Expr::Div { lhs: id1, rhs: id2 });
                match graph.get_expr(div_id) {
                    Expr::Div { lhs, rhs } => {
                        prop_assert_eq!(*lhs, id1);
                        prop_assert_eq!(*rhs, id2);
                    }
                    _ => prop_assert!(false, "expected Div expr"),
                }
            }

            #[test]
            fn expr_public_positions(positions in prop::collection::vec(0usize..100, 0..20)) {
                let mut graph = ExpressionGraph::<MockExtField>::new();
                let mut ids = Vec::new();

                for &pos in &positions {
                    let id = graph.add_expr(Expr::Public(pos));
                    ids.push(id);
                }

                for (&id, &expected_pos) in ids.iter().zip(positions.iter()) {
                    match graph.get_expr(id) {
                        Expr::Public(pos) => {
                            prop_assert_eq!(*pos, expected_pos, "public position should match");
                        }
                        _ => prop_assert!(false, "expected Public expr"),
                    }
                }
            }

            #[test]
            fn expr_equality(val in any::<u64>().prop_map(MockExtField)) {
                let expr1 = Expr::Const(val.clone());
                let expr2 = Expr::Const(val.clone());
                let expr3 = Expr::Const(MockExtField(val.0 + 1));

                prop_assert_eq!(&expr1, &expr2, "same expressions should be equal");
                prop_assert_ne!(&expr1, &expr3, "different expressions should not be equal");
            }
        }
    }
}
