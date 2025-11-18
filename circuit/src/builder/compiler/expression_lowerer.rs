use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};

use hashbrown::{HashMap, HashSet};
use p3_field::PrimeCharacteristicRing;

use crate::Op;
use crate::builder::CircuitBuilderError;
use crate::builder::compiler::get_witness_id;
use crate::expr::{Expr, ExpressionGraph};
use crate::op::WitnessHintsFiller;
use crate::types::{ExprId, WitnessAllocator, WitnessId};

/// Sparse disjoint-set "find" with path compression over a HashMap (iterative).
/// If `x` is not present, it's its own representative and is not inserted.
#[inline]
fn dsu_find(parents: &mut HashMap<usize, usize>, x: usize) -> usize {
    let mut v = x;
    let mut trail: Vec<usize> = Vec::new();
    while let Some(&p) = parents.get(&v) {
        if p == v {
            break;
        }
        trail.push(v);
        v = p;
    }
    let root = v;
    for u in trail {
        parents.insert(u, root);
    }
    root
}

/// Sparse disjoint-set "union" by attaching `b`'s root under `a`'s root.
#[inline]
fn dsu_union(parents: &mut HashMap<usize, usize>, a: usize, b: usize) {
    let ra = dsu_find(parents, a);
    let rb = dsu_find(parents, b);
    if ra != rb {
        parents.insert(rb, ra);
    }
}

/// Build a sparse disjoint-set forest honoring all pending connects.
/// Returns a parent map keyed only by ExprIds that appear in `connects`.
fn build_connect_dsu(connects: &[(ExprId, ExprId)]) -> HashMap<usize, usize> {
    let mut parents: HashMap<usize, usize> = HashMap::new();
    for (a, b) in connects {
        let ai = a.0 as usize;
        let bi = b.0 as usize;
        dsu_union(&mut parents, ai, bi);
    }
    parents
}

/// Responsible for lowering expression graphs to primitive operations.
///
/// This component handles:
/// - Converting high-level expressions to primitive operations (Const, Public, Add, Mul, etc.)
/// - Managing witness allocation during lowering
/// - Implementing the DSU-based connection strategy for witness sharing
/// - Building the mapping from ExprId to WitnessId
#[derive(Debug)]
pub struct ExpressionLowerer<'a, F> {
    /// Reference to the expression graph to lower
    graph: &'a ExpressionGraph<F>,

    /// Pending connections between expressions
    pending_connects: &'a [(ExprId, ExprId)],

    /// Number of public inputs
    public_input_count: usize,

    /// The fillers corresponding to the witness hints sequences.
    /// The order of fillers must match the order in which the witness hints sequences were allocated.
    hints_fillers: &'a [Box<dyn WitnessHintsFiller<F>>],

    /// Witness allocator
    witness_alloc: WitnessAllocator,
}

impl<'a, F> ExpressionLowerer<'a, F>
where
    F: Clone + PrimeCharacteristicRing + PartialEq + Eq + core::hash::Hash,
{
    /// Creates a new expression lowerer.
    pub const fn new(
        graph: &'a ExpressionGraph<F>,
        pending_connects: &'a [(ExprId, ExprId)],
        public_input_count: usize,
        hints_fillers: &'a [Box<dyn WitnessHintsFiller<F>>],
        witness_alloc: WitnessAllocator,
    ) -> Self {
        Self {
            graph,
            pending_connects,
            public_input_count,
            hints_fillers,
            witness_alloc,
        }
    }

    /// Lowers the expression graph to primitive operations.
    ///
    /// Returns:
    /// - Vector of primitive operations
    /// - Vector mapping public input positions to witness IDs
    /// - HashMap mapping expression IDs to witness IDs
    /// - HashMap mapping public input expression IDs to witness IDs
    /// - Total witness count
    #[allow(clippy::type_complexity)]
    pub fn lower(
        mut self,
    ) -> Result<
        (
            Vec<Op<F>>,
            Vec<WitnessId>,
            HashMap<ExprId, WitnessId>,
            HashMap<ExprId, WitnessId>,
            u32,
        ),
        CircuitBuilderError,
    > {
        // Build DSU over expression IDs to honor connect(a, b)
        let mut parents = build_connect_dsu(self.pending_connects);

        // Track nodes that participate in any connect
        let in_connect: HashSet<usize> = self
            .pending_connects
            .iter()
            .flat_map(|(a, b)| [a.0 as usize, b.0 as usize])
            .collect();

        let mut primitive_ops = Vec::new();
        let mut expr_to_widx: HashMap<ExprId, WitnessId> = HashMap::new();
        let mut public_rows: Vec<WitnessId> = vec![WitnessId(0); self.public_input_count];
        let mut public_mappings = HashMap::new();

        // Unified class slot map: DSU root -> chosen out slot
        let mut root_to_widx: HashMap<usize, WitnessId> = HashMap::new();

        // Pass A: emit constants (once per Const node; Expr-level dedup ensures one per value)
        for (expr_idx, expr) in self.graph.nodes().iter().enumerate() {
            if let Expr::Const(val) = expr {
                let id = ExprId(expr_idx as u32);
                let w = self.witness_alloc.alloc();
                primitive_ops.push(Op::Const {
                    out: w,
                    val: val.clone(),
                });
                expr_to_widx.insert(id, w);

                // If this Const participates in a connect class, bind the class to the const slot
                if in_connect.contains(&expr_idx) {
                    let root = dsu_find(&mut parents, expr_idx);
                    root_to_widx.insert(root, w);
                }
            }
        }

        let mut alloc_witness_id_for_expr = |expr_idx: usize| {
            if in_connect.contains(&expr_idx) {
                let root = dsu_find(&mut parents, expr_idx);
                *root_to_widx
                    .entry(root)
                    .or_insert_with(|| self.witness_alloc.alloc())
            } else {
                self.witness_alloc.alloc()
            }
        };

        // Pass B: emit public inputs
        for (expr_idx, expr) in self.graph.nodes().iter().enumerate() {
            if let Expr::Public(pos) = expr {
                let id = ExprId(expr_idx as u32);

                let out_widx = alloc_witness_id_for_expr(expr_idx);

                primitive_ops.push(Op::Public {
                    out: out_widx,
                    public_pos: *pos,
                });
                expr_to_widx.insert(id, out_widx);
                public_rows[*pos] = out_widx;
                public_mappings.insert(id, out_widx);
            }
        }

        // Pass C: emit arithmetic and unconstrained ops in creation order; tie outputs to class slot if connected
        let mut hints_sequence = vec![];
        let mut fillers_iter = self.hints_fillers.iter().cloned();
        for (expr_idx, expr) in self.graph.nodes().iter().enumerate() {
            let expr_id = ExprId(expr_idx as u32);
            match expr {
                Expr::Const(_) | Expr::Public(_) => { /* handled above */ }
                Expr::Witness { is_last_hint } => {
                    let expr_id = ExprId(expr_idx as u32);
                    let out_widx = alloc_witness_id_for_expr(expr_idx);
                    expr_to_widx.insert(expr_id, out_widx);
                    hints_sequence.push(out_widx);
                    if *is_last_hint {
                        // Since new hints can only be added through `alloc_witness_hints` or `alloc_witness_hints_default_filler`,
                        // there will always be exactly one filler for each sequence of expressions of the form
                        // `Witness{false}, ..., Witness{false}, Witness{true}`.
                        // Therefore, this error can only occur if the expression lowerer is not being used
                        // with the circuit builder as intended.
                        let filler = fillers_iter.next().ok_or(
                            CircuitBuilderError::MissingWitnessFiller {
                                sequence: hints_sequence.clone(),
                            },
                        )?;
                        let inputs = filler
                            .inputs()
                            .iter()
                            .map(|expr_id| {
                                expr_to_widx
                                    .get(expr_id)
                                    .ok_or(CircuitBuilderError::MissingExprMapping {
                                        expr_id: *expr_id,
                                        context: "Unconstrained op".to_string(),
                                    })
                                    .copied()
                            })
                            .collect::<Result<Vec<WitnessId>, _>>()?;
                        primitive_ops.push(Op::Unconstrained {
                            inputs,
                            outputs: hints_sequence,
                            filler,
                        });
                        hints_sequence = vec![];
                    }
                }
                Expr::Add { lhs, rhs } => {
                    let out_widx = alloc_witness_id_for_expr(expr_idx);
                    let a_widx =
                        get_witness_id(&expr_to_widx, *lhs, &format!("Add lhs for {expr_id:?}"))?;
                    let b_widx =
                        get_witness_id(&expr_to_widx, *rhs, &format!("Add rhs for {expr_id:?}"))?;
                    primitive_ops.push(Op::Add {
                        a: a_widx,
                        b: b_widx,
                        out: out_widx,
                    });
                    expr_to_widx.insert(expr_id, out_widx);
                }
                Expr::Sub { lhs, rhs } => {
                    let result_widx = alloc_witness_id_for_expr(expr_idx);
                    let lhs_widx =
                        get_witness_id(&expr_to_widx, *lhs, &format!("Sub lhs for {expr_id:?}"))?;
                    let rhs_widx =
                        get_witness_id(&expr_to_widx, *rhs, &format!("Sub rhs for {expr_id:?}"))?;
                    // Encode lhs - rhs = result as result + rhs = lhs.
                    primitive_ops.push(Op::Add {
                        a: rhs_widx,
                        b: result_widx,
                        out: lhs_widx,
                    });
                    expr_to_widx.insert(expr_id, result_widx);
                }
                Expr::Mul { lhs, rhs } => {
                    let out_widx = alloc_witness_id_for_expr(expr_idx);
                    let a_widx =
                        get_witness_id(&expr_to_widx, *lhs, &format!("Mul lhs for {expr_id:?}"))?;
                    let b_widx =
                        get_witness_id(&expr_to_widx, *rhs, &format!("Mul rhs for {expr_id:?}"))?;
                    primitive_ops.push(Op::Mul {
                        a: a_widx,
                        b: b_widx,
                        out: out_widx,
                    });
                    expr_to_widx.insert(expr_id, out_widx);
                }
                Expr::Div { lhs, rhs } => {
                    // lhs / rhs = out  is encoded as rhs * out = lhs
                    let b_widx = alloc_witness_id_for_expr(expr_idx);
                    let out_widx =
                        get_witness_id(&expr_to_widx, *lhs, &format!("Div lhs for {expr_id:?}"))?;
                    let a_widx =
                        get_witness_id(&expr_to_widx, *rhs, &format!("Div rhs for {expr_id:?}"))?;
                    primitive_ops.push(Op::Mul {
                        a: a_widx,
                        b: b_widx,
                        out: out_widx,
                    });
                    // The output of Div is the b_widx.
                    expr_to_widx.insert(expr_id, b_widx);
                }
            }
        }

        if !hints_sequence.is_empty() {
            return Err(CircuitBuilderError::MalformedWitnessHitnsSequence {
                sequence: hints_sequence,
            });
        }

        if fillers_iter.next().is_some() {
            return Err(CircuitBuilderError::UnmatchetWitnessFiller {});
        }

        let witness_count = self.witness_alloc.witness_count();
        Ok((
            primitive_ops,
            public_rows,
            expr_to_widx,
            public_mappings,
            witness_count,
        ))
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;

    use super::*;

    /// Helper to create an expression graph with a zero constant pre-allocated.
    fn create_graph_with_zero() -> ExpressionGraph<BabyBear> {
        let mut graph = ExpressionGraph::new();
        graph.add_expr(Expr::Const(BabyBear::ZERO));
        graph
    }

    #[test]
    fn test_dsu_utilities() {
        // Single element is its own root when not in the map
        let mut parents = HashMap::new();
        assert_eq!(dsu_find(&mut parents, 5), 5);

        // Path compression: chain 1 -> 2 -> 3 where 3 is root
        parents.clear();
        parents.insert(1, 2);
        parents.insert(2, 3);
        parents.insert(3, 3);
        assert_eq!(dsu_find(&mut parents, 1), 3);
        assert_eq!(parents[&1], 3); // Path compression applies

        // Union merges two elements
        parents.clear();
        dsu_union(&mut parents, 10, 20);
        assert_eq!(dsu_find(&mut parents, 10), dsu_find(&mut parents, 20));

        // Union is idempotent
        parents.clear();
        dsu_union(&mut parents, 7, 7);
        assert_eq!(dsu_find(&mut parents, 7), 7);
    }

    #[test]
    fn test_build_connect_dsu() {
        // Empty connections
        let connects = vec![];
        let parents = build_connect_dsu(&connects);
        assert!(parents.is_empty());

        // Single pair connection
        let connects = vec![(ExprId(1), ExprId(2))];
        let mut parents = build_connect_dsu(&connects);
        assert_eq!(dsu_find(&mut parents, 1), dsu_find(&mut parents, 2));

        // Transitive chain: 0 -> 1 -> 2 -> 3 all share same root
        let connects = vec![
            (ExprId(0), ExprId(1)),
            (ExprId(1), ExprId(2)),
            (ExprId(2), ExprId(3)),
        ];
        let mut parents = build_connect_dsu(&connects);
        let root = dsu_find(&mut parents, 0);
        assert_eq!(root, dsu_find(&mut parents, 1));
        assert_eq!(root, dsu_find(&mut parents, 2));
        assert_eq!(root, dsu_find(&mut parents, 3));

        // Multiple disjoint components: (0,1) separate from (2,3)
        let connects = vec![(ExprId(0), ExprId(1)), (ExprId(2), ExprId(3))];
        let mut parents = build_connect_dsu(&connects);
        let root01 = dsu_find(&mut parents, 0);
        assert_eq!(root01, dsu_find(&mut parents, 1));
        let root23 = dsu_find(&mut parents, 2);
        assert_eq!(root23, dsu_find(&mut parents, 3));
        assert_ne!(root01, root23);
    }

    #[test]
    fn test_lowering() {
        // Build a circuit exercising all primitive types and operations:
        // - Multiple constants (zero, one, 3, 7)
        // - Public inputs (positions 0, 1, 2)
        // - Arithmetic operations: Add, Sub, Mul, Div
        // - Circuit computes: ((p0 + p1) * c3 - c7) / p2
        let mut graph = create_graph_with_zero();

        // Constants
        let c_zero = ExprId::ZERO; // Pre-allocated
        let c_one = graph.add_expr(Expr::Const(BabyBear::ONE));
        let c_three = graph.add_expr(Expr::Const(BabyBear::from_u64(3)));
        let c_seven = graph.add_expr(Expr::Const(BabyBear::from_u64(7)));

        // Public inputs
        let p0 = graph.add_expr(Expr::Public(0));
        let p1 = graph.add_expr(Expr::Public(1));
        let p2 = graph.add_expr(Expr::Public(2));

        // Operations: (p0 + p1) * c3 - c7
        let sum = graph.add_expr(Expr::Add { lhs: p0, rhs: p1 });
        let prod = graph.add_expr(Expr::Mul {
            lhs: sum,
            rhs: c_three,
        });
        let diff = graph.add_expr(Expr::Sub {
            lhs: prod,
            rhs: c_seven,
        });

        // Final division: diff / p2
        let quot = graph.add_expr(Expr::Div { lhs: diff, rhs: p2 });

        let connects = vec![];
        let hints_fillers = vec![];
        let alloc = WitnessAllocator::new();

        let lowerer = ExpressionLowerer::new(&graph, &connects, 3, &hints_fillers, alloc);
        let (prims, public_rows, expr_map, public_map, witness_count) = lowerer.lower().unwrap();

        // Verify Primitives
        //
        // Expected: 4 Const + 3 Public + 1 Add + 1 Mul + 1 Add (Sub) + 1 Mul (Div) = 11 total
        assert_eq!(prims.len(), 11);

        // Constants (Pass A): zero, one, three, seven
        match &prims[0] {
            Op::Const { out, val } => {
                assert_eq!(out.0, 0);
                assert_eq!(*val, BabyBear::ZERO);
            }
            _ => panic!("Expected Const at position 0"),
        }
        match &prims[1] {
            Op::Const { out, val } => {
                assert_eq!(out.0, 1);
                assert_eq!(*val, BabyBear::ONE);
            }
            _ => panic!("Expected Const at position 1"),
        }
        match &prims[2] {
            Op::Const { out, val } => {
                assert_eq!(out.0, 2);
                assert_eq!(*val, BabyBear::from_u64(3));
            }
            _ => panic!("Expected Const at position 2"),
        }
        match &prims[3] {
            Op::Const { out, val } => {
                assert_eq!(out.0, 3);
                assert_eq!(*val, BabyBear::from_u64(7));
            }
            _ => panic!("Expected Const at position 3"),
        }

        // Public inputs (Pass B): p0, p1, p2
        match &prims[4] {
            Op::Public { out, public_pos } => {
                assert_eq!(out.0, 4);
                assert_eq!(*public_pos, 0);
            }
            _ => panic!("Expected Public at position 4"),
        }
        match &prims[5] {
            Op::Public { out, public_pos } => {
                assert_eq!(out.0, 5);
                assert_eq!(*public_pos, 1);
            }
            _ => panic!("Expected Public at position 5"),
        }
        match &prims[6] {
            Op::Public { out, public_pos } => {
                assert_eq!(out.0, 6);
                assert_eq!(*public_pos, 2);
            }
            _ => panic!("Expected Public at position 6"),
        }

        // Arithmetic operations (Pass C): Add, Mul, Add (encoding Sub), Mul (encoding Div)
        // Add: sum = p0 + p1
        match &prims[7] {
            Op::Add { a, b, out } => {
                assert_eq!(*a, WitnessId(4)); // p0
                assert_eq!(*b, WitnessId(5)); // p1
                assert_eq!(out.0, 7); // sum
            }
            _ => panic!("Expected Add at position 7"),
        }

        // Mul: prod = sum * c3
        match &prims[8] {
            Op::Mul { a, b, out } => {
                assert_eq!(*a, WitnessId(7)); // sum
                assert_eq!(*b, WitnessId(2)); // c_three
                assert_eq!(out.0, 8); // prod
            }
            _ => panic!("Expected Mul at position 8"),
        }

        // Sub encoded as Add: diff + c7 = prod
        match &prims[9] {
            Op::Add { a, b, out } => {
                assert_eq!(*a, WitnessId(3)); // c_seven (rhs)
                assert_eq!(*b, WitnessId(9)); // diff (result)
                assert_eq!(*out, WitnessId(8)); // prod (lhs)
            }
            _ => panic!("Expected Add (Sub encoding) at position 9"),
        }

        // Div encoded as Mul: p2 * quot = diff
        match &prims[10] {
            Op::Mul { a, b, out } => {
                assert_eq!(*a, WitnessId(6)); // p2 (divisor)
                assert_eq!(*b, WitnessId(10)); // quot (result)
                assert_eq!(*out, WitnessId(9)); // diff (dividend)
            }
            _ => panic!("Expected Mul (Div encoding) at position 10"),
        }

        // Verify Public Rows
        assert_eq!(public_rows.len(), 3);
        assert_eq!(public_rows[0], WitnessId(4)); // p0
        assert_eq!(public_rows[1], WitnessId(5)); // p1
        assert_eq!(public_rows[2], WitnessId(6)); // p2

        // Verify Expression to Witness Mapping
        assert_eq!(expr_map.len(), 11); // All 11 expressions mapped
        assert_eq!(expr_map[&c_zero], WitnessId(0));
        assert_eq!(expr_map[&c_one], WitnessId(1));
        assert_eq!(expr_map[&c_three], WitnessId(2));
        assert_eq!(expr_map[&c_seven], WitnessId(3));
        assert_eq!(expr_map[&p0], WitnessId(4));
        assert_eq!(expr_map[&p1], WitnessId(5));
        assert_eq!(expr_map[&p2], WitnessId(6));
        assert_eq!(expr_map[&sum], WitnessId(7));
        assert_eq!(expr_map[&prod], WitnessId(8));
        assert_eq!(expr_map[&diff], WitnessId(9));
        assert_eq!(expr_map[&quot], WitnessId(10));

        // Verify Public Mapping
        assert_eq!(public_map.len(), 3);
        assert_eq!(public_map[&p0], WitnessId(4));
        assert_eq!(public_map[&p1], WitnessId(5));
        assert_eq!(public_map[&p2], WitnessId(6));

        // Verify Witness Count
        assert_eq!(witness_count, 11);
    }

    #[test]
    fn test_witness_sharing() {
        // Test witness sharing scenarios:
        // 1. Constants connected to publics (const binds the shared witness)
        // 2. Transitive connections among publics (all share one witness)
        // 3. Operation results connected to other expressions
        // 4. Multiple disjoint connection groups
        //
        // Circuit: c42 ~ p0, p1 ~ p2 ~ p3, (p0 + c1) ~ p4, c99 (standalone)
        let mut graph = create_graph_with_zero();

        // Constants
        let c_zero = ExprId::ZERO;
        let c_one = graph.add_expr(Expr::Const(BabyBear::ONE));
        let c_42 = graph.add_expr(Expr::Const(BabyBear::from_u64(42)));
        let c_99 = graph.add_expr(Expr::Const(BabyBear::from_u64(99)));

        // Public inputs
        let p0 = graph.add_expr(Expr::Public(0));
        let p1 = graph.add_expr(Expr::Public(1));
        let p2 = graph.add_expr(Expr::Public(2));
        let p3 = graph.add_expr(Expr::Public(3));
        let p4 = graph.add_expr(Expr::Public(4));

        // Operation: sum = p0 + c1
        let sum = graph.add_expr(Expr::Add {
            lhs: p0,
            rhs: c_one,
        });

        // Connections:
        // Group A: c42 ~ p0 (const binds witness)
        // Group B: p1 ~ p2 ~ p3 (transitive)
        // Group C: sum ~ p4 (operation result shared)
        let connects = vec![(c_42, p0), (p1, p2), (p2, p3), (sum, p4)];
        let hints_fillers = vec![];
        let alloc = WitnessAllocator::new();

        let lowerer = ExpressionLowerer::new(&graph, &connects, 5, &hints_fillers, alloc);
        let (prims, public_rows, expr_map, public_map, witness_count) = lowerer.lower().unwrap();

        // Verify Primitives
        //
        // 4 Const + 5 Public + 1 Add = 10 primitives
        assert_eq!(prims.len(), 10);

        // Constants
        match &prims[0] {
            Op::Const { out, val } => {
                assert_eq!(out.0, 0);
                assert_eq!(*val, BabyBear::ZERO);
            }
            _ => panic!("Expected Const(0) at position 0"),
        }
        match &prims[1] {
            Op::Const { out, val } => {
                assert_eq!(out.0, 1);
                assert_eq!(*val, BabyBear::ONE);
            }
            _ => panic!("Expected Const(1) at position 1"),
        }
        match &prims[2] {
            Op::Const { out, val } => {
                assert_eq!(out.0, 2); // c42's witness (will be shared with p0)
                assert_eq!(*val, BabyBear::from_u64(42));
            }
            _ => panic!("Expected Const(42) at position 2"),
        }
        match &prims[3] {
            Op::Const { out, val } => {
                assert_eq!(out.0, 3);
                assert_eq!(*val, BabyBear::from_u64(99));
            }
            _ => panic!("Expected Const(99) at position 3"),
        }

        // Public inputs
        match &prims[4] {
            Op::Public { out, public_pos } => {
                assert_eq!(out.0, 2); // Shares witness with c42
                assert_eq!(*public_pos, 0);
            }
            _ => panic!("Expected Public(0) at position 4"),
        }
        match &prims[5] {
            Op::Public { out, public_pos } => {
                assert_eq!(out.0, 4); // New witness for p1 group
                assert_eq!(*public_pos, 1);
            }
            _ => panic!("Expected Public(1) at position 5"),
        }
        match &prims[6] {
            Op::Public { out, public_pos } => {
                assert_eq!(out.0, 4); // Shares witness with p1
                assert_eq!(*public_pos, 2);
            }
            _ => panic!("Expected Public(2) at position 6"),
        }
        match &prims[7] {
            Op::Public { out, public_pos } => {
                assert_eq!(out.0, 4); // Shares witness with p1, p2
                assert_eq!(*public_pos, 3);
            }
            _ => panic!("Expected Public(3) at position 7"),
        }
        match &prims[8] {
            Op::Public { out, public_pos } => {
                assert_eq!(out.0, 5); // New witness for p4 group
                assert_eq!(*public_pos, 4);
            }
            _ => panic!("Expected Public(4) at position 8"),
        }

        // Add operation: sum = p0 + c1
        match &prims[9] {
            Op::Add { a, b, out } => {
                assert_eq!(*a, WitnessId(2)); // p0 (shares with c42)
                assert_eq!(*b, WitnessId(1)); // c1
                assert_eq!(*out, WitnessId(5)); // sum (shares with p4)
            }
            _ => panic!("Expected Add at position 9"),
        }

        // Verify Public Rows
        assert_eq!(public_rows.len(), 5);
        assert_eq!(public_rows[0], WitnessId(2)); // p0 shares with c42
        assert_eq!(public_rows[1], WitnessId(4)); // p1, p2, p3 all share
        assert_eq!(public_rows[2], WitnessId(4));
        assert_eq!(public_rows[3], WitnessId(4));
        assert_eq!(public_rows[4], WitnessId(5)); // p4 shares with sum

        // Verify Expression to Witness Mapping
        assert_eq!(expr_map.len(), 10);

        // Group A: c42 ~ p0 both map to witness 2
        assert_eq!(expr_map[&c_42], WitnessId(2));
        assert_eq!(expr_map[&p0], WitnessId(2));

        // Group B: p1, p2, p3 all map to witness 4
        assert_eq!(expr_map[&p1], WitnessId(4));
        assert_eq!(expr_map[&p2], WitnessId(4));
        assert_eq!(expr_map[&p3], WitnessId(4));

        // Group C: sum ~ p4 both map to witness 5
        assert_eq!(expr_map[&sum], WitnessId(5));
        assert_eq!(expr_map[&p4], WitnessId(5));

        // Standalone expressions
        assert_eq!(expr_map[&c_zero], WitnessId(0));
        assert_eq!(expr_map[&c_one], WitnessId(1));
        assert_eq!(expr_map[&c_99], WitnessId(3));

        // Verify Public Mapping
        assert_eq!(public_map.len(), 5);
        assert_eq!(public_map[&p0], WitnessId(2));
        assert_eq!(public_map[&p1], WitnessId(4));
        assert_eq!(public_map[&p2], WitnessId(4));
        assert_eq!(public_map[&p3], WitnessId(4));
        assert_eq!(public_map[&p4], WitnessId(5));

        // Verify Witness Count
        //
        // Witnesses: 0 (zero), 1 (one), 2 (c42/p0), 3 (c99), 4 (p1/p2/p3), 5 (sum/p4)
        assert_eq!(witness_count, 6);
    }

    #[test]
    fn test_error_handling() {
        // Test 1: Missing expression in Add operand
        let mut graph = create_graph_with_zero();
        graph.add_expr(Expr::Add {
            lhs: ExprId(99), // Non-existent
            rhs: ExprId::ZERO,
        });

        let connects = vec![];
        let hints_fillers = vec![];
        let alloc = WitnessAllocator::new();
        let lowerer = ExpressionLowerer::new(&graph, &connects, 0, &hints_fillers, alloc);
        let result = lowerer.lower();

        assert!(result.is_err());
        match result {
            Err(CircuitBuilderError::MissingExprMapping { expr_id, context }) => {
                assert_eq!(expr_id, ExprId(99));
                assert!(context.contains("Add lhs"));
            }
            _ => panic!("Expected MissingExprMapping error for Add lhs"),
        }

        // Test 2: Missing expression in Mul operand
        let mut graph = create_graph_with_zero();
        graph.add_expr(Expr::Mul {
            lhs: ExprId::ZERO,
            rhs: ExprId(88), // Non-existent
        });

        let connects = vec![];
        let hints_fillers = vec![];
        let alloc = WitnessAllocator::new();
        let lowerer = ExpressionLowerer::new(&graph, &connects, 0, &hints_fillers, alloc);
        let result = lowerer.lower();

        assert!(result.is_err());
        match result {
            Err(CircuitBuilderError::MissingExprMapping { expr_id, context }) => {
                assert_eq!(expr_id, ExprId(88));
                assert!(context.contains("Mul rhs"));
            }
            _ => panic!("Expected MissingExprMapping error for Mul rhs"),
        }

        // Test 3: Helper function error propagation
        let expr_map = HashMap::new();
        let result = get_witness_id(&expr_map, ExprId(77), "test context");

        match result {
            Err(CircuitBuilderError::MissingExprMapping { expr_id, context }) => {
                assert_eq!(expr_id, ExprId(77));
                assert_eq!(context, "test context");
            }
            _ => panic!("Expected MissingExprMapping error from get_witness_id"),
        }
    }

    // Property-based tests for DSU utilities and connect DSU construction
    #[cfg(test)]
    mod proptests {
        use proptest::prelude::*;

        use super::*;

        // Strategy for generating lists of ExprId connect relations
        fn connections(max_id: u32) -> impl Strategy<Value = Vec<(ExprId, ExprId)>> {
            prop::collection::vec((0..max_id, 0..max_id), 0..20).prop_map(|pairs| {
                pairs
                    .into_iter()
                    .map(|(a, b)| (ExprId(a), ExprId(b)))
                    .collect()
            })
        }

        proptest! {
            #[test]
            fn dsu_find_idempotent(connects in connections(50)) {
                let mut parents = build_connect_dsu(&connects);
                let test_ids: Vec<usize> = (0..50).collect();

                for &id in &test_ids {
                    let root1 = dsu_find(&mut parents, id);
                    let root2 = dsu_find(&mut parents, id);
                    prop_assert_eq!(root1, root2, "dsu_find should be idempotent");
                }
            }

            #[test]
            fn dsu_union_transitivity(connects in connections(30)) {
                let mut parents = build_connect_dsu(&connects);

                // Check that all explicitly connected pairs have the same root
                for (a, b) in &connects {
                    let ra = dsu_find(&mut parents, a.0 as usize);
                    let rb = dsu_find(&mut parents, b.0 as usize);
                    prop_assert_eq!(ra, rb, "connected nodes should have same root");
                }
            }

            #[test]
            fn dsu_union_commutative(a in 0u32..100, b in 0u32..100) {
                let mut parents1 = HashMap::new();
                let mut parents2 = HashMap::new();

                dsu_union(&mut parents1, a as usize, b as usize);
                dsu_union(&mut parents2, b as usize, a as usize);

                let r1a = dsu_find(&mut parents1, a as usize);
                let r1b = dsu_find(&mut parents1, b as usize);
                let r2a = dsu_find(&mut parents2, a as usize);
                let r2b = dsu_find(&mut parents2, b as usize);

                prop_assert_eq!(r1a, r1b, "union should connect a and b");
                prop_assert_eq!(r2a, r2b, "union should connect b and a");
            }
        }
    }
}
