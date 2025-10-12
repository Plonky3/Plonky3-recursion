use alloc::vec::Vec;
use alloc::{format, vec};
use core::marker::PhantomData;

use hashbrown::{HashMap, HashSet};

use crate::op::{NonPrimitiveOpConfig, NonPrimitiveOpType};
use crate::{
    CircuitBuilderError, Expr, ExprId, NonPrimitiveOp, NonPrimitiveOpId, Prim, WitnessAllocator,
    WitnessId,
};

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

pub struct PublicInputData {
    rows: Vec<WitnessId>,
    mappings: HashMap<ExprId, WitnessId>,
}

pub struct CircuitLowerer<F> {
    /// Public inputs
    public_inputs: PublicInputData,
    /// Witness index allocator
    witness_alloc: WitnessAllocator,
    /// Connect disjoint-set forest
    parents: HashMap<usize, usize>,
    /// Nodes that participate in any connect
    in_connect: HashSet<usize>,
    /// Unified class slot map: DSU root -> chosen out slot
    root_to_widx: HashMap<usize, WitnessId>,

    _phantom: PhantomData<F>,
}

impl<F: Clone> CircuitLowerer<F> {
    pub fn new(pending_connects: &[(ExprId, ExprId)], public_inputs_count: usize) -> Self {
        let parents = build_connect_dsu(pending_connects);

        // Track nodes that participate in any connect
        let in_connect: HashSet<usize> = pending_connects
            .iter()
            .flat_map(|(a, b)| [a.0 as usize, b.0 as usize])
            .collect();

        let public_inputs = PublicInputData {
            rows: vec![WitnessId(0); public_inputs_count],
            mappings: HashMap::new(),
        };
        Self {
            witness_alloc: WitnessAllocator::new(),
            public_inputs,
            parents,
            in_connect,
            root_to_widx: HashMap::new(),
            _phantom: PhantomData,
        }
    }

    /// Perform the full lowering process.
    #[allow(clippy::type_complexity)]
    pub fn lower(
        &mut self,
        expressions: &[Expr<F>],
        non_primitive_ops: &[(NonPrimitiveOpId, NonPrimitiveOpType, Vec<ExprId>)],
        enabled_ops: &HashMap<NonPrimitiveOpType, NonPrimitiveOpConfig>,
    ) -> Result<
        (
            Vec<Prim<F>>,
            Vec<WitnessId>,
            HashMap<ExprId, WitnessId>,
            HashMap<ExprId, WitnessId>,
            u32,
            Vec<NonPrimitiveOp>,
        ),
        CircuitBuilderError,
    > {
        // Stage 1: Lower expressions to primitives
        let (primitive_ops, expr_to_widx) = self.lower_to_primitives(expressions)?;

        // Stage 2: Lower non-primitive operations using the expr_to_widx mapping
        let lowered_non_primitive_ops =
            self.lower_non_primitive_ops(non_primitive_ops, enabled_ops, &expr_to_widx)?;

        // Stage 3: IR transformations and optimizations
        let primitive_ops = Self::optimize_primitives(primitive_ops);

        Ok((
            primitive_ops,
            self.public_inputs.rows.clone(),
            expr_to_widx,
            self.public_inputs.mappings.clone(),
            self.witness_alloc.witness_count(),
            lowered_non_primitive_ops,
        ))
    }

    #[allow(clippy::type_complexity)]
    fn lower_to_primitives(
        &mut self,
        expressions: &[Expr<F>],
    ) -> Result<(Vec<Prim<F>>, HashMap<ExprId, WitnessId>), CircuitBuilderError> {
        let mut primitive_ops = Vec::new();
        let mut expr_to_widx: HashMap<ExprId, WitnessId> = HashMap::new();

        // Pass 1: Constants
        self.lower_constants(&mut primitive_ops, &mut expr_to_widx, expressions)?;

        // Pass 2: Public inputs
        self.lower_public_inputs(&mut primitive_ops, &mut expr_to_widx, expressions)?;

        // Pass 3: Arithmetic operations
        self.lower_arithmetic_ops(&mut primitive_ops, &mut expr_to_widx, expressions)?;

        Ok((primitive_ops, expr_to_widx))
    }

    fn alloc_witness_id_for_expr(&mut self, expr_idx: usize) -> WitnessId {
        if self.in_connect.contains(&expr_idx) {
            let root = dsu_find(&mut self.parents, expr_idx);
            *self
                .root_to_widx
                .entry(root)
                .or_insert_with(|| self.witness_alloc.alloc())
        } else {
            self.witness_alloc.alloc()
        }
    }

    /// Pass A: emit constants (once per Const node; Expr-level dedup ensures one per value)
    fn lower_constants(
        &mut self,
        primitive_ops: &mut Vec<Prim<F>>,
        expr_to_widx: &mut HashMap<ExprId, WitnessId>,
        expressions: &[Expr<F>],
    ) -> Result<(), CircuitBuilderError> {
        for (expr_idx, expr) in expressions.iter().enumerate() {
            if let Expr::Const(val) = expr {
                let id = ExprId(expr_idx as u32);
                let w = self.witness_alloc.alloc();
                primitive_ops.push(Prim::Const {
                    out: w,
                    val: val.clone(),
                });
                expr_to_widx.insert(id, w);

                // If this Const participates in a connect class, bind the class to the const slot
                if self.in_connect.contains(&expr_idx) {
                    let root = dsu_find(&mut self.parents, expr_idx);
                    self.root_to_widx.insert(root, w);
                }
            }
        }

        Ok(())
    }

    fn lower_public_inputs(
        &mut self,
        primitive_ops: &mut Vec<Prim<F>>,
        expr_to_widx: &mut HashMap<ExprId, WitnessId>,
        expressions: &[Expr<F>],
    ) -> Result<(), CircuitBuilderError> {
        for (expr_idx, expr) in expressions.iter().enumerate() {
            if let Expr::Public(pos) = expr {
                let id = ExprId(expr_idx as u32);

                let out_widx = self.alloc_witness_id_for_expr(expr_idx);

                primitive_ops.push(Prim::Public {
                    out: out_widx,
                    public_pos: *pos,
                });
                expr_to_widx.insert(id, out_widx);
                self.public_inputs.rows[*pos] = out_widx;
                self.public_inputs.mappings.insert(id, out_widx);
            }
        }

        Ok(())
    }

    fn lower_arithmetic_ops(
        &mut self,
        primitive_ops: &mut Vec<Prim<F>>,
        expr_to_widx: &mut HashMap<ExprId, WitnessId>,
        expressions: &[Expr<F>],
    ) -> Result<(), CircuitBuilderError> {
        for (expr_idx, expr) in expressions.iter().enumerate() {
            let expr_id = ExprId(expr_idx as u32);
            match expr {
                Expr::Const(_) | Expr::Public(_) => { /* handled above */ }
                Expr::Add { lhs, rhs } => {
                    let out_widx = self.alloc_witness_id_for_expr(expr_idx);
                    let a_widx = Self::get_witness_id(
                        expr_to_widx,
                        *lhs,
                        &format!("Add lhs for {expr_id:?}"),
                    )?;
                    let b_widx = Self::get_witness_id(
                        expr_to_widx,
                        *rhs,
                        &format!("Add rhs for {expr_id:?}"),
                    )?;
                    primitive_ops.push(Prim::Add {
                        a: a_widx,
                        b: b_widx,
                        out: out_widx,
                    });
                    expr_to_widx.insert(expr_id, out_widx);
                }
                Expr::Sub { lhs, rhs } => {
                    let result_widx = self.alloc_witness_id_for_expr(expr_idx);
                    let lhs_widx = Self::get_witness_id(
                        expr_to_widx,
                        *lhs,
                        &format!("Sub lhs for {expr_id:?}"),
                    )?;
                    let rhs_widx = Self::get_witness_id(
                        expr_to_widx,
                        *rhs,
                        &format!("Sub rhs for {expr_id:?}"),
                    )?;
                    // Encode lhs - rhs = result as result + rhs = lhs.
                    primitive_ops.push(Prim::Add {
                        a: rhs_widx,
                        b: result_widx,
                        out: lhs_widx,
                    });
                    expr_to_widx.insert(expr_id, result_widx);
                }
                Expr::Mul { lhs, rhs } => {
                    let out_widx = self.alloc_witness_id_for_expr(expr_idx);
                    let a_widx = Self::get_witness_id(
                        expr_to_widx,
                        *lhs,
                        &format!("Mul lhs for {expr_id:?}"),
                    )?;
                    let b_widx = Self::get_witness_id(
                        expr_to_widx,
                        *rhs,
                        &format!("Mul rhs for {expr_id:?}"),
                    )?;
                    primitive_ops.push(Prim::Mul {
                        a: a_widx,
                        b: b_widx,
                        out: out_widx,
                    });
                    expr_to_widx.insert(expr_id, out_widx);
                }
                Expr::Div { lhs, rhs } => {
                    // lhs / rhs = out  is encoded as rhs * out = lhs
                    let b_widx = self.alloc_witness_id_for_expr(expr_idx);
                    let out_widx = Self::get_witness_id(
                        expr_to_widx,
                        *lhs,
                        &format!("Div lhs for {expr_id:?}"),
                    )?;
                    let a_widx = Self::get_witness_id(
                        expr_to_widx,
                        *rhs,
                        &format!("Div rhs for {expr_id:?}"),
                    )?;
                    primitive_ops.push(Prim::Mul {
                        a: a_widx,
                        b: b_widx,
                        out: out_widx,
                    });
                    // The output of Div is the b_widx.
                    expr_to_widx.insert(expr_id, b_widx);
                }
            }
        }

        Ok(())
    }

    fn lower_non_primitive_ops(
        &mut self,
        non_primitive_ops: &[(NonPrimitiveOpId, NonPrimitiveOpType, Vec<ExprId>)],
        enabled_ops: &HashMap<NonPrimitiveOpType, NonPrimitiveOpConfig>,
        expr_to_widx: &HashMap<ExprId, WitnessId>,
    ) -> Result<Vec<NonPrimitiveOp>, CircuitBuilderError> {
        let mut lowered_ops = Vec::new();

        for (_op_id, op_type, witness_exprs) in non_primitive_ops {
            let config = enabled_ops.get(op_type);
            match op_type {
                NonPrimitiveOpType::MmcsVerify => {
                    let config = match config {
                        Some(NonPrimitiveOpConfig::MmcsVerifyConfig(config)) => Ok(config),
                        _ => Err(CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                            op: op_type.clone(),
                        }),
                    }?;
                    if witness_exprs.len() != config.input_size() {
                        return Err(CircuitBuilderError::NonPrimitiveOpArity {
                            op: "MmcsVerify",
                            expected: config.input_size(),
                            got: witness_exprs.len(),
                        });
                    }
                    let leaf_widx: Vec<WitnessId> = (0..config.ext_field_digest_elems)
                        .map(|i| {
                            Self::get_witness_id(
                                expr_to_widx,
                                witness_exprs[i],
                                "MmcsVerify leaf input",
                            )
                        })
                        .collect::<Result<_, _>>()?;
                    let index_widx = Self::get_witness_id(
                        expr_to_widx,
                        witness_exprs[config.ext_field_digest_elems],
                        "MmcsVerify index input",
                    )?;
                    let root_widx = (config.ext_field_digest_elems + 1..config.input_size())
                        .map(|i| {
                            Self::get_witness_id(
                                expr_to_widx,
                                witness_exprs[i],
                                "MmcsVerify root input",
                            )
                        })
                        .collect::<Result<_, _>>()?;

                    lowered_ops.push(NonPrimitiveOp::MmcsVerify {
                        leaf: leaf_widx,
                        index: index_widx,
                        root: root_widx,
                    });
                }
                NonPrimitiveOpType::FriVerify => {
                    todo!() // TODO: Add FRIVerify when it lands
                } // Add more variants here as needed
            }
        }

        Ok(lowered_ops)
    }

    fn optimize_primitives(primitive_ops: Vec<Prim<F>>) -> Vec<Prim<F>> {
        // Future passes can be added here:
        // - Dead code elimination
        // - Common subexpression elimination
        // - Instruction combining
        // - Constant folding
        primitive_ops
    }

    /// Helper function to get WitnessId with descriptive error messages
    fn get_witness_id(
        expr_to_widx: &HashMap<ExprId, WitnessId>,
        expr_id: ExprId,
        context: &str,
    ) -> Result<WitnessId, CircuitBuilderError> {
        expr_to_widx
            .get(&expr_id)
            .copied()
            .ok_or_else(|| CircuitBuilderError::MissingExprMapping {
                expr_id,
                context: context.into(),
            })
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::CircuitBuilder;

    #[test]
    fn test_build_connect_dsu_basic() {
        // 0~1~3~4 in one set; 2 alone
        let connects = vec![
            (ExprId::ZERO, ExprId(1)),
            (ExprId(3), ExprId(4)),
            (ExprId(1), ExprId(4)),
            (ExprId(2), ExprId(2)), // self-union no-op
        ];
        let mut parents = build_connect_dsu(&connects);
        let r0 = dsu_find(&mut parents, 0);
        let r1 = dsu_find(&mut parents, 1);
        let r3 = dsu_find(&mut parents, 3);
        let r4 = dsu_find(&mut parents, 4);
        let r2 = dsu_find(&mut parents, 2);
        assert_eq!(r0, r1);
        assert_eq!(r0, r3);
        assert_eq!(r0, r4);
        assert_ne!(r0, r2);
    }

    #[test]
    fn test_lower_to_primitives_constants() {
        // Test constant lowering creates Const primitive operations
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let c1 = builder.add_const(BabyBear::from_u64(42));
        let c2 = builder.add_const(BabyBear::from_u64(100));

        let (primitives, public_rows, expr_to_widx, public_mappings, _witness_count, _non_prim_ops) =
            builder.lower().unwrap();

        // Expected primitives: 3 constants (ZERO, 42, 100)
        let expected_primitives = vec![
            Prim::Const {
                out: WitnessId(0),
                val: BabyBear::ZERO,
            },
            Prim::Const {
                out: WitnessId(1),
                val: BabyBear::from_u64(42),
            },
            Prim::Const {
                out: WitnessId(2),
                val: BabyBear::from_u64(100),
            },
        ];
        assert_eq!(primitives, expected_primitives);

        // No public inputs
        let expected_public_rows: Vec<WitnessId> = vec![];
        assert_eq!(public_rows, expected_public_rows);

        // Expression to witness mapping
        let mut expected_expr_to_widx = HashMap::new();
        expected_expr_to_widx.insert(ExprId::ZERO, WitnessId(0));
        expected_expr_to_widx.insert(c1, WitnessId(1));
        expected_expr_to_widx.insert(c2, WitnessId(2));
        assert_eq!(expr_to_widx, expected_expr_to_widx);

        // No public mappings
        let expected_public_mappings = HashMap::new();
        assert_eq!(public_mappings, expected_public_mappings);
    }

    #[test]
    fn test_lower_to_primitives_public_inputs() {
        // Test public input lowering creates Public primitive operations
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let p1 = builder.add_public_input(); // position 0
        let p2 = builder.add_public_input(); // position 1

        let (primitives, public_rows, expr_to_widx, public_mappings, _witness_count, _non_prim_ops) =
            builder.lower().unwrap();

        // Expected primitives: 1 constant (ZERO) + 2 public inputs
        let expected_primitives = vec![
            Prim::Const {
                out: WitnessId(0),
                val: BabyBear::ZERO,
            },
            Prim::Public {
                out: WitnessId(1),
                public_pos: 0,
            },
            Prim::Public {
                out: WitnessId(2),
                public_pos: 1,
            },
        ];
        assert_eq!(primitives, expected_primitives);

        // Public rows mapping
        let expected_public_rows = vec![WitnessId(1), WitnessId(2)];
        assert_eq!(public_rows, expected_public_rows);

        // Expression to witness mapping
        let mut expected_expr_to_widx = HashMap::new();
        expected_expr_to_widx.insert(ExprId::ZERO, WitnessId(0));
        expected_expr_to_widx.insert(p1, WitnessId(1));
        expected_expr_to_widx.insert(p2, WitnessId(2));
        assert_eq!(expr_to_widx, expected_expr_to_widx);

        // Public mappings
        let mut expected_public_mappings = HashMap::new();
        expected_public_mappings.insert(p1, WitnessId(1));
        expected_public_mappings.insert(p2, WitnessId(2));
        assert_eq!(public_mappings, expected_public_mappings);
    }

    #[test]
    fn test_lower_to_primitives_arithmetic_operations() {
        // Test arithmetic operations create correct primitive operations
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let x = builder.add_public_input();
        let y = builder.add_public_input();
        let add_result = builder.add(x, y); // x + y

        let (primitives, public_rows, expr_to_widx, public_mappings, _witness_count, _non_prim_ops) =
            builder.lower().unwrap();

        // Expected primitives: ZERO + 2 public inputs + 1 add operation
        let expected_primitives = vec![
            Prim::Const {
                out: WitnessId(0),
                val: BabyBear::ZERO,
            },
            Prim::Public {
                out: WitnessId(1),
                public_pos: 0,
            },
            Prim::Public {
                out: WitnessId(2),
                public_pos: 1,
            },
            Prim::Add {
                a: WitnessId(1),
                b: WitnessId(2),
                out: WitnessId(3),
            },
        ];
        assert_eq!(primitives, expected_primitives);

        // Public rows mapping
        let expected_public_rows = vec![WitnessId(1), WitnessId(2)];
        assert_eq!(public_rows, expected_public_rows);

        // Expression to witness mapping
        let mut expected_expr_to_widx = HashMap::new();
        expected_expr_to_widx.insert(ExprId::ZERO, WitnessId(0));
        expected_expr_to_widx.insert(x, WitnessId(1));
        expected_expr_to_widx.insert(y, WitnessId(2));
        expected_expr_to_widx.insert(add_result, WitnessId(3));
        assert_eq!(expr_to_widx, expected_expr_to_widx);

        // Public mappings
        let mut expected_public_mappings = HashMap::new();
        expected_public_mappings.insert(x, WitnessId(1));
        expected_public_mappings.insert(y, WitnessId(2));
        assert_eq!(public_mappings, expected_public_mappings);
    }

    #[test]
    fn test_lower_to_primitives_subtraction_encoding() {
        // Test that subtraction is properly encoded as addition:
        // x - y = result becomes result + y = x
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let x = builder.add_public_input();
        let y = builder.add_public_input();
        let result = builder.sub(x, y); // x - y = result

        let (primitives, public_rows, expr_to_widx, public_mappings, _witness_count, _non_prim_ops) =
            builder.lower().unwrap();

        // Expected primitives: ZERO + 2 public inputs + 1 add (encoding subtraction)
        let expected_primitives = vec![
            Prim::Const {
                out: WitnessId(0),
                val: BabyBear::ZERO,
            },
            Prim::Public {
                out: WitnessId(1),
                public_pos: 0,
            },
            Prim::Public {
                out: WitnessId(2),
                public_pos: 1,
            },
            // Sub encoding: result + y = x, so a=y, b=result, out=x
            Prim::Add {
                a: WitnessId(2),
                b: WitnessId(3),
                out: WitnessId(1),
            },
        ];
        assert_eq!(primitives, expected_primitives);

        // Public rows mapping
        let expected_public_rows = vec![WitnessId(1), WitnessId(2)];
        assert_eq!(public_rows, expected_public_rows);

        // Expression to witness mapping
        let mut expected_expr_to_widx = HashMap::new();
        expected_expr_to_widx.insert(ExprId::ZERO, WitnessId(0));
        expected_expr_to_widx.insert(x, WitnessId(1));
        expected_expr_to_widx.insert(y, WitnessId(2));
        expected_expr_to_widx.insert(result, WitnessId(3));
        assert_eq!(expr_to_widx, expected_expr_to_widx);

        // Public mappings
        let mut expected_public_mappings = HashMap::new();
        expected_public_mappings.insert(x, WitnessId(1));
        expected_public_mappings.insert(y, WitnessId(2));
        assert_eq!(public_mappings, expected_public_mappings);
    }

    #[test]
    fn test_lower_to_primitives_division_encoding() {
        // Test that division is properly encoded as multiplication: x / y = result becomes y * result = x
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let x = builder.add_public_input();
        let y = builder.add_public_input();
        let result = builder.div(x, y); // x / y = result

        let (primitives, public_rows, expr_to_widx, public_mappings, _witness_count, _non_prim_ops) =
            builder.lower().unwrap();

        // Expected primitives: ZERO + 2 public inputs + 1 mul (encoding division)
        let expected_primitives = vec![
            Prim::Const {
                out: WitnessId(0),
                val: BabyBear::ZERO,
            },
            Prim::Public {
                out: WitnessId(1),
                public_pos: 0,
            },
            Prim::Public {
                out: WitnessId(2),
                public_pos: 1,
            },
            // Div encoding: y * result = x, so a=y, b=result, out=x
            Prim::Mul {
                a: WitnessId(2),
                b: WitnessId(3),
                out: WitnessId(1),
            },
        ];
        assert_eq!(primitives, expected_primitives);

        // Public rows mapping
        let expected_public_rows = vec![WitnessId(1), WitnessId(2)];
        assert_eq!(public_rows, expected_public_rows);

        // Expression to witness mapping
        let mut expected_expr_to_widx = HashMap::new();
        expected_expr_to_widx.insert(ExprId::ZERO, WitnessId(0));
        expected_expr_to_widx.insert(x, WitnessId(1));
        expected_expr_to_widx.insert(y, WitnessId(2));
        expected_expr_to_widx.insert(result, WitnessId(3));
        assert_eq!(expr_to_widx, expected_expr_to_widx);

        // Public mappings
        let mut expected_public_mappings = HashMap::new();
        expected_public_mappings.insert(x, WitnessId(1));
        expected_public_mappings.insert(y, WitnessId(2));
        assert_eq!(public_mappings, expected_public_mappings);
    }

    #[test]
    fn test_lower_to_primitives_connections_share_witnesses() {
        // Test that connected expressions share the same witness ID
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let x = builder.add_public_input();
        let y = builder.add_public_input();

        // Connect x and y - they should share witness ID
        builder.connect(x, y);

        let (primitives, public_rows, expr_to_widx, public_mappings, _witness_count, _non_prim_ops) =
            builder.lower().unwrap();

        // Expected primitives: ZERO + 2 public inputs (but sharing WitnessId(1))
        let expected_primitives = vec![
            Prim::Const {
                out: WitnessId(0),
                val: BabyBear::ZERO,
            },
            Prim::Public {
                out: WitnessId(1),
                public_pos: 0,
            },
            Prim::Public {
                out: WitnessId(1), // Same witness as x
                public_pos: 1,
            },
        ];
        assert_eq!(primitives, expected_primitives);

        // Public rows mapping - both positions map to same witness
        let expected_public_rows = vec![WitnessId(1), WitnessId(1)];
        assert_eq!(public_rows, expected_public_rows);

        // Expression to witness mapping - both x and y map to same witness
        let mut expected_expr_to_widx = HashMap::new();
        expected_expr_to_widx.insert(ExprId::ZERO, WitnessId(0));
        expected_expr_to_widx.insert(x, WitnessId(1));
        expected_expr_to_widx.insert(y, WitnessId(1)); // Same witness as x
        assert_eq!(expr_to_widx, expected_expr_to_widx);

        // Public mappings - both expressions map to same witness
        let mut expected_public_mappings = HashMap::new();
        expected_public_mappings.insert(x, WitnessId(1));
        expected_public_mappings.insert(y, WitnessId(1));
        assert_eq!(public_mappings, expected_public_mappings);
    }

    #[test]
    fn test_lower_to_primitives_constant_connection_binding() {
        // Test that constants bound to connection classes work correctly
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let x = builder.add_public_input();
        let c = builder.add_const(BabyBear::from_u64(42));

        // Connect public input to constant
        builder.connect(x, c);

        let (primitives, public_rows, expr_to_widx, public_mappings, _witness_count, _non_prim_ops) =
            builder.lower().unwrap();

        // Expected primitives: ZERO + constant 42 + public input (all sharing witness)
        let expected_primitives = vec![
            Prim::Const {
                out: WitnessId(0),
                val: BabyBear::ZERO,
            },
            Prim::Const {
                out: WitnessId(1), // Constants processed first
                val: BabyBear::from_u64(42),
            },
            Prim::Public {
                out: WitnessId(1), // Shares witness with constant
                public_pos: 0,
            },
        ];
        assert_eq!(primitives, expected_primitives);

        // Public rows mapping
        let expected_public_rows = vec![WitnessId(1)];
        assert_eq!(public_rows, expected_public_rows);

        // Expression to witness mapping - constant and public input share witness
        let mut expected_expr_to_widx = HashMap::new();
        expected_expr_to_widx.insert(ExprId::ZERO, WitnessId(0));
        expected_expr_to_widx.insert(c, WitnessId(1)); // Constant processed first
        expected_expr_to_widx.insert(x, WitnessId(1)); // Same witness as constant
        assert_eq!(expr_to_widx, expected_expr_to_widx);

        // Public mappings
        let mut expected_public_mappings = HashMap::new();
        expected_public_mappings.insert(x, WitnessId(1));
        assert_eq!(public_mappings, expected_public_mappings);
    }

    #[test]
    fn test_lower_to_primitives_witness_allocation_order() {
        // Test that witness IDs are allocated in predictable order
        let mut builder = CircuitBuilder::<BabyBear>::new();

        // Add expressions in specific order
        let c1 = builder.add_const(BabyBear::from_u64(10));
        let p1 = builder.add_public_input();
        let p2 = builder.add_public_input();
        let add_result = builder.add(p1, p2);

        let (primitives, public_rows, expr_to_widx, public_mappings, _witness_count, _non_prim_ops) =
            builder.lower().unwrap();

        // Expected primitives in processing order: constants, public inputs, arithmetic ops
        let expected_primitives = vec![
            Prim::Const {
                out: WitnessId(0),
                val: BabyBear::ZERO,
            },
            Prim::Const {
                out: WitnessId(1),
                val: BabyBear::from_u64(10),
            },
            Prim::Public {
                out: WitnessId(2),
                public_pos: 0,
            },
            Prim::Public {
                out: WitnessId(3),
                public_pos: 1,
            },
            Prim::Add {
                a: WitnessId(2),
                b: WitnessId(3),
                out: WitnessId(4),
            },
        ];
        assert_eq!(primitives, expected_primitives);

        // Public rows mapping
        let expected_public_rows = vec![WitnessId(2), WitnessId(3)];
        assert_eq!(public_rows, expected_public_rows);

        // Expression to witness mapping
        let mut expected_expr_to_widx = HashMap::new();
        expected_expr_to_widx.insert(ExprId::ZERO, WitnessId(0));
        expected_expr_to_widx.insert(c1, WitnessId(1));
        expected_expr_to_widx.insert(p1, WitnessId(2));
        expected_expr_to_widx.insert(p2, WitnessId(3));
        expected_expr_to_widx.insert(add_result, WitnessId(4));
        assert_eq!(expr_to_widx, expected_expr_to_widx);

        // Public mappings
        let mut expected_public_mappings = HashMap::new();
        expected_public_mappings.insert(p1, WitnessId(2));
        expected_public_mappings.insert(p2, WitnessId(3));
        assert_eq!(public_mappings, expected_public_mappings);
    }
}
