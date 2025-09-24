use alloc::vec::Vec;
use alloc::{format, vec};

use hashbrown::{HashMap, HashSet};
use p3_field::PrimeCharacteristicRing;
use thiserror::Error;

use crate::circuit::Circuit;
use crate::expr::{Expr, ExpressionGraph};
use crate::op::{NonPrimitiveOp, NonPrimitiveOpType, Prim};
use crate::types::{ExprId, NonPrimitiveOpId, WitnessAllocator, WitnessId};

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

/// Builder for constructing circuits using a fluent API
///
/// This struct provides methods to build up a computation graph by adding:
/// - Public inputs
/// - Constants
/// - Arithmetic operations (add, multiply, subtract)
/// - Assertions (values that must equal zero)
/// - Complex operations (like Merkle tree verification)
///
/// Call `.build()` to compile into an immutable `Circuit<F>` specification.
pub struct CircuitBuilder<F> {
    /// Expression graph for building the DAG
    expressions: ExpressionGraph<F>,
    /// Witness index allocator
    witness_alloc: WitnessAllocator,
    /// Track public input positions
    public_input_count: usize,
    /// Equality constraints to enforce at lowering
    pending_connects: Vec<(ExprId, ExprId)>,
    /// Non-primitive operations (complex constraints that don't produce ExprIds)
    non_primitive_ops: Vec<(NonPrimitiveOpId, NonPrimitiveOpType, Vec<ExprId>)>, // (op_id, op_type, witness_exprs)

    /// Builder-level constant pool: value -> unique Const ExprId
    const_pool: HashMap<F, ExprId>,
}

/// Errors that can occur during circuit building/lowering.
#[derive(Debug, Error)]
pub enum CircuitBuilderError {
    /// Expression not found in the witness mapping during lowering.
    #[error("Expression {expr_id:?} not found in witness mapping: {context}")]
    MissingExprMapping {
        expr_id: ExprId,
        context: alloc::string::String,
    },

    /// Non-primitive op received an unexpected number of input expressions.
    #[error("{op} expects exactly {expected} witness expressions, got {got}")]
    NonPrimitiveOpArity {
        op: &'static str,
        expected: usize,
        got: usize,
    },
}

impl<F> Default for CircuitBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + Eq + core::hash::Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F> CircuitBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + Eq + core::hash::Hash,
{
    /// Create a new circuit builder
    pub fn new() -> Self {
        let mut expressions = ExpressionGraph::new();

        // Insert Const(0) as the very first node so it has ExprId::ZERO.
        let zero_val = F::ZERO;
        let zero_id = expressions.add_expr(Expr::Const(zero_val.clone()));

        let mut const_pool = HashMap::new();
        const_pool.insert(zero_val, zero_id);

        Self {
            expressions,
            witness_alloc: WitnessAllocator::new(),
            public_input_count: 0,
            pending_connects: Vec::new(),
            non_primitive_ops: Vec::new(),
            const_pool,
        }
    }

    /// Add a public input to the circuit.
    ///
    /// Cost: 1 row in Public table + 1 row in witness table.
    pub fn add_public_input(&mut self) -> ExprId {
        let public_pos = self.public_input_count;
        self.public_input_count += 1;

        let public_expr = Expr::Public(public_pos);
        self.expressions.add_expr(public_expr)
    }

    /// Add a constant to the circuit (deduplicated).
    ///
    /// If this value was previously added, returns the original ExprId.
    /// Cost: 1 row in Const table + 1 row in witness table (only for new constants).
    pub fn add_const(&mut self, val: F) -> ExprId {
        if let Some(&id) = self.const_pool.get(&val) {
            return id;
        }
        let id = self.expressions.add_expr(Expr::Const(val.clone()));
        self.const_pool.insert(val, id);
        id
    }

    /// Add two expressions.
    ///
    /// Cost: 1 row in Add table + 1 row in witness table.
    pub fn add(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let add_expr = Expr::Add { lhs, rhs };
        self.expressions.add_expr(add_expr)
    }

    /// Subtract two expressions.
    ///
    /// Cost: 1 row in Add table + 1 row in witness table (encoded as result + rhs = lhs).
    pub fn sub(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let sub_expr = Expr::Sub { lhs, rhs };
        self.expressions.add_expr(sub_expr)
    }

    /// Multiply two expressions.
    ///
    /// Cost: 1 row in Mul table + 1 row in witness table.
    pub fn mul(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let mul_expr = Expr::Mul { lhs, rhs };
        self.expressions.add_expr(mul_expr)
    }
    /// Divide two expressions
    ///
    /// Cost: 1 row in Mul table + 1 row in witness table (encoded as rhs * out = lhs).
    pub fn div(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let div_expr = Expr::Div { lhs, rhs };
        self.expressions.add_expr(div_expr)
    }

    /// Assert that an expression equals zero by connecting it to Const(0).
    ///
    /// Cost: Free in proving (implemented via connect).
    pub fn assert_zero(&mut self, expr: ExprId) {
        self.connect(expr, ExprId::ZERO);
    }

    /// Connect two expressions, enforcing a == b (by aliasing outputs).
    ///
    /// Cost: Free in proving (handled by IR optimization layer via witness slot aliasing).
    pub fn connect(&mut self, a: ExprId, b: ExprId) {
        if a != b {
            self.pending_connects.push((a, b));
        }
    }

    /// Add a fake Merkle verification constraint (non-primitive operation)
    ///
    /// Non-primitive operations are complex constraints that:
    /// - Take existing expressions as inputs (leaf_expr, root_expr)
    /// - Add verification constraints to the circuit
    /// - Don't produce new ExprIds (unlike primitive ops)
    /// - Are kept separate from primitives to avoid disrupting optimization
    ///
    /// Returns an operation ID for setting private data later during execution.
    pub fn add_fake_merkle_verify(
        &mut self,
        leaf_expr: ExprId,
        root_expr: ExprId,
    ) -> NonPrimitiveOpId {
        // Store input expression IDs - will be lowered to WitnessId during build()
        // Non-primitive ops consume ExprIds but don't produce them
        let op_id = NonPrimitiveOpId(self.non_primitive_ops.len() as u32);
        let witness_exprs = vec![leaf_expr, root_expr];
        self.non_primitive_ops
            .push((op_id, NonPrimitiveOpType::FakeMerkleVerify, witness_exprs));

        op_id
    }

    /// Add a hash absorb operation (non-primitive operation)
    pub fn add_hash_absorb(&mut self, input_exprs: &[ExprId], reset: bool) -> NonPrimitiveOpId {
        let op_id = NonPrimitiveOpId(self.non_primitive_ops.len() as u32);
        let witness_exprs = input_exprs.to_vec();
        self.non_primitive_ops
            .push((op_id, NonPrimitiveOpType::HashAbsorb(reset), witness_exprs));

        op_id
    }

    /// Add a hash squeeze operation (non-primitive operation)
    pub fn add_hash_squeeze(&mut self, output_exprs: &[ExprId]) -> NonPrimitiveOpId {
        let op_id = NonPrimitiveOpId(self.non_primitive_ops.len() as u32);
        let witness_exprs = output_exprs.to_vec();
        self.non_primitive_ops
            .push((op_id, NonPrimitiveOpType::HashSqueeze, witness_exprs));

        op_id
    }
}

impl<F> CircuitBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + PartialEq + Eq + core::hash::Hash,
{
    /// Build the circuit into a Circuit with separate lowering and IR transformation stages.
    /// Returns an error if lowering fails due to an internal inconsistency.
    pub fn build(self) -> Result<Circuit<F>, CircuitBuilderError> {
        let (circuit, _) = self.build_with_public_mapping()?;
        Ok(circuit)
    }

    /// Build the circuit and return both the circuit and the ExprId→WitnessId mapping for public inputs.
    pub fn build_with_public_mapping(
        mut self,
    ) -> Result<(Circuit<F>, HashMap<ExprId, WitnessId>), CircuitBuilderError> {
        // Stage 1: Lower expressions to primitives
        let (primitive_ops, public_rows, expr_to_widx, public_mappings) =
            self.lower_to_primitives()?;

        // Stage 2: Lower non-primitive operations using the expr_to_widx mapping
        let lowered_non_primitive_ops = self.lower_non_primitive_ops(&expr_to_widx)?;

        // Stage 3: IR transformations and optimizations
        let primitive_ops = Self::optimize_primitives(primitive_ops);

        // Stage 4: Generate final circuit
        let witness_count = self.witness_alloc.witness_count();
        let mut circuit = Circuit::new(witness_count);
        circuit.primitive_ops = primitive_ops;
        circuit.non_primitive_ops = lowered_non_primitive_ops;
        circuit.public_rows = public_rows;
        circuit.public_flat_len = self.public_input_count;

        Ok((circuit, public_mappings))
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

    /// Stage 1: Lower expressions to primitives (Consts, Publics, then Ops) with DSU-aware class slots
    ///
    /// INVARIANT: All ExprIds reference only previously processed expressions.
    /// This is guaranteed because:
    /// - ExprIds are only created by primitive operations (add_*, mul, sub)
    /// - Non-primitive operations consume ExprIds but don't produce them
    /// - Expression graph construction maintains topological order
    #[allow(clippy::type_complexity)]
    fn lower_to_primitives(
        &mut self,
    ) -> Result<
        (
            Vec<Prim<F>>,
            Vec<WitnessId>,
            HashMap<ExprId, WitnessId>,
            HashMap<ExprId, WitnessId>,
        ),
        CircuitBuilderError,
    > {
        // Build DSU over expression IDs to honor connect(a, b)
        let mut parents: HashMap<usize, usize> = build_connect_dsu(&self.pending_connects);

        // Track nodes that participate in any connect
        let mut in_connect: HashSet<usize> = HashSet::new();
        for (a, b) in &self.pending_connects {
            in_connect.insert(a.0 as usize);
            in_connect.insert(b.0 as usize);
        }

        let mut primitive_ops = Vec::new();
        let mut expr_to_widx: HashMap<ExprId, WitnessId> = HashMap::new();
        let mut public_rows: Vec<WitnessId> = vec![WitnessId(0); self.public_input_count];
        let mut public_mappings = HashMap::new();

        // Unified class slot map: DSU root -> chosen out slot
        let mut root_to_widx: HashMap<usize, WitnessId> = HashMap::new();

        // Pass A: emit constants (once per Const node; Expr-level dedup ensures one per value)
        for (expr_idx, expr) in self.expressions.nodes().iter().enumerate() {
            if let Expr::Const(val) = expr {
                let id = ExprId(expr_idx as u32);
                let w = self.witness_alloc.alloc();
                primitive_ops.push(Prim::Const {
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
        for (expr_idx, expr) in self.expressions.nodes().iter().enumerate() {
            if let Expr::Public(pos) = expr {
                let id = ExprId(expr_idx as u32);

                let out_widx = alloc_witness_id_for_expr(expr_idx);

                primitive_ops.push(Prim::Public {
                    out: out_widx,
                    public_pos: *pos,
                });
                expr_to_widx.insert(id, out_widx);
                public_rows[*pos] = out_widx;
                public_mappings.insert(id, out_widx);
            }
        }

        // Pass C: emit arithmetic ops in creation order; tie outputs to class slot if connected
        for (expr_idx, expr) in self.expressions.nodes().iter().enumerate() {
            let expr_id = ExprId(expr_idx as u32);
            match expr {
                Expr::Const(_) | Expr::Public(_) => { /* handled above */ }
                Expr::Add { lhs, rhs } => {
                    let out_widx = alloc_witness_id_for_expr(expr_idx);
                    let a_widx = Self::get_witness_id(
                        &expr_to_widx,
                        *lhs,
                        &format!("Add lhs for {expr_id:?}"),
                    )?;
                    let b_widx = Self::get_witness_id(
                        &expr_to_widx,
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
                    let result_widx = alloc_witness_id_for_expr(expr_idx);
                    let lhs_widx = Self::get_witness_id(
                        &expr_to_widx,
                        *lhs,
                        &format!("Sub lhs for {expr_id:?}"),
                    )?;
                    let rhs_widx = Self::get_witness_id(
                        &expr_to_widx,
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
                    let out_widx = alloc_witness_id_for_expr(expr_idx);
                    let a_widx = Self::get_witness_id(
                        &expr_to_widx,
                        *lhs,
                        &format!("Mul lhs for {expr_id:?}"),
                    )?;
                    let b_widx = Self::get_witness_id(
                        &expr_to_widx,
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
                    let b_widx = alloc_witness_id_for_expr(expr_idx);
                    let out_widx = Self::get_witness_id(
                        &expr_to_widx,
                        *lhs,
                        &format!("Div lhs for {expr_id:?}"),
                    )?;
                    let a_widx = Self::get_witness_id(
                        &expr_to_widx,
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

        Ok((primitive_ops, public_rows, expr_to_widx, public_mappings))
    }

    /// Stage 2: Lower non-primitive operations from ExprIds to WitnessId
    fn lower_non_primitive_ops(
        &self,
        expr_to_widx: &HashMap<ExprId, WitnessId>,
    ) -> Result<Vec<NonPrimitiveOp>, CircuitBuilderError> {
        let mut lowered_ops = Vec::new();

        for (_op_id, op_type, witness_exprs) in &self.non_primitive_ops {
            match op_type {
                NonPrimitiveOpType::FakeMerkleVerify => {
                    if witness_exprs.len() != 2 {
                        return Err(CircuitBuilderError::NonPrimitiveOpArity {
                            op: "FakeMerkleVerify",
                            expected: 2,
                            got: witness_exprs.len(),
                        });
                    }
                    let leaf_widx = Self::get_witness_id(
                        expr_to_widx,
                        witness_exprs[0],
                        "FakeMerkl    let multi_prover = MultiTableProver::new();eVerify leaf input",
                    )?;
                    let root_widx = Self::get_witness_id(
                        expr_to_widx,
                        witness_exprs[1],
                        "FakeMerkleVerify root input",
                    )?;

                    lowered_ops.push(NonPrimitiveOp::FakeMerkleVerify {
                        leaf: leaf_widx,
                        root: root_widx,
                    });
                }
                NonPrimitiveOpType::HashAbsorb(reset) => {
                    let inputs_widx = witness_exprs
                        .iter()
                        .map(|expr| Self::get_witness_id(expr_to_widx, *expr, "HashAbsorb input"))
                        .collect::<Vec<_>>();

                    lowered_ops.push(NonPrimitiveOp::HashAbsorb {
                        reset_flag: *reset,
                        inputs: inputs_widx.into_iter().collect::<Result<Vec<_>, _>>()?,
                    });
                }
                NonPrimitiveOpType::HashSqueeze => {
                    let outputs_widx = witness_exprs
                        .iter()
                        .map(|expr| Self::get_witness_id(expr_to_widx, *expr, "HashSqueeze output"))
                        .collect::<Vec<_>>();

                    lowered_ops.push(NonPrimitiveOp::HashSqueeze {
                        outputs: outputs_widx.into_iter().collect::<Result<Vec<_>, _>>()?,
                    });
                }
            }
        }

        Ok(lowered_ops)
    }

    /// Stage 3: IR transformations and optimizations
    fn optimize_primitives(primitive_ops: Vec<Prim<F>>) -> Vec<Prim<F>> {
        // Future passes can be added here:
        // - Dead code elimination
        // - Common subexpression elimination
        // - Instruction combining
        // - Constant folding
        primitive_ops
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::CircuitError;
    use crate::tables::DummyPerm;

    #[test]
    fn test_circuit_basic_api() {
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let c37 = builder.add_const(BabyBear::from_u64(37)); // w1
        let c111 = builder.add_const(BabyBear::from_u64(111)); // w2
        let c1 = builder.add_const(BabyBear::from_u64(1)); // w3
        let x = builder.add_public_input(); // w4

        let mul_result = builder.mul(c37, x); // w5
        let sub_result = builder.sub(mul_result, c111); // writes into the zero slot (w0)
        builder.assert_zero(sub_result);

        let div_result = builder.div(mul_result, c111); // w6
        let sub_one = builder.sub(div_result, c1);
        builder.assert_zero(sub_one);

        let circuit = builder.build().unwrap();
        assert_eq!(circuit.witness_count, 7); // w0 reused for both assert_zero targets; w1-6 as annotated above

        // Assert all primitive operations (lowering order: Consts first, then Public, then ops)
        assert_eq!(circuit.primitive_ops.len(), 9);
        match &circuit.primitive_ops[0] {
            Prim::Const { out, val } => {
                assert_eq!(out.0, 0);
                assert_eq!(*val, BabyBear::from_u64(0));
            }
            _ => panic!("Expected Const(0) at op 0"),
        }
        match &circuit.primitive_ops[1] {
            Prim::Const { out, val } => {
                assert_eq!(out.0, 1);
                assert_eq!(*val, BabyBear::from_u64(37));
            }
            _ => panic!("Expected Const(37) at op 1"),
        }
        match &circuit.primitive_ops[2] {
            Prim::Const { out, val } => {
                assert_eq!(out.0, 2);
                assert_eq!(*val, BabyBear::from_u64(111));
            }
            _ => panic!("Expected Const(111) at op 2"),
        }
        match &circuit.primitive_ops[3] {
            Prim::Const { out, val } => {
                assert_eq!(out.0, 3);
                assert_eq!(*val, BabyBear::from_u64(1));
            }
            _ => panic!("Expected Const(1)"),
        }
        match &circuit.primitive_ops[4] {
            Prim::Public { out, public_pos } => {
                assert_eq!(out.0, 4);
                assert_eq!(*public_pos, 0);
            }
            _ => panic!("Expected Public at op 3"),
        }
        match &circuit.primitive_ops[5] {
            Prim::Mul { a, b, out } => {
                assert_eq!(a.0, 1);
                assert_eq!(b.0, 4);
                assert_eq!(out.0, 5);
            }
            _ => panic!("Expected Mul at op 4"),
        } // w1 * w4 = w5
        match &circuit.primitive_ops[6] {
            Prim::Add { a, b, out } => {
                assert_eq!(a.0, 2);
                assert_eq!(b.0, 0);
                assert_eq!(out.0, 5);
            } // w5 - w2 = w0
            _ => panic!("Expected Add encoding mul_result - c111"),
        }
        match &circuit.primitive_ops[7] {
            Prim::Mul { a, b, out } => {
                assert_eq!(a.0, 2);
                assert_eq!(b.0, 6);
                assert_eq!(out.0, 5);
            } // w2 * w6 = w5
            _ => panic!("Expected Mul"),
        }
        match &circuit.primitive_ops[8] {
            Prim::Add { a, b, out } => {
                assert_eq!(a.0, 3);
                assert_eq!(b.0, 0);
                assert_eq!(out.0, 6);
            } // w6 - w3 = w0
            _ => panic!("Expected Add encoding div_result - c1"),
        }

        assert_eq!(circuit.public_flat_len, 1);
        assert_eq!(circuit.public_rows, vec![WitnessId(4)]); // Public input at slot 4 (after consts)
    }

    #[test]
    fn test_connect_enforces_equality() {
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let x = builder.add_public_input();
        let c1 = builder.add_const(BabyBear::ONE);

        // a = x + 1, b = 1 + x
        let a = builder.add(x, c1);
        let b = builder.add(c1, x);

        // Enforce a == b
        builder.connect(a, b);

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();

        runner.set_public_inputs(&[BabyBear::from_u64(5)]).unwrap();
        // Should succeed; both write the same value into the shared slot
        runner
            .run::<DummyPerm, 0, 0, 0>(DummyPerm::default())
            .unwrap();
    }

    #[test]
    fn test_connect_conflict() {
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let x = builder.add_public_input();
        let y = builder.add_public_input();

        // Enforce x == y
        builder.connect(x, y);

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();

        // Provide different values; should error due to witness conflict on shared slot
        let err = runner
            .set_public_inputs(&[BabyBear::from_u64(3), BabyBear::from_u64(4)])
            .unwrap_err();
        match err {
            CircuitError::WitnessConflict { .. } => {}
            other => panic!("expected WitnessConflict, got {other}"),
        }
    }

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
    fn test_public_input_mapping() {
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let pub1 = builder.add_public_input();
        let c5 = builder.add_const(BabyBear::from_u64(5));
        let pub2 = builder.add_public_input();
        let sum = builder.add(pub1, pub2);
        let result = builder.mul(sum, c5);
        let pub3 = builder.add_public_input();
        let pub4 = builder.add_public_input();

        builder.connect(result, pub3);
        builder.connect(pub3, pub4);

        // Build with public mapping
        let (circuit, public_mapping) = builder.build_with_public_mapping().unwrap();

        // Verify we have mappings for all public inputs
        assert_eq!(public_mapping.len(), 4);
        assert!(public_mapping.contains_key(&pub1));
        assert!(public_mapping.contains_key(&pub2));
        assert!(public_mapping.contains_key(&pub3));
        assert!(public_mapping.contains_key(&pub4));

        // Verify the mapping is consistent with circuit.public_rows
        assert_eq!(circuit.public_rows.len(), 4);
        assert_eq!(public_mapping[&pub1], circuit.public_rows[0]);
        assert_eq!(public_mapping[&pub2], circuit.public_rows[1]);
        assert_eq!(public_mapping[&pub3], circuit.public_rows[2]);
        assert_eq!(public_mapping[&pub4], circuit.public_rows[3]);

        assert_eq!(public_mapping[&pub1], WitnessId(2));
        assert_eq!(public_mapping[&pub2], WitnessId(3));
        assert_eq!(public_mapping[&pub3], WitnessId(4));
        assert_eq!(public_mapping[&pub4], WitnessId(4));

        // Verify that regular build() still works (backward compatibility)
        let mut builder2 = CircuitBuilder::<BabyBear>::new();
        let _pub = builder2.add_public_input();
        let circuit2 = builder2.build().unwrap(); // Should not return mapping
        assert_eq!(circuit2.public_flat_len, 1);
    }
}
