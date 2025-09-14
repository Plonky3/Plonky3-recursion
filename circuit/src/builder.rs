use alloc::vec::Vec;
use alloc::{format, vec};

use hashbrown::{HashMap, HashSet};
use p3_field::PrimeCharacteristicRing;

use crate::circuit::Circuit;
use crate::expr::{Expr, ExpressionGraph};
use crate::op::{NonPrimitiveOp, NonPrimitiveOpType, Prim};
use crate::types::{ExprId, NonPrimitiveOpId, WitnessAllocator, WitnessId};

/// Sparse disjoint-set "find" with path compression over a HashMap (iterative).
/// If `x` is not present, it's its own representative and is not inserted.
#[inline]
fn dsu_find(parent: &mut HashMap<usize, usize>, x: usize) -> usize {
    let mut v = x;
    let mut trail: Vec<usize> = Vec::new();
    while let Some(&p) = parent.get(&v) {
        if p == v {
            break;
        }
        trail.push(v);
        v = p;
    }
    let root = v;
    for u in trail {
        parent.insert(u, root);
    }
    root
}

/// Sparse disjoint-set "union" by attaching `b`'s root under `a`'s root.
#[inline]
fn dsu_union(parent: &mut HashMap<usize, usize>, a: usize, b: usize) {
    let ra = dsu_find(parent, a);
    let rb = dsu_find(parent, b);
    if ra != rb {
        parent.insert(rb, ra);
    }
}

/// Build a sparse disjoint-set forest honoring all pending connects.
/// Returns a parent map keyed only by ExprIds that appear in `connects`.
fn build_connect_dsu(connects: &[(ExprId, ExprId)]) -> HashMap<usize, usize> {
    let mut parent: HashMap<usize, usize> = HashMap::new();
    for (a, b) in connects {
        let ai = a.0 as usize;
        let bi = b.0 as usize;
        dsu_union(&mut parent, ai, bi);
    }
    parent
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

        // Insert Const(0) as the very first node so it has ExprId(0).
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

    /// Add a public input to the circuit
    pub fn add_public_input(&mut self) -> ExprId {
        let public_pos = self.public_input_count;
        self.public_input_count += 1;

        let public_expr = Expr::Public(public_pos);
        self.expressions.add_expr(public_expr)
    }

    /// Add a constant to the circuit (deduplicated).
    ///
    /// If this value was previously added, returns the original ExprId.
    pub fn add_const(&mut self, val: F) -> ExprId {
        if let Some(&id) = self.const_pool.get(&val) {
            return id;
        }
        let id = self.expressions.add_expr(Expr::Const(val.clone()));
        self.const_pool.insert(val, id);
        id
    }

    /// Add two expressions
    pub fn add(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let add_expr = Expr::Add { lhs, rhs };
        self.expressions.add_expr(add_expr)
    }

    /// Subtract two expressions
    pub fn sub(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let sub_expr = Expr::Sub { lhs, rhs };
        self.expressions.add_expr(sub_expr)
    }

    /// Multiply two expressions
    pub fn mul(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let mul_expr = Expr::Mul { lhs, rhs };
        self.expressions.add_expr(mul_expr)
    }

    /// Assert that an expression equals zero by connecting it to Const(0).
    pub fn assert_zero(&mut self, expr: ExprId) {
        self.connect(expr, ExprId(0));
    }

    /// Connect two expressions, enforcing a == b (by aliasing outputs).
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
}

impl<F> CircuitBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + PartialEq + Eq + core::hash::Hash,
{
    /// Build the circuit into a Circuit with separate lowering and IR transformation stages
    pub fn build(mut self) -> Circuit<F> {
        // Stage 1: Lower expressions to primitives
        let (primitive_ops, public_rows, expr_to_widx) = self.lower_to_primitives();

        // Stage 2: Lower non-primitive operations using the expr_to_widx mapping
        let lowered_non_primitive_ops = self.lower_non_primitive_ops(&expr_to_widx);

        // Stage 3: IR transformations and optimizations
        let primitive_ops = Self::optimize_primitives(primitive_ops);

        // Stage 4: Generate final circuit
        let slot_count = self.witness_alloc.slot_count();
        let mut circuit = Circuit::new(slot_count);
        circuit.primitive_ops = primitive_ops;
        circuit.non_primitive_ops = lowered_non_primitive_ops;
        circuit.public_rows = public_rows;
        circuit.public_flat_len = self.public_input_count;

        circuit
    }

    /// Helper function to get WitnessId with descriptive error messages
    fn get_witness_id(
        expr_to_widx: &HashMap<ExprId, WitnessId>,
        expr_id: ExprId,
        context: &str,
    ) -> WitnessId {
        *expr_to_widx.get(&expr_id).unwrap_or_else(|| {
            panic!(
                "Expression {:?} not found in witness mapping: {}",
                expr_id, context
            )
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
    ) -> (Vec<Prim<F>>, Vec<WitnessId>, HashMap<ExprId, WitnessId>) {
        // Build DSU over expression IDs to honor connect(a, b)
        let mut parent: HashMap<usize, usize> = build_connect_dsu(&self.pending_connects);

        // Track nodes that participate in any connect
        let mut in_connect: HashSet<usize> = HashSet::new();
        for (a, b) in &self.pending_connects {
            in_connect.insert(a.0 as usize);
            in_connect.insert(b.0 as usize);
        }

        let mut primitive_ops = Vec::new();
        let mut expr_to_widx: HashMap<ExprId, WitnessId> = HashMap::new();
        let mut public_rows: Vec<WitnessId> = Vec::new();

        // Unified class slot map: DSU root -> chosen out slot
        let mut root_to_widx: HashMap<usize, WitnessId> = HashMap::new();
        // For conflict detection when multiple Consts appear in the same class
        let mut root_const_val: HashMap<usize, F> = HashMap::new();

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
                    let rep = dsu_find(&mut parent, expr_idx);
                    if let Some(prev) = root_const_val.get(&rep) {
                        if prev != val {
                            panic!(
                                "Conflicting constants in connected class (rep {}): {:?} vs {:?}",
                                rep, prev, val
                            );
                        }
                    }
                    root_const_val.insert(rep, val.clone());
                    root_to_widx.insert(rep, w);
                }
            }
        }

        let mut alloc_witness_id_for_expr =
            |expr_idx: usize,
             in_connect: &HashSet<usize>,
             parent: &mut HashMap<usize, usize>,
             root_to_widx: &mut HashMap<usize, WitnessId>| {
                if in_connect.contains(&expr_idx) {
                    let rep = dsu_find(parent, expr_idx);
                    *root_to_widx
                        .entry(rep)
                        .or_insert_with(|| self.witness_alloc.alloc())
                } else {
                    self.witness_alloc.alloc()
                }
            };

        // Pass B: emit public inputs
        for (expr_idx, expr) in self.expressions.nodes().iter().enumerate() {
            if let Expr::Public(pos) = expr {
                let id = ExprId(expr_idx as u32);

                let out_widx = alloc_witness_id_for_expr(
                    expr_idx,
                    &in_connect,
                    &mut parent,
                    &mut root_to_widx,
                );

                primitive_ops.push(Prim::Public {
                    out: out_widx,
                    public_pos: *pos,
                });
                expr_to_widx.insert(id, out_widx);
                if *pos >= public_rows.len() {
                    public_rows.resize(*pos + 1, WitnessId(0));
                }
                public_rows[*pos] = out_widx;
            }
        }

        // Pass C: emit arithmetic ops in creation order; tie outputs to class slot if connected
        for (expr_idx, expr) in self.expressions.nodes().iter().enumerate() {
            let id = ExprId(expr_idx as u32);
            match expr {
                Expr::Const(_) | Expr::Public(_) => { /* handled above */ }
                Expr::Add { lhs, rhs } => {
                    let out_widx = alloc_witness_id_for_expr(
                        expr_idx,
                        &in_connect,
                        &mut parent,
                        &mut root_to_widx,
                    );
                    let a_widx =
                        Self::get_witness_id(&expr_to_widx, *lhs, &format!("Add lhs for {id:?}"));
                    let b_widx =
                        Self::get_witness_id(&expr_to_widx, *rhs, &format!("Add rhs for {id:?}"));
                    primitive_ops.push(Prim::Add {
                        a: a_widx,
                        b: b_widx,
                        out: out_widx,
                    });
                    expr_to_widx.insert(id, out_widx);
                }
                Expr::Sub { lhs, rhs } => {
                    let out_widx = alloc_witness_id_for_expr(
                        expr_idx,
                        &in_connect,
                        &mut parent,
                        &mut root_to_widx,
                    );
                    let a_widx =
                        Self::get_witness_id(&expr_to_widx, *lhs, &format!("Sub lhs for {id:?}"));
                    let b_widx =
                        Self::get_witness_id(&expr_to_widx, *rhs, &format!("Sub rhs for {id:?}"));
                    primitive_ops.push(Prim::Sub {
                        a: a_widx,
                        b: b_widx,
                        out: out_widx,
                    });
                    expr_to_widx.insert(id, out_widx);
                }
                Expr::Mul { lhs, rhs } => {
                    let out_widx = alloc_witness_id_for_expr(
                        expr_idx,
                        &in_connect,
                        &mut parent,
                        &mut root_to_widx,
                    );
                    let a_widx =
                        Self::get_witness_id(&expr_to_widx, *lhs, &format!("Mul lhs for {id:?}"));
                    let b_widx =
                        Self::get_witness_id(&expr_to_widx, *rhs, &format!("Mul rhs for {id:?}"));
                    primitive_ops.push(Prim::Mul {
                        a: a_widx,
                        b: b_widx,
                        out: out_widx,
                    });
                    expr_to_widx.insert(id, out_widx);
                }
            }
        }

        (primitive_ops, public_rows, expr_to_widx)
    }

    /// Stage 2: Lower non-primitive operations from ExprIds to WitnessId
    fn lower_non_primitive_ops(
        &self,
        expr_to_widx: &HashMap<ExprId, WitnessId>,
    ) -> Vec<NonPrimitiveOp> {
        let mut lowered_ops = Vec::new();

        for (_op_id, op_type, witness_exprs) in &self.non_primitive_ops {
            match op_type {
                NonPrimitiveOpType::FakeMerkleVerify => {
                    if witness_exprs.len() != 2 {
                        panic!(
                            "FakeMerkleVerify expects exactly 2 witness expressions, got {}",
                            witness_exprs.len()
                        );
                    }
                    let leaf_widx = Self::get_witness_id(
                        expr_to_widx,
                        witness_exprs[0],
                        "FakeMerkleVerify leaf input",
                    );
                    let root_widx = Self::get_witness_id(
                        expr_to_widx,
                        witness_exprs[1],
                        "FakeMerkleVerify root input",
                    );

                    lowered_ops.push(NonPrimitiveOp::FakeMerkleVerify {
                        leaf: leaf_widx,
                        root: root_widx,
                    });
                } // Add more variants here as needed
            }
        }

        lowered_ops
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

    #[test]
    fn test_circuit_basic_api() {
        let mut builder = CircuitBuilder::<BabyBear>::new();

        // Test the DESIGN example: 37 * x - 111 = 0
        let x = builder.add_public_input();
        let c37 = builder.add_const(BabyBear::from_u64(37));
        let c111 = builder.add_const(BabyBear::from_u64(111));

        let mul_result = builder.mul(c37, x);
        let sub_result = builder.sub(mul_result, c111);
        builder.assert_zero(sub_result);

        let circuit = builder.build();
        assert_eq!(circuit.slot_count, 5); // 0:zero, 1:public, 2:c37, 3:c111, 4:mul_result

        // Assert all primitive operations (lowering order: Consts first, then Public, then ops)
        assert_eq!(circuit.primitive_ops.len(), 6);
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
            Prim::Public { out, public_pos } => {
                assert_eq!(out.0, 3);
                assert_eq!(*public_pos, 0);
            }
            _ => panic!("Expected Public at op 3"),
        }
        match &circuit.primitive_ops[4] {
            Prim::Mul { a, b, out } => {
                assert_eq!(a.0, 1);
                assert_eq!(b.0, 3);
                assert_eq!(out.0, 4);
            }
            _ => panic!("Expected Mul at op 4"),
        }
        match &circuit.primitive_ops[5] {
            Prim::Sub { a, b, out } => {
                assert_eq!(a.0, 4);
                assert_eq!(b.0, 2);
                assert_eq!(out.0, 0);
            }
            _ => panic!("Expected Sub(mul_result - c111) at op 5"),
        }

        assert_eq!(circuit.public_flat_len, 1);
        assert_eq!(circuit.public_rows, vec![WitnessId(3)]); // Public input at slot 3 (after consts)
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

        let circuit = builder.build();
        let mut runner = circuit.runner();

        runner.set_public_inputs(&[BabyBear::from_u64(5)]).unwrap();
        // Should succeed; both write the same value into the shared slot
        runner.run().unwrap();
    }

    #[test]
    fn test_connect_conflict() {
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let x = builder.add_public_input();
        let y = builder.add_public_input();

        // Enforce x == y
        builder.connect(x, y);

        let circuit = builder.build();
        let mut runner = circuit.runner();

        // Provide different values; should error due to witness conflict on shared slot
        let err = runner
            .set_public_inputs(&[BabyBear::from_u64(3), BabyBear::from_u64(4)])
            .unwrap_err();
        assert!(err.contains("Witness conflict"));
    }

    #[test]
    fn test_build_connect_dsu_basic() {
        // 0~1~3~4 in one set; 2 alone
        let connects = vec![
            (ExprId(0), ExprId(1)),
            (ExprId(3), ExprId(4)),
            (ExprId(1), ExprId(4)),
            (ExprId(2), ExprId(2)), // self-union no-op
        ];
        let mut parent = build_connect_dsu(&connects);
        let r0 = dsu_find(&mut parent, 0);
        let r1 = dsu_find(&mut parent, 1);
        let r3 = dsu_find(&mut parent, 3);
        let r4 = dsu_find(&mut parent, 4);
        let r2 = dsu_find(&mut parent, 2);
        assert_eq!(r0, r1);
        assert_eq!(r0, r3);
        assert_eq!(r0, r4);
        assert_ne!(r0, r2);
    }
}
