use std::collections::HashMap;

use p3_field::PrimeCharacteristicRing;

use crate::circuit::Circuit;
use crate::expr::{Expr, ExpressionGraph};
use crate::op::{NonPrimitiveOp, NonPrimitiveOpType, Prim};
use crate::types::{ExprId, NonPrimitiveOpId, WitnessAllocator, WitnessId};

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
    /// Pending zero assertions to lower in build()
    pending_asserts: Vec<ExprId>,
    /// Non-primitive operations (complex constraints that don't produce ExprIds)
    non_primitive_ops: Vec<(NonPrimitiveOpId, NonPrimitiveOpType, Vec<ExprId>)>, // (op_id, op_type, witness_exprs)
}

impl<F: Clone> CircuitBuilder<F> {
    /// Create a new circuit builder
    pub fn new() -> Self {
        Self {
            expressions: ExpressionGraph::new(),
            witness_alloc: WitnessAllocator::new(),
            public_input_count: 0,
            pending_asserts: Vec::new(),
            non_primitive_ops: Vec::new(),
        }
    }

    /// Add a public input to the circuit
    pub fn add_public_input(&mut self) -> ExprId {
        let public_pos = self.public_input_count;
        self.public_input_count += 1;

        let public_expr = Expr::Public(public_pos);
        self.expressions.add_expr(public_expr)
    }

    /// Add a constant to the circuit
    pub fn add_const(&mut self, val: F) -> ExprId {
        let const_expr = Expr::Const(val);
        self.expressions.add_expr(const_expr)
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

    /// Assert that an expression equals zero.
    /// Recorded as a pending assertion to be lowered in build() to a Sub with zero.
    pub fn assert_zero(&mut self, expr: ExprId) {
        self.pending_asserts.push(expr);
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

impl<F: Clone + PrimeCharacteristicRing + PartialEq + Eq + std::hash::Hash> CircuitBuilder<F> {
    /// Build the circuit into a Circuit with separate lowering and IR transformation stages
    pub fn build(mut self) -> Circuit<F> {
        // Stage 1: Lower expressions to naive primitives with constant pooling
        let (primitive_ops, const_pool, public_rows, expr_to_widx) = self.lower_to_primitives();

        // Stage 2: Lower non-primitive operations using the expr_to_widx mapping
        let lowered_non_primitive_ops = self.lower_non_primitive_ops(&expr_to_widx);

        // Stage 3: IR transformations and optimizations
        let primitive_ops = Self::optimize_primitives(primitive_ops, &const_pool);

        // Stage 4: Generate final circuit
        let slot_count = self.witness_alloc.slot_count();
        let mut circuit = Circuit::new(slot_count);
        circuit.primitive_ops = primitive_ops;
        circuit.non_primitive_ops = lowered_non_primitive_ops;
        circuit.public_rows = public_rows;
        circuit.public_flat_len = self.public_input_count;

        circuit
    }

    /// Stage 1: Lower expressions to primitives with constant pooling
    ///
    /// INVARIANT: All ExprIds reference only previously processed expressions.
    /// This is guaranteed because:
    /// - ExprIds are only created by primitive operations (add_*, mul, sub)
    /// - Non-primitive operations consume ExprIds but don't produce them
    /// - Expression graph construction maintains topological order
    #[allow(clippy::type_complexity)]
    fn lower_to_primitives(
        &mut self,
    ) -> (
        Vec<Prim<F>>,
        HashMap<F, WitnessId>,
        Vec<WitnessId>,
        HashMap<ExprId, WitnessId>,
    ) {
        let mut primitive_ops = Vec::new();
        let mut const_pool: HashMap<F, WitnessId> = HashMap::new();
        let mut expr_to_widx: HashMap<ExprId, WitnessId> = HashMap::new();
        let mut public_rows = Vec::new();

        // First, ensure zero constant always exists
        let zero = F::ZERO;
        let zero_widx = self.witness_alloc.alloc();
        const_pool.insert(zero.clone(), zero_widx);
        primitive_ops.push(Prim::Const {
            out: zero_widx,
            val: zero.clone(),
        });

        // Lower each expression to primitives
        for (expr_idx, expr) in self.expressions.nodes().iter().enumerate() {
            let expr_id = ExprId(expr_idx as u32);

            match expr {
                Expr::Const(val) => {
                    // Use existing constant from pool if available
                    let out_widx = if let Some(&existing_widx) = const_pool.get(val) {
                        existing_widx
                    } else {
                        let new_widx = self.witness_alloc.alloc();
                        const_pool.insert(val.clone(), new_widx);
                        primitive_ops.push(Prim::Const {
                            out: new_widx,
                            val: val.clone(),
                        });
                        new_widx
                    };
                    expr_to_widx.insert(expr_id, out_widx);
                }
                Expr::Public(pos) => {
                    let out_widx = self.witness_alloc.alloc();
                    primitive_ops.push(Prim::Public {
                        out: out_widx,
                        public_pos: *pos,
                    });
                    expr_to_widx.insert(expr_id, out_widx);
                    // Track public input mapping
                    if *pos >= public_rows.len() {
                        public_rows.resize(*pos + 1, WitnessId(0));
                    }
                    public_rows[*pos] = out_widx;
                }
                Expr::Add { lhs, rhs } => {
                    let out_widx = self.witness_alloc.alloc();
                    let a_widx = expr_to_widx[lhs];
                    let b_widx = expr_to_widx[rhs];
                    primitive_ops.push(Prim::Add {
                        a: a_widx,
                        b: b_widx,
                        out: out_widx,
                    });
                    expr_to_widx.insert(expr_id, out_widx);
                }
                Expr::Sub { lhs, rhs } => {
                    let out_widx = self.witness_alloc.alloc();
                    let a_widx = expr_to_widx[lhs];
                    let b_widx = expr_to_widx[rhs];
                    primitive_ops.push(Prim::Sub {
                        a: a_widx,
                        b: b_widx,
                        out: out_widx,
                    });
                    expr_to_widx.insert(expr_id, out_widx);
                }
                Expr::Mul { lhs, rhs } => {
                    let out_widx = self.witness_alloc.alloc();
                    let a_widx = expr_to_widx[lhs];
                    let b_widx = expr_to_widx[rhs];
                    primitive_ops.push(Prim::Mul {
                        a: a_widx,
                        b: b_widx,
                        out: out_widx,
                    });
                    expr_to_widx.insert(expr_id, out_widx);
                } // No AssertZero variant; assertions are not encoded as expressions in Stage 1
            }
        }

        // Lower pending assertions: encode z - 0 = 0 by writing a Sub with out = zero_widx
        for z_expr in &self.pending_asserts {
            if let Some(&z_widx) = expr_to_widx.get(z_expr) {
                primitive_ops.push(Prim::Sub {
                    a: z_widx,
                    b: zero_widx,
                    out: zero_widx,
                });
            }
        }

        (primitive_ops, const_pool, public_rows, expr_to_widx)
    }

    /// Stage 2: Lower non-primitive operations from ExprIds to WitnessId
    fn lower_non_primitive_ops(
        &self,
        expr_to_widx: &HashMap<ExprId, WitnessId>,
    ) -> Vec<NonPrimitiveOp> {
        use crate::op::NonPrimitiveOp;

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
                    let leaf_widx = expr_to_widx
                        .get(&witness_exprs[0])
                        .copied()
                        .expect("Leaf expression should have been lowered to WitnessId");
                    let root_widx = expr_to_widx
                        .get(&witness_exprs[1])
                        .copied()
                        .expect("Root expression should have been lowered to WitnessId");

                    lowered_ops.push(NonPrimitiveOp::FakeMerkleVerify {
                        leaf: leaf_widx,
                        root: root_widx,
                    });
                } // Future operations can be added here with different witness expression counts
            }
        }

        lowered_ops
    }

    /// Stage 3: IR transformations and optimizations
    fn optimize_primitives(
        primitive_ops: Vec<Prim<F>>,
        _const_pool: &HashMap<F, WitnessId>,
    ) -> Vec<Prim<F>> {
        // Future passes can be added here:
        // - Dead code elimination
        // - Common subexpression elimination
        // - Instruction combining
        // - Constant folding

        primitive_ops
    }
}

impl<F: Clone> Default for CircuitBuilder<F> {
    fn default() -> Self {
        Self::new()
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

        // Test the DESIGN.txt example: 37 * x - 111 = 0
        let x = builder.add_public_input();
        let c37 = builder.add_const(BabyBear::from_u64(37));
        let c111 = builder.add_const(BabyBear::from_u64(111));

        let mul_result = builder.mul(c37, x);
        let sub_result = builder.sub(mul_result, c111);
        builder.assert_zero(sub_result);

        let circuit = builder.build();
        assert_eq!(circuit.slot_count, 6); // 0:zero, 1:public, 2:c37, 3:c111, 4:mul_result, 5:sub_result

        // Assert all primitive operations
        assert_eq!(circuit.primitive_ops.len(), 7);
        match &circuit.primitive_ops[0] {
            Prim::Const { out, val } => {
                assert_eq!(out.0, 0);
                assert_eq!(*val, BabyBear::from_u64(0));
            }
            _ => panic!("Expected Const(0)"),
        }
        match &circuit.primitive_ops[1] {
            Prim::Public { out, public_pos } => {
                assert_eq!(out.0, 1);
                assert_eq!(*public_pos, 0);
            }
            _ => panic!("Expected Public"),
        }
        match &circuit.primitive_ops[2] {
            Prim::Const { out, val } => {
                assert_eq!(out.0, 2);
                assert_eq!(*val, BabyBear::from_u64(37));
            }
            _ => panic!("Expected Const(37)"),
        }
        match &circuit.primitive_ops[3] {
            Prim::Const { out, val } => {
                assert_eq!(out.0, 3);
                assert_eq!(*val, BabyBear::from_u64(111));
            }
            _ => panic!("Expected Const(111)"),
        }
        match &circuit.primitive_ops[4] {
            Prim::Mul { a, b, out } => {
                assert_eq!(a.0, 2);
                assert_eq!(b.0, 1);
                assert_eq!(out.0, 4);
            }
            _ => panic!("Expected Mul"),
        }
        match &circuit.primitive_ops[5] {
            Prim::Sub { a, b, out } => {
                assert_eq!(a.0, 4);
                assert_eq!(b.0, 3);
                assert_eq!(out.0, 5);
            }
            _ => panic!("Expected Sub(mul_result - c111)"),
        }
        match &circuit.primitive_ops[6] {
            Prim::Sub { a, b, out } => {
                assert_eq!(a.0, 5);
                assert_eq!(b.0, 0);
                assert_eq!(out.0, 0);
            }
            _ => panic!("Expected Sub assertion"),
        }

        assert_eq!(circuit.public_flat_len, 1);
        assert_eq!(circuit.public_rows, vec![WitnessId(1)]); // Public input at slot 1
    }
}
