use crate::{
    expr::{Expr, ExprArena},
    prim::Prim,
    program::Program,
    types::{ExprId, WIdx, WitnessAllocator},
};
use p3_field::PrimeCharacteristicRing;
use std::collections::HashMap;

/// Circuit builder for constructing field programs
pub struct Circuit<F> {
    /// Expression arena for building the DAG
    expr_arena: ExprArena<F>,
    /// Witness index allocator
    witness_alloc: WitnessAllocator,
    /// Track public input positions
    public_input_count: usize,
    /// Pending zero assertions to lower in build()
    pending_asserts: Vec<ExprId>,
}

impl<F: Clone> Circuit<F> {
    /// Create a new circuit builder
    pub fn new() -> Self {
        Self {
            expr_arena: ExprArena::new(),
            witness_alloc: WitnessAllocator::new(),
            public_input_count: 0,
            pending_asserts: Vec::new(),
        }
    }

    /// Add a public input to the circuit
    pub fn add_public_input(&mut self) -> ExprId {
        let public_pos = self.public_input_count;
        self.public_input_count += 1;

        let public_expr = Expr::Public(public_pos);
        self.expr_arena.add_expr(public_expr)
    }

    /// Add a constant to the circuit
    pub fn add_const(&mut self, val: F) -> ExprId {
        let const_expr = Expr::Const(val);
        self.expr_arena.add_expr(const_expr)
    }

    /// Add two expressions
    pub fn add(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let add_expr = Expr::Add { lhs, rhs };
        self.expr_arena.add_expr(add_expr)
    }

    /// Subtract two expressions  
    pub fn sub(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let sub_expr = Expr::Sub { lhs, rhs };
        self.expr_arena.add_expr(sub_expr)
    }

    /// Multiply two expressions
    pub fn mul(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let mul_expr = Expr::Mul { lhs, rhs };
        self.expr_arena.add_expr(mul_expr)
    }

    /// Assert that an expression equals zero.
    /// Recorded as a pending assertion to be lowered in build() to a Sub with zero.
    pub fn assert_zero(&mut self, expr: ExprId) {
        self.pending_asserts.push(expr);
    }
}

impl<F: Clone + PrimeCharacteristicRing + PartialEq + Eq + std::hash::Hash> Circuit<F> {
    /// Build the circuit into a Program with separate lowering and IR transformation stages
    pub fn build(mut self) -> Program<F> {
        // Stage 1: Lower expressions to naive primitives with constant pooling
        let (prim_ops, const_pool, public_rows) = self.lower_to_primitives();

        // Stage 2: IR transformations and optimizations
        let prim_ops = Self::optimize_primitives(prim_ops, &const_pool);

        // Stage 3: Generate final program
        let slot_count = self.witness_alloc.slot_count();
        let mut program = Program::new(slot_count);
        program.prim_ops = prim_ops;
        program.public_rows = public_rows;
        program.public_flat_len = self.public_input_count;

        program
    }

    /// Stage 1: Lower expressions to primitives with constant pooling
    fn lower_to_primitives(&mut self) -> (Vec<Prim<F>>, HashMap<F, WIdx>, Vec<WIdx>) {
        let mut prim_ops = Vec::new();
        let mut const_pool: HashMap<F, WIdx> = HashMap::new();
        let mut expr_to_widx: HashMap<ExprId, WIdx> = HashMap::new();
        let mut public_rows = Vec::new();

        // First, ensure zero constant always exists
        let zero = F::ZERO;
        let zero_widx = self.witness_alloc.alloc();
        const_pool.insert(zero.clone(), zero_widx);
        prim_ops.push(Prim::Const {
            out: zero_widx,
            val: zero.clone(),
        });

        // Lower each expression to primitives
        for (expr_idx, expr) in self.expr_arena.nodes().iter().enumerate() {
            let expr_id = ExprId(expr_idx as u32);

            match expr {
                Expr::Const(val) => {
                    // Use existing constant from pool if available
                    let out_widx = if let Some(&existing_widx) = const_pool.get(val) {
                        existing_widx
                    } else {
                        let new_widx = self.witness_alloc.alloc();
                        const_pool.insert(val.clone(), new_widx);
                        prim_ops.push(Prim::Const {
                            out: new_widx,
                            val: val.clone(),
                        });
                        new_widx
                    };
                    expr_to_widx.insert(expr_id, out_widx);
                }
                Expr::Public(pos) => {
                    let out_widx = self.witness_alloc.alloc();
                    prim_ops.push(Prim::Public {
                        out: out_widx,
                        public_pos: *pos,
                    });
                    expr_to_widx.insert(expr_id, out_widx);
                    // Track public input mapping
                    if *pos >= public_rows.len() {
                        public_rows.resize(*pos + 1, WIdx(0));
                    }
                    public_rows[*pos] = out_widx;
                }
                Expr::Add { lhs, rhs } => {
                    let out_widx = self.witness_alloc.alloc();
                    let a_widx = expr_to_widx[lhs];
                    let b_widx = expr_to_widx[rhs];
                    prim_ops.push(Prim::Add {
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
                    prim_ops.push(Prim::Sub {
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
                    prim_ops.push(Prim::Mul {
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
                prim_ops.push(Prim::Sub {
                    a: z_widx,
                    b: zero_widx,
                    out: zero_widx,
                });
            }
        }

        (prim_ops, const_pool, public_rows)
    }

    /// Stage 2: IR transformations and optimizations
    fn optimize_primitives(prim_ops: Vec<Prim<F>>, _const_pool: &HashMap<F, WIdx>) -> Vec<Prim<F>> {
        // Future passes can be added here:
        // - Dead code elimination
        // - Common subexpression elimination
        // - Instruction combining
        // - Constant folding

        prim_ops
    }
}

impl<F: Clone> Default for Circuit<F> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    #[test]
    fn test_circuit_basic_api() {
        let mut circuit = Circuit::<BabyBear>::new();

        // Test the DESIGN.txt example: 37 * x - 111 = 0
        let x = circuit.add_public_input();
        let c37 = circuit.add_const(BabyBear::from_u64(37));
        let c111 = circuit.add_const(BabyBear::from_u64(111));

        let mul_result = circuit.mul(c37, x);
        let sub_result = circuit.sub(mul_result, c111);
        circuit.assert_zero(sub_result);

        let program = circuit.build();
        assert_eq!(program.slot_count, 6); // 0:zero, 1:public, 2:c37, 3:c111, 4:mul_result, 5:sub_result

        // Assert all primitive operations
        assert_eq!(program.prim_ops.len(), 7);
        match &program.prim_ops[0] {
            Prim::Const { out, val } => {
                assert_eq!(out.0, 0);
                assert_eq!(*val, BabyBear::from_u64(0));
            }
            _ => panic!("Expected Const(0)"),
        }
        match &program.prim_ops[1] {
            Prim::Public { out, public_pos } => {
                assert_eq!(out.0, 1);
                assert_eq!(*public_pos, 0);
            }
            _ => panic!("Expected Public"),
        }
        match &program.prim_ops[2] {
            Prim::Const { out, val } => {
                assert_eq!(out.0, 2);
                assert_eq!(*val, BabyBear::from_u64(37));
            }
            _ => panic!("Expected Const(37)"),
        }
        match &program.prim_ops[3] {
            Prim::Const { out, val } => {
                assert_eq!(out.0, 3);
                assert_eq!(*val, BabyBear::from_u64(111));
            }
            _ => panic!("Expected Const(111)"),
        }
        match &program.prim_ops[4] {
            Prim::Mul { a, b, out } => {
                assert_eq!(a.0, 2);
                assert_eq!(b.0, 1);
                assert_eq!(out.0, 4);
            }
            _ => panic!("Expected Mul"),
        }
        match &program.prim_ops[5] {
            Prim::Sub { a, b, out } => {
                assert_eq!(a.0, 4);
                assert_eq!(b.0, 3);
                assert_eq!(out.0, 5);
            }
            _ => panic!("Expected Sub(mul_result - c111)"),
        }
        match &program.prim_ops[6] {
            Prim::Sub { a, b, out } => {
                assert_eq!(a.0, 5);
                assert_eq!(b.0, 0);
                assert_eq!(out.0, 0);
            }
            _ => panic!("Expected Sub assertion"),
        }

        assert_eq!(program.public_flat_len, 1);
        assert_eq!(program.public_rows, vec![WIdx(1)]); // Public input at slot 1
    }
}
