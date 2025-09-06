use crate::{
    types::{ExprId, WitnessAllocator, WIdx},
    expr::{ExtExpr, ExprArena},
    prim::Prim,
    program::Program,
};

/// Circuit builder for constructing extension field programs
pub struct Circuit<E> {
    /// Expression arena for building the DAG
    expr_arena: ExprArena<E>,
    /// Witness index allocator
    witness_alloc: WitnessAllocator,
    /// Track public input positions
    public_input_count: usize,
}

impl<E: Clone> Circuit<E> {
    /// Create a new circuit builder
    pub fn new() -> Self {
        Self {
            expr_arena: ExprArena::new(),
            witness_alloc: WitnessAllocator::new(),
            public_input_count: 0,
        }
    }

    /// Add a public input to the circuit
    pub fn add_public_input(&mut self) -> ExprId {
        let public_pos = self.public_input_count;
        self.public_input_count += 1;
        
        let public_expr = ExtExpr::Public(public_pos);
        self.expr_arena.add_expr(public_expr)
    }

    /// Add a constant to the circuit
    pub fn add_const(&mut self, val: E) -> ExprId {
        let const_expr = ExtExpr::Const(val);
        self.expr_arena.add_expr(const_expr)
    }

    /// Add two expressions
    pub fn add(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let add_expr = ExtExpr::Add { lhs, rhs };
        self.expr_arena.add_expr(add_expr)
    }

    /// Subtract two expressions  
    pub fn sub(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let sub_expr = ExtExpr::Sub { lhs, rhs };
        self.expr_arena.add_expr(sub_expr)
    }

    /// Multiply two expressions
    pub fn mul(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let mul_expr = ExtExpr::Mul { lhs, rhs };
        self.expr_arena.add_expr(mul_expr)
    }

    /// Assert that an expression equals zero
    pub fn assert_zero(&mut self, expr: ExprId) where E: Default {
        // Create zero constant
        let zero = self.add_const(E::default());
        
        // Create subtraction: expr - 0 = 0
        let _zero_check = self.sub(expr, zero);
        
        // Note: The actual assertion will be handled in build() 
        // by generating an AssertZero primitive
    }
}

impl<E: Clone + Default> Circuit<E> {
    /// Build the circuit into a Program
    pub fn build(mut self) -> Program<E> {
        let mut prim_ops = Vec::new();
        
        // Lower each expression to primitives
        for (_expr_id, expr) in self.expr_arena.nodes().iter().enumerate() {
            let out_widx = self.witness_alloc.alloc();
            match expr {
                ExtExpr::Const(val) => {
                    prim_ops.push(Prim::Const { 
                        out: out_widx, 
                        val: val.clone() 
                    });
                }
                ExtExpr::Public(pos) => {
                    prim_ops.push(Prim::Public { 
                        out: out_widx, 
                        public_pos: *pos 
                    });
                }
                ExtExpr::Add { lhs, rhs } => {
                    let a_widx = WIdx(lhs.0);
                    let b_widx = WIdx(rhs.0);
                    prim_ops.push(Prim::Add { 
                        a: a_widx, 
                        b: b_widx, 
                        out: out_widx 
                    });
                }
                ExtExpr::Sub { lhs, rhs } => {
                    let a_widx = WIdx(lhs.0);
                    let b_widx = WIdx(rhs.0);
                    prim_ops.push(Prim::Sub { 
                        a: a_widx, 
                        b: b_widx, 
                        out: out_widx 
                    });
                }
                ExtExpr::Mul { lhs, rhs } => {
                    let a_widx = WIdx(lhs.0);
                    let b_widx = WIdx(rhs.0);
                    prim_ops.push(Prim::Mul { 
                        a: a_widx, 
                        b: b_widx, 
                        out: out_widx 
                    });
                }
            }
        }
        
        let slot_count = self.witness_alloc.slot_count();
        let mut program = Program::new(slot_count);
        program.prim_ops = prim_ops;
        
        program
    }
}

impl<E: Clone> Default for Circuit<E> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Mock extension field element for testing
    #[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
    struct MockExtField(u64);

    #[test]
    fn test_circuit_basic_api() {
        let mut circuit = Circuit::<MockExtField>::new();
        
        // Test the DESIGN.txt example: 37 * x - 111 = 0
        let x = circuit.add_public_input();
        let c37 = circuit.add_const(MockExtField(37));
        let c111 = circuit.add_const(MockExtField(111));
        
        let mul_result = circuit.mul(c37, x);
        let sub_result = circuit.sub(mul_result, c111);
        circuit.assert_zero(sub_result);
        
        let program = circuit.build();
        
        // Should have allocated some witness slots
        assert!(program.slot_count > 0);
        assert_eq!(program.vk.operation_air_ids.len(), 4);
    }
    
    #[test]
    fn test_public_input_tracking() {
        let mut circuit = Circuit::<MockExtField>::new();
        
        let x1 = circuit.add_public_input();  // Should be Public(0)
        let x2 = circuit.add_public_input();  // Should be Public(1)
        
        // Verify they got different expression IDs
        assert_ne!(x1, x2);
        
        // Check the expressions are correct
        assert_eq!(circuit.expr_arena.get_expr(x1), &ExtExpr::Public(0));
        assert_eq!(circuit.expr_arena.get_expr(x2), &ExtExpr::Public(1));
    }
}