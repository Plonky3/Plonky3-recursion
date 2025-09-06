use crate::types::ExprId;

/// Expression DAG for extension field operations
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum ExtExpr<E> {
    /// Constant extension field element
    Const(E),
    /// Public input at declaration position
    Public(usize),
    /// Addition of two expressions
    Add { lhs: ExprId, rhs: ExprId },
    /// Subtraction of two expressions  
    Sub { lhs: ExprId, rhs: ExprId },
    /// Multiplication of two expressions
    Mul { lhs: ExprId, rhs: ExprId },
}

/// Arena for storing expression DAG nodes
#[derive(Debug, Clone)]
pub struct ExprArena<E> {
    nodes: Vec<ExtExpr<E>>,
}

impl<E> ExprArena<E> {
    pub fn new() -> Self {
        Self {
            nodes: Vec::new(),
        }
    }

    /// Add an expression to the arena, returning its ID
    pub fn add_expr(&mut self, expr: ExtExpr<E>) -> ExprId {
        let id = ExprId(self.nodes.len() as u32);
        self.nodes.push(expr);
        id
    }

    /// Get an expression by ID
    pub fn get_expr(&self, id: ExprId) -> &ExtExpr<E> {
        &self.nodes[id.0 as usize]
    }

    /// Get all nodes in the arena
    pub fn nodes(&self) -> &[ExtExpr<E>] {
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
    fn test_expr_arena() {
        let mut arena = ExprArena::<MockExtField>::new();
        
        let const_expr = ExtExpr::Const(MockExtField(42));
        let public_expr = ExtExpr::Public(0);
        
        let const_id = arena.add_expr(const_expr.clone());
        let public_id = arena.add_expr(public_expr.clone());
        
        assert_eq!(const_id, ExprId(0));
        assert_eq!(public_id, ExprId(1));
        
        assert_eq!(arena.get_expr(const_id), &const_expr);
        assert_eq!(arena.get_expr(public_id), &public_expr);
        
        let add_expr = ExtExpr::Add { lhs: const_id, rhs: public_id };
        let add_id = arena.add_expr(add_expr.clone());
        assert_eq!(add_id, ExprId(2));
        assert_eq!(arena.get_expr(add_id), &add_expr);
    }
}