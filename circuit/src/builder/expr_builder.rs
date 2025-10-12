/// This module provides a builder for constructing expression graphs.
use alloc::vec::Vec;

use hashbrown::HashMap;
use p3_field::PrimeCharacteristicRing;

use crate::expr::{Expr, ExpressionGraph};
use crate::types::ExprId;

/// Builder for constructing expression graphs
pub struct ExpressionBuilder<F> {
    /// Expression graph for building the DAG
    expressions: ExpressionGraph<F>,
    /// Builder-level constant pool: value -> unique Const ExprId
    const_pool: HashMap<F, ExprId>,
    /// Equality constraints to enforce at lowering
    pending_connects: Vec<(ExprId, ExprId)>,
}

impl<F> ExpressionBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + Eq + core::hash::Hash,
{
    /// Create a new expression builder
    pub fn new() -> Self {
        let mut expressions = ExpressionGraph::new();

        // Insert Const(0) as the very first node so it has ExprId::ZERO.
        let zero_val = F::ZERO;
        let zero_id = expressions.add_expr(Expr::Const(zero_val.clone()));

        let mut const_pool = HashMap::new();
        const_pool.insert(zero_val, zero_id);

        Self {
            expressions,
            const_pool,
            pending_connects: Vec::new(),
        }
    }

    /// Add a constant to the expression graph (deduplicated).
    ///
    /// If this value was previously added, returns the original ExprId.
    pub fn add_const(&mut self, val: F) -> ExprId {
        *self
            .const_pool
            .entry(val)
            .or_insert_with_key(|k| self.expressions.add_expr(Expr::Const(k.clone())))
    }

    /// Add a public input expression.
    ///
    /// Note: This creates the expression but doesn't track public input count.
    /// The caller is responsible for tracking public input positions.
    pub fn add_public_expr(&mut self, public_pos: usize) -> ExprId {
        self.expressions.add_expr(Expr::Public(public_pos))
    }

    /// Add two expressions.
    pub fn add(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let add_expr = Expr::Add { lhs, rhs };
        self.expressions.add_expr(add_expr)
    }

    /// Subtract two expressions.
    pub fn sub(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let sub_expr = Expr::Sub { lhs, rhs };
        self.expressions.add_expr(sub_expr)
    }

    /// Multiply two expressions.
    pub fn mul(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let mul_expr = Expr::Mul { lhs, rhs };
        self.expressions.add_expr(mul_expr)
    }

    /// Divide two expressions.
    pub fn div(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        let div_expr = Expr::Div { lhs, rhs };
        self.expressions.add_expr(div_expr)
    }

    /// Connect two expressions, enforcing a == b (by aliasing outputs).
    ///
    /// Cost: Free in proving (handled by IR optimization layer via witness slot aliasing).
    pub fn connect(&mut self, a: ExprId, b: ExprId) {
        if a != b {
            self.pending_connects.push((a, b));
        }
    }

    /// Get the expression graph.
    pub fn finish(self) -> (ExpressionGraph<F>, Vec<(ExprId, ExprId)>) {
        (self.expressions, self.pending_connects)
    }

    /// Get a reference to the expression graph (for reading).
    pub fn expressions(&self) -> &ExpressionGraph<F> {
        &self.expressions
    }

    /// Get a mutable reference to the expression graph.
    pub fn expressions_mut(&mut self) -> &mut ExpressionGraph<F> {
        &mut self.expressions
    }

    /// Get the pending connections.
    pub fn pending_connects(&self) -> &[(ExprId, ExprId)] {
        &self.pending_connects
    }

    /// Get the constant pool.
    pub fn const_pool(&self) -> &HashMap<F, ExprId> {
        &self.const_pool
    }
}

impl<F> Default for ExpressionBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + Eq + core::hash::Hash,
{
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;

    use super::*;

    #[test]
    fn test_expression_builder_basic() {
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        // Test constant deduplication
        let c1 = builder.add_const(BabyBear::from_u64(42));
        let c2 = builder.add_const(BabyBear::from_u64(42));
        assert_eq!(c1, c2);

        // Test different constants
        let c3 = builder.add_const(BabyBear::from_u64(43));
        assert_ne!(c1, c3);

        // Test arithmetic operations
        let add_result = builder.add(c1, c3);
        let mul_result = builder.mul(add_result, c1);

        // Test connections
        builder.connect(add_result, mul_result);

        // Finish and verify
        let (expressions, connects) = builder.finish();
        assert_eq!(expressions.nodes().len(), 5); // 0 (ZERO), 42, 43, add, mul
        assert_eq!(connects.len(), 1);
    }

    #[test]
    fn test_expression_builder_public_inputs() {
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        let pub1 = builder.add_public_expr(0);
        let pub2 = builder.add_public_expr(1);
        let _sum = builder.add(pub1, pub2);

        let (expressions, _) = builder.finish();
        assert_eq!(expressions.nodes().len(), 4); // 0, pub1, pub2, add
    }
}
