use alloc::boxed::Box;
#[cfg(debug_assertions)]
use alloc::vec;
use alloc::vec::Vec;

use hashbrown::HashMap;
use itertools::Itertools;
use p3_field::PrimeCharacteristicRing;

use crate::expr::{Expr, ExpressionGraph};
use crate::op::WitnessHintFiller;
use crate::types::ExprId;
#[cfg(debug_assertions)]
use crate::{AllocationEntry, AllocationType};

/// Manages expression graph construction and constant pooling.
#[derive(Debug)]
pub struct ExpressionBuilder<F> {
    /// The underlying expression graph
    graph: ExpressionGraph<F>,

    /// Builder-level constant pool: value -> unique Const ExprId
    const_pool: HashMap<F, ExprId>,

    /// Equality constraints to enforce at lowering
    pending_connects: Vec<(ExprId, ExprId)>,

    /// The witness hints together with theit witness fillers
    hints_with_fillers: Vec<Box<dyn WitnessHintFiller<F>>>,

    /// Debug log of all allocations
    #[cfg(debug_assertions)]
    allocation_log: Vec<AllocationEntry>,

    /// Stack of active scopes for organizing allocations
    #[cfg(debug_assertions)]
    scope_stack: Vec<&'static str>,
}

impl<F> ExpressionBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + Eq + core::hash::Hash,
{
    /// Creates a new expression builder with zero constant pre-allocated.
    pub fn new() -> Self {
        let mut graph = ExpressionGraph::new();

        // Insert Const(0) as the very first node so it has ExprId::ZERO
        let zero_val = F::ZERO;
        let zero_id = graph.add_expr(Expr::Const(zero_val.clone()));

        let mut const_pool = HashMap::new();
        const_pool.insert(zero_val, zero_id);

        Self {
            graph,
            const_pool,
            pending_connects: Vec::new(),
            hints_with_fillers: Vec::new(),
            #[cfg(debug_assertions)]
            allocation_log: Vec::new(),
            #[cfg(debug_assertions)]
            scope_stack: Vec::new(),
        }
    }

    /// Adds a constant to the expression graph (deduplicated).
    ///
    /// If this value was previously added, returns the original ExprId.
    #[allow(unused_variables)]
    pub fn add_const(&mut self, val: F, label: &'static str) -> ExprId {
        #[cfg(debug_assertions)]
        let current_scope = self.current_scope();

        *self.const_pool.entry(val).or_insert_with_key(|k| {
            let expr_id = self.graph.add_expr(Expr::Const(k.clone()));

            #[cfg(debug_assertions)]
            self.allocation_log.push(AllocationEntry {
                expr_id,
                alloc_type: AllocationType::Const,
                label,
                dependencies: vec![],
                scope: current_scope,
            });

            expr_id
        })
    }

    /// Adds a public input expression to the graph.
    #[allow(unused_variables)]
    pub fn add_public(&mut self, pos: usize, label: &'static str) -> ExprId {
        let expr_id = self.graph.add_expr(Expr::Public(pos));

        #[cfg(debug_assertions)]
        self.allocation_log.push(AllocationEntry {
            expr_id,
            alloc_type: AllocationType::Public,
            label,
            dependencies: vec![],
            scope: self.current_scope(),
        });

        expr_id
    }

    /// Adds a witness hint to the graph.
    /// It will allocate a `WitnessId` during lowering, with no primitive op.
    /// TODO: Make this function private.
    #[allow(unused_variables)]
    #[must_use]
    pub fn add_witness_hint(&mut self, label: &'static str) -> ExprId {
        let expr_id = self.graph.add_expr(Expr::Witness { last_hint: true });

        #[cfg(debug_assertions)]
        self.allocation_log.push(AllocationEntry {
            expr_id,
            alloc_type: AllocationType::WitnessHint,
            label,
            dependencies: vec![],
            scope: self.current_scope(),
        });

        expr_id
    }

    /// Adds `filler.n_outputs()` witness hints to the graph.
    /// During circuit evaluation, the `filler` will derive the concrete
    /// witness values for these hints.
    #[allow(unused_variables)]
    #[must_use]
    pub fn add_witness_hints<W: 'static + WitnessHintFiller<F>>(
        &mut self,
        filler: W,
        label: &'static str,
    ) -> Vec<ExprId> {
        let n_outputs = filler.n_outputs();
        let expr_ids = (0..n_outputs)
            .map(|i| {
                self.graph.add_expr(Expr::Witness {
                    last_hint: i == n_outputs - 1,
                })
            })
            .collect_vec();
        self.hints_with_fillers.push(Box::new(filler));
        expr_ids
    }

    /// Adds an addition expression to the graph.
    #[allow(unused_variables)]
    pub fn add_add(&mut self, lhs: ExprId, rhs: ExprId, label: &'static str) -> ExprId {
        let expr_id = self.graph.add_expr(Expr::Add { lhs, rhs });

        #[cfg(debug_assertions)]
        self.allocation_log.push(AllocationEntry {
            expr_id,
            alloc_type: AllocationType::Add,
            label,
            dependencies: vec![vec![lhs], vec![rhs]],
            scope: self.current_scope(),
        });

        expr_id
    }

    /// Adds a subtraction expression to the graph.
    #[allow(unused_variables)]
    pub fn add_sub(&mut self, lhs: ExprId, rhs: ExprId, label: &'static str) -> ExprId {
        let expr_id = self.graph.add_expr(Expr::Sub { lhs, rhs });

        #[cfg(debug_assertions)]
        self.allocation_log.push(AllocationEntry {
            expr_id,
            alloc_type: AllocationType::Sub,
            label,
            dependencies: vec![vec![lhs], vec![rhs]],
            scope: self.current_scope(),
        });

        expr_id
    }

    /// Adds a multiplication expression to the graph.
    #[allow(unused_variables)]
    pub fn add_mul(&mut self, lhs: ExprId, rhs: ExprId, label: &'static str) -> ExprId {
        let expr_id = self.graph.add_expr(Expr::Mul { lhs, rhs });

        #[cfg(debug_assertions)]
        self.allocation_log.push(AllocationEntry {
            expr_id,
            alloc_type: AllocationType::Mul,
            label,
            dependencies: vec![vec![lhs], vec![rhs]],
            scope: self.current_scope(),
        });

        expr_id
    }

    /// Adds a division expression to the graph.
    #[allow(unused_variables)]
    pub fn add_div(&mut self, lhs: ExprId, rhs: ExprId, label: &'static str) -> ExprId {
        let expr_id = self.graph.add_expr(Expr::Div { lhs, rhs });

        #[cfg(debug_assertions)]
        self.allocation_log.push(AllocationEntry {
            expr_id,
            alloc_type: AllocationType::Div,
            label,
            dependencies: vec![vec![lhs], vec![rhs]],
            scope: self.current_scope(),
        });

        expr_id
    }

    /// Connects two expressions, enforcing equality.
    pub fn connect(&mut self, a: ExprId, b: ExprId) {
        if a != b {
            self.pending_connects.push((a, b));
        }
    }

    /// Returns a reference to the expression graph.
    pub const fn graph(&self) -> &ExpressionGraph<F> {
        &self.graph
    }

    /// Returns a reference to pending connections.
    pub fn pending_connects(&self) -> &[(ExprId, ExprId)] {
        &self.pending_connects
    }

    /// Returns a reference to the witness hints with fillers.
    pub fn hints_with_fillers(&self) -> &[Box<dyn WitnessHintFiller<F>>] {
        &self.hints_with_fillers
    }

    /// Logs a non-primitive operation allocation.
    #[cfg(debug_assertions)]
    pub fn log_non_primitive_op(
        &mut self,
        op_id: crate::types::NonPrimitiveOpId,
        op_type: crate::op::NonPrimitiveOpType,
        dependencies: Vec<Vec<ExprId>>,
        label: &'static str,
    ) {
        self.allocation_log.push(AllocationEntry {
            expr_id: ExprId(op_id.0),
            alloc_type: AllocationType::NonPrimitiveOp(op_type),
            label,
            dependencies,
            scope: self.current_scope(),
        });
    }

    /// Pushes a new scope onto the scope stack.
    #[cfg(debug_assertions)]
    pub fn push_scope(&mut self, scope: &'static str) {
        self.scope_stack.push(scope);
    }

    /// Pops the current scope from the scope stack.
    #[cfg(debug_assertions)]
    pub fn pop_scope(&mut self) {
        self.scope_stack.pop();
    }

    /// Gets the current scope (if any).
    #[cfg(debug_assertions)]
    fn current_scope(&self) -> Option<&'static str> {
        self.scope_stack.last().copied()
    }

    /// Returns a reference to the allocation log.
    #[cfg(debug_assertions)]
    pub fn allocation_log(&self) -> &[AllocationEntry] {
        &self.allocation_log
    }

    /// Dump the allocation log.
    ///
    /// If debug_assertions are not enabled, this is a no-op.
    pub fn dump_allocation_log(&self) {
        #[cfg(debug_assertions)]
        crate::alloc_entry::dump_allocation_log(&self.allocation_log);
    }

    /// List all unique scopes in the allocation log.
    ///
    /// Returns an empty vector if debug_assertions are not enabled.
    pub fn list_scopes(&self) -> Vec<&'static str> {
        #[cfg(debug_assertions)]
        {
            crate::alloc_entry::list_scopes(&self.allocation_log)
        }
        #[cfg(not(debug_assertions))]
        {
            Vec::new()
        }
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
    use p3_field::Field;

    use super::*;

    #[test]
    fn test_new_builder_has_zero_constant() {
        // New builder should pre-allocate zero constant
        let builder = ExpressionBuilder::<BabyBear>::new();

        // Zero should be in the graph at ExprId::ZERO
        assert_eq!(builder.graph().nodes().len(), 1);
        match &builder.graph().nodes()[0] {
            Expr::Const(val) => assert_eq!(*val, BabyBear::ZERO),
            _ => panic!("Expected Const(0) at ExprId::ZERO"),
        }

        // Const pool should contain zero
        assert_eq!(builder.const_pool.len(), 1);
        assert!(builder.const_pool.contains_key(&BabyBear::ZERO));

        // No pending connections
        assert!(builder.pending_connects.is_empty());
    }

    #[test]
    fn test_add_const_single() {
        // Adding a single constant should work
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        let c1 = builder.add_const(BabyBear::ONE, "test_const");

        // Should have 2 nodes: zero + one
        assert_eq!(builder.graph().nodes().len(), 2);
        assert_eq!(c1, ExprId(1));

        // Verify the constant was added to graph
        match &builder.graph().nodes()[1] {
            Expr::Const(val) => assert_eq!(*val, BabyBear::ONE),
            _ => panic!("Expected Const(1)"),
        }

        // Const pool should have both zero and one
        assert_eq!(builder.const_pool.len(), 2);
    }

    #[test]
    fn test_add_const_deduplication() {
        // Adding the same constant twice should return same ExprId
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        let c1 = builder.add_const(BabyBear::from_u64(42), "first");
        let c2 = builder.add_const(BabyBear::from_u64(42), "second");

        // Should return same ExprId
        assert_eq!(c1, c2);

        // Should only have 2 nodes (zero + 42), not 3
        assert_eq!(builder.graph().nodes().len(), 2);

        // Const pool should only have 2 entries
        assert_eq!(builder.const_pool.len(), 2);
    }

    #[test]
    fn test_add_const_multiple_different() {
        // Adding different constants should create distinct ExprIds
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        let c1 = builder.add_const(BabyBear::from_u64(1), "one");
        let c2 = builder.add_const(BabyBear::from_u64(2), "two");
        let c3 = builder.add_const(BabyBear::from_u64(3), "three");

        // All should be different
        assert_ne!(c1, c2);
        assert_ne!(c2, c3);
        assert_ne!(c1, c3);

        // Should have 4 nodes: zero + 1 + 2 + 3
        assert_eq!(builder.graph().nodes().len(), 4);
        assert_eq!(builder.const_pool.len(), 4);
    }

    #[test]
    fn test_add_const_zero_deduplicates_with_prealloc() {
        // Adding zero constant should return pre-allocated ExprId::ZERO
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        let zero = builder.add_const(BabyBear::ZERO, "explicit_zero");

        // Should return ExprId::ZERO (the pre-allocated one)
        assert_eq!(zero, ExprId::ZERO);

        // Should still have only 1 node
        assert_eq!(builder.graph().nodes().len(), 1);
        assert_eq!(builder.const_pool.len(), 1);
    }

    #[test]
    fn test_add_public_single() {
        // Adding a single public input
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        let p0 = builder.add_public(0, "public_0");

        // Should have 2 nodes: zero + public
        assert_eq!(builder.graph().nodes().len(), 2);
        assert_eq!(p0, ExprId(1));

        // Verify it's a Public node
        match &builder.graph().nodes()[1] {
            Expr::Public(pos) => assert_eq!(*pos, 0),
            _ => panic!("Expected Public(0)"),
        }
    }

    #[test]
    fn test_add_public_multiple() {
        // Adding multiple public inputs with different positions
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        let p0 = builder.add_public(0, "p0");
        let p1 = builder.add_public(1, "p1");
        let p2 = builder.add_public(2, "p2");

        // All should be different
        assert_ne!(p0, p1);
        assert_ne!(p1, p2);

        // Should have 4 nodes: zero + 3 publics
        assert_eq!(builder.graph().nodes().len(), 4);

        // Verify positions
        match &builder.graph().nodes()[1] {
            Expr::Public(pos) => assert_eq!(*pos, 0),
            _ => panic!("Expected Public(0)"),
        }
        match &builder.graph().nodes()[2] {
            Expr::Public(pos) => assert_eq!(*pos, 1),
            _ => panic!("Expected Public(1)"),
        }
        match &builder.graph().nodes()[3] {
            Expr::Public(pos) => assert_eq!(*pos, 2),
            _ => panic!("Expected Public(2)"),
        }
    }

    #[test]
    fn test_add_public_same_position_creates_different_nodes() {
        // Adding public inputs with same position creates different nodes
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        let p0_a = builder.add_public(0, "first");
        let p0_b = builder.add_public(0, "second");

        // Should be different ExprIds (no deduplication for Public)
        assert_ne!(p0_a, p0_b);

        // Should have 3 nodes
        assert_eq!(builder.graph().nodes().len(), 3);
    }

    #[test]
    fn test_add_operation() {
        // Test Add operation
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        let a = builder.add_const(BabyBear::from_u64(2), "a");
        let b = builder.add_const(BabyBear::from_u64(3), "b");
        let _sum = builder.add_add(a, b, "sum");

        // Should have 4 nodes: zero + 2 + 3 + add
        assert_eq!(builder.graph().nodes().len(), 4);

        // Verify Add node
        match &builder.graph().nodes()[3] {
            Expr::Add { lhs, rhs } => {
                assert_eq!(*lhs, a);
                assert_eq!(*rhs, b);
            }
            _ => panic!("Expected Add operation"),
        }
    }

    #[test]
    fn test_sub_operation() {
        // Test Sub operation
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        let a = builder.add_const(BabyBear::from_u64(5), "a");
        let b = builder.add_const(BabyBear::from_u64(3), "b");
        let _diff = builder.add_sub(a, b, "diff");

        assert_eq!(builder.graph().nodes().len(), 4);

        match &builder.graph().nodes()[3] {
            Expr::Sub { lhs, rhs } => {
                assert_eq!(*lhs, a);
                assert_eq!(*rhs, b);
            }
            _ => panic!("Expected Sub operation"),
        }
    }

    #[test]
    fn test_mul_operation() {
        // Test Mul operation
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        let a = builder.add_const(BabyBear::from_u64(7), "a");
        let b = builder.add_const(BabyBear::from_u64(6), "b");
        let _prod = builder.add_mul(a, b, "prod");

        assert_eq!(builder.graph().nodes().len(), 4);

        match &builder.graph().nodes()[3] {
            Expr::Mul { lhs, rhs } => {
                assert_eq!(*lhs, a);
                assert_eq!(*rhs, b);
            }
            _ => panic!("Expected Mul operation"),
        }
    }

    #[test]
    fn test_div_operation() {
        // Test Div operation
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        let a = builder.add_const(BabyBear::from_u64(10), "a");
        let b = builder.add_const(BabyBear::from_u64(2), "b");
        let _quot = builder.add_div(a, b, "quot");

        assert_eq!(builder.graph().nodes().len(), 4);

        match &builder.graph().nodes()[3] {
            Expr::Div { lhs, rhs } => {
                assert_eq!(*lhs, a);
                assert_eq!(*rhs, b);
            }
            _ => panic!("Expected Div operation"),
        }
    }

    #[derive(Debug, Clone)]
    struct IdentityHint {
        inputs: Vec<ExprId>,
        n_outputs: usize,
    }

    impl IdentityHint {
        pub fn new(inputs: Vec<ExprId>) -> Self {
            Self {
                n_outputs: inputs.len(),
                inputs,
            }
        }
    }

    impl<F: Field> WitnessHintFiller<F> for IdentityHint {
        fn inputs(&self) -> &[ExprId] {
            &self.inputs
        }

        fn n_outputs(&self) -> usize {
            self.n_outputs
        }

        fn compute_outputs(&self, inputs_val: Vec<F>) -> Result<Vec<F>, crate::CircuitError> {
            Ok(inputs_val)
        }
    }
    #[test]
    fn test_build_with_witness_hint() {
        let mut builder = ExpressionBuilder::<BabyBear>::new();
        let a = builder.add_const(BabyBear::ZERO, "a");
        let b = builder.add_const(BabyBear::ONE, "b");
        let id_hint = IdentityHint::new(vec![a, b]);
        let c = builder.add_witness_hints(id_hint, "c");
        assert_eq!(c.len(), 2);

        assert_eq!(builder.graph().nodes().len(), 4);

        match (&builder.graph().nodes()[2], &builder.graph().nodes()[3]) {
            (Expr::Witness { last_hint: false }, Expr::Witness { last_hint: true }) => (),
            _ => panic!("Expected Witness operation"),
        }
    }

    #[test]
    fn test_nested_operations() {
        // Test nested operations: (a + b) * (c - d)
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        let a = builder.add_const(BabyBear::from_u64(1), "a");
        let b = builder.add_const(BabyBear::from_u64(2), "b");
        let c = builder.add_const(BabyBear::from_u64(3), "c");
        let d = builder.add_const(BabyBear::from_u64(4), "d");

        let sum = builder.add_add(a, b, "sum");
        let diff = builder.add_sub(c, d, "diff");
        let _prod = builder.add_mul(sum, diff, "prod");

        // zero + 4 consts + 3 ops = 8 nodes
        assert_eq!(builder.graph().nodes().len(), 8);

        // Verify final operation references intermediate results
        match &builder.graph().nodes()[7] {
            Expr::Mul { lhs, rhs } => {
                assert_eq!(*lhs, sum);
                assert_eq!(*rhs, diff);
            }
            _ => panic!("Expected Mul operation"),
        }
    }

    #[test]
    fn test_connect_different_expressions() {
        // Connecting different expressions should add to pending_connects
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        let a = builder.add_const(BabyBear::ONE, "a");
        let b = builder.add_const(BabyBear::from_u64(2), "b");

        builder.connect(a, b);

        // Should have one pending connection
        assert_eq!(builder.pending_connects.len(), 1);
        assert_eq!(builder.pending_connects[0], (a, b));
    }

    #[test]
    fn test_connect_same_expression_no_op() {
        // Connecting an expression to itself should be a no-op
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        let a = builder.add_const(BabyBear::ONE, "a");

        builder.connect(a, a);

        // Should not add to pending_connects
        assert!(builder.pending_connects.is_empty());
    }

    #[test]
    fn test_connect_multiple() {
        // Multiple connections should all be tracked
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        let a = builder.add_const(BabyBear::from_u64(1), "a");
        let b = builder.add_const(BabyBear::from_u64(2), "b");
        let c = builder.add_const(BabyBear::from_u64(3), "c");

        builder.connect(a, b);
        builder.connect(b, c);

        assert_eq!(builder.pending_connects.len(), 2);
        assert_eq!(builder.pending_connects[0], (a, b));
        assert_eq!(builder.pending_connects[1], (b, c));
    }

    #[test]
    fn test_connect_with_operations() {
        // Can connect operation results
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        let a = builder.add_const(BabyBear::ONE, "a");
        let b = builder.add_const(BabyBear::from_u64(2), "b");
        let sum = builder.add_add(a, b, "sum");
        let c = builder.add_public(0, "c");

        builder.connect(sum, c);

        assert_eq!(builder.pending_connects.len(), 1);
        assert_eq!(builder.pending_connects[0], (sum, c));
    }

    #[test]
    fn test_graph_accessor() {
        // graph() should return reference to underlying graph
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        builder.add_const(BabyBear::ONE, "one");

        let graph = builder.graph();
        assert_eq!(graph.nodes().len(), 2); // zero + one
    }

    #[test]
    fn test_pending_connects_accessor() {
        // pending_connects() should return slice of connections
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        let a = builder.add_const(BabyBear::ONE, "a");
        let b = builder.add_const(BabyBear::from_u64(2), "b");

        builder.connect(a, b);

        let connects = builder.pending_connects();
        assert_eq!(connects.len(), 1);
        assert_eq!(connects[0], (a, b));
    }

    #[test]
    #[cfg(debug_assertions)]
    fn test_scope_stack() {
        // Test scope push/pop functionality
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        // Initially no scope
        assert!(builder.current_scope().is_none());

        // Push a scope
        builder.push_scope("test_scope");
        assert_eq!(builder.current_scope(), Some("test_scope"));

        // Push nested scope
        builder.push_scope("nested_scope");
        assert_eq!(builder.current_scope(), Some("nested_scope"));

        // Pop scope
        builder.pop_scope();
        assert_eq!(builder.current_scope(), Some("test_scope"));

        // Pop last scope
        builder.pop_scope();
        assert!(builder.current_scope().is_none());
    }

    #[test]
    #[cfg(debug_assertions)]
    fn test_allocation_log() {
        // Allocation log should track all allocations
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        // Initial log has zero const
        assert_eq!(builder.allocation_log().len(), 0); // Zero is pre-allocated without logging

        // Add a const
        builder.add_const(BabyBear::ONE, "test_const");
        assert_eq!(builder.allocation_log().len(), 1);

        // Add a public
        builder.add_public(0, "test_public");
        assert_eq!(builder.allocation_log().len(), 2);

        // Add an operation
        let a = builder.add_const(BabyBear::from_u64(2), "a");
        let b = builder.add_const(BabyBear::from_u64(3), "b");
        builder.add_add(a, b, "sum");
        assert_eq!(builder.allocation_log().len(), 5); // +3 more (2 consts + 1 add)
    }

    #[test]
    #[cfg(debug_assertions)]
    fn test_list_scopes() {
        // list_scopes should return unique scopes
        let mut builder = ExpressionBuilder::<BabyBear>::new();

        builder.push_scope("scope_a");
        builder.add_const(BabyBear::ONE, "in_a");

        builder.push_scope("scope_b");
        builder.add_const(BabyBear::from_u64(2), "in_b");

        builder.pop_scope();
        builder.add_const(BabyBear::from_u64(3), "in_a_again");

        let scopes = builder.list_scopes();
        assert!(scopes.contains(&"scope_a"));
        assert!(scopes.contains(&"scope_b"));
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn test_list_scopes_release() {
        // In release mode, list_scopes should return empty vec
        let builder = ExpressionBuilder::<BabyBear>::new();
        assert!(builder.list_scopes().is_empty());
    }
}
