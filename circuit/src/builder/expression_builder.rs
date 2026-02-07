//! Expression graph construction and constant pooling.
//!
//! The [`ExpressionBuilder`] is the layer for building arithmetic circuits.
//!
//! It manages a directed acyclic graph (DAG) of expressions where
//! - nodes represent field operations,
//! - edges represent dependencies between expressions.

#[cfg(debug_assertions)]
use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use hashbrown::HashMap;
use p3_field::PrimeCharacteristicRing;

use crate::NonPrimitiveOpType;
use crate::expr::{Expr, ExpressionGraph};
use crate::types::{ExprId, NonPrimitiveOpId};
#[cfg(debug_assertions)]
use crate::{AllocationEntry, AllocationType};

/// Manages expression graph construction, constant pooling, and debug instrumentation.
///
/// The expression builder provides a high-level interface for constructing arithmetic
/// circuits as directed acyclic graphs (DAGs).
///
/// Each node in the graph represents a field operation or a special value
/// (constant, public input, witness hint).
#[derive(Debug)]
pub struct ExpressionBuilder<F> {
    /// The underlying expression graph storage.
    ///
    /// This graph holds all expression nodes in a flat vector, indexed by [`ExprId`].
    ///
    /// The graph is append-only: once an expression is added, it never moves or gets
    /// removed, ensuring stable handles.
    graph: ExpressionGraph<F>,

    /// Constant deduplication pool.
    ///
    /// Maps field values to their unique [`ExprId`] in the graph.
    ///
    /// When a constant is requested via [`add_const`](Self::add_const), this pool is checked first.
    ///
    /// If the value exists, the cached ID is returned immediately, avoiding duplicate nodes.
    const_pool: HashMap<F, ExprId>,

    /// Pending equality constraints.
    ///
    /// Each entry `(a, b)` represents a constraint that expressions `a` and `b` must
    /// evaluate to the same value. These constraints are resolved during the lowering
    /// phase using Union-Find (DSU) to merge witness slots.
    ///
    /// Self-connections `(a, a)` are filtered out to avoid unnecessary work.
    pending_connects: Vec<(ExprId, ExprId)>,

    /// Complete allocation history for debugging.
    ///
    /// Tracks every expression added to the graph, including metadata:
    /// - Allocation type (Const, Add, Mul, etc.)
    /// - Human-readable label
    /// - Expression dependencies
    /// - Scope context
    ///
    /// **Only present in debug builds.**
    #[cfg(debug_assertions)]
    allocation_log: Vec<AllocationEntry>,

    /// Hierarchical scope stack for organizing allocations.
    ///
    /// Users can push/pop named scopes to organize the allocation log into logical
    /// groups (e.g., "fibonacci_step", "mmcs_verify", etc.).
    ///
    /// The current scope is attached to each allocation.
    ///
    /// **Only present in debug builds.**
    #[cfg(debug_assertions)]
    scope_stack: Vec<&'static str>,
}

impl<F> ExpressionBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + Eq + Hash,
{
    /// Creates a new expression builder with zero constant pre-allocated.
    ///
    /// The zero constant is always the first node in the graph, accessible via
    /// [`ExprId::ZERO`].
    ///
    /// # Postconditions
    ///
    /// After construction:
    /// - The graph contains exactly one node: `Expr::Const(F::ZERO)`
    /// - The constant pool contains one entry: `F::ZERO → ExprId::ZERO`
    /// - All other collections (pending_connects, hints_fillers) are empty
    pub fn new() -> Self {
        // Initialize an empty expression graph.
        let mut graph = ExpressionGraph::new();

        // Pre-allocate the zero constant as the first node.
        //
        // This ensures ExprId::ZERO (which is ExprId(0)) always refers to zero.
        let zero_val = F::ZERO;
        let zero_id = graph.add_expr(Expr::Const(zero_val.clone()));

        // Pre-populate the constant pool with zero.
        let const_pool = [(zero_val, zero_id)].into();

        Self {
            graph,
            const_pool,
            pending_connects: Vec::new(),
            #[cfg(debug_assertions)]
            allocation_log: Vec::new(),
            #[cfg(debug_assertions)]
            scope_stack: Vec::new(),
        }
    }

    /// Adds a constant to the expression graph with automatic deduplication.
    ///
    /// If this constant value was previously added, returns the existing [`ExprId`]
    /// handle instead of creating a duplicate node. This ensures the graph contains
    /// at most one node per unique constant value.
    ///
    /// # Arguments
    ///
    /// - `val`: The constant field value to add
    /// - `label`: Human-readable label for debug logging
    ///
    /// # Returns
    ///
    /// An [`ExprId`] handle to the constant. If `val` was seen before, returns the
    /// cached ID. Otherwise, creates a new node and returns its ID.
    ///
    /// # Debug Behavior
    ///
    /// In debug builds, logs the allocation to the allocation log with:
    /// - Type: `AllocationType::Const`
    /// - Label: the provided label
    /// - Dependencies: empty (constants have no dependencies)
    /// - Scope: the current scope from the scope stack
    ///
    /// **Important**: Only new allocations are logged. Returning a cached constant
    /// does not create a new log entry.
    pub fn add_const(&mut self, val: F, label: &'static str) -> ExprId {
        // Check if this constant already exists in the pool.
        if let Some(&cached_id) = self.const_pool.get(&val) {
            // Found a cached entry. Return it immediately without allocating.
            return cached_id;
        }

        // This is a new constant. Add it to the expression graph.
        let expr_id = self.graph.add_expr(Expr::Const(val.clone()));

        // Insert into the constant pool for future lookups.
        self.const_pool.insert(val, expr_id);

        // Log the allocation in debug builds only.
        //
        // In release builds, this entire call compiles to nothing.
        #[cfg(debug_assertions)]
        self.log_alloc(expr_id, label, || (AllocationType::Const, vec![]));
        #[cfg(not(debug_assertions))]
        self.log_alloc(expr_id, label, || ());

        expr_id
    }

    /// Adds a public input expression to the graph.
    ///
    /// Public inputs are values known to both the prover and verifier. They are
    /// identified by their position in the public input vector.
    ///
    /// **Important**: Unlike constants, public inputs are **not** deduplicated. Each
    /// call creates a new expression node, even if the position is the same. This is
    /// intentional: multiple references to the same public input are treated as
    /// independent expressions that happen to read from the same source.
    ///
    /// # Arguments
    ///
    /// - `pos`: Zero-based index into the public input vector
    /// - `label`: Human-readable label for debug logging
    ///
    /// # Returns
    ///
    /// A new [`ExprId`] handle to the public input expression.
    pub fn add_public(&mut self, pos: usize, label: &'static str) -> ExprId {
        // Create a new Public expression node in the graph.
        //
        // The `pos` field indicates which public input slot this expression reads from.
        let expr_id = self.graph.add_expr(Expr::Public(pos));

        // Log the allocation in debug builds.
        //
        // Public inputs have no dependencies (they are leaf nodes in the expression DAG).
        #[cfg(debug_assertions)]
        self.log_alloc(expr_id, label, || (AllocationType::Public, vec![]));
        #[cfg(not(debug_assertions))]
        self.log_alloc(expr_id, label, || ());

        expr_id
    }

    /// Adds an addition expression to the graph.
    ///
    /// Represents the field addition operation: `result = lhs + rhs`.
    ///
    /// # Arguments
    ///
    /// - `lhs`: Left operand expression
    /// - `rhs`: Right operand expression
    /// - `label`: Human-readable label for debug logging
    ///
    /// # Returns
    ///
    /// An [`ExprId`] handle to the addition expression.
    pub fn add_add(&mut self, lhs: ExprId, rhs: ExprId, label: &'static str) -> ExprId {
        self.add_bin_op(
            Expr::Add { lhs, rhs },
            label,
            #[cfg(debug_assertions)]
            AllocationType::Add,
            lhs,
            rhs,
        )
    }

    /// Adds a subtraction expression to the graph.
    ///
    /// Represents the field subtraction operation: `result = lhs - rhs`.
    ///
    /// **Note**: During lowering, subtraction is encoded as an addition row in the ALU table:
    /// `lhs - rhs = result` becomes `result + rhs = lhs` with the `add` selector enabled.
    ///
    /// # Arguments
    ///
    /// - `lhs`: Left operand (minuend)
    /// - `rhs`: Right operand (subtrahend)
    /// - `label`: Human-readable label for debug logging
    ///
    /// # Returns
    ///
    /// An [`ExprId`] handle to the subtraction expression.
    pub fn add_sub(&mut self, lhs: ExprId, rhs: ExprId, label: &'static str) -> ExprId {
        self.add_bin_op(
            Expr::Sub { lhs, rhs },
            label,
            #[cfg(debug_assertions)]
            AllocationType::Sub,
            lhs,
            rhs,
        )
    }

    /// Adds a multiplication expression to the graph.
    ///
    /// Represents the field multiplication operation: `result = lhs * rhs`.
    ///
    /// # Arguments
    ///
    /// - `lhs`: Left operand
    /// - `rhs`: Right operand
    /// - `label`: Human-readable label for debug logging
    ///
    /// # Returns
    ///
    /// An [`ExprId`] handle to the multiplication expression.
    pub fn add_mul(&mut self, lhs: ExprId, rhs: ExprId, label: &'static str) -> ExprId {
        self.add_bin_op(
            Expr::Mul { lhs, rhs },
            label,
            #[cfg(debug_assertions)]
            AllocationType::Mul,
            lhs,
            rhs,
        )
    }

    /// Adds a division expression to the graph.
    ///
    /// Represents the field division operation: `result = lhs / rhs`.
    ///
    /// **Note**: During lowering, division is encoded as a multiplication row in the ALU table:
    /// `lhs / rhs = result` becomes `result * rhs = lhs` with the `mul` selector enabled.
    ///
    /// # Arguments
    ///
    /// - `lhs`: Left operand (dividend)
    /// - `rhs`: Right operand (divisor, must be non-zero)
    /// - `label`: Human-readable label for debug logging
    ///
    /// # Returns
    ///
    /// An [`ExprId`] handle to the division expression.
    pub fn add_div(&mut self, lhs: ExprId, rhs: ExprId, label: &'static str) -> ExprId {
        self.add_bin_op(
            Expr::Div { lhs, rhs },
            label,
            #[cfg(debug_assertions)]
            AllocationType::Div,
            lhs,
            rhs,
        )
    }

    /// Adds a non-primitive output expression to the graph.
    ///
    /// This expression represents a value produced by a non-primitive operation.
    /// The `call` parameter is the `ExprId` of the `NonPrimitiveCall` node, making
    /// the dependency explicit in the DAG structure.
    pub fn add_non_primitive_output(
        &mut self,
        call: ExprId,
        output_idx: u32,
        label: &'static str,
    ) -> ExprId {
        let expr_id = self
            .graph
            .add_expr(Expr::NonPrimitiveOutput { call, output_idx });

        #[cfg(debug_assertions)]
        self.log_alloc(expr_id, label, || {
            (AllocationType::NonPrimitiveOutput, vec![vec![call]])
        });
        #[cfg(not(debug_assertions))]
        self.log_alloc(expr_id, label, || ());

        expr_id
    }

    /// Adds a non-primitive call anchor expression to the graph.
    ///
    /// This expression has no witness value, but provides an explicit point in the expression DAG
    /// for the lowerer to emit the non-primitive op in the correct execution order.
    ///
    /// The `inputs` parameter contains all input expressions (flattened), making dependencies
    /// explicit in the DAG structure. For stateful ops with chaining (e.g., `in_ctl=false`),
    /// `inputs` may be empty since chained values are not in the witness table.
    #[allow(unused)]
    pub fn add_non_primitive_call(
        &mut self,
        op_id: NonPrimitiveOpId,
        op_type: NonPrimitiveOpType,
        inputs: Vec<ExprId>,
        label: &'static str,
    ) -> ExprId {
        #[cfg(debug_assertions)]
        let dependencies: Vec<Vec<ExprId>> = inputs.iter().map(|&id| vec![id]).collect();

        let expr_id = self
            .graph
            .add_expr(Expr::NonPrimitiveCall { op_id, inputs });

        #[cfg(debug_assertions)]
        self.log_alloc(expr_id, label, || {
            (AllocationType::NonPrimitiveOp(op_type), dependencies)
        });
        #[cfg(not(debug_assertions))]
        self.log_alloc(expr_id, label, || ());

        expr_id
    }

    /// Internal helper for adding binary operations.
    ///
    /// # Arguments
    ///
    /// - `expr`: The binary expression variant to add (Add/Sub/Mul/Div)
    /// - `label`: Human-readable label for debug logging
    /// - `alloc_type`: Allocation type for debug logging (only exists in debug builds)
    /// - `lhs`: Left operand dependency
    /// - `rhs`: Right operand dependency
    ///
    /// # Returns
    ///
    /// An [`ExprId`] handle to the newly created expression.
    #[inline(always)]
    #[allow(unused_variables)]
    fn add_bin_op(
        &mut self,
        expr: Expr<F>,
        label: &'static str,
        #[cfg(debug_assertions)] alloc_type: AllocationType,
        lhs: ExprId,
        rhs: ExprId,
    ) -> ExprId {
        // Add the expression to the graph.
        let expr_id = self.graph.add_expr(expr);

        // Log the allocation with dependencies.
        //
        // Binary operations have two dependencies: one for lhs, one for rhs.
        #[cfg(debug_assertions)]
        self.log_alloc(expr_id, label, || (alloc_type, vec![vec![lhs], vec![rhs]]));
        #[cfg(not(debug_assertions))]
        self.log_alloc(expr_id, label, || ());

        expr_id
    }

    /// Enforces equality between two expressions.
    ///
    /// Adds a pending constraint that expressions `a` and `b` must evaluate to
    /// the same value. During the lowering phase, these constraints are resolved
    /// using Union-Find (DSU) to merge the witness slots for `a` and `b`.
    ///
    /// # Arguments
    ///
    /// - `a`: First expression
    /// - `b`: Second expression
    ///
    /// # Self-Connection Optimization
    ///
    /// If `a == b` (same expression), this is a no-op. No constraint is added
    /// because an expression is trivially equal to itself.
    ///
    /// # Constraint Resolution
    ///
    /// Constraints are not resolved immediately. They are stored in the
    /// `pending_connects` vector and processed during circuit compilation.
    pub fn connect(&mut self, a: ExprId, b: ExprId) {
        // Skip self-connections as they are trivially satisfied.
        if a != b {
            self.pending_connects.push((a, b));
        }
    }

    /// Returns an immutable reference to the underlying expression graph.
    ///
    /// The graph provides access to all expression nodes and their relationships.
    ///
    /// # Returns
    ///
    /// A reference to the [`ExpressionGraph`] containing all expressions.
    #[inline]
    pub const fn graph(&self) -> &ExpressionGraph<F> {
        &self.graph
    }

    /// Returns a slice of pending equality constraints.
    ///
    /// Each constraint `(a, b)` represents an assertion that expressions `a` and `b`
    /// must evaluate to the same value.
    ///
    /// # Returns
    ///
    /// A slice of `(ExprId, ExprId)` pairs representing pending connections.
    #[inline]
    pub fn pending_connects(&self) -> &[(ExprId, ExprId)] {
        &self.pending_connects
    }

    /// Centralized logging helper for debug builds.
    ///
    /// # Arguments
    ///
    /// - `id`: The expression ID being logged
    /// - `label`: Human-readable label
    /// - `info_fn`: Closure that produces allocation metadata **only when needed**
    #[cfg(debug_assertions)]
    #[inline(always)]
    fn log_alloc<Info>(&mut self, id: ExprId, label: &'static str, info_fn: Info)
    where
        Info: FnOnce() -> (AllocationType, Vec<Vec<ExprId>>),
    {
        // Execute the closure to get allocation metadata.
        let (alloc_type, dependencies) = info_fn();

        // Capture the current scope from the stack.
        let scope = self.scope_stack.last().copied();

        // Add an entry to the allocation log.
        self.allocation_log.push(AllocationEntry {
            expr_id: id,
            alloc_type,
            label,
            dependencies,
            scope,
        });
    }

    /// No-op logging helper for release builds.
    #[cfg(not(debug_assertions))]
    #[inline(always)]
    #[allow(clippy::needless_pass_by_ref_mut)]
    fn log_alloc<Info>(&mut self, _id: ExprId, _label: &'static str, _info_fn: Info)
    where
        Info: FnOnce(),
    {
        // Intentionally empty - compiles to nothing in release builds.
    }

    /// Logs a non-primitive operation allocation (debug builds only).
    ///
    /// Non-primitive operations (MMCS, FRI, Poseidon2, etc.) are not part of the
    /// standard expression types but need to be tracked in the allocation log.
    ///
    /// # Arguments
    ///
    /// - `op_id`: The non-primitive operation ID
    /// - `op_type`: The type of operation (e.g., `NonPrimitiveOpType::MmcsVerify`)
    /// - `input_deps`: Input expression dependencies for this operation
    /// - `output_deps`: Output expression dependencies for this operation
    /// - `label`: Human-readable label
    #[cfg(debug_assertions)]
    pub fn log_non_primitive_op(
        &mut self,
        op_id: crate::types::NonPrimitiveOpId,
        op_type: crate::op::NonPrimitiveOpType,
        input_deps: Vec<Vec<ExprId>>,
        output_deps: Vec<Vec<ExprId>>,
        label: &'static str,
    ) {
        // Capture the current scope.
        let scope = self.scope_stack.last().copied();

        // Combine inputs and outputs for dependency tracking.
        // Use a separator to distinguish inputs from outputs in the log.
        let mut dependencies = input_deps;
        dependencies.extend(output_deps);

        // Add to allocation log.
        //
        // Non-primitive operations are stored with a special allocation type
        // that includes the operation variant.
        self.allocation_log.push(AllocationEntry {
            expr_id: ExprId(op_id.0),
            alloc_type: AllocationType::NonPrimitiveOp(op_type),
            label,
            dependencies,
            scope,
        });
    }

    /// Pushes a new scope onto the scope stack (debug builds only).
    ///
    /// Scopes provide hierarchical organization for the allocation log. Subsequent
    /// allocations will be tagged with this scope until it is popped.
    ///
    /// # Arguments
    ///
    /// - `scope`: Human-readable scope name
    #[allow(unused_variables)]
    #[allow(clippy::missing_const_for_fn)]
    pub fn push_scope(&mut self, scope: &'static str) {
        #[cfg(debug_assertions)]
        self.scope_stack.push(scope);
    }

    /// Pops the current scope from the scope stack (debug builds only).
    ///
    /// # Panics
    ///
    /// Panics if the scope stack is empty (mismatched push/pop).
    #[allow(clippy::missing_const_for_fn)]
    pub fn pop_scope(&mut self) {
        #[cfg(debug_assertions)]
        self.scope_stack.pop();
    }

    /// Returns the current scope (debug builds only).
    ///
    /// Returns the name of the most recently pushed scope, or `None` if no scope is active.
    ///
    /// # Returns
    ///
    /// - `Some(&'static str)` - The name of the current scope
    /// - `None` - No active scope
    #[cfg(debug_assertions)]
    pub fn current_scope(&self) -> Option<&'static str> {
        self.scope_stack.last().copied()
    }

    /// Returns a reference to the allocation log (debug builds only).
    ///
    /// Provides read-only access to all allocation entries recorded during circuit
    /// construction. Useful for testing and verifying allocation behavior.
    ///
    /// # Returns
    ///
    /// A slice of [`AllocationEntry`] containing all recorded allocations.
    #[cfg(debug_assertions)]
    pub fn allocation_log(&self) -> &[AllocationEntry] {
        &self.allocation_log
    }

    /// Dumps the allocation log for specific `ExprId`s.
    ///
    /// If debug_assertions are not enabled, this is a no-op.
    #[allow(clippy::missing_const_for_fn)]
    #[allow(unused_variables)]
    pub fn dump_expr_ids(&self, expr_ids: &[ExprId]) {
        #[cfg(debug_assertions)]
        crate::alloc_entry::dump_expr_ids(&self.allocation_log, expr_ids);
    }

    /// Dumps the allocation log to stdout (debug builds only).
    ///
    /// Prints a formatted view of all allocations, including their types, labels,
    /// dependencies, and scopes. Useful for debugging circuit construction.
    ///
    /// # Output
    ///
    /// In debug builds, outputs a detailed allocation report. In release builds,
    /// this method does nothing.
    #[allow(clippy::missing_const_for_fn)]
    pub fn dump_allocation_log(&self) {
        #[cfg(debug_assertions)]
        crate::alloc_entry::dump_allocation_log(&self.allocation_log);
    }

    /// Lists all unique scopes in the allocation log.
    ///
    /// Returns a vector of scope names that appear in the allocation log,
    /// with duplicates removed.
    ///
    /// # Returns
    ///
    /// - **Debug builds**: Vector of unique scope names
    /// - **Release builds**: Empty vector (no scopes tracked)
    #[allow(clippy::missing_const_for_fn)]
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
    F: Clone + PrimeCharacteristicRing + Eq + Hash,
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
        let mut expected_const_pool = HashMap::new();
        expected_const_pool.insert(BabyBear::ZERO, ExprId::ZERO);
        assert_eq!(builder.const_pool, expected_const_pool);

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
