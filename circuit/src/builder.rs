use alloc::vec::Vec;
use alloc::{format, vec};

use hashbrown::{HashMap, HashSet};
use p3_field::PrimeCharacteristicRing;
use thiserror::Error;

use crate::circuit::Circuit;
use crate::expr::{Expr, ExpressionGraph};
use crate::op::{NonPrimitiveOp, NonPrimitiveOpConfig, NonPrimitiveOpType, Prim};
use crate::ops::MmcsVerifyConfig;
use crate::types::{ExprId, NonPrimitiveOpId, WitnessAllocator, WitnessId};
#[cfg(debug_assertions)]
use crate::{AllocationEntry, AllocationType};

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
/// - Complex operations (like Mmcs tree verification)
///
/// Call `.build()` to compile into an immutable `Circuit<F>` specification.
pub struct CircuitBuilder<F> {
    /// Expression graph for building the DAG
    expressions: ExpressionGraph<F>,
    /// Witness index allocator
    witness_alloc: WitnessAllocator,
    /// Track public input positions
    pub public_input_count: usize,
    /// Equality constraints to enforce at lowering
    pending_connects: Vec<(ExprId, ExprId)>,
    /// Non-primitive operations (complex constraints that don't produce ExprIds)
    non_primitive_ops: Vec<NonPrimitiveOperationData>, // (op_id, op_type, witness_exprs)
    /// Builder-level constant pool: value -> unique Const ExprId
    const_pool: HashMap<F, ExprId>,

    /// Enabled non-primitive operation types with their respective configuration
    enabled_ops: HashMap<NonPrimitiveOpType, NonPrimitiveOpConfig>,

    /// Debug log of all allocations
    #[cfg(debug_assertions)]
    allocation_log: Vec<AllocationEntry>,

    /// Stack of active scopes for organizing allocations
    #[cfg(debug_assertions)]
    scope_stack: Vec<&'static str>,
}

/// The non-primitive operation id, type, the expressions represeting its inputs
type NonPrimitiveOperationData = (NonPrimitiveOpId, NonPrimitiveOpType, Vec<Vec<ExprId>>);

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

    /// Non-primitive operation rejected by the active policy/profile.
    #[error("Operation {op:?} is not allowed by the current profile")]
    OpNotAllowed { op: NonPrimitiveOpType },

    /// Non-primitive operation is recognized but not implemented in lowering.
    #[error("Operation {op:?} is not implemented in lowering")]
    UnsupportedNonPrimitiveOp { op: NonPrimitiveOpType },

    /// Mismatched non-primitive operation configuration
    #[error("Invalid configuration for operation {op:?}")]
    InvalidNonPrimitiveOpConfiguration { op: NonPrimitiveOpType },
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
            enabled_ops: HashMap::new(), // All non-primitive ops are disabled by default
            #[cfg(debug_assertions)]
            allocation_log: Vec::new(),
            #[cfg(debug_assertions)]
            scope_stack: Vec::new(),
        }
    }

    /// Enable a non-primitive operation type on this builder.
    pub fn enable_op(&mut self, op: NonPrimitiveOpType, cfg: NonPrimitiveOpConfig) {
        self.enabled_ops.insert(op, cfg);
    }

    /// Enable Mmcs verification operations.
    pub fn enable_mmcs(&mut self, mmcs_config: &MmcsVerifyConfig) {
        self.enable_op(
            NonPrimitiveOpType::MmcsVerify,
            NonPrimitiveOpConfig::MmcsVerifyConfig(mmcs_config.clone()),
        );
    }

    /// Enable FRI verification operations.
    pub fn enable_fri(&mut self) {
        // TODO: Add FRI ops when they land
    }

    /// Add a public input to the circuit.
    ///
    /// Cost: 1 row in Public table + 1 row in witness table.
    pub fn add_public_input(&mut self) -> ExprId {
        self.alloc_public_input("")
    }

    /// Allocate a public input with a descriptive label.
    ///
    /// The label is logged in debug builds for easier debugging of public input ordering.
    ///
    /// Cost: 1 row in Public table + 1 row in witness table.
    ///
    /// # Parameters
    /// - `label`: Description of what this public input represents
    ///
    /// # Returns
    /// The allocated `ExprId` for this public input
    #[allow(unused_variables)]
    pub fn alloc_public_input(&mut self, label: &'static str) -> ExprId {
        let public_pos = self.public_input_count;
        self.public_input_count += 1;

        let public_expr = Expr::Public(public_pos);
        let expr_id = self.expressions.add_expr(public_expr);

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

    /// Allocate multiple public inputs with a descriptive label.
    ///
    /// # Parameters
    /// - `count`: Number of public inputs to allocate
    /// - `label`: Description of what these inputs represent
    pub fn alloc_public_inputs(&mut self, count: usize, label: &'static str) -> Vec<ExprId> {
        (0..count).map(|_| self.alloc_public_input(label)).collect()
    }

    /// Allocate a fixed-size array of public inputs with a descriptive label.
    pub fn alloc_public_input_array<const N: usize>(&mut self, label: &'static str) -> [ExprId; N] {
        core::array::from_fn(|_| self.alloc_public_input(label))
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

    /// Push a new scope onto the scope stack.
    ///
    /// All subsequent allocations will be tagged with this scope until
    /// `pop_scope` is called. Scopes can be nested.
    ///
    /// If debug_assertions are not enabled, this is a no-op.
    ///
    /// # Example
    /// ```ignore
    /// builder.push_scope("verify_fri");
    /// builder.push_scope("open_input");
    /// // ... build `open_input` sub-circuit of `verify_fri` sub-circuit ...
    /// builder.pop_scope(); // return to `verify_fri` scope
    /// builder.pop_scope(); // return to main scope
    /// ```
    #[allow(unused_variables)]
    pub fn push_scope(&mut self, scope: &'static str) {
        #[cfg(debug_assertions)]
        self.scope_stack.push(scope);
    }

    /// Pop the current scope from the scope stack.
    ///
    /// If debug_assertions are not enabled, this is a no-op.
    pub fn pop_scope(&mut self) {
        #[cfg(debug_assertions)]
        {
            self.scope_stack.pop();
        }
    }

    /// Get the current scope (if any).
    ///
    /// Returns the most recently pushed scope that hasn't been popped.
    #[cfg(debug_assertions)]
    fn current_scope(&self) -> Option<&'static str> {
        self.scope_stack.last().copied()
    }

    /// Add a constant to the circuit (deduplicated).
    ///
    /// If this value was previously added, returns the original ExprId.
    /// Cost: 1 row in Const table + 1 row in witness table (only for new constants).
    pub fn add_const(&mut self, val: F) -> ExprId {
        self.alloc_const(val, "")
    }

    /// Allocate a constant with a descriptive label.
    ///
    /// Cost: 1 row in Const table + 1 row in witness table (only for new constants).
    #[allow(unused_variables)]
    pub fn alloc_const(&mut self, val: F, label: &'static str) -> ExprId {
        #[cfg(debug_assertions)]
        let current_scope = self.current_scope();

        *self.const_pool.entry(val).or_insert_with_key(|k| {
            let expr_id = self.expressions.add_expr(Expr::Const(k.clone()));
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

    /// Add two expressions.
    ///
    /// Cost: 1 row in Add table + 1 row in witness table.
    pub fn add(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.alloc_add(lhs, rhs, "")
    }

    /// Add two expressions with a descriptive label.
    ///
    /// Cost: 1 row in Add table + 1 row in witness table.
    #[allow(unused_variables)]
    pub fn alloc_add(&mut self, lhs: ExprId, rhs: ExprId, label: &'static str) -> ExprId {
        let add_expr = Expr::Add { lhs, rhs };
        let expr_id = self.expressions.add_expr(add_expr);

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

    /// Subtract two expressions.
    ///
    /// Cost: 1 row in Add table + 1 row in witness table (encoded as result + rhs = lhs).
    pub fn sub(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.alloc_sub(lhs, rhs, "")
    }

    /// Subtract two expressions with a descriptive label.
    ///
    /// Cost: 1 row in Add table + 1 row in witness table.
    #[allow(unused_variables)]
    pub fn alloc_sub(&mut self, lhs: ExprId, rhs: ExprId, label: &'static str) -> ExprId {
        let sub_expr = Expr::Sub { lhs, rhs };
        let expr_id = self.expressions.add_expr(sub_expr);

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

    /// Multiply two expressions.
    ///
    /// Cost: 1 row in Mul table + 1 row in witness table.
    pub fn mul(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.alloc_mul(lhs, rhs, "")
    }

    /// Multiply two expressions with a descriptive label.
    ///
    /// Cost: 1 row in Mul table + 1 row in witness table.
    #[allow(unused_variables)]
    pub fn alloc_mul(&mut self, lhs: ExprId, rhs: ExprId, label: &'static str) -> ExprId {
        let mul_expr = Expr::Mul { lhs, rhs };
        let expr_id = self.expressions.add_expr(mul_expr);

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

    /// Divide two expressions.
    ///
    /// Cost: 1 row in Mul table + 1 row in witness table (encoded as rhs * out = lhs).
    pub fn div(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.alloc_div(lhs, rhs, "")
    }

    /// Divide two expressions with a descriptive label.
    ///
    /// Cost: 1 row in Mul table + 1 row in witness table.
    #[allow(unused_variables)]
    pub fn alloc_div(&mut self, lhs: ExprId, rhs: ExprId, label: &'static str) -> ExprId {
        let div_expr = Expr::Div { lhs, rhs };
        let expr_id = self.expressions.add_expr(div_expr);

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

    /// Assert that an expression equals zero by connecting it to Const(0).
    ///
    /// Cost: Free in proving (implemented via connect).
    pub fn assert_zero(&mut self, expr: ExprId) {
        self.connect(expr, ExprId::ZERO);
    }

    /// Assert that an expression is boolean: b ∈ {0,1}.
    ///
    /// Encodes the constraint b · (b − 1) = 0 via `assert_zero`.
    /// Cost: 1 mul + 1 add.
    pub fn assert_bool(&mut self, b: ExprId) {
        let one = self.add_const(F::ONE);
        let b_minus_one = self.sub(b, one);
        let prod = self.mul(b, b_minus_one);
        self.assert_zero(prod);
    }

    /// Select between two values using selector `b`:
    /// result = s + b · (t − s).
    ///
    /// When `b` ∈ {0,1}, this returns `t` if b = 1, else `s` if b = 0.
    /// Call `assert_bool(b)` beforehand if you need booleanity enforced.
    /// Cost: 1 mul + 2 add.
    pub fn select(&mut self, b: ExprId, t: ExprId, s: ExprId) -> ExprId {
        let t_minus_s = self.sub(t, s);
        let scaled = self.mul(b, t_minus_s);
        self.add(s, scaled)
    }

    /// Connect two expressions, enforcing a == b (by aliasing outputs).
    ///
    /// Cost: Free in proving (handled by IR optimization layer via witness slot aliasing).
    pub fn connect(&mut self, a: ExprId, b: ExprId) {
        if a != b {
            self.pending_connects.push((a, b));
        }
    }

    /// Exponentiate a base expression to a power of 2 (i.e. base^(2^power_log)), by squaring repeatedly.
    pub fn exp_power_of_2(&mut self, base: ExprId, power_log: usize) -> ExprId {
        let mut res = base;
        for _ in 0..power_log {
            let square = self.mul(res, res);
            res = square;
        }
        res
    }

    /// Helper to push a non-primitive op. Returns op id.
    #[allow(unused_variables)]
    pub(crate) fn push_non_primitive_op(
        &mut self,
        op_type: NonPrimitiveOpType,
        witness_exprs: Vec<Vec<ExprId>>,
        label: &'static str,
    ) -> NonPrimitiveOpId {
        let op_id = NonPrimitiveOpId(self.non_primitive_ops.len() as u32);

        #[cfg(debug_assertions)]
        {
            // For non-primitive ops, we don't have a single ExprId, so we use a placeholder
            // The dependencies are the witness expressions that this op depends on
            // TODO: Can we find something better than the `op_id`?
            self.allocation_log.push(AllocationEntry {
                expr_id: ExprId(op_id.0),
                alloc_type: AllocationType::NonPrimitiveOp(op_type.clone()),
                label,
                dependencies: witness_exprs.clone(),
                scope: self.current_scope(),
            });
        }

        self.non_primitive_ops.push((op_id, op_type, witness_exprs));
        op_id
    }

    /// Check whether an op type is enabled on this builder.
    fn is_op_enabled(&self, op: &NonPrimitiveOpType) -> bool {
        self.enabled_ops.contains_key(op)
    }

    pub(crate) fn ensure_op_enabled(
        &self,
        op: NonPrimitiveOpType,
    ) -> Result<(), CircuitBuilderError> {
        if !self.is_op_enabled(&op) {
            return Err(CircuitBuilderError::OpNotAllowed { op });
        }
        Ok(())
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
    #[allow(clippy::type_complexity)]
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
        circuit.enabled_ops = self.enabled_ops;

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
        let in_connect: HashSet<usize> = self
            .pending_connects
            .iter()
            .flat_map(|(a, b)| [a.0 as usize, b.0 as usize])
            .collect();

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
            let config = self.enabled_ops.get(op_type);
            match op_type {
                NonPrimitiveOpType::MmcsVerify => {
                    let config = match config {
                        Some(NonPrimitiveOpConfig::MmcsVerifyConfig(config)) => Ok(config),
                        _ => Err(CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                            op: op_type.clone(),
                        }),
                    }?;
                    if !config.number_of_inputs().contains(&witness_exprs.len()) {
                        return Err(CircuitBuilderError::NonPrimitiveOpArity {
                            op: "MmcsVerify",
                            expected: config.number_of_inputs().end, // TODO: Make this a string or change the error.
                            got: witness_exprs.len(),
                        });
                    }

                    let directions_len = witness_exprs[witness_exprs.len() - 2].len();
                    if !config.directions_size().contains(&directions_len) {
                        return Err(CircuitBuilderError::NonPrimitiveOpArity {
                            op: "MmcsVerify",
                            expected: config.directions_size().end, //TODO: Change the error field to string?
                            got: witness_exprs[1].len(),
                        });
                    }

                    // The length must be directions_len + 2: directions_len leaves + direction + root
                    if witness_exprs.len() != directions_len + 2 {
                        return Err(CircuitBuilderError::NonPrimitiveOpArity {
                            op: "MmcsVerify",
                            expected: directions_len + 2,
                            got: witness_exprs.len(),
                        });
                    }

                    // The leaves are represented as the first witness_exprs.len() - 2 elements
                    // Each leave should be either a vector of length config.ext_field_digest_elems,
                    // or an empty vec, meaning that there's no matrix in the Mmcs scheme at that level.
                    let leaves_expr = &witness_exprs[..directions_len];
                    if !leaves_expr
                        .iter()
                        .all(|leaf| leaf.len() == config.ext_field_digest_elems || leaf.is_empty())
                    {
                        // TODO: Add another error or make this one more flexible
                        return Err(CircuitBuilderError::NonPrimitiveOpArity {
                            op: "MmcsVerify",
                            expected: config.ext_field_digest_elems,
                            got: witness_exprs[0].len(),
                        });
                    }
                    let leaves_widx: Vec<Vec<WitnessId>> = leaves_expr
                        .iter()
                        .map(|leaf| {
                            leaf.iter()
                                .map(|expr_id| {
                                    Self::get_witness_id(
                                        expr_to_widx,
                                        *expr_id,
                                        "MmcsVerify leaf input",
                                    )
                                })
                                .collect::<Result<Vec<WitnessId>, _>>()
                        })
                        .collect::<Result<_, _>>()?;

                    // directions are witnesses at position directions_len
                    let directions_widx = witness_exprs[directions_len]
                        .iter()
                        .map(|expr_id| {
                            Self::get_witness_id(expr_to_widx, *expr_id, "MmcsVerify index input")
                        })
                        .collect::<Result<_, _>>()?;

                    let root_widx = witness_exprs[directions_len + 1]
                        .iter()
                        .map(|expr_id| {
                            Self::get_witness_id(expr_to_widx, *expr_id, "MmcsVerify root input")
                        })
                        .collect::<Result<_, _>>()?;

                    lowered_ops.push(NonPrimitiveOp::MmcsVerify {
                        leaves: leaves_widx,
                        directions: directions_widx,
                        root: root_widx,
                    });
                }
                NonPrimitiveOpType::FriVerify => {
                    todo!() // TODO: Add FRIVerify when it lands
                }
                NonPrimitiveOpType::HashAbsorb { reset } => {
                    let inputs = witness_exprs
                        .iter()
                        .map(|expr| Self::get_witness_id(expr_to_widx, expr[0], "HashAbsorb input"))
                        .collect::<Result<_, _>>()?;

                    lowered_ops.push(NonPrimitiveOp::HashAbsorb {
                        reset_flag: *reset,
                        inputs,
                    });
                }
                NonPrimitiveOpType::HashSqueeze => {
                    let outputs = witness_exprs
                        .iter()
                        .map(|expr| {
                            Self::get_witness_id(expr_to_widx, expr[0], "HashSqueeze output")
                        })
                        .collect::<Result<_, _>>()?;

                    lowered_ops.push(NonPrimitiveOp::HashSqueeze { outputs });
                } // Add more variants here as needed
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
    use crate::op::NonPrimitiveOpType;
    use crate::{CircuitError, MmcsOps, NonPrimitiveOp};

    #[cfg(test)]
    mod proptests {
        use proptest::prelude::*;

        use super::*;

        // Strategy for generating valid field elements
        fn field_element() -> impl Strategy<Value = BabyBear> {
            any::<u64>().prop_map(BabyBear::from_u64)
        }

        // Strategy for generating lists of ExprId connect relations
        fn connections(max_id: u32) -> impl Strategy<Value = Vec<(ExprId, ExprId)>> {
            prop::collection::vec((0..max_id, 0..max_id), 0..20).prop_map(|pairs| {
                pairs
                    .into_iter()
                    .map(|(a, b)| (ExprId(a), ExprId(b)))
                    .collect()
            })
        }

        proptest! {
            #[test]
            fn dsu_find_idempotent(connects in connections(50)) {
                let mut parents = build_connect_dsu(&connects);
                let test_ids: Vec<usize> = (0..50).collect();

                for &id in &test_ids {
                    let root1 = dsu_find(&mut parents, id);
                    let root2 = dsu_find(&mut parents, id);
                    prop_assert_eq!(root1, root2, "dsu_find should be idempotent");
                }
            }

            #[test]
            fn dsu_union_transitivity(connects in connections(30)) {
                let mut parents = build_connect_dsu(&connects);

                // Check transitivity: if a~b and b~c then a~c
                for (a, b) in &connects {
                    let ra = dsu_find(&mut parents, a.0 as usize);
                    let rb = dsu_find(&mut parents, b.0 as usize);
                    prop_assert_eq!(ra, rb, "connected nodes should have same root");
                }
            }

            #[test]
            fn dsu_union_commutative(a in 0u32..100, b in 0u32..100) {
                let mut parents1 = HashMap::new();
                let mut parents2 = HashMap::new();

                dsu_union(&mut parents1, a as usize, b as usize);
                dsu_union(&mut parents2, b as usize, a as usize);

                let r1a = dsu_find(&mut parents1, a as usize);
                let r1b = dsu_find(&mut parents1, b as usize);
                let r2a = dsu_find(&mut parents2, a as usize);
                let r2b = dsu_find(&mut parents2, b as usize);

                prop_assert_eq!(r1a, r1b, "union should connect a and b");
                prop_assert_eq!(r2a, r2b, "union should connect b and a");
            }

            #[test]
            fn field_add_commutative(a in field_element(), b in field_element()) {
                let mut builder1 = CircuitBuilder::<BabyBear>::new();
                let ca = builder1.add_const(a);
                let cb = builder1.add_const(b);
                let sum1 = builder1.add(ca, cb);

                let mut builder2 = CircuitBuilder::<BabyBear>::new();
                let ca2 = builder2.add_const(a);
                let cb2 = builder2.add_const(b);
                let sum2 = builder2.add(cb2, ca2);

                let circuit1 = builder1.build().unwrap();
                let circuit2 = builder2.build().unwrap();

                let  runner1 = circuit1.runner();
                let  runner2 = circuit2.runner();

                let traces1 = runner1.run().unwrap();
                let traces2 = runner2.run().unwrap();

                // Get the computed sums
                prop_assert_eq!(
                    traces1.witness_trace.values[sum1.0 as usize],
                    traces2.witness_trace.values[sum2.0 as usize],
                    "addition should be commutative"
                );
            }

            #[test]
            fn field_mul_commutative(a in field_element(), b in field_element()) {
                let mut builder1 = CircuitBuilder::<BabyBear>::new();
                let ca = builder1.add_const(a);
                let cb = builder1.add_const(b);
                let prod1 = builder1.mul(ca, cb);

                let mut builder2 = CircuitBuilder::<BabyBear>::new();
                let ca2 = builder2.add_const(a);
                let cb2 = builder2.add_const(b);
                let prod2 = builder2.mul(cb2, ca2);

                let circuit1 = builder1.build().unwrap();
                let circuit2 = builder2.build().unwrap();

                let  runner1 = circuit1.runner();
                let  runner2 = circuit2.runner();

                let traces1 = runner1.run().unwrap();
                let traces2 = runner2.run().unwrap();

                prop_assert_eq!(
                    traces1.witness_trace.values[prod1.0 as usize],
                    traces2.witness_trace.values[prod2.0 as usize],
                    "multiplication should be commutative"
                );
            }

            #[test]
            fn field_add_identity(a in field_element()) {
                let mut builder = CircuitBuilder::<BabyBear>::new();
                let ca = builder.add_const(a);
                let zero = builder.add_const(BabyBear::ZERO);
                let result = builder.add(ca, zero);

                let circuit = builder.build().unwrap();
                let  runner = circuit.runner();
                let traces = runner.run().unwrap();

                prop_assert_eq!(
                    traces.witness_trace.values[result.0 as usize],
                    a,
                    "a + 0 = a"
                );
            }

            #[test]
            fn field_mul_identity(a in field_element()) {
                let mut builder = CircuitBuilder::<BabyBear>::new();
                let ca = builder.add_const(a);
                let one = builder.add_const(BabyBear::ONE);
                let result = builder.mul(ca, one);

                let circuit = builder.build().unwrap();
                let  runner = circuit.runner();
                let traces = runner.run().unwrap();

                prop_assert_eq!(
                    traces.witness_trace.values[result.0 as usize],
                    a,
                    "a * 1 = a"
                );
            }

            #[test]
            fn field_add_sub(a in field_element(), b in field_element()) {
                let mut builder = CircuitBuilder::<BabyBear>::new();
                let ca = builder.add_const(a);
                let cb = builder.add_const(b);
                let diff = builder.sub(ca, cb);
                let result = builder.add(diff, cb);

                let circuit = builder.build().unwrap();
                let  runner = circuit.runner();
                let traces = runner.run().unwrap();

                prop_assert_eq!(
                    traces.witness_trace.values[result.0 as usize],
                    a,
                    "(a - b) + b = a"
                );
            }

            #[test]
            fn field_mul_div(a in field_element(), b in field_element().prop_filter("b must be non-zero", |&x| x != BabyBear::ZERO)) {
                let mut builder = CircuitBuilder::<BabyBear>::new();
                let ca = builder.add_const(a);
                let cb = builder.add_const(b);
                let quot = builder.div(ca, cb);
                let result = builder.mul(quot, cb);

                let circuit = builder.build().unwrap();
                let  runner = circuit.runner();
                let traces = runner.run().unwrap();

                prop_assert_eq!(
                    traces.witness_trace.values[result.0 as usize],
                    a,
                    "(a / b) * b = a"
                );
            }

            #[test]
            fn constant_deduplication(a in field_element()) {
                let mut builder = CircuitBuilder::<BabyBear>::new();
                let c1 = builder.add_const(a);
                let c2 = builder.add_const(a);
                let c3 = builder.add_const(a);

                prop_assert_eq!(c1, c2, "same constant should return same ExprId");
                prop_assert_eq!(c2, c3, "same constant should return same ExprId");
            }

            #[test]
            fn constant_uniqueness(a in field_element(), b in field_element()) {
                prop_assume!(a != b);
                let mut builder = CircuitBuilder::<BabyBear>::new();
                let c1 = builder.add_const(a);
                let c2 = builder.add_const(b);

                prop_assert_ne!(c1, c2, "different constants should return different ExprIds");
            }

            #[test]
            fn public_input_uniqueness(count in 1usize..50) {
                let mut builder = CircuitBuilder::<BabyBear>::new();
                let mut inputs = Vec::new();

                for _ in 0..count {
                    inputs.push(builder.add_public_input());
                }

                // All ExprIds should be unique
                let mut seen = HashSet::new();
                for input in inputs {
                    prop_assert!(seen.insert(input), "each public input should have unique ExprId");
                }

                prop_assert_eq!(builder.public_input_count, count, "public input count should match");
            }

            #[test]
            fn connect_self_is_noop(count in 1usize..10) {
                let mut builder = CircuitBuilder::<BabyBear>::new();

                for _ in 0..count {
                    let input = builder.add_const(BabyBear::ONE);
                    builder.connect(input, input); // Self-connect
                }

                let circuit = builder.build().unwrap();

                // Only a single witness is allocated, on top of the zero slot.
                assert_eq!(circuit.witness_count, 2);

                let runner = circuit.runner();

                runner.run().unwrap();
            }
        }
    }

    #[test]
    fn test_circuit_basic_api() {
        let mut builder = CircuitBuilder::new();

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
        let mut builder = CircuitBuilder::new();

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
        runner.run().unwrap();
    }

    #[test]
    fn test_connect_conflict() {
        let mut builder = CircuitBuilder::new();

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
        let mut builder = CircuitBuilder::new();

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

    #[test]
    fn test_mmcs_config_blocks_when_disabled() {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let mmcs_config = MmcsVerifyConfig::mock_config();

        let leaves = (0..mmcs_config.ext_field_digest_elems)
            .map(|_| vec![builder.add_public_input()])
            .collect::<Vec<Vec<ExprId>>>();
        let directions = (0..mmcs_config.max_tree_height)
            .map(|_| builder.add_public_input())
            .collect::<Vec<ExprId>>();
        let root = (0..mmcs_config.ext_field_digest_elems)
            .map(|_| builder.add_public_input())
            .collect::<Vec<ExprId>>();

        // not enabled yet
        let err = builder
            .add_mmcs_verify(&leaves, &directions, &root)
            .unwrap_err();
        match err {
            CircuitBuilderError::OpNotAllowed { op } => {
                assert_eq!(op, NonPrimitiveOpType::MmcsVerify);
            }
            other => panic!("expected OpNotAllowed, got {other:?}"),
        }
    }

    #[test]
    fn test_constant_deduplication() {
        // Test that identical constants are deduplicated and reuse ExprIds
        let mut builder = CircuitBuilder::<BabyBear>::new();

        // Add the same constant multiple times
        let c1_first = builder.add_const(BabyBear::from_u64(42));
        let c1_second = builder.add_const(BabyBear::from_u64(42));
        let c1_third = builder.add_const(BabyBear::from_u64(42));

        // Should all return the same ExprId due to deduplication
        assert_eq!(c1_first, c1_second);
        assert_eq!(c1_second, c1_third);

        // Add a different constant - should get different ExprId
        let c2 = builder.add_const(BabyBear::from_u64(43));
        assert_ne!(c1_first, c2);

        // Build circuit and verify that only 3 constants exist:
        // - Const(0) automatically added during builder creation
        // - Const(42) added by user (deduplicated)
        // - Const(43) added by user
        let circuit = builder.build().unwrap();

        // Zero is always ExprId(0), so we expect exactly 2 user constants
        let const_count = circuit
            .primitive_ops
            .iter()
            .filter(|op| matches!(op, Prim::Const { .. }))
            .count();
        assert_eq!(const_count, 3); // 0, 42, 43
    }

    #[test]
    fn test_arithmetic_operations_chain() {
        // Test chaining multiple arithmetic operations: ((x + 5) * 3) - 2 = result
        let mut builder = CircuitBuilder::<BabyBear>::new();

        // Create public input and constants
        let x = builder.add_public_input();
        let c5 = builder.add_const(BabyBear::from_u64(5));
        let c3 = builder.add_const(BabyBear::from_u64(3));
        let c2 = builder.add_const(BabyBear::from_u64(2));

        // Chain operations: ((x + 5) * 3) - 2
        let step1 = builder.add(x, c5); // x + 5
        let step2 = builder.mul(step1, c3); // (x + 5) * 3
        let result = builder.sub(step2, c2); // ((x + 5) * 3) - 2

        // Add expected result as public input and assert equality
        let expected = builder.add_public_input();
        builder.connect(result, expected);

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();

        // Test with x = 7: ((7 + 5) * 3) - 2 = (12 * 3) - 2 = 36 - 2 = 34
        let x_val = BabyBear::from_u64(7);
        let expected_val = BabyBear::from_u64(34);
        runner.set_public_inputs(&[x_val, expected_val]).unwrap();

        // Should succeed - constraint is satisfied
        let traces = runner.run().unwrap();

        // Verify we have the expected number of operations in traces
        assert_eq!(traces.add_trace.lhs_values.len(), 2); // Two adds: x+5 and internal sub encoding
        assert_eq!(traces.mul_trace.lhs_values.len(), 1); // One mul: (x+5)*3
    }

    #[test]
    fn test_division_operation() {
        // Test division: (x * y) / z = result, where division is encoded as z * result = (x * y)
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let x = builder.add_public_input();
        let y = builder.add_public_input();
        let z = builder.add_public_input();
        let expected_result = builder.add_public_input();

        // Compute x * y
        let xy = builder.mul(x, y);

        // Divide by z: (x * y) / z
        let division_result = builder.div(xy, z);

        // Assert division result equals expected
        builder.connect(division_result, expected_result);

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();

        // Test: (6 * 7) / 2 = 42 / 2 = 21
        let x_val = BabyBear::from_u64(6);
        let y_val = BabyBear::from_u64(7);
        let z_val = BabyBear::from_u64(2);
        let expected_val = BabyBear::from_u64(21);

        runner
            .set_public_inputs(&[x_val, y_val, z_val, expected_val])
            .unwrap();
        let traces = runner.run().unwrap();

        // Verify traces: should have 2 multiplications (x*y and the div encoding z*result=xy)
        assert_eq!(traces.mul_trace.lhs_values.len(), 2);
    }

    #[test]
    fn test_assert_zero_functionality() {
        // Test assert_zero by creating an expression that should equal zero
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let x = builder.add_public_input();
        let y = builder.add_public_input();

        // Create expression: x - y (should be zero when x == y)
        let difference = builder.sub(x, y);

        // Assert that difference equals zero
        builder.assert_zero(difference);

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();

        // Test case 1: Equal values - should succeed
        let equal_val = BabyBear::from_u64(15);
        runner.set_public_inputs(&[equal_val, equal_val]).unwrap();
        runner.run().unwrap(); // Should succeed

        // Test case 2: Different values - should fail
        let mut builder2 = CircuitBuilder::<BabyBear>::new();
        let x2 = builder2.add_public_input();
        let y2 = builder2.add_public_input();
        let difference2 = builder2.sub(x2, y2);
        builder2.assert_zero(difference2);
        let circuit2 = builder2.build().unwrap();
        let mut runner2 = circuit2.runner();
        let val1 = BabyBear::from_u64(15);
        let val2 = BabyBear::from_u64(16);
        runner2.set_public_inputs(&[val1, val2]).unwrap();

        // Should fail because difference is not zero
        let err = runner2.run().unwrap_err();
        match err {
            CircuitError::WitnessConflict { .. } => {} // Expected: can't satisfy x-y=0 when x≠y
            other => panic!("Expected WitnessConflict, got {:?}", other),
        }
    }

    #[test]
    fn test_mmcs_config_allows_when_enabled() {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let mmcs_config = MmcsVerifyConfig::mock_config();

        let leaves = (0..mmcs_config.max_tree_height)
            .map(|_| {
                (0..mmcs_config.ext_field_digest_elems)
                    .map(|_| builder.add_public_input())
                    .collect()
            })
            .collect::<Vec<Vec<ExprId>>>();
        let directions = (0..mmcs_config.max_tree_height)
            .map(|_| builder.add_public_input())
            .collect::<Vec<ExprId>>();
        let root = (0..mmcs_config.ext_field_digest_elems)
            .map(|_| builder.add_public_input())
            .collect::<Vec<ExprId>>();

        builder.enable_mmcs(&mmcs_config);
        builder
            .add_mmcs_verify(&leaves, &directions, &root)
            .expect("should be allowed");

        let circuit = builder.build().unwrap();
        assert_eq!(circuit.non_primitive_ops.len(), 1);
        match &circuit.non_primitive_ops[0] {
            NonPrimitiveOp::MmcsVerify { .. } => {}
            NonPrimitiveOp::HashAbsorb { .. } | NonPrimitiveOp::HashSqueeze { .. } => {
                panic!("Expected MmcsVerify operation");
            }
        }
    }

    #[test]
    fn test_complex_connect_chains() {
        // Test complex connection chains: a=b, b=c, c=d should make all equivalent
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let x = builder.add_public_input();
        let c1 = builder.add_const(BabyBear::from_u64(10));
        let c2 = builder.add_const(BabyBear::from_u64(5));

        // Create chain of equivalent expressions
        let _a = builder.add(x, c1); // a = x + 10
        let _b = builder.add(x, c1); // b = x + 10 (same as a)
        let const_2 = builder.add_const(BabyBear::from_u64(2));
        let _c = builder.mul(c2, const_2); // c = 5 * 2 = 10
        let const_10 = builder.add_const(BabyBear::from_u64(10));
        let _d = builder.add(x, const_10); // d = x + 10

        // Actually test with simpler expressions to focus on connect functionality
        let pub1 = builder.add_public_input(); // This will be at position 0
        let pub2 = builder.add_public_input(); // This will be at position 1
        let pub3 = builder.add_public_input(); // This will be at position 2
        let pub4 = builder.add_public_input(); // This will be at position 3

        // Create connection chain: pub1 = pub2 = pub3 = pub4
        builder.connect(pub1, pub2);
        builder.connect(pub2, pub3);
        builder.connect(pub3, pub4);

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();

        // All should have same value due to connections
        let shared_val = BabyBear::from_u64(99);
        runner
            .set_public_inputs(&[shared_val, shared_val, shared_val, shared_val, shared_val])
            .unwrap();
        runner.run().unwrap(); // Should succeed

        // Test with different values - should fail - create new circuit
        let mut builder2 = CircuitBuilder::<BabyBear>::new();
        let p1 = builder2.add_public_input();
        let p2 = builder2.add_public_input();
        let p3 = builder2.add_public_input();
        let p4 = builder2.add_public_input();
        builder2.connect(p1, p2);
        builder2.connect(p2, p3);
        builder2.connect(p3, p4);
        let circuit2 = builder2.build().unwrap();
        let mut runner2 = circuit2.runner();
        let val1 = BabyBear::from_u64(99);
        let val2 = BabyBear::from_u64(100); // Different value
        // This should fail during public input setting due to connection constraints
        let result = runner2.set_public_inputs(&[val1, val2, val1, val1]);
        match result {
            Err(CircuitError::WitnessConflict { .. }) => {} // Expected - conflict detected early
            other => panic!("Expected WitnessConflict, got {:?}", other),
        }
    }

    #[test]
    fn test_mmcs_config_with_custom_params() {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let mmcs_config = MmcsVerifyConfig::mock_config();

        let leaves = (0..mmcs_config.max_tree_height)
            .map(|_| {
                (0..mmcs_config.ext_field_digest_elems)
                    .map(|_| builder.add_public_input())
                    .collect()
            })
            .collect::<Vec<Vec<ExprId>>>();
        let directions = (0..mmcs_config.max_tree_height)
            .map(|_| builder.add_public_input())
            .collect::<Vec<ExprId>>();
        let root = (0..mmcs_config.ext_field_digest_elems)
            .map(|_| builder.add_public_input())
            .collect::<Vec<ExprId>>();

        builder.enable_mmcs(&mmcs_config);
        builder
            .add_mmcs_verify(&leaves, &directions, &root)
            .expect("should be allowed with custom config");

        let circuit = builder.build().unwrap();
        assert_eq!(circuit.non_primitive_ops.len(), 1);
    }

    #[test]
    fn test_zero_constant_special_case() {
        // Test that zero constant gets special handling and is always ExprId::ZERO
        let mut builder = CircuitBuilder::<BabyBear>::new();

        // Zero should already exist and be ExprId::ZERO
        let zero_id = builder.add_const(BabyBear::ZERO);
        assert_eq!(zero_id, ExprId::ZERO);

        // Adding zero again should return the same ID
        let zero_id2 = builder.add_const(BabyBear::ZERO);
        assert_eq!(zero_id2, ExprId::ZERO);

        // Use zero in an operation
        let x = builder.add_public_input();
        let result = builder.add(x, zero_id); // x + 0 = x

        // Connect result back to x (should be equivalent)
        builder.connect(result, x);

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();

        // Should work with any value since x + 0 = x
        runner.set_public_inputs(&[BabyBear::from_u64(42)]).unwrap();
        runner.run().unwrap();
    }

    #[test]
    fn test_self_connect_no_op() {
        // Test that connecting an expression to itself is a no-op
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let x = builder.add_public_input();
        let y = builder.add_public_input();

        // Self-connects should be ignored
        builder.connect(x, x);
        builder.connect(y, y);

        // Real connect should still work
        builder.connect(x, y);

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();

        // Should enforce x = y
        let val = BabyBear::from_u64(123);
        runner.set_public_inputs(&[val, val]).unwrap();
        runner.run().unwrap(); // Should succeed

        // Different values should fail - create new circuit
        let mut builder2 = CircuitBuilder::<BabyBear>::new();
        let x2 = builder2.add_public_input();
        let y2 = builder2.add_public_input();
        builder2.connect(x2, x2); // Self-connects should be ignored
        builder2.connect(y2, y2);
        builder2.connect(x2, y2); // Real connect should still work
        let circuit2 = builder2.build().unwrap();
        let mut runner2 = circuit2.runner();
        // This should fail during public input setting due to connection constraint
        let result = runner2.set_public_inputs(&[BabyBear::from_u64(123), BabyBear::from_u64(124)]);
        match result {
            Err(CircuitError::WitnessConflict { .. }) => {} // Expected - conflict detected early
            other => panic!("Expected WitnessConflict, got {:?}", other),
        }
    }

    #[test]
    fn test_lower_to_primitives_constants() {
        // Test constant lowering creates Const primitive operations
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let c1 = builder.add_const(BabyBear::from_u64(42));
        let c2 = builder.add_const(BabyBear::from_u64(100));

        let (primitives, public_rows, expr_to_widx, public_mappings) =
            builder.lower_to_primitives().unwrap();

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

        let (primitives, public_rows, expr_to_widx, public_mappings) =
            builder.lower_to_primitives().unwrap();

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

        let (primitives, public_rows, expr_to_widx, public_mappings) =
            builder.lower_to_primitives().unwrap();

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

        let (primitives, public_rows, expr_to_widx, public_mappings) =
            builder.lower_to_primitives().unwrap();

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

        let (primitives, public_rows, expr_to_widx, public_mappings) =
            builder.lower_to_primitives().unwrap();

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

        let (primitives, public_rows, expr_to_widx, public_mappings) =
            builder.lower_to_primitives().unwrap();

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

        let (primitives, public_rows, expr_to_widx, public_mappings) =
            builder.lower_to_primitives().unwrap();

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

        let (primitives, public_rows, expr_to_widx, public_mappings) =
            builder.lower_to_primitives().unwrap();

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

    #[test]
    #[cfg(debug_assertions)]
    fn test_allocation_log_operations() {
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let a = builder.alloc_public_input("input a");
        let b = builder.alloc_public_input("input b");

        let _sum = builder.alloc_add(a, b, "compute sum");
        let _product = builder.alloc_mul(a, b, "compute product");
        let _constant = builder.alloc_const(BabyBear::ONE, "unit constant");

        // Check consolidated log
        assert_eq!(builder.allocation_log.len(), 5);
        assert_eq!(builder.allocation_log[0].label, "input a");
        assert!(matches!(
            builder.allocation_log[0].alloc_type,
            AllocationType::Public
        ));
        assert_eq!(builder.allocation_log[1].label, "input b");
        assert!(matches!(
            builder.allocation_log[1].alloc_type,
            AllocationType::Public
        ));
        assert_eq!(builder.allocation_log[2].label, "compute sum");
        assert!(matches!(
            builder.allocation_log[2].alloc_type,
            AllocationType::Add
        ));
        assert_eq!(builder.allocation_log[3].label, "compute product");
        assert!(matches!(
            builder.allocation_log[3].alloc_type,
            AllocationType::Mul
        ));
        assert_eq!(builder.allocation_log[4].label, "unit constant");
        assert!(matches!(
            builder.allocation_log[4].alloc_type,
            AllocationType::Const
        ));
    }

    #[test]
    #[cfg(debug_assertions)]
    fn test_allocation_log_unlabeled() {
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let a = builder.add_public_input();
        let b = builder.add_const(BabyBear::TWO);
        let _sum = builder.add(a, b);

        // Should all be logged with no labels
        assert_eq!(builder.allocation_log.len(), 3);
        assert_eq!(builder.allocation_log[0].label, "");
        assert!(matches!(
            builder.allocation_log[0].alloc_type,
            AllocationType::Public
        ));
        assert_eq!(builder.allocation_log[1].label, "");
        assert!(matches!(
            builder.allocation_log[1].alloc_type,
            AllocationType::Const
        ));
        assert_eq!(builder.allocation_log[2].label, "");
        assert!(matches!(
            builder.allocation_log[2].alloc_type,
            AllocationType::Add
        ));
    }

    #[test]
    #[cfg(debug_assertions)]
    fn test_allocation_log_const_deduplication() {
        let mut builder = CircuitBuilder::<BabyBear>::new();

        // First time: should log
        let _c1 = builder.alloc_const(BabyBear::ONE, "one");
        assert_eq!(builder.allocation_log.len(), 1);

        // Second time: deduplicated, should NOT log
        let _c2 = builder.alloc_const(BabyBear::ONE, "one again");
        assert_eq!(builder.allocation_log.len(), 1);

        // Different value: should log
        let _c3 = builder.alloc_const(BabyBear::TWO, "two");
        assert_eq!(builder.allocation_log.len(), 2);
        assert_eq!(builder.allocation_log[0].label, "one");
        assert!(matches!(
            builder.allocation_log[0].alloc_type,
            AllocationType::Const
        ));
        assert_eq!(builder.allocation_log[1].label, "two");
        assert!(matches!(
            builder.allocation_log[1].alloc_type,
            AllocationType::Const
        ));
    }

    #[test]
    #[cfg(debug_assertions)]
    fn test_allocation_log_with_dependencies() {
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let a = builder.alloc_public_input("input_a");
        let b = builder.alloc_public_input("input_b");
        let sum = builder.alloc_add(a, b, "compute_sum");
        let product = builder.alloc_mul(a, b, "compute_product");
        let _final_result = builder.alloc_add(sum, product, "final_result");

        // Verify all entries are logged
        assert_eq!(builder.allocation_log.len(), 5);

        // Check dependencies are tracked correctly
        let add_entry = &builder.allocation_log[2]; // First add
        assert_eq!(add_entry.label, "compute_sum");
        assert!(matches!(add_entry.alloc_type, AllocationType::Add));
        assert_eq!(add_entry.dependencies.len(), 2);
        assert_eq!(add_entry.dependencies[0][0], a);
        assert_eq!(add_entry.dependencies[1][0], b);

        let mul_entry = &builder.allocation_log[3]; // Multiply
        assert_eq!(mul_entry.label, "compute_product");
        assert!(matches!(mul_entry.alloc_type, AllocationType::Mul));
        assert_eq!(mul_entry.dependencies.len(), 2);
        assert_eq!(mul_entry.dependencies[0][0], a);
        assert_eq!(mul_entry.dependencies[1][0], b);

        let final_entry = &builder.allocation_log[4]; // Final add
        assert_eq!(final_entry.label, "final_result");
        assert!(matches!(final_entry.alloc_type, AllocationType::Add));
        assert_eq!(final_entry.dependencies.len(), 2);
        assert_eq!(final_entry.dependencies[0][0], sum);
        assert_eq!(final_entry.dependencies[1][0], product);
    }

    #[test]
    #[cfg(debug_assertions)]
    fn test_allocation_log_expr_ids() {
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let a = builder.alloc_public_input("a");
        let b = builder.alloc_const(BabyBear::ONE, "one");
        let c = builder.alloc_add(a, b, "a_plus_one");

        // Check that expr_ids match the returned values
        assert_eq!(builder.allocation_log[0].expr_id, a);
        assert_eq!(builder.allocation_log[1].expr_id, b);
        assert_eq!(builder.allocation_log[2].expr_id, c);
    }
}
