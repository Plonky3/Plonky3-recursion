//! Mutable state for the multi-phase lowering pipeline.

use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{format, vec};

use hashbrown::{HashMap, HashSet};
use p3_field::Field;

use super::ExpressionLowerer;
use super::connect_dsu::ConnectDsu;
use crate::builder::CircuitBuilderError;
use crate::builder::npo::{
    NonPrimitiveOpParams, NonPrimitiveOperationData, NpoCircuitPlugin, NpoLoweringContext,
};
use crate::expr::{Expr, ExpressionGraph};
use crate::ops::{AluOpKind, NpoTypeId, Op};
use crate::types::{ExprId, NonPrimitiveOpId, WitnessAllocator, WitnessId};

/// Accumulated mutable state threaded through all lowering phases.
pub(super) struct LoweringState<'a, F: Field> {
    /// The expression DAG being lowered (immutable, borrowed).
    graph: &'a ExpressionGraph<F>,
    /// Plugin registry for table-backed non-primitive operations (immutable, borrowed).
    npo_registry: &'a HashMap<NpoTypeId, Arc<dyn NpoCircuitPlugin<F>>>,
    /// Registered non-primitive operation descriptors (immutable, borrowed).
    non_primitive_ops: &'a [NonPrimitiveOperationData<F>],

    /// Disjoint-set forest for connect-based witness sharing.
    dsu: ConnectDsu,
    /// Monotonic witness slot allocator.
    pub(super) witness_alloc: WitnessAllocator,

    /// Accumulated primitive operations in emission order.
    pub(super) ops: Vec<Op<F>>,
    /// Expression-to-witness mapping built during lowering.
    pub(super) expr_to_widx: HashMap<ExprId, WitnessId>,
    /// Witness slot for each public input position.
    pub(super) public_rows: Vec<WitnessId>,
    /// Witness slot for each private input position.
    pub(super) private_input_rows: Vec<WitnessId>,
    /// Expression-to-witness mapping restricted to public inputs.
    pub(super) public_mappings: HashMap<ExprId, WitnessId>,

    /// Pre-computed map from each non-primitive operation to its sorted output expressions.
    ///
    /// Built and validated during construction.
    op_id_to_output_exprs: HashMap<NonPrimitiveOpId, Vec<(u32, ExprId)>>,
    /// Tracks which non-primitive operations have already been emitted,
    /// preventing duplicate emission from multiple output nodes.
    emitted_npo_ops: HashSet<NonPrimitiveOpId>,

    /// `connect` pairs in which EXACTLY ONE side is a constant — normalized as
    /// `(value_expr, const_expr)`. These are NOT fed to the DSU: aliasing a
    /// value-bearing witness into a constant's shared slot is the unsound
    /// representation behind the `WitnessId(0)` `assert_zero` collapse (a
    /// genuinely-nonzero value-bearing witness gets the constant's slot and
    /// clobbers it at witness-generation time). Instead each is lowered to a
    /// per-target equality CONSTRAINT in [`Self::emit_deferred_const_connects`],
    /// keeping the value in its own slot and the constant the sole writer of its.
    deferred_const_connects: Vec<(ExprId, ExprId)>,
}

impl<'a, F: Field> LoweringState<'a, F> {
    /// Initialise the lowering state from a consumed lowerer.
    ///
    /// Builds the DSU from pending connects and validates the non-primitive
    /// output map (contiguous indices, no duplicates).
    pub fn new(lowerer: ExpressionLowerer<'a, F>) -> Result<Self, CircuitBuilderError> {
        // Borrow immutable references before moving owned fields.
        let graph = lowerer.graph;
        let non_primitive_ops = lowerer.non_primitive_ops;
        let npo_registry = lowerer.npo_registry;

        // Partition the declared connect pairs. A `connect(a, b)` whose two sides are BOTH
        // value-bearing (or both constants of equal value — a no-op already skipped upstream)
        // is a sound aliasing: both members compute the same value, so sharing one witness slot
        // is free equality. But `connect(value, const)` (the dominant case being
        // `assert_zero(x)` == `connect(x, ExprId::ZERO)`) is NOT sound to alias: it would give
        // the value-bearing witness the constant's shared slot. When that value is genuinely
        // nonzero at witness-generation time (e.g. a recursion verifier's reduced-opening
        // accumulator that a forged/over-aligned proof leaves nonzero, OR — fatally — when
        // many independent `assert_zero`s collapse through the single circuit-wide
        // `ExprId::ZERO` class and one member is nonzero) its creator overwrites the constant's
        // slot, raising `WitnessConflict { WitnessId(0) }`. We therefore DEFER each
        // value↔const connect out of the DSU and re-emit it as a per-target equality CONSTRAINT
        // (see `emit_deferred_const_connects`), so the value keeps its own slot, the constant
        // stays the sole writer of its slot, and a mismatch fails LOCALLY and cleanly.
        let mut aliasable_connects: Vec<(ExprId, ExprId)> =
            Vec::with_capacity(lowerer.pending_connects.len());
        let mut deferred_const_connects: Vec<(ExprId, ExprId)> = Vec::new();
        for &(a, b) in lowerer.pending_connects.iter() {
            let a_is_const = matches!(graph.get_expr(a), Expr::Const(_));
            let b_is_const = matches!(graph.get_expr(b), Expr::Const(_));
            // Exactly one side a constant ⇒ a value↔const equality: defer it.
            if a_is_const ^ b_is_const {
                // Normalize as (value_expr, const_expr).
                let pair = if a_is_const { (b, a) } else { (a, b) };
                deferred_const_connects.push(pair);
            } else {
                // value↔value (sound aliasing) or const↔const (equal-value no-op): keep in DSU.
                aliasable_connects.push((a, b));
            }
        }

        Ok(Self {
            graph,
            npo_registry,
            non_primitive_ops,
            // Build the DSU only from aliasable connects (value↔const pairs are deferred).
            dsu: ConnectDsu::from_connects(&aliasable_connects),
            // Take ownership of the allocator for witness slot creation.
            witness_alloc: lowerer.witness_alloc,
            ops: Vec::new(),
            expr_to_widx: HashMap::new(),
            // Pre-size positional vectors with placeholder witness IDs.
            public_rows: vec![WitnessId(0); lowerer.public_input_count],
            private_input_rows: vec![WitnessId(0); lowerer.private_input_count],
            public_mappings: HashMap::new(),
            // Validate and cache the non-primitive output map (may fail).
            op_id_to_output_exprs: graph.build_npo_output_map()?,
            emitted_npo_ops: HashSet::new(),
            deferred_const_connects,
        })
    }

    /// Look up an already-assigned witness for the given expression.
    ///
    /// # Returns
    ///
    /// The witness slot, or an error with the provided context string
    /// for diagnostics if the expression has not been lowered yet.
    fn resolve_witness(
        &self,
        expr_id: ExprId,
        context: &str,
    ) -> Result<WitnessId, CircuitBuilderError> {
        self.expr_to_widx.get(&expr_id).copied().ok_or_else(|| {
            CircuitBuilderError::MissingExprMapping {
                expr_id,
                context: context.into(),
            }
        })
    }

    /// Emit one constant operation per constant node in the graph.
    ///
    /// Constants are emitted first so they are available as operands in all
    /// subsequent phases. Expression-level deduplication ensures at most one
    /// node per distinct value.
    pub fn emit_constants(&mut self) {
        for (expr_idx, expr) in self.graph.nodes().iter().enumerate() {
            if let Expr::Const(val) = expr {
                let expr_id = ExprId(expr_idx as u32);
                // Allocate a witness (shared if this const is in a connect class).
                let w = self.dsu.alloc_witness(expr_id, &mut self.witness_alloc);
                self.ops.push(Op::Const { out: w, val: *val });
                self.expr_to_widx.insert(expr_id, w);
            }
        }
    }

    /// Emit one public-input operation per declared public.
    ///
    /// Records the witness slot both in the positional public-rows vector
    /// and in the public-specific expression mapping.
    pub fn emit_publics(&mut self) {
        for (expr_idx, expr) in self.graph.nodes().iter().enumerate() {
            if let Expr::Public(pos) = expr {
                let expr_id = ExprId(expr_idx as u32);
                let out_widx = self.dsu.alloc_witness(expr_id, &mut self.witness_alloc);
                self.ops.push(Op::Public {
                    out: out_widx,
                    public_pos: *pos,
                });
                self.expr_to_widx.insert(expr_id, out_widx);
                // Store the witness in the positional vector.
                self.public_rows[*pos] = out_widx;
                // Also record in the public-only mapping.
                self.public_mappings.insert(expr_id, out_widx);
            }
        }
    }

    /// Allocate witness slots for private inputs.
    ///
    /// Private inputs produce no operation — they are set externally.
    /// Only a witness slot is allocated and recorded.
    pub fn emit_privates(&mut self) {
        for (expr_idx, expr) in self.graph.nodes().iter().enumerate() {
            if let Expr::PrivateInput(pos) = expr {
                let expr_id = ExprId(expr_idx as u32);
                let out_widx = self.dsu.alloc_witness(expr_id, &mut self.witness_alloc);
                self.expr_to_widx.insert(expr_id, out_widx);
                self.private_input_rows[*pos] = out_widx;
            }
        }
    }

    /// Emit arithmetic and non-primitive operations in DAG creation order.
    ///
    /// Skips constants, publics, and private inputs (already handled).
    /// Each expression variant dispatches to a dedicated emit method.
    pub fn emit_operations(&mut self) -> Result<(), CircuitBuilderError> {
        for (expr_idx, expr) in self.graph.nodes().iter().enumerate() {
            let expr_id = ExprId(expr_idx as u32);
            match expr {
                // Already handled in earlier phases.
                Expr::Const(_) | Expr::Public(_) | Expr::PrivateInput(_) => {}
                Expr::Add { lhs, rhs } => self.emit_add(expr_id, *lhs, *rhs)?,
                Expr::Sub { lhs, rhs } => self.emit_sub(expr_id, *lhs, *rhs)?,
                Expr::Mul { lhs, rhs } => self.emit_mul(expr_id, *lhs, *rhs)?,
                Expr::Div { lhs, rhs } => self.emit_div(expr_id, *lhs, *rhs)?,
                Expr::HornerAcc {
                    acc,
                    alpha,
                    p_at_z,
                    p_at_x,
                } => self.emit_horner_acc(expr_id, *acc, *alpha, *p_at_z, *p_at_x)?,
                Expr::BoolCheck { val } => self.emit_bool_check(expr_id, *val)?,
                Expr::MulAdd { a, b, c } => self.emit_mul_add(expr_id, *a, *b, *c)?,
                Expr::NonPrimitiveCall { op_id, inputs: _ } => {
                    self.emit_npo_call(*op_id)?;
                }
                Expr::NonPrimitiveOutput {
                    call,
                    output_idx: _,
                } => {
                    self.emit_npo_output(expr_id, *call)?;
                }
            }
        }
        Ok(())
    }

    /// Emit: out = lhs + rhs.
    fn emit_add(
        &mut self,
        expr_id: ExprId,
        lhs: ExprId,
        rhs: ExprId,
    ) -> Result<(), CircuitBuilderError> {
        // Allocate a witness for the result (shared if in a connect class).
        let out_widx = self.dsu.alloc_witness(expr_id, &mut self.witness_alloc);
        // Resolve both operand witnesses (must have been emitted in an earlier phase).
        let a_widx = self.resolve_witness(lhs, &format!("Add lhs for {expr_id:?}"))?;
        let b_widx = self.resolve_witness(rhs, &format!("Add rhs for {expr_id:?}"))?;
        // Emit the forward add: out = a + b.
        self.ops.push(Op::add(a_widx, b_widx, out_widx));
        self.expr_to_widx.insert(expr_id, out_widx);
        Ok(())
    }

    /// Emit: out = lhs - rhs.
    ///
    /// # Algorithm
    ///
    /// Two encoding strategies depending on the operand shapes:
    ///
    /// - **Fast path** (mul-const rewrite): when the left operand is a product
    ///   and the right operand is a constant, rewrites `a * b - c` into
    ///   `a * b + (-c)` as a forward add. This lets the downstream optimizer
    ///   fuse the preceding multiply into a single fused multiply-add.
    ///
    /// - **Generic path**: encodes `lhs - rhs = result` as the constraint
    ///   `rhs + result = lhs` (a backwards add).
    fn emit_sub(
        &mut self,
        expr_id: ExprId,
        lhs: ExprId,
        rhs: ExprId,
    ) -> Result<(), CircuitBuilderError> {
        let lhs_expr = self.graph.get_expr(lhs);
        let rhs_expr = self.graph.get_expr(rhs);

        let result_widx = self.dsu.alloc_witness(expr_id, &mut self.witness_alloc);
        let lhs_widx =
            self.resolve_witness(lhs, &format!("Sub lhs (mul result) for {expr_id:?}"))?;

        if let (Expr::Mul { .. }, Expr::Const(const_val)) = (lhs_expr, rhs_expr) {
            // Fast path: emit a synthetic constant for the negated value.
            // The synthetic ID is beyond the graph so it never collides with real expressions.
            let synthetic_id = ExprId(self.graph.nodes().len() as u32);
            let neg_const_widx = self
                .dsu
                .alloc_witness(synthetic_id, &mut self.witness_alloc);
            self.ops.push(Op::Const {
                out: neg_const_widx,
                val: -(*const_val),
            });
            // Encode as forward add: result = lhs + (-c).
            self.ops
                .push(Op::add(lhs_widx, neg_const_widx, result_widx));
        } else {
            // Generic path: encode result + rhs = lhs (backwards add).
            let rhs_widx = self.resolve_witness(rhs, &format!("Sub rhs for {expr_id:?}"))?;
            self.ops.push(Op::add(rhs_widx, result_widx, lhs_widx));
        }
        self.expr_to_widx.insert(expr_id, result_widx);
        Ok(())
    }

    /// Emit: out = lhs * rhs.
    fn emit_mul(
        &mut self,
        expr_id: ExprId,
        lhs: ExprId,
        rhs: ExprId,
    ) -> Result<(), CircuitBuilderError> {
        // Allocate result witness and resolve both operands.
        let out_widx = self.dsu.alloc_witness(expr_id, &mut self.witness_alloc);
        let a_widx = self.resolve_witness(lhs, &format!("Mul lhs for {expr_id:?}"))?;
        let b_widx = self.resolve_witness(rhs, &format!("Mul rhs for {expr_id:?}"))?;
        // Emit the forward multiply: out = a * b.
        self.ops.push(Op::mul(a_widx, b_widx, out_widx));
        self.expr_to_widx.insert(expr_id, out_widx);
        Ok(())
    }

    /// Emit: out = lhs / rhs.
    ///
    /// Encoded as the constraint `rhs * out = lhs` (a multiplication
    /// where the quotient is the second operand).
    fn emit_div(
        &mut self,
        expr_id: ExprId,
        lhs: ExprId,
        rhs: ExprId,
    ) -> Result<(), CircuitBuilderError> {
        // The quotient witness is allocated for this expression.
        let b_widx = self.dsu.alloc_witness(expr_id, &mut self.witness_alloc);
        let out_widx = self.resolve_witness(lhs, &format!("Div lhs for {expr_id:?}"))?;
        let a_widx = self.resolve_witness(rhs, &format!("Div rhs for {expr_id:?}"))?;
        // Emit rhs * quotient = lhs.
        self.ops.push(Op::mul(a_widx, b_widx, out_widx));
        self.expr_to_widx.insert(expr_id, b_widx);
        Ok(())
    }

    /// Emit: out = acc * alpha + p_at_z - p_at_x.
    ///
    /// Single fused ALU operation with no intermediate witnesses.
    fn emit_horner_acc(
        &mut self,
        expr_id: ExprId,
        acc: ExprId,
        alpha: ExprId,
        p_at_z: ExprId,
        p_at_x: ExprId,
    ) -> Result<(), CircuitBuilderError> {
        // Allocate the result witness.
        let out_widx = self.dsu.alloc_witness(expr_id, &mut self.witness_alloc);
        // Resolve all four input witnesses.
        let acc_widx = self.resolve_witness(acc, &format!("HornerAcc acc for {expr_id:?}"))?;
        let alpha_widx =
            self.resolve_witness(alpha, &format!("HornerAcc alpha for {expr_id:?}"))?;
        let p_at_z_widx =
            self.resolve_witness(p_at_z, &format!("HornerAcc p_at_z for {expr_id:?}"))?;
        let p_at_x_widx =
            self.resolve_witness(p_at_x, &format!("HornerAcc p_at_x for {expr_id:?}"))?;
        // Emit a single fused ALU op: out = acc * alpha + p_at_z - p_at_x.
        self.ops.push(Op::horner_acc(
            p_at_x_widx,
            alpha_widx,
            p_at_z_widx,
            out_widx,
            acc_widx,
        ));
        self.expr_to_widx.insert(expr_id, out_widx);
        Ok(())
    }

    /// Emit: assert val in {0, 1}.
    ///
    /// Uses the ALU boolean-check encoding: `sel_bool * a * (a - 1) = 0`.
    /// The zero constant (always at position 0) is used as the `b` operand.
    fn emit_bool_check(&mut self, expr_id: ExprId, val: ExprId) -> Result<(), CircuitBuilderError> {
        let out_widx = self.dsu.alloc_witness(expr_id, &mut self.witness_alloc);
        let val_widx = self.resolve_witness(val, &format!("BoolCheck val for {expr_id:?}"))?;
        // The zero constant is always the first expression in the graph.
        let zero_widx = self.resolve_witness(ExprId::ZERO, "BoolCheck zero constant")?;
        self.ops.push(Op::Alu {
            kind: AluOpKind::BoolCheck,
            a: val_widx,
            b: zero_widx,
            c: Some(val_widx),
            out: out_widx,
            intermediate_out: None,
        });
        self.expr_to_widx.insert(expr_id, out_widx);
        Ok(())
    }

    /// Emit: out = a * b + c.
    ///
    /// Single fused multiply-add ALU operation.
    fn emit_mul_add(
        &mut self,
        expr_id: ExprId,
        a: ExprId,
        b: ExprId,
        c: ExprId,
    ) -> Result<(), CircuitBuilderError> {
        // Allocate the result witness and resolve all three operands.
        let out_widx = self.dsu.alloc_witness(expr_id, &mut self.witness_alloc);
        let a_widx = self.resolve_witness(a, &format!("MulAdd a for {expr_id:?}"))?;
        let b_widx = self.resolve_witness(b, &format!("MulAdd b for {expr_id:?}"))?;
        let c_widx = self.resolve_witness(c, &format!("MulAdd c for {expr_id:?}"))?;
        // Emit a single fused ALU op: out = a * b + c.
        self.ops.push(Op::mul_add(a_widx, b_widx, c_widx, out_widx));
        self.expr_to_widx.insert(expr_id, out_widx);
        Ok(())
    }

    /// Emit a non-primitive operation (hint or table-backed), deduplicating by op ID.
    ///
    /// Multiple output nodes may reference the same operation; this method
    /// ensures the operation is emitted exactly once. Pre-allocates witness
    /// slots for all outputs before dispatching to the type-specific emitter.
    fn emit_npo_call(&mut self, op_id: NonPrimitiveOpId) -> Result<(), CircuitBuilderError> {
        // Dedup guard: skip if already emitted.
        if !self.emitted_npo_ops.insert(op_id) {
            return Ok(());
        }
        let data = self
            .non_primitive_ops
            .get(op_id.0 as usize)
            .ok_or(CircuitBuilderError::MissingNonPrimitiveOp { op_id })?;
        let outputs = self
            .op_id_to_output_exprs
            .get(&op_id)
            .cloned()
            .unwrap_or_default();

        // Pre-allocate witness slots for all output expressions.
        for &(_output_idx, expr_id) in &outputs {
            self.expr_to_widx
                .entry(expr_id)
                .or_insert_with(|| self.dsu.alloc_witness(expr_id, &mut self.witness_alloc));
        }

        // Dispatch to the appropriate emitter based on operation type.
        if data.op_type == NpoTypeId::unconstrained() {
            self.emit_unconstrained_hint(data, &outputs)?;
        } else {
            self.emit_table_backed_npo(data, &outputs)?;
        }
        Ok(())
    }

    /// Emit an unconstrained hint (non-table-backed non-primitive operation).
    ///
    /// Validates the executor configuration and input arity, resolves all
    /// input witnesses, and emits a single hint operation.
    fn emit_unconstrained_hint(
        &mut self,
        data: &NonPrimitiveOperationData<F>,
        output_exprs: &[(u32, ExprId)],
    ) -> Result<(), CircuitBuilderError> {
        // Extract the executor closure from the operation parameters.
        let executor = match data.params.as_ref().ok_or_else(|| {
            CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                op: data.op_type.clone(),
            }
        })? {
            NonPrimitiveOpParams::Unconstrained { executor } => executor.clone(),
            _ => {
                return Err(CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                    op: data.op_type.clone(),
                });
            }
        };

        // Unconstrained ops expect exactly one input group.
        if data.input_exprs.len() != 1 {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "Unconstrained",
                expected: "1 [in]".to_string(),
                got: data.input_exprs.len(),
            });
        }

        // Resolve each input expression to its witness slot.
        let flat_inputs: Vec<WitnessId> = data.input_exprs[0]
            .iter()
            .map(|&expr| self.resolve_witness(expr, "Unconstrained operation input"))
            .collect::<Result<_, _>>()?;

        // Ensure every output expression has a witness slot allocated.
        let flat_outputs: Vec<WitnessId> = output_exprs
            .iter()
            .map(|&(_output_idx, expr_id)| {
                *self
                    .expr_to_widx
                    .entry(expr_id)
                    .or_insert_with(|| self.dsu.alloc_witness(expr_id, &mut self.witness_alloc))
            })
            .collect();

        self.ops.push(Op::Hint {
            inputs: flat_inputs,
            outputs: flat_outputs,
            executor,
        });
        Ok(())
    }

    /// Emit a table-backed non-primitive operation via its registered plugin.
    ///
    /// Delegates to the plugin's lowering logic, passing a context that provides
    /// mutable access to the witness map and an allocation closure.
    fn emit_table_backed_npo(
        &mut self,
        data: &NonPrimitiveOperationData<F>,
        output_exprs: &[(u32, ExprId)],
    ) -> Result<(), CircuitBuilderError> {
        let plugin = self.npo_registry.get(&data.op_type).ok_or_else(|| {
            CircuitBuilderError::UnsupportedNonPrimitiveOp {
                op: data.op_type.clone(),
            }
        })?;

        // The plugin context expects `FnMut(usize)` — convert at this API boundary.
        let mut alloc_fn = |idx: usize| {
            self.dsu
                .alloc_witness(ExprId(idx as u32), &mut self.witness_alloc)
        };
        let mut ctx = NpoLoweringContext::new(&mut self.expr_to_widx, &mut alloc_fn);
        let op = plugin.lower(data, output_exprs, &mut ctx)?;
        self.ops.push(op);
        Ok(())
    }

    /// Emit (if not yet emitted) the non-primitive op referenced by an output node.
    ///
    /// Resolves the call expression to find the operation ID, delegates to the
    /// shared emission logic, then ensures this specific output node has a witness.
    fn emit_npo_output(
        &mut self,
        expr_id: ExprId,
        call: ExprId,
    ) -> Result<(), CircuitBuilderError> {
        // Resolve the call node to get the operation ID.
        let Expr::NonPrimitiveCall { op_id, .. } = self.graph.get_expr(call) else {
            return Err(CircuitBuilderError::MissingExprMapping {
                expr_id: call,
                context: "NonPrimitiveOutput.call must reference a NonPrimitiveCall".to_string(),
            });
        };
        // Copy the ID to release the borrow on the graph before mutating self.
        let op_id = *op_id;
        self.emit_npo_call(op_id)?;

        // Ensure this output node has a witness (may already have been assigned
        // during pre-allocation in the call emission).
        if !self.expr_to_widx.contains_key(&expr_id) {
            let widx = self.dsu.alloc_witness(expr_id, &mut self.witness_alloc);
            self.expr_to_widx.insert(expr_id, widx);
        }
        Ok(())
    }

    /// Verify that every registered non-primitive operation was reachable.
    ///
    /// An unreachable operation indicates a DAG construction bug — the op was
    /// registered but no expression node references it.
    pub fn validate_all_npo_emitted(&self) -> Result<(), CircuitBuilderError> {
        // Fast path: if counts match, all ops were emitted.
        if self.emitted_npo_ops.len() != self.non_primitive_ops.len() {
            for data in self.non_primitive_ops {
                if !self.emitted_npo_ops.contains(&data.op_id) {
                    return Err(CircuitBuilderError::UnanchoredNonPrimitiveOp {
                        op_id: data.op_id,
                    });
                }
            }
        }
        Ok(())
    }

    /// Emit a per-target equality CONSTRAINT for each deferred `connect(value, const)` pair.
    ///
    /// A `connect(x, c)` with `c` a constant (the dominant case being `assert_zero(x)` ==
    /// `connect(x, ExprId::ZERO)`) is NOT aliased into the constant's class (that is the
    /// unsound representation behind the circuit-wide `ExprId::ZERO` slot collapse). Instead
    /// we enforce `x == c` as a row that keeps `x` in its OWN witness slot:
    ///
    /// ```text
    ///   Op::MulAdd { a: x, b: ZERO, c: const, out: x }   // x*0 + c == x  ⇔  x == c
    /// ```
    ///
    /// At witness generation `MulAdd` computes `x*0 + c = c` and writes `out == x`'s slot; if
    /// `x` already holds a value `≠ c` the write conflicts on `x`'s OWN slot (a clean, LOCAL
    /// failure — never the shared constant slot), and on the honest path (`x == c`) it agrees.
    /// In the AIR this is a genuine `MulAdd` constraint binding `x` to the constant, so the
    /// equality is enforced, not merely witness-aliased. WitnessChecks/`ext_reads` accounting
    /// flows through the existing ALU reader/creator logic — no new bus path is needed (unlike
    /// a second `Op::Const` writer, which `generate_preprocessed_columns` treats as a creator).
    ///
    /// Putting BOTH the target and the constant into the op (as `a`/`out` and `c`) keeps the
    /// row distinct under the optimizer's ALU dedup (whose key includes these operands), so two
    /// equalities with the same target but different constants are not collapsed.
    pub fn emit_deferred_const_connects(&mut self) -> Result<(), CircuitBuilderError> {
        if self.deferred_const_connects.is_empty() {
            return Ok(());
        }
        let zero_widx = self.resolve_witness(ExprId::ZERO, "deferred const connect: zero const")?;
        // Move out to satisfy the borrow checker (resolve_witness borrows &self).
        let pairs = core::mem::take(&mut self.deferred_const_connects);
        for &(value_expr, const_expr) in &pairs {
            let value_widx =
                self.resolve_witness(value_expr, "deferred const connect: value")?;
            let const_widx =
                self.resolve_witness(const_expr, "deferred const connect: const")?;
            // x * 0 + c == x  ⇔  x == c, with the failure local to `value_widx`.
            self.ops
                .push(Op::mul_add(value_widx, zero_widx, const_widx, value_widx));
        }
        Ok(())
    }

    /// Fill in witness mappings for connect-class members not directly visited.
    ///
    /// After all phases complete, some expressions in a connect class may not
    /// have been the direct target of a witness allocation (e.g., they only
    /// appear as a connect partner). This pass ensures every connected expression
    /// has a mapping, using the class representative's witness slot.
    pub fn backfill_connect_mappings(&mut self) {
        // Collect first to avoid borrowing the DSU during iteration + mutation.
        let connected: Vec<ExprId> = self.dsu.connected_exprs().collect();
        for expr_id in connected {
            if !self.expr_to_widx.contains_key(&expr_id)
                && let Some(widx) = self.dsu.class_witness(expr_id)
            {
                self.expr_to_widx.insert(expr_id, widx);
            }
        }
    }
}
