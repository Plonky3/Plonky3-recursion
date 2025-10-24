use alloc::vec::Vec;
use core::hash::Hash;

use hashbrown::HashMap;
use p3_field::{Field, PrimeCharacteristicRing};

use super::compiler::{ExpressionLowerer, NonPrimitiveLowerer, Optimizer};
use super::{BuilderConfig, ExpressionBuilder, PublicInputTracker};
use crate::CircuitBuilderError;
use crate::circuit::Circuit;
use crate::op::NonPrimitiveOpType;
use crate::ops::MmcsVerifyConfig;
use crate::types::{ExprId, NonPrimitiveOpId, WitnessAllocator, WitnessId};

/// Builder for constructing circuits.
pub struct CircuitBuilder<F> {
    /// Expression graph builder
    expr_builder: ExpressionBuilder<F>,

    /// Public input tracker
    public_tracker: PublicInputTracker,

    /// Witness index allocator
    witness_alloc: WitnessAllocator,

    /// Non-primitive operations (complex constraints that don't produce `ExprId`s)
    non_primitive_ops: Vec<(NonPrimitiveOpId, NonPrimitiveOpType, Vec<ExprId>)>,

    /// Builder configuration
    config: BuilderConfig,
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
    /// Creates a new circuit builder.
    pub fn new() -> Self {
        Self {
            expr_builder: ExpressionBuilder::new(),
            public_tracker: PublicInputTracker::new(),
            witness_alloc: WitnessAllocator::new(),
            non_primitive_ops: Vec::new(),
            config: BuilderConfig::new(),
        }
    }

    /// Enables a non-primitive operation type on this builder.
    pub fn enable_op(&mut self, op: NonPrimitiveOpType, cfg: crate::op::NonPrimitiveOpConfig) {
        self.config.enable_op(op, cfg);
    }

    /// Enables Mmcs verification operations.
    pub fn enable_mmcs(&mut self, mmcs_config: &MmcsVerifyConfig) {
        self.config.enable_mmcs(mmcs_config);
    }

    /// Enables FRI verification operations.
    pub fn enable_fri(&mut self) {
        self.config.enable_fri();
    }

    /// Checks whether an op type is enabled on this builder.
    fn is_op_enabled(&self, op: &NonPrimitiveOpType) -> bool {
        self.config.is_op_enabled(op)
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

    /// Adds a public input to the circuit.
    ///
    /// Cost: 1 row in Public table + 1 row in witness table.
    pub fn add_public_input(&mut self) -> ExprId {
        self.alloc_public_input("")
    }

    /// Allocates a public input with a descriptive label.
    ///
    /// The label is logged in debug builds for easier debugging of public input ordering.
    ///
    /// Cost: 1 row in Public table + 1 row in witness table.
    pub fn alloc_public_input(&mut self, label: &'static str) -> ExprId {
        let pos = self.public_tracker.alloc();
        self.expr_builder.add_public(pos, label)
    }

    /// Allocates multiple public inputs with a descriptive label.
    pub fn alloc_public_inputs(&mut self, count: usize, label: &'static str) -> Vec<ExprId> {
        (0..count).map(|_| self.alloc_public_input(label)).collect()
    }

    /// Allocates a fixed-size array of public inputs with a descriptive label.
    pub fn alloc_public_input_array<const N: usize>(&mut self, label: &'static str) -> [ExprId; N] {
        core::array::from_fn(|_| self.alloc_public_input(label))
    }

    /// Returns the current public input count.
    pub fn public_input_count(&self) -> usize {
        self.public_tracker.count()
    }

    /// Allocates a witness hint (uninitialized witness slot set during non-primitive execution).
    #[must_use]
    pub fn alloc_witness_hint(&mut self, label: &'static str) -> ExprId {
        self.expr_builder.add_witness_hint(label)
    }

    /// Allocates multiple witness hints.
    #[must_use]
    pub fn alloc_witness_hints(&mut self, count: usize, label: &'static str) -> Vec<ExprId> {
        self.expr_builder.add_witness_hints(count, label)
    }

    /// Adds a constant to the circuit (deduplicated).
    ///
    /// If this value was previously added, returns the original ExprId.
    /// Cost: 1 row in Const table + 1 row in witness table (only for new constants).
    pub fn add_const(&mut self, val: F) -> ExprId {
        self.alloc_const(val, "")
    }

    /// Allocates a constant with a descriptive label.
    ///
    /// Cost: 1 row in Const table + 1 row in witness table (only for new constants).
    pub fn alloc_const(&mut self, val: F, label: &'static str) -> ExprId {
        self.expr_builder.add_const(val, label)
    }

    /// Adds two expressions.
    ///
    /// Cost: 1 row in Add table + 1 row in witness table.
    pub fn add(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.alloc_add(lhs, rhs, "")
    }

    /// Adds two expressions with a descriptive label.
    ///
    /// Cost: 1 row in Add table + 1 row in witness table.
    pub fn alloc_add(&mut self, lhs: ExprId, rhs: ExprId, label: &'static str) -> ExprId {
        self.expr_builder.add_add(lhs, rhs, label)
    }

    /// Subtracts two expressions.
    ///
    /// Cost: 1 row in Add table + 1 row in witness table (encoded as result + rhs = lhs).
    pub fn sub(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.alloc_sub(lhs, rhs, "")
    }

    /// Subtracts two expressions with a descriptive label.
    ///
    /// Cost: 1 row in Add table + 1 row in witness table.
    pub fn alloc_sub(&mut self, lhs: ExprId, rhs: ExprId, label: &'static str) -> ExprId {
        self.expr_builder.add_sub(lhs, rhs, label)
    }

    /// Multiplies two expressions.
    ///
    /// Cost: 1 row in Mul table + 1 row in witness table.
    pub fn mul(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.alloc_mul(lhs, rhs, "")
    }

    /// Multiplies two expressions with a descriptive label.
    ///
    /// Cost: 1 row in Mul table + 1 row in witness table.
    pub fn alloc_mul(&mut self, lhs: ExprId, rhs: ExprId, label: &'static str) -> ExprId {
        self.expr_builder.add_mul(lhs, rhs, label)
    }

    /// Divides two expressions.
    ///
    /// Cost: 1 row in Mul table + 1 row in witness table (encoded as rhs * out = lhs).
    pub fn div(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.alloc_div(lhs, rhs, "")
    }

    /// Divides two expressions with a descriptive label.
    ///
    /// Cost: 1 row in Mul table + 1 row in witness table.
    pub fn alloc_div(&mut self, lhs: ExprId, rhs: ExprId, label: &'static str) -> ExprId {
        self.expr_builder.add_div(lhs, rhs, label)
    }

    /// Asserts that an expression equals zero by connecting it to Const(0).
    ///
    /// Cost: Free in proving (implemented via connect).
    pub fn assert_zero(&mut self, expr: ExprId) {
        self.connect(expr, ExprId::ZERO);
    }

    /// Asserts that an expression is boolean: b ∈ {0,1}.
    ///
    /// Encodes the constraint b · (b − 1) = 0 via `assert_zero`.
    /// Cost: 1 mul + 1 add.
    pub fn assert_bool(&mut self, b: ExprId) {
        let one = self.add_const(F::ONE);
        let b_minus_one = self.sub(b, one);
        let prod = self.mul(b, b_minus_one);
        self.assert_zero(prod);
    }

    /// Connects two expressions, enforcing a == b (by aliasing outputs).
    ///
    /// Cost: Free in proving (handled by IR optimization layer via witness slot aliasing).
    pub fn connect(&mut self, a: ExprId, b: ExprId) {
        self.expr_builder.connect(a, b);
    }

    /// Selects between two values using selector `b`:
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

    /// Exponentiates a base expression to a power of 2 (i.e. base^(2^power_log)), by squaring repeatedly.
    pub fn exp_power_of_2(&mut self, base: ExprId, power_log: usize) -> ExprId {
        let mut res = base;
        for _ in 0..power_log {
            let square = self.mul(res, res);
            res = square;
        }
        res
    }

    /// Pushes a non-primitive op. Returns op id.
    #[allow(unused_variables)]
    pub(crate) fn push_non_primitive_op(
        &mut self,
        op_type: NonPrimitiveOpType,
        witness_exprs: Vec<ExprId>,
        label: &'static str,
    ) -> NonPrimitiveOpId {
        let op_id = NonPrimitiveOpId(self.non_primitive_ops.len() as u32);

        #[cfg(debug_assertions)]
        self.expr_builder.log_non_primitive_op(
            op_id,
            op_type.clone(),
            witness_exprs.clone(),
            label,
        );

        self.non_primitive_ops.push((op_id, op_type, witness_exprs));
        op_id
    }

    /// Pushes a new scope onto the scope stack.
    ///
    /// All subsequent allocations will be tagged with this scope until
    /// `pop_scope` is called. Scopes can be nested.
    ///
    /// If debug_assertions are not enabled, this is a no-op.
    #[allow(unused_variables)]
    pub fn push_scope(&mut self, scope: &'static str) {
        #[cfg(debug_assertions)]
        self.expr_builder.push_scope(scope);
    }

    /// Pops the current scope from the scope stack.
    ///
    /// If debug_assertions are not enabled, this is a no-op.
    pub fn pop_scope(&mut self) {
        #[cfg(debug_assertions)]
        self.expr_builder.pop_scope();
    }

    /// Dumps the allocation log.
    ///
    /// If debug_assertions are not enabled, this is a no-op.
    pub fn dump_allocation_log(&self) {
        self.expr_builder.dump_allocation_log();
    }

    /// Lists all unique scopes in the allocation log.
    ///
    /// Returns an empty vector if debug_assertions are not enabled.
    pub fn list_scopes(&self) -> Vec<&'static str> {
        self.expr_builder.list_scopes()
    }
}

impl<F> CircuitBuilder<F>
where
    F: Field + Clone + PrimeCharacteristicRing + PartialEq + Eq + Hash,
{
    /// Builds the circuit into a Circuit with separate lowering and IR transformation stages.
    /// Returns an error if lowering fails due to an internal inconsistency.
    pub fn build(self) -> Result<Circuit<F>, CircuitBuilderError> {
        let (circuit, _) = self.build_with_public_mapping()?;
        Ok(circuit)
    }

    /// Builds the circuit and returns both the circuit and the ExprId→WitnessId mapping for public inputs.
    #[allow(clippy::type_complexity)]
    pub fn build_with_public_mapping(
        self,
    ) -> Result<(Circuit<F>, HashMap<ExprId, WitnessId>), CircuitBuilderError> {
        // Stage 1: Lower expressions to primitives
        let lowerer = ExpressionLowerer::new(
            self.expr_builder.graph(),
            self.expr_builder.pending_connects(),
            self.public_tracker.count(),
            self.witness_alloc,
        );
        let (primitive_ops, public_rows, expr_to_widx, public_mappings, witness_count) =
            lowerer.lower()?;

        // Stage 2: Lower non-primitive operations using the expr_to_widx mapping
        let non_primitive_lowerer =
            NonPrimitiveLowerer::new(&self.non_primitive_ops, &expr_to_widx, &self.config);
        let lowered_non_primitive_ops = non_primitive_lowerer.lower()?;

        // Stage 3: IR transformations and optimizations
        let optimizer = Optimizer::new();
        let primitive_ops = optimizer.optimize(primitive_ops);

        // Stage 4: Generate final circuit
        let mut circuit = Circuit::new(witness_count, expr_to_widx);
        circuit.primitive_ops = primitive_ops;
        circuit.non_primitive_ops = lowered_non_primitive_ops;
        circuit.public_rows = public_rows;
        circuit.public_flat_len = self.public_tracker.count();
        circuit.enabled_ops = self.config.into_enabled_ops();

        Ok((circuit, public_mappings))
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;

    use super::*;

    #[test]
    fn test_new_builder_initialization() {
        let builder = CircuitBuilder::<BabyBear>::new();
        assert_eq!(builder.public_input_count(), 0);
    }

    #[test]
    fn test_default_same_as_new() {
        let builder1 = CircuitBuilder::<BabyBear>::new();
        let builder2 = CircuitBuilder::<BabyBear>::default();
        assert_eq!(builder1.public_input_count(), builder2.public_input_count());
    }

    #[test]
    fn test_add_public_input_single() {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        builder.add_public_input();
        assert_eq!(builder.public_input_count(), 1);
    }

    #[test]
    fn test_alloc_public_inputs_multiple() {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let pis = builder.alloc_public_inputs(5, "batch");
        assert_eq!(pis.len(), 5);
        assert_eq!(builder.public_input_count(), 5);
    }

    #[test]
    fn test_alloc_public_input_array() {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let pis: [ExprId; 3] = builder.alloc_public_input_array("array");
        assert_eq!(pis.len(), 3);
        assert_eq!(builder.public_input_count(), 3);
    }

    #[test]
    fn test_public_input_count_increments() {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        assert_eq!(builder.public_input_count(), 0);
        builder.add_public_input();
        assert_eq!(builder.public_input_count(), 1);
        builder.add_public_input();
        assert_eq!(builder.public_input_count(), 2);
    }

    #[test]
    fn test_add_const_deduplication() {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let c1 = builder.add_const(BabyBear::from_u64(99));
        let c2 = builder.add_const(BabyBear::from_u64(99));
        assert_eq!(c1, c2);
    }

    #[test]
    fn test_exp_power_of_2_zero() {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let base = builder.add_const(BabyBear::from_u64(5));
        let result = builder.exp_power_of_2(base, 0);
        assert_eq!(result, base);
    }

    #[test]
    fn test_select_operation() {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let b = builder.add_public_input();
        let t = builder.add_const(BabyBear::from_u64(10));
        let s = builder.add_const(BabyBear::from_u64(5));
        let _result = builder.select(b, t, s);
        // Should create: t_minus_s, scaled, and result
        assert_eq!(builder.public_input_count(), 1);
    }

    #[test]
    fn test_ensure_op_enabled_success() {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let config = MmcsVerifyConfig::mock_config();
        builder.enable_mmcs(&config);
        let result = builder.ensure_op_enabled(NonPrimitiveOpType::MmcsVerify);
        assert!(result.is_ok());
    }

    #[test]
    fn test_ensure_op_enabled_failure() {
        let builder = CircuitBuilder::<BabyBear>::new();
        let result = builder.ensure_op_enabled(NonPrimitiveOpType::MmcsVerify);
        assert!(result.is_err());
        match result {
            Err(CircuitBuilderError::OpNotAllowed { op }) => {
                assert_eq!(op, NonPrimitiveOpType::MmcsVerify);
            }
            _ => panic!("Expected OpNotAllowed error"),
        }
    }

    #[test]
    #[cfg(debug_assertions)]
    fn test_scope_operations() {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        builder.push_scope("test_scope");
        builder.add_const(BabyBear::ONE);
        builder.pop_scope();
        let scopes = builder.list_scopes();
        assert!(scopes.contains(&"test_scope"));
    }

    #[test]
    #[cfg(not(debug_assertions))]
    fn test_list_scopes_release() {
        let builder = CircuitBuilder::<BabyBear>::new();
        assert!(builder.list_scopes().is_empty());
    }

    #[test]
    fn test_build_empty_circuit() {
        let builder = CircuitBuilder::<BabyBear>::new();
        let circuit = builder
            .build()
            .expect("Empty circuit should build successfully");

        assert_eq!(circuit.public_flat_len, 0);
        assert_eq!(circuit.witness_count, 1);
        assert_eq!(circuit.primitive_ops.len(), 1);
        assert!(circuit.non_primitive_ops.is_empty());
        assert!(circuit.public_rows.is_empty());
        assert!(circuit.enabled_ops.is_empty());

        match &circuit.primitive_ops[0] {
            crate::op::Op::Const { out, val } => {
                assert_eq!(*out, WitnessId(0));
                assert_eq!(*val, BabyBear::ZERO);
            }
            _ => panic!("Expected Const operation at index 0"),
        }
    }

    #[test]
    fn test_build_with_public_inputs() {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        builder.add_public_input();
        builder.add_public_input();
        let circuit = builder
            .build()
            .expect("Circuit with public inputs should build");

        assert_eq!(circuit.public_flat_len, 2);
        assert_eq!(circuit.public_rows.len(), 2);
        assert_eq!(circuit.witness_count, 3);
        assert_eq!(circuit.primitive_ops.len(), 3);

        match &circuit.primitive_ops[0] {
            crate::op::Op::Const { out, val } => {
                assert_eq!(*out, WitnessId(0));
                assert_eq!(*val, BabyBear::ZERO);
            }
            _ => panic!("Expected Const at index 0"),
        }

        match &circuit.primitive_ops[1] {
            crate::op::Op::Public { out, public_pos } => {
                assert_eq!(*out, WitnessId(1));
                assert_eq!(*public_pos, 0);
            }
            _ => panic!("Expected Public at index 1"),
        }

        match &circuit.primitive_ops[2] {
            crate::op::Op::Public { out, public_pos } => {
                assert_eq!(*out, WitnessId(2));
                assert_eq!(*public_pos, 1);
            }
            _ => panic!("Expected Public at index 2"),
        }

        assert_eq!(circuit.public_rows[0], WitnessId(1));
        assert_eq!(circuit.public_rows[1], WitnessId(2));
    }

    #[test]
    fn test_build_with_constants() {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        builder.add_const(BabyBear::from_u64(1));
        builder.add_const(BabyBear::from_u64(2));
        let circuit = builder
            .build()
            .expect("Circuit with constants should build");

        assert_eq!(circuit.public_flat_len, 0);
        assert!(circuit.public_rows.is_empty());
        assert_eq!(circuit.witness_count, 3);
        assert_eq!(circuit.primitive_ops.len(), 3);

        match &circuit.primitive_ops[0] {
            crate::op::Op::Const { out, val } => {
                assert_eq!(*out, WitnessId(0));
                assert_eq!(*val, BabyBear::ZERO);
            }
            _ => panic!("Expected Const at index 0"),
        }

        match &circuit.primitive_ops[1] {
            crate::op::Op::Const { out, val } => {
                assert_eq!(*out, WitnessId(1));
                assert_eq!(*val, BabyBear::from_u64(1));
            }
            _ => panic!("Expected Const at index 1"),
        }

        match &circuit.primitive_ops[2] {
            crate::op::Op::Const { out, val } => {
                assert_eq!(*out, WitnessId(2));
                assert_eq!(*val, BabyBear::from_u64(2));
            }
            _ => panic!("Expected Const at index 2"),
        }
    }

    #[test]
    fn test_build_with_operations() {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let a = builder.add_const(BabyBear::from_u64(2));
        let b = builder.add_const(BabyBear::from_u64(3));
        builder.add(a, b);
        let circuit = builder
            .build()
            .expect("Circuit with operations should build");

        assert_eq!(circuit.witness_count, 4);
        assert_eq!(circuit.primitive_ops.len(), 4);

        match &circuit.primitive_ops[3] {
            crate::op::Op::Add { out, a, b } => {
                assert_eq!(*out, WitnessId(3));
                assert_eq!(*a, WitnessId(1));
                assert_eq!(*b, WitnessId(2));
            }
            _ => panic!("Expected Add at index 3"),
        }
    }

    #[test]
    fn test_build_with_public_mapping() {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let p0 = builder.add_public_input();
        let p1 = builder.add_public_input();
        let (circuit, mapping) = builder
            .build_with_public_mapping()
            .expect("Circuit should build with public mapping");

        assert_eq!(circuit.public_flat_len, 2);
        assert_eq!(mapping.len(), 2);
        assert_eq!(mapping[&p0], WitnessId(1));
        assert_eq!(mapping[&p1], WitnessId(2));
    }

    #[test]
    fn test_build_with_connect_deduplication() {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let a = builder.add_const(BabyBear::from_u64(5));
        let b = builder.add_const(BabyBear::from_u64(5));
        builder.connect(a, b);
        let circuit = builder
            .build()
            .expect("Circuit with constraints should build");

        assert_eq!(circuit.witness_count, 2);
        assert_eq!(circuit.primitive_ops.len(), 2);
    }
}

#[cfg(test)]
mod proptests {
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;
    use proptest::prelude::*;

    use super::*;

    // Strategy for generating valid field elements
    fn field_element() -> impl Strategy<Value = BabyBear> {
        any::<u64>().prop_map(BabyBear::from_u64)
    }

    proptest! {
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
    }
}
