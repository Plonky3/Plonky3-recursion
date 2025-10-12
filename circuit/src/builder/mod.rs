use alloc::vec::Vec;

use hashbrown::HashMap;
use p3_field::PrimeCharacteristicRing;
use thiserror::Error;

use crate::circuit::Circuit;
use crate::op::{NonPrimitiveOpConfig, NonPrimitiveOpType};
use crate::ops::MmcsVerifyConfig;
use crate::types::{ExprId, NonPrimitiveOpId, WitnessId};
use crate::{NonPrimitiveOp, Prim};

pub mod expr_builder;
use expr_builder::ExpressionBuilder;

pub mod public_input_builder;
use public_input_builder::PublicInputBuilder;

pub mod lowerer;
use lowerer::CircuitLowerer;

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
    /// Expression builder for managing the expression graph
    expr_builder: ExpressionBuilder<F>,
    /// Public input builder for managing public inputs
    public_input_builder: PublicInputBuilder<F>,
    /// Non-primitive operations (complex constraints that don't produce ExprIds)
    non_primitive_ops: Vec<(NonPrimitiveOpId, NonPrimitiveOpType, Vec<ExprId>)>, // (op_id, op_type, witness_exprs)

    /// Enabled non-primitive operation types with their respective configuration
    enabled_ops: HashMap<NonPrimitiveOpType, NonPrimitiveOpConfig>,

    /// Debug log of public input allocations with labels
    #[cfg(debug_assertions)]
    allocation_log: Vec<&'static str>,
}

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
        let expr_builder = ExpressionBuilder::new();
        let public_input_builder = PublicInputBuilder::new();

        Self {
            expr_builder,
            public_input_builder,
            non_primitive_ops: Vec::new(),
            enabled_ops: HashMap::new(), // All non-primitive ops are disabled by default
            #[cfg(debug_assertions)]
            allocation_log: Vec::new(),
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
        self.alloc_public_input("unlabeled")
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
        #[cfg(debug_assertions)]
        self.allocation_log.push(label);

        self.public_input_builder
            .add_public_input(&mut self.expr_builder)
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

    /// Get the current number of public inputs.
    pub fn public_input_count(&self) -> usize {
        self.public_input_builder.count()
    }

    /// Dump the public input allocation log (debug builds only).
    ///
    /// Shows the complete ordering of all public inputs with their labels.
    #[cfg(debug_assertions)]
    pub fn dump_allocation_log(&self) {
        tracing::debug!("=== Public Input Allocation Log ===");
        for (idx, label) in self.allocation_log.iter().enumerate() {
            tracing::debug!("  PublicInput[{}]: {}", idx, label);
        }
        tracing::debug!("Total public inputs: {}", self.allocation_log.len());
    }

    /// Add a constant to the circuit (deduplicated).
    ///
    /// If this value was previously added, returns the original ExprId.
    /// Cost: 1 row in Const table + 1 row in witness table (only for new constants).
    pub fn add_const(&mut self, val: F) -> ExprId {
        self.alloc_const(val, "const")
    }

    /// Allocate a constant with a descriptive label.
    ///
    /// Cost: 1 row in Const table + 1 row in witness table (only for new constants).
    #[allow(unused_variables)]
    pub fn alloc_const(&mut self, val: F, label: &'static str) -> ExprId {
        #[cfg(debug_assertions)]
        if !self.expr_builder.const_pool().contains_key(&val) {
            self.allocation_log.push(label);
        }

        self.expr_builder.add_const(val)
    }

    /// Add two expressions.
    ///
    /// Cost: 1 row in Add table + 1 row in witness table.
    pub fn add(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.alloc_add(lhs, rhs, "add")
    }

    /// Add two expressions with a descriptive label.
    ///
    /// Cost: 1 row in Add table + 1 row in witness table.
    #[allow(unused_variables)]
    pub fn alloc_add(&mut self, lhs: ExprId, rhs: ExprId, label: &'static str) -> ExprId {
        #[cfg(debug_assertions)]
        self.allocation_log.push(label);

        self.expr_builder.add(lhs, rhs)
    }

    /// Subtract two expressions.
    ///
    /// Cost: 1 row in Add table + 1 row in witness table (encoded as result + rhs = lhs).
    pub fn sub(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.alloc_sub(lhs, rhs, "sub")
    }

    /// Subtract two expressions with a descriptive label.
    ///
    /// Cost: 1 row in Add table + 1 row in witness table.
    #[allow(unused_variables)]
    pub fn alloc_sub(&mut self, lhs: ExprId, rhs: ExprId, label: &'static str) -> ExprId {
        #[cfg(debug_assertions)]
        self.allocation_log.push(label);

        self.expr_builder.sub(lhs, rhs)
    }

    /// Multiply two expressions.
    ///
    /// Cost: 1 row in Mul table + 1 row in witness table.
    pub fn mul(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.alloc_mul(lhs, rhs, "mul")
    }

    /// Multiply two expressions with a descriptive label.
    ///
    /// Cost: 1 row in Mul table + 1 row in witness table.
    #[allow(unused_variables)]
    pub fn alloc_mul(&mut self, lhs: ExprId, rhs: ExprId, label: &'static str) -> ExprId {
        #[cfg(debug_assertions)]
        self.allocation_log.push(label);

        self.expr_builder.mul(lhs, rhs)
    }

    /// Divide two expressions.
    ///
    /// Cost: 1 row in Mul table + 1 row in witness table (encoded as rhs * out = lhs).
    pub fn div(&mut self, lhs: ExprId, rhs: ExprId) -> ExprId {
        self.alloc_div(lhs, rhs, "div")
    }

    /// Divide two expressions with a descriptive label.
    ///
    /// Cost: 1 row in Mul table + 1 row in witness table.
    #[allow(unused_variables)]
    pub fn alloc_div(&mut self, lhs: ExprId, rhs: ExprId, label: &'static str) -> ExprId {
        #[cfg(debug_assertions)]
        self.allocation_log.push(label);

        self.expr_builder.div(lhs, rhs)
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
        self.expr_builder.connect(a, b);
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
    pub(crate) fn push_non_primitive_op(
        &mut self,
        op_type: NonPrimitiveOpType,
        witness_exprs: Vec<ExprId>,
    ) -> NonPrimitiveOpId {
        let op_id = NonPrimitiveOpId(self.non_primitive_ops.len() as u32);
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
        let (
            primitive_ops,
            public_rows,
            _expr_to_widx,
            public_mappings,
            witness_count,
            lowered_non_primitive_ops,
        ) = self.lower()?;

        // Generate final circuit
        let mut circuit = Circuit::new(witness_count);

        circuit.primitive_ops = primitive_ops;
        circuit.non_primitive_ops = lowered_non_primitive_ops;
        circuit.public_rows = public_rows;
        circuit.public_flat_len = self.public_input_count();
        circuit.enabled_ops = self.enabled_ops;

        Ok((circuit, public_mappings))
    }

    #[allow(clippy::type_complexity)]
    pub fn lower(
        &mut self,
    ) -> Result<
        (
            Vec<Prim<F>>,
            Vec<WitnessId>,
            HashMap<ExprId, WitnessId>,
            HashMap<ExprId, WitnessId>,
            u32,
            Vec<NonPrimitiveOp>,
        ),
        CircuitBuilderError,
    > {
        let (expressions, pending_connects) =
            core::mem::take(&mut self.expr_builder).finish();

        let mut lowerer: CircuitLowerer<F> =
            CircuitLowerer::new(&pending_connects, self.public_input_count());

        lowerer.lower(
            expressions.nodes(),
            &self.non_primitive_ops,
            &self.enabled_ops,
        )
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::op::NonPrimitiveOpType;
    use crate::{CircuitError, MmcsOps};

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

        let leaf = (0..mmcs_config.ext_field_digest_elems)
            .map(|_| builder.add_public_input())
            .collect::<Vec<ExprId>>();
        let index = builder.add_public_input();
        let root = (0..mmcs_config.ext_field_digest_elems)
            .map(|_| builder.add_public_input())
            .collect::<Vec<ExprId>>();

        // not enabled yet
        let err = builder.add_mmcs_verify(&leaf, &index, &root).unwrap_err();
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

        let leaf = (0..mmcs_config.ext_field_digest_elems)
            .map(|_| builder.add_public_input())
            .collect::<Vec<ExprId>>();
        let index = builder.add_public_input();
        let root = (0..mmcs_config.ext_field_digest_elems)
            .map(|_| builder.add_public_input())
            .collect::<Vec<ExprId>>();

        builder.enable_mmcs(&mmcs_config);
        builder
            .add_mmcs_verify(&leaf, &index, &root)
            .expect("should be allowed");

        let circuit = builder.build().unwrap();
        assert_eq!(circuit.non_primitive_ops.len(), 1);
        match &circuit.non_primitive_ops[0] {
            NonPrimitiveOp::MmcsVerify { .. } => {}
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

        let leaf = (0..mmcs_config.ext_field_digest_elems)
            .map(|_| builder.add_public_input())
            .collect::<Vec<ExprId>>();
        let index = builder.add_public_input();
        let root = (0..mmcs_config.ext_field_digest_elems)
            .map(|_| builder.add_public_input())
            .collect::<Vec<ExprId>>();

        builder.enable_mmcs(&mmcs_config);
        builder
            .add_mmcs_verify(&leaf, &index, &root)
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
        assert_eq!(builder.allocation_log[0], "input a");
        assert_eq!(builder.allocation_log[1], "input b");
        assert_eq!(builder.allocation_log[2], "compute sum");
        assert_eq!(builder.allocation_log[3], "compute product");
        assert_eq!(builder.allocation_log[4], "unit constant");
    }

    #[test]
    #[cfg(debug_assertions)]
    fn test_allocation_log_unlabeled() {
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let a = builder.add_public_input();
        let b = builder.add_const(BabyBear::TWO);
        let _sum = builder.add(a, b);

        // Should all be logged with default labels
        assert_eq!(builder.allocation_log.len(), 3);
        assert_eq!(builder.allocation_log[0], "unlabeled");
        assert_eq!(builder.allocation_log[1], "const");
        assert_eq!(builder.allocation_log[2], "add");
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
        assert_eq!(builder.allocation_log[0], "one");
        assert_eq!(builder.allocation_log[1], "two");
    }
}
