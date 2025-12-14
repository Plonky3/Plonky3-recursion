use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};

use hashbrown::HashMap;
use p3_util::zip_eq::zip_eq;
use tracing::instrument;

use super::add::AddTraceBuilder;
use super::constant::ConstTraceBuilder;
use super::mul::MulTraceBuilder;
use super::public::PublicTraceBuilder;
use super::witness::WitnessTraceBuilder;
use super::{NonPrimitiveTrace, Traces};
use crate::circuit::Circuit;
use crate::op::{ExecutionContext, NonPrimitiveOpPrivateData, Op};
use crate::types::{NonPrimitiveOpId, WitnessId};
use crate::{CircuitError, CircuitField};

/// Circuit execution engine.
pub struct CircuitRunner<F> {
    /// Circuit specification.
    circuit: Circuit<F>,
    /// Witness values (None = unset, Some = computed).
    witness: Vec<Option<F>>,
    /// Private data for non-primitive operations (not on witness bus)
    non_primitive_op_private_data: Vec<Option<NonPrimitiveOpPrivateData<F>>>,
}

impl<F: CircuitField> CircuitRunner<F> {
    /// Creates circuit runner with empty witness storage.
    pub fn new(circuit: Circuit<F>) -> Self {
        let witness = vec![None; circuit.witness_count as usize];
        let non_primitive_op_private_data = vec![None; circuit.non_primitive_ops.len()];
        Self {
            circuit,
            witness,
            non_primitive_op_private_data,
        }
    }

    /// Sets public input values into witness table.
    pub fn set_public_inputs(&mut self, public_values: &[F]) -> Result<(), CircuitError> {
        if public_values.len() != self.circuit.public_flat_len {
            return Err(CircuitError::PublicInputLengthMismatch {
                expected: self.circuit.public_flat_len,
                got: public_values.len(),
            });
        }
        if self.circuit.public_rows.len() != self.circuit.public_flat_len {
            return Err(CircuitError::MissingPublicRowsMapping);
        }

        for (i, value) in public_values.iter().enumerate() {
            let widx = self.circuit.public_rows[i];
            self.set_witness(widx, *value)?;
        }

        Ok(())
    }

    /// Sets private data for a non-primitive operation.
    pub fn set_non_primitive_op_private_data(
        &mut self,
        op_id: NonPrimitiveOpId,
        private_data: NonPrimitiveOpPrivateData<F>,
    ) -> Result<(), CircuitError> {
        // Validate that the op_id exists in the circuit
        if op_id.0 as usize >= self.circuit.non_primitive_ops.len() {
            return Err(CircuitError::NonPrimitiveOpIdOutOfRange {
                op_id: op_id.0,
                max_ops: self.circuit.non_primitive_ops.len(),
            });
        }

        // Validate that the private data matches the operation type
        if let Op::NonPrimitiveOpWithExecutor { executor, .. } =
            &self.circuit.non_primitive_ops[op_id.0 as usize]
        {
            match (executor.op_type(), &private_data) {
                (
                    crate::op::NonPrimitiveOpType::PoseidonPerm,
                    NonPrimitiveOpPrivateData::PoseidonPerm(_),
                ) => {
                    // ok
                }
            }
        }

        // Disallow double-setting private data
        if self.non_primitive_op_private_data[op_id.0 as usize].is_some()
            && let Op::NonPrimitiveOpWithExecutor { executor, .. } =
                &self.circuit.non_primitive_ops[op_id.0 as usize]
        {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                op: executor.op_type().clone(),
                operation_index: op_id,
                expected: "private data not previously set".to_string(),
                got: "already set".to_string(),
            });
        }

        // Store private data for this operation
        self.non_primitive_op_private_data[op_id.0 as usize] = Some(private_data);
        Ok(())
    }

    /// Run the circuit and generate traces
    #[instrument(skip_all)]
    pub fn run(mut self) -> Result<Traces<F>, CircuitError> {
        // Step 1: Execute primitives to fill witness vector
        self.execute_primitives()?;

        // Step 2: Execute non-primitives to fill remaining witness vector
        self.execute_non_primitives()?;

        // Step 3: Delegate to trace builders for each table
        let witness_trace = WitnessTraceBuilder::new(&self.witness).build()?;
        let const_trace = ConstTraceBuilder::new(&self.circuit.primitive_ops).build()?;
        let public_trace =
            PublicTraceBuilder::new(&self.circuit.primitive_ops, &self.witness).build()?;
        let add_trace = AddTraceBuilder::new(&self.circuit.primitive_ops, &self.witness).build()?;
        let mul_trace = MulTraceBuilder::new(&self.circuit.primitive_ops, &self.witness).build()?;

        let mut non_primitive_traces: HashMap<&'static str, Box<dyn NonPrimitiveTrace<F>>> =
            HashMap::new();
        for generator in self.circuit.non_primitive_trace_generators.values() {
            if let Some(trace) = generator(
                &self.circuit,
                &self.witness,
                &self.non_primitive_op_private_data,
            )? {
                let id = trace.id();
                non_primitive_traces.insert(id, trace);
            }
        }

        Ok(Traces {
            witness_trace,
            const_trace,
            public_trace,
            add_trace,
            mul_trace,
            non_primitive_traces,
        })
    }

    /// Executes primitive operations to populate witness table.
    ///
    /// Operations run forward or backward depending on known operands.
    fn execute_primitives(&mut self) -> Result<(), CircuitError> {
        // Clone primitive operations to avoid borrowing issues
        let primitive_ops = self.circuit.primitive_ops.clone();

        for prim in primitive_ops {
            match prim {
                Op::Const { out, val } => {
                    self.set_witness(out, val)?;
                }
                Op::Public { out, public_pos: _ } => {
                    // Public inputs should already be set
                    if self.witness[out.0 as usize].is_none() {
                        return Err(CircuitError::PublicInputNotSet { witness_id: out });
                    }
                }
                Op::Add { a, b, out } => {
                    let a_val = self.get_witness(a)?;
                    if let Ok(b_val) = self.get_witness(b) {
                        let result = a_val + b_val;
                        self.set_witness(out, result)?;
                    } else {
                        let out_val = self.get_witness(out)?;
                        let b_val = out_val - a_val;
                        self.set_witness(b, b_val)?;
                    }
                }
                Op::Mul { a, b, out } => {
                    // Mul is used to represent either `Mul` or `Div` operations.
                    // We determine which based on which inputs are set.
                    let a_val = self.get_witness(a)?;
                    if let Ok(b_val) = self.get_witness(b) {
                        let result = a_val * b_val;
                        self.set_witness(out, result)?;
                    } else {
                        let result_val = self.get_witness(out)?;
                        let a_inv = a_val.try_inverse().ok_or(CircuitError::DivisionByZero)?;
                        let b_val = result_val * a_inv;
                        self.set_witness(b, b_val)?;
                    }
                }
                Op::Unconstrained {
                    inputs,
                    outputs,
                    filler,
                } => {
                    let inputs_val = inputs
                        .iter()
                        .map(|&input| self.get_witness(input))
                        .collect::<Result<Vec<F>, _>>()?;
                    let outputs_val = filler.compute_outputs(inputs_val)?;

                    for (&output, &output_val) in zip_eq(
                        outputs.iter(),
                        outputs_val.iter(),
                        CircuitError::UnconstrainedOpInputLengthMismatch {
                            op: "equal to".to_string(),
                            expected: outputs.len(),
                            got: outputs_val.len(),
                        },
                    )? {
                        self.set_witness(output, output_val)?;
                    }
                }
                Op::NonPrimitiveOpWithExecutor { .. } => {
                    // Handled separately in execute_non_primitives
                }
            }
        }
        Ok(())
    }

    /// Execute all non-primitive operations to fill remaining witness vector
    fn execute_non_primitives(&mut self) -> Result<(), CircuitError> {
        // Clone primitive operations to avoid borrowing issues
        let non_primitive_ops = self.circuit.non_primitive_ops.clone();

        // Global chaining state for Poseidon permutation
        let mut last_poseidon: Option<[F; 4]> = None;

        for op in non_primitive_ops {
            let Op::NonPrimitiveOpWithExecutor {
                inputs,
                outputs,
                executor,
                op_id,
            } = op
            else {
                continue;
            };

            let mut ctx = ExecutionContext::new(
                &mut self.witness,
                &self.non_primitive_op_private_data,
                &self.circuit.enabled_ops,
                op_id,
                &mut last_poseidon,
            );

            executor.execute(&inputs, &outputs, &mut ctx)?;
        }

        Ok(())
    }

    /// Gets witness value by ID.
    fn get_witness(&self, widx: WitnessId) -> Result<F, CircuitError> {
        self.witness
            .get(widx.0 as usize)
            .and_then(|opt| opt.as_ref())
            .cloned()
            .ok_or(CircuitError::WitnessNotSet { witness_id: widx })
    }

    /// Sets witness value by ID.
    fn set_witness(&mut self, widx: WitnessId, value: F) -> Result<(), CircuitError> {
        if widx.0 as usize >= self.witness.len() {
            return Err(CircuitError::WitnessIdOutOfBounds { witness_id: widx });
        }

        // Check for conflicting reassignment
        if let Some(existing_value) = self.witness[widx.0 as usize] {
            if existing_value != value {
                return Err(CircuitError::WitnessConflict {
                    witness_id: widx,
                    existing: format!("{existing_value:?}"),
                    new: format!("{value:?}"),
                });
            }
        } else {
            self.witness[widx.0 as usize] = Some(value);
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    extern crate std;

    use p3_baby_bear::BabyBear;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
    use tracing_forest::ForestLayer;
    use tracing_forest::util::LevelFilter;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{EnvFilter, Registry};

    use crate::ExprId;
    use crate::builder::CircuitBuilder;
    use crate::op::WitnessHintsFiller;
    use crate::types::WitnessId;

    #[test]
    fn test_table_generation_basic() {
        let mut builder = CircuitBuilder::new();

        // Simple test: x + 5 = result
        let x = builder.add_public_input();
        let c5 = builder.add_const(BabyBear::from_u64(5));
        let _result = builder.add(x, c5);

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();

        // Set public input: x = 3
        runner.set_public_inputs(&[BabyBear::from_u64(3)]).unwrap();

        let traces = runner.run().unwrap();

        // Check witness trace
        assert_eq!(
            traces.witness_trace.index.len(),
            traces.witness_trace.values.len()
        );

        // Check that we have const trace entries
        assert!(!traces.const_trace.values.is_empty());

        // Check that we have public trace entries
        assert!(!traces.public_trace.values.is_empty());

        // Check that we have add trace entries
        assert!(!traces.add_trace.lhs_values.is_empty());
    }

    fn init_logger() {
        let env_filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();

        Registry::default()
            .with(env_filter)
            .with(ForestLayer::default())
            .init();
    }

    #[derive(Debug, Clone)]
    /// The hint defined by x in an equation a*x - b = 0
    struct XHint {
        inputs: Vec<ExprId>,
    }

    impl XHint {
        pub fn new(a: ExprId, b: ExprId) -> Self {
            Self { inputs: vec![a, b] }
        }
    }

    impl<F: Field> WitnessHintsFiller<F> for XHint {
        fn inputs(&self) -> &[ExprId] {
            &self.inputs
        }

        fn n_outputs(&self) -> usize {
            1
        }

        fn compute_outputs(&self, inputs_val: Vec<F>) -> Result<Vec<F>, crate::CircuitError> {
            if inputs_val.len() != self.inputs.len() {
                Err(crate::CircuitError::UnconstrainedOpInputLengthMismatch {
                    op: "equal to".to_string(),
                    expected: self.inputs.len(),
                    got: inputs_val.len(),
                })
            } else {
                let a = inputs_val[0];
                let b = inputs_val[1];
                let inv_a = a.try_inverse().ok_or(CircuitError::DivisionByZero)?;
                let x = b * inv_a;
                Ok(vec![x])
            }
        }
    }

    #[test]
    // Proves that we know x such that 37 * x - 111 = 0
    fn test_toy_example_37_times_x_minus_111() {
        init_logger();
        let mut builder = CircuitBuilder::new();

        let c37 = builder.add_const(BabyBear::from_u64(37));
        let c111 = builder.add_const(BabyBear::from_u64(111));
        let x_hint = XHint::new(c37, c111);
        let x = builder.alloc_witness_hints(x_hint, "x")[0];

        let mul_result = builder.mul(c37, x);
        let sub_result = builder.sub(mul_result, c111);
        builder.assert_zero(sub_result);

        let circuit = builder.build().unwrap();

        let witness_count = circuit.witness_count;
        let runner = circuit.runner();

        let traces = runner.run().unwrap();

        traces.dump_primitive_traces_log();

        // Verify trace structure
        assert_eq!(traces.witness_trace.index.len(), witness_count as usize);

        // Should have constants: 0, 37, 111
        assert_eq!(traces.const_trace.values.len(), 3);

        // Should have no public input
        assert!(traces.public_trace.values.is_empty());

        // Should store the value of the hint (3) at `WitnessId(3)``
        assert_eq!(traces.witness_trace.index[3], WitnessId(3));
        assert_eq!(traces.witness_trace.values[3], BabyBear::from_usize(3));

        // Should have one mul operation: 37 * x
        assert_eq!(traces.mul_trace.lhs_values.len(), 1);

        // Encoded subtraction lands in the add table (result + rhs = lhs).
        assert_eq!(traces.add_trace.lhs_values.len(), 1);
        assert_eq!(traces.add_trace.lhs_index, vec![WitnessId(2)]);
        assert_eq!(traces.add_trace.rhs_index, vec![WitnessId(0)]);
        assert_eq!(traces.add_trace.result_index, vec![WitnessId(4)]);
    }

    #[test]
    fn test_extension_field_support() {
        type ExtField = BinomialExtensionField<BabyBear, 4>;

        let mut builder = CircuitBuilder::new();

        // Test extension field operations: x + y * z
        let x = builder.add_public_input();
        let y = builder.add_public_input();
        let z = builder.add_public_input();

        let yz = builder.mul(y, z);
        let _result = builder.add(x, yz);

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();

        // Set public inputs to genuine extension field values with ALL non-zero coefficients
        let x_val = ExtField::from_basis_coefficients_slice(&[
            BabyBear::from_u64(1), // a0
            BabyBear::from_u64(2), // a1
            BabyBear::from_u64(3), // a2
            BabyBear::from_u64(4), // a3
        ])
        .unwrap();
        let y_val = ExtField::from_basis_coefficients_slice(&[
            BabyBear::from_u64(5), // b0
            BabyBear::from_u64(6), // b1
            BabyBear::from_u64(7), // b2
            BabyBear::from_u64(8), // b3
        ])
        .unwrap();
        let z_val = ExtField::from_basis_coefficients_slice(&[
            BabyBear::from_u64(9),  // c0
            BabyBear::from_u64(10), // c1
            BabyBear::from_u64(11), // c2
            BabyBear::from_u64(12), // c3
        ])
        .unwrap();

        runner.set_public_inputs(&[x_val, y_val, z_val]).unwrap();
        let traces = runner.run().unwrap();

        // Verify extension field traces were generated correctly
        assert_eq!(traces.public_trace.values.len(), 3);
        assert_eq!(traces.public_trace.values[0], x_val);
        assert_eq!(traces.public_trace.values[1], y_val);
        assert_eq!(traces.public_trace.values[2], z_val);

        // Should have one mul and one add operation
        assert_eq!(traces.mul_trace.lhs_values.len(), 1);
        assert_eq!(traces.add_trace.lhs_values.len(), 1);

        // Verify mul operation: y * z with genuine extension field multiplication
        let expected_yz = y_val * z_val;
        assert_eq!(traces.mul_trace.lhs_values[0], y_val);
        assert_eq!(traces.mul_trace.rhs_values[0], z_val);
        assert_eq!(traces.mul_trace.result_values[0], expected_yz);

        // Verify add operation: x + yz with genuine extension field addition
        let expected_result = x_val + expected_yz;
        assert_eq!(traces.add_trace.lhs_values[0], x_val);
        assert_eq!(traces.add_trace.rhs_values[0], expected_yz);
        assert_eq!(traces.add_trace.result_values[0], expected_result);
    }
}
