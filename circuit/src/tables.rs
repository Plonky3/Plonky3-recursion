use alloc::vec::Vec;
use alloc::{format, vec};

use hashbrown::HashMap;
use tracing::instrument;

use crate::circuit::Circuit;
use crate::op::{ExecutionContext, NonPrimitiveOpPrivateData, Op};
use crate::types::WitnessId;
use crate::{CircuitError, CircuitField, ExprId};

mod mmcs;
pub use mmcs::{MmcsPathTrace, MmcsPrivateData, MmcsTrace};

/// Execution traces for all tables
#[derive(Debug, Clone)]
pub struct Traces<F> {
    /// Witness table (central bus)
    pub witness_trace: WitnessTrace<F>,
    /// Constant table
    pub const_trace: ConstTrace<F>,
    /// Public input table
    pub public_trace: PublicTrace<F>,
    /// Add operation table
    pub add_trace: AddTrace<F>,
    /// Mul operation table
    pub mul_trace: MulTrace<F>,
    /// Mmcs verification table
    pub mmcs_trace: MmcsTrace<F>,
}

/// Central witness table with preprocessed index column
#[derive(Debug, Clone)]
pub struct WitnessTrace<F> {
    /// Preprocessed index column (WitnessId(0), WitnessId(1), WitnessId(2), ...)
    pub index: Vec<WitnessId>,
    /// Witness values
    pub values: Vec<F>,
}

/// Constant table
#[derive(Debug, Clone)]
pub struct ConstTrace<F> {
    /// Preprocessed index column (equals the WitnessId this row binds)
    pub index: Vec<WitnessId>,
    /// Constant values
    pub values: Vec<F>,
}

/// Public input table
#[derive(Debug, Clone)]
pub struct PublicTrace<F> {
    /// Preprocessed index column (equals the WitnessId of that public)
    pub index: Vec<WitnessId>,
    /// Public input values
    pub values: Vec<F>,
}

/// Add operation table
#[derive(Debug, Clone)]
pub struct AddTrace<F> {
    /// Left operand values
    pub lhs_values: Vec<F>,
    /// Left operand indices (references witness bus)
    pub lhs_index: Vec<WitnessId>,
    /// Right operand values
    pub rhs_values: Vec<F>,
    /// Right operand indices (references witness bus)
    pub rhs_index: Vec<WitnessId>,
    /// Result values
    pub result_values: Vec<F>,
    /// Result indices (references witness bus)
    pub result_index: Vec<WitnessId>,
}

/// Mul operation table
#[derive(Debug, Clone)]
pub struct MulTrace<F> {
    /// Left operand values
    pub lhs_values: Vec<F>,
    /// Left operand indices (references witness bus)
    pub lhs_index: Vec<WitnessId>,
    /// Right operand values
    pub rhs_values: Vec<F>,
    /// Right operand indices (references witness bus)
    pub rhs_index: Vec<WitnessId>,
    /// Result values
    pub result_values: Vec<F>,
    /// Result indices (references witness bus)
    pub result_index: Vec<WitnessId>,
}

/// Circuit runner that executes circuits and generates execution traces
///
/// This struct manages the runtime execution of a `Circuit` specification:
/// - Maintains a mutable witness table for intermediate values
/// - Accepts public input values and private data for complex operations
/// - Runs all operations to generate execution traces for proving
///
/// Created from a `Circuit` via `.runner()`, this provides the execution
/// layer between the immutable constraint specification and trace generation.
pub struct CircuitRunner<F> {
    circuit: Circuit<F>,
    witness: Vec<Option<F>>,
    /// Private data for complex operations (not on witness bus)
    non_primitive_op_private_data: HashMap<ExprId, Option<NonPrimitiveOpPrivateData<F>>>,
}

impl<F: CircuitField> CircuitRunner<F> {
    /// Create a new prover instance
    pub fn new(circuit: Circuit<F>) -> Self {
        let witness = vec![None; circuit.witness_count as usize];
        let non_primitive_op_private_data = HashMap::new();
        Self {
            circuit,
            witness,
            non_primitive_op_private_data,
        }
    }

    /// Set public inputs according to Circuit.public_rows mapping
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

    /// Set private data for a complex operation
    pub fn set_non_primitive_op_private_data(
        &mut self,
        expr_id: ExprId,
        private_data: NonPrimitiveOpPrivateData<F>,
    ) -> Result<(), CircuitError> {
        self.non_primitive_op_private_data
            .insert(expr_id, Some(private_data));
        Ok(())
    }

    /// Run the circuit and generate traces
    #[instrument(skip_all)]
    pub fn run(mut self) -> Result<Traces<F>, CircuitError> {
        // Step 1: Execute primitives to fill witness vector
        self.execute_primitives()?;

        // Step 1: Execute non-primitives to fill remaining witness vector
        self.execute_non_primitives()?;

        // Step 2: Generate all table traces
        let witness_trace = self.generate_witness_trace()?;
        let const_trace = self.generate_const_trace()?;
        let public_trace = self.generate_public_trace()?;
        let add_trace = self.generate_add_trace()?;
        let mul_trace = self.generate_mul_trace()?;
        let mmcs_trace = self.generate_mmcs_trace()?;

        Ok(Traces {
            witness_trace,
            const_trace,
            public_trace,
            add_trace,
            mul_trace,
            mmcs_trace,
        })
    }

    /// Execute all primitive operations to fill witness vector
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
                Op::NonPrimitiveOpWithExecutor {
                    inputs: _,
                    outputs: _,
                    executor: _,
                    expr_id: _,
                } => { // Handled separately }
                }
            }
        }
        Ok(())
    }

    /// Execute all non-primitive operations to fill remaining witness vector
    fn execute_non_primitives(&mut self) -> Result<(), CircuitError> {
        // Clone primitive operations to avoid borrowing issues
        let non_primitive_ops = self.circuit.non_primitive_ops.clone();

        for op in non_primitive_ops {
            let Op::NonPrimitiveOpWithExecutor {
                inputs,
                outputs,
                executor,
                expr_id,
            } = op
            else {
                continue;
            };

            let mut ctx = ExecutionContext::new(
                &mut self.witness,
                &self.non_primitive_op_private_data,
                &self.circuit.enabled_ops,
                expr_id,
            );

            executor.execute(&inputs, &outputs, &mut ctx)?;
        }

        Ok(())
    }

    fn get_witness(&self, widx: WitnessId) -> Result<F, CircuitError> {
        self.witness
            .get(widx.0 as usize)
            .and_then(|opt| opt.as_ref())
            .cloned()
            .ok_or(CircuitError::WitnessNotSet { witness_id: widx })
    }

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

    fn generate_witness_trace(&self) -> Result<WitnessTrace<F>, CircuitError> {
        let mut index = Vec::new();
        let mut values = Vec::new();

        for (i, witness_opt) in self.witness.iter().enumerate() {
            match witness_opt {
                Some(value) => {
                    index.push(WitnessId(i as u32));
                    values.push(*value);
                }
                None => {
                    return Err(CircuitError::WitnessNotSetForIndex { index: i });
                }
            }
        }

        Ok(WitnessTrace { index, values })
    }

    fn generate_const_trace(&self) -> Result<ConstTrace<F>, CircuitError> {
        let mut index = Vec::new();
        let mut values = Vec::new();

        // Collect all constants from primitive operations
        for prim in &self.circuit.primitive_ops {
            if let Op::Const { out, val } = prim {
                index.push(*out);
                values.push(*val);
            }
        }

        Ok(ConstTrace { index, values })
    }

    fn generate_public_trace(&self) -> Result<PublicTrace<F>, CircuitError> {
        let mut index = Vec::new();
        let mut values = Vec::new();

        // Collect all public inputs from primitive operations
        for prim in &self.circuit.primitive_ops {
            if let Op::Public { out, public_pos: _ } = prim {
                index.push(*out);
                let value = self.get_witness(*out)?;
                values.push(value);
            }
        }

        Ok(PublicTrace { index, values })
    }

    fn generate_add_trace(&self) -> Result<AddTrace<F>, CircuitError> {
        let mut lhs_values = Vec::new();
        let mut lhs_index = Vec::new();
        let mut rhs_values = Vec::new();
        let mut rhs_index = Vec::new();
        let mut result_values = Vec::new();
        let mut result_index = Vec::new();

        for prim in &self.circuit.primitive_ops {
            if let Op::Add { a, b, out } = prim {
                lhs_values.push(self.get_witness(*a)?);
                lhs_index.push(*a);
                rhs_values.push(self.get_witness(*b)?);
                rhs_index.push(*b);
                result_values.push(self.get_witness(*out)?);
                result_index.push(*out);
            }
        }

        Ok(AddTrace {
            lhs_values,
            lhs_index,
            rhs_values,
            rhs_index,
            result_values,
            result_index,
        })
    }

    fn generate_mul_trace(&self) -> Result<MulTrace<F>, CircuitError> {
        let mut lhs_values = Vec::new();
        let mut lhs_index = Vec::new();
        let mut rhs_values = Vec::new();
        let mut rhs_index = Vec::new();
        let mut result_values = Vec::new();
        let mut result_index = Vec::new();

        for prim in &self.circuit.primitive_ops {
            if let Op::Mul { a, b, out } = prim {
                lhs_values.push(self.get_witness(*a)?);
                lhs_index.push(*a);
                rhs_values.push(self.get_witness(*b)?);
                rhs_index.push(*b);
                result_values.push(self.get_witness(*out)?);
                result_index.push(*out);
            }
        }

        Ok(MulTrace {
            lhs_values,
            lhs_index,
            rhs_values,
            rhs_index,
            result_values,
            result_index,
        })
    }

    fn generate_mmcs_trace(&self) -> Result<MmcsTrace<F>, CircuitError> {
        mmcs::generate_mmcs_trace(&self.circuit, &self.non_primitive_op_private_data)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use alloc::vec;
    use std::println;

    use p3_baby_bear::BabyBear;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};

    use crate::builder::CircuitBuilder;
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

    #[test]
    // Proves that we know x such that 37 * x - 111 = 0
    fn test_toy_example_37_times_x_minus_111() {
        let mut builder = CircuitBuilder::new();

        let x = builder.add_public_input();
        let c37 = builder.add_const(BabyBear::from_u64(37));
        let c111 = builder.add_const(BabyBear::from_u64(111));

        let mul_result = builder.mul(c37, x);
        let sub_result = builder.sub(mul_result, c111);
        builder.assert_zero(sub_result);

        let circuit = builder.build().unwrap();
        println!("=== CIRCUIT PRIMITIVE OPERATIONS ===");
        for (i, prim) in circuit.primitive_ops.iter().enumerate() {
            println!("{i}: {prim:?}");
        }

        let witness_count = circuit.witness_count;
        let mut runner = circuit.runner();

        // Set public input: x = 3 (should satisfy 37 * 3 - 111 = 0)
        runner.set_public_inputs(&[BabyBear::from_u64(3)]).unwrap();

        let traces = runner.run().unwrap();

        println!("\n=== WITNESS TRACE ===");
        for (i, (idx, val)) in traces
            .witness_trace
            .index
            .iter()
            .zip(traces.witness_trace.values.iter())
            .enumerate()
        {
            println!("Row {i}: WitnessId({idx}) = {val:?}");
        }

        println!("\n=== CONST TRACE ===");
        for (i, (idx, val)) in traces
            .const_trace
            .index
            .iter()
            .zip(traces.const_trace.values.iter())
            .enumerate()
        {
            println!("Row {i}: WitnessId({idx}) = {val:?}");
        }

        println!("\n=== PUBLIC TRACE ===");
        for (i, (idx, val)) in traces
            .public_trace
            .index
            .iter()
            .zip(traces.public_trace.values.iter())
            .enumerate()
        {
            println!("Row {i}: WitnessId({idx}) = {val:?}");
        }

        println!("\n=== MUL TRACE ===");
        for i in 0..traces.mul_trace.lhs_values.len() {
            println!(
                "Row {}: WitnessId({}) * WitnessId({}) -> WitnessId({}) | {:?} * {:?} -> {:?}",
                i,
                traces.mul_trace.lhs_index[i],
                traces.mul_trace.rhs_index[i],
                traces.mul_trace.result_index[i],
                traces.mul_trace.lhs_values[i],
                traces.mul_trace.rhs_values[i],
                traces.mul_trace.result_values[i]
            );
        }

        println!("\n=== ADD TRACE ===");
        for i in 0..traces.add_trace.lhs_values.len() {
            println!(
                "Row {}: WitnessId({}) + WitnessId({}) -> WitnessId({}) | {:?} + {:?} -> {:?}",
                i,
                traces.add_trace.lhs_index[i],
                traces.add_trace.rhs_index[i],
                traces.add_trace.result_index[i],
                traces.add_trace.lhs_values[i],
                traces.add_trace.rhs_values[i],
                traces.add_trace.result_values[i]
            );
        }

        // Verify trace structure
        assert_eq!(traces.witness_trace.index.len(), witness_count as usize);

        // Should have constants: 0, 37, 111
        assert_eq!(traces.const_trace.values.len(), 3);

        // Should have one public input
        assert_eq!(traces.public_trace.values.len(), 1);
        assert_eq!(traces.public_trace.values[0], BabyBear::from_u64(3));

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
