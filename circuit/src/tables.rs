use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};

use p3_field::Field;

use crate::circuit::Circuit;
use crate::op::{NonPrimitiveOpPrivateData, Prim};
use crate::types::{NonPrimitiveOpId, WitnessId};

/// Errors that can occur during circuit execution and trace generation.
#[derive(Debug)]
pub enum CircuitError {
    /// Public input length mismatch.
    PublicInputLengthMismatch { expected: usize, got: usize },
    /// Circuit missing public_rows mapping.
    MissingPublicRowsMapping,
    /// NonPrimitiveOpId out of range.
    NonPrimitiveOpIdOutOfRange { op_id: u32, max_ops: usize },
    /// Public input not set for a WitnessId.
    PublicInputNotSet { witness_id: u32 },
    /// Witness not set for a WitnessId.
    WitnessNotSet { witness_id: u32 },
    /// WitnessId out of bounds.
    WitnessIdOutOfBounds { witness_id: u32 },
    /// Witness conflict: trying to reassign to a different value.
    WitnessConflict {
        witness_id: u32,
        existing: String,
        new: String,
    },
    /// Witness not set for an index during trace generation.
    WitnessNotSetForIndex { index: usize },
    /// Non-primitive op attempted to read a witness value that was not set.
    NonPrimitiveOpWitnessNotSet { operation_index: usize },
    /// Missing private data for a non-primitive operation.
    NonPrimitiveOpMissingPrivateData { operation_index: usize },
    /// Division by zero encountered.
    DivisionByZero,
    /// Invalid bit value in SampleBits bit decomposition (must be 0 or 1).
    InvalidBitValue { input_witness_id: u32, bit_value: String },
    /// Bit decomposition doesn't reconstruct to the input value.
    BitDecompositionMismatch {
        input_witness_id: u32,
        expected: String,
        reconstructed: String
    },
}

impl core::fmt::Display for CircuitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CircuitError::PublicInputLengthMismatch { expected, got } => {
                write!(
                    f,
                    "Public input length mismatch: expected {expected}, got {got}"
                )
            }
            CircuitError::MissingPublicRowsMapping => {
                write!(f, "Circuit missing public_rows mapping")
            }
            CircuitError::NonPrimitiveOpIdOutOfRange { op_id, max_ops } => {
                write!(
                    f,
                    "NonPrimitiveOpId {op_id} out of range (circuit has {max_ops} complex ops)"
                )
            }
            CircuitError::PublicInputNotSet { witness_id } => {
                write!(f, "Public input not set for WitnessId({witness_id})")
            }
            CircuitError::WitnessNotSet { witness_id } => {
                write!(f, "Witness not set for WitnessId({witness_id})")
            }
            CircuitError::WitnessIdOutOfBounds { witness_id } => {
                write!(f, "WitnessId({witness_id}) out of bounds")
            }
            CircuitError::WitnessConflict {
                witness_id,
                existing,
                new,
            } => {
                write!(
                    f,
                    "Witness conflict: WitnessId({witness_id}) already set to {existing}, cannot reassign to {new}"
                )
            }
            CircuitError::WitnessNotSetForIndex { index } => {
                write!(f, "Witness not set for index {index}")
            }
            CircuitError::NonPrimitiveOpWitnessNotSet { operation_index } => {
                write!(
                    f,
                    "Witness value not set for non-primitive operation {operation_index}"
                )
            }
            CircuitError::NonPrimitiveOpMissingPrivateData { operation_index } => {
                write!(
                    f,
                    "Missing private data for non-primitive operation {operation_index}"
                )
            }
            CircuitError::DivisionByZero => {
                write!(f, "Division by zero encountered")
            }
            CircuitError::InvalidBitValue { input_witness_id, bit_value } => {
                write!(f, "Invalid bit value in SampleBits bit decomposition for WitnessId({input_witness_id}): {bit_value} (must be 0 or 1)")
            }
            CircuitError::BitDecompositionMismatch { input_witness_id, expected, reconstructed } => {
                write!(f, "Bit decomposition for WitnessId({input_witness_id}) doesn't match input: expected {expected}, reconstructed {reconstructed}")
            }
        }
    }
}

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
    /// Fake Merkle verification table
    pub fake_merkle_trace: FakeMerkleTrace<F>,
    /// Sample bits operation table
    pub sample_bits_trace: SampleBitsTrace<F>,
}

/// Central witness table with transparent index column
#[derive(Debug, Clone)]
pub struct WitnessTrace<F> {
    /// Transparent index column (0, 1, 2, ...)
    pub index: Vec<u32>,
    /// Witness values
    pub values: Vec<F>,
}

/// Constant table
#[derive(Debug, Clone)]
pub struct ConstTrace<F> {
    /// Transparent index column (equals the WitnessId this row binds)
    pub index: Vec<u32>,
    /// Constant values
    pub values: Vec<F>,
}

/// Public input table
#[derive(Debug, Clone)]
pub struct PublicTrace<F> {
    /// Transparent index column (equals the WitnessId of that public)
    pub index: Vec<u32>,
    /// Public input values
    pub values: Vec<F>,
}

/// Add operation table
#[derive(Debug, Clone)]
pub struct AddTrace<F> {
    /// Left operand values
    pub lhs_values: Vec<F>,
    /// Left operand indices
    pub lhs_index: Vec<u32>,
    /// Right operand values
    pub rhs_values: Vec<F>,
    /// Right operand indices
    pub rhs_index: Vec<u32>,
    /// Result values
    pub result_values: Vec<F>,
    /// Result indices
    pub result_index: Vec<u32>,
}

/// Mul operation table
#[derive(Debug, Clone)]
pub struct MulTrace<F> {
    /// Left operand values
    pub lhs_values: Vec<F>,
    /// Left operand indices
    pub lhs_index: Vec<u32>,
    /// Right operand values
    pub rhs_values: Vec<F>,
    /// Right operand indices
    pub rhs_index: Vec<u32>,
    /// Result values
    pub result_values: Vec<F>,
    /// Result indices
    pub result_index: Vec<u32>,
}

/// Fake Merkle verification table (simplified: single field elements)
#[derive(Debug, Clone)]
pub struct FakeMerkleTrace<F> {
    /// Left operand values (current hash)
    pub left_values: Vec<F>,
    /// Left operand indices
    pub left_index: Vec<u32>,
    /// Right operand values (sibling hash)
    pub right_values: Vec<F>,
    /// Right operand indices (not on witness bus - private)
    pub right_index: Vec<u32>,
    /// Result values (computed parent hash)
    pub result_values: Vec<F>,
    /// Result indices
    pub result_index: Vec<u32>,
    /// Path direction bits (0 = left, 1 = right) - private
    pub path_directions: Vec<u32>,
}

/// Sample bits operation table for FRI challenger integration
#[derive(Debug, Clone)]
pub struct SampleBitsTrace<F> {
    /// Input field element values (from challenger sampling)
    pub input_values: Vec<F>,
    /// Input indices (pointing to witness bus)
    pub input_index: Vec<u32>,
    /// Output values (extracted bits as field elements)
    pub output_values: Vec<F>,
    /// Output indices (pointing to witness bus)
    pub output_index: Vec<u32>,
    /// Number of bits extracted for each operation (private)
    pub num_bits: Vec<u32>,
    /// Bit decomposition witness for each input (private, flattened)
    pub bit_decompositions: Vec<F>,
    /// Lengths of each bit decomposition (private, for parsing bit_decompositions)
    pub bit_decomposition_lengths: Vec<u32>,
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
    non_primitive_op_private_data: Vec<Option<NonPrimitiveOpPrivateData<F>>>,
}

impl<
    F: Clone
        + Default
        + core::ops::Add<Output = F>
        + core::ops::Sub<Output = F>
        + core::ops::Mul<Output = F>
        + PartialEq
        + core::fmt::Debug
        + Field,
> CircuitRunner<F>
{
    /// Create a new prover instance
    pub fn new(circuit: Circuit<F>) -> Self {
        let witness = vec![None; circuit.witness_count as usize];
        let non_primitive_op_private_data = vec![None; circuit.non_primitive_ops.len()];
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
        let non_primitive_op = &self.circuit.non_primitive_ops[op_id.0 as usize];
        match (non_primitive_op, &private_data) {
            (
                crate::op::NonPrimitiveOp::FakeMerkleVerify { .. },
                NonPrimitiveOpPrivateData::FakeMerkleVerify(_),
            ) => {
                // Type match - good!
            }
            (
                crate::op::NonPrimitiveOp::SampleBits { .. },
                NonPrimitiveOpPrivateData::SampleBits(_),
            ) => {
                // Type match - good!
            }
            _ => {
                return Err(CircuitError::NonPrimitiveOpIdOutOfRange {
                    op_id: op_id.0,
                    max_ops: self.circuit.non_primitive_ops.len(),
                });
            }
        }

        self.non_primitive_op_private_data[op_id.0 as usize] = Some(private_data);
        Ok(())
    }

    /// Run the circuit and generate traces
    pub fn run(mut self) -> Result<Traces<F>, CircuitError> {
        // Step 1: Execute primitives to fill witness vector
        self.execute_primitives()?;

        // Step 2: Generate all table traces
        let witness_trace = self.generate_witness_trace()?;
        let const_trace = self.generate_const_trace()?;
        let public_trace = self.generate_public_trace()?;
        let add_trace = self.generate_add_trace()?;
        let mul_trace = self.generate_mul_trace()?;
        let fake_merkle_trace = self.generate_fake_merkle_trace()?;
        let sample_bits_trace = self.generate_sample_bits_trace()?;

        Ok(Traces {
            witness_trace,
            const_trace,
            public_trace,
            add_trace,
            mul_trace,
            fake_merkle_trace,
            sample_bits_trace,
        })
    }

    /// Execute all primitive operations to fill witness vector
    fn execute_primitives(&mut self) -> Result<(), CircuitError> {
        // Clone primitive operations to avoid borrowing issues
        let primitive_ops = self.circuit.primitive_ops.clone();

        for prim in primitive_ops {
            match prim {
                Prim::Const { out, val } => {
                    self.set_witness(out, val)?;
                }
                Prim::Public { out, public_pos: _ } => {
                    // Public inputs should already be set
                    if self.witness[out.0 as usize].is_none() {
                        return Err(CircuitError::PublicInputNotSet { witness_id: out.0 });
                    }
                }
                Prim::Add { a, b, out } => {
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
                Prim::Mul { a, b, out } => {
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
            }
        }

        Ok(())
    }

    fn get_witness(&self, widx: WitnessId) -> Result<F, CircuitError> {
        self.witness
            .get(widx.0 as usize)
            .and_then(|opt| opt.as_ref())
            .cloned()
            .ok_or(CircuitError::WitnessNotSet { witness_id: widx.0 })
    }

    fn set_witness(&mut self, widx: WitnessId, value: F) -> Result<(), CircuitError> {
        if widx.0 as usize >= self.witness.len() {
            return Err(CircuitError::WitnessIdOutOfBounds { witness_id: widx.0 });
        }

        // Check for conflicting reassignment
        if let Some(existing_value) = self.witness[widx.0 as usize] {
            if existing_value != value {
                return Err(CircuitError::WitnessConflict {
                    witness_id: widx.0,
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
                    index.push(i as u32);
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
            if let Prim::Const { out, val } = prim {
                index.push(out.0);
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
            if let Prim::Public { out, public_pos: _ } = prim {
                index.push(out.0);
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
            if let Prim::Add { a, b, out } = prim {
                lhs_values.push(self.get_witness(*a)?);
                lhs_index.push(a.0);
                rhs_values.push(self.get_witness(*b)?);
                rhs_index.push(b.0);
                result_values.push(self.get_witness(*out)?);
                result_index.push(out.0);
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
            if let Prim::Mul { a, b, out } = prim {
                lhs_values.push(self.get_witness(*a)?);
                lhs_index.push(a.0);
                rhs_values.push(self.get_witness(*b)?);
                rhs_index.push(b.0);
                result_values.push(self.get_witness(*out)?);
                result_index.push(out.0);
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

    fn generate_fake_merkle_trace(&mut self) -> Result<FakeMerkleTrace<F>, CircuitError> {
        let mut left_values = Vec::new();
        let mut left_index = Vec::new();
        let mut right_values = Vec::new();
        let mut right_index = Vec::new();
        let mut result_values = Vec::new();
        let mut result_index = Vec::new();
        let mut path_directions = Vec::new();

        // Process each complex operation by index to avoid borrowing conflicts
        for op_idx in 0..self.circuit.non_primitive_ops.len() {
            // Copy out leaf/root to end immutable borrow immediately
            let (leaf, root) = match &self.circuit.non_primitive_ops[op_idx] {
                crate::op::NonPrimitiveOp::FakeMerkleVerify { leaf, root } => (*leaf, *root),
                _ => continue, // Skip non-FakeMerkleVerify operations
            };

            // Clone private data option to avoid holding a borrow on self
            if let Some(Some(NonPrimitiveOpPrivateData::FakeMerkleVerify(private_data))) =
                self.non_primitive_op_private_data.get(op_idx).cloned()
            {
                let mut current_hash =
                    if let Some(val) = self.witness.get(leaf.0 as usize).and_then(|x| x.as_ref()) {
                        *val
                    } else {
                        return Err(CircuitError::NonPrimitiveOpWitnessNotSet {
                            operation_index: op_idx,
                        });
                    };

                // For each step in the Merkle path
                for (sibling_value, &direction) in private_data
                    .path_siblings
                    .iter()
                    .zip(private_data.path_directions.iter())
                {
                    // Current hash becomes left operand
                    left_values.push(current_hash);
                    left_index.push(leaf.0); // Points to witness bus

                    // Sibling becomes right operand (private data - not on witness bus)
                    right_values.push(*sibling_value);
                    right_index.push(0); // Not on witness bus - private data

                    // Compute parent hash (simple mock hash: left + right + direction)
                    let parent_hash = current_hash
                        + *sibling_value
                        + if direction {
                            F::from_u64(1)
                        } else {
                            F::from_u64(0)
                        };

                    result_values.push(parent_hash);
                    result_index.push(root.0); // Points to witness bus

                    path_directions.push(if direction { 1 } else { 0 });

                    // Update current hash for next iteration
                    current_hash = parent_hash;
                }

                // Root is computed; write back to the witness bus at root index
                self.set_witness(root, current_hash)?;
            } else {
                return Err(CircuitError::NonPrimitiveOpMissingPrivateData {
                    operation_index: op_idx,
                });
            }
        }

        Ok(FakeMerkleTrace {
            left_values,
            left_index,
            right_values,
            right_index,
            result_values,
            result_index,
            path_directions,
        })
    }

    fn generate_sample_bits_trace(&mut self) -> Result<SampleBitsTrace<F>, CircuitError> {
        let mut input_values = Vec::new();
        let mut input_index = Vec::new();
        let mut output_values = Vec::new();
        let mut output_index = Vec::new();
        let mut num_bits = Vec::new();
        let mut bit_decompositions = Vec::new();
        let mut bit_decomposition_lengths = Vec::new();

        // Process each SampleBits operation
        for op_idx in 0..self.circuit.non_primitive_ops.len() {
            // Extract input and output indices
            let (input, output) = match &self.circuit.non_primitive_ops[op_idx] {
                crate::op::NonPrimitiveOp::SampleBits { input, output } => (*input, *output),
                _ => continue, // Skip non-SampleBits operations
            };

            // Get private data for this operation
            if let Some(Some(crate::op::NonPrimitiveOpPrivateData::SampleBits(private_data))) =
                self.non_primitive_op_private_data.get(op_idx).cloned()
            {
                // Get input value from witness
                let input_value = if let Some(val) =
                    self.witness.get(input.0 as usize).and_then(|x| x.as_ref())
                {
                    *val
                } else {
                    return Err(CircuitError::NonPrimitiveOpWitnessNotSet {
                        operation_index: op_idx,
                    });
                };

                // Compute output value by extracting the lowest num_bits bits
                let output_value = self.compute_sample_bits(input_value, &private_data, input, output)?;

                // Store the computed output in the witness table
                self.set_witness(output, output_value)?;

                // Add to trace
                input_values.push(input_value);
                input_index.push(input.0);
                output_values.push(output_value);
                output_index.push(output.0);
                num_bits.push(private_data.num_bits as u32);

                // Add bit decomposition to flattened vector
                bit_decomposition_lengths.push(private_data.bit_decomposition.len() as u32);
                bit_decompositions.extend_from_slice(&private_data.bit_decomposition);
            } else {
                return Err(CircuitError::NonPrimitiveOpMissingPrivateData {
                    operation_index: op_idx,
                });
            }
        }

        Ok(SampleBitsTrace {
            input_values,
            input_index,
            output_values,
            output_index,
            num_bits,
            bit_decompositions,
            bit_decomposition_lengths,
        })
    }

    /// Compute the sample_bits operation: extract the lowest `num_bits` bits from input
    fn compute_sample_bits(
        &self,
        input: F,
        private_data: &crate::op::SampleBitsPrivateData<F>,
        input_witness_id: WitnessId,
        _output_witness_id: WitnessId,
    ) -> Result<F, CircuitError> {
        // Verify bit decomposition is correct
        let mut reconstructed = F::ZERO;
        let mut power_of_two = F::ONE;

        for &bit in &private_data.bit_decomposition {
            // Verify each bit is 0 or 1
            if bit != F::ZERO && bit != F::ONE {
                return Err(CircuitError::InvalidBitValue {
                    input_witness_id: input_witness_id.0,
                    bit_value: format!("{:?}", bit),
                });
            }

            reconstructed += bit * power_of_two;
            power_of_two += power_of_two;
        }

        // Verify bit decomposition matches input
        if reconstructed != input {
            return Err(CircuitError::BitDecompositionMismatch {
                input_witness_id: input_witness_id.0,
                expected: format!("{:?}", input),
                reconstructed: format!("{:?}", reconstructed),
            });
        }

        // Extract the lowest num_bits bits
        let mut result = F::ZERO;
        let mut power_of_two = F::ONE;

        for i in 0..private_data
            .num_bits
            .min(private_data.bit_decomposition.len())
        {
            result += private_data.bit_decomposition[i] * power_of_two;
            power_of_two += power_of_two;
        }

        Ok(result)
    }
}

impl<
    F: Clone
        + Default
        + core::ops::Add<Output = F>
        + core::ops::Sub<Output = F>
        + core::ops::Mul<Output = F>
        + PartialEq
        + core::fmt::Debug
        + Field,
> Circuit<F>
{
    /// Create a circuit runner for execution and trace generation
    pub fn runner(self) -> CircuitRunner<F> {
        CircuitRunner::new(self)
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

    #[test]
    fn test_table_generation_basic() {
        let mut builder = CircuitBuilder::<BabyBear>::new();

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
    fn test_toy_example_37_times_x_minus_111() {
        let mut builder = CircuitBuilder::<BabyBear>::new();

        let x = builder.add_public_input();
        let c37 = builder.add_const(BabyBear::from_u64(37));
        let c111 = builder.add_const(BabyBear::from_u64(111));
        let c1 = builder.add_const(BabyBear::from_u64(1));

        let mul_result = builder.mul(c37, x);
        let sub_result = builder.sub(mul_result, c111);
        builder.assert_zero(sub_result);

        let div_result = builder.div(mul_result, c111);
        let sub_one = builder.sub(div_result, c1);
        builder.assert_zero(sub_one);

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

        // Should have constants: 37, 111, 1 and 0 (for assert_zero)
        assert!(traces.const_trace.values.len() >= 4);

        // Should have one public input
        assert_eq!(traces.public_trace.values.len(), 1);
        assert_eq!(traces.public_trace.values[0], BabyBear::from_u64(3));

        // Should have two mul operations (explicit Mul and Div lowering to Mul with inverse)
        assert_eq!(traces.mul_trace.lhs_values.len(), 2);

        // Encoded subtractions land in the add table (result + rhs = lhs).
        assert_eq!(traces.add_trace.lhs_values.len(), 2);
        assert_eq!(traces.add_trace.lhs_index, vec![2, 3]);
        assert_eq!(traces.add_trace.rhs_index, vec![0, 0]);
        assert_eq!(traces.add_trace.result_index, vec![5, 6]);
    }

    #[test]
    fn test_extension_field_support() {
        type ExtField = BinomialExtensionField<BabyBear, 4>;

        let mut builder = CircuitBuilder::<ExtField>::new();

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
