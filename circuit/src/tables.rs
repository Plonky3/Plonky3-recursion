use core::array;

use p3_field::{Field, PrimeCharacteristicRing};
use p3_symmetric::{CryptographicHasher, CryptographicPermutation};
use rand::SeedableRng;
use rand::rngs::SmallRng;

use crate::builder::{CIRCUIT_HASH_CAPACITY, CIRCUIT_HASH_RATE};
use crate::circuit::Circuit;
use crate::op::{NonPrimitiveOpPrivateData, Prim};
use crate::types::{NonPrimitiveOpId, WitnessId};

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
    /// Sub operation table
    pub sub_trace: SubTrace<F>,
    /// Fake Merkle verification table
    pub fake_merkle_trace: FakeMerkleTrace<F>,
    /// Sponge hash table
    pub sponge_trace: SpongeTrace<CIRCUIT_HASH_RATE, CIRCUIT_HASH_CAPACITY, F>, // Example sizes; adjust as needed
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

/// Sub operation table
#[derive(Debug, Clone)]
pub struct SubTrace<F> {
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

/// Sponge hash table (for hash absorb/squeeze)
#[derive(Debug, Clone, Default)]
pub struct SpongeTrace<const R: usize, const C: usize, F> {
    /// Flags to reset the capacity
    pub reset: Vec<bool>,
    /// Rate values; either absorbed inputs or squeezed outputs
    pub rate_values: Vec<[F; R]>,
    /// Rate indices
    pub rate_indices: Vec<[u32; R]>,
    /// Capacity values (not on witness bus - private)
    pub capacity_values: Vec<[F; C]>,
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
    complex_op_private_data: Vec<Option<NonPrimitiveOpPrivateData<F>>>,
}

impl<
    F: Clone
        + Default
        + std::ops::Add<Output = F>
        + std::ops::Sub<Output = F>
        + std::ops::Mul<Output = F>
        + PartialEq
        + std::fmt::Debug
        + PrimeCharacteristicRing,
> CircuitRunner<F>
{
    /// Create a new prover instance
    pub fn new(circuit: Circuit<F>) -> Self {
        let witness = vec![None; circuit.slot_count as usize];
        let complex_op_private_data = vec![None; circuit.non_primitive_ops.len()];
        Self {
            circuit,
            witness,
            complex_op_private_data,
        }
    }

    /// Set public inputs according to Circuit.public_rows mapping
    pub fn set_public_inputs(&mut self, public_values: &[F]) -> Result<(), String> {
        if public_values.len() != self.circuit.public_flat_len {
            return Err(format!(
                "Public input length mismatch: expected {}, got {}",
                self.circuit.public_flat_len,
                public_values.len()
            ));
        }
        if self.circuit.public_rows.len() != self.circuit.public_flat_len {
            return Err("Circuit missing public_rows mapping".to_string());
        }

        for (i, value) in public_values.iter().enumerate() {
            let widx = self.circuit.public_rows[i];
            self.witness[widx.0 as usize] = Some(value.clone());
        }

        Ok(())
    }

    /// Set private data for a complex operation
    pub fn set_complex_op_private_data(
        &mut self,
        op_id: NonPrimitiveOpId,
        private_data: NonPrimitiveOpPrivateData<F>,
    ) -> Result<(), String> {
        // Validate that the op_id exists in the circuit
        if op_id.0 as usize >= self.circuit.non_primitive_ops.len() {
            return Err(format!(
                "NonPrimitiveOpId {} out of range (circuit has {} complex ops)",
                op_id.0,
                self.circuit.non_primitive_ops.len()
            ));
        }

        // Validate that the private data matches the operation type
        let complex_op = &self.circuit.non_primitive_ops[op_id.0 as usize];
        match (complex_op, &private_data) {
            (
                crate::op::NonPrimitiveOp::FakeMerkleVerify { .. },
                NonPrimitiveOpPrivateData::FakeMerkleVerify(_),
            ) => {
                // Type match - good!
            }
            (crate::op::NonPrimitiveOp::HashAbsorb { .. }, _) => {
                panic!("HashAbsorb operation does not take private data");
            }
            (crate::op::NonPrimitiveOp::HashSqueeze { .. }, _) => {
                panic!("HashSqueeze operation does not take private data");
            }
            _ => {
                panic!("Private data type does not match operation type");
            }
        }

        self.complex_op_private_data[op_id.0 as usize] = Some(private_data);
        Ok(())
    }

    /// Run the circuit and generate traces
    pub fn run(mut self) -> Result<Traces<F>, String> {
        // Step 1: Execute primitives to fill witness vector
        self.execute_primitives()?;

        // Step 2: Generate all table traces
        let witness_trace = self.generate_witness_trace()?;
        let const_trace = self.generate_const_trace()?;
        let public_trace = self.generate_public_trace()?;
        let add_trace = self.generate_add_trace()?;
        let mul_trace = self.generate_mul_trace()?;
        let sub_trace = self.generate_sub_trace()?;
        let fake_merkle_trace = self.generate_fake_merkle_trace()?;
        Ok(Traces {
            witness_trace,
            const_trace,
            public_trace,
            add_trace,
            mul_trace,
            sub_trace,
            fake_merkle_trace,
            sponge_trace: SpongeTrace::default(),
        })
    }

    /// Run the circuit and generate traces
    pub fn run_with_hash<P: CryptographicPermutation<[F; N]>, const N: usize>(
        mut self,
        perm: P,
    ) -> Result<Traces<F>, String> {
        // Step 1: Execute primitives to fill witness vector
        self.execute_primitives()?;

        // Step 2: Generate all table traces
        let witness_trace = self.generate_witness_trace()?;
        let const_trace = self.generate_const_trace()?;
        let public_trace = self.generate_public_trace()?;
        let add_trace = self.generate_add_trace()?;
        let mul_trace = self.generate_mul_trace()?;
        let sub_trace = self.generate_sub_trace()?;
        let fake_merkle_trace = self.generate_fake_merkle_trace()?;
        let sponge_trace = self.generate_sponge_trace(perm)?;

        Ok(Traces {
            witness_trace,
            const_trace,
            public_trace,
            add_trace,
            mul_trace,
            sub_trace,
            fake_merkle_trace,
            sponge_trace,
        })
    }

    /// Execute all primitive operations to fill witness vector
    fn execute_primitives(&mut self) -> Result<(), String> {
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
                        return Err(format!("Public input not set for WitnessId({})", out.0));
                    }
                }
                Prim::Add { a, b, out } => {
                    let a_val = self.get_witness(a)?;
                    let b_val = self.get_witness(b)?;
                    let result = a_val + b_val;
                    self.set_witness(out, result)?;
                }
                Prim::Sub { a, b, out } => {
                    let a_val = self.get_witness(a)?;
                    let b_val = self.get_witness(b)?;
                    let result = a_val - b_val;
                    self.set_witness(out, result)?;
                }
                Prim::Mul { a, b, out } => {
                    let a_val = self.get_witness(a)?;
                    let b_val = self.get_witness(b)?;
                    let result = a_val * b_val;
                    self.set_witness(out, result)?;
                }
            }
        }

        Ok(())
    }

    fn get_witness(&self, widx: WitnessId) -> Result<F, String> {
        self.witness
            .get(widx.0 as usize)
            .and_then(|opt| opt.as_ref())
            .cloned()
            .ok_or_else(|| format!("Witness not set for WitnessId({})", widx.0))
    }

    fn set_witness(&mut self, widx: WitnessId, value: F) -> Result<(), String> {
        if widx.0 as usize >= self.witness.len() {
            return Err(format!("WitnessId({}) out of bounds", widx.0));
        }

        // Check for conflicting reassignment
        if let Some(existing_value) = self.witness[widx.0 as usize].clone() {
            if existing_value != value {
                return Err(format!(
                    "Witness conflict: WitnessId({}) already set to {:?}, cannot reassign to {:?}",
                    widx.0, existing_value, value
                ));
            }
        } else {
            self.witness[widx.0 as usize] = Some(value);
        }

        Ok(())
    }

    fn generate_witness_trace(&self) -> Result<WitnessTrace<F>, String> {
        let mut index = Vec::new();
        let mut values = Vec::new();

        for (i, witness_opt) in self.witness.iter().enumerate() {
            match witness_opt {
                Some(value) => {
                    index.push(i as u32);
                    values.push(value.clone());
                }
                None => {
                    return Err(format!("Witness not set for index {i}"));
                }
            }
        }

        Ok(WitnessTrace { index, values })
    }

    fn generate_const_trace(&self) -> Result<ConstTrace<F>, String> {
        let mut index = Vec::new();
        let mut values = Vec::new();

        // Collect all constants from primitive operations
        for prim in &self.circuit.primitive_ops {
            if let Prim::Const { out, val } = prim {
                index.push(out.0);
                values.push(val.clone());
            }
        }

        Ok(ConstTrace { index, values })
    }

    fn generate_public_trace(&self) -> Result<PublicTrace<F>, String> {
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

    fn generate_add_trace(&self) -> Result<AddTrace<F>, String> {
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

    fn generate_mul_trace(&self) -> Result<MulTrace<F>, String> {
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

    fn generate_sub_trace(&self) -> Result<SubTrace<F>, String> {
        let mut lhs_values = Vec::new();
        let mut lhs_index = Vec::new();
        let mut rhs_values = Vec::new();
        let mut rhs_index = Vec::new();
        let mut result_values = Vec::new();
        let mut result_index = Vec::new();

        for prim in &self.circuit.primitive_ops {
            if let Prim::Sub { a, b, out } = prim {
                lhs_values.push(self.get_witness(*a)?);
                lhs_index.push(a.0);
                rhs_values.push(self.get_witness(*b)?);
                rhs_index.push(b.0);
                result_values.push(self.get_witness(*out)?);
                result_index.push(out.0);
            }
        }

        Ok(SubTrace {
            lhs_values,
            lhs_index,
            rhs_values,
            rhs_index,
            result_values,
            result_index,
        })
    }

    fn generate_fake_merkle_trace(&mut self) -> Result<FakeMerkleTrace<F>, String> {
        let mut left_values = Vec::new();
        let mut left_index = Vec::new();
        let mut right_values = Vec::new();
        let mut right_index = Vec::new();
        let mut result_values = Vec::new();
        let mut result_index = Vec::new();
        let mut path_directions = Vec::new();

        // Process each complex operation by index to avoid borrowing conflicts
        for op_idx in 0..self.circuit.non_primitive_ops.len() {
            // Only handle FakeMerkleVerify ops here
            match &self.circuit.non_primitive_ops[op_idx] {
                crate::op::NonPrimitiveOp::FakeMerkleVerify { leaf, root } => {
                    // Copy out leaf/root to end immutable borrow immediately
                    let (leaf, root) = (*leaf, *root);

                    // Clone private data option to avoid holding a borrow on self
                    if let Some(Some(NonPrimitiveOpPrivateData::FakeMerkleVerify(private_data))) =
                        self.complex_op_private_data.get(op_idx).cloned()
                    {
                        let mut current_hash = if let Some(val) =
                            self.witness.get(leaf.0 as usize).and_then(|x| x.as_ref())
                        {
                            val.clone()
                        } else {
                            return Err(format!(
                                "Leaf value not set for FakeMerkleVerify operation {op_idx}"
                            ));
                        };

                        // For each step in the Merkle path
                        for (sibling_value, &direction) in private_data
                            .path_siblings
                            .iter()
                            .zip(private_data.path_directions.iter())
                        {
                            // Current hash becomes left operand
                            left_values.push(current_hash.clone());
                            left_index.push(leaf.0); // Points to witness bus

                            // Sibling becomes right operand (private data - not on witness bus)
                            right_values.push(sibling_value.clone());
                            right_index.push(0); // Not on witness bus - private data

                            // Compute parent hash (simple mock hash: left + right + direction)
                            let parent_hash = current_hash.clone()
                                + sibling_value.clone()
                                + if direction {
                                    F::from_u64(1)
                                } else {
                                    F::from_u64(0)
                                };

                            result_values.push(parent_hash.clone());
                            result_index.push(root.0); // Points to witness bus

                            path_directions.push(if direction { 1 } else { 0 });

                            // Update current hash for next iteration
                            current_hash = parent_hash;
                        }

                        // Root is computed; write back to the witness bus at root index
                        self.set_witness(root, current_hash.clone())?;
                    } else {
                        return Err(format!(
                            "Missing private data for FakeMerkleVerify operation {op_idx}"
                        ));
                    }
                }
                _ => continue,
            };
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

    fn generate_sponge_trace<P, const R: usize, const C: usize, const N: usize>(
        &mut self,
        perm: P,
    ) -> Result<SpongeTrace<R, C, F>, String>
    where
        P: CryptographicPermutation<[F; N]>,
    {
        let mut reset = Vec::new();
        let mut rate_values = Vec::new();
        let mut rate_indices = Vec::new();
        let mut capacity_values = Vec::new();

        let mut state = array::from_fn(|_| F::default());

        // Process each complex operation by index to avoid borrowing conflicts
        for op_idx in 0..self.circuit.non_primitive_ops.len() {
            // Only handle SpongeTrace ops here
            match &self.circuit.non_primitive_ops[op_idx] {
                crate::op::NonPrimitiveOp::HashAbsorb { reset_flag, inputs } => {
                    reset.push(*reset_flag);
                    rate_indices.push(array::from_fn(|i| inputs[i].0));
                    let input_values: [Result<F, String>; R] =
                        array::from_fn(|i| self.get_witness(inputs[i]));
                    let input_values = input_values.into_iter().collect::<Result<Vec<_>, _>>()?;
                    let input_values: [F; R] = input_values
                        .try_into()
                        .expect("input_values should have R elements");
                    state[0..R].clone_from_slice(&input_values);
                    rate_values.push(input_values);
                    if *reset_flag {
                        state[R..].fill(F::default());
                    }
                    let current_capacity = array::from_fn(|i| state[R + i].clone());
                    capacity_values.push(current_capacity);

                    state = perm.permute(state.into());
                }
                crate::op::NonPrimitiveOp::HashSqueeze { outputs } => {
                    reset.push(false);
                    // Clone outputs to end immutable borrow immediately
                    let outputs = outputs.clone();
                    rate_indices.push(array::from_fn(|i| outputs[i].0));

                    let output_values: [F; R] = array::from_fn(|i| state[i].clone());
                    for i in 0..R {
                        // Sanity check that outputs are set to the correct values
                        self.set_witness(outputs[i], output_values[i].clone())?;
                    }
                    rate_values.push(output_values);

                    let current_capacity = array::from_fn(|i| state[R + i].clone());
                    capacity_values.push(current_capacity);

                    state = perm.permute(state);
                }
                _ => continue,
            };
        }

        Ok(SpongeTrace {
            reset,
            rate_values,
            rate_indices,
            capacity_values,
        })
    }
}

impl<
    F: Clone
        + Default
        + std::ops::Add<Output = F>
        + std::ops::Sub<Output = F>
        + std::ops::Mul<Output = F>
        + PartialEq
        + std::fmt::Debug
        + PrimeCharacteristicRing,
> Circuit<F>
{
    /// Create a circuit runner for execution and trace generation
    pub fn runner(self) -> CircuitRunner<F> {
        CircuitRunner::new(self)
    }
}

#[cfg(test)]
mod tests {
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

        let circuit = builder.build();
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

        // DESIGN.txt example: 37 * x - 111 = 0
        let x = builder.add_public_input();
        let c37 = builder.add_const(BabyBear::from_u64(37));
        let c111 = builder.add_const(BabyBear::from_u64(111));

        let mul_result = builder.mul(c37, x);
        let sub_result = builder.sub(mul_result, c111);
        builder.assert_zero(sub_result);

        let circuit = builder.build();
        println!("=== CIRCUIT PRIMITIVE OPERATIONS ===");
        for (i, prim) in circuit.primitive_ops.iter().enumerate() {
            println!("{i}: {prim:?}");
        }

        let slot_count = circuit.slot_count;
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

        println!("\n=== SUB TRACE ===");
        for i in 0..traces.sub_trace.lhs_values.len() {
            println!(
                "Row {}: WitnessId({}) - WitnessId({}) -> WitnessId({}) | {:?} - {:?} -> {:?}",
                i,
                traces.sub_trace.lhs_index[i],
                traces.sub_trace.rhs_index[i],
                traces.sub_trace.result_index[i],
                traces.sub_trace.lhs_values[i],
                traces.sub_trace.rhs_values[i],
                traces.sub_trace.result_values[i]
            );
        }

        // Verify trace structure
        assert_eq!(traces.witness_trace.index.len(), slot_count as usize);

        // Should have constants: 37, 111, and 0 (for assert_zero)
        assert!(traces.const_trace.values.len() >= 2);

        // Should have one public input
        assert_eq!(traces.public_trace.values.len(), 1);
        assert_eq!(traces.public_trace.values[0], BabyBear::from_u64(3));

        // Should have one mul operation
        assert_eq!(traces.mul_trace.lhs_values.len(), 1);

        // Should have two sub operations (explicit Sub and assert_zero lowering to Sub with zero)
        assert_eq!(traces.sub_trace.lhs_values.len(), 2);
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

        let circuit = builder.build();
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

        // No sub operations in this simplified test
        assert_eq!(traces.sub_trace.lhs_values.len(), 0);
    }
}
