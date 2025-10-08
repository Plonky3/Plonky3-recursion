use alloc::vec::Vec;
use alloc::{format, vec};

use itertools::izip;
use p3_field::{ExtensionField, Field};
use p3_symmetric::PseudoCompressionFunction;
use tracing::instrument;

use crate::circuit::Circuit;
use crate::op::{
    MmcsVerifyConfig, NonPrimitiveOpConfig, NonPrimitiveOpPrivateData, NonPrimitiveOpType, Prim,
};
use crate::types::{NonPrimitiveOpId, WitnessId};
use crate::{CircuitError, CircuitField, NonPrimitiveOp};

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

/// Fake Mmcs verification table (simplified: single field elements)
#[derive(Debug, Clone)]
pub struct MmcsTrace<F> {
    /// All the mmcs paths computed in this trace
    pub mmcs_paths: Vec<MmcsPathTrace<F>>,
}

/// A single Mmcs Path verification table
#[derive(Debug, Clone, Default)]
pub struct MmcsPathTrace<F> {
    /// Left operand values (current hash). A vector of field elements representing a digest.
    pub left_values: Vec<Vec<F>>,
    /// Left operand indices.
    pub left_index: Vec<Vec<u32>>,
    /// Right operand values (sibling hash). A vector of field elements representing a digest
    pub right_values: Vec<Vec<F>>,
    /// Right operand indices (not on witness bus - private)
    pub right_index: Vec<u32>,
    /// Path direction bits (0 = left, 1 = right) - private
    pub path_directions: Vec<bool>,
    /// Indicates if the current row is processing a smaller
    /// matrix of the Mmcs.
    pub is_extra: Vec<bool>,
    /// Final digest after traversing the path (expected root value).
    pub final_value: Vec<F>,
    /// Witness indices corresponding to the final digest wires.
    pub final_index: Vec<u32>,
}

/// Private Mmcs path data for Mmcs verification
///
/// This represents the private witness information that the prover needs
/// to demonstrate knowledge of a valid Mmcs path from leaf to root.
#[derive(Debug, Clone, PartialEq)]
pub struct MmcsPrivateData<F> {
    /// Sibling and state hash values along the Mmcs path
    ///
    /// The sequence of states along the path.
    pub path_states: Vec<Vec<F>>,
    /// The sequence of sibling with optional tuple of extra state
    /// and siblings, present when the Mmcs has a smaller matrix at this step.
    pub path_siblings: Vec<SiblingWithExtra<F>>,
}

type SiblingWithExtra<F> = (Vec<F>, Option<(Vec<F>, Vec<F>)>);

impl<F: Field + Clone + Default> MmcsPrivateData<F> {
    /// Computes the private mmcs data for the mmcs path defined by `leaf`, `siblings` and `directions`,
    /// for a given a compression function.
    pub fn new<BF, C, const DIGEST_ELEMS: usize>(
        compress: &C,
        config: &MmcsVerifyConfig,
        leaf: &[F],
        siblings: &[(Vec<F>, Option<Vec<F>>)],
        directions: &[bool],
    ) -> Result<Self, CircuitError>
    where
        BF: Field,
        F: ExtensionField<BF> + Clone,
        C: PseudoCompressionFunction<[BF; DIGEST_ELEMS], 2>,
    {
        // Worst case we push two states per step (if `other_sibling` is Some).
        let mut private_data = Self {
            path_states: Vec::with_capacity(siblings.len() + 1),
            path_siblings: Vec::with_capacity(siblings.len()),
        };
        let path_states = &mut private_data.path_states;
        let path_siblings = &mut private_data.path_siblings;

        let mut state = leaf.to_vec();
        for (&dir, (sibling, other)) in directions.iter().zip(siblings.iter()) {
            path_states.push(state.to_vec());

            let state_as_slice = config.ext_to_base(&state)?;
            let sibling_as_slice = config.ext_to_base(sibling)?;

            let input = if dir {
                [state_as_slice, sibling_as_slice]
            } else {
                [sibling_as_slice, state_as_slice]
            };
            state = config.base_to_ext(&compress.compress(input))?;

            // Optional second hash when the step has an extra sibling.
            if let Some(other) = other {
                let intermediate = state.to_vec();
                path_siblings.push((
                    sibling.to_vec(),
                    Some((intermediate.clone(), other.clone())),
                ));
                let state_as_slice = config.ext_to_base(&intermediate)?;
                let other = config.ext_to_base(other)?;
                state = config.base_to_ext(&compress.compress([state_as_slice, other]))?;
            } else {
                path_siblings.push((sibling.to_vec(), None));
            }
        }
        // Append the final state (root).
        path_states.push(state.to_vec());
        Ok(private_data)
    }
    
    /// Builds a valid `MmcsVerifyAir` trace from a private Mmcs proof,
    /// given also the leaf’s digest wires and value used in the circuit, and the leaf’s index in the tree.
    pub fn to_trace(
        &self,
        mmcs_config: &MmcsVerifyConfig,
        leaf_wires: &[WitnessId],
        root_wires: &[WitnessId],
        index_value: u32,
    ) -> Result<MmcsPathTrace<F>, CircuitError> {
        let mut trace = MmcsPathTrace::default();

        // Get the adrresses of the leaf wires
        let leaf_indices: Vec<u32> = leaf_wires.iter().map(|wid| wid.0).collect();
        let root_indices: Vec<u32> = root_wires.iter().map(|wid| wid.0).collect();

        debug_assert!(self.path_siblings.len() <= mmcs_config.max_tree_height);
        let path_directions = (0..mmcs_config.max_tree_height).map(|i| (index_value >> i) & 1 == 1);

        // For each step in the Mmcs path (excluding the final state which is the root)
        debug_assert_eq!(self.path_states.len(), self.path_siblings.len() + 1);
        for (state, (sibling, extra), direction) in izip!(
            self.path_states.iter().take(self.path_siblings.len()),
            self.path_siblings.iter(),
            path_directions
        ) {
            // Current hash becomes left operand
            trace.left_values.push(state.clone());
            // TODO: What is the address of this value?
            trace.left_index.push(leaf_indices.clone()); // Points to witness bus

            // Sibling becomes right operand (private data - not on witness bus)
            trace.right_values.push(sibling.clone());
            trace.right_index.push(0); // Not on witness bus - private data

            trace.path_directions.push(direction);
            trace.is_extra.push(false);

            // If there's an extra sibling we push another row to the trace
            if let Some((extra_state, extra_sibling)) = extra {
                trace.left_values.push(extra_state.to_vec());
                trace.left_index.push(leaf_indices.clone());

                trace.right_values.push(extra_sibling.clone());
                trace.right_index.push(0); // TODO: This should have an address on the witness table

                trace.path_directions.push(direction);
                trace.is_extra.push(true);
            }
        }
        trace.final_value = self.path_states.last().cloned().unwrap_or_default();
        trace.final_index = root_indices;
        Ok(trace)
    }
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

impl<F: CircuitField> CircuitRunner<F> {
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
            (NonPrimitiveOp::MmcsVerify { .. }, NonPrimitiveOpPrivateData::MmcsVerify(_)) => {
                // Type match - good!
            }
        }

        self.non_primitive_op_private_data[op_id.0 as usize] = Some(private_data);
        Ok(())
    }

    /// Run the circuit and generate traces
    #[instrument(skip_all)]
    pub fn run(mut self) -> Result<Traces<F>, CircuitError> {
        // Step 1: Execute primitives to fill witness vector
        self.execute_primitives()?;

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
                Prim::Const { out, val } => {
                    self.set_witness(out, val)?;
                }
                Prim::Public { out, public_pos: _ } => {
                    // Public inputs should already be set
                    if self.witness[out.0 as usize].is_none() {
                        return Err(CircuitError::PublicInputNotSet { witness_id: out });
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
            if let Prim::Const { out, val } = prim {
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
            if let Prim::Public { out, public_pos: _ } = prim {
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
            if let Prim::Add { a, b, out } = prim {
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
            if let Prim::Mul { a, b, out } = prim {
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

    fn generate_mmcs_trace(&mut self) -> Result<MmcsTrace<F>, CircuitError> {
        let mut mmcs_paths = Vec::new();

        // Process each complex operation by index to avoid borrowing conflicts
        for op_idx in 0..self.circuit.non_primitive_ops.len() {
            // Copy out leaf/root to end immutable borrow immediately
            let NonPrimitiveOp::MmcsVerify { leaf, index, root } =
                &self.circuit.non_primitive_ops[op_idx];

            if let Some(Some(NonPrimitiveOpPrivateData::MmcsVerify(private_data))) =
                self.non_primitive_op_private_data.get(op_idx).cloned()
            {
                let config = match self
                    .circuit
                    .enabled_ops
                    .get(&NonPrimitiveOpType::MmcsVerify)
                {
                    Some(NonPrimitiveOpConfig::MmcsVerifyConfig(config)) => Ok(config),
                    _ => Err(CircuitError::InvalidNonPrimitiveOpConfiguration {
                        op: NonPrimitiveOpType::MmcsVerify,
                    }),
                }?;

                // Validate that the witness data is consistent with public inputs
                // Check leaf values
                let witness_leaf: Vec<F> = leaf
                    .iter()
                    .map(|&wid| self.get_witness(wid))
                    .collect::<Result<_, _>>()?;
                let private_data_leaf = private_data
                    .path_states
                    .first()
                    .ok_or(CircuitError::NonPrimitiveOpMissingPrivateData {
                        operation_index: op_idx,
                    })?;
                if witness_leaf != *private_data_leaf {
                    return Err(CircuitError::MmcsWitnessMismatch {
                        operation_index: op_idx,
                        witness_value: alloc::format!("{:?}", private_data_leaf),
                        public_value: alloc::format!("{:?}", witness_leaf),
                    });
                }

                // Check root values
                let witness_root: Vec<F> = root
                    .iter()
                    .map(|&wid| self.get_witness(wid))
                    .collect::<Result<_, _>>()?;
                let computed_root = private_data
                    .path_states
                    .last()
                    .ok_or(CircuitError::NonPrimitiveOpMissingPrivateData {
                        operation_index: op_idx,
                    })?;
                if witness_root != *computed_root {
                    return Err(CircuitError::MmcsWitnessMismatch {
                        operation_index: op_idx,
                        witness_value: alloc::format!("{:?}", computed_root),
                        public_value: alloc::format!("{:?}", witness_root),
                    });
                }

                let trace = private_data.to_trace(config, leaf, root, index.0)?;
                mmcs_paths.push(trace);
            } else {
                return Err(CircuitError::NonPrimitiveOpMissingPrivateData {
                    operation_index: op_idx,
                });
            }
        }

        Ok(MmcsTrace { mmcs_paths })
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
    use p3_symmetric::PseudoCompressionFunction;

    use crate::MmcsPrivateData;
    use crate::builder::CircuitBuilder;
    use crate::op::MmcsVerifyConfig;
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

    #[derive(Clone, Debug)]
    struct MockCompression {}

    impl PseudoCompressionFunction<[BabyBear; 1], 2> for MockCompression {
        fn compress(&self, input: [[BabyBear; 1]; 2]) -> [BabyBear; 1] {
            input[0]
        }
    }

    #[test]
    fn test_mmcs_private_data() {
        let leaf = [BabyBear::from_u64(1)];
        let siblings = [
            (vec![BabyBear::from_u64(2)], None),
            (
                vec![BabyBear::from_u64(3)],
                Some(vec![BabyBear::from_u64(4)]),
            ),
            (vec![BabyBear::from_u64(5)], None),
        ];
        let directions = [false, true, true];

        let expected_private_data = MmcsPrivateData {
            path_states: vec![
                // The first state is the leaf
                vec![BabyBear::from_u64(1)],
                // here there's an extra sibling, so we do two compressions.
                // Since dir = false, the first input is [2, 1] and thus compress.compress(input) = 2.
                // The extra input is [2, 4] and compress.compress(input) = 2
                vec![BabyBear::from_u64(2)],
                // direction = true and then input is [2, 5] compress.compress(input) = 2
                vec![BabyBear::from_u64(2)],
                // final root state after the full path
                vec![BabyBear::from_u64(2)],
            ],
            path_siblings: vec![
                (vec![BabyBear::from_u64(2)], None), // The first sibling
                // The second sibling with the extra state and sibling
                (
                    vec![BabyBear::from_u64(3)],
                    Some((vec![BabyBear::from_u64(2)], vec![BabyBear::from_u64(4)])),
                ),
                // The third sibling
                (vec![BabyBear::from_u64(5)], None),
            ],
        };

        let compress = MockCompression {};
        let config = MmcsVerifyConfig::mock_config();

        let private_data = MmcsPrivateData::new::<BabyBear, _, 1>(
            &compress,
            &config,
            &leaf,
            &siblings,
            &directions,
        )
        .unwrap();

        assert_eq!(private_data, expected_private_data);
    }

    #[test]
    fn test_mmcs_witness_validation() {
        use crate::errors::CircuitError;
        use crate::ops::MmcsOps;
        use crate::NonPrimitiveOpPrivateData;

        type F = BinomialExtensionField<BabyBear, 4>;

        let compress = MockCompression {};
        // Use config with max_tree_height=4 to support 3 layers + 1 extra sibling
        let config = MmcsVerifyConfig {
            base_field_digest_elems: 1,
            ext_field_digest_elems: 1,
            max_tree_height: 4,
        };

        // Build circuit once
        let mut builder = CircuitBuilder::new();
        builder.enable_mmcs(&config);
        let leaf = (0..config.ext_field_digest_elems)
            .map(|_| builder.add_public_input())
            .collect::<alloc::vec::Vec<_>>();
        let index = builder.add_public_input();
        let root = (0..config.ext_field_digest_elems)
            .map(|_| builder.add_public_input())
            .collect::<alloc::vec::Vec<_>>();
        let mmcs_op_id = builder.add_mmcs_verify(&leaf, &index, &root).unwrap();
        let circuit = builder.build().unwrap();

        // Create test data with 3 layers, varying directions, and one extra sibling
        let leaf_value = [F::from_u64(42)];
        let siblings = [
            // Layer 0: direction=false, no extra sibling
            (vec![F::from_u64(10)], None),
            // Layer 1: direction=true, WITH extra sibling
            (
                vec![F::from_u64(20)],
                Some(vec![F::from_u64(25)]),
            ),
            // Layer 2: direction=false, no extra sibling
            (vec![F::from_u64(30)], None),
        ];
        let directions = [false, true, false];

        // Compute what the CORRECT root should be
        let correct_private_data = MmcsPrivateData::new::<BabyBear, _, 1>(
            &compress,
            &config,
            &leaf_value,
            &siblings,
            &directions,
        )
        .unwrap();
        let correct_root = correct_private_data.path_states.last().unwrap();

        // Test 1: Valid witness should be accepted
        {
            // Index corresponds to directions: [false, true, false] -> 0b010 = 2
            let index_value = F::from_u64(
                directions
                    .iter()
                    .enumerate()
                    .filter(|(_, dir)| **dir)
                    .map(|(i, _)| 1 << i)
                    .sum::<u64>(),
            );

            let mut public_inputs = vec![];
            public_inputs.extend(leaf_value);
            public_inputs.push(index_value);
            public_inputs.extend(correct_root);

            let mut runner = circuit.clone().runner();
            runner.set_public_inputs(&public_inputs).unwrap();
            runner
                .set_non_primitive_op_private_data(
                    mmcs_op_id,
                    NonPrimitiveOpPrivateData::MmcsVerify(correct_private_data.clone()),
                )
                .unwrap();

            assert!(runner.run().is_ok(), "Valid witness should be accepted");
        }

        // Test 2: Invalid witness (wrong root) should be rejected
        {
            // Use same index as test 1
            let index_value = F::from_u64(
                directions
                    .iter()
                    .enumerate()
                    .filter(|(_, dir)| **dir)
                    .map(|(i, _)| 1 << i)
                    .sum::<u64>(),
            );

            let wrong_root = [F::from_u64(999)];
            let mut public_inputs = vec![];
            public_inputs.extend(leaf_value);
            public_inputs.push(index_value);
            public_inputs.extend(wrong_root);

            let mut runner = circuit.clone().runner();
            runner.set_public_inputs(&public_inputs).unwrap();
            runner
                .set_non_primitive_op_private_data(
                    mmcs_op_id,
                    NonPrimitiveOpPrivateData::MmcsVerify(correct_private_data),
                )
                .unwrap();

            match runner.run() {
                Err(CircuitError::MmcsWitnessMismatch { .. }) => {
                    // Expected! The witness validation caught the mismatch
                }
                Ok(_) => panic!("Expected witness validation to fail, but it succeeded!"),
                Err(e) => panic!("Expected MmcsWitnessMismatch error, got: {:?}", e),
            }
        }
    }
}
