use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};

use p3_field::{BasedVectorSpace, Field, Packable, PrimeCharacteristicRing};
use p3_symmetric::PseudoCompressionFunction;

use crate::NonPrimitiveOp;
use crate::circuit::Circuit;
use crate::config::CircuitRunnerConfig;
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
    /// Degree not supported.
    UnsupportedDegree(usize),
    /// The size of the digest does not match the expected one.
    MerkleVerifyDigestLengthMismatch { expected: usize, got: usize },
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
            CircuitError::UnsupportedDegree(degree) => write!(f, "Degree {degree} not supported"),
            CircuitError::MerkleVerifyDigestLengthMismatch { expected, got } => {
                write!(f, "Expected digest len {expected} got {got}")
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
    /// Merkle verification table
    pub merkle_trace: MerkleTrace<F>,
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
pub struct MerkleTrace<F> {
    /// All the merkle paths computed in this trace
    pub merkle_paths: Vec<MerklePathTrace<F>>,
}

/// A single Merkle Path verification table (simplified: single field elements)
#[derive(Debug, Clone, Default)]
pub struct MerklePathTrace<F> {
    /// Left operand values (current hash)
    pub left_values: Vec<Vec<F>>,
    /// Left operand indices
    pub left_index: Vec<u32>,
    /// Right operand values (sibling hash)
    pub right_values: Vec<Vec<F>>,
    /// Right operand indices (not on witness bus - private)
    pub right_index: Vec<u32>,
    /// Path direction bits (0 = left, 1 = right) - private
    pub path_directions: Vec<bool>,
    /// Indicates if the current row is processing a smaller
    /// matrix of the Mmcs.
    pub is_extra: Vec<bool>,
}

/// Private Merkle path data for fake Merkle verification (simplified)
///
/// This represents the private witness information that the prover needs
/// to demonstrate knowledge of a valid Merkle path from leaf to root.
/// In a real implementation, this would contain cryptographic hash values
/// and tree structure information.
///
/// Note: This is a simplified "fake" implementation for demonstration.
/// Production Merkle verification would use proper cryptographic hashes
/// and handle multi-element hash digests, not single field elements.
#[derive(Debug, Clone, PartialEq)]
pub struct MerklePrivateData<F> {
    /// Sibling hash values along the Merkle path
    ///
    /// For each level of the tree (from leaf to root), contains the
    /// sibling hash needed to compute the parent hash. It might optionally
    /// include the hash of the row of a smaller matrix in the Mmcs.
    pub path_siblings: Vec<(Vec<F>, Option<Vec<F>>)>,
}

impl<F: Clone + Default> MerklePrivateData<F> {
    // TODO: Maybe an unsafe cast might be more efficient here
    fn into_bf_slice<BF, const DIGEST_ELEMS: usize, const BF_DIGEST_ELEMS: usize>(
        f_slice: &[F],
    ) -> Result<[BF; BF_DIGEST_ELEMS], CircuitError>
    where
        BF: PrimeCharacteristicRing + Copy,
        F: BasedVectorSpace<BF>,
    {
        f_slice
            .iter()
            .flat_map(F::as_basis_coefficients_slice)
            .copied()
            .collect::<Vec<BF>>()
            .try_into()
            .map_err(|_| CircuitError::MerkleVerifyDigestLengthMismatch {
                expected: BF_DIGEST_ELEMS,
                got: f_slice.len() * F::DIMENSION,
            })
    }

    // TODO: Maybe an unsafe cast might be more efficient here
    fn into_f_slice<BF, const DIGEST_ELEMS: usize, const BF_DIGEST_ELEMS: usize>(
        bf_slice: &[BF],
    ) -> Result<[F; DIGEST_ELEMS], CircuitError>
    where
        BF: PrimeCharacteristicRing + Copy,
        F: BasedVectorSpace<BF>,
    {
        let f_vec = bf_slice
            .chunks_exact(F::DIMENSION)
            .map(F::from_basis_coefficients_slice)
            .collect::<Option<Vec<F>>>()
            .ok_or(CircuitError::MerkleVerifyDigestLengthMismatch {
                expected: BF_DIGEST_ELEMS,
                got: bf_slice.len() * F::DIMENSION,
            })?;
        f_vec
            .try_into()
            .map_err(|_| CircuitError::MerkleVerifyDigestLengthMismatch {
                expected: BF_DIGEST_ELEMS,
                got: bf_slice.len() * F::DIMENSION,
            })
    }

    pub fn to_trace<
        BF: PrimeCharacteristicRing + Copy,
        C,
        const DIGEST_ELEMS: usize,
        const BF_DIGEST_ELEMS: usize,
    >(
        &self,
        compress: &C,
        leaf_index: u32,
        leaf_value: [F; DIGEST_ELEMS],
        index_value: u32,
    ) -> Result<MerklePathTrace<F>, CircuitError>
    where
        F: BasedVectorSpace<BF>,
        C: PseudoCompressionFunction<[BF; BF_DIGEST_ELEMS], 2> + Sync,
    {
        debug_assert_eq!(DIGEST_ELEMS * F::DIMENSION, BF_DIGEST_ELEMS);

        let mut trace = MerklePathTrace::default();
        let mut state: [BF; BF_DIGEST_ELEMS] =
            Self::into_bf_slice::<_, DIGEST_ELEMS, _>(&leaf_value)?;

        let path_directions = (0..32).map(|i| (index_value >> i) & 1 == 1);
        // For each step in the Merkle path
        for ((sibling_value, extra_sibling_value), direction) in
            self.path_siblings.iter().zip(path_directions)
        {
            let sibling_value: [BF; BF_DIGEST_ELEMS] =
                Self::into_bf_slice::<_, DIGEST_ELEMS, _>(sibling_value)?;
            // Current hash becomes left operand
            trace
                .left_values
                .push(Self::into_f_slice::<_, DIGEST_ELEMS, BF_DIGEST_ELEMS>(&state)?.to_vec());
            // TODO: What is the address of this value?
            trace.left_index.push(leaf_index); // Points to witness bus

            // Sibling becomes right operand (private data - not on witness bus)
            trace.right_values.push(
                Self::into_f_slice::<_, DIGEST_ELEMS, BF_DIGEST_ELEMS>(&sibling_value)?.to_vec(),
            );
            trace.right_index.push(0); // Not on witness bus - private data

            // Compute parent hash (simple mock hash: left + right + direction)
            let parent_hash = if direction {
                compress.compress([state, sibling_value])
            } else {
                compress.compress([sibling_value, state])
            };

            trace.path_directions.push(direction);
            trace.is_extra.push(false);

            // Update current hash for next iteration
            state = parent_hash;

            // If there's an extra sibling we push another row to the trace
            if let Some(extra_sibling_value) = extra_sibling_value {
                let extra_sibling_value: [BF; BF_DIGEST_ELEMS] =
                    Self::into_bf_slice::<_, DIGEST_ELEMS, _>(extra_sibling_value)?;
                trace
                    .left_values
                    .push(Self::into_f_slice::<_, DIGEST_ELEMS, BF_DIGEST_ELEMS>(&state)?.to_vec());
                trace.left_index.push(leaf_index);

                trace.right_values.push(
                    Self::into_f_slice::<_, DIGEST_ELEMS, BF_DIGEST_ELEMS>(&extra_sibling_value)?
                        .to_vec(),
                );
                trace.right_index.push(0); // TODO: This should have an address on the witness table

                let parent_hash = compress.compress([state, extra_sibling_value]);
                trace.path_directions.push(direction);
                trace.is_extra.push(true);

                state = parent_hash;
            }
        }
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
pub struct CircuitRunner<F, RC: CircuitRunnerConfig<DIGEST_ELEMS>, const DIGEST_ELEMS: usize> {
    circuit: Circuit<F>,
    witness: Vec<Option<F>>,
    /// Private data for complex operations (not on witness bus)
    non_primitive_op_private_data: Vec<Option<NonPrimitiveOpPrivateData<F>>>,
    /// The circuit runner configuration data
    config: RC,
}

impl<
    F: Clone
        + Default
        + core::ops::Add<Output = F>
        + core::ops::Sub<Output = F>
        + core::ops::Mul<Output = F>
        + PartialEq
        + core::fmt::Debug
        + PrimeCharacteristicRing
        + Packable
        + Field
        + BasedVectorSpace<RC::Field>,
    RC: CircuitRunnerConfig<DIGEST_ELEMS>,
    const DIGEST_ELEMS: usize,
> CircuitRunner<F, RC, DIGEST_ELEMS>
{
    /// Create a new prover instance
    pub fn new(circuit: Circuit<F>, config: RC) -> Self {
        let witness = vec![None; circuit.witness_count as usize];
        let non_primitive_op_private_data = vec![None; circuit.non_primitive_ops.len()];
        Self {
            circuit,
            witness,
            non_primitive_op_private_data,
            config,
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
            (NonPrimitiveOp::MerkleVerify { .. }, NonPrimitiveOpPrivateData::MerkleVerify(_)) => {
                // Type match - good!
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
        let merkle_trace = self.generate_merkle_trace()?;

        Ok(Traces {
            witness_trace,
            const_trace,
            public_trace,
            add_trace,
            mul_trace,
            merkle_trace,
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

    fn generate_merkle_trace(&mut self) -> Result<MerkleTrace<F>, CircuitError> {
        let mut merkle_paths = Vec::new();

        // Process each complex operation by index to avoid borrowing conflicts
        for op_idx in 0..self.circuit.non_primitive_ops.len() {
            // Copy out leaf/root to end immutable borrow immediately
            let NonPrimitiveOp::MerkleVerify {
                leaf,
                index,
                root: _,
            } = self.circuit.non_primitive_ops[op_idx];

            // Clone private data option to avoid holding a borrow on self
            let first = leaf.0 as usize;
            let last = first + DIGEST_ELEMS;
            let leaf: [F; DIGEST_ELEMS] = if let Some(val) = self
                .witness
                .get(first..last)
                .and_then(|xs| xs.iter().copied().collect::<Option<Vec<F>>>())
            {
                let val_len = val.len();
                val.try_into()
                    .map_err(|_| CircuitError::MerkleVerifyDigestLengthMismatch {
                        expected: DIGEST_ELEMS,
                        got: val_len,
                    })?
            } else {
                return Err(CircuitError::NonPrimitiveOpWitnessNotSet {
                    operation_index: op_idx,
                });
            };

            if let Some(Some(NonPrimitiveOpPrivateData::MerkleVerify(private_data))) =
                self.non_primitive_op_private_data.get(op_idx).cloned()
            {
                let trace =
                    private_data.to_trace(self.config.compress(), first as u32, leaf, index.0)?;
                merkle_paths.push(trace);
            } else {
                return Err(CircuitError::NonPrimitiveOpMissingPrivateData {
                    operation_index: op_idx,
                });
            }
        }

        Ok(MerkleTrace { merkle_paths })
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
        + PrimeCharacteristicRing
        + Packable
        + Field,
> Circuit<F>
{
    /// Create a circuit runner for execution and trace generation
    pub fn runner<RC: CircuitRunnerConfig<DIGEST_ELEMS>, const DIGEST_ELEMS: usize>(
        self,
        config: RC,
    ) -> CircuitRunner<F, RC, DIGEST_ELEMS>
    where
        F: BasedVectorSpace<RC::Field>,
    {
        CircuitRunner::new(self, config)
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
    use crate::config::babybear_config::default_babybear_poseidon2_circuit_runner_config;

    #[test]
    fn test_table_generation_basic() {
        let mut builder = CircuitBuilder::<BabyBear>::new();

        // Simple test: x + 5 = result
        let x = builder.add_public_input();
        let c5 = builder.add_const(BabyBear::from_u64(5));
        let _result = builder.add(x, c5);

        let circuit = builder.build().unwrap();
        let config = default_babybear_poseidon2_circuit_runner_config();
        let mut runner = circuit.runner(config);

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
        let config = default_babybear_poseidon2_circuit_runner_config();
        let mut runner = circuit.runner(config);

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
        let config = default_babybear_poseidon2_circuit_runner_config();
        let mut runner = circuit.runner(config);

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
