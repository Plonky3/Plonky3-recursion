use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::any::Any;
use core::fmt::Debug;

use p3_field::{ExtensionField, PrimeCharacteristicRing, PrimeField};

use super::NonPrimitiveTrace;
use crate::CircuitError;
use crate::circuit::{Circuit, CircuitField};
use crate::op::{NonPrimitiveOpPrivateData, NonPrimitiveOpType, Op};
use crate::ops::poseidon2_perm::Poseidon2PermExecutor;
use crate::types::WitnessId;

/// Private data for Poseidon2 permutation.
/// Only used for Merkle mode operations, contains exactly 2 extension field limbs (the sibling).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Poseidon2PermPrivateData<F> {
    pub sibling: [F; 2],
}

/// Trait to provide Poseidon2 configuration parameters for a field type.
///
/// This allows the trace generator and AIR to work with different Poseidon2 configurations
/// without hardcoding parameters. Implementations should provide the standard
/// parameters for their field type.
pub trait Poseidon2Params {
    type BaseField: PrimeField + PrimeCharacteristicRing;
    /// Extension degree D
    const D: usize;
    /// Total width in base field elements
    const WIDTH: usize;

    /// Rate in extension elements
    const RATE_EXT: usize;
    /// Capacity in extension elements
    const CAPACITY_EXT: usize;
    /// Digest size in extension elements (number of extension elements output by squeeze)
    const DIGEST_EXT: usize;
    /// Capacity size in base field elements = CAPACITY_EXT * D
    const CAPACITY_SIZE: usize = Self::CAPACITY_EXT * Self::D;

    /// S-box degree (polynomial degree for the S-box)
    const SBOX_DEGREE: u64;
    /// Number of S-box registers
    const SBOX_REGISTERS: usize;

    /// Number of half full rounds
    const HALF_FULL_ROUNDS: usize;
    /// Number of partial rounds
    const PARTIAL_ROUNDS: usize;

    /// Width in extension elements = RATE_EXT + CAPACITY_EXT
    const WIDTH_EXT: usize = Self::RATE_EXT + Self::CAPACITY_EXT;
}

/// Poseidon2 operation table row.
///
/// This implements the Poseidon2 Permutation Table specification.
/// See: https://github.com/Plonky3/Plonky3-recursion/discussions/186
///
/// The table has one row per Poseidon2 call, implementing:
/// - Standard chaining (Challenger-style sponge use)
/// - Merkle-path chaining (MMCS directional hashing)
/// - Selective limb exposure to the witness via CTL
/// - Optional MMCS index accumulator
#[derive(Debug, Clone)]
pub struct Poseidon2CircuitRow<
    F,
    const WIDTH_EXT: usize,
    const RATE_EXT: usize,
    const DIGEST_EXT: usize,
> {
    /// Control: If 1, row begins a new independent Poseidon2 chain.
    pub new_start: bool,
    /// Control: 0 → normal sponge/Challenger mode, 1 → Merkle-path mode.
    pub merkle_path: bool,
    /// Control: Direction bit for Merkle left/right hashing (only meaningful when merkle_path = 1).
    pub mmcs_bit: bool,
    /// Value: Optional MMCS accumulator (base field, encodes a u32-like integer).
    pub mmcs_index_sum: F,
    /// Inputs to the Poseidon2 permutation (flattened state, length = WIDTH).
    /// Represents in[0..WIDTH_EXT-1] - WIDTH_EXT extension limbs (input digest).
    pub input_values: Vec<F>,
    /// Input exposure flags: for each limb i, if 1, in[i] must match witness lookup at input_indices[i].
    pub in_ctl: Vec<bool>,
    /// Input exposure indices: index into the witness table for each limb.
    pub input_indices: Vec<u32>,
    /// Output exposure flags: for digest limbs only, if 1, out[i] must match witness lookup at output_indices[i].
    /// Note: capacity limbs are never publicly exposed (always private).
    pub out_ctl: Vec<bool>,
    /// Output exposure indices: index into the witness table for digest limbs.
    pub output_indices: Vec<u32>,
    /// MMCS index exposure: index for CTL exposure of mmcs_index_sum.
    pub mmcs_index_sum_idx: u32,
}

pub type Poseidon2CircuitTrace<
    F,
    const WIDTH_EXT: usize,
    const RATE_EXT: usize,
    const DIGEST_EXT: usize,
> = Vec<Poseidon2CircuitRow<F, WIDTH_EXT, RATE_EXT, DIGEST_EXT>>;

/// Poseidon2 trace for all hash operations in the circuit.
#[derive(Debug, Clone)]
pub struct Poseidon2Trace<F, const WIDTH_EXT: usize, const RATE_EXT: usize, const DIGEST_EXT: usize>
{
    /// All Poseidon2 operations (sponge and compress) in this trace.
    pub operations: Poseidon2CircuitTrace<F, WIDTH_EXT, RATE_EXT, DIGEST_EXT>,
}

// Needed for NonPrimitiveTrace<F>
unsafe impl<F: Send + Sync, const WIDTH_EXT: usize, const RATE_EXT: usize, const DIGEST_EXT: usize>
    Send for Poseidon2Trace<F, WIDTH_EXT, RATE_EXT, DIGEST_EXT>
{
}
unsafe impl<F: Send + Sync, const WIDTH_EXT: usize, const RATE_EXT: usize, const DIGEST_EXT: usize>
    Sync for Poseidon2Trace<F, WIDTH_EXT, RATE_EXT, DIGEST_EXT>
{
}

impl<F, const WIDTH_EXT: usize, const RATE_EXT: usize, const DIGEST_EXT: usize>
    Poseidon2Trace<F, WIDTH_EXT, RATE_EXT, DIGEST_EXT>
{
    pub const fn total_rows(&self) -> usize {
        self.operations.len()
    }
}

impl<
    F: Clone + Send + Sync + 'static,
    const WIDTH_EXT: usize,
    const RATE_EXT: usize,
    const DIGEST_EXT: usize,
> NonPrimitiveTrace<F> for Poseidon2Trace<F, WIDTH_EXT, RATE_EXT, DIGEST_EXT>
{
    fn id(&self) -> &'static str {
        "poseidon2"
    }

    fn rows(&self) -> usize {
        self.total_rows()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn boxed_clone(&self) -> Box<dyn NonPrimitiveTrace<F>> {
        let cloned = self.clone();
        Box::new(cloned) as Box<dyn NonPrimitiveTrace<F>>
    }
}

/// Builder for generating Poseidon2 traces.
///
/// The builder handles the conversion from the circuit's extension field (`CF`) to the
/// base field (`Config::BaseField`) required by the Poseidon2 permutation.
pub struct Poseidon2TraceBuilder<'a, CF, Config: Poseidon2Params> {
    circuit: &'a Circuit<CF>,
    witness: &'a [Option<CF>],
    non_primitive_op_private_data: &'a [Option<NonPrimitiveOpPrivateData<CF>>],

    phantom: core::marker::PhantomData<Config>,
}

impl<'a, CF, Config> Poseidon2TraceBuilder<'a, CF, Config>
where
    CF: CircuitField + ExtensionField<Config::BaseField>,
    Config: Poseidon2Params,
{
    /// Creates a new Poseidon2 trace builder.
    pub const fn new(
        circuit: &'a Circuit<CF>,
        witness: &'a [Option<CF>],
        non_primitive_op_private_data: &'a [Option<NonPrimitiveOpPrivateData<CF>>],
    ) -> Self {
        Self {
            circuit,
            witness,
            non_primitive_op_private_data,
            phantom: core::marker::PhantomData,
        }
    }

    fn get_witness(&self, index: &WitnessId) -> Result<CF, CircuitError> {
        self.witness
            .get(index.0 as usize)
            .and_then(|opt| opt.as_ref())
            .cloned()
            .ok_or(CircuitError::WitnessNotSet { witness_id: *index })
    }

    /// Builds operations
    // This is done without const generics, because it's easier to match on the op type.
    // It will be converted back to a const-generic version in batch_stark_prover.
    fn build_operations(
        self,
    ) -> Result<Vec<Poseidon2CircuitRowDyn<Config::BaseField>>, CircuitError> {
        let mut operations = Vec::new();

        let width = Config::WIDTH;
        let d = Config::D;
        let width_ext = Config::WIDTH_EXT;
        let digest_ext = Config::DIGEST_EXT;

        for op in &self.circuit.ops {
            let Op::NonPrimitiveOpWithExecutor {
                inputs,
                outputs,
                executor,
                op_id,
            } = op
            else {
                continue;
            };

            if executor.op_type() == &NonPrimitiveOpType::Poseidon2Perm {
                let Some(exec) = executor.as_any().downcast_ref::<Poseidon2PermExecutor>() else {
                    return Err(CircuitError::InvalidNonPrimitiveOpConfiguration {
                        op: executor.op_type().clone(),
                    });
                };
                let (new_start, merkle_path) = (exec.new_start, exec.merkle_path);
                // Expected input layout: [in0, in1, in2, in3, mmcs_index_sum, mmcs_bit]
                if inputs.len() != 6 {
                    return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                        op: executor.op_type().clone(),
                        expected: "6 input vectors".to_string(),
                        got: inputs.len(),
                    });
                }
                // Expected output layout: [out0, out1]
                if outputs.len() != 2 {
                    return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                        op: executor.op_type().clone(),
                        expected: "2 output vectors".to_string(),
                        got: outputs.len(),
                    });
                }

                // mmcs_bit is at inputs[5]
                if inputs[5].len() > 1 {
                    return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                        op: executor.op_type().clone(),
                        expected: "0 or 1 element for mmcs_bit".to_string(),
                        got: inputs[5].len(),
                    });
                }
                if merkle_path && inputs[5].is_empty() {
                    return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                        op: executor.op_type().clone(),
                        operation_index: *op_id,
                        expected: "mmcs_bit must be provided when merkle_path=true".to_string(),
                        got: "missing mmcs_bit".to_string(),
                    });
                }

                let mmcs_bit = if inputs[5].len() == 1 {
                    let val = self.get_witness(&inputs[5][0])?;
                    let base = val.as_base().ok_or_else(|| {
                        CircuitError::IncorrectNonPrimitiveOpPrivateData {
                            op: executor.op_type().clone(),
                            operation_index: *op_id,
                            expected: "base field mmcs_bit".to_string(),
                            got: "extension value".to_string(),
                        }
                    })?;
                    match base {
                        x if x == Config::BaseField::ZERO => false,
                        x if x == Config::BaseField::ONE => true,
                        other => {
                            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                                op: executor.op_type().clone(),
                                operation_index: *op_id,
                                expected: "boolean mmcs_bit (0 or 1)".to_string(),
                                got: format!("{other:?}"),
                            });
                        }
                    }
                } else {
                    false
                };

                // Initialize padded_inputs.
                // If private data is available, use it as the default.
                // Otherwise start with zero.
                let mut padded_inputs = vec![Config::BaseField::ZERO; width];

                if let Some(Some(NonPrimitiveOpPrivateData::Poseidon2Perm(private_data))) =
                    self.non_primitive_op_private_data.get(op_id.0 as usize)
                {
                    // Private inputs are only valid for Merkle mode (merkle_path && !new_start).
                    // The type [F; 2] guarantees exactly 2 limbs (the sibling).
                    if !merkle_path || new_start {
                        return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                            op: executor.op_type().clone(),
                            operation_index: *op_id,
                            expected: "no private data (only Merkle mode accepts private data)"
                                .to_string(),
                            got: "private data provided for non-Merkle operation".to_string(),
                        });
                    }

                    // Place sibling in the correct limbs based on mmcs_bit.
                    // mmcs_bit=0: sibling in 2-3
                    // mmcs_bit=1: sibling in 0-1
                    let start_limb = if mmcs_bit { 0 } else { 2 };
                    for (i, limb) in private_data.sibling.iter().enumerate() {
                        let target_limb = start_limb + i;
                        let coeffs = limb.as_basis_coefficients_slice();
                        padded_inputs[target_limb * d..(target_limb + 1) * d]
                            .copy_from_slice(coeffs);
                    }
                }

                let mut in_ctl = vec![false; width_ext];
                let mut in_idx = vec![0u32; width_ext];
                for limb in 0..width_ext {
                    let chunk = &inputs[limb];
                    match chunk.len() {
                        0 => {}
                        1 => {
                            let val = self.get_witness(&chunk[0])?;
                            let coeffs = val.as_basis_coefficients_slice();
                            if coeffs.len() != d {
                                return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                                    op: executor.op_type().clone(),
                                    expected: d.to_string(),
                                    got: coeffs.len(),
                                });
                            }
                            in_ctl[limb] = true;
                            in_idx[limb] = chunk[0].0;
                            padded_inputs[limb * d..(limb + 1) * d].copy_from_slice(coeffs);
                        }
                        len if len == d => {
                            in_ctl[limb] = true;
                            in_idx[limb] = chunk[0].0;
                            for (dst, &wid) in padded_inputs[limb * d..(limb + 1) * d]
                                .iter_mut()
                                .zip(chunk.iter())
                            {
                                let val = self.get_witness(&wid)?;
                                let base = val.as_base().ok_or_else(|| {
                                    CircuitError::IncorrectNonPrimitiveOpPrivateData {
                                        op: executor.op_type().clone(),
                                        operation_index: *op_id,
                                        expected: "base field limb component".to_string(),
                                        got: "extension value".to_string(),
                                    }
                                })?;
                                *dst = base;
                            }
                        }
                        other => {
                            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                                op: executor.op_type().clone(),
                                expected: format!("0, 1, or {d} elements per limb"),
                                got: other,
                            });
                        }
                    }
                }

                let mut out_ctl = vec![false; digest_ext];
                let mut out_idx = vec![0u32; digest_ext];
                for (offset, chunk) in outputs.iter().enumerate() {
                    if chunk.len() == d || chunk.len() == 1 {
                        out_ctl[offset] = true;
                        out_idx[offset] = chunk[0].0;
                    } else if !chunk.is_empty() {
                        return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                            op: executor.op_type().clone(),
                            expected: format!("0, 1, or {d} elements per output limb"),
                            got: chunk.len(),
                        });
                    }
                }

                // mmcs_index_sum is at inputs[4]
                let (mmcs_index_sum, mmcs_index_sum_idx) = if inputs[4].len() == 1 {
                    let val = self.get_witness(&inputs[4][0])?;
                    let base = val.as_base().ok_or_else(|| {
                        CircuitError::IncorrectNonPrimitiveOpPrivateData {
                            op: executor.op_type().clone(),
                            operation_index: *op_id,
                            expected: "base field mmcs_index_sum".to_string(),
                            got: "extension value".to_string(),
                        }
                    })?;
                    (base, inputs[4][0].0)
                } else {
                    (Config::BaseField::ZERO, 0)
                };

                operations.push(Poseidon2CircuitRowDyn {
                    new_start,
                    merkle_path,
                    mmcs_bit,
                    mmcs_index_sum,
                    input_values: padded_inputs,
                    in_ctl,
                    input_indices: in_idx,
                    out_ctl,
                    output_indices: out_idx,
                    mmcs_index_sum_idx,
                });
                continue;
            }
        }

        Ok(operations)
    }
}

/// Generate the Poseidon2 trace with a specific configuration.
///
/// # Type Parameters
/// - `F`: The field type (e.g., `BabyBear`, `KoalaBear`)
/// - `Config`: A type implementing `Poseidon2Params` that specifies the Poseidon2 configuration
///   (e.g., `BabyBearD4Width16`, `BabyBearD4Width24` from [`p3-poseidon2-circuit-air::public_types`])
///
/// # Example
///
/// ```ignore
/// use p3_poseidon2_circuit_air::BabyBearD4Width16;
/// builder.enable_hash(true, generate_poseidon2_trace::<BabyBear, BabyBearD4Width16>);
/// ```
pub fn generate_poseidon2_trace<
    F: CircuitField + ExtensionField<Config::BaseField>,
    Config: Poseidon2Params,
>(
    circuit: &Circuit<F>,
    witness: &[Option<F>],
    non_primitive_data: &[Option<NonPrimitiveOpPrivateData<F>>],
) -> Result<Option<Box<dyn NonPrimitiveTrace<F>>>, CircuitError> {
    let builder = Poseidon2TraceBuilder::<F, Config>::new(circuit, witness, non_primitive_data);

    let operations = builder.build_operations()?;
    if operations.is_empty() {
        Ok(None)
    } else {
        // Convert base field operations to circuit field operations
        // Since F: ExtensionField<Config::BaseField>, we can embed base field values
        let operations_cf: Vec<Poseidon2CircuitRowDyn<F>> = operations
            .into_iter()
            .map(|row| {
                // Convert base field values to circuit field values by embedding
                // Base field values are embedded as extension field elements
                // Since F: ExtensionField<Config::BaseField>, we can embed base field values
                let input_values: Vec<F> = row
                    .input_values
                    .into_iter()
                    .map(|v| {
                        // For extension fields, base field values are embedded as (v, 0, 0, ...)
                        let mut coeffs = vec![Config::BaseField::ZERO; Config::D];
                        coeffs[0] = v;
                        F::from_basis_coefficients_slice(&coeffs)
                            .expect("Failed to embed base field value")
                    })
                    .collect();
                Poseidon2CircuitRowDyn {
                    new_start: row.new_start,
                    merkle_path: row.merkle_path,
                    mmcs_bit: row.mmcs_bit,
                    mmcs_index_sum: {
                        let mut coeffs = vec![Config::BaseField::ZERO; Config::D];
                        coeffs[0] = row.mmcs_index_sum;
                        F::from_basis_coefficients_slice(&coeffs)
                            .expect("Failed to embed base field value")
                    },
                    input_values,
                    in_ctl: row.in_ctl,
                    input_indices: row.input_indices,
                    out_ctl: row.out_ctl,
                    output_indices: row.output_indices,
                    mmcs_index_sum_idx: row.mmcs_index_sum_idx,
                }
            })
            .collect();
        Ok(Some(Box::new(Poseidon2TraceDyn::new(operations_cf))))
    }
}

/// Non-generic version of [`Poseidon2CircuitRow`], to be used for trait objects.
//This is used as an intermediate step, but the const-generic version
// is used in the AIR and by the batch_stark_prover.
#[derive(Clone)]
pub struct Poseidon2CircuitRowDyn<F> {
    pub new_start: bool,
    pub merkle_path: bool,
    pub mmcs_bit: bool,
    pub mmcs_index_sum: F,
    pub input_values: Vec<F>,
    pub in_ctl: Vec<bool>,
    pub input_indices: Vec<u32>,
    pub out_ctl: Vec<bool>,
    pub output_indices: Vec<u32>,
    pub mmcs_index_sum_idx: u32,
}

/// Non-generic version of Poseidon2Trace (for trait objects).
pub struct Poseidon2TraceDyn<F> {
    pub operations: Vec<Poseidon2CircuitRowDyn<F>>,
}

impl<F> Poseidon2TraceDyn<F> {
    pub const fn new(operations: Vec<Poseidon2CircuitRowDyn<F>>) -> Self {
        Self { operations }
    }

    pub const fn total_rows(&self) -> usize {
        self.operations.len()
    }

    pub fn to_const_generic<
        const WIDTH_EXT: usize,
        const RATE_EXT: usize,
        const DIGEST_EXT: usize,
    >(
        &self,
    ) -> Result<Poseidon2Trace<F, WIDTH_EXT, RATE_EXT, DIGEST_EXT>, CircuitError>
    where
        F: Clone,
    {
        let operations: Result<Vec<_>, CircuitError> = self
            .operations
            .iter()
            .map(|row| -> Result<_, CircuitError> {
                Ok(Poseidon2CircuitRow {
                    new_start: row.new_start,
                    merkle_path: row.merkle_path,
                    mmcs_bit: row.mmcs_bit,
                    mmcs_index_sum: row.mmcs_index_sum.clone(),
                    input_values: row.input_values.clone(),
                    in_ctl: row.in_ctl.clone(),
                    input_indices: row.input_indices.clone(),
                    out_ctl: row.out_ctl.clone(),
                    output_indices: row.output_indices.clone(),
                    mmcs_index_sum_idx: row.mmcs_index_sum_idx,
                })
            })
            .collect();

        Ok(Poseidon2Trace::<F, WIDTH_EXT, RATE_EXT, DIGEST_EXT> {
            operations: operations?,
        })
    }
}

impl<F: Clone + Send + Sync + 'static> NonPrimitiveTrace<F> for Poseidon2TraceDyn<F> {
    fn id(&self) -> &'static str {
        "poseidon2"
    }

    fn rows(&self) -> usize {
        self.operations.len()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn boxed_clone(&self) -> Box<dyn NonPrimitiveTrace<F>> {
        Box::new(Self {
            operations: self.operations.clone(),
        })
    }
}
