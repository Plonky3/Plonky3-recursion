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
use crate::types::WitnessId;

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
/// This implements the Poseidon Permutation Table specification.
/// See: https://github.com/Plonky3/Plonky3-recursion/discussions/186
///
/// The table has one row per Poseidon call, implementing:
/// - Standard chaining (Challenger-style sponge use)
/// - Merkle-path chaining (MMCS directional hashing)
/// - Selective limb exposure to the witness via CTL
/// - Optional MMCS index accumulator
#[derive(Debug, Clone)]
pub struct Poseidon2CircuitRow<F> {
    /// Control: If 1, row begins a new independent Poseidon chain.
    pub new_start: bool,
    /// Control: 0 → normal sponge/Challenger mode, 1 → Merkle-path mode.
    pub merkle_path: bool,
    /// Control: Direction bit for Merkle left/right hashing (only meaningful when merkle_path = 1).
    pub mmcs_bit: bool,
    /// Value: Optional MMCS accumulator (base field, encodes a u32-like integer).
    pub mmcs_index_sum: F,
    /// Inputs to the Poseidon2 permutation (flattened state, length = WIDTH).
    /// Represents in[0..3] - 4 extension limbs (input digest).
    pub input_values: Vec<F>,
    /// Input exposure flags: for each limb i, if 1, in[i] must match witness lookup at input_indices[i].
    pub in_ctl: [bool; 4],
    /// Input exposure indices: index into the witness table for each limb.
    pub input_indices: [u32; 4],
    /// Output exposure flags: for limbs 0-1 only, if 1, out[i] must match witness lookup at output_indices[i].
    /// Note: limbs 2-3 are never publicly exposed (always private).
    pub out_ctl: [bool; 2],
    /// Output exposure indices: index into the witness table for limbs 0-1.
    pub output_indices: [u32; 2],
    /// MMCS index exposure: index for CTL exposure of mmcs_index_sum.
    pub mmcs_index_sum_idx: u32,
}
pub type Poseidon2CircuitTrace<F> = Vec<Poseidon2CircuitRow<F>>;

/// Poseidon2 trace for all hash operations in the circuit.
#[derive(Debug, Clone)]
pub struct Poseidon2Trace<F> {
    /// All Poseidon2 operations (permutation rows) in this trace.
    pub operations: Poseidon2CircuitTrace<F>,
}

// Needed for NonPrimitiveTrace<F>
unsafe impl<F: Send + Sync> Send for Poseidon2Trace<F> {}
unsafe impl<F: Send + Sync> Sync for Poseidon2Trace<F> {}

impl<F> Poseidon2Trace<F> {
    pub const fn total_rows(&self) -> usize {
        self.operations.len()
    }
}

impl<TraceF: Clone + Send + Sync + 'static, CF> NonPrimitiveTrace<CF> for Poseidon2Trace<TraceF> {
    fn id(&self) -> &'static str {
        "poseidon2"
    }

    fn rows(&self) -> usize {
        self.total_rows()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn boxed_clone(&self) -> Box<dyn NonPrimitiveTrace<CF>> {
        Box::new(self.clone())
    }
}

/// Builder for generating Poseidon2 traces.
pub struct Poseidon2TraceBuilder<'a, CF, Config: Poseidon2Params> {
    circuit: &'a Circuit<CF>,
    witness: &'a [Option<CF>],
    #[allow(dead_code)] // TODO: Will be used when filling the state with hints
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

    /// Builds the Poseidon2 trace by scanning non-primitive ops with hash executors.
    /// Also maintains state and fills state hints for stateful operations.
    pub fn build(self) -> Result<Poseidon2Trace<Config::BaseField>, CircuitError> {
        let mut operations = Vec::new();

        let width = Config::WIDTH;
        let d = Config::D;

        for op in &self.circuit.non_primitive_ops {
            let Op::NonPrimitiveOpWithExecutor {
                inputs,
                outputs: _,
                executor,
                op_id,
            } = op
            else {
                continue;
            };

            match executor.op_type() {
                NonPrimitiveOpType::PoseidonPerm {
                    new_start,
                    merkle_path,
                    mmcs_bit,
                } => {
                    // Expected layout: [in0, in1, in2, in3, out0, out1, mmcs_index_sum]
                    if inputs.len() != 7 {
                        return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                            op: executor.op_type().clone(),
                            expected: "7 input vectors".to_string(),
                            got: inputs.len(),
                        });
                    }

                    let mut padded_inputs = vec![Config::BaseField::ZERO; width];
                    let mut in_ctl = [false; 4];
                    let mut in_idx = [0u32; 4];
                    for limb in 0..4 {
                        let chunk = &inputs[limb];
                        match chunk.len() {
                            0 => {}
                            1 => {
                                let val = self.get_witness(&chunk[0])?;
                                let coeffs = val.as_basis_coefficients_slice();
                                if coeffs.len() != d {
                                    return Err(
                                        CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                                            op: executor.op_type().clone(),
                                            expected: d.to_string(),
                                            got: coeffs.len(),
                                        },
                                    );
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
                                    let base = val.as_base().ok_or(
                                        CircuitError::IncorrectNonPrimitiveOpPrivateData {
                                            op: executor.op_type().clone(),
                                            operation_index: *op_id,
                                            expected: "base field limb component".to_string(),
                                            got: "extension value".to_string(),
                                        },
                                    )?;
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

                    let mut out_ctl = [false; 2];
                    let mut out_idx = [0u32; 2];
                    for (offset, limb) in (4..6).enumerate() {
                        let chunk = &inputs[limb];
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

                    let (mmcs_index_sum, mmcs_index_sum_idx) = if inputs[6].len() == 1 {
                        let val = self.get_witness(&inputs[6][0])?;
                        let base = val.as_base().ok_or(
                            CircuitError::IncorrectNonPrimitiveOpPrivateData {
                                op: executor.op_type().clone(),
                                operation_index: *op_id,
                                expected: "base field mmcs_index_sum".to_string(),
                                got: "extension value".to_string(),
                            },
                        )?;
                        (base, inputs[6][0].0)
                    } else {
                        (Config::BaseField::ZERO, 0)
                    };

                    operations.push(Poseidon2CircuitRow {
                        new_start: *new_start,
                        merkle_path: *merkle_path,
                        mmcs_bit: *mmcs_bit,
                        mmcs_index_sum,
                        input_values: padded_inputs,
                        in_ctl,
                        input_indices: in_idx,
                        out_ctl,
                        output_indices: out_idx,
                        mmcs_index_sum_idx,
                    });
                }
                _ => {
                    // Skip other operation types
                    continue;
                }
            }
        }

        Ok(Poseidon2Trace { operations })
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
    let trace =
        Poseidon2TraceBuilder::<F, Config>::new(circuit, witness, non_primitive_data).build()?;
    if trace.total_rows() == 0 {
        Ok(None)
    } else {
        Ok(Some(Box::new(trace)))
    }
}
