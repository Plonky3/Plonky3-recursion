use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;
use core::fmt::Debug;

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
    /// See spec section 2.2: new_start, and section 5.1: Reset / Independent Row.
    pub new_start: bool,
    /// Control: 0 → normal sponge/Challenger mode, 1 → Merkle-path mode.
    /// See spec section 2.2: merkle_path, and section 5: Chaining Rules.
    pub merkle_path: bool,
    /// Control: Direction bit for Merkle left/right hashing (only meaningful when merkle_path = 1).
    /// See spec section 2.2: mmcs_bit, and section 5.3: Merkle Path Mode.
    pub mmcs_bit: bool,
    /// Value: Optional MMCS accumulator (base field, encodes a u32-like integer).
    /// See spec section 2.1: mmcs_index_sum, and section 6: MMCS Index Accumulator.
    pub mmcs_index_sum: F,
    /// Inputs to the Poseidon2 permutation (flattened state, length = WIDTH).
    /// Represents in[0..3] - 4 extension limbs (input digest).
    /// See spec section 2.1: in[0..3].
    pub input_values: Vec<F>,
    /// Input exposure flags: for each limb i, if 1, in[i] must match witness lookup at input_indices[i].
    /// See spec section 2.2: in_ctl[0..3], and section 3.1: Inputs.
    pub in_ctl: [bool; 4],
    /// Input exposure indices: index into the witness table for each limb.
    /// See spec section 2.2: in_idx[0..3].
    pub input_indices: [u32; 4],
    /// Output exposure flags: for limbs 0-1 only, if 1, out[i] must match witness lookup at output_indices[i].
    /// See spec section 2.2: out_ctl[0..1], and section 3.2: Outputs.
    /// Note: limbs 2-3 are never publicly exposed (always private).
    pub out_ctl: [bool; 2],
    /// Output exposure indices: index into the witness table for limbs 0-1.
    /// See spec section 2.2: out_idx[0..1].
    pub output_indices: [u32; 2],
    /// MMCS index exposure: index for CTL exposure of mmcs_index_sum.
    /// See spec section 2.2: mmcs_index_sum_idx, and section 3.3: MMCS index exposure.
    pub mmcs_index_sum_idx: u32,
}
pub type Poseidon2CircuitTrace<F> = Vec<Poseidon2CircuitRow<F>>;

/// Poseidon2 trace for all hash operations in the circuit.
#[derive(Debug, Clone)]
pub struct Poseidon2Trace<F> {
    /// All Poseidon2 operations (sponge and compress) in this trace.
    pub operations: Poseidon2CircuitTrace<F>,
}

// Needed for NonPrimitiveTrace<F>
unsafe impl<F: Send + Sync> Send for Poseidon2Trace<F> {}
unsafe impl<F: Send + Sync> Sync for Poseidon2Trace<F> {}

impl<F> Poseidon2Trace<F> {
    pub fn total_rows(&self) -> usize {
        self.operations.len()
    }
}

impl<F: Clone + Send + Sync + 'static> NonPrimitiveTrace<F> for Poseidon2Trace<F> {
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
        let cloned: Poseidon2Trace<F> = self.clone();
        Box::new(cloned) as Box<dyn NonPrimitiveTrace<F>>
    }
}

/// Builder for generating Poseidon2 traces.
pub struct Poseidon2TraceBuilder<'a, F, Config: Poseidon2Params> {
    circuit: &'a Circuit<F>,
    witness: &'a [Option<F>],
    #[allow(dead_code)] // TODO: Will be used when filling the state with hints
    non_primitive_op_private_data: &'a [Option<NonPrimitiveOpPrivateData<F>>],

    phantom: core::marker::PhantomData<Config>,
}

impl<'a, F: CircuitField, Config: Poseidon2Params> Poseidon2TraceBuilder<'a, F, Config> {
    /// Creates a new Poseidon2 trace builder.
    pub fn new(
        circuit: &'a Circuit<F>,
        witness: &'a [Option<F>],
        non_primitive_op_private_data: &'a [Option<NonPrimitiveOpPrivateData<F>>],
    ) -> Self {
        Self {
            circuit,
            witness,
            non_primitive_op_private_data,
            phantom: core::marker::PhantomData,
        }
    }

    fn get_witness(&self, index: &WitnessId) -> Result<F, CircuitError> {
        self.witness
            .get(index.0 as usize)
            .and_then(|opt| opt.as_ref())
            .cloned()
            .ok_or(CircuitError::WitnessNotSet { witness_id: *index })
    }

    /// Builds the Poseidon2 trace by scanning non-primitive ops with hash executors.
    /// Also maintains state and fills state hints for stateful operations.
    pub fn build(self) -> Result<Poseidon2Trace<F>, CircuitError> {
        let mut operations = Vec::new();

        let width = Config::WIDTH;
        let d = Config::D;

        for op in &self.circuit.non_primitive_ops {
            let Op::NonPrimitiveOpWithExecutor {
                inputs,
                outputs,
                executor,
                op_id: _op_id,
            } = op
            else {
                continue;
            };

            match executor.op_type() {
                NonPrimitiveOpType::HashAbsorb { reset } => {
                    let input_wids = inputs.first().ok_or(
                        CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                            op: executor.op_type().clone(),
                            expected: "at least 1 input vector".to_string(),
                            got: inputs.len(),
                        },
                    )?;

                    let input_values: Vec<F> = input_wids
                        .iter()
                        .map(|wid| self.get_witness(wid))
                        .collect::<Result<Vec<F>, _>>()?;

                    let mut padded_inputs = input_values.clone();
                    padded_inputs.resize(width, F::ZERO);

                    let mut in_ctl = [false; 4];
                    let mut in_idx = [0u32; 4];
                    for (limb, chunk) in input_wids.chunks(d).take(4).enumerate() {
                        if let Some(first) = chunk.first() {
                            in_ctl[limb] = true;
                            in_idx[limb] = first.0;
                        }
                    }

                    operations.push(Poseidon2CircuitRow {
                        new_start: *reset,
                        merkle_path: false,
                        mmcs_bit: false,
                        mmcs_index_sum: F::ZERO,
                        input_values: padded_inputs,
                        in_ctl,
                        input_indices: in_idx,
                        out_ctl: [false; 2],
                        output_indices: [0; 2],
                        mmcs_index_sum_idx: 0,
                    });
                }
                NonPrimitiveOpType::HashSqueeze => {
                    // For HashSqueeze, outputs[0] contains squeezed values + new state capacity
                    let output_wids = outputs.first().ok_or(
                        CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                            op: executor.op_type().clone(),
                            expected: "at least 1 output vector".to_string(),
                            got: outputs.len(),
                        },
                    )?;

                    // Validate outputs are set (values will be verified by AIR constraints)
                    let _output_values: Vec<F> = output_wids
                        .iter()
                        .map(|wid| self.get_witness(wid))
                        .collect::<Result<Vec<F>, _>>()?;

                    let mut out_ctl = [false; 2];
                    let mut out_idx = [0u32; 2];
                    for (limb, chunk) in output_wids.chunks(d).take(2).enumerate() {
                        if let Some(first) = chunk.first() {
                            out_ctl[limb] = true;
                            out_idx[limb] = first.0;
                        }
                    }

                    operations.push(Poseidon2CircuitRow {
                        new_start: false,
                        merkle_path: false,
                        mmcs_bit: false,
                        mmcs_index_sum: F::ZERO,
                        input_values: vec![F::ZERO; width],
                        in_ctl: [false; 4],
                        input_indices: [0; 4],
                        out_ctl,
                        output_indices: out_idx,
                        mmcs_index_sum_idx: 0,
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
pub fn generate_poseidon2_trace<F: CircuitField, Config: Poseidon2Params>(
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
