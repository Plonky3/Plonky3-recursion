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
/// This implements the Poseidon Permutation Table specification.
/// See: https://github.com/Plonky3/Plonky3-recursion/discussions/186
///
/// The table has one row per Poseidon call, implementing:
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
    /// Control: If 1, row begins a new independent Poseidon chain.
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
    pub in_ctl: [bool; WIDTH_EXT],
    /// Input exposure indices: index into the witness table for each limb.
    pub input_indices: [u32; WIDTH_EXT],
    /// Output exposure flags: for digest limbs only, if 1, out[i] must match witness lookup at output_indices[i].
    /// Note: capacity limbs are never publicly exposed (always private).
    pub out_ctl: [bool; DIGEST_EXT],
    /// Output exposure indices: index into the witness table for digest limbs.
    pub output_indices: [u32; DIGEST_EXT],
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
    /// TODO: Replace sponge ops with perm ops - remove HashAbsorb/HashSqueeze operations
    /// and replace them with permutation operations in trace generation and table.
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
pub struct Poseidon2TraceBuilder<'a, F, Config: Poseidon2Params> {
    circuit: &'a Circuit<F>,
    witness: &'a [Option<F>],
    #[allow(dead_code)] // TODO: Will be used when filling the state with hints
    non_primitive_op_private_data: &'a [Option<NonPrimitiveOpPrivateData<F>>],

    phantom: core::marker::PhantomData<Config>,
}

impl<'a, F: CircuitField, Config: Poseidon2Params> Poseidon2TraceBuilder<'a, F, Config> {
    /// Creates a new Poseidon2 trace builder.
    pub const fn new(
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

    /// Builds operations
    // This is done without const generics, because it's easier to match on the op type.
    // It will be converted back to a const-generic version in batch_stark_prover.
    fn build_operations(self) -> Result<Vec<Poseidon2CircuitRowDyn<F>>, CircuitError> {
        let mut operations = Vec::new();

        let width = Config::WIDTH;
        let d = Config::D;
        let width_ext = Config::WIDTH_EXT;
        let digest_ext = Config::DIGEST_EXT;

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
                    // For HashAbsorb, inputs[0] contains the input values
                    // inputs[1] may contain previous state capacity (if reset=false)
                    let input_wids = inputs.first().ok_or_else(|| {
                        CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                            op: executor.op_type().clone(),
                            expected: "at least 1 input vector".to_string(),
                            got: inputs.len(),
                        }
                    })?;

                    let input_values: Vec<F> = input_wids
                        .iter()
                        .map(|wid| self.get_witness(wid))
                        .collect::<Result<Vec<F>, _>>()?;

                    let mut padded_inputs = input_values.clone();
                    padded_inputs.resize(width, F::ZERO);

                    let mut in_ctl = vec![false; width_ext];
                    let mut in_idx = vec![0u32; width_ext];
                    for (limb, chunk) in input_wids.chunks(d).take(width_ext).enumerate() {
                        if let Some(first) = chunk.first() {
                            in_ctl[limb] = true;
                            in_idx[limb] = first.0;
                        }
                    }

                    operations.push(Poseidon2CircuitRowDyn {
                        new_start: *reset,
                        merkle_path: false,
                        mmcs_bit: false,
                        mmcs_index_sum: F::ZERO,
                        input_values: padded_inputs,
                        in_ctl,
                        input_indices: in_idx,
                        out_ctl: vec![false; digest_ext],
                        output_indices: vec![0; digest_ext],
                        mmcs_index_sum_idx: 0,
                    });
                }
                NonPrimitiveOpType::HashSqueeze => {
                    // For HashSqueeze, outputs[0] contains squeezed values + new state capacity
                    let output_wids = outputs.first().ok_or_else(|| {
                        CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                            op: executor.op_type().clone(),
                            expected: "at least 1 output vector".to_string(),
                            got: outputs.len(),
                        }
                    })?;

                    // Validate outputs are set (values will be verified by AIR constraints)
                    let _output_values: Vec<F> = output_wids
                        .iter()
                        .map(|wid| self.get_witness(wid))
                        .collect::<Result<Vec<F>, _>>()?;

                    let mut out_ctl = vec![false; digest_ext];
                    let mut out_idx = vec![0u32; digest_ext];
                    for (limb, chunk) in output_wids.chunks(d).take(digest_ext).enumerate() {
                        if let Some(first) = chunk.first() {
                            out_ctl[limb] = true;
                            out_idx[limb] = first.0;
                        }
                    }

                    operations.push(Poseidon2CircuitRowDyn {
                        new_start: false,
                        merkle_path: false,
                        mmcs_bit: false,
                        mmcs_index_sum: F::ZERO,
                        input_values: vec![F::ZERO; width],
                        in_ctl: vec![false; width_ext],
                        input_indices: vec![0; width_ext],
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
pub fn generate_poseidon2_trace<F: CircuitField, Config: Poseidon2Params>(
    circuit: &Circuit<F>,
    witness: &[Option<F>],
    non_primitive_data: &[Option<NonPrimitiveOpPrivateData<F>>],
) -> Result<Option<Box<dyn NonPrimitiveTrace<F>>>, CircuitError> {
    let builder = Poseidon2TraceBuilder::<F, Config>::new(circuit, witness, non_primitive_data);

    let operations = builder.build_operations()?;
    if operations.is_empty() {
        Ok(None)
    } else {
        Ok(Some(Box::new(Poseidon2TraceDyn::new(operations))))
    }
}

/// Non-generic version of [`Poseidon2CircuitRow`], to be used for trait objects.
//This is used as an intermediate step, but the const-generic version
// is used in the AIR and by the batch_stark_prover.
#[derive(Clone)]
pub struct Poseidon2CircuitRowDyn<F> {
    new_start: bool,
    merkle_path: bool,
    mmcs_bit: bool,
    mmcs_index_sum: F,
    input_values: Vec<F>,
    in_ctl: Vec<bool>,
    input_indices: Vec<u32>,
    out_ctl: Vec<bool>,
    output_indices: Vec<u32>,
    mmcs_index_sum_idx: u32,
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
        let operations: Result<Vec<_>, _> = self
            .operations
            .iter()
            .map(|row| {
                Ok(Poseidon2CircuitRow {
                    new_start: row.new_start,
                    merkle_path: row.merkle_path,
                    mmcs_bit: row.mmcs_bit,
                    mmcs_index_sum: row.mmcs_index_sum.clone(),
                    input_values: row.input_values.clone(),
                    in_ctl: row
                        .in_ctl
                        .clone()
                        .try_into()
                        .map_err(|_| CircuitError::InvalidTraceData)?,
                    input_indices: row
                        .input_indices
                        .clone()
                        .try_into()
                        .map_err(|_| CircuitError::InvalidTraceData)?,
                    out_ctl: row
                        .out_ctl
                        .clone()
                        .try_into()
                        .map_err(|_| CircuitError::InvalidTraceData)?,
                    output_indices: row
                        .output_indices
                        .clone()
                        .try_into()
                        .map_err(|_| CircuitError::InvalidTraceData)?,
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
