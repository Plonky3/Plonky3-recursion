use alloc::boxed::Box;
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

/// Poseidon2 operation table
#[derive(Debug, Clone)]
pub struct Poseidon2CircuitRow<F> {
    /// Poseidon2 operation type
    pub is_sponge: bool,
    /// Reset flag
    pub reset: bool,
    /// Absorb flags
    pub absorb_flags: Vec<bool>,
    /// Inputs to the Poseidon2 permutation
    pub input_values: Vec<F>,
    /// Input indices
    pub input_indices: Vec<u32>,
    /// Output indices
    pub output_indices: Vec<u32>,
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

        // Get Poseidon2 parameters from config type
        let capacity_size = Config::CAPACITY_SIZE;
        let rate_ext = Config::RATE_EXT;
        let d = Config::D;

        let mut current_state_capacity: Option<Vec<F>> = None;

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
                NonPrimitiveOpType::HashSqueeze { reset } => {
                    // TODO: Build trace correctly

                    operations.push(Poseidon2CircuitRow {
                        is_sponge: true,
                        reset: false,
                        absorb_flags: vec![false; rate_ext], // No absorb during squeeze
                        input_values: vec![],                // No inputs for squeeze
                        input_indices: vec![],
                        output_indices: vec![],
                    });

                    // TODO: When lookups are implemented, connect the output indices to the input
                    // indices of the next operation.
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
