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

// Ensure Poseidon2Trace is Send + Sync for use in parallel contexts
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
pub struct Poseidon2TraceBuilder<'a, F> {
    circuit: &'a Circuit<F>,
    witness: &'a [Option<F>],
    #[allow(dead_code)] // Will be used when we implement state hint filling
    non_primitive_op_private_data: &'a [Option<NonPrimitiveOpPrivateData<F>>],
}

impl<'a, F: CircuitField> Poseidon2TraceBuilder<'a, F> {
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
        
        // Maintain state between operations
        // Capacity size: For BabyBear D=4, WIDTH=16, RATE_EXT=2, CAPACITY_EXT=2
        // Capacity in base elements = CAPACITY_EXT * D = 2 * 4 = 8
        const CAPACITY_SIZE: usize = 8;
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
                NonPrimitiveOpType::HashAbsorb { reset } => {
                    // For HashAbsorb, inputs[0] contains the input values
                    // inputs[1] may contain previous state capacity (if reset=false)
                    let input_wids = inputs.get(0).ok_or(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                        op: executor.op_type().clone(),
                        expected: "at least 1 input vector".to_string(),
                        got: inputs.len(),
                    })?;

                    let input_values: Vec<F> = input_wids
                        .iter()
                        .map(|wid| self.get_witness(wid))
                        .collect::<Result<Vec<F>, _>>()?;

                    // Read previous state if not resetting
                    if !*reset {
                        if let Some(prev_state_wids) = inputs.get(1) {
                            // Read previous state from hints
                            let prev_state: Vec<F> = prev_state_wids
                                .iter()
                                .map(|wid| self.get_witness(wid))
                                .collect::<Result<Vec<F>, _>>()?;
                            current_state_capacity = Some(prev_state);
                        } else if let Some(state) = current_state_capacity.clone() {
                            // Use maintained state
                            current_state_capacity = Some(state);
                        } else {
                            // No previous state, start with zeros
                            current_state_capacity = Some(vec![F::ZERO; CAPACITY_SIZE]);
                        }
                    } else {
                        // Reset: clear state
                        current_state_capacity = Some(vec![F::ZERO; CAPACITY_SIZE]);
                    }

                    // Determine absorb flags - for now, mark all as absorbed
                    // In a full implementation, this would be configurable
                    let absorb_flags = vec![true; input_values.len()];

                    operations.push(Poseidon2CircuitRow {
                        is_sponge: true,
                        reset: *reset,
                        absorb_flags,
                        input_values,
                        input_indices: input_wids.iter().map(|wid| wid.0).collect(),
                        output_indices: vec![], // No outputs for absorb
                    });

                    // TODO: When lookups are implemented, compute new state after permutation
                    // and fill state output hints here. Currently, state is maintained internally
                    // and verified by AIR constraints. Lookups will verify that witness table
                    // values match the computed state.
                }
                NonPrimitiveOpType::HashSqueeze => {
                    // For HashSqueeze, outputs[0] contains squeezed values + new state capacity
                    let output_wids = outputs.get(0).ok_or(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                        op: executor.op_type().clone(),
                        expected: "at least 1 output vector".to_string(),
                        got: outputs.len(),
                    })?;

                    // Split outputs: first part is squeezed values, rest is new state
                    // For now, we'll determine this based on the operation structure
                    // The actual values will be filled by the trace generator based on Poseidon2 computation
                    let output_values: Vec<F> = output_wids
                        .iter()
                        .map(|wid| self.get_witness(wid))
                        .collect::<Result<Vec<F>, _>>()?;

                    // Use current state for this squeeze operation
                    if current_state_capacity.is_none() {
                        current_state_capacity = Some(vec![F::ZERO; CAPACITY_SIZE]);
                    }

                    operations.push(Poseidon2CircuitRow {
                        is_sponge: true,
                        reset: false,
                        absorb_flags: vec![false; output_values.len()], // No absorb during squeeze
                        input_values: vec![], // No inputs for squeeze
                        input_indices: vec![],
                        output_indices: output_wids.iter().map(|wid| wid.0).collect(),
                    });

                    // TODO: When lookups are implemented, compute new state after permutation
                    // and fill state output hints here. Currently, state is maintained internally
                    // and verified by AIR constraints. Lookups will verify that witness table
                    // values match the computed state.
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

/// Generate the Poseidon2 trace if hash operations are present in the circuit.
pub fn generate_poseidon2_trace<F: CircuitField>(
    circuit: &Circuit<F>,
    witness: &[Option<F>],
    non_primitive_data: &[Option<NonPrimitiveOpPrivateData<F>>],
) -> Result<Option<Box<dyn NonPrimitiveTrace<F>>>, CircuitError> {
    let trace = Poseidon2TraceBuilder::new(circuit, witness, non_primitive_data).build()?;
    if trace.total_rows() == 0 {
        Ok(None)
    } else {
        Ok(Some(Box::new(trace)))
    }
}
