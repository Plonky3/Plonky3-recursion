//! Hash operation trace generation.
//!
//! This module generates execution traces for HashAbsorb and HashSqueeze operations
//! using Poseidon2 as the underlying permutation function.

use alloc::vec::Vec;

use crate::circuit::Circuit;
use crate::op::NonPrimitiveOp;
use crate::types::WitnessId;
use crate::{CircuitError, CircuitField};

/// Hash operations trace.
///
/// Contains the execution trace for all HashAbsorb and HashSqueeze operations
/// in the circuit, sequenced in the order they were executed.
#[derive(Debug, Clone)]
pub struct HashTrace<F> {
    /// Sequence of hash operations performed
    pub operations: Vec<HashOperation<F>>,
}

/// Represents a single hash operation in the trace.
#[derive(Debug, Clone)]
pub enum HashOperation<F> {
    /// An absorb operation
    Absorb {
        /// Whether to reset the sponge state
        reset: bool,
        /// Input values that were absorbed
        inputs: Vec<F>,
        /// Witness IDs for the inputs
        input_witness_ids: Vec<WitnessId>,
    },
    /// A squeeze operation
    Squeeze {
        /// Output values that were squeezed
        outputs: Vec<F>,
        /// Witness IDs for the outputs
        output_witness_ids: Vec<WitnessId>,
    },
}

/// Generate hash operation trace from circuit and witness values.
pub(super) fn generate_hash_trace<F: CircuitField>(
    circuit: &Circuit<F>,
    witness: &[Option<F>],
) -> Result<HashTrace<F>, CircuitError> {
    let mut operations = Vec::new();

    let get_witness = |widx: WitnessId| -> Result<F, CircuitError> {
        witness
            .get(widx.0 as usize)
            .and_then(|opt| opt.as_ref())
            .cloned()
            .ok_or(CircuitError::WitnessNotSet { witness_id: widx })
    };

    for non_primitive_op in &circuit.non_primitive_ops {
        match non_primitive_op {
            NonPrimitiveOp::Poseidon2Permutation { .. } => {
                // Skip - Poseidon2 permutations are handled separately
                // They're validated by ExtendedPoseidon2Air, not hash trace
            }
            NonPrimitiveOp::HashAbsorb { reset_flag, inputs } => {
                // LEGACY - these operations are no longer used
                let input_values: Result<Vec<F>, _> =
                    inputs.iter().map(|&widx| get_witness(widx)).collect();

                operations.push(HashOperation::Absorb {
                    reset: *reset_flag,
                    inputs: input_values?,
                    input_witness_ids: inputs.clone(),
                });
            }
            NonPrimitiveOp::HashSqueeze { outputs } => {
                // LEGACY - these operations are no longer used
                let output_values: Result<Vec<F>, _> =
                    outputs.iter().map(|&widx| get_witness(widx)).collect();

                operations.push(HashOperation::Squeeze {
                    outputs: output_values?,
                    output_witness_ids: outputs.clone(),
                });
            }
            _ => {
                // Skip non-hash operations
            }
        }
    }

    Ok(HashTrace { operations })
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;

    use crate::CircuitBuilder;
    use crate::op::{NonPrimitiveOpConfig, NonPrimitiveOpType};
    use crate::ops::HashOps;

    #[test]
    fn test_hash_trace_generation() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        circuit.enable_op(
            NonPrimitiveOpType::HashAbsorb { reset: true },
            NonPrimitiveOpConfig::None,
        );
        circuit.enable_op(NonPrimitiveOpType::HashSqueeze, NonPrimitiveOpConfig::None);

        let input1 = circuit.add_const(BabyBear::new(1));
        let input2 = circuit.add_const(BabyBear::new(2));

        circuit.add_hash_absorb(&[input1, input2], true).unwrap();

        let output = circuit.add_public_input();
        circuit.add_hash_squeeze(&[output]).unwrap();

        let circuit = circuit.build().unwrap();
        let mut runner = circuit.runner();

        runner.set_public_inputs(&[BabyBear::new(42)]).unwrap();

        let traces = runner.run().unwrap();

        // Verify hash trace contains the operations
        assert_eq!(traces.hash_trace.operations.len(), 2);

        // First operation should be absorb
        match &traces.hash_trace.operations[0] {
            super::HashOperation::Absorb { reset, inputs, .. } => {
                assert!(reset);
                assert_eq!(inputs.len(), 2);
            }
            _ => panic!("Expected Absorb operation"),
        }

        // Second operation should be squeeze
        match &traces.hash_trace.operations[1] {
            super::HashOperation::Squeeze { outputs, .. } => {
                assert_eq!(outputs.len(), 1);
            }
            _ => panic!("Expected Squeeze operation"),
        }
    }
}
