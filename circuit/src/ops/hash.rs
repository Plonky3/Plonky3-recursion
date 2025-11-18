//! Module defining hash operations for circuit builder.
//!
//! Provides methods for absorbing and squeezing elements using a sponge
//! construction within the circuit.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_field::{Field, PrimeCharacteristicRing};

use crate::CircuitError;
use crate::builder::{CircuitBuilder, CircuitBuilderError};
use crate::op::{ExecutionContext, NonPrimitiveExecutor, NonPrimitiveOpType};
use crate::types::{ExprId, NonPrimitiveOpId, WitnessId};

/// Hash operations trait for `CircuitBuilder`.
pub trait HashOps<F: Clone + PrimeCharacteristicRing + Eq + Hash> {
    /// Absorb field elements into the sponge state.
    ///
    /// # Arguments
    ///
    /// * `inputs` - The `ExprId`s to absorb
    /// * `reset` - Whether to reset the sponge state before absorbing
    fn add_hash_absorb(
        &mut self,
        inputs: &[ExprId],
        reset: bool,
    ) -> Result<NonPrimitiveOpId, CircuitBuilderError>;

    /// Squeeze field elements from the sponge state, creating outputs.
    ///
    /// Returns the newly created output `ExprId`s.
    fn add_hash_squeeze(&mut self, count: usize) -> Result<Vec<ExprId>, CircuitBuilderError>;
}

impl<F> HashOps<F> for CircuitBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + Eq + Hash,
{
    fn add_hash_absorb(
        &mut self,
        inputs: &[ExprId],
        reset: bool,
    ) -> Result<NonPrimitiveOpId, CircuitBuilderError> {
        self.ensure_op_enabled(NonPrimitiveOpType::HashAbsorb { reset })?;

        // Capacity size: For BabyBear D=4, WIDTH=16, RATE_EXT=2, CAPACITY_EXT=2
        // Capacity in base elements = CAPACITY_EXT * D = 2 * 4 = 8
        // TODO: Make this configurable via NonPrimitiveOpConfig
        const CAPACITY_SIZE: usize = 8;

        let mut operation_inputs = vec![inputs.to_vec()];
        
        // If not resetting, accept previous state capacity as input
        // TODO: When lookups are implemented, these hints will be used to verify
        // that state transitions match the witness table via lookups
        if !reset {
            let prev_state = self.alloc_witness_hints_default_filler(
                CAPACITY_SIZE,
                "hash_state_capacity_input",
            );
            operation_inputs.push(prev_state);
        }

        // TODO: Output new state capacity for next operation
        // Currently state is maintained internally by the trace generator and verified
        // by AIR constraints. When lookups are implemented, these hints will be filled
        // with computed state values and used to verify state transitions via lookups.
        // The hints will also need to be connected to the next operation's state input hints.
        let _new_state = self.alloc_witness_hints_default_filler(
            CAPACITY_SIZE,
            "hash_state_capacity_output",
        );

        Ok(self.push_non_primitive_op(
            NonPrimitiveOpType::HashAbsorb { reset },
            operation_inputs,
            "HashAbsorb",
        ))
    }

    fn add_hash_squeeze(&mut self, count: usize) -> Result<Vec<ExprId>, CircuitBuilderError> {
        self.ensure_op_enabled(NonPrimitiveOpType::HashSqueeze)?;

        // Capacity size: same as in add_hash_absorb
        const CAPACITY_SIZE: usize = 8;

        // TODO: When lookups are implemented, accept current state capacity as input.
        // For now, the input state is not needed as the trace generator maintains it internally.
        
        // Output squeezed values
        let outputs = self.alloc_witness_hints_default_filler(count, "hash_squeeze_output");
        
        // TODO: Output new state capacity when lookups are enabled.
        let new_state = self.alloc_witness_hints_default_filler(
            CAPACITY_SIZE,
            "hash_state_capacity_output",
        );

        // Combine outputs: squeezed values + new state
        let mut all_outputs = outputs.clone();
        all_outputs.extend(new_state);

        let _ = self.push_non_primitive_op(
            NonPrimitiveOpType::HashSqueeze,
            vec![all_outputs],
            "HashSqueeze",
        );

        Ok(outputs)
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::op::NonPrimitiveOpConfig;

    #[test]
    fn test_hash_absorb() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        circuit.enable_op(
            NonPrimitiveOpType::HashAbsorb { reset: true },
            NonPrimitiveOpConfig::None,
        );

        let input1 = circuit.add_const(BabyBear::ONE);
        let input2 = circuit.add_const(BabyBear::TWO);

        circuit.add_hash_absorb(&[input1, input2], true).unwrap();
    }

    #[test]
    fn test_hash_squeeze() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        circuit.enable_op(NonPrimitiveOpType::HashSqueeze, NonPrimitiveOpConfig::None);

        let _outputs = circuit.add_hash_squeeze(1).unwrap();
    }

    #[test]
    fn test_hash_absorb_squeeze_sequence() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        circuit.enable_op(
            NonPrimitiveOpType::HashAbsorb { reset: true },
            NonPrimitiveOpConfig::None,
        );
        circuit.enable_op(NonPrimitiveOpType::HashSqueeze, NonPrimitiveOpConfig::None);

        // Absorb
        let input = circuit.add_const(BabyBear::ONE);
        circuit.add_hash_absorb(&[input], true).unwrap();

        // Squeeze
        let _outputs = circuit.add_hash_squeeze(1).unwrap();
    }

    #[test]
    fn test_hash_absorb_not_enabled() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();

        let input = circuit.add_const(BabyBear::ONE);
        let result = circuit.add_hash_absorb(&[input], true);

        assert!(result.is_err());
    }

}

/// Executor for hash absorb operations
///
/// The state is maintained internally and propagated via witness hints.
#[derive(Debug, Clone)]
pub struct HashAbsorbExecutor {
    op_type: NonPrimitiveOpType,
}

impl HashAbsorbExecutor {
    /// Create a new hash absorb executor
    pub fn new(reset: bool) -> Self {
        Self {
            op_type: NonPrimitiveOpType::HashAbsorb { reset },
        }
    }
}

impl<F: Field> NonPrimitiveExecutor<F> for HashAbsorbExecutor {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        _outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<F>,
    ) -> Result<(), CircuitError> {
        // For HashAbsorb:
        // - inputs[0] = data to absorb
        // - inputs[1] = previous state capacity (if reset=false)
        // - outputs would contain new state capacity, but we handle it via hints (currently unused)
        
        // Validate inputs are present (state will be read by trace generator)
        if inputs.is_empty() {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                op: self.op_type.clone(),
                expected: "at least 1 input vector".to_string(),
                got: 0,
            });
        }

        // Read previous state if not resetting (for validation)
        // TODO: When lookups are implemented, we'll need to fill state output hints here
        // with computed values so lookups can verify state transitions match the witness table
        if let NonPrimitiveOpType::HashAbsorb { reset } = &self.op_type {
            if !*reset && inputs.len() > 1 {
                // Validate that previous state hints are present
                // The actual values will be read and used by the trace generator
                let _prev_state = inputs[1]
                    .iter()
                    .map(|&wid| ctx.get_witness(wid))
                    .collect::<Result<Vec<F>, _>>()?;
                // State is validated but not used here - trace generator will use it
            }
        }

        // TODO: When lookups are implemented, compute permutation here and
        // fill state output hints.
        
        Ok(())
    }

    fn op_type(&self) -> &NonPrimitiveOpType {
        &self.op_type
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}

/// Executor for hash squeeze operations
///
/// Maintains Poseidon2 sponge state between operations using hints.
#[derive(Debug, Clone)]
pub struct HashSqueezeExecutor {
    op_type: NonPrimitiveOpType,
}

impl HashSqueezeExecutor {
    /// Create a new hash squeeze executor
    pub fn new() -> Self {
        Self {
            op_type: NonPrimitiveOpType::HashSqueeze,
        }
    }
}

impl Default for HashSqueezeExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field> NonPrimitiveExecutor<F> for HashSqueezeExecutor {
    fn execute(
        &self,
        _inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        _ctx: &mut ExecutionContext<F>,
    ) -> Result<(), CircuitError> {
        // For HashSqueeze:
        // - inputs[0] would be state capacity (currently not passed, maintained by trace generator)
        // - outputs[0] = squeezed values + new state capacity
        
        // Validate outputs are present
        if outputs.is_empty() || outputs[0].is_empty() {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                op: self.op_type.clone(),
                expected: "at least 1 output".to_string(),
                got: outputs.len(),
            });
        }
        
        // TODO: When lookups are implemented, read state from inputs and compute
        // Poseidon2 permutation here, then fill output hints. Currently, the trace
        // generator handles the actual computation and AIR constraints verify state
        // transitions. Lookups will add an additional verification layer to ensure
        // witness table values match the trace.
        
        Ok(())
    }

    fn op_type(&self) -> &NonPrimitiveOpType {
        &self.op_type
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}
