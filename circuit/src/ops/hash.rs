//! Module defining hash operations for circuit builder.
//!
//! Provides methods for absorbing and squeezing elements using a sponge
//! construction within the circuit.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_field::{Field, PrimeCharacteristicRing};

use crate::builder::{CircuitBuilder, CircuitBuilderError};
use crate::op::{ExecutionContext, NonPrimitiveExecutor, NonPrimitiveOpConfig, NonPrimitiveOpType};
use crate::types::{ExprId, NonPrimitiveOpId, WitnessId};
use crate::{CircuitError, circuit};

pub trait CircuitPermutation<F> {
    fn permute(&self, input: &[F]) -> Vec<F>;
}

/// Configuration parameters for hash operations.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct HashConfig {
    /// Rate (number of elements absorbed/squeezed per operation)
    pub rate: usize,
}

pub struct CircuitChallenger {
    reset: bool,
    buffer: Vec<ExprId>,
}

/// Hash operations trait for `CircuitBuilder`.
pub trait HashOps<F: Clone + PrimeCharacteristicRing + Eq + Hash> {
    /// Absorb field elements into the sponge state.
    /// Does not produce any operations until a squeeze is performed.
    fn sponge_absorb(
        &mut self,
        inputs: &[ExprId],
        circuit_challenger: &mut CircuitChallenger,
        reset: bool,
    ) -> Result<(), CircuitBuilderError>;

    /// Squeeze field elements from the sponge state, creating outputs.
    fn sponge_squeeze(
        &mut self,
        circuit_challenger: &mut CircuitChallenger,
    ) -> Result<Vec<ExprId>, CircuitBuilderError>;

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

    /// Squeeze `RATE` elements from the sponge state, creating outputs.
    ///
    /// Returns the newly created output `ExprId`s.
    fn add_hash_squeeze(&mut self, rate: usize) -> Result<Vec<ExprId>, CircuitBuilderError>;
}

impl<F> HashOps<F> for CircuitBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + Eq + Hash,
{
    fn sponge_absorb(
        &mut self,
        inputs: &[ExprId],
        circuit_challenger: &mut CircuitChallenger,
        reset: bool,
    ) -> Result<(), CircuitBuilderError> {
        if reset {
            circuit_challenger.buffer.clear();
            circuit_challenger.reset = true;
        }
        circuit_challenger.buffer.extend_from_slice(inputs);
        Ok(())
    }

    fn sponge_squeeze(
        &mut self,
        circuit_challenger: &mut CircuitChallenger,
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
        let hash_config = if let Some(config) = self
            .config()
            .get_op_config(&NonPrimitiveOpType::HashSqueeze)
        {
            if let NonPrimitiveOpConfig::HashConfig(hash_config) = config {
                hash_config
            } else {
                return Err(CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                    op: NonPrimitiveOpType::HashSqueeze,
                });
            }
        } else {
            return Err(CircuitBuilderError::OpNotAllowed {
                op: NonPrimitiveOpType::HashSqueeze,
            });
        };

        let rate = hash_config.rate;

        // Consume all buffered inputs
        let chunks = circuit_challenger.buffer.chunks(rate).collect::<Vec<_>>();
        for chunk in chunks {
            // The last chunk might not be complete, but we do not pad inputs.
            self.add_hash_absorb(chunk, circuit_challenger.reset)?;
            circuit_challenger.reset = false;
        }

        let outputs = self.add_hash_squeeze(rate)?;
        Ok(outputs)
    }

    fn add_hash_absorb(
        &mut self,
        inputs: &[ExprId],
        reset: bool,
    ) -> Result<NonPrimitiveOpId, CircuitBuilderError> {
        self.ensure_op_enabled(NonPrimitiveOpType::HashAbsorb { reset })?;

        Ok(self.push_non_primitive_op(
            NonPrimitiveOpType::HashAbsorb { reset },
            vec![inputs.to_vec()],
            "HashAbsorb",
        ))
    }

    fn add_hash_squeeze(&mut self, rate: usize) -> Result<Vec<ExprId>, CircuitBuilderError> {
        self.ensure_op_enabled(NonPrimitiveOpType::HashSqueeze)?;

        // let filler =
        let outputs = self.alloc_witness_hints_default_filler(rate, "hash_squeeze_output");

        let _ = self.push_non_primitive_op(
            NonPrimitiveOpType::HashSqueeze,
            vec![outputs.to_vec()],
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
/// TODO: This is a dummy implementation.
/// Sponge state will be tracked by a dedicated AIR structure in the future.
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
        _inputs: &[Vec<WitnessId>],
        _outputs: &[Vec<WitnessId>],
        _ctx: &mut ExecutionContext<F>,
    ) -> Result<(), CircuitError> {
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
/// TODO: This is a dummy implementation.
/// Sponge state will be tracked by a dedicated AIR structure in the future.
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
        _outputs: &[Vec<WitnessId>],
        _ctx: &mut ExecutionContext<F>,
    ) -> Result<(), CircuitError> {
        Ok(())
    }

    fn op_type(&self) -> &NonPrimitiveOpType {
        &self.op_type
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}
