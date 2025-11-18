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
use crate::op::{
    ExecutionContext, HashHint, NonPrimitiveExecutor, NonPrimitiveOpConfig, NonPrimitiveOpType,
};
use crate::types::{ExprId, NonPrimitiveOpId, WitnessId};
use crate::{CircuitError, circuit};

pub trait CircuitPermutation<F> {
    fn permute(&self, input: &[F]) -> Vec<F>;
}

/// Configuration parameters for hash operations.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct HashConfig {
    /// Rate (number of elements absorbed/squeezed per operation)
    pub rate: usize,
}

pub struct CircuitSponge {
    reset: bool,
    buffer: Vec<ExprId>,
}

impl CircuitSponge {
    pub fn new() -> Self {
        Self {
            reset: true,
            buffer: Vec::new(),
        }
    }

    pub fn reset(&mut self) {
        self.reset = true;
        self.buffer.clear();
    }
}

/// Hash operations trait for `CircuitBuilder`.
pub trait HashOps<F: Clone + PrimeCharacteristicRing + Eq + Hash> {
    /// Buffer input field elements into the sponge state.
    /// Does not produce any operations until a squeeze is performed.
    fn sponge_add_inputs(
        &mut self,
        inputs: &[ExprId],
        circuit_sponge: &mut CircuitSponge,
        reset: bool,
    ) -> Result<(), CircuitBuilderError>;

    /// Consumes all buffered inputs and squeeze `RATE` field elements from the sponge state, creating outputs.
    /// If `reset` is set to `true`, the sponge state is reset before absorbing inputs.
    fn sponge_squeeze(
        &mut self,
        circuit_sponge: &mut CircuitSponge,
    ) -> Result<Vec<ExprId>, CircuitBuilderError>;
}

impl<F> HashOps<F> for CircuitBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + Eq + Hash,
{
    fn sponge_add_inputs(
        &mut self,
        inputs: &[ExprId],
        circuit_sponge: &mut CircuitSponge,
        reset: bool,
    ) -> Result<(), CircuitBuilderError> {
        if reset {
            circuit_sponge.buffer.clear();
            circuit_sponge.reset = true;
        }
        circuit_sponge.buffer.extend_from_slice(inputs);
        Ok(())
    }

    fn sponge_squeeze(
        &mut self,
        circuit_sponge: &mut CircuitSponge,
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
        let hash_config = if let Some(config) =
            self.config()
                .get_op_config(&NonPrimitiveOpType::HashSqueeze {
                    reset: circuit_sponge.reset,
                }) {
            if let NonPrimitiveOpConfig::HashConfig(hash_config) = config {
                hash_config
            } else {
                return Err(CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                    op: NonPrimitiveOpType::HashSqueeze {
                        reset: circuit_sponge.reset,
                    },
                });
            }
        } else {
            return Err(CircuitBuilderError::OpNotAllowed {
                op: NonPrimitiveOpType::HashSqueeze {
                    reset: circuit_sponge.reset,
                },
            });
        };

        let rate = hash_config.rate;

        let filler = HashHint::new(&circuit_sponge.buffer, rate);
        let outputs = self.alloc_witness_hints(filler, "hash squeeze");

        self.push_non_primitive_op(
            NonPrimitiveOpType::HashSqueeze {
                reset: circuit_sponge.reset,
            },
            vec![circuit_sponge.buffer.to_vec()],
            "HashSqueeze",
        );

        circuit_sponge.reset = false;
        circuit_sponge.buffer.clear();

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
    fn test_hash_squeeze() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        circuit.enable_hash_squeeze(&HashConfig::default());

        let mut sponge = CircuitSponge::new();
        let _outputs = circuit.sponge_squeeze(&mut sponge).unwrap();
    }

    #[test]
    fn test_hash_absorb_squeeze_sequence() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        circuit.enable_hash_squeeze(&HashConfig::default());

        let mut sponge = CircuitSponge::new();

        // Absorb
        let input = circuit.add_const(BabyBear::ONE);
        circuit
            .sponge_add_inputs(&[input], &mut sponge, true)
            .unwrap();

        // Squeeze
        let _outputs = circuit.sponge_squeeze(&mut sponge).unwrap();
    }

    #[test]
    fn test_hash_squeeze_not_enabled() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();

        let mut sponge = CircuitSponge::new();
        let result = circuit.sponge_squeeze(&mut sponge);
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
    pub fn new(reset: bool) -> Self {
        Self {
            op_type: NonPrimitiveOpType::HashSqueeze { reset },
        }
    }
}

impl Default for HashSqueezeExecutor {
    fn default() -> Self {
        Self::new(true)
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
