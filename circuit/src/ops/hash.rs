//! Module defining hash operations for circuit builder.
//!
//! Provides methods for absorbing and squeezing elements using a sponge
//! construction within the circuit.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_field::{Field, PrimeCharacteristicRing};

use crate::CircuitError;
use crate::builder::{CircuitBuilder, CircuitBuilderError};
use crate::op::{
    ExecutionContext, HashSqueezeHint, NonPrimitiveExecutor, NonPrimitiveOpConfig,
    NonPrimitiveOpType,
};
use crate::types::{ExprId, WitnessId};

pub trait CircuitPermutation<F> {
    fn permute(&self, input: &[F]) -> Vec<F>;
    fn width(&self) -> usize;
}

/// Configuration parameters for hash operations.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct HashConfig {
    /// Rate (number of elements absorbed/squeezed per operation)
    pub rate: usize,
}

/// Hash operations trait for `CircuitBuilder`.
pub trait HashOps<F: Clone + PrimeCharacteristicRing + Eq + Hash> {
    /// Consumes all buffered inputs and squeeze `RATE` field elements from the sponge state, creating outputs.
    /// If `reset` is set to `true`, the sponge state is reset before absorbing inputs.
    fn add_hash_squeeze(
        &mut self,
        inputs: &[ExprId],
        reset: bool,
    ) -> Result<Vec<ExprId>, CircuitBuilderError>;
}

impl<F> HashOps<F> for CircuitBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + Eq + Hash,
{
    fn add_hash_squeeze(
        &mut self,
        inputs: &[ExprId],
        reset: bool,
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
        let hash_config = if let Some(config) = self
            .config()
            .get_op_config(&NonPrimitiveOpType::HashSqueeze { reset: reset })
        {
            if let NonPrimitiveOpConfig::HashConfig(hash_config) = config {
                hash_config
            } else {
                return Err(CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                    op: NonPrimitiveOpType::HashSqueeze { reset: reset },
                });
            }
        } else {
            return Err(CircuitBuilderError::OpNotAllowed {
                op: NonPrimitiveOpType::HashSqueeze { reset: reset },
            });
        };

        let filler = HashSqueezeHint::new(inputs, hash_config.rate, reset);
        let outputs = self.alloc_witness_hints(filler, "hash squeeze");

        let _ = self.push_non_primitive_op(
            NonPrimitiveOpType::HashSqueeze { reset },
            vec![inputs.to_vec(), outputs.clone()],
            "hash squeeze",
        );

        Ok(outputs)
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::tables::{Poseidon2Params, generate_poseidon2_trace};

    struct DummyParams;

    impl Poseidon2Params for DummyParams {
        const D: usize = 4;
        const WIDTH: usize = 16;
        const RATE_EXT: usize = 2;
        const CAPACITY_EXT: usize = 2;
        const SBOX_DEGREE: u64 = 7;
        const SBOX_REGISTERS: usize = 1;
        const HALF_FULL_ROUNDS: usize = 4;
        const PARTIAL_ROUNDS: usize = 13;
    }

    #[test]
    fn test_hash_squeeze() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        circuit.enable_hash_squeeze(
            &HashConfig::default(),
            generate_poseidon2_trace::<BabyBear, DummyParams>,
        );
        let input = circuit.add_const(BabyBear::ONE);
        let _ = circuit.add_hash_squeeze(&[input], true).unwrap();
    }

    #[test]
    fn test_hash_squeeze_not_enabled() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        let input = circuit.add_const(BabyBear::ONE);
        let result = circuit.add_hash_squeeze(&[input], true);
        assert!(result.is_err());
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
