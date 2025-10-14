//! Module defining hash operations for circuit builder.
//!
//! Provides methods for absorbing and squeezing elements using a sponge
//! construction within the circuit.

use alloc::boxed::Box;
use alloc::vec;

use p3_field::{Field, PrimeCharacteristicRing};

use crate::CircuitError;
use crate::builder::{CircuitBuilder, CircuitBuilderError};
use crate::op::{ExecutionContext, NonPrimitiveExecutor, NonPrimitiveOpType};
use crate::types::{ExprId, WitnessId};

/// Hash operations trait for `CircuitBuilder`.
pub trait HashOps<F: Clone + PrimeCharacteristicRing + Eq + core::hash::Hash> {
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
    ) -> Result<ExprId, CircuitBuilderError>;

    /// Squeeze field elements from the sponge state.
    ///
    /// # Arguments
    ///
    /// * `outputs` - The `ExprId`s to store squeezed values in
    fn add_hash_squeeze(&mut self, outputs: &[ExprId]) -> Result<ExprId, CircuitBuilderError>;
}

impl<F> HashOps<F> for CircuitBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + Eq + core::hash::Hash,
{
    fn add_hash_absorb(
        &mut self,
        inputs: &[ExprId],
        reset: bool,
    ) -> Result<ExprId, CircuitBuilderError> {
        self.push_non_primitive_op(
            NonPrimitiveOpType::HashAbsorb { reset },
            inputs.to_vec(),
            vec![],
            "HashAbsorb",
        )
    }

    fn add_hash_squeeze(&mut self, outputs: &[ExprId]) -> Result<ExprId, CircuitBuilderError> {
        self.push_non_primitive_op(
            NonPrimitiveOpType::HashSqueeze,
            vec![],
            outputs.to_vec(),
            "HashSqueeze",
        )
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

        let output = circuit.add_public_input();

        circuit.add_hash_squeeze(&[output]).unwrap();
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
        let output = circuit.add_public_input();
        circuit.add_hash_squeeze(&[output]).unwrap();
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
        _inputs: &[WitnessId],
        _outputs: &[WitnessId],
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
        _inputs: &[WitnessId],
        _outputs: &[WitnessId],
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
