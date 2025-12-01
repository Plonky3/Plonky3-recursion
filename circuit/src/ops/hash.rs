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
use crate::op::{ExecutionContext, NonPrimitiveExecutor, NonPrimitiveOpType, WitnessHintsFiller};
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

    /// Add hash squeeze operation with custom hint filler.
    /// This allows providing precomputed values for the squeeze outputs.
    fn add_hash_squeeze_with_filler<W: 'static + WitnessHintsFiller<F>>(
        &mut self,
        filler: W,
        label: &'static str,
    ) -> Result<Vec<ExprId>, CircuitBuilderError>;
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

        Ok(self.push_non_primitive_op(
            NonPrimitiveOpType::HashAbsorb { reset },
            vec![inputs.to_vec()],
            "HashAbsorb",
        ))
    }

    fn add_hash_squeeze(&mut self, count: usize) -> Result<Vec<ExprId>, CircuitBuilderError> {
        self.ensure_op_enabled(NonPrimitiveOpType::HashSqueeze)?;

        let outputs = self.alloc_witness_hints_default_filler(count, "hash_squeeze_output");

        let _ = self.push_non_primitive_op(
            NonPrimitiveOpType::HashSqueeze,
            vec![outputs.to_vec()],
            "HashSqueeze",
        );

        Ok(outputs)
    }

    fn add_hash_squeeze_with_filler<W: 'static + WitnessHintsFiller<F>>(
        &mut self,
        filler: W,
        label: &'static str,
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
        self.ensure_op_enabled(NonPrimitiveOpType::HashSqueeze)?;

        let outputs = self.alloc_witness_hints(filler, label);

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
    pub const fn new(reset: bool) -> Self {
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
        _ctx: &mut ExecutionContext<'_, F>,
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
    pub const fn new() -> Self {
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
        _ctx: &mut ExecutionContext<'_, F>,
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
