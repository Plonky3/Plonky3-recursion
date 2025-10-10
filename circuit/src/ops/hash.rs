use p3_field::PrimeCharacteristicRing;

use crate::builder::{CircuitBuilder, CircuitBuilderError};
use crate::op::NonPrimitiveOpType;
use crate::types::{ExprId, NonPrimitiveOpId};

/// Extension trait for hash-related non-primitive ops.
pub trait HashOps<F>
where
    F: PrimeCharacteristicRing,
{
    /// Add a hash absorb operation to the circuit.
    ///
    /// Absorbs the given inputs into the sponge state. If `reset` is true,
    /// the sponge state is reset before absorbing.
    ///
    /// # Parameters
    /// - `input_exprs`: Field elements to absorb into the sponge
    /// - `reset`: Whether to reset the sponge state before absorbing
    ///
    /// # Returns
    /// Operation ID that can be used to set private data if needed
    fn add_hash_absorb(
        &mut self,
        input_exprs: &[ExprId],
        reset: bool,
    ) -> Result<NonPrimitiveOpId, CircuitBuilderError>;

    /// Add a hash squeeze operation to the circuit.
    ///
    /// Extracts challenge values from the sponge state.
    ///
    /// # Parameters
    /// - `output_exprs`: Expressions that will receive the squeezed values
    ///
    /// # Returns
    /// Operation ID that can be used to set private data if needed
    fn add_hash_squeeze(
        &mut self,
        output_exprs: &[ExprId],
    ) -> Result<NonPrimitiveOpId, CircuitBuilderError>;
}

impl<F> HashOps<F> for CircuitBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + Eq + core::hash::Hash,
{
    fn add_hash_absorb(
        &mut self,
        input_exprs: &[ExprId],
        reset: bool,
    ) -> Result<NonPrimitiveOpId, CircuitBuilderError> {
        self.ensure_op_enabled(NonPrimitiveOpType::HashAbsorb { reset })?;

        let witness_exprs = input_exprs.to_vec();
        Ok(self.push_non_primitive_op(NonPrimitiveOpType::HashAbsorb { reset }, witness_exprs))
    }

    fn add_hash_squeeze(
        &mut self,
        output_exprs: &[ExprId],
    ) -> Result<NonPrimitiveOpId, CircuitBuilderError> {
        self.ensure_op_enabled(NonPrimitiveOpType::HashSqueeze)?;

        let witness_exprs = output_exprs.to_vec();
        Ok(self.push_non_primitive_op(NonPrimitiveOpType::HashSqueeze, witness_exprs))
    }
}
