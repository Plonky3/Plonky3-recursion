use alloc::vec::Vec;

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
    /// - `num_outputs`: Number of field elements to squeeze
    ///
    /// # Returns
    /// Tuple of (operation ID, vector of output expression IDs)
    fn add_hash_squeeze(
        &mut self,
        num_outputs: usize,
    ) -> Result<(NonPrimitiveOpId, Vec<ExprId>), CircuitBuilderError>;
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
        num_outputs: usize,
    ) -> Result<(NonPrimitiveOpId, Vec<ExprId>), CircuitBuilderError> {
        self.ensure_op_enabled(NonPrimitiveOpType::HashSqueeze)?;

        // Allocate public inputs for the squeezed outputs
        // These will be provided by the prover and constrained by the sponge AIR
        let output_exprs: Vec<ExprId> = (0..num_outputs)
            .map(|_| self.add_public_input())
            .collect();

        let op_id = self.push_non_primitive_op(
            NonPrimitiveOpType::HashSqueeze,
            output_exprs.clone(),
        );

        Ok((op_id, output_exprs))
    }
}
