//! Poseidon2 permutation operations for circuit builder.

use alloc::vec::Vec;

use p3_field::PrimeCharacteristicRing;

use crate::builder::{CircuitBuilder, CircuitBuilderError};
use crate::op::NonPrimitiveOpType;
use crate::types::ExprId;

/// Poseidon2 permutation operations trait for `CircuitBuilder`.
pub trait Poseidon2Ops<F: Clone + PrimeCharacteristicRing + Eq + core::hash::Hash> {
    /// Apply Poseidon2 permutation to a full state.
    ///
    /// # Arguments
    ///
    /// * `input_state` - The input state (WIDTH elements)
    ///
    /// # Returns
    ///
    /// The output state after applying Poseidon2 permutation (WIDTH elements)
    fn add_poseidon2_permutation(
        &mut self,
        input_state: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError>;
}

impl<F> Poseidon2Ops<F> for CircuitBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + Eq + core::hash::Hash,
{
    fn add_poseidon2_permutation(
        &mut self,
        input_state: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
        self.ensure_op_enabled(NonPrimitiveOpType::Poseidon2Permutation)?;

        // Allocate output state as public inputs
        // TODO: Once Poseidon2 trace generation is fully integrated, these can be
        // witness values constrained by ExtendedPoseidon2Air. For now, they must be
        // public inputs to be provided during execution.
        let width = input_state.len();
        let output_state: Vec<ExprId> = (0..width).map(|_| self.add_public_input()).collect();

        self.push_non_primitive_op(
            NonPrimitiveOpType::Poseidon2Permutation,
            input_state
                .iter()
                .chain(output_state.iter())
                .copied()
                .collect(),
        );

        Ok(output_state)
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;

    use super::*;
    use crate::op::NonPrimitiveOpConfig;

    #[test]
    fn test_poseidon2_permutation() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        circuit.enable_op(
            NonPrimitiveOpType::Poseidon2Permutation,
            NonPrimitiveOpConfig::None,
        );

        // Create a state of 16 elements (WIDTH for BabyBear Poseidon2)
        let input_state: Vec<_> = (0..16)
            .map(|i| circuit.add_const(BabyBear::new(i)))
            .collect();

        let output_state = circuit.add_poseidon2_permutation(&input_state).unwrap();

        assert_eq!(output_state.len(), 16);
    }
}
