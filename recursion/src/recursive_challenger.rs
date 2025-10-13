//! Recursive challenger trait for Fiat-Shamir transformations in circuits.
//!
//! This module defines the interface for performing Fiat-Shamir operations
//! within a circuit.

use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
use p3_circuit::utils::decompose_to_bits;
use p3_field::Field;

use crate::Target;

/// Trait for performing Fiat-Shamir operations within a circuit.
///
/// Maintains an internal sponge state as circuit targets and provides methods to:
/// - Observe field elements
/// - Sample challenges
pub trait RecursiveChallenger<F: Field> {
    /// Observe a single field element in the Fiat-Shamir transcript.
    fn observe(&mut self, circuit: &mut CircuitBuilder<F>, value: Target);

    /// Observe multiple field elements in the Fiat-Shamir transcript.
    fn observe_slice(&mut self, circuit: &mut CircuitBuilder<F>, values: &[Target]) {
        for &value in values {
            self.observe(circuit, value);
        }
    }

    /// Sample a challenge from the current challenger state.
    fn sample(&mut self, circuit: &mut CircuitBuilder<F>) -> Target;

    /// Sample multiple challenges.
    fn sample_vec(&mut self, circuit: &mut CircuitBuilder<F>, count: usize) -> Vec<Target> {
        (0..count).map(|_| self.sample(circuit)).collect()
    }

    fn sample_bits(
        &mut self,
        circuit: &mut CircuitBuilder<F>,
        total_num_bits: usize,
        num_bits: usize,
    ) -> Vec<Target> {
        let x = self.sample(circuit);
        // Adds one public input per bit (there are as many bits as for a field element).
        // It also checks that the bits are boolean and they are equal to `x`.
        let bits = decompose_to_bits(circuit, x, total_num_bits);

        bits[..num_bits].to_vec()
    }

    fn check_witness(
        &mut self,
        circuit: &mut CircuitBuilder<F>,
        witness_bits: usize,
        witness: Target,
        total_num_bits: usize,
    ) {
        // TODO: Replace `sample_bits` with a specific method that only gets returns the final bits: the first ones are all 0.
        self.observe(circuit, witness);
        let bits = self.sample_bits(circuit, total_num_bits, witness_bits);
        for bit in bits {
            circuit.assert_zero(bit);
        }
    }

    /// Clear the challenger state.
    fn clear(&mut self);
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    impl<F: Field> RecursiveChallenger<F> for () {
        fn observe(&mut self, _circuit: &mut CircuitBuilder<F>, _value: Target) {
            // No-op: no challenger to observe with
        }

        fn sample(&mut self, circuit: &mut CircuitBuilder<F>) -> Target {
            circuit.add_public_input()
        }

        fn clear(&mut self) {
            // No-op: no challenger to clear
        }
    }

    #[test]
    fn test_noop_challenger() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        let mut challenger = ();

        let value = circuit.add_const(BabyBear::ONE);
        challenger.observe(&mut circuit, value);

        let challenge = challenger.sample(&mut circuit);
        assert!(challenge.0 > 0);

        let challenges = challenger.sample_vec(&mut circuit, 3);
        assert_eq!(challenges.len(), 3);
    }
}
