//! Recursive challenger trait for Fiat-Shamir transformations in circuits.
//!
//! This module defines the interface for performing Fiat-Shamir operations
//! within a circuit.

use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
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
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::target_allocator::TargetAllocator;

    impl<F: Field> RecursiveChallenger<F> for () {
        fn observe(&mut self, _circuit: &mut CircuitBuilder<F>, _value: Target) {
            // No-op: no challenger to observe with
        }

        fn sample(&mut self, circuit: &mut CircuitBuilder<F>) -> Target {
            let mut alloc = TargetAllocator::new(circuit);
            alloc.alloc("challenge (public input mode)")
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
