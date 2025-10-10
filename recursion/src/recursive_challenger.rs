//! Recursive challenger for Fiat-Shamir transformations in circuits.
//!
//! This module defines the trait for performing Fiat-Shamir transformations within
//! a verification circuit. A recursive challenger maintains a sponge state as circuit
//! targets and allows observing values and sampling challenges.

use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
use p3_field::Field;

use crate::Target;

/// Trait for performing Fiat-Shamir transformations within a circuit.
///
/// A recursive challenger maintains a cryptographic sponge state as circuit targets
/// and provides methods to:
/// - Observe field elements (hash them into the state)
/// - Sample challenges (extract field elements from the state)
///
/// # Implementation Requirements
///
/// Implementations need:
/// - A cryptographic hash/sponge function available in the circuit (e.g., Poseidon2)
/// - State management as circuit targets
/// - Observation and sampling logic matching the native challenger
pub trait RecursiveChallenger<F: Field> {
    /// Observe a single field element in the Fiat-Shamir transcript.
    ///
    /// This should hash the value into the challenger's internal sponge state.
    fn observe(&mut self, circuit: &mut CircuitBuilder<F>, value: Target);

    /// Observe multiple field elements in the Fiat-Shamir transcript.
    ///
    /// Default implementation calls `observe()` for each element.
    fn observe_slice(&mut self, circuit: &mut CircuitBuilder<F>, values: &[Target]) {
        for &value in values {
            self.observe(circuit, value);
        }
    }

    /// Sample a challenge from the current challenger state.
    ///
    /// This should extract a field element from the sponge state, updating
    /// the state in the process (e.g., by performing a permutation).
    fn sample(&mut self, circuit: &mut CircuitBuilder<F>) -> Target;

    /// Sample multiple challenges.
    ///
    /// Default implementation calls `sample()` multiple times.
    fn sample_vec(&mut self, circuit: &mut CircuitBuilder<F>, count: usize) -> Vec<Target> {
        (0..count).map(|_| self.sample(circuit)).collect()
    }
}

/// Extension trait for sampling extension field elements.
///
/// This is needed when the challenger operates over a base field but needs to
/// sample extension field challenges.
pub trait RecursiveChallengerExt<F: Field>: RecursiveChallenger<F> {
    /// Sample an extension field element as a challenge.
    ///
    /// This typically involves sampling multiple base field elements and
    /// combining them into an extension field element.
    fn sample_ext_element(
        &mut self,
        circuit: &mut CircuitBuilder<F>,
        ext_degree: usize,
    ) -> Vec<Target>;
}

/// No-op implementation for `()` type.
///
/// This allows `ChallengeBuilder::with_public_inputs()` to work with methods
/// that have `RecursiveChallenger` trait bounds. All observations are no-ops,
/// and sampling returns public inputs. Used for testing or backwards compatibility.
impl<F: Field> RecursiveChallenger<F> for () {
    fn observe(&mut self, _circuit: &mut CircuitBuilder<F>, _value: Target) {
        // No-op: no challenger to observe with
    }

    fn sample(&mut self, circuit: &mut CircuitBuilder<F>) -> Target {
        // Fallback to public input when no challenger
        circuit.add_public_input()
    }
}
