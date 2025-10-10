//! Circuit-based challenger implementation using HashAbsorb and HashSqueeze operations.
//!
//! This provides a `RecursiveChallenger` implementation that maintains a sponge state
//! as circuit targets and uses non-primitive hash operations.

use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
use p3_circuit::ops::HashOps;
use p3_field::Field;

use crate::Target;
use crate::recursive_challenger::RecursiveChallenger;

/// Recursive challenger that uses circuit hash operations.
///
/// This challenger maintains a sponge state as circuit targets and uses
/// `HashAbsorb` and `HashSqueeze` non-primitive operations to perform
/// Fiat-Shamir transformations.
///
/// The actual hash function (e.g., Poseidon2) is implemented via the sponge AIR table.
///
/// # Generic Parameters
/// - `R`: Sponge rate (number of field elements that can be absorbed/squeezed per operation)
///
/// # Example
/// ```ignore
/// let mut challenger = CircuitChallenger::<16>::new(circuit);
///
/// // Observe some values
/// challenger.observe(circuit, trace_commitment);
/// challenger.observe_slice(circuit, &public_values);
///
/// // Sample a challenge
/// let alpha = challenger.sample(circuit);
/// ```
pub struct CircuitChallenger<const R: usize> {
    /// Current sponge state (as circuit targets).
    /// In a real implementation, this would track the full Poseidon2 state.
    /// For now, it's a placeholder that will be populated when sponge ops are executed.
    pub state: Vec<Target>,

    /// Buffer of values waiting to be absorbed.
    /// When the buffer reaches size R, a HashAbsorb operation is added.
    pub absorb_buffer: Vec<Target>,

    /// Whether the next absorb should reset the sponge state.
    pub needs_reset: bool,
}

impl<const R: usize> CircuitChallenger<R> {
    /// Create a new circuit challenger.
    ///
    /// Initially, the sponge state is uninitialized and will be set up
    /// on the first absorb operation.
    pub fn new() -> Self {
        Self {
            state: Vec::new(),
            absorb_buffer: Vec::new(),
            needs_reset: true, // First operation should reset
        }
    }

    /// Flush the absorb buffer by adding a HashAbsorb operation.
    fn flush_absorb<F: Field>(&mut self, circuit: &mut CircuitBuilder<F>) {
        if self.absorb_buffer.is_empty() {
            return;
        }

        // Add HashAbsorb operation
        let _ = circuit.add_hash_absorb(&self.absorb_buffer, self.needs_reset);

        // Clear buffer and reset flag
        self.absorb_buffer.clear();
        self.needs_reset = false;
    }
}

impl<const R: usize> Default for CircuitChallenger<R> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field, const R: usize> RecursiveChallenger<F> for CircuitChallenger<R> {
    fn observe(&mut self, circuit: &mut CircuitBuilder<F>, value: Target) {
        // Add to buffer
        self.absorb_buffer.push(value);

        // Flush if buffer is full
        if self.absorb_buffer.len() >= R {
            self.flush_absorb(circuit);
        }
    }

    fn observe_slice(&mut self, circuit: &mut CircuitBuilder<F>, values: &[Target]) {
        for &value in values {
            self.observe(circuit, value);
        }
    }

    fn sample(&mut self, circuit: &mut CircuitBuilder<F>) -> Target {
        // Flush any pending absorbs before squeezing
        self.flush_absorb(circuit);

        // Create a target for the output
        let output = circuit.add_public_input();

        // Add HashSqueeze operation
        // TODO: This should actually squeeze from the sponge state maintained by the AIR
        // For now, we just add the operation for documentation/structure
        let _ = circuit.add_hash_squeeze(&[output]);

        output
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    #[test]
    fn test_circuit_challenger_basic() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        let mut challenger = CircuitChallenger::<16>::new();

        // Observe some values
        let value1 = circuit.add_const(BabyBear::ONE);
        let value2 = circuit.add_const(BabyBear::TWO);

        challenger.observe(&mut circuit, value1);
        challenger.observe(&mut circuit, value2);

        // Sample a challenge
        let challenge = challenger.sample(&mut circuit);
        assert!(challenge.0 > 0);
    }

    #[test]
    fn test_circuit_challenger_buffering() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        let mut challenger = CircuitChallenger::<4>::new(); // Rate 4

        // Observe 3 values (should buffer, not flush)
        for i in 0..3 {
            let val = circuit.add_const(BabyBear::from_u32(i));
            challenger.observe(&mut circuit, val);
        }
        assert_eq!(challenger.absorb_buffer.len(), 3);

        // Observe 4th value (should flush)
        let val = circuit.add_const(BabyBear::from_u32(3));
        challenger.observe(&mut circuit, val);
        assert_eq!(challenger.absorb_buffer.len(), 0);

        // Sample (should flush any remaining)
        let _challenge = challenger.sample(&mut circuit);
        assert_eq!(challenger.absorb_buffer.len(), 0);
    }
}
