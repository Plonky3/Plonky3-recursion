//! Circuit-based challenger implementation.

use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
// TODO: Replace with Poseidon perm once integrated.
use p3_field::Field;

use crate::Target;
use crate::traits::RecursiveChallenger;

/// Concrete challenger implementation for Fiat-Shamir operations in circuits.
pub struct CircuitChallenger<const RATE: usize> {
    /// Buffer of field elements waiting to be absorbed
    absorb_buffer: Vec<Target>,
    /// Whether the buffer has been flushed (absorbed) since the last observation
    buffer_flushed: bool,
}

impl<const RATE: usize> CircuitChallenger<RATE> {
    /// Create a new circuit challenger with empty state.
    pub const fn new() -> Self {
        Self {
            absorb_buffer: Vec::new(),
            buffer_flushed: true,
        }
    }

    /// Flush the absorb buffer, performing the actual hash absorb operation.
    fn flush_absorb<F: Field>(&mut self, _circuit: &mut CircuitBuilder<F>) {
        if self.buffer_flushed || self.absorb_buffer.is_empty() {
            return;
        }

        // Hash absorb removed; placeholder until Poseidon perm is wired.
        self.absorb_buffer.clear();
        self.buffer_flushed = true;
    }
}

impl<const RATE: usize> Default for CircuitChallenger<RATE> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field, const RATE: usize> RecursiveChallenger<F> for CircuitChallenger<RATE> {
    fn observe(&mut self, _circuit: &mut CircuitBuilder<F>, value: Target) {
        self.absorb_buffer.push(value);
        self.buffer_flushed = false;
    }

    fn sample(&mut self, circuit: &mut CircuitBuilder<F>) -> Target {
        // Flush any pending observations
        self.flush_absorb(circuit);

        // TODO: replace with Poseidon perm squeeze; for now, sample as public input.
        circuit.alloc_public_input("sampled challenge")
    }

    fn clear(&mut self) {
        self.absorb_buffer.clear();
        self.buffer_flushed = true;
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    const DEFAULT_CHALLENGER_RATE: usize = 8;

    #[test]
    fn test_circuit_challenger_observe_sample() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        let mut challenger = CircuitChallenger::<DEFAULT_CHALLENGER_RATE>::new();

        let val1 = circuit.add_const(BabyBear::ONE);
        let val2 = circuit.add_const(BabyBear::TWO);
        challenger.observe(&mut circuit, val1);
        challenger.observe(&mut circuit, val2);

        let challenge = challenger.sample(&mut circuit);
        assert!(challenge.0 > 0);
    }

    #[test]
    fn test_circuit_challenger_sample_vec() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        let mut challenger = CircuitChallenger::<DEFAULT_CHALLENGER_RATE>::new();

        let challenges = challenger.sample_vec(&mut circuit, 3);
        assert_eq!(challenges.len(), 3);
    }

    #[test]
    fn test_circuit_challenger_clear() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        let mut challenger = CircuitChallenger::<DEFAULT_CHALLENGER_RATE>::new();

        let val = circuit.add_const(BabyBear::ONE);
        RecursiveChallenger::<BabyBear>::observe(&mut challenger, &mut circuit, val);

        assert!(!challenger.buffer_flushed);
        assert_eq!(challenger.absorb_buffer.len(), 1);

        RecursiveChallenger::<BabyBear>::clear(&mut challenger);

        assert!(challenger.buffer_flushed);
        assert!(challenger.absorb_buffer.is_empty());
    }
}
