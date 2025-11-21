//! Circuit-based challenger implementation.

use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
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

        // TODO: Determine when to reset the sponge state?
        // For now, reset on first absorb (when buffer was flushed before)
        let _reset = self.buffer_flushed;

        // TODO: How do we want to handle padding?
        // Process buffer in chunks of RATE
        // for chunk in self.absorb_buffer.chunks(RATE) {
        //     let _ = circuit.add_hash_absorb(chunk, reset);
        // }

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

        // TODO: We should be calling `add_hash_squeeze` but we may want to wait
        // for Poseidon2 to be merged so that we actually generate challenges via hints
        // and not public inputs.
        // let output = circuit.add_hash_squeeze(1).expect("Failed to squeeze")[0];

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
    use p3_circuit::ops::hash::HashConfig;
    use p3_circuit::tables::{Poseidon2Params, generate_poseidon2_trace};
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    const DEFAULT_CHALLENGER_RATE: usize = 8;

    struct DummyParams;

    impl Poseidon2Params for DummyParams {
        const D: usize = 4;
        const WIDTH: usize = 16;
        const RATE_EXT: usize = 2;
        const CAPACITY_EXT: usize = 2;
        const SBOX_DEGREE: u64 = 7;
        const SBOX_REGISTERS: usize = 1;
        const HALF_FULL_ROUNDS: usize = 4;
        const PARTIAL_ROUNDS: usize = 13;
    }

    #[test]
    fn test_circuit_challenger_observe_sample() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        circuit.enable_hash_squeeze(
            &HashConfig {
                rate: DEFAULT_CHALLENGER_RATE,
            },
            generate_poseidon2_trace::<BabyBear, DummyParams>,
        );

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
        circuit.enable_hash_squeeze(
            &HashConfig {
                rate: DEFAULT_CHALLENGER_RATE,
            },
            generate_poseidon2_trace::<BabyBear, DummyParams>,
        );

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
