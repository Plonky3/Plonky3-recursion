//! Circuit-based challenger implementation.

use alloc::vec;
use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
use p3_circuit::ops::HashOps;
use p3_field::Field;

use crate::Target;
use crate::traits::RecursiveChallenger;

/// Concrete challenger implementation for Fiat-Shamir operations in circuits.
pub struct CircuitChallenger<const RATE: usize> {
    /// Buffer of field elements waiting to be absorbed
    absorb_buffer: Vec<Target>,
    /// Buffer of outputs squeezed from the sponge
    output_buffer: Vec<Target>,
    /// Whether the state (and the capacity) must be reset on the next squeeze.
    reset: bool,
}

impl<const RATE: usize> CircuitChallenger<RATE> {
    /// Create a new circuit challenger with empty state.
    pub const fn new() -> Self {
        Self {
            absorb_buffer: Vec::new(),
            output_buffer: Vec::new(),
            reset: true,
        }
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
        // Any existing output is now invalid
        self.output_buffer.clear();
    }

    fn sample(&mut self, circuit: &mut CircuitBuilder<F>) -> Target {
        if let Some(challenge) = self.output_buffer.pop() {
            challenge
        } else {
            let outputs = circuit
                .add_hash_squeeze(&self.absorb_buffer, self.reset)
                .expect("Failed to squeeze");
            self.absorb_buffer.clear();
            self.reset = false;

            self.output_buffer.extend_from_slice(&outputs);

            self.output_buffer
                .pop()
                .expect("Output buffer should have at least one element")
        }
    }

    fn clear(&mut self) {
        self.absorb_buffer.clear();
        self.output_buffer.clear();
        self.reset = true;
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_circuit::op::{NonPrimitiveOpConfig, NonPrimitiveOpType};
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
        circuit.enable_hash_squeeze(
            &HashConfig::default(),
            generate_poseidon2_trace::<BabyBear, DummyParams>,
        );

        let mut challenger = CircuitChallenger::<DEFAULT_CHALLENGER_RATE>::new();

        let val = circuit.add_const(BabyBear::ONE);
        RecursiveChallenger::<BabyBear>::observe(&mut challenger, &mut circuit, val);

        RecursiveChallenger::<BabyBear>::clear(&mut challenger);

        assert!(challenger.reset);
        assert!(challenger.absorb_buffer.is_empty());
        assert!(challenger.output_buffer.is_empty());
    }
}
