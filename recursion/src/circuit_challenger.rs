//! Circuit-based challenger implementation.
//!
//! This module provides a concrete implementation of `RecursiveChallenger`
//! that manages sponge state explicitly as circuit Targets, using Poseidon2
//! permutations for cryptographic operations.
//!
//! The sponge construction is handled entirely in-circuit, with state wiring
//! managed via Targets. The ExtendedPoseidon2Air validates permutation correctness.

use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
use p3_circuit::ops::Poseidon2Ops;
use p3_field::Field;

use crate::Target;
use crate::recursive_challenger::RecursiveChallenger;

/// Concrete challenger implementation for Fiat-Shamir operations using Poseidon2.
///
/// This challenger manages a duplex sponge in overwrite mode:
/// - State is split into RATE (absorbed/squeezed) and CAPACITY (internal security)
/// - Absorb: overwrite rate portion with inputs, apply permutation
/// - Squeeze: extract from rate portion, apply permutation for next output
///
/// The sponge state is managed as circuit Targets, with permutations validated
/// by ExtendedPoseidon2Air.
///
/// Note: WIDTH = RATE + CAPACITY must be known at compile time.
pub struct CircuitChallenger<const RATE: usize, const CAPACITY: usize, const WIDTH: usize> {
    /// Current sponge state as circuit targets (WIDTH elements)
    /// None indicates the sponge hasn't been initialized yet
    sponge_state: Option<[Target; WIDTH]>,

    /// Buffer of field elements waiting to be absorbed
    absorb_buffer: Vec<Target>,

    /// Current position in rate for squeezing
    squeeze_pos: usize,
}

impl<const RATE: usize, const CAPACITY: usize, const WIDTH: usize>
    CircuitChallenger<RATE, CAPACITY, WIDTH>
{
    /// Create a new circuit challenger.
    pub fn new() -> Self {
        Self {
            sponge_state: None,
            absorb_buffer: Vec::new(),
            squeeze_pos: RATE, // Force permutation on first squeeze
        }
    }

    /// Initialize sponge state with zeros.
    fn init_sponge_state<F: Field>(&mut self, circuit: &mut CircuitBuilder<F>) {
        if self.sponge_state.is_none() {
            // Initialize to all zeros
            let zero = circuit.add_const(F::ZERO);
            let state = [zero; WIDTH];
            self.sponge_state = Some(state);
        }
    }

    /// Apply Poseidon2 permutation to current sponge state.
    fn permute<F: Field>(&mut self, circuit: &mut CircuitBuilder<F>) {
        if let Some(state) = &self.sponge_state {
            let new_state = circuit
                .add_poseidon2_permutation(state)
                .expect("Poseidon2 permutation should be enabled");

            // Convert Vec to array - the permutation should return exactly WIDTH elements
            assert_eq!(
                new_state.len(),
                WIDTH,
                "Permutation should return WIDTH elements"
            );

            // Initialize array with first element, then fill
            let mut new_state_array = [new_state[0]; WIDTH];
            for (i, &target) in new_state.iter().enumerate() {
                new_state_array[i] = target;
            }

            self.sponge_state = Some(new_state_array);
        }
    }

    /// Absorb buffered inputs into sponge state.
    fn flush_absorb<F: Field>(&mut self, circuit: &mut CircuitBuilder<F>) {
        if self.absorb_buffer.is_empty() {
            return;
        }

        self.init_sponge_state(circuit);

        // Clone buffer to avoid borrow issues
        let buffer = self.absorb_buffer.clone();

        // Process inputs in chunks of RATE
        for chunk in buffer.chunks(RATE) {
            // Overwrite rate portion with inputs
            if let Some(state) = &mut self.sponge_state {
                for (i, &input) in chunk.iter().enumerate() {
                    state[i] = input;
                }
                // Pad remaining rate with zeros if chunk is smaller than RATE
                if chunk.len() < RATE {
                    let zero = circuit.add_const(F::ZERO);
                    for val in state.iter_mut().take(RATE).skip(chunk.len()) {
                        *val = zero;
                    }
                }
            }

            // Apply permutation
            self.permute(circuit);
        }

        self.absorb_buffer.clear();
        self.squeeze_pos = 0; // Can now squeeze from beginning of rate
    }
}

impl<const RATE: usize, const CAPACITY: usize, const WIDTH: usize> Default
    for CircuitChallenger<RATE, CAPACITY, WIDTH>
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field, const RATE: usize, const CAPACITY: usize, const WIDTH: usize>
    RecursiveChallenger<F, RATE, CAPACITY> for CircuitChallenger<RATE, CAPACITY, WIDTH>
{
    fn observe(&mut self, _circuit: &mut CircuitBuilder<F>, value: Target) {
        // Just buffer the observation - actual absorption happens on flush
        self.absorb_buffer.push(value);
    }

    fn sample(&mut self, circuit: &mut CircuitBuilder<F>) -> Target {
        // Flush any pending absorptions
        self.flush_absorb(circuit);

        // Initialize sponge if not already done
        self.init_sponge_state(circuit);

        // Check if we need to permute before squeezing
        if self.squeeze_pos >= RATE {
            self.permute(circuit);
            self.squeeze_pos = 0;
        }

        // Extract output from current rate position
        let output = self.sponge_state.expect("Sponge should be initialized")[self.squeeze_pos];

        self.squeeze_pos += 1;

        output
    }

    fn clear(&mut self) {
        self.sponge_state = None;
        self.absorb_buffer.clear();
        self.squeeze_pos = RATE;
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_circuit::op::{NonPrimitiveOpConfig, NonPrimitiveOpType};
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    const DEFAULT_RATE: usize = 8;
    const DEFAULT_CAPACITY: usize = 8;
    const DEFAULT_WIDTH: usize = 16; // RATE + CAPACITY

    #[test]
    fn test_circuit_challenger_observe_sample() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        circuit.enable_op(
            NonPrimitiveOpType::Poseidon2Permutation,
            NonPrimitiveOpConfig::None,
        );

        let mut challenger =
            CircuitChallenger::<DEFAULT_RATE, DEFAULT_CAPACITY, DEFAULT_WIDTH>::new();

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
        circuit.enable_op(
            NonPrimitiveOpType::Poseidon2Permutation,
            NonPrimitiveOpConfig::None,
        );

        let mut challenger =
            CircuitChallenger::<DEFAULT_RATE, DEFAULT_CAPACITY, DEFAULT_WIDTH>::new();

        let challenges = challenger.sample_vec(&mut circuit, 3);
        assert_eq!(challenges.len(), 3);
    }

    #[test]
    fn test_sponge_state_management() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        circuit.enable_op(
            NonPrimitiveOpType::Poseidon2Permutation,
            NonPrimitiveOpConfig::None,
        );

        let mut challenger =
            CircuitChallenger::<DEFAULT_RATE, DEFAULT_CAPACITY, DEFAULT_WIDTH>::new();

        // Initially no state
        assert!(challenger.sponge_state.is_none());

        // After observe and sample, state should be initialized
        let val = circuit.add_const(BabyBear::ONE);
        challenger.observe(&mut circuit, val);
        let _challenge = challenger.sample(&mut circuit);

        assert!(challenger.sponge_state.is_some());

        // Clear should reset state
        RecursiveChallenger::<BabyBear, DEFAULT_RATE, DEFAULT_CAPACITY>::clear(&mut challenger);
        assert!(challenger.sponge_state.is_none());
    }
}
