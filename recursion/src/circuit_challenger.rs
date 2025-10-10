//! Circuit-based challenger implementation using HashAbsorb and HashSqueeze operations.
//!
//! This provides a `RecursiveChallenger` implementation that maintains a sponge state
//! as circuit targets and uses non-primitive hash operations.
//!
//! # Design
//!
//! The `CircuitChallenger` acts as a circuit-compatible Fiat-Shamir challenger:
//! - **Observations**: Values are absorbed into the sponge via `HashAbsorb` operations
//! - **Sampling**: Challenges are squeezed from the sponge via `HashSqueeze` operations
//! - **Verification**: The sponge AIR table verifies all operations are correctly computed
//!
//! Sampled challenges are provided as public inputs by the prover, and the sponge AIR
//! constrains them to match what would be squeezed from the sponge state.

// TODO: Enforce sponge ops to be primitive ops? Or included in default?

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
    /// The actual state transitions are verified by the sponge AIR.
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

        // Squeeze a challenge from the sponge
        // The output is constrained by the sponge AIR to match the actual squeeze
        let (_op_id, outputs) = circuit.add_hash_squeeze(1).expect("HashSqueeze should be enabled");
        
        outputs[0]
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    #[test]
    fn test_circuit_challenger_basic() {
        use p3_circuit::op::{NonPrimitiveOpConfig, NonPrimitiveOpType};
        
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        
        // Enable hash operations
        circuit.enable_op(NonPrimitiveOpType::HashAbsorb { reset: true }, NonPrimitiveOpConfig::None);
        circuit.enable_op(NonPrimitiveOpType::HashAbsorb { reset: false }, NonPrimitiveOpConfig::None);
        circuit.enable_op(NonPrimitiveOpType::HashSqueeze, NonPrimitiveOpConfig::None);
        
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
        use p3_circuit::op::{NonPrimitiveOpConfig, NonPrimitiveOpType};
        
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        
        // Enable hash operations
        circuit.enable_op(NonPrimitiveOpType::HashAbsorb { reset: true }, NonPrimitiveOpConfig::None);
        circuit.enable_op(NonPrimitiveOpType::HashAbsorb { reset: false }, NonPrimitiveOpConfig::None);
        circuit.enable_op(NonPrimitiveOpType::HashSqueeze, NonPrimitiveOpConfig::None);
        
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
