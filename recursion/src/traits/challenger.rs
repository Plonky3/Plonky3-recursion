//! Trait for recursive Fiat-Shamir challenger operations within circuits.

use alloc::vec::Vec;

use p3_circuit::{CircuitBuilder, CircuitError};
use p3_field::{ExtensionField, Field, PrimeField64};

use crate::Target;

/// Trait for performing Fiat-Shamir transformations within a circuit.
///
/// This trait provides an interface for implementing the Fiat-Shamir heuristic
/// in recursive verification circuits. Implementations maintain an internal sponge
/// state as circuit targets and provide methods to observe values and sample challenges.
///
/// # Design
/// The trait follows the duplex sponge construction pattern:
/// - **Observe**: Absorb field elements into the sponge state
/// - **Sample**: Squeeze field elements from the sponge state as challenges
pub trait RecursiveChallenger<F: Field> {
    /// Observe a single field element in the Fiat-Shamir transcript.
    ///
    /// Absorbs the value into the internal sponge state. The value will influence
    /// all future challenge samples.
    ///
    /// # Parameters
    /// - `circuit`: Circuit builder for creating operations
    /// - `value`: The target to observe
    fn observe(&mut self, circuit: &mut CircuitBuilder<F>, value: Target);

    /// Observe multiple field elements in the Fiat-Shamir transcript.
    ///
    /// This is equivalent to calling `observe()` for each element in order.
    ///
    /// # Parameters
    /// - `circuit`: Circuit builder for creating operations
    /// - `values`: Slice of targets to observe
    fn observe_slice(&mut self, circuit: &mut CircuitBuilder<F>, values: &[Target]) {
        for &value in values {
            self.observe(circuit, value);
        }
    }

    /// Sample a challenge from the current sponge state.
    ///
    /// Squeezes a field element from the sponge. This challenge is deterministically
    /// derived from all previously observed values.
    ///
    /// # Parameters
    /// - `circuit`: Circuit builder for creating operations
    ///
    /// # Returns
    /// A target representing the sampled challenge
    fn sample(&mut self, circuit: &mut CircuitBuilder<F>) -> Target;

    /// Sample multiple challenges from the current sponge state.
    ///
    /// This is equivalent to calling `sample()` multiple times.
    ///
    /// # Parameters
    /// - `circuit`: Circuit builder for creating operations
    /// - `count`: Number of challenges to sample
    ///
    /// # Returns
    /// Vector of sampled challenge targets
    fn sample_vec(&mut self, circuit: &mut CircuitBuilder<F>, count: usize) -> Vec<Target> {
        (0..count).map(|_| self.sample(circuit)).collect()
    }

    /// Sample a challenge and decompose it into bits.
    ///
    /// This is useful for sampling query indices in FRI or other bit-based challenges.
    /// The challenge is first sampled as a field element, then decomposed into
    /// `total_num_bits` bits, and the first `num_bits` are returned.
    ///
    /// # Parameters
    /// - `circuit`: Circuit builder for creating operations
    /// - `total_num_bits`: Total number of bits to decompose (typically field bit width)
    /// - `num_bits`: Number of bits to return (e.g., log of domain size)
    ///
    /// # Returns
    /// Vector of the first `num_bits` bits as targets (each in {0, 1})
    fn sample_public_bits<BF: PrimeField64>(
        &mut self,
        circuit: &mut CircuitBuilder<F>,
        total_num_bits: usize,
        num_bits: usize,
    ) -> Result<Vec<Target>, CircuitError>
    where
        F: ExtensionField<BF>,
    {
        let x = self.sample(circuit);

        // Decompose to bits and verifies they reconstruct x
        let bits = circuit.decompose_to_bits::<BF>(x, total_num_bits)?;

        Ok(bits[..num_bits].to_vec())
    }

    /// Verify a proof-of-work witness.
    ///
    /// Observes the witness, samples a challenge, decomposes it to bits,
    /// and verifies that the first `witness_bits` bits are all zero.
    ///
    /// # Parameters
    /// - `circuit`: Circuit builder for creating operations
    /// - `witness_bits`: Number of leading bits that must be zero
    /// - `witness`: The proof-of-work witness target
    /// - `total_num_bits`: Total number of bits to decompose
    fn check_witness<BF: PrimeField64>(
        &mut self,
        circuit: &mut CircuitBuilder<F>,
        witness_bits: usize,
        witness: Target,
        total_num_bits: usize,
    ) -> Result<(), CircuitError>
    where
        F: ExtensionField<BF>,
    {
        self.observe(circuit, witness);
        let bits = self.sample_public_bits(circuit, total_num_bits, witness_bits)?;

        // All bits must be zero for valid PoW
        for bit in bits {
            circuit.assert_zero(bit);
        }

        Ok(())
    }

    /// Clear the challenger state.
    ///
    /// Resets the internal sponge state. This is typically called to start
    /// a fresh transcript for a new proof verification.
    fn clear(&mut self);
}
