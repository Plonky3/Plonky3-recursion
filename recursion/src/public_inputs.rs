//! Helper functions and builders for constructing public inputs for recursive verification circuits.
//!
//! Public input construction is error-prone because:
//! - Inputs must match the exact order of circuit builder allocations
//! - Some operations (like bit decomposition) create hidden public inputs
//! - Manual construction leads to duplication and bugs
//!
//! This module provides type-safe builders and helpers to construct inputs correctly.

use alloc::vec::Vec;

use p3_field::{BasedVectorSpace, Field, PrimeField64};

use crate::recursive_pcs::MAX_QUERY_INDEX_BITS;

/// Builder for constructing public inputs that mirrors circuit allocation order.
///
/// This builder ensures public inputs are constructed in the same order as the circuit
/// allocates them, preventing ordering bugs.
///
/// # Example
/// ```ignore
/// let inputs = PublicInputBuilder::new()
///     .add_proof_values(proof_values)
///     .add_challenge(alpha)
///     .add_challenges(betas)
///     .build();
/// ```
pub struct PublicInputBuilder<F: Field> {
    inputs: Vec<F>,
}

impl<F: Field> PublicInputBuilder<F> {
    /// Create a new empty builder.
    pub fn new() -> Self {
        Self { inputs: Vec::new() }
    }

    /// Add proof values extracted via `Recursive::get_values`.
    pub fn add_proof_values(&mut self, values: impl IntoIterator<Item = F>) -> &mut Self {
        self.inputs.extend(values);
        self
    }

    /// Add a single challenge value.
    pub fn add_challenge(&mut self, challenge: F) -> &mut Self {
        self.inputs.push(challenge);
        self
    }

    /// Add multiple challenge values.
    pub fn add_challenges(&mut self, challenges: impl IntoIterator<Item = F>) -> &mut Self {
        self.inputs.extend(challenges);
        self
    }

    /// Add a query index with automatic bit decomposition.
    pub fn add_query_index(&mut self, index: F) -> &mut Self
    where
        F: PrimeField64,
    {
        // Extract the index value as usize
        let index_usize = index.as_canonical_u64() as usize;

        // Add bit decomposition (MAX_QUERY_INDEX_BITS public inputs)
        for k in 0..MAX_QUERY_INDEX_BITS {
            let bit = if (index_usize >> k) & 1 == 1 {
                F::ONE
            } else {
                F::ZERO
            };
            self.inputs.push(bit);
        }

        self
    }

    /// Add pre-decomposed query index bits.
    ///
    /// Use this when you already have the bits (e.g., from test data generation).
    pub fn add_query_index_bits(&mut self, bits: impl IntoIterator<Item = F>) -> &mut Self {
        self.inputs.extend(bits);
        self
    }

    /// Get the current number of inputs.
    pub fn len(&self) -> usize {
        self.inputs.len()
    }

    /// Check if the builder is empty.
    pub fn is_empty(&self) -> bool {
        self.inputs.is_empty()
    }

    /// Build and return the final input vector.
    pub fn build(self) -> Vec<F> {
        self.inputs
    }
}

impl<F: Field> Default for PublicInputBuilder<F> {
    fn default() -> Self {
        Self::new()
    }
}

/// Structure for organizing commitment opening data.
#[derive(Clone, Debug)]
pub struct CommitmentOpening<F: Field> {
    /// The commitment value (placeholder in arithmetic-only verification).
    pub commitment: F,
    /// Opened points: (evaluation point, values at that point).
    pub opened_points: Vec<(F, Vec<F>)>,
}

/// Helper for constructing public inputs for FRI-only verification circuits.
///
/// This is used in standalone FRI tests where we only verify the FRI proof
/// without the full STARK AIR constraints.
pub struct FriVerifierInputs<F: Field> {
    /// Values from FRI proof (commitments, opened values, final poly, etc.)
    pub fri_proof_values: Vec<F>,
    /// Alpha challenge for batch combination
    pub alpha: F,
    /// Beta challenges for FRI folding rounds
    pub betas: Vec<F>,
    /// Query index bits (pre-decomposed, little-endian)
    pub query_index_bits: Vec<Vec<F>>,
    /// Commitment openings (batch commitments and their opened values)
    pub commitment_openings: Vec<CommitmentOpening<F>>,
}

impl<F: Field> FriVerifierInputs<F> {
    /// Build the public input vector in the correct order.
    ///
    /// Order:
    /// 1. FRI proof values
    /// 2. Alpha challenge
    /// 3. Beta challenges
    /// 4. Query index bits (for each query)
    /// 5. Commitment openings (commitment, then (z, f(z)) pairs)
    pub fn build(self) -> Vec<F> {
        let mut builder = PublicInputBuilder::new();

        // 1. FRI proof values
        builder.add_proof_values(self.fri_proof_values);

        // 2. Alpha challenge
        builder.add_challenge(self.alpha);

        // 3. Beta challenges
        builder.add_challenges(self.betas);

        // 4. Query index bits (pre-decomposed)
        for bits in self.query_index_bits {
            builder.add_query_index_bits(bits);
        }

        // 5. Commitment openings
        for opening in self.commitment_openings {
            builder.add_challenge(opening.commitment);
            for (z, values) in opening.opened_points {
                builder.add_challenge(z);
                builder.add_proof_values(values);
            }
        }

        builder.build()
    }
}

/// Helper for constructing public inputs for full STARK verification circuits.
///
/// This includes AIR public values, proof values, and challenges.
pub struct StarkVerifierInputs<F, EF>
where
    F: Field + PrimeField64,
    EF: Field + BasedVectorSpace<F> + From<F>,
{
    /// Public input values for the AIR being verified
    pub air_public_values: Vec<F>,
    /// Values extracted from the proof via `Recursive::get_values`
    pub proof_values: Vec<EF>,
    /// All challenges (including query indices at the end)
    pub challenges: Vec<EF>,
    /// Number of FRI query proofs
    pub num_queries: usize,
}

impl<F, EF> StarkVerifierInputs<F, EF>
where
    F: Field + PrimeField64,
    EF: Field + BasedVectorSpace<F> + From<F>,
{
    /// Build the public input vector in the correct order.
    ///
    /// Order:
    /// 1. AIR public values
    /// 2. Proof values
    /// 3. All challenges (alpha, zeta, zeta_next, betas, query indices)
    /// 4. Query index bit decompositions (MAX_QUERY_INDEX_BITS per query)
    pub fn build(self) -> Vec<EF> {
        let mut builder = PublicInputBuilder::new();

        // 1. AIR public values (converted to extension field)
        builder.add_proof_values(self.air_public_values.iter().map(|&v| v.into()));

        // 2. Proof values
        builder.add_proof_values(self.proof_values);

        // 3. ALL challenges (including query indices)
        builder.add_challenges(self.challenges.iter().copied());

        // 4. Query index bit decompositions
        // The circuit calls decompose_to_bits on each query index,
        // which creates MAX_QUERY_INDEX_BITS additional public inputs per query
        let num_regular_challenges = self.challenges.len() - self.num_queries;
        for &query_index in &self.challenges[num_regular_challenges..] {
            let coeffs = query_index.as_basis_coefficients_slice();
            let index_usize = coeffs[0].as_canonical_u64() as usize;

            // Add bit decomposition (MAX_QUERY_INDEX_BITS public inputs)
            for k in 0..MAX_QUERY_INDEX_BITS {
                let bit: EF = if (index_usize >> k) & 1 == 1 {
                    EF::ONE
                } else {
                    EF::ZERO
                };
                builder.add_challenge(bit);
            }
        }

        builder.build()
    }
}

/// Constructs the public input values for a STARK verification circuit.
///
/// # Parameters
/// - `public_values`: The AIR public input values
/// - `proof_values`: Values extracted from the proof targets
/// - `challenges`: All challenge values
/// - `num_queries`: Number of FRI query proofs
///
/// # Returns
/// A vector of field elements ready to be passed to `CircuitRunner::set_public_inputs`
pub fn construct_stark_verifier_inputs<F, EF>(
    air_public_values: &[F],
    proof_values: &[EF],
    challenges: &[EF],
    num_queries: usize,
) -> Vec<EF>
where
    F: Field + PrimeField64,
    EF: Field + BasedVectorSpace<F> + From<F>,
{
    StarkVerifierInputs {
        air_public_values: air_public_values.to_vec(),
        proof_values: proof_values.to_vec(),
        challenges: challenges.to_vec(),
        num_queries,
    }
    .build()
}

/// Calculate the expected number of public inputs for a STARK verification circuit.
///
/// This is a helper to estimate the size. The actual count depends on:
/// - Number of AIR public values
/// - Proof structure (commitments, opened values, opening proof)
/// - Number of challenges (depends on PCS)
/// - Number of queries and their bit decompositions
///
/// For exact counts, use the actual proof structure and challenge generation.
pub fn estimate_stark_verifier_input_count(
    num_air_public_values: usize,
    num_proof_values: usize,
    num_challenges_before_queries: usize,
    num_queries: usize,
) -> usize {
    num_air_public_values
        + num_proof_values
        + num_challenges_before_queries
        + num_queries // query index challenges themselves
        + (num_queries * MAX_QUERY_INDEX_BITS) // bit decompositions
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    #[test]
    fn test_public_input_builder() {
        let mut builder = PublicInputBuilder::<BabyBear>::new();

        assert_eq!(builder.len(), 0);
        assert!(builder.is_empty());

        builder
            .add_proof_values([BabyBear::from_u32(1), BabyBear::from_u32(2)])
            .add_challenge(BabyBear::from_u32(3))
            .add_challenges([BabyBear::from_u32(4), BabyBear::from_u32(5)]);

        assert_eq!(builder.len(), 5);
        assert!(!builder.is_empty());

        let inputs = builder.build();
        assert_eq!(inputs.len(), 5);
        assert_eq!(inputs[0], BabyBear::from_u32(1));
        assert_eq!(inputs[4], BabyBear::from_u32(5));
    }

    #[test]
    fn test_query_index_bit_decomposition() {
        let mut builder = PublicInputBuilder::<BabyBear>::new();

        // Index 5 = 0b101 in binary
        builder.add_query_index(BabyBear::from_u32(5));

        let inputs = builder.build();

        // Should have MAX_QUERY_INDEX_BITS bits
        assert_eq!(inputs.len(), MAX_QUERY_INDEX_BITS);

        // Check first few bits: 101 (little-endian)
        assert_eq!(inputs[0], BabyBear::ONE); // bit 0
        assert_eq!(inputs[1], BabyBear::ZERO); // bit 1
        assert_eq!(inputs[2], BabyBear::ONE); // bit 2

        // Rest should be zeros
        for &bit in &inputs[3..] {
            assert_eq!(bit, BabyBear::ZERO);
        }
    }
}
