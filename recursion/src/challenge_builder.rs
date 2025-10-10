//! Helper for managing challenge generation in verification circuits.
//!
//! Challenge generation in STARK verification follows a specific Fiat-Shamir transcript order.
//! This module provides a builder to make that order explicit and less error-prone.

use alloc::vec;
use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
use p3_field::Field;

use crate::Target;

/// Builder for creating challenge targets in the correct Fiat-Shamir order.
///
/// Generic over a challenger type `C` that implements `RecursiveChallenger`.
/// Use `()` for public-input mode (no observations, just sampling).
///
/// # Modes
///
/// 1. **Public input mode**: `ChallengeBuilder::new(circuit)` uses `()` challenger
///    - Observations are no-ops
///    - Sampling returns public inputs
///
/// 2. **Challenger mode**: `ChallengeBuilder::with_challenger(circuit, challenger)`
///    - Observations hash into challenger state
///    - Sampling extracts from challenger state
///
/// # Example
/// ```ignore
/// // Public input mode (current)
/// let challenges = ChallengeBuilder::new(circuit)
///     .add_alpha_challenge()
///     .add_zeta_challenges()
///     .build();
///
/// // Challenger mode (future)
/// let challenger = Poseidon2Challenger::new(...);
/// let challenges = ChallengeBuilder::with_challenger(circuit, challenger)
///     .observe_degree_bits(degree_bits, is_zk)
///     .observe_trace_commitment(&trace)
///     .observe_public_values(&public_values)
///     .sample_alpha()
///     .observe_quotient_chunks(&quotient)
///     .sample_zeta_and_zeta_next()
///     .build();
/// ```
pub struct ChallengeBuilder<'a, F: Field, C = ()> {
    circuit: &'a mut CircuitBuilder<F>,
    challenger: C,
    challenges: Vec<Target>,
}

impl<'a, F: Field> ChallengeBuilder<'a, F, ()> {
    /// Create a new challenge builder in public input mode.
    ///
    /// Uses `()` as a no-op challenger - observations do nothing,
    /// sampling returns public inputs.
    pub fn new(circuit: &'a mut CircuitBuilder<F>) -> Self {
        Self {
            circuit,
            challenger: (),
            challenges: Vec::new(),
        }
    }
}

impl<'a, F: Field, C> ChallengeBuilder<'a, F, C>
where
    C: crate::recursive_challenger::RecursiveChallenger<F>,
{
    /// Create a new challenge builder with a specific recursive challenger.
    ///
    /// When using an actual challenger (e.g., Poseidon2-based), observations
    /// will hash values and sampling will extract challenges from the state.
    pub fn with_challenger(circuit: &'a mut CircuitBuilder<F>, challenger: C) -> Self {
        Self {
            circuit,
            challenger,
            challenges: Vec::new(),
        }
    }
}

impl<'a, F: Field, C> ChallengeBuilder<'a, F, C> {
    /// Observe degree bits in the Fiat-Shamir transcript.
    ///
    /// Hashes the degree information using the challenger.
    /// For `()` challenger, this is a no-op.
    pub fn observe_degree_bits(&mut self, degree_bits: usize, is_zk: usize) -> &mut Self
    where
        C: crate::recursive_challenger::RecursiveChallenger<F>,
    {
        // TODO: Convert usize to field elements in circuit
        // let degree_target = self.circuit.add_const(F::from_usize(degree_bits));
        // let is_zk_target = self.circuit.add_const(F::from_usize(degree_bits - is_zk));
        // self.challenger.observe(self.circuit, degree_target);
        // self.challenger.observe(self.circuit, is_zk_target);
        let _ = (&mut self.challenger, degree_bits, is_zk);
        self
    }

    /// Observe trace commitment in the Fiat-Shamir transcript.
    ///
    /// Hashes the commitment using the challenger.
    /// For `()` challenger, this is a no-op.
    pub fn observe_trace_commitment<Comm>(&mut self, commitment: &Comm) -> &mut Self
    where
        C: crate::recursive_challenger::RecursiveChallenger<F>,
    {
        // TODO: Hash commitment targets into challenger
        // For each target in commitment, call:
        // self.challenger.observe(self.circuit, target);
        let _ = (&mut self.challenger, commitment);
        self
    }

    /// Observe public values in the Fiat-Shamir transcript.
    ///
    /// Hashes each public value using the challenger.
    /// For `()` challenger, this is a no-op.
    pub fn observe_public_values(&mut self, public_values: &[Target]) -> &mut Self
    where
        C: crate::recursive_challenger::RecursiveChallenger<F>,
    {
        self.challenger.observe_slice(self.circuit, public_values);
        self
    }

    /// Sample the alpha challenge from the challenger.
    ///
    /// For `()` challenger, returns a public input.
    /// For real challenger, extracts from sponge state.
    pub fn sample_alpha(&mut self) -> &mut Self
    where
        C: crate::recursive_challenger::RecursiveChallenger<F>,
    {
        let alpha = self.challenger.sample(self.circuit);
        self.challenges.push(alpha);
        self
    }

    /// Add the alpha challenge (used for folding constraints).
    ///
    /// This is a convenience method that will eventually perform the full observation sequence.
    ///
    /// Currently just samples alpha as a public input (observations are no-ops).
    pub fn add_alpha_challenge(&mut self) -> &mut Self
    where
        C: crate::recursive_challenger::RecursiveChallenger<F>,
    {
        // TODO: Observe degree_bits, trace_commitment, and public_values.
        self.sample_alpha()
    }

    /// Observe quotient chunks commitment in the Fiat-Shamir transcript.
    ///
    /// Hashes the commitment using the challenger.
    /// For `()` challenger, this is a no-op.
    pub fn observe_quotient_chunks<Comm>(&mut self, commitment: &Comm) -> &mut Self
    where
        C: crate::recursive_challenger::RecursiveChallenger<F>,
    {
        // TODO: Hash commitment targets into challenger
        // For each target in commitment, call:
        // self.challenger.observe(self.circuit, target);
        let _ = (&mut self.challenger, commitment);
        self
    }

    /// Observe random commitment in the Fiat-Shamir transcript (ZK mode only).
    ///
    /// Hashes the commitment if present using the challenger.
    /// For `()` challenger, this is a no-op.
    pub fn observe_random_commitment<Comm>(&mut self, commitment: Option<&Comm>) -> &mut Self
    where
        C: crate::recursive_challenger::RecursiveChallenger<F>,
    {
        // TODO: Hash commitment targets into challenger if present
        // if let Some(commit) = commitment {
        //     for target in commit { self.challenger.observe(self.circuit, target); }
        // }
        let _ = (&mut self.challenger, commitment);
        self
    }

    /// Sample the zeta and zeta_next challenges from the challenger.
    ///
    /// For `()` challenger, returns public inputs.
    /// For real challenger:
    /// - Zeta is sampled from the challenger
    /// - Zeta_next is computed from zeta (next point in trace domain)
    pub fn sample_zeta_and_zeta_next(&mut self) -> &mut Self
    where
        C: crate::recursive_challenger::RecursiveChallenger<F>,
    {
        // Sample zeta from challenger
        let zeta = self.challenger.sample(self.circuit);

        // TODO: Compute zeta_next as next point in trace domain
        // This requires access to the trace domain, which we don't have here
        // For now, sample zeta_next as well (will need refactoring)
        let zeta_next = self.challenger.sample(self.circuit);

        self.challenges.push(zeta);
        self.challenges.push(zeta_next);
        self
    }

    /// Add the zeta and zeta_next challenges (out-of-domain evaluation points)
    /// after observing quotient chunks and random commitment.
    pub fn add_zeta_challenges(&mut self) -> &mut Self
    where
        C: crate::recursive_challenger::RecursiveChallenger<F>,
    {
        // TODO: Observe quotient_chunks and random_commitment
        self.sample_zeta_and_zeta_next()
    }

    /// Add PCS-specific challenges (e.g., FRI betas and query indices).
    ///
    /// The exact number and meaning depends on the PCS implementation.
    ///
    /// TODO: Replace with actual PCS challenger observations.
    pub fn add_pcs_challenges(&mut self, count: usize) -> &mut Self {
        for _ in 0..count {
            self.challenges.push(self.circuit.add_public_input());
        }
        self
    }

    /// Get the current number of challenges.
    pub fn len(&self) -> usize {
        self.challenges.len()
    }

    /// Check if any challenges have been added.
    pub fn is_empty(&self) -> bool {
        self.challenges.is_empty()
    }

    /// Build and return the challenges vector.
    pub fn build(&mut self) -> Vec<Target> {
        core::mem::take(&mut self.challenges)
    }
}

/// Base STARK challenges (independent of PCS choice).
///
/// These are the fundamental challenges needed for any STARK verification:
/// - Alpha: for folding constraint polynomials
/// - Zeta, Zeta_next: for out-of-domain evaluation
#[derive(Debug, Clone)]
pub struct BaseStarkChallenges {
    /// Alpha: challenge for folding all constraint polynomials
    pub alpha: Target,
    /// Zeta: out-of-domain evaluation point
    pub zeta: Target,
    /// Zeta next: evaluation point for next row (zeta * g in the trace domain)
    pub zeta_next: Target,
}

impl BaseStarkChallenges {
    /// Create base STARK challenges using the challenge builder.
    ///
    /// This generates alpha, zeta, and zeta_next in the correct Fiat-Shamir order.
    pub fn generate<F: Field>(circuit: &mut CircuitBuilder<F>) -> Self {
        let challenges = ChallengeBuilder::new(circuit)
            .add_alpha_challenge()
            .add_zeta_challenges()
            .build();

        assert_eq!(
            challenges.len(),
            3,
            "Base STARK should have exactly 3 challenges"
        );

        Self {
            alpha: challenges[0],
            zeta: challenges[1],
            zeta_next: challenges[2],
        }
    }

    /// Convert to a flat vector.
    pub fn to_vec(&self) -> Vec<Target> {
        vec![self.alpha, self.zeta, self.zeta_next]
    }
}

/// Complete STARK challenges including PCS-specific challenges.
///
/// This makes it clear what each challenge is used for, preventing indexing errors.
#[derive(Debug, Clone)]
pub struct StarkChallenges {
    /// Base STARK challenges (alpha, zeta, zeta_next)
    pub base: BaseStarkChallenges,
    /// PCS-specific challenges (e.g., FRI betas and query indices)
    pub pcs_challenges: Vec<Target>,
}

impl StarkChallenges {
    /// Create complete STARK challenges with both base and PCS challenges.
    pub fn new(base: BaseStarkChallenges, pcs_challenges: Vec<Target>) -> Self {
        Self {
            base,
            pcs_challenges,
        }
    }

    /// Create from a flat challenge vector.
    ///
    /// Assumes standard ordering: [alpha, zeta, zeta_next, ...pcs_challenges]
    pub fn from_vec(challenges: Vec<Target>) -> Self {
        assert!(
            challenges.len() >= 3,
            "Need at least 3 challenges (alpha, zeta, zeta_next)"
        );

        Self {
            base: BaseStarkChallenges {
                alpha: challenges[0],
                zeta: challenges[1],
                zeta_next: challenges[2],
            },
            pcs_challenges: challenges[3..].to_vec(),
        }
    }

    /// Convert back to a flat vector.
    pub fn to_vec(&self) -> Vec<Target> {
        let mut v = Vec::with_capacity(3 + self.pcs_challenges.len());
        v.extend(&self.base.to_vec());
        v.extend(&self.pcs_challenges);
        v
    }

    /// Get the total number of challenges.
    pub fn len(&self) -> usize {
        3 + self.pcs_challenges.len()
    }

    /// Check if there are any PCS challenges.
    pub fn is_empty(&self) -> bool {
        false // Always has at least alpha, zeta, zeta_next
    }

    /// Convenience accessor for alpha.
    pub fn alpha(&self) -> Target {
        self.base.alpha
    }

    /// Convenience accessor for zeta.
    pub fn zeta(&self) -> Target {
        self.base.zeta
    }

    /// Convenience accessor for zeta_next.
    pub fn zeta_next(&self) -> Target {
        self.base.zeta_next
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;

    use super::*;

    #[test]
    fn test_challenge_builder_order() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();

        let challenges = ChallengeBuilder::new(&mut circuit)
            .add_alpha_challenge()
            .add_zeta_challenges()
            .add_pcs_challenges(5)
            .build();

        // Should have: 1 alpha + 2 zeta + 5 pcs = 8 total
        assert_eq!(challenges.len(), 8);
    }

    #[test]
    fn test_stark_challenges_roundtrip() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();

        let original = ChallengeBuilder::new(&mut circuit)
            .add_alpha_challenge()
            .add_zeta_challenges()
            .add_pcs_challenges(3)
            .build();

        let structured = StarkChallenges::from_vec(original.clone());
        let reconstructed = structured.to_vec();

        assert_eq!(original, reconstructed);
        assert_eq!(structured.len(), 6);
        assert_eq!(structured.pcs_challenges.len(), 3);
    }
}
