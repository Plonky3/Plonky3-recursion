//! Helper for managing challenge generation in verification circuits.
//!
//! Challenge generation in STARK verification follows a specific Fiat-Shamir transcript order.
//! This module provides a builder to make that order explicit and less error-prone.

use alloc::vec;
use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
use p3_field::{Field, PrimeCharacteristicRing};

use crate::Target;
use crate::circuit_challenger::CircuitChallenger;

/// Default sponge rate for the recursive challenger.
/// TODO: Make this configurable.
pub const DEFAULT_SPONGE_RATE: usize = 8;

/// Builder for creating challenge targets in the correct Fiat-Shamir order.
///
/// Generic over a challenger type `C` that implements `RecursiveChallenger`.
/// By default uses `CircuitChallenger` for proper Fiat-Shamir transformations.
///
/// # Modes
///
/// 1. **Default (CircuitChallenger)**: `ChallengeBuilder::new(circuit)`
///    - Uses `CircuitChallenger<8>` for proper Fiat-Shamir
///    - Observations hash into sponge state via HashAbsorb
///    - Sampling extracts from sponge state via HashSqueeze
///
/// 2. **Public input mode**: `ChallengeBuilder::with_public_inputs(circuit)`
///    - Uses `()` as a no-op challenger
///    - Observations are no-ops
///    - Sampling returns public inputs
///    - For testing or backwards compatibility
///
/// 3. **Custom challenger**: `ChallengeBuilder::with_challenger(circuit, challenger)`
///    - Use a custom `RecursiveChallenger` implementation
///
/// # Example
/// ```ignore
/// // Default mode (uses CircuitChallenger)
/// let challenges = ChallengeBuilder::new(circuit)
///     .add_alpha_challenge()
///     .add_zeta_challenges()
///     .build();
///
/// // Public input mode (for testing)
/// let challenges = ChallengeBuilder::with_public_inputs(circuit)
///     .add_alpha_challenge()
///     .add_zeta_challenges()
///     .build();
/// ```
pub struct ChallengeBuilder<
    'a,
    F: Field + PrimeCharacteristicRing,
    C = CircuitChallenger<DEFAULT_SPONGE_RATE>,
> {
    circuit: &'a mut CircuitBuilder<F>,
    challenger: C,
    challenges: Vec<Target>,
}

impl<'a, F: Field + PrimeCharacteristicRing>
    ChallengeBuilder<'a, F, CircuitChallenger<DEFAULT_SPONGE_RATE>>
{
    /// Create a new challenge builder with a `CircuitChallenger`.
    ///
    /// This is the default mode that performs proper Fiat-Shamir transformations
    /// using HashAbsorb and HashSqueeze operations.
    pub fn new(circuit: &'a mut CircuitBuilder<F>) -> Self {
        Self {
            circuit,
            challenger: CircuitChallenger::new(),
            challenges: Vec::new(),
        }
    }
}

impl<'a, F: Field + PrimeCharacteristicRing, C> ChallengeBuilder<'a, F, C>
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

impl<'a, F: Field + PrimeCharacteristicRing, C> ChallengeBuilder<'a, F, C> {
    /// Observe degree bits in the Fiat-Shamir transcript.
    pub fn observe_degree_bits(&mut self, degree_bits: usize) -> &mut Self
    where
        C: crate::recursive_challenger::RecursiveChallenger<F>,
    {
        let degree_target = self.circuit.add_const(F::from_usize(degree_bits));
        self.challenger.observe(self.circuit, degree_target);

        self
    }

    /// Observe trace commitment in the Fiat-Shamir transcript.
    ///
    /// **TODO**: Currently a no-op. Needs commitment structure to be defined.
    pub fn observe_trace_commitment<Comm>(&mut self, commitment: &Comm) -> &mut Self
    where
        C: crate::recursive_challenger::RecursiveChallenger<F>,
    {
        // TODO: Hash commitment targets into challenger once commitment structure is defined
        // For each target in commitment, call:
        // self.challenger.observe(self.circuit, target);
        let _ = (&mut self.challenger, commitment);
        self
    }

    /// Observe public values in the Fiat-Shamir transcript.
    pub fn observe_public_values(&mut self, public_values: &[Target]) -> &mut Self
    where
        C: crate::recursive_challenger::RecursiveChallenger<F>,
    {
        self.challenger.observe_slice(self.circuit, public_values);
        self
    }

    /// Sample the alpha challenge from the challenger.
    ///
    /// Extracts a challenge from the challenger's sponge state.
    fn sample_alpha(&mut self) -> &mut Self
    where
        C: crate::recursive_challenger::RecursiveChallenger<F>,
    {
        let alpha = self.challenger.sample(self.circuit);
        self.challenges.push(alpha);
        self
    }

    /// Add the alpha challenge (used for folding constraints).
    ///
    /// This is a convenience method that samples the alpha challenge.
    /// Observations of degree_bits, trace_commitment, and public_values should
    /// be done before calling this method when using a real challenger.
    pub fn add_alpha_challenge(&mut self) -> &mut Self
    where
        C: crate::recursive_challenger::RecursiveChallenger<F>,
    {
        self.sample_alpha()
    }

    /// Observe quotient chunks commitment in the Fiat-Shamir transcript.
    ///
    /// Hashes the commitment targets using the challenger.
    ///
    /// **TODO**: Currently a no-op. Needs commitment structure to be defined.
    pub fn observe_quotient_chunks<Comm>(&mut self, commitment: &Comm) -> &mut Self
    where
        C: crate::recursive_challenger::RecursiveChallenger<F>,
    {
        // TODO: Hash commitment targets into challenger once commitment structure is defined
        // For each target in commitment, call:
        // self.challenger.observe(self.circuit, target);
        let _ = (&mut self.challenger, commitment);
        self
    }

    /// Observe random commitment in the Fiat-Shamir transcript (ZK mode only).
    ///
    /// Hashes the commitment targets if present using the challenger.
    ///
    /// **TODO**: Currently a no-op. Needs commitment structure to be defined.
    pub fn observe_random_commitment<Comm>(&mut self, commitment: Option<&Comm>) -> &mut Self
    where
        C: crate::recursive_challenger::RecursiveChallenger<F>,
    {
        // TODO: Hash commitment targets into challenger once commitment structure is defined
        // if let Some(commit) = commitment {
        //     for target in commit { self.challenger.observe(self.circuit, target); }
        // }
        let _ = (&mut self.challenger, commitment);
        self
    }

    /// Sample the zeta and zeta_next challenges from the challenger.
    ///
    /// - Zeta is sampled from the challenger's sponge state
    /// - Zeta_next is also sampled (TODO: should be computed from zeta)
    fn sample_zeta_and_zeta_next(&mut self) -> &mut Self
    where
        C: crate::recursive_challenger::RecursiveChallenger<F>,
    {
        // Sample zeta from challenger
        let zeta = self.challenger.sample(self.circuit);

        // TODO: Compute zeta_next as next point in trace domain (zeta * g)
        // This requires access to the trace domain generator
        // For now, sample zeta_next independently
        let zeta_next = self.challenger.sample(self.circuit);

        self.challenges.push(zeta);
        self.challenges.push(zeta_next);
        self
    }

    /// Add the zeta and zeta_next challenges (out-of-domain evaluation points).
    ///
    /// This is a convenience method that samples the zeta challenges.
    /// Observations of quotient_chunks and random_commitment should be done
    /// before calling this method when using a real challenger.
    pub fn add_zeta_challenges(&mut self) -> &mut Self
    where
        C: crate::recursive_challenger::RecursiveChallenger<F>,
    {
        self.sample_zeta_and_zeta_next()
    }

    /// Add PCS-specific challenges (e.g., FRI betas and query indices).
    ///
    /// Samples the specified number of challenges from the challenger.
    /// The exact meaning depends on the PCS implementation.
    ///
    /// **TODO**: This is a temporary helper. PCS challenge generation should be
    /// handled by the PCS implementation directly with proper observations.
    pub fn add_pcs_challenges(&mut self, count: usize) -> &mut Self
    where
        C: crate::recursive_challenger::RecursiveChallenger<F>,
    {
        for _ in 0..count {
            let challenge = self.challenger.sample(self.circuit);
            self.challenges.push(challenge);
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
        use p3_circuit::op::{NonPrimitiveOpConfig, NonPrimitiveOpType};
        
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        
        // Enable hash operations for CircuitChallenger
        circuit.enable_op(NonPrimitiveOpType::HashAbsorb { reset: true }, NonPrimitiveOpConfig::None);
        circuit.enable_op(NonPrimitiveOpType::HashAbsorb { reset: false }, NonPrimitiveOpConfig::None);
        circuit.enable_op(NonPrimitiveOpType::HashSqueeze, NonPrimitiveOpConfig::None);

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
        use p3_circuit::op::{NonPrimitiveOpConfig, NonPrimitiveOpType};
        
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        
        // Enable hash operations for CircuitChallenger
        circuit.enable_op(NonPrimitiveOpType::HashAbsorb { reset: true }, NonPrimitiveOpConfig::None);
        circuit.enable_op(NonPrimitiveOpType::HashAbsorb { reset: false }, NonPrimitiveOpConfig::None);
        circuit.enable_op(NonPrimitiveOpType::HashSqueeze, NonPrimitiveOpConfig::None);

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
