//! Challenge target structures for STARK verification circuits.
//!
//! This module provides structured allocation of challenge targets,
//! encapsulating the Fiat-Shamir ordering and making challenge generation
//! more maintainable.

use alloc::vec;
use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
use p3_field::Field;

use crate::Target;

/// Base STARK challenges (independent of PCS choice).
///
/// These are the fundamental challenges needed for any STARK verification:
/// - Alpha: for folding constraint polynomials
/// - Zeta, Zeta_next: for out-of-domain evaluation
#[derive(Debug, Clone)]
pub struct StarkChallenges {
    /// Alpha: challenge for folding all constraint polynomials
    pub alpha: Target,
    /// Zeta: out-of-domain evaluation point
    pub zeta: Target,
    /// Zeta next: evaluation point for next row (zeta * g in the trace domain)
    pub zeta_next: Target,
}

impl StarkChallenges {
    /// Allocate base STARK challenge targets.
    ///
    /// These challenges are allocated as public inputs. In the native verifier,
    /// they would be sampled from the challenger after specific observations.
    ///
    /// TODO: Integrate with recursive challenger for proper Fiat-Shamir observations.
    pub fn allocate<F: Field>(circuit: &mut CircuitBuilder<F>) -> Self {
        // TODO: Observe degree_bits and degree_bits - is_zk
        // TODO: Observe trace commitment
        // TODO: Observe public values
        let alpha = circuit.alloc_public_input("alpha challenge");

        // TODO: Observe quotient chunks commitment
        // TODO: Observe random commitment (if ZK mode)
        let zeta = circuit.alloc_public_input("zeta challenge");
        let zeta_next = circuit.alloc_public_input("zeta_next challenge");

        Self {
            alpha,
            zeta,
            zeta_next,
        }
    }

    /// Convert to flat vector: [alpha, zeta, zeta_next]
    pub fn to_vec(&self) -> Vec<Target> {
        vec![self.alpha, self.zeta, self.zeta_next]
    }

    /// Get individual challenge targets.
    pub fn alpha(&self) -> Target {
        self.alpha
    }

    pub fn zeta(&self) -> Target {
        self.zeta
    }

    pub fn zeta_next(&self) -> Target {
        self.zeta_next
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;

    use super::*;

    #[test]
    fn test_stark_challenges_allocation() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();

        let challenges = StarkChallenges::allocate(&mut circuit);

        // Verify all challenges are allocated
        assert!(challenges.alpha.0 > 0);
        assert!(challenges.zeta.0 > 0);
        assert!(challenges.zeta_next.0 > 0);

        // Verify they're sequential
        assert_eq!(challenges.zeta.0, challenges.alpha.0 + 1);
        assert_eq!(challenges.zeta_next.0, challenges.zeta.0 + 1);
    }

    #[test]
    fn test_stark_challenges_to_vec() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();

        let challenges = StarkChallenges::allocate(&mut circuit);
        let vec = challenges.to_vec();

        let StarkChallenges {
            alpha,
            zeta,
            zeta_next,
        } = challenges;

        assert_eq!(vec.len(), 3);
        assert_eq!(vec[0], alpha);
        assert_eq!(vec[1], zeta);
        assert_eq!(vec[2], zeta_next);
    }

    #[test]
    fn challenges_deterministic() {
        let mut circuit1 = CircuitBuilder::<BabyBear>::new();
        let mut circuit2 = CircuitBuilder::<BabyBear>::new();

        let challenges1 = StarkChallenges::allocate(&mut circuit1);
        let challenges2 = StarkChallenges::allocate(&mut circuit2);

        assert_eq!(challenges1.alpha, challenges2.alpha);
        assert_eq!(challenges1.zeta, challenges2.zeta);
        assert_eq!(challenges1.zeta_next, challenges2.zeta_next);
    }

    #[test]
    fn to_vec_order_preserved() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        let challenges = StarkChallenges::allocate(&mut circuit);
        let vec = challenges.to_vec();

        assert_eq!(vec.len(), 3);
        assert_eq!(vec[0], challenges.alpha());
        assert_eq!(vec[1], challenges.zeta());
        assert_eq!(vec[2], challenges.zeta_next());
    }
}
