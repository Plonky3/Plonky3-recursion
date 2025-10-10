//! Challenge target structures for STARK verification circuits.
//!
//! This module provides structured allocation of challenge targets,
//! encapsulating the Fiat-Shamir ordering and making challenge generation
//! more maintainable.

use alloc::vec;
use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::StarkGenericConfig;

use crate::Target;
use crate::circuit_challenger::CircuitChallenger;
use crate::circuit_verifier::ObservableCommitment;
use crate::recursive_challenger::RecursiveChallenger;
use crate::recursive_traits::{ProofTargets, Recursive};

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
    /// Allocate base STARK challenge targets using Fiat-Shamir transform.
    ///
    /// It will mutate the challenger state.
    ///
    /// # Fiat-Shamir Ordering
    /// 1. Observe domain parameters (degree_bits, log_quotient_degree)
    /// 2. Observe trace commitment
    /// 3. Observe public values
    /// 4. **Sample alpha** (for constraint folding)
    /// 5. Observe quotient chunks commitment
    /// 6. Observe random commitment (if ZK mode)
    /// 7. **Sample zeta** (OOD evaluation point)
    /// 8. **Sample zeta_next** (next row evaluation point)
    /// 9. Return challenger for PCS to continue sampling (betas, query indices)
    pub fn allocate<SC, Comm, OpeningProof>(
        circuit: &mut CircuitBuilder<SC::Challenge>,
        challenger: &mut CircuitChallenger,
        proof_targets: &ProofTargets<SC, Comm, OpeningProof>,
        public_values: &[Target],
        log_quotient_degree: usize,
    ) -> Self
    where
        SC: StarkGenericConfig,
        SC::Challenge: PrimeCharacteristicRing,
        Comm: Recursive<SC::Challenge> + ObservableCommitment,
        OpeningProof: Recursive<SC::Challenge>,
    {
        // Extract commitment targets from proof
        let trace_comm_targets = proof_targets
            .commitments_targets
            .trace_targets
            .to_observation_targets();
        let quotient_comm_targets = proof_targets
            .commitments_targets
            .quotient_chunks_targets
            .to_observation_targets();
        let random_comm_targets = proof_targets
            .commitments_targets
            .random_commit
            .as_ref()
            .map(|c| c.to_observation_targets());

        // Observe domain parameters
        let degree_bits_target =
            circuit.add_const(SC::Challenge::from_usize(proof_targets.degree_bits));
        let log_quotient_degree_target =
            circuit.add_const(SC::Challenge::from_usize(log_quotient_degree));
        challenger.observe(circuit, degree_bits_target);
        challenger.observe(circuit, log_quotient_degree_target);

        // Observe trace commitment
        challenger.observe_slice(circuit, &trace_comm_targets);

        // Observe public values
        challenger.observe_slice(circuit, public_values);

        // Sample alpha challenge
        let alpha = challenger.sample(circuit);

        // Observe quotient chunks commitment
        challenger.observe_slice(circuit, &quotient_comm_targets);

        // Observe random commitment if in ZK mode
        if let Some(random_comm) = random_comm_targets {
            challenger.observe_slice(circuit, &random_comm);
        }

        // Sample zeta and zeta_next challenges
        let zeta = challenger.sample(circuit);
        let zeta_next = challenger.sample(circuit);

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
    use p3_circuit::ExprId;

    use super::*;

    // Note: Full integration tests with ProofTargets are in circuit_verifier.rs
    #[test]
    fn test_stark_challenges_to_vec() {
        let challenges = StarkChallenges {
            alpha: ExprId(1),
            zeta: ExprId(2),
            zeta_next: ExprId(3),
        };

        let vec = challenges.to_vec();
        assert_eq!(vec.len(), 3);
        assert_eq!(vec[0], challenges.alpha);
        assert_eq!(vec[1], challenges.zeta);
        assert_eq!(vec[2], challenges.zeta_next);
    }
}
