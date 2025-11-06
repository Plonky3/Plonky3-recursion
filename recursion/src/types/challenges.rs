//! Challenge target structures for STARK verification circuits.

use alloc::vec;
use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::StarkGenericConfig;

use crate::Target;
use crate::traits::{Recursive, RecursiveChallenger};
use crate::types::ProofTargets;
use crate::verifier::ObservableCommitment;

/// Base STARK challenges (independent of PCS choice).
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
    /// This method follows the standard STARK protocol ordering:
    /// 1. Observe domain parameters
    /// 2. Observe trace commitment
    /// 3. Observe public values
    /// 4. Sample alpha
    /// 5. Observe quotient commitment
    /// 6. Observe random commitment (if ZK)
    /// 7. Sample zeta and zeta_next
    ///
    /// The challenger state is mutated and can be used for further PCS challenge sampling.
    ///
    /// # Parameters
    /// - `circuit`: Circuit builder
    /// - `challenger`: Fiat-Shamir challenger (will be mutated)
    /// - `proof_targets`: Proof structure with commitments
    /// - `public_values`: AIR public input values
    /// - `log_quotient_degree`: Log₂ of the quotient polynomial degree
    ///
    /// # Returns
    /// The three base STARK challenges
    pub fn allocate<SC, Comm, OpeningProof>(
        circuit: &mut CircuitBuilder<SC::Challenge>,
        challenger: &mut impl RecursiveChallenger<SC::Challenge>,
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
        let degree_bits_target = circuit.alloc_const(
            SC::Challenge::from_usize(proof_targets.degree_bits),
            "degree bits",
        );
        let log_quotient_degree_target = circuit.alloc_const(
            SC::Challenge::from_usize(log_quotient_degree),
            "log quotient degree",
        );
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

    /// Get the alpha challenge (for constraint folding).
    pub const fn alpha(&self) -> Target {
        self.alpha
    }

    /// Get the zeta challenge (OOD evaluation point).
    pub const fn zeta(&self) -> Target {
        self.zeta
    }

    /// Get the zeta_next challenge (next row evaluation point).
    pub const fn zeta_next(&self) -> Target {
        self.zeta_next
    }
}

#[cfg(test)]
mod tests {
    use p3_circuit::ExprId;

    use super::*;

    #[test]
    fn test_stark_challenges_to_vec() {
        let alpha = ExprId(1);
        let zeta = ExprId(2);
        let zeta_next = ExprId(3);
        let challenges = StarkChallenges {
            alpha,
            zeta,
            zeta_next,
        };

        let vec = challenges.to_vec();
        assert_eq!(vec.len(), 3);
        assert_eq!(vec[0], alpha);
        assert_eq!(vec[1], zeta);
        assert_eq!(vec[2], zeta_next);
    }
}
