//! Trait for recursive Polynomial Commitment Scheme (PCS) operations.

use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
use p3_uni_stark::StarkGenericConfig;

use super::Recursive;
use crate::Target;
use crate::types::{OpenedValuesTargets, ProofTargets, RecursiveLagrangeSelectors};
use crate::verifier::VerificationError;

/// Type alias for commitments with their opening points.
///
/// Each entry is:
/// - A commitment (Comm)
/// - A list of (Domain, Vec<(point, opened_values)>) tuples
pub type ComsWithOpeningsTargets<Comm, Domain> =
    [(Comm, Vec<(Domain, Vec<(Target, Vec<Target>)>)>)];

/// Trait for recursive polynomial commitment scheme verification.
///
/// This trait provides the interface for verifying polynomial openings within
/// a recursive circuit.
pub trait RecursivePcs<
    SC: StarkGenericConfig,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
    Comm: Recursive<SC::Challenge>,
    Domain,
>
{
    /// PCS-specific verifier parameters (e.g., FRI parameters).
    type VerifierParams;

    /// Recursive proof type (may differ from OpeningProof for some schemes).
    type RecursiveProof;

    /// Generate PCS-specific challenges (e.g., FRI beta challenges, query indices).
    ///
    /// This method observes the opened values and opening proof, then samples
    /// challenges needed for verification. For FRI, this includes:
    /// - Beta challenges for each folding round
    /// - Query indices for spot-checking
    ///
    /// # Parameters
    /// - `circuit`: Circuit builder for creating operations
    /// - `challenger`: Running Fiat-Shamir challenger state
    /// - `proof_targets`: Proof structure with commitments and opening proof
    /// - `opened_values`: All opened values at evaluation points
    /// - `params`: PCS-specific verifier parameters
    ///
    /// # Returns
    /// Vector of challenge targets (ordering depends on PCS scheme)
    fn get_challenges_circuit<const RATE: usize>(
        circuit: &mut CircuitBuilder<SC::Challenge>,
        challenger: &mut crate::challenger::CircuitChallenger<RATE>,
        proof_targets: &ProofTargets<SC, Comm, OpeningProof>,
        opened_values: &OpenedValuesTargets<SC>,
        params: &Self::VerifierParams,
    ) -> Vec<Target>;

    /// Verify the polynomial commitment opening proof in-circuit.
    ///
    /// This method checks that the claimed opened values are consistent with
    /// the commitments, using the opening proof and challenges.
    ///
    /// # Parameters
    /// - `circuit`: Circuit builder for creating operations
    /// - `challenges`: PCS challenges (from `get_challenges_circuit`)
    /// - `commitments_with_opening_points`: All commitments and their opening points
    /// - `opening_proof`: The opening proof targets
    /// - `params`: PCS-specific verifier parameters
    ///
    /// # Returns
    /// `Ok(())` if verification constraints were successfully added,
    /// `Err` if there was a structural error in the proof
    fn verify_circuit(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        challenges: &[Target],
        commitments_with_opening_points: &ComsWithOpeningsTargets<Comm, Domain>,
        opening_proof: &OpeningProof,
        params: &Self::VerifierParams,
    ) -> Result<(), VerificationError>;

    /// Compute Lagrange selector values at a point within the circuit.
    ///
    /// Evaluates row selector polynomials (is_first_row, is_last_row, is_transition)
    /// and computes the vanishing polynomial inverse at the given point.
    ///
    /// # Parameters
    /// - `circuit`: Circuit builder for creating operations
    /// - `domain`: The domain over which the polynomials are defined
    /// - `point`: The evaluation point
    ///
    /// # Returns
    /// Row selectors and vanishing inverse at the point
    fn selectors_at_point_circuit(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        domain: &Domain,
        point: &Target,
    ) -> RecursiveLagrangeSelectors;

    /// Create a disjoint domain for the quotient polynomial.
    ///
    /// The quotient domain must be:
    /// - Large enough to hold the quotient polynomial
    /// - Disjoint from the trace domain (to avoid division by zero)
    ///
    /// # Parameters
    /// - `trace_domain`: The trace polynomial domain
    /// - `degree`: The quotient polynomial degree
    ///
    /// # Returns
    /// A disjoint domain of appropriate size
    fn create_disjoint_domain(&self, trace_domain: Domain, degree: usize) -> Domain;

    /// Split a domain into subdomains for quotient chunks.
    ///
    /// When the quotient polynomial is too large, it's split into chunks
    /// committed separately. This method computes the subdomain for each chunk.
    ///
    /// # Parameters
    /// - `trace_domain`: The trace polynomial domain
    /// - `degree`: The quotient polynomial degree
    ///
    /// # Returns
    /// Vector of subdomains (one per chunk)
    fn split_domains(&self, trace_domain: &Domain, degree: usize) -> Vec<Domain>;

    /// Return log₂ of the domain size.
    ///
    /// # Parameters
    /// - `trace_domain`: The domain
    ///
    /// # Returns
    /// Log₂ of the domain size
    fn log_size(&self, trace_domain: &Domain) -> usize;

    /// Return the domain size.
    ///
    /// # Parameters
    /// - `trace_domain`: The domain
    ///
    /// # Returns
    /// The domain size (power of 2)
    fn size(&self, trace_domain: &Domain) -> usize {
        1 << self.log_size(trace_domain)
    }

    /// Return the first point in the domain.
    ///
    /// For a multiplicative coset, this is the coset offset.
    ///
    /// # Parameters
    /// - `trace_domain`: The domain
    ///
    /// # Returns
    /// The first domain point
    fn first_point(&self, trace_domain: &Domain) -> SC::Challenge;
}
