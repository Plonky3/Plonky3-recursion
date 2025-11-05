use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::marker::PhantomData;

use itertools::Itertools;
use p3_circuit::CircuitBuilder;
use p3_circuit::op::{NonPrimitiveOpConfig, NonPrimitiveOpType};
use p3_circuit::utils::ColumnsTargets;
use p3_commit::Pcs;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_uni_stark::StarkGenericConfig;
use p3_util::zip_eq::zip_eq;

use super::{ObservableCommitment, VerificationError, recompose_quotient_from_chunks_circuit};
use crate::Target;
use crate::challenger::CircuitChallenger;
use crate::traits::{Recursive, RecursiveAir, RecursivePcs};
use crate::types::{CommitmentTargets, OpenedValuesTargets, ProofTargets, StarkChallenges};

/// Type alias for PCS verifier parameters.
type PcsVerifierParams<SC, InputProof, OpeningProof, Comm> =
    <<SC as StarkGenericConfig>::Pcs as RecursivePcs<
        SC,
        InputProof,
        OpeningProof,
        Comm,
        <<SC as StarkGenericConfig>::Pcs as Pcs<
            <SC as StarkGenericConfig>::Challenge,
            <SC as StarkGenericConfig>::Challenger,
        >>::Domain,
    >>::VerifierParams;

type PcsDomain<SC> = <<SC as StarkGenericConfig>::Pcs as Pcs<
    <SC as StarkGenericConfig>::Challenge,
    <SC as StarkGenericConfig>::Challenger,
>>::Domain;

/// Verifies a STARK proof within a circuit.
///
/// This function adds constraints to the circuit builder that verify a STARK proof.
///
/// # Parameters
/// - `config`: STARK configuration including PCS and challenger
/// - `air`: The Algebraic Intermediate Representation defining the computation
/// - `circuit`: Circuit builder to add verification constraints to
/// - `proof_targets`: Recursive representation of the proof
/// - `public_values`: Public input targets
/// - `pcs_params`: PCS-specific verifier parameters (e.g. FRI's log blowup / final poly size)
///
/// # Returns
/// `Ok(())` if the circuit was successfully constructed, `Err` otherwise.
pub fn verify_circuit<
    A,
    SC: StarkGenericConfig,
    Comm: Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        > + Clone
        + ObservableCommitment,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
    const RATE: usize,
>(
    config: &SC,
    air: &A,
    circuit: &mut CircuitBuilder<SC::Challenge>,
    proof_targets: &ProofTargets<SC, Comm, OpeningProof>,
    public_values: &[Target],
    pcs_params: &PcsVerifierParams<SC, InputProof, OpeningProof, Comm>,
) -> Result<(), VerificationError>
where
    A: RecursiveAir<SC::Challenge>,
    <SC as StarkGenericConfig>::Pcs: RecursivePcs<
            SC,
            InputProof,
            OpeningProof,
            Comm,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
    SC::Challenge: PrimeCharacteristicRing,
{
    // Enable hash operations for CircuitChallenger
    // Note: These are placeholders until Poseidon2CircuitAir is implemented
    circuit.enable_op(
        NonPrimitiveOpType::HashAbsorb { reset: true },
        NonPrimitiveOpConfig::None,
    );
    circuit.enable_op(NonPrimitiveOpType::HashSqueeze, NonPrimitiveOpConfig::None);

    let ProofTargets {
        commitments_targets:
            CommitmentTargets {
                trace_targets,
                quotient_chunks_targets,
                random_commit,
                ..
            },
        opened_values_targets:
            OpenedValuesTargets {
                trace_local_targets: opened_trace_local_targets,
                trace_next_targets: opened_trace_next_targets,
                quotient_chunks_targets: opened_quotient_chunks_targets,
                random_targets: opened_random,
                ..
            },
        opening_proof,
        degree_bits,
    } = proof_targets;

    let degree = 1 << degree_bits;
    let log_quotient_degree = A::get_log_quotient_degree(air, public_values.len(), config.is_zk());
    let quotient_degree = 1 << (log_quotient_degree + config.is_zk());

    let pcs = config.pcs();
    let trace_domain = pcs.natural_domain_for_degree(degree);
    let init_trace_domain = pcs.natural_domain_for_degree(degree >> (config.is_zk()));

    let quotient_domain =
        pcs.create_disjoint_domain(trace_domain, 1 << (degree_bits + log_quotient_degree));
    let quotient_chunks_domains = pcs.split_domains(&quotient_domain, quotient_degree);

    let randomized_quotient_chunks_domains = quotient_chunks_domains
        .iter()
        .map(|domain| pcs.natural_domain_for_degree(pcs.size(domain) << (config.is_zk())))
        .collect_vec();

    // Generate all challenges (alpha, zeta, zeta_next, PCS challenges)
    let challenge_targets = get_circuit_challenges::<A, SC, Comm, InputProof, OpeningProof, RATE>(
        air,
        config,
        proof_targets,
        public_values,
        &OpenedValuesTargets {
            trace_local_targets: opened_trace_local_targets.clone(),
            trace_next_targets: opened_trace_next_targets.clone(),
            quotient_chunks_targets: opened_quotient_chunks_targets.clone(),
            random_targets: opened_random.clone(),
            _phantom: PhantomData,
        },
        circuit,
        pcs_params,
    );

    // Validate ZK randomization consistency
    if (opened_random.is_some() != SC::Pcs::ZK) || (random_commit.is_some() != SC::Pcs::ZK) {
        return Err(VerificationError::RandomizationError);
    }

    // Validate proof shape
    validate_proof_shape::<A, SC>(
        air,
        opened_trace_local_targets,
        opened_trace_next_targets,
        opened_quotient_chunks_targets,
        opened_random,
        quotient_degree,
    )?;

    let alpha = challenge_targets[0];
    let zeta = challenge_targets[1];
    let zeta_next = challenge_targets[2];

    // Prepare commitments with their opening points for PCS verification
    let mut coms_to_verify = if let Some(r_commit) = &random_commit {
        let random_values = opened_random
            .as_ref()
            .ok_or(VerificationError::RandomizationError)?;
        vec![(
            r_commit.clone(),
            vec![(trace_domain, vec![(zeta, random_values.clone())])],
        )]
    } else {
        vec![]
    };

    coms_to_verify.extend(vec![
        (
            trace_targets.clone(),
            vec![(
                trace_domain,
                vec![
                    (zeta, opened_trace_local_targets.clone()),
                    (zeta_next, opened_trace_next_targets.clone()),
                ],
            )],
        ),
        (
            quotient_chunks_targets.clone(),
            // Check the commitment on the randomized domains
            zip_eq(
                randomized_quotient_chunks_domains.iter(),
                opened_quotient_chunks_targets,
                VerificationError::InvalidProofShape(
                    "Randomized quotient chunks length mismatch".to_string(),
                ),
            )?
            .map(|(domain, values)| (*domain, vec![(zeta, values.clone())]))
            .collect_vec(),
        ),
    ]);

    // Verify polynomial openings using PCS
    pcs.verify_circuit(
        circuit,
        &challenge_targets[3..], // PCS challenges (after alpha, zeta, zeta_next)
        &coms_to_verify,
        opening_proof,
        pcs_params,
    )?;

    // Compute quotient polynomial evaluation from chunks
    let quotient = recompose_quotient_from_chunks_circuit::<
        SC,
        InputProof,
        OpeningProof,
        Comm,
        PcsDomain<SC>,
    >(
        circuit,
        &quotient_chunks_domains,
        opened_quotient_chunks_targets,
        zeta,
        pcs,
    );

    // Evaluate AIR constraints at out-of-domain point
    let sels = pcs.selectors_at_point_circuit(circuit, &init_trace_domain, &zeta);
    let columns_targets = ColumnsTargets {
        challenges: &[],
        public_values,
        local_prep_values: &[],
        next_prep_values: &[],
        local_values: opened_trace_local_targets,
        next_values: opened_trace_next_targets,
    };
    let folded_constraints = air.eval_folded_circuit(circuit, &sels, &alpha, columns_targets);

    // Verify: constraints / Z_H(zeta) == quotient(zeta)
    let folded_mul = circuit.mul(folded_constraints, sels.inv_vanishing);
    circuit.connect(folded_mul, quotient);

    Ok(())
}

/// Generate all challenges for STARK verification.
///
/// This includes:
/// - Base STARK challenges (alpha, zeta, zeta_next)
/// - PCS-specific challenges (e.g., FRI betas, query indices)
fn get_circuit_challenges<
    A: RecursiveAir<SC::Challenge>,
    SC: StarkGenericConfig,
    Comm: Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        > + ObservableCommitment,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
    const RATE: usize,
>(
    air: &A,
    config: &SC,
    proof_targets: &ProofTargets<SC, Comm, OpeningProof>,
    public_values: &[Target],
    opened_values: &OpenedValuesTargets<SC>,
    circuit: &mut CircuitBuilder<SC::Challenge>,
    pcs_params: &PcsVerifierParams<SC, InputProof, OpeningProof, Comm>,
) -> Vec<Target>
where
    SC::Pcs: RecursivePcs<
            SC,
            InputProof,
            OpeningProof,
            Comm,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
    SC::Challenge: PrimeCharacteristicRing,
{
    let log_quotient_degree = A::get_log_quotient_degree(air, public_values.len(), config.is_zk());

    let mut challenger = CircuitChallenger::<RATE>::new();

    // Allocate base STARK challenges (alpha, zeta, zeta_next) using Fiat-Shamir
    let base_challenges = StarkChallenges::allocate::<SC, Comm, OpeningProof>(
        circuit,
        &mut challenger,
        proof_targets,
        public_values,
        log_quotient_degree,
    );

    // Get PCS-specific challenges (FRI betas, query indices, etc.)
    let pcs_challenges = SC::Pcs::get_challenges_circuit::<RATE>(
        circuit,
        &mut challenger,
        proof_targets,
        opened_values,
        pcs_params,
    );

    // Return flat vector: [alpha, zeta, zeta_next, ...pcs_challenges]
    let mut all_challenges = base_challenges.to_vec();
    all_challenges.extend(pcs_challenges);
    all_challenges
}

/// Validate the shape of the proof (dimensions, lengths).
fn validate_proof_shape<A, SC: StarkGenericConfig>(
    air: &A,
    opened_trace_local: &[Target],
    opened_trace_next: &[Target],
    opened_quotient_chunks: &[Vec<Target>],
    opened_random: &Option<Vec<Target>>,
    quotient_degree: usize,
) -> Result<(), VerificationError>
where
    A: RecursiveAir<SC::Challenge>,
    SC::Challenge: PrimeCharacteristicRing,
{
    let air_width = A::width(air);

    if opened_trace_local.len() != air_width || opened_trace_next.len() != air_width {
        return Err(VerificationError::InvalidProofShape(format!(
            "Expected opened_trace_local and opened_trace_next to have length {}, got {} and {}",
            air_width,
            opened_trace_local.len(),
            opened_trace_next.len()
        )));
    }

    if opened_quotient_chunks.len() != quotient_degree {
        return Err(VerificationError::InvalidProofShape(format!(
            "Expected opened_quotient_chunks to have length {}, got {}",
            quotient_degree,
            opened_quotient_chunks.len()
        )));
    }

    if opened_quotient_chunks
        .iter()
        .any(|opened_chunk| opened_chunk.len() != SC::Challenge::DIMENSION)
    {
        return Err(VerificationError::InvalidProofShape(format!(
            "Invalid quotient chunk length: expected {}",
            SC::Challenge::DIMENSION
        )));
    }

    if let Some(r_comm) = &opened_random
        && r_comm.len() != SC::Challenge::DIMENSION
    {
        return Err(VerificationError::InvalidProofShape(format!(
            "Expected opened random values to have length {}, got {}",
            SC::Challenge::DIMENSION,
            r_comm.len()
        )));
    }

    Ok(())
}
