use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;

use p3_air::Air;
use p3_challenger::{CanObserve, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_commit::{BatchOpening, Mmcs, Pcs, PolynomialSpace};
use p3_field::{PrimeCharacteristicRing, TwoAdicField};
use p3_fri::{FriProof, TwoAdicFriPcs};
use p3_uni_stark::{
    Domain, Proof, StarkGenericConfig, SymbolicAirBuilder, Val, get_log_quotient_degree,
};
use p3_util::zip_eq::zip_eq;
use thiserror::Error;

use crate::lookup::{GlobalLookup, LocalLookup, RecursiveLookupVerification};

#[derive(Debug, Error)]
pub enum GenerationError {
    #[error("Missing parameter for challenge generation")]
    MissingParameterError,

    #[error(
        "Invalid number of parameters provided for challenge generation: got {0}, expected {1}"
    )]
    InvalidParameterCount(usize, usize),

    #[error("The FRI batch randomization does not correspond to the ZK setting.")]
    RandomizationError,

    #[error("Witness check failed during challenge generation.")]
    InvalidPowWitness,

    #[error("Got {0} {1}, {2} {3}")]
    ProofParametersMismatch(usize, String, usize, String),

    #[error("Invalid proof shape")]
    InvalidShape,
}

/// A type alias for a single opening point and its values.
type PointOpening<SC> = (
    <SC as StarkGenericConfig>::Challenge,
    Vec<<SC as StarkGenericConfig>::Challenge>,
);

/// A type alias for all openings within a specific domain.
type DomainOpenings<SC> = Vec<(Domain<SC>, Vec<PointOpening<SC>>)>;

/// A type alias for a commitment and its associated domain openings.
type CommitmentWithOpenings<SC> = (
    <<SC as StarkGenericConfig>::Pcs as Pcs<
        <SC as StarkGenericConfig>::Challenge,
        <SC as StarkGenericConfig>::Challenger,
    >>::Commitment,
    DomainOpenings<SC>,
);

/// The final type alias for a slice of commitments with their openings.
pub type ComsWithOpenings<SC> = [CommitmentWithOpenings<SC>];

/// Trait which defines the methods necessary
/// for a Pcs to generate challenge values.
pub trait PcsGeneration<SC: StarkGenericConfig, OpeningProof> {
    fn generate_challenges(
        &self,
        config: &SC,
        challenger: &mut SC::Challenger,
        coms_to_verify: &ComsWithOpenings<SC>,
        opening_proof: &OpeningProof,
        // Depending on the `OpeningProof`, we might need additional parameters. For example, for a `FriProof`, we need the `log_max_height` to sample query indices.
        extra_params: Option<&[usize]>,
    ) -> Result<Vec<SC::Challenge>, GenerationError>;

    fn num_challenges(
        opening_proof: &OpeningProof,
        extra_params: Option<&[usize]>,
    ) -> Result<usize, GenerationError>;
}

/// A type alias for a proof along with its associated local and global lookups.
pub type ProofWithLookup<'a, SC> = (Proof<SC>, &'a [LocalLookup<'a>], &'a [GlobalLookup<'a>]);

/// Given proofs of various AIRs -- along with their lookups, public values and log quotient degrees -- generates all the challenges needed for their joint verification.
pub fn generate_challenges_multitable<
    SC: StarkGenericConfig,
    Lookup: RecursiveLookupVerification<SC::Challenge>,
>(
    config: &SC,
    proofs: &[ProofWithLookup<SC>],
    log_quotient_degrees: &[usize],
    all_public_values: &[&[Val<SC>]],
    extra_params: Option<&[usize]>,
    lookup_gadget: &Lookup,
) -> Result<Vec<SC::Challenge>, GenerationError>
where
    SC::Pcs: PcsGeneration<SC, <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>,
{
    if proofs.len() != all_public_values.len() || proofs.len() != log_quotient_degrees.len() {
        return Err(GenerationError::ProofParametersMismatch(
            proofs.len(),
            "proofs".to_string(),
            all_public_values.len(),
            "all_public_values".to_string(),
        ));
    }

    // First, we compute the total number of challenges we will need to generate.
    let mut num_challenges = 0;

    let all_global_lookups = proofs
        .iter()
        .flat_map(|(proof, local_lookups, global_lookups)| {
            num_challenges += 3 // alpha, zeta and zeta_next
            + lookup_gadget.num_local_lookup_challenges(local_lookups)
         + SC::Pcs::num_challenges(&proof.opening_proof, extra_params).unwrap();
            global_lookups.iter().cloned()
        })
        .collect::<Vec<_>>();

    num_challenges += lookup_gadget.num_global_lookup_challenges(&all_global_lookups);

    let mut challenges = Vec::with_capacity(num_challenges);

    let mut challenger = config.initialise_challenger();

    // Observe all traces so we can generate the global lookup challenges.
    for ((proof, _, _), public_values) in zip_eq(
        proofs,
        all_public_values,
        GenerationError::ProofParametersMismatch(
            proofs.len(),
            "proofs".to_string(),
            all_public_values.len(),
            "all_public_values".to_string(),
        ),
    )? {
        let Proof {
            commitments,
            degree_bits,
            ..
        } = proof;
        challenger.observe(Val::<SC>::from_usize(*degree_bits));
        challenger.observe(Val::<SC>::from_usize(*degree_bits - config.is_zk()));

        challenger.observe(commitments.trace.clone());
        challenger.observe_slice(public_values);
    }

    // Sample global lookup challenges.
    challenges.extend(
        lookup_gadget
            .generate_global_lookup_challenges(&mut challenger, &all_global_lookups)
            .into_iter()
            .flatten(),
    );

    // Now, generate the challenges for each table individually.
    for ((proof, _local_lookups, _), &log_quotient_degree) in zip_eq(
        proofs,
        log_quotient_degrees,
        GenerationError::ProofParametersMismatch(
            proofs.len(),
            "proofs".to_string(),
            log_quotient_degrees.len(),
            "log quotient degrees".to_string(),
        ),
    )? {
        generate_challenges_one_table(
            config,
            proof,
            &mut challenger,
            &mut challenges,
            extra_params,
            log_quotient_degree,
        )?;
    }

    Ok(challenges)
}

pub fn generate_challenges_one_table<SC: StarkGenericConfig>(
    config: &SC,
    proof: &Proof<SC>,
    challenger: &mut SC::Challenger,
    challenges: &mut Vec<SC::Challenge>,
    extra_params: Option<&[usize]>,
    log_quotient_degree: usize, // Pass this as a parameter since we can't compute it from trait object
) -> Result<(), GenerationError>
where
    SC::Pcs: PcsGeneration<SC, <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>,
{
    let Proof {
        commitments,
        opened_values,
        opening_proof,
        degree_bits,
    } = proof;

    let degree = 1 << degree_bits;
    let pcs = config.pcs();
    let quotient_degree = 1 << (log_quotient_degree + config.is_zk());

    let trace_domain = pcs.natural_domain_for_degree(degree);
    let init_trace_domain = pcs.natural_domain_for_degree(degree >> (config.is_zk()));
    let quotient_domain =
        trace_domain.create_disjoint_domain(1 << (degree_bits + log_quotient_degree));
    let quotient_chunks_domains = quotient_domain.split_domains(quotient_degree);

    let randomized_quotient_chunks_domains = quotient_chunks_domains
        .iter()
        .map(|domain| pcs.natural_domain_for_degree(domain.size() << (config.is_zk())))
        .collect::<Vec<_>>();

    // Get the first Fiat-Shamir challenge which will be used to combine all constraint polynomials into a single polynomial.
    challenges.push(challenger.sample_algebra_element());
    challenger.observe(commitments.quotient_chunks.clone());

    if let Some(r_commit) = commitments.random.clone() {
        challenger.observe(r_commit);
    }

    // Get an out-of-domain point to open our values at.
    let zeta = challenger.sample_algebra_element();
    challenges.push(zeta);
    let zeta_next = init_trace_domain.next_point(zeta).unwrap();
    challenges.push(zeta_next);

    let mut coms_to_verify = if let Some(r_commit) = &commitments.random {
        let random_values = opened_values
            .random
            .as_ref()
            .ok_or(GenerationError::RandomizationError)?;
        vec![(
            r_commit.clone(),
            vec![(trace_domain, vec![(zeta, random_values.clone())])],
        )]
    } else {
        vec![]
    };
    coms_to_verify.extend(vec![
        (
            commitments.trace.clone(),
            vec![(
                trace_domain,
                vec![
                    (zeta, opened_values.trace_local.clone()),
                    (zeta_next, opened_values.trace_next.clone()),
                ],
            )],
        ),
        (
            commitments.quotient_chunks.clone(),
            // Check the commitment on the randomized domains.
            zip_eq(
                randomized_quotient_chunks_domains.iter(),
                opened_values.quotient_chunks.clone(),
                GenerationError::InvalidShape,
            )?
            .map(|(domain, values)| (*domain, vec![(zeta, values.clone())]))
            .collect::<Vec<_>>(),
        ),
    ]);

    let pcs_challenges = pcs.generate_challenges(
        config,
        challenger,
        &coms_to_verify,
        opening_proof,
        extra_params,
    )?;

    challenges.extend(pcs_challenges);

    Ok(())
}

// TODO: This could be used on the Plonky3 side as well.
/// Generates the challenges used in the verification of a STARK proof.
pub fn generate_challenges<SC: StarkGenericConfig, A>(
    air: &A,
    config: &SC,
    proof: &Proof<SC>,
    public_values: &[Val<SC>],
    extra_params: Option<&[usize]>,
) -> Result<Vec<SC::Challenge>, GenerationError>
where
    A: Air<SymbolicAirBuilder<Val<SC>>>,
    SC::Pcs: PcsGeneration<SC, <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>,
{
    let Proof {
        commitments,
        opened_values,
        opening_proof,
        degree_bits,
    } = proof;

    let degree = 1 << degree_bits;
    let pcs = config.pcs();
    let log_quotient_degree =
        get_log_quotient_degree::<Val<SC>, A>(air, 0, public_values.len(), config.is_zk());
    let quotient_degree = 1 << (log_quotient_degree + config.is_zk());

    let trace_domain = pcs.natural_domain_for_degree(degree);
    let init_trace_domain = pcs.natural_domain_for_degree(degree >> (config.is_zk()));
    let quotient_domain =
        trace_domain.create_disjoint_domain(1 << (degree_bits + log_quotient_degree));
    let quotient_chunks_domains = quotient_domain.split_domains(quotient_degree);

    let randomized_quotient_chunks_domains = quotient_chunks_domains
        .iter()
        .map(|domain| pcs.natural_domain_for_degree(domain.size() << (config.is_zk())))
        .collect::<Vec<_>>();

    let num_challenges = 3 // alpha, zeta and zeta_next
     + SC::Pcs::num_challenges(opening_proof, extra_params)?;

    let mut challenges = Vec::with_capacity(num_challenges);

    let mut challenger = config.initialise_challenger();

    challenger.observe(Val::<SC>::from_usize(*degree_bits));
    challenger.observe(Val::<SC>::from_usize(*degree_bits - config.is_zk()));

    challenger.observe(commitments.trace.clone());
    challenger.observe_slice(public_values);

    // Get the first Fiat-Shamir challenge which will be used to combine all constraint polynomials into a single polynomial.
    challenges.push(challenger.sample_algebra_element());
    challenger.observe(commitments.quotient_chunks.clone());

    if let Some(r_commit) = commitments.random.clone() {
        challenger.observe(r_commit);
    }

    // Get an out-of-domain point to open our values at.
    let zeta = challenger.sample_algebra_element();
    challenges.push(zeta);
    let zeta_next = init_trace_domain.next_point(zeta).unwrap();
    challenges.push(zeta_next);

    let mut coms_to_verify = if let Some(r_commit) = &commitments.random {
        let random_values = opened_values
            .random
            .as_ref()
            .ok_or(GenerationError::RandomizationError)?;
        vec![(
            r_commit.clone(),
            vec![(trace_domain, vec![(zeta, random_values.clone())])],
        )]
    } else {
        vec![]
    };
    coms_to_verify.extend(vec![
        (
            commitments.trace.clone(),
            vec![(
                trace_domain,
                vec![
                    (zeta, opened_values.trace_local.clone()),
                    (zeta_next, opened_values.trace_next.clone()),
                ],
            )],
        ),
        (
            commitments.quotient_chunks.clone(),
            // Check the commitment on the randomized domains.
            zip_eq(
                randomized_quotient_chunks_domains.iter(),
                opened_values.quotient_chunks.clone(),
                GenerationError::InvalidShape,
            )?
            .map(|(domain, values)| (*domain, vec![(zeta, values.clone())]))
            .collect::<Vec<_>>(),
        ),
    ]);

    let pcs_challenges = pcs.generate_challenges(
        config,
        &mut challenger,
        &coms_to_verify,
        opening_proof,
        extra_params,
    )?;

    challenges.extend(pcs_challenges);

    Ok(challenges)
}

type InnerFriProof<SC, InputMmcs, FriMmcs> = FriProof<
    <SC as StarkGenericConfig>::Challenge,
    FriMmcs,
    Val<SC>,
    Vec<BatchOpening<Val<SC>, InputMmcs>>,
>;

impl<SC: StarkGenericConfig, Dft, InputMmcs: Mmcs<Val<SC>>, FriMmcs: Mmcs<SC::Challenge>>
    PcsGeneration<SC, InnerFriProof<SC, InputMmcs, FriMmcs>>
    for TwoAdicFriPcs<Val<SC>, Dft, InputMmcs, FriMmcs>
where
    Val<SC>: TwoAdicField,
    SC::Challenger: FieldChallenger<Val<SC>>
        + GrindingChallenger<Witness = Val<SC>>
        + CanObserve<FriMmcs::Commitment>,
{
    fn generate_challenges(
        &self,
        _config: &SC,
        challenger: &mut SC::Challenger,
        coms_to_verify: &ComsWithOpenings<SC>,
        opening_proof: &InnerFriProof<SC, InputMmcs, FriMmcs>,
        extra_params: Option<&[usize]>,
    ) -> Result<Vec<SC::Challenge>, GenerationError> {
        let num_challenges =
            1 + opening_proof.commit_phase_commits.len() + opening_proof.query_proofs.len();
        let mut challenges = Vec::with_capacity(num_challenges);

        // Observe all openings.
        for (_, round) in coms_to_verify {
            for (_, mat) in round {
                for (_, point) in mat {
                    point
                        .iter()
                        .for_each(|&opening| challenger.observe_algebra_element(opening));
                }
            }
        }

        challenges.push(challenger.sample_algebra_element());

        // Get `beta` challenges for the FRI rounds.
        opening_proof.commit_phase_commits.iter().for_each(|comm| {
            // To match with the prover (and for security purposes),
            // we observe the commitment before sampling the challenge.
            challenger.observe(comm.clone());
            challenges.push(challenger.sample_algebra_element());
        });

        // Observe all coefficients of the final polynomial.
        opening_proof
            .final_poly
            .iter()
            .for_each(|x| challenger.observe_algebra_element(*x));

        let params = extra_params.ok_or(GenerationError::MissingParameterError)?;

        if params.len() != 2 {
            return Err(GenerationError::InvalidParameterCount(params.len(), 2));
        }
        // Observe PoW and sample bits.
        let pow_bits = params[0];
        if !challenger.check_witness(pow_bits, opening_proof.pow_witness) {
            return Err(GenerationError::InvalidPowWitness);
        }

        let log_height_max = params[1];
        let log_global_max_height = opening_proof.commit_phase_commits.len() + log_height_max;
        for _ in &opening_proof.query_proofs {
            // For each query proof, we start by generating the random index.
            challenges.push(SC::Challenge::from_usize(
                challenger.sample_bits(log_global_max_height),
            ));
        }

        Ok(challenges)
    }

    fn num_challenges(
        opening_proof: &InnerFriProof<SC, InputMmcs, FriMmcs>,
        _extra_params: Option<&[usize]>,
    ) -> Result<usize, GenerationError> {
        let num_challenges =
            1 + opening_proof.commit_phase_commits.len() + opening_proof.query_proofs.len();

        Ok(num_challenges)
    }
}
