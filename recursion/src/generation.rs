use alloc::vec;
use alloc::vec::Vec;

use itertools::zip_eq;
use p3_air::Air;
use p3_batch_stark::BatchProof;
use p3_batch_stark::config::{observe_base_as_ext, observe_instance_binding};
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_commit::{BatchOpening, Mmcs, Pcs, PolynomialSpace};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField, TwoAdicField};
use p3_fri::{FriProof, TwoAdicFriPcs};
use p3_uni_stark::{
    Domain, Proof, StarkGenericConfig, SymbolicAirBuilder, Val, VerifierConstraintFolder,
    get_log_quotient_degree,
};
use thiserror::Error;
use tracing::debug_span;

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

    #[error("Invalid proof shape: {0}")]
    InvalidProofShape(&'static str),
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
type ComsWithOpenings<SC> = [CommitmentWithOpenings<SC>];

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
    A: Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    SC::Pcs: PcsGeneration<SC, <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>,
{
    let Proof {
        commitments,
        opened_values,
        opening_proof,
        degree_bits,
    } = proof;

    let preprocessed = air.preprocessed_trace();
    let preprocessed_width = preprocessed.as_ref().map(|m| m.width).unwrap_or(0);

    let degree = 1 << degree_bits;
    let pcs = config.pcs();
    let log_quotient_degree = get_log_quotient_degree::<Val<SC>, A>(
        air,
        preprocessed_width,
        public_values.len(),
        config.is_zk(),
    );
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

    let preprocessed_commit = if preprocessed_width > 0 {
        assert_eq!(config.is_zk(), 0); // TODO: preprocessed columns not supported in zk mode

        let prep = preprocessed.expect("If the width is > 0, then the commit exists.");
        let height = prep.values.len() / preprocessed_width;

        if height != trace_domain.size() {
            return Err(GenerationError::InvalidProofShape(
                "Verifier's preprocessed trace height must be equal to trace domain size",
            ));
        }

        let (preprocessed_commit, _) = debug_span!("process preprocessed trace")
            .in_scope(|| pcs.commit([(trace_domain, prep)]));
        Some(preprocessed_commit)
    } else {
        None
    };

    let num_challenges = 3 // alpha, zeta and zeta_next
     + SC::Pcs::num_challenges(opening_proof, extra_params)?;

    let mut challenges = Vec::with_capacity(num_challenges);

    let mut challenger = config.initialise_challenger();

    challenger.observe(Val::<SC>::from_usize(*degree_bits));
    challenger.observe(Val::<SC>::from_usize(*degree_bits - config.is_zk()));

    challenger.observe(Val::<SC>::from_usize(preprocessed_width));
    challenger.observe(commitments.trace.clone());
    if preprocessed_width > 0 {
        challenger.observe(
            preprocessed_commit
                .as_ref()
                .expect("If the width is > 0, then the commit exists.")
                .clone(),
        );
    }
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
            )
            .map(|(domain, values)| (*domain, vec![(zeta, values.clone())]))
            .collect::<Vec<_>>(),
        ),
    ]);

    // Add preprocessed commitment verification if present
    if preprocessed_width > 0 {
        // If preprocessed_width > 0, then preprocessed opened values must be present.
        let opened_prep_local =
            &opened_values
                .preprocessed_local
                .clone()
                .ok_or(GenerationError::InvalidProofShape(
                    "Missing preprocessed local opened values",
                ))?;

        let opened_prep_next =
            &opened_values
                .preprocessed_next
                .clone()
                .ok_or(GenerationError::InvalidProofShape(
                    "Missing preprocessed next opened values",
                ))?;

        coms_to_verify.push((
            preprocessed_commit.unwrap(),
            vec![(
                trace_domain,
                vec![
                    (zeta, opened_prep_local.clone()),
                    (zeta_next, opened_prep_next.clone()),
                ],
            )],
        ));
    }

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

/// Generates the challenges used in the verification of a batch-STARK proof.
pub fn generate_batch_challenges<SC: StarkGenericConfig, A>(
    airs: &[A],
    config: &SC,
    proof: &BatchProof<SC>,
    public_values: &[Vec<Val<SC>>],
    extra_params: Option<&[usize]>,
) -> Result<Vec<SC::Challenge>, GenerationError>
where
    A: Air<SymbolicAirBuilder<Val<SC>>> + for<'a> Air<VerifierConstraintFolder<'a, SC>>,
    SC::Pcs: PcsGeneration<SC, <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>,
{
    debug_assert_eq!(config.is_zk(), 0, "batch recursion assumes non-ZK");
    if SC::Pcs::ZK {
        return Err(GenerationError::InvalidProofShape(
            "batch-STARK challenge generation does not support ZK mode",
        ));
    }

    let BatchProof {
        commitments,
        opened_values,
        opening_proof,
        degree_bits,
    } = proof;

    let n_instances = airs.len();
    if n_instances == 0
        || opened_values.instances.len() != n_instances
        || public_values.len() != n_instances
        || degree_bits.len() != n_instances
    {
        return Err(GenerationError::InvalidProofShape(
            "instance metadata length mismatch",
        ));
    }

    let pcs = config.pcs();
    let mut challenger = config.initialise_challenger();

    observe_base_as_ext::<SC>(&mut challenger, Val::<SC>::from_usize(n_instances));

    for inst in &opened_values.instances {
        if inst
            .quotient_chunks
            .iter()
            .any(|c| c.len() != SC::Challenge::DIMENSION)
        {
            return Err(GenerationError::InvalidProofShape(
                "invalid quotient chunk length",
            ));
        }
    }

    let mut log_quotient_degrees = Vec::with_capacity(n_instances);
    let mut quotient_degrees = Vec::with_capacity(n_instances);
    for (air, pv) in airs.iter().zip(public_values.iter()) {
        let log_qd = get_log_quotient_degree::<Val<SC>, A>(air, 0, pv.len(), config.is_zk());
        let quotient_degree = 1 << (log_qd + config.is_zk());
        log_quotient_degrees.push(log_qd);
        quotient_degrees.push(quotient_degree);
    }

    for i in 0..n_instances {
        let ext_db = degree_bits[i];
        let base_db =
            ext_db
                .checked_sub(config.is_zk())
                .ok_or(GenerationError::InvalidProofShape(
                    "extended degree smaller than zk adjustment",
                ))?;
        observe_instance_binding::<SC>(
            &mut challenger,
            ext_db,
            base_db,
            A::width(&airs[i]),
            quotient_degrees[i],
        );
    }

    challenger.observe(commitments.main.clone());
    for pv in public_values {
        challenger.observe_slice(pv);
    }
    let alpha = challenger.sample_algebra_element();

    challenger.observe(commitments.quotient_chunks.clone());
    let zeta = challenger.sample_algebra_element();

    let ext_trace_domains: Vec<_> = degree_bits
        .iter()
        .map(|&ext_db| pcs.natural_domain_for_degree(1 << ext_db))
        .collect();

    let mut coms_to_verify = Vec::new();

    let trace_round = ext_trace_domains
        .iter()
        .zip(opened_values.instances.iter())
        .map(|(ext_dom, inst)| {
            let zeta_next = ext_dom
                .next_point(zeta)
                .ok_or(GenerationError::InvalidProofShape(
                    "trace domain lacks next point",
                ))?;
            Ok((
                *ext_dom,
                vec![
                    (zeta, inst.trace_local.clone()),
                    (zeta_next, inst.trace_next.clone()),
                ],
            ))
        })
        .collect::<Result<Vec<_>, GenerationError>>()?;
    coms_to_verify.push((commitments.main.clone(), trace_round));

    let quotient_domains: Vec<Vec<_>> = degree_bits
        .iter()
        .zip(ext_trace_domains.iter())
        .zip(log_quotient_degrees.iter())
        .map(|((&ext_db, ext_dom), &log_qd)| {
            let base_db = ext_db - config.is_zk();
            let q_domain = ext_dom.create_disjoint_domain(1 << (base_db + log_qd + config.is_zk()));
            q_domain.split_domains(1 << (log_qd + config.is_zk()))
        })
        .collect();

    let mut quotient_round = Vec::new();
    for (domains, inst) in quotient_domains.iter().zip(opened_values.instances.iter()) {
        if inst.quotient_chunks.len() != domains.len() {
            return Err(GenerationError::InvalidProofShape(
                "quotient chunk count mismatch",
            ));
        }
        for (domain, values) in domains.iter().zip(inst.quotient_chunks.iter()) {
            quotient_round.push((*domain, vec![(zeta, values.clone())]));
        }
    }
    coms_to_verify.push((commitments.quotient_chunks.clone(), quotient_round));

    let pcs_challenges = pcs.generate_challenges(
        config,
        &mut challenger,
        &coms_to_verify,
        opening_proof,
        extra_params,
    )?;

    let mut challenges = Vec::with_capacity(2 + pcs_challenges.len());
    challenges.push(alpha);
    challenges.push(zeta);
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
    Val<SC>: TwoAdicField + PrimeField,
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
            <Self as PcsGeneration<SC, InnerFriProof<SC, InputMmcs, FriMmcs>>>::num_challenges(
                opening_proof,
                None,
            )?;
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

        // Check PoW witness.
        challenger.observe(opening_proof.pow_witness);

        // Sample a challenge as H(transcript || pow_witness). The circuit later
        // verifies that the challenge begins with the required number of leading zeros.
        let rand_f: Val<SC> = challenger.sample();
        let rand_usize = rand_f.as_canonical_biguint().to_u64_digits()[0] as usize;
        challenges.push(SC::Challenge::from_usize(rand_usize));

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
