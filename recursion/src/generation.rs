use alloc::vec;
use alloc::vec::Vec;

use p3_air::Air;
use p3_air::symbolic::AirLayout;
use p3_batch_stark::symbolic::get_log_num_quotient_chunks as get_batch_log_num_quotient_chunks;
use p3_batch_stark::{BatchProof, BatchTranscript, CommonData};
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_commit::{Mmcs, OpenedValues, Pcs, PolynomialSpace};
use p3_field::{Algebra, BasedVectorSpace, PrimeCharacteristicRing, PrimeField, TwoAdicField};
use p3_fri::{BatchMultiOpening, FriProof, HidingFriPcs, TwoAdicFriPcs};
use p3_lookup::logup::LogUpGadget;
use p3_lookup::symbolic::InteractionSymbolicBuilder;
use p3_lookup::{Lookup, LookupProtocol};
use p3_uni_stark::{
    Domain, StarkGenericConfig, SymbolicExpression, SymbolicExpressionExt, Val,
    validate_degree_bits,
};
use thiserror::Error;

use crate::pcs::fri::fri_proof_num_queries;
use crate::traits::RecursiveAir;

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
pub type CommitmentWithOpenings<SC> = (
    <<SC as StarkGenericConfig>::Pcs as Pcs<
        <SC as StarkGenericConfig>::Challenge,
        <SC as StarkGenericConfig>::Challenger,
    >>::Commitment,
    DomainOpenings<SC>,
);

/// The final type alias for a slice of commitments with their openings.
pub type ComsWithOpenings<SC> = [CommitmentWithOpenings<SC>];

/// A STARK verifier's transcript replayed to the point its PCS opening argument begins.
///
/// The two fields are exactly the two arguments
/// [`Pcs::verify`] is called with: the challenger in the state that
/// call enters with, and the commitments the opening argument is checked against. Producing
/// them off-circuit is what lets a witness generator rerun the PCS's own verification steps —
/// FRI's query-index sampling and fold chain, say — for data the proof does not carry.
pub struct OpeningTranscript<SC: StarkGenericConfig> {
    /// The challenger in the state [`Pcs::verify`] is entered with:
    /// every commitment and public value observed, no opened value observed yet.
    pub challenger: SC::Challenger,
    /// The commitments and their opening points, in the order the PCS observes them.
    pub commitments_with_opening_points: Vec<CommitmentWithOpenings<SC>>,
}

/// Observe every opened value, mirroring the loop
/// [`TwoAdicFriPcs::verify`](p3_fri::TwoAdicFriPcs) runs before entering `verify_fri`.
///
/// Advances a challenger from the state [`OpeningTranscript`] holds to the one the FRI verifier
/// itself starts from.
pub fn observe_opened_values<SC: StarkGenericConfig>(
    challenger: &mut SC::Challenger,
    coms_to_verify: &ComsWithOpenings<SC>,
) {
    for (_, round) in coms_to_verify {
        for (_, mat) in round {
            for (_, point) in mat {
                challenger.observe_algebra_slice(point);
            }
        }
    }
}

/// Append a hiding PCS's random-codeword openings onto the public ones, mirroring
/// [`HidingFriPcs::verify`](p3_fri::HidingFriPcs).
///
/// A hiding FRI proof splits every opening in two: the public half travels in the STARK's opened
/// values, the hidden half beside the proof as random codewords. The inner FRI verifier is given
/// the merged openings, so anything replaying its transcript must merge them the same way.
pub fn merge_hiding_random_openings<SC: StarkGenericConfig>(
    coms_to_verify: &mut [CommitmentWithOpenings<SC>],
    random_openings: &OpenedValues<SC::Challenge>,
) -> Result<(), GenerationError> {
    if random_openings.len() != coms_to_verify.len() {
        return Err(GenerationError::InvalidProofShape(
            "hiding random openings do not cover every round",
        ));
    }
    for (round, rand_round) in coms_to_verify.iter_mut().zip(random_openings) {
        if rand_round.len() != round.1.len() {
            return Err(GenerationError::InvalidProofShape(
                "hiding random openings do not cover every matrix",
            ));
        }
        for (mat, rand_mat) in round.1.iter_mut().zip(rand_round) {
            if rand_mat.len() != mat.1.len() {
                return Err(GenerationError::InvalidProofShape(
                    "hiding random openings do not cover every opening point",
                ));
            }
            for (point, rand_point) in mat.1.iter_mut().zip(rand_mat) {
                point.1.extend(rand_point);
            }
        }
    }
    Ok(())
}

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

/// Generates the challenges used in the verification of a batch-STARK proof.
pub fn generate_batch_challenges<SC: StarkGenericConfig, A, LG: LookupProtocol>(
    airs: &[A],
    config: &SC,
    proof: &BatchProof<SC>,
    public_values: &[Vec<Val<SC>>],
    extra_params: Option<&[usize]>,
    common_data: &CommonData<SC>,
    lookup_gadget: &LG,
) -> Result<Vec<SC::Challenge>, GenerationError>
where
    A: Air<InteractionSymbolicBuilder<Val<SC>, SC::Challenge>>,
    SC::Pcs: PcsGeneration<SC, <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    let (mut transcript, mut challenges) = replay_batch_stark_transcript::<SC, A, LG>(
        airs,
        config,
        proof,
        public_values,
        common_data,
        lookup_gadget,
    )?;

    let pcs_challenges = config.pcs().generate_challenges(
        config,
        &mut transcript.challenger,
        &transcript.commitments_with_opening_points,
        &proof.opening_proof,
        extra_params,
    )?;
    challenges.extend(pcs_challenges);

    Ok(challenges)
}

/// Replays a batch-STARK verifier's transcript up to the PCS opening argument.
///
/// Returns the [`OpeningTranscript`] and the challenges sampled along the way, in the order the
/// in-circuit verifier connects them: the lookup permutation challenges, then `alpha`, then
/// `zeta`.
pub fn replay_batch_stark_transcript<SC: StarkGenericConfig, A, LG: LookupProtocol>(
    airs: &[A],
    config: &SC,
    proof: &BatchProof<SC>,
    public_values: &[Vec<Val<SC>>],
    common_data: &CommonData<SC>,
    lookup_gadget: &LG,
) -> Result<(OpeningTranscript<SC>, Vec<SC::Challenge>), GenerationError>
where
    A: Air<InteractionSymbolicBuilder<Val<SC>, SC::Challenge>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    let all_lookups = &common_data.lookups;

    let BatchProof {
        commitments,
        opened_values,
        lookup_terminals,
        degree_bits,
        ..
    } = proof;

    // Single-terminal layout: each AIR commits exactly one terminal iff it declares any lookup.
    all_lookups
        .iter()
        .zip(lookup_terminals)
        .try_for_each(|(lookups, terminal)| {
            if lookups.is_empty() == terminal.is_some() {
                return Err(GenerationError::InvalidProofShape(
                    "Lookup terminal presence does not match the AIR's declared lookups",
                ));
            }
            Ok(())
        })?;

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

    // Check randomization consistency against the PCS ZK setting.
    if (opened_values
        .instances
        .iter()
        .any(|ov| ov.base_opened_values.random.is_some() != SC::Pcs::ZK))
        || (commitments.random.is_some() != SC::Pcs::ZK)
    {
        return Err(GenerationError::RandomizationError);
    }

    let pcs = config.pcs();
    let mut transcript = BatchTranscript::<SC>::new(config.initialise_challenger());

    transcript.observe_instance_count(n_instances);

    for inst in &opened_values.instances {
        if inst
            .base_opened_values
            .quotient_chunks
            .iter()
            .any(|c| c.len() != SC::Challenge::DIMENSION)
        {
            return Err(GenerationError::InvalidProofShape(
                "invalid quotient chunk length",
            ));
        }

        if inst
            .base_opened_values
            .random
            .as_ref()
            .is_some_and(|r_vals| r_vals.len() != SC::Challenge::DIMENSION)
        {
            return Err(GenerationError::RandomizationError);
        }
    }

    let mut preprocessed_widths = Vec::with_capacity(airs.len());
    let mut log_quotient_degrees = Vec::with_capacity(n_instances);
    let mut quotient_degrees = Vec::with_capacity(n_instances);
    for (i, air) in airs.iter().enumerate() {
        let pre_w = common_data
            .preprocessed
            .as_ref()
            .and_then(|g| g.instances[i].as_ref().map(|m| m.width))
            .unwrap_or(0);
        preprocessed_widths.push(pre_w);

        let batch_layout = AirLayout {
            preprocessed_width: pre_w,
            main_width: air.width(),
            num_public_values: air.num_public_values(),
            ..Default::default()
        };
        let base_db = degree_bits[i].checked_sub(config.is_zk()).ok_or(
            GenerationError::InvalidProofShape("extended degree smaller than zk adjustment"),
        )?;
        let log_qd = get_batch_log_num_quotient_chunks(
            air,
            batch_layout,
            1usize << base_db,
            &all_lookups[i],
            config.is_zk(),
            lookup_gadget,
        );
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

        transcript.observe_instance_binding(
            ext_db,
            base_db,
            A::width(&airs[i]),
            quotient_degrees[i],
        );
    }

    transcript.observe_main(&commitments.main, public_values);
    transcript.observe_preprocessed(&preprocessed_widths, common_data.preprocessed.as_ref());

    let is_lookup = commitments.permutation.is_some();

    // Sample the batch's single permutation challenge pair on the transcript challenger. This has
    // the same transcript effect as the native `sample_perm_challenges` (two `sample_algebra_element`
    // draws) while returning the raw pair the in-circuit verifier samples and connects to.
    let different_challenges = get_different_perm_challenges::<SC, LG, _>(
        &mut transcript.challenger,
        all_lookups,
        lookup_gadget,
    );

    // Then, observe the permutation tables, if any and sample the alpha challenge.
    let alpha = transcript
        .observe_perm_and_sample_alpha(commitments.permutation.as_ref(), lookup_terminals);

    transcript.observe_quotient_commitment(&commitments.quotient_chunks);
    if let Some(random_commit) = &commitments.random {
        transcript.observe_random_commitment(random_commit);
    }
    let zeta = transcript.sample_zeta();

    let trace_domains: Vec<_> = degree_bits
        .iter()
        .map(|&ext_db| {
            let base_db =
                ext_db
                    .checked_sub(config.is_zk())
                    .ok_or(GenerationError::InvalidProofShape(
                        "extended degree smaller than zk adjustment",
                    ))?;
            Ok(pcs.natural_domain_for_degree(1 << base_db))
        })
        .collect::<Result<Vec<_>, GenerationError>>()?;
    let ext_trace_domains: Vec<_> = degree_bits
        .iter()
        .map(|&ext_db| pcs.natural_domain_for_degree(1 << ext_db))
        .collect();

    // We have, in the typical lookup case, up to five rounds:
    // optional random, trace, quotient, optional preprocessed, and optional permutation.
    let mut coms_to_verify = Vec::with_capacity(5);

    if let Some(random_commit) = &commitments.random {
        let random_round = ext_trace_domains
            .iter()
            .zip(opened_values.instances.iter())
            .map(|(domain, inst)| {
                let random_vals = inst
                    .base_opened_values
                    .random
                    .as_ref()
                    .ok_or(GenerationError::RandomizationError)?;
                Ok((*domain, vec![(zeta, random_vals.clone())]))
            })
            .collect::<Result<Vec<_>, GenerationError>>()?;
        coms_to_verify.push((random_commit.clone(), random_round));
    }

    let trace_round = ext_trace_domains
        .iter()
        .zip(trace_domains.iter())
        .zip(opened_values.instances.iter())
        .map(|((ext_dom, trace_dom), inst)| {
            // The `zeta_next` opening is present only when the AIR accesses the next row
            // (mirrors the native prover's `main_next_row_columns` gating).
            let mut points = vec![(zeta, inst.base_opened_values.trace_local.clone())];
            if let Some(trace_next) = &inst.base_opened_values.trace_next {
                let zeta_next =
                    trace_dom
                        .next_point(zeta)
                        .ok_or(GenerationError::InvalidProofShape(
                            "trace domain lacks next point",
                        ))?;
                points.push((zeta_next, trace_next.clone()));
            }
            Ok((*ext_dom, points))
        })
        .collect::<Result<Vec<_>, GenerationError>>()?;
    coms_to_verify.push((commitments.main.clone(), trace_round));

    let quotient_domains: Vec<Vec<_>> = degree_bits
        .iter()
        .zip(ext_trace_domains.iter())
        .zip(log_quotient_degrees.iter())
        .map(
            |((&ext_db, ext_dom), &log_qd)| -> Result<Vec<_>, GenerationError> {
                let base_db = ext_db.checked_sub(config.is_zk()).ok_or(
                    GenerationError::InvalidProofShape(
                        "extended degree smaller than zk adjustment",
                    ),
                )?;
                let q_domain =
                    ext_dom.create_disjoint_domain(1 << (base_db + log_qd + config.is_zk()));
                Ok(q_domain.split_domains(1 << (log_qd + config.is_zk())))
            },
        )
        .collect::<Result<Vec<_>, GenerationError>>()?;

    let randomized_quotient_domains: Vec<Vec<_>> = quotient_domains
        .iter()
        .map(|domains| {
            domains
                .iter()
                .map(|domain| pcs.natural_domain_for_degree(domain.size() << config.is_zk()))
                .collect()
        })
        .collect();

    let mut quotient_round = Vec::with_capacity(
        randomized_quotient_domains
            .iter()
            .map(|domains| domains.len())
            .sum(),
    );
    for (domains, inst) in randomized_quotient_domains
        .iter()
        .zip(opened_values.instances.iter())
    {
        if inst.base_opened_values.quotient_chunks.len() != domains.len() {
            return Err(GenerationError::InvalidProofShape(
                "quotient chunk count mismatch",
            ));
        }
        for (domain, values) in domains
            .iter()
            .zip(inst.base_opened_values.quotient_chunks.iter())
        {
            quotient_round.push((*domain, vec![(zeta, values.clone())]));
        }
    }
    coms_to_verify.push((commitments.quotient_chunks.clone(), quotient_round));

    if let Some(global) = &common_data.preprocessed {
        let mut pre_round = Vec::with_capacity(global.matrix_to_instance.len());

        for (matrix_index, &inst_idx) in global.matrix_to_instance.iter().enumerate() {
            let pre_w = preprocessed_widths[inst_idx];
            if pre_w == 0 {
                return Err(GenerationError::InvalidProofShape(
                    "preprocessed width is zero but commitment exists",
                ));
            }

            let inst = &opened_values.instances[inst_idx];
            let local = inst.base_opened_values.preprocessed_local.as_ref().ok_or(
                GenerationError::InvalidProofShape("preprocessed local values should exist"),
            )?;
            let next = inst.base_opened_values.preprocessed_next.as_ref().ok_or(
                GenerationError::InvalidProofShape("preprocessed next values should exist"),
            )?;

            // Validate that the preprocessed data's degree metadata matches this instance.
            let ext_db = degree_bits[inst_idx];

            let meta =
                global.instances[inst_idx]
                    .as_ref()
                    .ok_or(GenerationError::InvalidProofShape(
                        "Missing preprocessed instance metadata",
                    ))?;
            if meta.matrix_index != matrix_index || meta.degree_bits != ext_db {
                return Err(GenerationError::InvalidProofShape(
                    "Preprocessed instance metadata mismatch",
                ));
            }

            let base_db = meta.degree_bits;
            let pre_domain = pcs.natural_domain_for_degree(1 << base_db);
            let zeta_next_i = trace_domains[inst_idx].next_point(zeta).ok_or(
                GenerationError::InvalidProofShape("Preprocessed domain lacks next point"),
            )?;

            pre_round.push((
                pre_domain,
                vec![(zeta, local.clone()), (zeta_next_i, next.clone())],
            ));
        }

        coms_to_verify.push((global.commitment.clone(), pre_round));
    }

    if is_lookup {
        let permutation_commit = commitments.permutation.clone().unwrap();
        let mut permutation_round = Vec::with_capacity(ext_trace_domains.len());
        for (i, (ext_dom, inst_opened_vals)) in ext_trace_domains
            .iter()
            .zip(opened_values.instances.iter())
            .enumerate()
        {
            if inst_opened_vals.permutation_local.len() != inst_opened_vals.permutation_next.len() {
                return Err(GenerationError::InvalidProofShape(
                    "Permutation opened values length mismatch",
                ));
            }
            if !inst_opened_vals.permutation_local.is_empty() {
                let zeta_next =
                    trace_domains[i]
                        .next_point(zeta)
                        .ok_or(GenerationError::InvalidProofShape(
                            "Missing preprocessed instance metadata",
                        ))?;
                permutation_round.push((
                    *ext_dom,
                    vec![
                        (zeta, inst_opened_vals.permutation_local.clone()),
                        (zeta_next, inst_opened_vals.permutation_next.clone()),
                    ],
                ));
            }
        }
        coms_to_verify.push((permutation_commit, permutation_round));
    }

    let mut challenges = Vec::with_capacity(2 + different_challenges.len());
    challenges.extend(different_challenges);
    challenges.push(alpha);
    challenges.push(zeta);

    Ok((
        OpeningTranscript {
            challenger: transcript.challenger,
            commitments_with_opening_points: coms_to_verify,
        },
        challenges,
    ))
}

/// Replays a single-instance (uni-STARK) verifier's transcript up to the PCS opening argument.
///
/// The observation order mirrors [`p3_uni_stark::verify`], and the shape the transcript binds —
/// the preprocessed width, the quotient-chunk count, and which openings each commitment carries —
/// is derived exactly as [`verify_p3_uni_proof_circuit`](crate::verify_p3_uni_proof_circuit)
/// derives it, so the replayed transcript is the one the recursive verifier reproduces in-circuit.
pub fn replay_uni_stark_transcript<SC: StarkGenericConfig, A>(
    config: &SC,
    air: &A,
    proof: &p3_uni_stark::Proof<SC>,
    public_values: &[Val<SC>],
    preprocessed_commit: Option<&<SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment>,
) -> Result<OpeningTranscript<SC>, GenerationError>
where
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SymbolicExpression<Val<SC>>>,
{
    let pcs = config.pcs();
    let is_zk = config.is_zk();
    let degree_bits = proof.degree_bits;
    validate_degree_bits(None, degree_bits, is_zk, pcs.log_max_lde_height())
        .map_err(|_| GenerationError::InvalidProofShape("invalid degree bits"))?;

    let commitments = &proof.commitments;
    let opened_values = &proof.opened_values;

    // The recursive verifier reads the preprocessed width off the opened values rather than off a
    // verifier key, so the transcript binding must be read the same way here.
    let preprocessed_width = opened_values
        .preprocessed_local
        .as_ref()
        .map_or(0, |v| v.len());
    if (preprocessed_width > 0) != preprocessed_commit.is_some() {
        return Err(GenerationError::InvalidProofShape(
            "preprocessed commitment presence does not match the opened preprocessed width",
        ));
    }

    let degree = 1usize << degree_bits;
    let base_degree = degree >> is_zk;
    let trace_domain = pcs.natural_domain_for_degree(degree);
    let init_trace_domain = pcs.natural_domain_for_degree(base_degree);

    // Lookups are not supported for recursive single-STARK verification, so the quotient degree is
    // derived with empty lookup contexts — matching the in-circuit verifier.
    let log_quotient_degree =
        air.get_log_num_quotient_chunks(preprocessed_width, base_degree, &[], is_zk, &LogUpGadget);
    let quotient_degree = 1 << (log_quotient_degree + is_zk);
    let quotient_domain =
        trace_domain.create_disjoint_domain(1 << (degree_bits + log_quotient_degree));
    let randomized_quotient_chunks_domains: Vec<_> = quotient_domain
        .split_domains(quotient_degree)
        .iter()
        .map(|domain| pcs.natural_domain_for_degree(domain.size() << is_zk))
        .collect();

    let mut challenger = config.initialise_challenger();
    challenger.observe(Val::<SC>::from_usize(degree_bits));
    challenger.observe(Val::<SC>::from_usize(degree_bits - is_zk));
    challenger.observe(Val::<SC>::from_usize(preprocessed_width));
    challenger.observe(commitments.trace.clone());
    if let Some(prep_commit) = preprocessed_commit
        && preprocessed_width > 0
    {
        challenger.observe(prep_commit.clone());
    }
    challenger.observe_slice(public_values);

    let _alpha: SC::Challenge = challenger.sample_algebra_element();
    challenger.observe(commitments.quotient_chunks.clone());
    if let Some(random_commit) = commitments.random.clone() {
        challenger.observe(random_commit);
    }
    let zeta: SC::Challenge = challenger.sample_algebra_element();
    let zeta_next =
        init_trace_domain
            .next_point(zeta)
            .ok_or(GenerationError::InvalidProofShape(
                "trace domain lacks next point",
            ))?;

    let mut coms_to_verify = if let Some(random_commit) = &commitments.random {
        let random_values = opened_values
            .random
            .as_ref()
            .ok_or(GenerationError::RandomizationError)?;
        vec![(
            random_commit.clone(),
            vec![(trace_domain, vec![(zeta, random_values.clone())])],
        )]
    } else {
        vec![]
    };

    let mut trace_points = vec![(zeta, opened_values.trace_local.clone())];
    // The `zeta_next` opening is present only when the AIR accesses the next row.
    if air.opens_trace_next() {
        let trace_next =
            opened_values
                .trace_next
                .as_ref()
                .ok_or(GenerationError::InvalidProofShape(
                    "AIR opens the next trace row but the proof carries no such opening",
                ))?;
        trace_points.push((zeta_next, trace_next.clone()));
    }
    coms_to_verify.push((
        commitments.trace.clone(),
        vec![(trace_domain, trace_points)],
    ));

    if randomized_quotient_chunks_domains.len() != opened_values.quotient_chunks.len() {
        return Err(GenerationError::InvalidProofShape(
            "quotient chunk count mismatch",
        ));
    }
    coms_to_verify.push((
        commitments.quotient_chunks.clone(),
        randomized_quotient_chunks_domains
            .iter()
            .zip(&opened_values.quotient_chunks)
            .map(|(domain, values)| (*domain, vec![(zeta, values.clone())]))
            .collect(),
    ));

    if preprocessed_width > 0 {
        let local =
            opened_values
                .preprocessed_local
                .as_ref()
                .ok_or(GenerationError::InvalidProofShape(
                    "preprocessed local values should exist",
                ))?;
        let next =
            opened_values
                .preprocessed_next
                .as_ref()
                .ok_or(GenerationError::InvalidProofShape(
                    "preprocessed next values should exist",
                ))?;
        coms_to_verify.push((
            preprocessed_commit
                .expect("presence checked against the preprocessed width above")
                .clone(),
            vec![(
                trace_domain,
                vec![(zeta, local.clone()), (zeta_next, next.clone())],
            )],
        ));
    }

    Ok(OpeningTranscript {
        challenger,
        commitments_with_opening_points: coms_to_verify,
    })
}

type InnerFriProof<SC, InputMmcs, FriMmcs> = FriProof<
    <SC as StarkGenericConfig>::Challenge,
    FriMmcs,
    Val<SC>,
    Vec<BatchMultiOpening<Val<SC>, InputMmcs>>,
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
        opening_proof
            .commit_phase_commits
            .iter()
            .zip(&opening_proof.commit_pow_witnesses)
            .for_each(|(comm, pow_witness)| {
                // To match with the prover (and for security purposes),
                // we observe the commitment before sampling the challenge.
                challenger.observe(comm.clone());
                challenger.observe(*pow_witness);
                // Sample a challenge as H(transcript || pow_witness). The circuit later
                // verifies that the challenge begins with the required number of leading zeros.
                let rand_f: Val<SC> = challenger.sample();
                let rand_usize = rand_f.as_canonical_biguint().to_u64_digits()[0] as usize;
                challenges.push(SC::Challenge::from_usize(rand_usize));

                challenges.push(challenger.sample_algebra_element());
            });

        // Observe all coefficients of the final polynomial.
        opening_proof
            .final_poly
            .iter()
            .for_each(|x| challenger.observe_algebra_element(*x));

        // Bind the variable-arity schedule into the transcript before query grinding,
        // matching the native FRI verifier in Plonky3.
        for step in &opening_proof.commit_phase_openings {
            challenger.observe(Val::<SC>::from_usize(step.log_arity as usize));
        }

        let params = extra_params.ok_or(GenerationError::MissingParameterError)?;

        if params.len() != 2 {
            return Err(GenerationError::InvalidParameterCount(params.len(), 2));
        }

        // Check PoW witness.
        challenger.observe(opening_proof.query_pow_witness);

        // Sample a challenge as H(transcript || pow_witness). The circuit later
        // verifies that the challenge begins with the required number of leading zeros.
        let rand_f: Val<SC> = challenger.sample();
        let rand_usize = rand_f.as_canonical_biguint().to_u64_digits()[0] as usize;
        challenges.push(SC::Challenge::from_usize(rand_usize));

        let log_height_max = params[1];
        let log_global_max_height = opening_proof.commit_phase_commits.len() + log_height_max;
        for _ in 0..fri_proof_num_queries(opening_proof) {
            // For each query, we start by generating the random index.
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
            1 + opening_proof.commit_phase_commits.len() + fri_proof_num_queries(opening_proof);

        Ok(num_challenges)
    }
}

type HidingInnerFriProof<SC, InputMmcs, FriMmcs> = (
    OpenedValues<<SC as StarkGenericConfig>::Challenge>,
    InnerFriProof<SC, InputMmcs, FriMmcs>,
);

impl<SC: StarkGenericConfig, Dft, InputMmcs: Mmcs<Val<SC>>, FriMmcs: Mmcs<SC::Challenge>, R>
    PcsGeneration<SC, HidingInnerFriProof<SC, InputMmcs, FriMmcs>>
    for HidingFriPcs<Val<SC>, Dft, InputMmcs, FriMmcs, R>
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
        opening_proof: &HidingInnerFriProof<SC, InputMmcs, FriMmcs>,
        extra_params: Option<&[usize]>,
    ) -> Result<Vec<SC::Challenge>, GenerationError> {
        let inner_proof = &opening_proof.1;
        let num_challenges = <Self as PcsGeneration<
            SC,
            HidingInnerFriProof<SC, InputMmcs, FriMmcs>,
        >>::num_challenges(opening_proof, None)?;
        let mut challenges = Vec::with_capacity(num_challenges);

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

        inner_proof
            .commit_phase_commits
            .iter()
            .zip(&inner_proof.commit_pow_witnesses)
            .for_each(|(comm, pow_witness)| {
                challenger.observe(comm.clone());
                challenger.observe(*pow_witness);
                let rand_f: Val<SC> = challenger.sample();
                let rand_usize = rand_f.as_canonical_biguint().to_u64_digits()[0] as usize;
                challenges.push(SC::Challenge::from_usize(rand_usize));
                challenges.push(challenger.sample_algebra_element());
            });

        inner_proof
            .final_poly
            .iter()
            .for_each(|x| challenger.observe_algebra_element(*x));

        for step in &inner_proof.commit_phase_openings {
            challenger.observe(Val::<SC>::from_usize(step.log_arity as usize));
        }

        let params = extra_params.ok_or(GenerationError::MissingParameterError)?;
        if params.len() != 2 {
            return Err(GenerationError::InvalidParameterCount(params.len(), 2));
        }

        challenger.observe(inner_proof.query_pow_witness);
        let rand_f: Val<SC> = challenger.sample();
        let rand_usize = rand_f.as_canonical_biguint().to_u64_digits()[0] as usize;
        challenges.push(SC::Challenge::from_usize(rand_usize));

        let log_height_max = params[1];
        let log_global_max_height = inner_proof.commit_phase_commits.len() + log_height_max;
        for _ in 0..fri_proof_num_queries(inner_proof) {
            challenges.push(SC::Challenge::from_usize(
                challenger.sample_bits(log_global_max_height),
            ));
        }

        Ok(challenges)
    }

    fn num_challenges(
        opening_proof: &HidingInnerFriProof<SC, InputMmcs, FriMmcs>,
        _extra_params: Option<&[usize]>,
    ) -> Result<usize, GenerationError> {
        let inner_proof = &opening_proof.1;
        Ok(1 + inner_proof.commit_phase_commits.len() + fri_proof_num_queries(inner_proof))
    }
}

/// Samples the batch's single permutation challenge pair on the transcript challenger and returns
/// it, so the generated challenge public values stay in the sampling order the in-circuit verifier
/// reproduces. Returns an empty vector when no AIR declares a lookup (no pair is drawn), matching
/// the native `sample_perm_challenges`.
pub fn get_different_perm_challenges<SC, LG, L>(
    challenger: &mut SC::Challenger,
    all_lookups: &[L],
    lookup_gadget: &LG,
) -> Vec<SC::Challenge>
where
    SC: StarkGenericConfig,
    LG: LookupProtocol,
    L: AsRef<[Lookup<Val<SC>>]>,
{
    assert_eq!(
        lookup_gadget.num_challenges(),
        2,
        "single-pair bus-prefix challenge layout requires exactly two challenges per lookup"
    );

    if !all_lookups
        .iter()
        .any(|contexts| !contexts.as_ref().is_empty())
    {
        return Vec::new();
    }

    let alpha = challenger.sample_algebra_element::<SC::Challenge>();
    let beta = challenger.sample_algebra_element::<SC::Challenge>();
    vec![alpha, beta]
}
