use alloc::vec;
use alloc::vec::Vec;

use p3_air::Air;
use p3_air::symbolic::AirLayout;
use p3_batch_stark::symbolic::get_log_num_quotient_chunks as get_batch_log_num_quotient_chunks;
use p3_batch_stark::{BatchProof, BatchShape, CommonData};
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_commit::{Mmcs, OpenedValues, Pcs, PolynomialSpace, UnivariateStarkPcs};
use p3_field::{Algebra, BasedVectorSpace, PrimeCharacteristicRing, PrimeField, TwoAdicField};
use p3_fri::{BatchMultiOpening, FriProof, FriShape, HidingFriPcs, PcsShape, TwoAdicFriPcs};
use p3_lookup::logup::LogUpGadget;
use p3_lookup::symbolic::InteractionSymbolicBuilder;
use p3_lookup::{Lookup, LookupProtocol};
use p3_uni_stark::{
    Domain, StarkGenericConfig, SymbolicExpression, SymbolicExpressionExt, Val,
    validate_degree_bits,
};
use thiserror::Error;

use crate::input_contract::stark_layout::{
    CommitmentRole, InstanceLayout, MatrixRoute, NativeStarkLayout, validate_preprocessed_metadata,
};
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

/// Seed the FRI PCS transcript and observe every opened value, mirroring what
/// [`TwoAdicFriPcs::verify`](p3_fri::TwoAdicFriPcs) does before its batch phase.
///
/// Advances a challenger from the state [`OpeningTranscript`] holds to the one the PCS batch
/// phase (the batch grind, then `alpha`) starts from. `batch_pow_bits` is the native
/// `FriParameters::batch_proof_of_work_bits`; it is bound into the PCS domain separator.
pub fn observe_opened_values<SC: StarkGenericConfig>(
    challenger: &mut SC::Challenger,
    coms_to_verify: &ComsWithOpenings<SC>,
    batch_pow_bits: usize,
) {
    fri_pcs_shape::<SC>(coms_to_verify, batch_pow_bits)
        .domain_separator::<Val<SC>, SC::Challenge>()
        .seed(challenger);
    for (_, round) in coms_to_verify {
        for (_, mat) in round {
            for (_, point) in mat {
                challenger.observe_algebra_slice(point);
            }
        }
    }
}

/// Absorb a PCS commitment, disambiguating from the base-field `observe` a grinding challenger
/// also offers.
fn observe_commitment<SC: StarkGenericConfig>(
    challenger: &mut SC::Challenger,
    commitment: &<SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
) {
    CanObserve::observe(challenger, commitment.clone());
}

/// The FRI PCS transcript shape for a set of claims: one evaluation count per opening point.
pub fn fri_pcs_shape<SC: StarkGenericConfig>(
    coms_to_verify: &ComsWithOpenings<SC>,
    batch_pow_bits: usize,
) -> PcsShape {
    PcsShape {
        claimed_evaluation_counts: coms_to_verify
            .iter()
            .map(|(_, round)| {
                round
                    .iter()
                    .map(|(_, points)| points.iter().map(|(_, values)| values.len()).collect())
                    .collect()
            })
            .collect(),
        batch_pow_bits,
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
    SC::Challenger: GrindingChallenger<Witness = Val<SC>>,
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
    SC::Challenger: GrindingChallenger<Witness = Val<SC>>,
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
        lookup_pow_witness,
        ood_pow_witness,
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

    if let Some(global) = &common_data.preprocessed {
        let metadata = global
            .instances
            .iter()
            .map(|entry| {
                entry
                    .as_ref()
                    .map(|meta| (meta.matrix_index, meta.width, meta.degree_bits))
            })
            .collect::<Vec<_>>();
        validate_preprocessed_metadata(&metadata, &global.matrix_to_instance, degree_bits)
            .map_err(|_| GenerationError::InvalidProofShape("invalid preprocessed metadata"))?;
    }

    let pcs = config.pcs();

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

    let is_lookup = commitments.permutation.is_some();

    let permutation_widths: Vec<usize> = all_lookups
        .iter()
        .map(|lookups| {
            if lookups.is_empty() {
                Ok(0)
            } else {
                lookups
                    .len()
                    .checked_add(1)
                    .and_then(|width| width.checked_mul(SC::Challenge::DIMENSION))
                    .ok_or(GenerationError::InvalidProofShape(
                        "packed permutation width overflows",
                    ))
            }
        })
        .collect::<Result<_, _>>()?;

    let layout_instances: Vec<InstanceLayout> = airs
        .iter()
        .zip(degree_bits.iter().zip(log_quotient_degrees.iter()))
        .enumerate()
        .map(|(i, (air, (&ext_log, &quotient_log)))| InstanceLayout {
            ext_log,
            base_log: ext_log - config.is_zk(),
            challenge_width: SC::Challenge::DIMENSION,
            trace_width: air.width(),
            trace_next: !p3_air::BaseAir::<Val<SC>>::main_next_row_columns(air).is_empty(),
            pre_width: preprocessed_widths[i],
            pre_next: !p3_air::BaseAir::<Val<SC>>::preprocessed_next_row_columns(air).is_empty(),
            quotient_log,
            quotient_chunks: quotient_degrees[i],
            permutation_width: permutation_widths[i],
        })
        .collect();

    for (i, instance) in opened_values.instances.iter().enumerate() {
        let expected_permutation_width = layout_instances[i].permutation_width;
        if instance.permutation_local.len() != expected_permutation_width
            || instance.permutation_next.len() != expected_permutation_width
        {
            return Err(GenerationError::InvalidProofShape(
                "permutation opening width does not match packed lookup metadata",
            ));
        }
    }
    let preprocessed_order = common_data
        .preprocessed
        .as_ref()
        .map_or(&[][..], |global| global.matrix_to_instance.as_slice());
    let layout = NativeStarkLayout::new(
        layout_instances,
        preprocessed_order,
        commitments.random.is_some(),
        common_data.preprocessed.is_some(),
        is_lookup,
    )
    .map_err(|_| GenerationError::InvalidProofShape("invalid STARK opening layout"))?;

    for (i, instance) in opened_values.instances.iter().enumerate() {
        let shape = layout.instances[i];
        let pre_local_len = instance
            .base_opened_values
            .preprocessed_local()
            .map_or(0, <[_]>::len);
        let pre_next_len = instance
            .base_opened_values
            .preprocessed_next()
            .map_or(0, <[_]>::len);
        let trace_next_len = instance
            .base_opened_values
            .trace_next
            .as_ref()
            .map_or(0, Vec::len);
        if instance.base_opened_values.trace_local.len() != shape.trace_width
            || trace_next_len != shape.trace_width * usize::from(shape.trace_next)
            || pre_local_len != shape.pre_width
            || pre_next_len != shape.pre_width * usize::from(shape.pre_next)
            || instance.base_opened_values.quotient_chunks.len() != shape.quotient_chunks
        {
            return Err(GenerationError::InvalidProofShape(
                "opened value widths do not match the validated STARK layout",
            ));
        }
    }

    // Replay `p3_batch_stark::verify_batch`'s transcript step for step: the domain-separator seed
    // of the batch shape, the instance heights, the main and preprocessed commitments, the lookup
    // phase, the permutation phase, the quotient phase and the out-of-domain phase.
    let num_lookup_instances = all_lookups.iter().filter(|c| !c.is_empty()).count();
    if (num_lookup_instances > 0) != is_lookup {
        return Err(GenerationError::InvalidProofShape(
            "permutation commitment presence does not match the declared lookups",
        ));
    }
    let shape = BatchShape {
        trace_widths: airs.iter().map(|air| air.width()).collect(),
        public_value_counts: airs.iter().map(|air| air.num_public_values()).collect(),
        preprocessed_widths: preprocessed_widths.clone(),
        has_preprocessed_commitment: common_data.preprocessed.is_some(),
        num_lookup_instances,
        lookup_pow_bits: config.lookup_proof_of_work_bits(),
        has_randomization_commitment: SC::Pcs::ZK,
        ood_pow_bits: config.ood_proof_of_work_bits(),
    };
    let mut challenger = config.initialise_challenger();
    shape
        .domain_separator::<Val<SC>, SC::Challenge>()
        .seed(&mut challenger);
    for &bits in degree_bits {
        challenger.observe_algebra_element(SC::Challenge::from(Val::<SC>::from_usize(bits)));
    }
    observe_commitment::<SC>(&mut challenger, &commitments.main);
    for values in public_values {
        challenger.observe_slice(values);
    }
    if let Some(global) = &common_data.preprocessed {
        observe_commitment::<SC>(&mut challenger, &global.commitment);
    }

    // The lookup phase grinds before its challenges; a zero difficulty absorbs nothing.
    if is_lookup {
        let witness = lookup_pow_witness.ok_or(GenerationError::InvalidPowWitness)?;
        if !challenger.check_witness(config.lookup_proof_of_work_bits(), witness) {
            return Err(GenerationError::InvalidPowWitness);
        }
    }
    let different_challenges =
        get_different_perm_challenges::<SC, LG, _>(&mut challenger, all_lookups, lookup_gadget);

    if let Some(permutation) = &commitments.permutation {
        observe_commitment::<SC>(&mut challenger, &permutation);
    }
    for terminal in lookup_terminals.iter().flatten() {
        challenger.observe_algebra_element(terminal.0);
    }
    let alpha: SC::Challenge = challenger.sample_algebra_element();

    observe_commitment::<SC>(&mut challenger, &commitments.quotient_chunks);
    if let Some(random_commit) = &commitments.random {
        observe_commitment::<SC>(&mut challenger, &random_commit);
    }
    if !challenger.check_witness(config.ood_proof_of_work_bits(), *ood_pow_witness) {
        return Err(GenerationError::InvalidPowWitness);
    }
    let zeta: SC::Challenge = challenger.sample_algebra_element();

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
        let random_round = layout
            .matrices(CommitmentRole::Random)
            .map(|matrix| {
                let MatrixRoute::Random { instance } = matrix.route else {
                    unreachable!("random planner emits only random routes")
                };
                let random_vals = opened_values.instances[instance]
                    .base_opened_values
                    .random
                    .as_ref()
                    .ok_or(GenerationError::RandomizationError)?;
                Ok((
                    ext_trace_domains[instance],
                    vec![(zeta, random_vals.clone())],
                ))
            })
            .collect::<Result<Vec<_>, GenerationError>>()?;
        coms_to_verify.push((random_commit.clone(), random_round));
    }

    let trace_round = layout
        .matrices(CommitmentRole::Trace)
        .map(|matrix| {
            let MatrixRoute::Trace { instance } = matrix.route else {
                unreachable!("trace planner emits only trace routes")
            };
            let inst = &opened_values.instances[instance];
            let mut points = vec![(zeta, inst.base_opened_values.trace_local.clone())];
            if matrix.point_count == 2 {
                let trace_next = inst.base_opened_values.trace_next.as_ref().ok_or(
                    GenerationError::InvalidProofShape(
                        "AIR opens the next trace row but the proof carries no such opening",
                    ),
                )?;
                let zeta_next = trace_domains[instance].next_point(zeta).ok_or(
                    GenerationError::InvalidProofShape("trace domain lacks next point"),
                )?;
                points.push((zeta_next, trace_next.clone()));
            }
            Ok((ext_trace_domains[instance], points))
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

    let mut quotient_round =
        Vec::with_capacity(layout.instances.iter().map(|i| i.quotient_chunks).sum());
    for matrix in layout.matrices(CommitmentRole::Quotient) {
        let MatrixRoute::Quotient { instance, chunk } = matrix.route else {
            unreachable!("quotient planner emits only quotient routes")
        };
        let domains = &randomized_quotient_domains[instance];
        let values = opened_values.instances[instance]
            .base_opened_values
            .quotient_chunks
            .get(chunk)
            .ok_or(GenerationError::InvalidProofShape(
                "quotient chunk count mismatch",
            ))?;
        let domain = domains
            .get(chunk)
            .ok_or(GenerationError::InvalidProofShape(
                "quotient chunk count mismatch",
            ))?;
        quotient_round.push((*domain, vec![(zeta, values.clone())]));
    }
    coms_to_verify.push((commitments.quotient_chunks.clone(), quotient_round));

    if let Some(global) = &common_data.preprocessed {
        let mut pre_round = Vec::with_capacity(global.matrix_to_instance.len());

        for matrix in layout.matrices(CommitmentRole::Preprocessed) {
            let MatrixRoute::Preprocessed {
                instance: inst_idx,
                matrix: matrix_index,
            } = matrix.route
            else {
                unreachable!("preprocessed planner emits only preprocessed routes")
            };
            let pre_w = preprocessed_widths[inst_idx];
            if pre_w == 0 {
                return Err(GenerationError::InvalidProofShape(
                    "preprocessed width is zero but commitment exists",
                ));
            }

            let inst = &opened_values.instances[inst_idx];
            let ext_db = degree_bits[inst_idx];
            let base_db = ext_db;
            let pre_domain = pcs.natural_domain_for_degree(1 << base_db);
            let zeta_next_i = trace_domains[inst_idx].next_point(zeta).ok_or(
                GenerationError::InvalidProofShape("Preprocessed domain lacks next point"),
            )?;
            let local = inst.base_opened_values.preprocessed_local().ok_or(
                GenerationError::InvalidProofShape("preprocessed local values should exist"),
            )?;
            let mut points = vec![(zeta, local.to_vec())];
            if !p3_air::BaseAir::<Val<SC>>::preprocessed_next_row_columns(&airs[inst_idx])
                .is_empty()
            {
                let next = inst.base_opened_values.preprocessed_next().ok_or(
                    GenerationError::InvalidProofShape("preprocessed next values should exist"),
                )?;
                points.push((zeta_next_i, next.to_vec()));
            }

            // Validate that the preprocessed data's degree metadata matches this instance.
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

            pre_round.push((pre_domain, points));
        }

        coms_to_verify.push((global.commitment.clone(), pre_round));
    }

    if is_lookup {
        let permutation_commit = commitments.permutation.clone().unwrap();
        let mut permutation_round = Vec::with_capacity(layout.instances.len());
        for matrix in layout.matrices(CommitmentRole::Permutation) {
            let MatrixRoute::Permutation { instance } = matrix.route else {
                unreachable!("permutation planner emits only permutation routes")
            };
            let inst_opened_vals = &opened_values.instances[instance];
            let zeta_next = trace_domains[instance].next_point(zeta).ok_or(
                GenerationError::InvalidProofShape("permutation domain lacks next point"),
            )?;
            permutation_round.push((
                ext_trace_domains[instance],
                vec![
                    (zeta, inst_opened_vals.permutation_local.clone()),
                    (zeta_next, inst_opened_vals.permutation_next.clone()),
                ],
            ));
        }
        coms_to_verify.push((permutation_commit, permutation_round));
    }

    let mut challenges = Vec::with_capacity(2 + different_challenges.len());
    challenges.extend(different_challenges);
    challenges.push(alpha);
    challenges.push(zeta);

    Ok((
        OpeningTranscript {
            challenger,
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
    SC::Challenger: GrindingChallenger<Witness = Val<SC>>,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SymbolicExpression<Val<SC>>>,
{
    let pcs = config.pcs();
    let is_zk = config.is_zk();
    let degree_bits = proof.degree_bits;
    validate_degree_bits(
        None,
        degree_bits,
        is_zk,
        pcs.log_min_trace_height(),
        pcs.log_max_trace_height(),
    )
    .map_err(|_| GenerationError::InvalidProofShape("invalid degree bits"))?;

    let commitments = &proof.commitments;
    let opened_values = &proof.opened_values;

    // The recursive verifier reads the preprocessed width off the opened values rather than off a
    // verifier key, so the transcript binding must be read the same way here.
    let preprocessed_width = opened_values.preprocessed_local().map_or(0, |v| v.len());
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

    let layout = NativeStarkLayout::new(
        vec![InstanceLayout {
            ext_log: degree_bits,
            base_log: degree_bits
                .checked_sub(is_zk)
                .ok_or(GenerationError::InvalidProofShape(
                    "extended degree smaller than zk adjustment",
                ))?,
            challenge_width: SC::Challenge::DIMENSION,
            trace_width: air.width(),
            trace_next: air.opens_trace_next(),
            pre_width: preprocessed_width,
            pre_next: air.opens_preprocessed_next(),
            quotient_log: log_quotient_degree,
            quotient_chunks: quotient_degree,
            permutation_width: 0,
        }],
        if preprocessed_width > 0 { &[0] } else { &[] },
        commitments.random.is_some(),
        preprocessed_width > 0,
        false,
    )
    .map_err(|_| GenerationError::InvalidProofShape("invalid STARK opening layout"))?;

    if opened_values.trace_local.len() != air.width()
        || opened_values.trace_next.as_ref().map_or(0, Vec::len)
            != usize::from(air.opens_trace_next()) * air.width()
        || opened_values.quotient_chunks.len() != quotient_degree
    {
        return Err(GenerationError::InvalidProofShape(
            "opened value widths do not match the validated STARK layout",
        ));
    }

    // Replay `p3_uni_stark::verify`'s transcript: the domain-separator seed of the STARK shape,
    // the constraint phase, then the out-of-domain phase.
    let mut challenger = config.initialise_challenger();
    crate::transcript::uni_stark_shape(
        air,
        preprocessed_width,
        public_values.len(),
        degree_bits,
        degree_bits - is_zk,
        quotient_degree,
        SC::Pcs::ZK,
        config.ood_proof_of_work_bits(),
    )
    .domain_separator::<Val<SC>, SC::Challenge>()
    .seed(&mut challenger);
    observe_commitment::<SC>(&mut challenger, &commitments.trace);
    if let Some(prep_commit) = preprocessed_commit
        && preprocessed_width > 0
    {
        observe_commitment::<SC>(&mut challenger, &prep_commit);
    }
    challenger.observe_slice(public_values);

    let _alpha: SC::Challenge = challenger.sample_algebra_element();
    observe_commitment::<SC>(&mut challenger, &commitments.quotient_chunks);
    if let Some(random_commit) = commitments.random.clone() {
        observe_commitment::<SC>(&mut challenger, &random_commit);
    }
    if !challenger.check_witness(config.ood_proof_of_work_bits(), proof.ood_pow_witness) {
        return Err(GenerationError::InvalidPowWitness);
    }
    let zeta: SC::Challenge = challenger.sample_algebra_element();
    let zeta_next =
        init_trace_domain
            .next_point(zeta)
            .ok_or(GenerationError::InvalidProofShape(
                "trace domain lacks next point",
            ))?;

    let mut coms_to_verify = Vec::with_capacity(layout.commitment_count());
    for matrix in layout.matrices(CommitmentRole::Random) {
        let MatrixRoute::Random { .. } = matrix.route else {
            unreachable!("random planner emits only random routes")
        };
        let random_values = opened_values
            .random
            .as_ref()
            .ok_or(GenerationError::RandomizationError)?;
        coms_to_verify.push((
            commitments
                .random
                .clone()
                .ok_or(GenerationError::RandomizationError)?,
            vec![(trace_domain, vec![(zeta, random_values.clone())])],
        ));
    }

    let mut trace_points = vec![(zeta, opened_values.trace_local.clone())];
    if layout
        .matrices(CommitmentRole::Trace)
        .next()
        .is_some_and(|m| m.point_count == 2)
    {
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
    let quotient_points = layout
        .matrices(CommitmentRole::Quotient)
        .map(|matrix| {
            let MatrixRoute::Quotient { chunk, .. } = matrix.route else {
                unreachable!("quotient planner emits only quotient routes")
            };
            (
                randomized_quotient_chunks_domains[chunk],
                vec![(zeta, opened_values.quotient_chunks[chunk].clone())],
            )
        })
        .collect();
    coms_to_verify.push((commitments.quotient_chunks.clone(), quotient_points));

    if preprocessed_width > 0 {
        let local =
            opened_values
                .preprocessed_local()
                .ok_or(GenerationError::InvalidProofShape(
                    "preprocessed local values should exist",
                ))?;
        let mut points = vec![(zeta, local.to_vec())];
        if layout
            .matrices(CommitmentRole::Preprocessed)
            .next()
            .is_some_and(|matrix| matrix.point_count == 2)
        {
            let next =
                opened_values
                    .preprocessed_next()
                    .ok_or(GenerationError::InvalidProofShape(
                        "preprocessed next values should exist",
                    ))?;
            points.push((zeta_next, next.to_vec()));
        }
        coms_to_verify.push((
            preprocessed_commit
                .ok_or(GenerationError::InvalidProofShape(
                    "preprocessed commitment missing",
                ))?
                .clone(),
            vec![(trace_domain, points)],
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
        generate_fri_challenges::<SC, InputMmcs, FriMmcs>(
            challenger,
            coms_to_verify,
            opening_proof,
            extra_params,
        )
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
        let (random_openings, inner_proof) = opening_proof;
        let mut merged = coms_to_verify.to_vec();
        merge_hiding_random_openings::<SC>(&mut merged, random_openings)?;
        generate_fri_challenges::<SC, InputMmcs, FriMmcs>(
            challenger,
            &merged,
            inner_proof,
            extra_params,
        )
    }

    fn num_challenges(
        opening_proof: &HidingInnerFriProof<SC, InputMmcs, FriMmcs>,
        _extra_params: Option<&[usize]>,
    ) -> Result<usize, GenerationError> {
        let inner_proof = &opening_proof.1;
        Ok(1 + inner_proof.commit_phase_commits.len() + fri_proof_num_queries(inner_proof))
    }
}

/// Replay the FRI PCS transcript (0.8 layout) from the state [`OpeningTranscript`] holds.
///
/// `extra_params` is `[log_blowup, log_final_poly_len, max_log_arity, commit_pow_bits,
/// query_pow_bits, batch_pow_bits]`: the native `FriParameters` scalars the PCS and FRI domain
/// separators bind. The returned challenges are `alpha`, then per commit round the round's grind
/// sample (zero at zero difficulty) and `beta`, then the query grind sample, then one index per
/// query.
fn generate_fri_challenges<SC, InputMmcs, FriMmcs>(
    challenger: &mut SC::Challenger,
    coms_to_verify: &ComsWithOpenings<SC>,
    opening_proof: &InnerFriProof<SC, InputMmcs, FriMmcs>,
    extra_params: Option<&[usize]>,
) -> Result<Vec<SC::Challenge>, GenerationError>
where
    SC: StarkGenericConfig,
    InputMmcs: Mmcs<Val<SC>>,
    FriMmcs: Mmcs<SC::Challenge>,
    Val<SC>: TwoAdicField + PrimeField,
    SC::Challenger: FieldChallenger<Val<SC>>
        + GrindingChallenger<Witness = Val<SC>>
        + CanObserve<FriMmcs::Commitment>,
{
    let params = extra_params.ok_or(GenerationError::MissingParameterError)?;
    let &[
        log_blowup,
        log_final_poly_len,
        max_log_arity,
        commit_pow_bits,
        query_pow_bits,
        batch_pow_bits,
    ] = params
    else {
        return Err(GenerationError::InvalidParameterCount(params.len(), 6));
    };
    let num_queries = fri_proof_num_queries(opening_proof);
    let mut challenges =
        Vec::with_capacity(2 + 2 * opening_proof.commit_phase_commits.len() + num_queries);

    // PCS phase: domain separator, claimed openings, batch grind, `alpha`.
    observe_opened_values::<SC>(challenger, coms_to_verify, batch_pow_bits);
    if !challenger.check_witness(batch_pow_bits, opening_proof.batch_pow_witness) {
        return Err(GenerationError::InvalidPowWitness);
    }
    challenges.push(challenger.sample_algebra_element());

    // Low-degree test: its own domain separator, bound to the configured fold schedule.
    let mut input_log_heights: Vec<usize> = coms_to_verify
        .iter()
        .flat_map(|(_, round)| {
            round
                .iter()
                .map(|(domain, _)| p3_util::log2_strict_usize(domain.size()) + log_blowup)
        })
        .collect();
    input_log_heights.sort_unstable_by(|a, b| b.cmp(a));
    input_log_heights.dedup();
    let log_global_max_height = *input_log_heights
        .first()
        .ok_or(GenerationError::InvalidProofShape("FRI opens no matrix"))?;
    let log_arities = p3_fri::fold_schedule(
        &input_log_heights,
        log_blowup + log_final_poly_len,
        max_log_arity,
    );
    FriShape {
        log_arities,
        final_poly_len: 1 << log_final_poly_len,
        commit_pow_bits,
        query_pow_bits,
        num_queries,
        index_bits: log_global_max_height,
        log_blowup,
        max_log_arity,
    }
    .domain_separator::<Val<SC>, SC::Challenge>()
    .seed(challenger);

    let grind = |challenger: &mut SC::Challenger, bits: usize, witness: Val<SC>| {
        // A zero difficulty leaves the transcript untouched, as the native check does.
        if bits == 0 {
            return SC::Challenge::ZERO;
        }
        challenger.observe(witness);
        let rand_f: Val<SC> = challenger.sample();
        let rand_usize = rand_f.as_canonical_biguint().to_u64_digits()[0] as usize;
        SC::Challenge::from_usize(rand_usize)
    };

    for (comm, pow_witness) in opening_proof
        .commit_phase_commits
        .iter()
        .zip(&opening_proof.commit_pow_witnesses)
    {
        challenger.observe(comm.clone());
        challenges.push(grind(challenger, commit_pow_bits, *pow_witness));
        challenges.push(challenger.sample_algebra_element());
    }

    challenger.observe_algebra_slice(&opening_proof.final_poly);
    challenges.push(grind(
        challenger,
        query_pow_bits,
        opening_proof.query_pow_witness,
    ));

    for _ in 0..num_queries {
        challenges.push(SC::Challenge::from_usize(
            challenger.sample_bits(log_global_max_height),
        ));
    }

    Ok(challenges)
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
