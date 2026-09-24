use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};

use itertools::Itertools;
use p3_circuit::symbolic::ColumnsTargets;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, NonPrimitiveOpId};
use p3_commit::{Pcs, PolynomialSpace, UnivariateStarkPcs};
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
use p3_lookup::logup::LogUpGadget;
use p3_uni_stark::{StarkGenericConfig, Val, validate_degree_bits};

use super::{ObservableCommitment, VerificationError, recompose_quotient_from_chunks_circuit};
use crate::Target;
use crate::challenger::CircuitChallenger;
use crate::challenger_perm::ChallengerPermConfig;
use crate::input_contract::stark_layout::{
    CommitmentRole, InstanceLayout, MatrixRoute, NativeStarkLayout, checked_power_of_two,
};
use crate::traits::RecursiveChallenger;
use crate::traits::{LookupMetadata, Recursive, RecursiveAir, RecursivePcs};
use crate::transcript::domain_separator_seed;
use crate::types::{
    CommitmentTargets, OpenedValuesTargets, OpenedValuesTargetsWithLookups, ProofTargets,
    StarkChallengeParams, StarkChallenges,
};

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

/// Derive and validate the native uni-STARK opening layout without allocating
/// targets or touching a challenger.
pub(crate) fn plan_uni_native_layout<SC, A>(
    config: &SC,
    air: &A,
    proof: &p3_uni_stark::Proof<SC>,
    public_value_count: usize,
    preprocessed_commit: Option<&<SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment>,
) -> Result<NativeStarkLayout<'static>, VerificationError>
where
    SC: StarkGenericConfig,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    Val<SC>: PrimeField64,
    SC::Challenge: ExtensionField<Val<SC>> + PrimeCharacteristicRing,
{
    plan_uni_native_layout_with_policy(
        config.is_zk(),
        config.pcs().log_min_trace_height(),
        config.pcs().log_max_trace_height(),
        air,
        proof,
        public_value_count,
        preprocessed_commit,
    )
}

pub(crate) fn plan_uni_native_layout_with_policy<SC, A>(
    is_zk: usize,
    log_min_trace_height: usize,
    log_max_lde_height: usize,
    air: &A,
    proof: &p3_uni_stark::Proof<SC>,
    public_value_count: usize,
    preprocessed_commit: Option<&<SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment>,
) -> Result<NativeStarkLayout<'static>, VerificationError>
where
    SC: StarkGenericConfig,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    Val<SC>: PrimeField64,
    SC::Challenge: ExtensionField<Val<SC>> + PrimeCharacteristicRing,
{
    if air.expected_public_input_count() != Some(public_value_count) {
        return Err(VerificationError::InvalidProofShape(
            "uni-STARK public input count disagrees with the AIR".into(),
        ));
    }
    let degree_bits = proof.degree_bits;
    validate_degree_bits(
        None,
        degree_bits,
        is_zk,
        log_min_trace_height,
        log_max_lde_height,
    )
    .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
    let base_log = degree_bits.checked_sub(is_zk).ok_or_else(|| {
        VerificationError::InvalidProofShape(
            "extended degree smaller than zk adjustment".to_string(),
        )
    })?;
    let opened = &proof.opened_values;
    let preprocessed_width = opened.preprocessed_local().map_or(0, <[_]>::len);
    if (preprocessed_width != 0) != preprocessed_commit.is_some() {
        return Err(VerificationError::InvalidProofShape(
            "preprocessed commitment presence disagrees with its opening".into(),
        ));
    }
    if air.declares_interactions(preprocessed_width) {
        return Err(VerificationError::InvalidProofShape(
            "uni-stark recursive verifier does not support AIR lookup interactions".into(),
        ));
    }
    let log_quotient_degree = air.get_log_num_quotient_chunks(
        preprocessed_width,
        checked_power_of_two(base_log)
            .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?,
        &[],
        is_zk,
        &LogUpGadget,
    );
    let quotient_log = log_quotient_degree
        .checked_add(is_zk)
        .ok_or_else(|| VerificationError::InvalidProofShape("quotient log overflows".into()))?;
    let quotient_chunks = checked_power_of_two(quotient_log)
        .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
    let expected_trace_next = air.width() * usize::from(air.opens_trace_next());
    let expected_pre_next = preprocessed_width * usize::from(air.opens_preprocessed_next());
    if opened.trace_local.len() != air.width()
        || opened.trace_next.as_ref().map_or(0, Vec::len) != expected_trace_next
        || opened.preprocessed_next().map_or(0, <[_]>::len) != expected_pre_next
        || opened.quotient_chunks.len() != quotient_chunks
        || opened
            .quotient_chunks
            .iter()
            .any(|chunk| chunk.len() != SC::Challenge::DIMENSION)
        || opened
            .random
            .as_ref()
            .is_some_and(|values| values.len() != SC::Challenge::DIMENSION)
    {
        return Err(VerificationError::InvalidProofShape(
            "uni-STARK openings disagree with the trusted layout".into(),
        ));
    }
    if (proof.commitments.random.is_some() != (is_zk != 0))
        || (opened.random.is_some() != (is_zk != 0))
    {
        return Err(VerificationError::RandomizationError);
    }
    NativeStarkLayout::new(
        vec![InstanceLayout {
            ext_log: degree_bits,
            base_log,
            challenge_width: SC::Challenge::DIMENSION,
            trace_width: air.width(),
            trace_next: air.opens_trace_next(),
            pre_width: preprocessed_width,
            pre_next: air.opens_preprocessed_next(),
            quotient_log: log_quotient_degree,
            quotient_chunks,
            permutation_width: 0,
        }],
        if preprocessed_width == 0 { &[] } else { &[0] },
        proof.commitments.random.is_some(),
        preprocessed_width != 0,
        false,
    )
    .map(|layout| layout.to_owned_layout())
    .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))
}

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
/// `Ok(Vec<NonPrimitiveOpId>)` containing operation IDs that require private data
/// (e.g., Merkle sibling values for MMCS verification). The caller must set
/// private data for these operations before running the circuit.
/// `Err` if there was a structural error.
#[allow(clippy::too_many_arguments)]
pub fn verify_p3_uni_proof_circuit<
    A,
    SC: StarkGenericConfig,
    Comm: Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        > + Clone
        + ObservableCommitment,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
    CP: ChallengerPermConfig,
    const WIDTH: usize,
    const RATE: usize,
>(
    config: &SC,
    air: &A,
    circuit: &mut CircuitBuilder<SC::Challenge>,
    proof_targets: &ProofTargets<SC, Comm, OpeningProof>,
    public_values: &[Target],
    preprocessed_commit: &Option<Comm>,
    pcs_params: &PcsVerifierParams<SC, InputProof, OpeningProof, Comm>,
    challenger_perm_config: CP,
) -> Result<Vec<NonPrimitiveOpId>, VerificationError>
where
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    <SC as StarkGenericConfig>::Pcs: RecursivePcs<
            SC,
            InputProof,
            OpeningProof,
            Comm,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
    Val<SC>: PrimeField64,
    SC::Challenge: ExtensionField<Val<SC>> + PrimeCharacteristicRing,
{
    let ProofTargets {
        commitments_targets:
            CommitmentTargets {
                trace_targets,
                quotient_chunks_targets,
                random_commit,
                ..
            },
        opened_values_targets,
        opening_proof,
        degree_bits,
    } = proof_targets;

    let OpenedValuesTargets {
        trace_local_targets: opened_trace_local_targets,
        trace_next_targets: opened_trace_next_targets,
        preprocessed_local_targets: opt_opened_preprocessed_local_targets,
        preprocessed_next_targets: opt_opened_preprocessed_next_targets,
        quotient_chunks_targets: opened_quotient_chunks_targets,
        random_targets: opened_random,
        ..
    } = opened_values_targets;

    // `degree_bits` feeds `1 << degree_bits` below; validate bounds up front (parity with
    // native p3-uni-stark) instead of shift-overflowing or building a degenerate domain
    // from a crafted proof.
    let pcs = config.pcs();
    validate_degree_bits(
        None,
        *degree_bits,
        config.is_zk(),
        pcs.log_min_trace_height(),
        pcs.log_max_trace_height(),
    )
    .map_err(|e| VerificationError::InvalidProofShape(e.to_string()))?;

    let degree = 1 << degree_bits;
    let lookup_gadget = LogUpGadget {};
    let preprocessed_width = opt_opened_preprocessed_local_targets
        .as_ref()
        .map_or(0, |p| p.len());

    // Lookups are not supported for recursive single STARK verification: the AIR
    // is evaluated below with empty lookup contexts, which does not enforce any
    // lookup argument. Reject AIRs that declare interactions rather than verifying
    // them with their lookups silently unenforced.
    if air.declares_interactions(preprocessed_width) {
        return Err(VerificationError::InvalidProofShape(
            "uni-stark recursive verifier does not support AIRs with lookup interactions"
                .to_string(),
        ));
    }

    // Lookups are not supported for recursive single STARK verification.
    let log_quotient_degree = A::get_log_num_quotient_chunks(
        air,
        preprocessed_width,
        degree >> config.is_zk(),
        &[],
        config.is_zk(),
        &lookup_gadget,
    );
    let quotient_degree = 1 << (log_quotient_degree + config.is_zk());

    let trace_domain = pcs.natural_domain_for_degree(degree);
    let init_trace_domain = pcs.natural_domain_for_degree(degree >> (config.is_zk()));

    let quotient_domain =
        pcs.create_disjoint_domain(trace_domain, 1 << (degree_bits + log_quotient_degree));
    let quotient_chunks_domains = pcs.split_domains(&quotient_domain, quotient_degree);

    let randomized_quotient_chunks_domains = quotient_chunks_domains
        .iter()
        .map(|domain| pcs.natural_domain_for_degree(pcs.size(domain) << (config.is_zk())))
        .collect_vec();

    // The recursive verifier replays no out-of-domain grind, so it only accepts the zero
    // difficulty, at which the native transcript absorbs nothing for that phase.
    if config.ood_proof_of_work_bits() != 0 {
        return Err(VerificationError::InvalidProofShape(
            "recursive uni-STARK verification requires zero OOD proof of work".to_string(),
        ));
    }

    // Generate all challenges (alpha, zeta, zeta_next, PCS challenges)
    let (challenge_targets, mut challenger) =
        get_circuit_challenges::<A, SC, Comm, InputProof, OpeningProof, CP, WIDTH, RATE>(
            air,
            config,
            proof_targets,
            public_values,
            preprocessed_width,
            quotient_degree,
            preprocessed_commit,
            &init_trace_domain,
            circuit,
            pcs_params,
            challenger_perm_config,
        )?;

    // Validate ZK randomization consistency
    if (opened_random.is_some() != SC::Pcs::ZK) || (random_commit.is_some() != SC::Pcs::ZK) {
        return Err(VerificationError::RandomizationError);
    }

    // Validate proof shape
    validate_proof_shape::<A, SC, Comm>(
        air,
        opened_values_targets,
        preprocessed_width,
        preprocessed_commit,
        quotient_degree,
    )?;

    let layout = NativeStarkLayout::new(
        vec![InstanceLayout {
            ext_log: *degree_bits,
            base_log: degree_bits.checked_sub(config.is_zk()).ok_or_else(|| {
                VerificationError::InvalidProofShape(
                    "extended degree smaller than zk adjustment".to_string(),
                )
            })?,
            challenge_width: SC::Challenge::DIMENSION,
            trace_width: A::width(air),
            trace_next: air.opens_trace_next(),
            pre_width: preprocessed_width,
            pre_next: air.opens_preprocessed_next(),
            quotient_log: log_quotient_degree,
            quotient_chunks: quotient_degree,
            permutation_width: 0,
        }],
        if preprocessed_width > 0 { &[0] } else { &[] },
        random_commit.is_some(),
        preprocessed_width > 0,
        false,
    )
    .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;

    let alpha = challenge_targets[0];
    let zeta = challenge_targets[1];
    let zeta_next = challenge_targets[2];

    // Prepare commitments with their opening points for PCS verification
    let mut coms_to_verify = Vec::with_capacity(layout.commitment_count());
    for matrix in layout.matrices(CommitmentRole::Random) {
        let MatrixRoute::Random { .. } = matrix.route else {
            unreachable!("random planner emits only random routes")
        };
        let random_values = opened_random
            .as_ref()
            .ok_or(VerificationError::RandomizationError)?;
        coms_to_verify.push((
            random_commit
                .clone()
                .ok_or(VerificationError::RandomizationError)?,
            vec![(trace_domain, vec![(zeta, random_values.clone())])],
        ));
    }
    for matrix in layout.matrices(CommitmentRole::Trace) {
        let MatrixRoute::Trace { .. } = matrix.route else {
            unreachable!("trace planner emits only trace routes")
        };
        let mut points = vec![(zeta, opened_trace_local_targets.clone())];
        if matrix.point_count == 2 {
            points.push((zeta_next, opened_trace_next_targets.clone()));
        }
        coms_to_verify.push((trace_targets.clone(), vec![(trace_domain, points)]));
    }
    let quotient_matrices: Vec<_> = layout.matrices(CommitmentRole::Quotient).collect();
    if quotient_matrices.len() != opened_quotient_chunks_targets.len()
        || quotient_matrices.len() != randomized_quotient_chunks_domains.len()
    {
        return Err(VerificationError::InvalidProofShape(
            "Randomized quotient chunks length mismatch".to_string(),
        ));
    }
    let quotient_points = quotient_matrices
        .into_iter()
        .zip(randomized_quotient_chunks_domains.iter())
        .map(|(matrix, domain)| {
            let MatrixRoute::Quotient { chunk, .. } = matrix.route else {
                unreachable!("quotient planner emits only quotient routes")
            };
            (
                *domain,
                vec![(zeta, opened_quotient_chunks_targets[chunk].clone())],
            )
        })
        .collect();
    coms_to_verify.push((quotient_chunks_targets.clone(), quotient_points));
    for matrix in layout.matrices(CommitmentRole::Preprocessed) {
        let MatrixRoute::Preprocessed { .. } = matrix.route else {
            unreachable!("preprocessed planner emits only preprocessed routes")
        };
        let local = opt_opened_preprocessed_local_targets
            .clone()
            .ok_or_else(|| {
                VerificationError::InvalidProofShape(
                    "preprocessed local values should exist".to_string(),
                )
            })?;
        let mut points = vec![(zeta, local)];
        if matrix.point_count == 2 {
            points.push((
                zeta_next,
                opt_opened_preprocessed_next_targets
                    .clone()
                    .ok_or_else(|| {
                        VerificationError::InvalidProofShape(
                            "preprocessed next values should exist".to_string(),
                        )
                    })?,
            ));
        }
        coms_to_verify.push((
            preprocessed_commit.clone().ok_or_else(|| {
                VerificationError::InvalidProofShape("preprocessed commitment missing".to_string())
            })?,
            vec![(trace_domain, points)],
        ));
    }

    // Verify polynomial openings using PCS
    let mmcs_op_ids = pcs.verify_circuit::<WIDTH, RATE, CP>(
        circuit,
        &challenge_targets[3..], // PCS challenges (after alpha, zeta, zeta_next)
        &mut challenger,
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
    // Note that lookups are not supported for recursive single STARK verification.
    let sels = pcs.selectors_at_point_circuit(circuit, &init_trace_domain, &zeta);
    // Periodic columns are verifier-recomputed AIR constants, evaluated at the
    // opening point over the same `init_trace_domain` the native verifier uses.
    let periodic_columns = air.periodic_columns();
    let periodic_values = pcs.evaluate_periodic_columns_at_point_circuit(
        circuit,
        &init_trace_domain,
        &periodic_columns,
        zeta,
    )?;
    let columns_targets = ColumnsTargets {
        challenges: &[],
        public_values,
        permutation_local_values: &[],
        permutation_next_values: &[],
        permutation_values: &[],
        local_prep_values: opt_opened_preprocessed_local_targets
            .as_ref()
            .map_or(&[], |p| p),
        next_prep_values: opt_opened_preprocessed_next_targets
            .as_ref()
            .map_or(&[], |p| p),
        periodic_values: &periodic_values,
        local_values: opened_trace_local_targets,
        next_values: opened_trace_next_targets,
    };

    let dummy_lookup_metadata = LookupMetadata { contexts: &[] };
    let folded_constraints = air.eval_folded_circuit(
        circuit,
        &sels,
        &alpha,
        &dummy_lookup_metadata,
        columns_targets,
        &lookup_gadget,
    );

    // Verify: constraints / Z_H(zeta) == quotient(zeta)
    let folded_mul = circuit.mul(folded_constraints, sels.inv_vanishing);
    circuit.connect(folded_mul, quotient);

    Ok(mmcs_op_ids)
}

/// Generate all challenges for STARK verification.
///
/// This includes:
/// - Base STARK challenges (alpha, zeta, zeta_next)
/// - PCS-specific challenges (e.g., FRI betas, query indices)
#[allow(clippy::too_many_arguments)]
fn get_circuit_challenges<
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    SC: StarkGenericConfig,
    Comm: Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        > + ObservableCommitment,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
    CP: ChallengerPermConfig,
    const WIDTH: usize,
    const RATE: usize,
>(
    _air: &A,
    config: &SC,
    proof_targets: &ProofTargets<SC, Comm, OpeningProof>,
    public_values: &[Target],
    preprocessed_width: usize,
    quotient_degree: usize,
    preprocessed_commit: &Option<Comm>,
    init_trace_domain: &PcsDomain<SC>,
    circuit: &mut CircuitBuilder<SC::Challenge>,
    pcs_params: &PcsVerifierParams<SC, InputProof, OpeningProof, Comm>,
    challenger_perm_config: CP,
) -> Result<(Vec<Target>, CircuitChallenger<WIDTH, RATE, CP>), CircuitBuilderError>
where
    SC::Pcs: RecursivePcs<
            SC,
            InputProof,
            OpeningProof,
            Comm,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
    Val<SC>: PrimeField64,
    SC::Challenge: ExtensionField<Val<SC>> + PrimeCharacteristicRing,
{
    let pcs = config.pcs();

    // Compute the trace domain generator for zeta_next = zeta * generator
    // The generator is the primitive n-th root of unity for the init_trace_domain
    let first_point = pcs.first_point(init_trace_domain);
    let next_point = init_trace_domain
        .next_point(first_point)
        .expect("init_trace_domain should have next_point");
    let trace_domain_generator = next_point * first_point.inverse();

    let mut challenger = CircuitChallenger::<WIDTH, RATE, CP>::new(challenger_perm_config);

    // Set up challenge parameters matching native challenger behavior
    let degree_bits = proof_targets.degree_bits;
    let transcript_seed = domain_separator_seed(
        &crate::transcript::uni_stark_shape(
            _air,
            preprocessed_width,
            public_values.len(),
            degree_bits,
            degree_bits - config.is_zk(),
            quotient_degree,
            SC::Pcs::ZK,
            config.ood_proof_of_work_bits(),
        )
        .domain_separator::<Val<SC>, SC::Challenge>(),
    );
    let challenge_params = StarkChallengeParams {
        transcript_seed,
        preprocessed_width,
        preprocessed_commit,
        trace_domain_generator,
    };

    // Allocate base STARK challenges (alpha, zeta, zeta_next) using Fiat-Shamir
    let base_challenges = StarkChallenges::allocate::<SC, Comm, OpeningProof>(
        circuit,
        &mut challenger,
        proof_targets,
        public_values,
        &challenge_params,
    );

    let opened_values_no_lookups = OpenedValuesTargetsWithLookups {
        opened_values_no_lookups: proof_targets.opened_values_targets.clone(),
        permutation_local_targets: vec![],
        permutation_next_targets: vec![],
    };

    // Observe opened values before getting PCS challenges, when this PCS's native
    // transcript expects them pre-observed (FRI). WHIR observes them itself,
    // interleaved with its own per-commitment challenges, inside verify_circuit.
    if SC::Pcs::PRE_OBSERVES_OPENED_VALUES {
        // The PCS opens its own transcript with a seed bound to the claims' shape, in the
        // commitment order random, trace, quotient chunks, preprocessed.
        let values = &opened_values_no_lookups.opened_values_no_lookups;
        let mut counts = Vec::with_capacity(4);
        if let Some(random) = &values.random_targets {
            counts.push(vec![vec![random.len()]]);
        }
        let mut trace_points = vec![values.trace_local_targets.len()];
        if _air.opens_trace_next() {
            trace_points.push(values.trace_next_targets.len());
        }
        counts.push(vec![trace_points]);
        counts.push(
            values
                .quotient_chunks_targets
                .iter()
                .map(|chunk| vec![chunk.len()])
                .collect(),
        );
        if let Some(local) = &values.preprocessed_local_targets {
            let mut points = vec![local.len()];
            if _air.opens_preprocessed_next() {
                points.push(
                    values
                        .preprocessed_next_targets
                        .as_ref()
                        .map_or(0, Vec::len),
                );
            }
            counts.push(vec![points]);
        }
        let seed = SC::Pcs::claims_transcript_seed(pcs_params, counts);
        RecursiveChallenger::<Val<SC>, SC::Challenge>::observe_seed(
            &mut challenger,
            circuit,
            &seed,
        );
        opened_values_no_lookups.observe(circuit, &mut challenger);
    }

    // Get PCS-specific challenges (FRI betas, query indices, etc.)
    let pcs_challenges = SC::Pcs::get_challenges_circuit::<WIDTH, RATE, CP>(
        circuit,
        &mut challenger,
        &proof_targets.opening_proof,
        &opened_values_no_lookups,
        pcs_params,
    )?;

    // Return flat vector: [alpha, zeta, zeta_next, ...pcs_challenges] and challenger for PCS verification
    let mut all_challenges = base_challenges.to_vec();
    all_challenges.extend(pcs_challenges);
    Ok((all_challenges, challenger))
}

/// Validate the shape of the proof (dimensions, lengths).
fn validate_proof_shape<A, SC: StarkGenericConfig, Comm>(
    air: &A,
    opened_values: &OpenedValuesTargets<SC>,
    preprocessed_width: usize,
    preprocessed_commit: &Option<Comm>,
    quotient_degree: usize,
) -> Result<(), VerificationError>
where
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    SC::Challenge: PrimeCharacteristicRing,
{
    let air_width = A::width(air);

    if preprocessed_commit.is_some() && preprocessed_width == 0 {
        return Err(VerificationError::InvalidProofShape(
            "There is a preprocessed commit but no opening values provided.".to_string(),
        ));
    }

    if preprocessed_commit.is_none() && preprocessed_width > 0 {
        return Err(VerificationError::InvalidProofShape(
            "Preprocessed width is non-zero but no preprocessed commit provided.".to_string(),
        ));
    }

    let OpenedValuesTargets {
        trace_local_targets: opened_trace_local,
        trace_next_targets: opened_trace_next,
        preprocessed_local_targets: opened_prep_local,
        preprocessed_next_targets: opened_prep_next,
        quotient_chunks_targets: opened_quotient_chunks,
        random_targets: opened_random,
        ..
    } = opened_values;

    // The next-row opening is suppressed (empty) for AIRs that do not access it.
    let expected_next_len = if air.opens_trace_next() { air_width } else { 0 };
    if opened_trace_local.len() != air_width || opened_trace_next.len() != expected_next_len {
        return Err(VerificationError::InvalidProofShape(format!(
            "Expected opened_trace_local and opened_trace_next to have length {air_width} and \
             {expected_next_len}, got {} and {}",
            opened_trace_local.len(),
            opened_trace_next.len()
        )));
    }

    let preprocessed_local_len = opened_prep_local.as_ref().map_or(0, |v| v.len());
    let preprocessed_next_len = opened_prep_next.as_ref().map_or(0, |v| v.len());
    let expected_next_len = if air.opens_preprocessed_next() {
        preprocessed_width
    } else {
        0
    };
    if preprocessed_width != preprocessed_local_len || expected_next_len != preprocessed_next_len {
        // Verifier expects preprocessed trace while proof does not have it, or vice versa
        return Err(VerificationError::InvalidProofShape(format!(
            "Expected preprocessed width {preprocessed_width} and next width {expected_next_len} but local has length {preprocessed_local_len} and next has length {preprocessed_next_len}"
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
