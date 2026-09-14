//! Structural descriptors for recursive WHIR input allocation.

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use p3_commit::Mmcs;
use p3_field::{BasedVectorSpace, ExtensionField, Field, TwoAdicField};
use p3_merkle_tree::{MerkleCap, PrunedMerklePaths};
use p3_sumcheck::SumcheckData;
use p3_whir::parameters::WhirConfig;
use p3_whir::pcs::proof::{PcsProof, QueryOpenings};

use super::{FriOpeningLayout, MerkleCapShape};
use crate::PermConfig;
use crate::pcs::whir::params::WhirVerifierParams;
use crate::pcs::whir::uni::WhirUniVerifierParams;
use crate::pcs::whir::uni::pcs::WhirUniProof;
use crate::traits::CheckedRecursive;
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};

/// Allocation-relevant structure of one sumcheck transcript.
#[derive(Clone, PartialEq, Eq)]
pub struct SumcheckShape {
    pub(crate) polynomial_evaluations: usize,
    pub(crate) pow_witnesses: usize,
}

/// Field variant and per-query row widths of WHIR openings.
#[derive(Clone, PartialEq, Eq)]
pub enum QueryOpeningsShape {
    Base { rows: Vec<usize> },
    Extension { rows: Vec<usize> },
}

/// Allocation-relevant structure of one intermediate WHIR step.
#[derive(Clone, PartialEq, Eq)]
pub struct WhirStepShape<C> {
    pub(crate) commitment: Option<C>,
    pub(crate) ood_answers: usize,
    pub(crate) openings: QueryOpeningsShape,
    pub(crate) sumcheck: SumcheckShape,
}

/// Complete allocation-relevant structure of one WHIR transcript.
#[derive(Clone, PartialEq, Eq)]
pub struct WhirShape<C> {
    pub(crate) initial_ood_answers: usize,
    pub(crate) initial_sumcheck: SumcheckShape,
    pub(crate) rounds: Vec<WhirStepShape<C>>,
    pub(crate) final_poly: Option<usize>,
    pub(crate) final_openings: QueryOpeningsShape,
    pub(crate) final_sumcheck: Option<SumcheckShape>,
}

/// Current/next partition of one PCS opening batch.
#[derive(Clone, PartialEq, Eq)]
pub struct OpeningBatchShape {
    pub(crate) current: usize,
    pub(crate) next: usize,
}

/// Allocation-relevant structure of one outer univariate PCS round.
#[derive(Clone, PartialEq, Eq)]
pub struct WhirPcsRoundShape<C> {
    pub(crate) evals: Vec<OpeningBatchShape>,
    pub(crate) whir: WhirShape<C>,
}

/// Complete allocation-relevant structure of a WHIR univariate opening proof.
#[derive(Clone, PartialEq, Eq)]
pub struct WhirUniShape<C> {
    pub(crate) rounds: Vec<WhirPcsRoundShape<C>>,
}

/// Compact result of the borrowed WHIR context pass.
///
/// This contains only geometry later needed to build a recursive verifier. It
/// deliberately excludes proof values, cap contents, and dynamic Merkle
/// frontier lengths.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WhirContextShape {
    pub(crate) stacked_num_variables: usize,
    pub(crate) opening_batches: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WhirRoundContext {
    pub(crate) ood_samples: usize,
    pub(crate) num_queries: usize,
    pub(crate) folding_pow_bits: usize,
    pub(crate) folding_factor: usize,
    pub(crate) domain_size: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WhirContextParams {
    pub(crate) num_variables: usize,
    pub(crate) commitment_ood_samples: usize,
    pub(crate) starting_folding_factor: usize,
    pub(crate) starting_folding_pow_bits: usize,
    pub(crate) rounds: Vec<WhirRoundContext>,
    pub(crate) final_poly_num_variables: usize,
    pub(crate) final_queries: usize,
    pub(crate) final_sumcheck_rounds: usize,
    pub(crate) final_folding_factor: usize,
    pub(crate) final_folding_pow_bits: usize,
    pub(crate) final_domain_size: usize,
}

/// Compact authority produced by a complete, cap-aware WHIR input pass.
///
/// It retains only canonical integer parameters, cap cardinalities, and the
/// proof choices that affect target allocation. Proof values, Merkle
/// frontiers, challengers, PCS objects, and configs are deliberately absent.
#[derive(Clone, PartialEq, Eq)]
pub struct ValidatedWhirContext<F> {
    pub(crate) layout: super::stark_layout::NativeStarkLayout<'static>,
    pub(crate) permutation: PermConfig,
    pub(crate) canonical: Vec<WhirContextParams>,
    pub(crate) verifier_params: Vec<WhirVerifierParams<F>>,
    pub(crate) outside_cap_roots: Vec<usize>,
    pub(crate) shape: WhirUniShape<MerkleCapShape>,
    pub(crate) _field: core::marker::PhantomData<F>,
}

impl<F> ValidatedWhirContext<F> {
    pub(crate) const fn layout(&self) -> &super::stark_layout::NativeStarkLayout<'static> {
        &self.layout
    }

    pub(crate) const fn permutation(&self) -> PermConfig {
        self.permutation
    }

    pub(crate) fn canonical(&self) -> &[WhirContextParams] {
        &self.canonical
    }

    pub(crate) fn verifier_params(&self) -> &[WhirVerifierParams<F>] {
        &self.verifier_params
    }
}

/// Checked capability implemented by concrete WHIR opening target adapters.
pub trait CheckedWhirOpening<F, EF, C>: CheckedRecursive<EF>
where
    F: Field,
    EF: ExtensionField<F>,
    C: CheckedRecursive<EF>,
{
    /// Walk all proof-owned resources for the audited native Merkle proof
    /// composition before target allocation, packing, or transcript replay.
    fn check_whir_resources(
        input: &Self::Input,
        limits: &VerifierLimits,
    ) -> Result<InputResourceUsage, VerificationError>;

    fn validate_whir_context(
        input: &Self::Input,
        params: &WhirUniVerifierParams<F>,
        layout: FriOpeningLayout<'_>,
        caps: &[&C::Input],
    ) -> Result<ValidatedWhirContext<F>, VerificationError>;

    fn validate_whir_replacement(
        input: &Self::Input,
        expected: &ValidatedWhirContext<F>,
        layout: FriOpeningLayout<'_>,
        caps: &[&C::Input],
    ) -> Result<(), VerificationError>;
}

pub(crate) trait WhirResourceProof {
    fn compressed_frontier_hashes(&self) -> usize;
}

impl<F, const DIGEST_ELEMS: usize> WhirResourceProof for PrunedMerklePaths<F, DIGEST_ELEMS> {
    fn compressed_frontier_hashes(&self) -> usize {
        self.sibling_hashes.len()
    }
}

fn checked_product(
    left: usize,
    right: usize,
    component: &'static str,
) -> Result<usize, VerificationError> {
    left.checked_mul(right)
        .ok_or(VerificationError::ResourceArithmeticOverflow { component })
}

fn add_sumcheck_resources<F: Field, EF: Field>(
    usage: &mut InputResourceUsage,
    limits: &VerifierLimits,
    data: &SumcheckData<F, EF>,
) -> Result<(), VerificationError> {
    let evaluations = checked_product(data.polynomial_evaluations().len(), 2, "scalar elements")?;
    usage.add_scalar_elements(limits, evaluations)?;
    usage.add_scalar_elements(limits, data.pow_witnesses.len())
}

fn add_query_resources<F, EF, P>(
    usage: &mut InputResourceUsage,
    limits: &VerifierLimits,
    openings: &QueryOpenings<F, EF, P>,
) -> Result<(), VerificationError>
where
    P: WhirResourceProof,
{
    match openings {
        QueryOpenings::Base(opening) => {
            usage.add_query_round(limits, opening.rows.len())?;
            for row in &opening.rows {
                usage.check_matrix_width(limits, row.len())?;
                usage.add_scalar_elements(limits, row.len())?;
            }
            usage.add_compressed_frontier_hashes(limits, opening.proof.compressed_frontier_hashes())
        }
        QueryOpenings::Extension(opening) => {
            usage.add_query_round(limits, opening.rows.len())?;
            for row in &opening.rows {
                usage.check_matrix_width(limits, row.len())?;
                usage.add_scalar_elements(limits, row.len())?;
            }
            usage.add_compressed_frontier_hashes(limits, opening.proof.compressed_frontier_hashes())
        }
    }
}

pub(crate) fn check_whir_resource_limits<F, EF, MT, const DIGEST_ELEMS: usize>(
    input: &WhirUniProof<F, EF, MT>,
    limits: &VerifierLimits,
) -> Result<InputResourceUsage, VerificationError>
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    MT: Mmcs<F, Commitment = MerkleCap<F, [F; DIGEST_ELEMS]>>,
    MT::MultiProof: WhirResourceProof,
{
    let mut usage = InputResourceUsage::default();
    usage.add_rounds(limits, input.rounds.len())?;
    for argument in &input.rounds {
        for batch in &argument.evals {
            usage.check_matrix_width(limits, batch.current().len())?;
            usage.check_matrix_width(limits, batch.next().len())?;
            usage.add_scalar_elements(limits, batch.current().len())?;
            usage.add_scalar_elements(limits, batch.next().len())?;
        }

        let proof = &argument.whir;
        usage.check_matrix_width(limits, proof.initial_ood_answers.len())?;
        usage.add_scalar_elements(limits, proof.initial_ood_answers.len())?;
        add_sumcheck_resources(&mut usage, limits, &proof.initial_sumcheck)?;
        usage.add_rounds(limits, proof.rounds.len())?;
        for round in &proof.rounds {
            if let Some(cap) = &round.commitment {
                let roots = cap.num_roots();
                usage.add_cap_roots(limits, roots)?;
                let packed = checked_product(
                    roots,
                    crate::pcs::whir::uni::targets::packed_digest_len(DIGEST_ELEMS, EF::DIMENSION),
                    "scalar elements",
                )?;
                usage.add_scalar_elements(limits, packed)?;
            }
            usage.check_matrix_width(limits, round.ood_answers.len())?;
            usage.add_scalar_elements(limits, round.ood_answers.len())?;
            usage.add_scalar_elements(limits, 1)?;
            add_query_resources(&mut usage, limits, &round.openings)?;
            add_sumcheck_resources(&mut usage, limits, &round.sumcheck)?;
        }

        if let Some(final_poly) = &proof.final_poly {
            usage.add_final_poly_evaluations(limits, final_poly.num_evals())?;
            usage.add_scalar_elements(limits, final_poly.num_evals())?;
        }
        usage.add_scalar_elements(limits, 1)?;
        add_query_resources(&mut usage, limits, &proof.final_openings)?;
        if let Some(final_sumcheck) = &proof.final_sumcheck {
            // Native WHIR may semantically ignore a present zero-round block;
            // it still selects proof shape and therefore consumes its budget.
            add_sumcheck_resources(&mut usage, limits, final_sumcheck)?;
        }
    }
    usage.check(limits)?;
    Ok(usage)
}

impl WhirContextParams {
    pub(crate) fn from_recursive<F: Field>(params: &WhirVerifierParams<F>) -> Self {
        Self {
            num_variables: params.num_variables(),
            commitment_ood_samples: params.commitment_ood_samples(),
            starting_folding_factor: params.round_folding_factor(0),
            starting_folding_pow_bits: params.starting_folding_pow_bits(),
            rounds: params
                .round_params()
                .iter()
                .map(|round| WhirRoundContext {
                    ood_samples: round.ood_samples(),
                    num_queries: round.num_queries(),
                    folding_pow_bits: round.folding_pow_bits(),
                    folding_factor: round.folding_factor(),
                    domain_size: round.domain_size(),
                })
                .collect(),
            final_poly_num_variables: params.final_poly_num_variables(),
            final_queries: params.final_queries(),
            final_sumcheck_rounds: params.final_sumcheck_rounds(),
            final_folding_factor: params.final_folding_factor(),
            final_folding_pow_bits: params.final_folding_pow_bits(),
            final_domain_size: params.final_domain_size(),
        }
    }
}

impl WhirContextParams {
    pub(crate) fn from_native<EF, F, Ch>(config: &WhirConfig<EF, F, Ch>) -> Self
    where
        F: TwoAdicField,
        EF: ExtensionField<F> + TwoAdicField,
        Ch: p3_challenger::FieldChallenger<F> + p3_challenger::GrindingChallenger<Witness = F>,
    {
        let final_config = config.final_round_config();
        Self {
            num_variables: config.num_variables,
            commitment_ood_samples: config.commitment_ood_samples,
            starting_folding_factor: config.round_folding_factor(0),
            starting_folding_pow_bits: config.starting_folding_pow_bits,
            rounds: config
                .round_parameters
                .iter()
                .map(|round| WhirRoundContext {
                    ood_samples: round.ood_samples,
                    num_queries: round.num_queries,
                    folding_pow_bits: round.folding_pow_bits,
                    folding_factor: round.folding_factor,
                    domain_size: round.domain_size,
                })
                .collect(),
            final_poly_num_variables: final_config.num_variables,
            final_queries: config.final_queries,
            final_sumcheck_rounds: config.final_sumcheck_rounds,
            final_folding_factor: final_config.folding_factor,
            final_folding_pow_bits: config.final_folding_pow_bits,
            final_domain_size: final_config.domain_size,
        }
    }
}

fn checked_pow2(log: usize, what: &'static str) -> Result<usize, VerificationError> {
    let shift = u32::try_from(log).map_err(|_| {
        VerificationError::InvalidProofShape(format!(
            "WHIR {what} exponent {log} does not fit in u32"
        ))
    })?;
    1usize.checked_shl(shift).ok_or_else(|| {
        VerificationError::InvalidProofShape(format!(
            "WHIR {what} exponent {log} exceeds the usize word width"
        ))
    })
}

fn validate_sumcheck<F, EF>(
    sumcheck: &p3_sumcheck::SumcheckData<F, EF>,
    expected_rounds: usize,
    pow_bits: usize,
    label: &str,
) -> Result<(), VerificationError> {
    if sumcheck.polynomial_evaluations.len() != expected_rounds {
        return Err(VerificationError::InvalidProofShape(format!(
            "WHIR {label} sumcheck expects {expected_rounds} rounds, got {}",
            sumcheck.polynomial_evaluations.len()
        )));
    }
    // Native WHIR intentionally ignores this field when pow_bits == 0. Keep
    // that compatibility boundary; present ignored payloads still remain part
    // of the retained allocation shape captured by the target adapter.
    if pow_bits > 0 && sumcheck.pow_witnesses.len() != expected_rounds {
        return Err(VerificationError::InvalidProofShape(format!(
            "WHIR {label} sumcheck expects {expected_rounds} PoW witnesses, got {}",
            sumcheck.pow_witnesses.len()
        )));
    }
    Ok(())
}

fn validate_query_rows<T>(
    rows: &[Vec<T>],
    expected_queries: usize,
    expected_width: usize,
    label: &str,
) -> Result<(), VerificationError> {
    if rows.len() != expected_queries {
        return Err(VerificationError::InvalidProofShape(format!(
            "WHIR {label} expects {expected_queries} query rows, got {}",
            rows.len()
        )));
    }
    if let Some((query, row)) = rows
        .iter()
        .enumerate()
        .find(|(_, row)| row.len() != expected_width)
    {
        return Err(VerificationError::InvalidProofShape(format!(
            "WHIR {label} query {query} expects width {expected_width}, got {}",
            row.len()
        )));
    }
    Ok(())
}

fn validate_query_openings<F, EF, P>(
    openings: &QueryOpenings<F, EF, P>,
    expected_extension: bool,
    expected_queries: usize,
    expected_width: usize,
    label: &str,
) -> Result<(), VerificationError> {
    let is_extension = matches!(openings, QueryOpenings::Extension(_));
    if is_extension != expected_extension {
        return Err(VerificationError::InvalidProofShape(format!(
            "WHIR {label} query field variant disagrees with its round"
        )));
    }
    match openings {
        QueryOpenings::Base(opening) => {
            validate_query_rows(&opening.rows, expected_queries, expected_width, label)
        }
        QueryOpenings::Extension(opening) => {
            validate_query_rows(&opening.rows, expected_queries, expected_width, label)
        }
    }
}

/// Validates one WHIR PCS argument against canonical parameters and borrowed
/// statement geometry, before any transcript replay or target allocation.
///
/// `matrix_shapes` is `(log_height, width, point_count)` in matrix order. It
/// is supplied by the trusted STARK layout, never inferred from the proof.
pub(crate) fn validate_whir_pcs_context<F, EF, MT>(
    proof: &PcsProof<F, EF, MT>,
    params: &WhirContextParams,
    matrix_shapes: &[(usize, usize, usize)],
) -> Result<WhirContextShape, VerificationError>
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    MT: Mmcs<F>,
{
    validate_whir_pcs_context_iter::<F, EF, MT, _>(proof, params, matrix_shapes.iter().copied())
}

/// Iterator form used by production layout planners so quotient matrices stay
/// lazy instead of materializing a proof-sized shape vector.
pub(crate) fn validate_whir_pcs_context_iter<F, EF, MT, I>(
    proof: &PcsProof<F, EF, MT>,
    params: &WhirContextParams,
    matrix_shapes: I,
) -> Result<WhirContextShape, VerificationError>
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    MT: Mmcs<F>,
    I: Iterator<Item = (usize, usize, usize)> + Clone,
{
    if matrix_shapes.clone().next().is_none() {
        return Err(VerificationError::InvalidProofShape(
            "WHIR commitment must contain at least one matrix".into(),
        ));
    }
    if matrix_shapes
        .clone()
        .any(|(_, width, points)| width == 0 || points == 0)
    {
        return Err(VerificationError::InvalidProofShape(
            "WHIR matrices require positive widths and point counts".into(),
        ));
    }
    let expected_batches = matrix_shapes
        .clone()
        .try_fold(0usize, |sum, (_, _, points)| {
            sum.checked_add(points).ok_or_else(|| {
                VerificationError::InvalidProofShape(
                    "WHIR opening batch count overflows usize".into(),
                )
            })
        })?;
    if proof.evals.len() != expected_batches {
        return Err(VerificationError::InvalidProofShape(
            "WHIR opening batch count disagrees with the statement layout".into(),
        ));
    }
    let batch_widths = matrix_shapes
        .clone()
        .flat_map(|(_, width, points)| core::iter::repeat_n(width, points));
    for (batch, (width, eval)) in batch_widths.zip(proof.evals.iter()).enumerate() {
        if eval.current().len() != width || !eval.next().is_empty() {
            return Err(VerificationError::InvalidProofShape(format!(
                "WHIR opening batch {batch} has an invalid current/next width"
            )));
        }
    }

    let shapes = matrix_shapes.map(|(log_height, width, _)| {
        (
            crate::pcs::whir::uni::plan::padded_arity(log_height, params.starting_folding_factor),
            width,
        )
    });
    let stacked_num_variables = crate::pcs::whir::uni::plan::checked_stacked_num_variables(shapes)
        .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
    if stacked_num_variables != params.num_variables {
        return Err(VerificationError::InvalidProofShape(format!(
            "WHIR stacked arity {stacked_num_variables} disagrees with canonical {}",
            params.num_variables
        )));
    }
    if proof.whir.rounds.len() != params.rounds.len() {
        return Err(VerificationError::InvalidProofShape(format!(
            "WHIR intermediate round count expects {}, got {}",
            params.rounds.len(),
            proof.whir.rounds.len()
        )));
    }
    if proof.whir.initial_ood_answers.len() != params.commitment_ood_samples {
        return Err(VerificationError::InvalidProofShape(
            "WHIR initial OOD answer count disagrees with canonical parameters".into(),
        ));
    }
    validate_sumcheck(
        &proof.whir.initial_sumcheck,
        params.starting_folding_factor,
        params.starting_folding_pow_bits,
        "initial",
    )?;

    for (round, (step, expected)) in proof
        .whir
        .rounds
        .iter()
        .zip(params.rounds.iter())
        .enumerate()
    {
        let _cap = step.commitment.as_ref().ok_or_else(|| {
            VerificationError::InvalidProofShape(format!(
                "WHIR intermediate round {round} is missing its commitment"
            ))
        })?;
        if step.ood_answers.len() != expected.ood_samples {
            return Err(VerificationError::InvalidProofShape(format!(
                "WHIR intermediate round {round} OOD count disagrees with canonical parameters"
            )));
        }
        let width = checked_pow2(expected.folding_factor, "intermediate leaf")?;
        let expected_queries = expected
            .num_queries
            .min(expected.domain_size >> expected.folding_factor);
        validate_query_openings(
            &step.openings,
            round != 0,
            expected_queries,
            width,
            "intermediate",
        )?;
        validate_sumcheck(
            &step.sumcheck,
            params
                .rounds
                .get(round + 1)
                .map_or(params.final_folding_factor, |next| next.folding_factor),
            expected.folding_pow_bits,
            "intermediate",
        )?;
    }

    let final_poly = proof.whir.final_poly.as_ref().ok_or_else(|| {
        VerificationError::InvalidProofShape("WHIR proof is missing its final polynomial".into())
    })?;
    let expected_final_poly = checked_pow2(params.final_poly_num_variables, "final polynomial")?;
    if final_poly.num_evals() != expected_final_poly {
        return Err(VerificationError::InvalidProofShape(
            "WHIR final polynomial length disagrees with canonical parameters".into(),
        ));
    }
    let final_width = checked_pow2(params.final_folding_factor, "final leaf")?;
    let final_queries = params
        .final_queries
        .min(params.final_domain_size >> params.final_folding_factor);
    validate_query_openings(
        &proof.whir.final_openings,
        !params.rounds.is_empty(),
        final_queries,
        final_width,
        "final",
    )?;
    match (&proof.whir.final_sumcheck, params.final_sumcheck_rounds) {
        // Native WHIR returns before reading an optional payload when the
        // configured final sumcheck has no rounds. Keep the payload in the
        // retained allocation shape, but do not assign it semantic counts.
        (Some(_), 0) => {}
        (Some(sumcheck), rounds) => {
            validate_sumcheck(sumcheck, rounds, params.final_folding_pow_bits, "final")?;
        }
        (None, 0) => {}
        (None, _) => {
            return Err(VerificationError::InvalidProofShape(
                "WHIR final sumcheck is required by canonical parameters".into(),
            ));
        }
    }

    Ok(WhirContextShape {
        stacked_num_variables,
        opening_batches: proof.evals.len(),
    })
}

fn sumcheck_shape<F, EF>(input: &SumcheckData<F, EF>) -> SumcheckShape {
    SumcheckShape {
        polynomial_evaluations: input.polynomial_evaluations().len(),
        pow_witnesses: input.pow_witnesses.len(),
    }
}

fn query_shape<F, EF, P>(input: &QueryOpenings<F, EF, P>) -> QueryOpeningsShape {
    match input {
        QueryOpenings::Base(opening) => QueryOpeningsShape::Base {
            rows: opening.rows.iter().map(Vec::len).collect(),
        },
        QueryOpenings::Extension(opening) => QueryOpeningsShape::Extension {
            rows: opening.rows.iter().map(Vec::len).collect(),
        },
    }
}

fn validate_digest_packing(
    digest_elems: usize,
    extension_dimension: usize,
) -> Result<(), VerificationError> {
    if extension_dimension != 1 && !digest_elems.is_multiple_of(extension_dimension) {
        return Err(VerificationError::InvalidProofShape(format!(
            "WHIR cap absorption requires EF::DIMENSION ({extension_dimension}) to be 1 or \
             evenly divide DIGEST_ELEMS ({digest_elems})"
        )));
    }
    Ok(())
}

/// Validate raw WHIR proof structure before target allocation.
///
/// These checks cover only relationships visible in the proof itself. Round counts,
/// widths, and polynomial lengths derived from the committed statement are checked by
/// the PCS/backend once its verifier parameters and native commitment layout are known.
pub(crate) fn validate_whir_uni_input<F, EF, MT, const DIGEST_ELEMS: usize>(
    input: &WhirUniProof<F, EF, MT>,
) -> Result<(), VerificationError>
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    MT: Mmcs<F, Commitment = MerkleCap<F, [F; DIGEST_ELEMS]>>,
{
    validate_digest_packing(DIGEST_ELEMS, <EF as BasedVectorSpace<F>>::DIMENSION)?;
    for round in &input.rounds {
        for batch in &round.evals {
            if !batch.next().is_empty() {
                return Err(VerificationError::InvalidProofShape(
                    "WHIR uni openings use no next group".into(),
                ));
            }
        }
        for step in &round.whir.rounds {
            let commitment = step.commitment.as_ref().ok_or_else(|| {
                VerificationError::InvalidProofShape(
                    "WHIR proof missing intermediate round commitment".into(),
                )
            })?;
            let roots = commitment.num_roots();
            if roots == 0 || !roots.is_power_of_two() {
                return Err(VerificationError::InvalidProofShape(
                    "WHIR commitment cap must have a non-empty power-of-two root count".into(),
                ));
            }
        }
        if round.whir.final_poly.is_none() {
            return Err(VerificationError::InvalidProofShape(
                "WHIR proof missing final polynomial".into(),
            ));
        }
    }
    Ok(())
}

/// Captures every native proof choice that changes WHIR target allocation.
pub(crate) fn capture_whir_uni_shape<F, EF, MT, const DIGEST_ELEMS: usize>(
    input: &WhirUniProof<F, EF, MT>,
) -> Result<WhirUniShape<MerkleCapShape>, VerificationError>
where
    F: Field,
    EF: ExtensionField<F> + BasedVectorSpace<F>,
    MT: Mmcs<F, Commitment = MerkleCap<F, [F; DIGEST_ELEMS]>>,
{
    validate_whir_uni_input::<F, EF, MT, DIGEST_ELEMS>(input)?;

    let rounds = input
        .rounds
        .iter()
        .map(|round| {
            let evals = round
                .evals
                .iter()
                .map(|batch| {
                    if !batch.next().is_empty() {
                        return Err(VerificationError::InvalidProofShape(
                            "WHIR uni openings use no next group".into(),
                        ));
                    }
                    Ok(OpeningBatchShape {
                        current: batch.current().len(),
                        next: batch.next().len(),
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;

            let whir = &round.whir;
            let rounds = whir
                .rounds
                .iter()
                .map(|step| {
                    let commitment = step.commitment.as_ref().ok_or_else(|| {
                        VerificationError::InvalidProofShape(
                            "WHIR proof missing intermediate round commitment".into(),
                        )
                    })?;
                    Ok(WhirStepShape {
                        commitment: Some(MerkleCapShape {
                            roots: commitment.num_roots(),
                        }),
                        ood_answers: step.ood_answers.len(),
                        openings: query_shape(&step.openings),
                        sumcheck: sumcheck_shape(&step.sumcheck),
                    })
                })
                .collect::<Result<Vec<_>, VerificationError>>()?;
            let final_poly = whir.final_poly.as_ref().ok_or_else(|| {
                VerificationError::InvalidProofShape("WHIR proof missing final polynomial".into())
            })?;

            Ok(WhirPcsRoundShape {
                evals,
                whir: WhirShape {
                    initial_ood_answers: whir.initial_ood_answers.len(),
                    initial_sumcheck: sumcheck_shape(&whir.initial_sumcheck),
                    rounds,
                    final_poly: Some(final_poly.num_evals()),
                    final_openings: query_shape(&whir.final_openings),
                    final_sumcheck: whir.final_sumcheck.as_ref().map(sumcheck_shape),
                },
            })
        })
        .collect::<Result<Vec<_>, VerificationError>>()?;

    Ok(WhirUniShape { rounds })
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;
    use p3_field::extension::BinomialExtensionField;
    use p3_merkle_tree::{MerkleCap, PrunedMerklePaths};
    use p3_multilinear_util::poly::Poly;
    use p3_sumcheck::OpeningBatch;
    use p3_sumcheck::strategy::VariableOrder;
    use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};
    use p3_whir::pcs::proof::{QueryOpenings, SharedProofOpening, WhirRoundProof};

    use super::{
        CheckedWhirOpening, WhirContextParams, validate_digest_packing, validate_whir_pcs_context,
    };
    use crate::input_contract::stark_layout::{InstanceLayout, NativeStarkLayout};
    use crate::pcs::fri::MerkleCapTargets;
    use crate::pcs::whir::uni::WhirUniVerifierParams;
    use crate::pcs::whir::uni::pcs::WhirUniProof;
    use crate::pcs::whir::uni::pcs::tests::{MyMmcs, open_two_matrices};
    use crate::pcs::whir::uni::targets::WhirUniProofTargets;
    use crate::traits::{CheckedRecursive, PreparedRecursive};
    use crate::verifier::{VerificationError, VerifierLimits};

    type F = BabyBear;
    type EF = BinomialExtensionField<F, 4>;
    type Targets = WhirUniProofTargets<F, EF, MyMmcs, 8>;
    type CapTargets = MerkleCapTargets<F, 8>;

    fn zero_cap() -> MerkleCap<F, [F; 8]> {
        MerkleCap::new(vec![[F::ZERO; 8]])
    }

    fn zero_frontier() -> PrunedMerklePaths<F, 8> {
        PrunedMerklePaths {
            sibling_hashes: vec![],
        }
    }

    fn sc(rounds: usize, witnesses: usize) -> p3_sumcheck::SumcheckData<F, EF> {
        p3_sumcheck::SumcheckData {
            polynomial_evaluations: vec![[EF::ZERO; 2]; rounds],
            pow_witnesses: vec![F::ZERO; witnesses],
        }
    }

    fn base_opening(queries: usize, width: usize) -> QueryOpenings<F, EF, PrunedMerklePaths<F, 8>> {
        QueryOpenings::Base(SharedProofOpening {
            rows: vec![vec![F::ZERO; width]; queries],
            proof: zero_frontier(),
        })
    }

    fn extension_opening(
        queries: usize,
        width: usize,
    ) -> QueryOpenings<F, EF, PrunedMerklePaths<F, 8>> {
        QueryOpenings::Extension(SharedProofOpening {
            rows: vec![vec![EF::ZERO; width]; queries],
            proof: zero_frontier(),
        })
    }

    fn canonical_two_argument_fixture() -> (
        WhirUniProof<F, EF, MyMmcs>,
        WhirUniVerifierParams<F>,
        NativeStarkLayout<'static>,
        Vec<MerkleCap<F, [F; 8]>>,
    ) {
        let protocol = ProtocolParameters {
            starting_log_inv_rate: 6,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(8),
            soundness_type: SecurityAssumption::CapacityBound,
            security_level: 32,
            pow_bits: 0,
        };
        let params = WhirUniVerifierParams::new(
            protocol,
            VariableOrder::Prefix,
            crate::Poseidon2Config::BABY_BEAR_D4_W16,
        )
        .unwrap();
        let layout = NativeStarkLayout::new(
            vec![InstanceLayout {
                challenge_width: 4,
                ext_log: 8,
                base_log: 8,
                trace_width: 3,
                trace_next: true,
                pre_width: 0,
                pre_next: false,
                quotient_log: 5,
                quotient_chunks: 32,
                permutation_width: 0,
            }],
            &[],
            false,
            false,
            false,
        )
        .unwrap();
        let trace = p3_whir::pcs::proof::PcsProof {
            whir: p3_whir::pcs::proof::WhirProof {
                initial_ood_answers: vec![EF::ZERO],
                initial_sumcheck: sc(8, 0),
                rounds: vec![],
                final_poly: Some(Poly::new(vec![EF::ZERO; 4])),
                final_pow_witness: F::ZERO,
                final_openings: base_opening(6, 256),
                final_sumcheck: Some(sc(2, 0)),
            },
            evals: vec![
                OpeningBatch::new(vec![EF::ZERO; 3], vec![]),
                OpeningBatch::new(vec![EF::ZERO; 3], vec![]),
            ],
        };
        let quotient = p3_whir::pcs::proof::PcsProof {
            whir: p3_whir::pcs::proof::WhirProof {
                initial_ood_answers: vec![EF::ZERO],
                initial_sumcheck: sc(8, 0),
                rounds: vec![WhirRoundProof {
                    commitment: Some(zero_cap()),
                    ood_answers: vec![EF::ZERO],
                    pow_witness: F::ZERO,
                    openings: base_opening(6, 256),
                    sumcheck: sc(7, 0),
                }],
                final_poly: Some(Poly::new(vec![EF::ZERO; 1])),
                final_pow_witness: F::ZERO,
                final_openings: extension_opening(3, 128),
                final_sumcheck: None,
            },
            evals: (0..32)
                .map(|_| OpeningBatch::new(vec![EF::ZERO; 4], vec![]))
                .collect(),
        };
        (
            WhirUniProof {
                rounds: vec![trace, quotient],
            },
            params,
            layout,
            vec![zero_cap(), zero_cap()],
        )
    }

    fn whir_fixture() -> WhirUniProof<F, EF, MyMmcs> {
        let (_pcs, commitment, _coms, mut proof) = open_two_matrices();
        let whir = &mut proof.rounds[0].whir;
        whir.rounds.push(WhirRoundProof {
            commitment: Some(commitment),
            ood_answers: whir.initial_ood_answers.clone(),
            pow_witness: F::ZERO,
            openings: whir.final_openings.clone(),
            sumcheck: whir.initial_sumcheck.clone(),
        });
        proof
    }

    #[test]
    fn whir_resource_walk_checks_all_native_axes_and_present_ignored_payloads() {
        let (mut proof, _params, _layout, _caps) = canonical_two_argument_fixture();
        match &mut proof.rounds[0].whir.final_openings {
            QueryOpenings::Base(opening) => {
                opening.proof.sibling_hashes.extend([[F::ZERO; 8]; 5]);
            }
            QueryOpenings::Extension(_) => unreachable!(),
        }
        let exact = VerifierLimits {
            max_rounds: 3,
            max_queries_per_round: 6,
            max_matrix_width: 256,
            max_final_poly_evaluations: 5,
            max_cap_roots: 1,
            max_total_scalar_elements: 3653,
            max_compressed_frontier_hashes: 5,
            ..VerifierLimits::default()
        };

        let usage = <Targets as CheckedWhirOpening<F, EF, CapTargets>>::check_whir_resources(
            &proof, &exact,
        )
        .expect("literal exact boundaries are accepted");
        assert_eq!(usage.rounds, 3);
        assert_eq!(usage.cap_roots, 1);
        assert_eq!(usage.final_poly_evaluations, 5);
        assert_eq!(usage.compressed_frontier_hashes, 5);

        for (limits, component) in [
            (
                VerifierLimits {
                    max_rounds: 2,
                    ..exact
                },
                "rounds",
            ),
            (
                VerifierLimits {
                    max_queries_per_round: 5,
                    ..exact
                },
                "queries per round",
            ),
            (
                VerifierLimits {
                    max_matrix_width: 255,
                    ..exact
                },
                "matrix or row width",
            ),
            (
                VerifierLimits {
                    max_final_poly_evaluations: 4,
                    ..exact
                },
                "final polynomial evaluations",
            ),
            (
                VerifierLimits {
                    max_cap_roots: 0,
                    ..exact
                },
                "cap roots",
            ),
            (
                VerifierLimits {
                    max_total_scalar_elements: 3652,
                    ..exact
                },
                "scalar elements",
            ),
            (
                VerifierLimits {
                    max_compressed_frontier_hashes: 4,
                    ..exact
                },
                "compressed frontier hashes",
            ),
        ] {
            let error = <Targets as CheckedWhirOpening<F, EF, CapTargets>>::check_whir_resources(
                &proof, &limits,
            )
            .expect_err("one-below boundary must reject");
            assert!(matches!(
                error,
                VerificationError::ResourceLimitExceeded { component: actual, .. }
                    if actual == component
            ));
        }
    }

    fn set_query_rows(
        openings: &mut QueryOpenings<F, EF, <MyMmcs as p3_commit::Mmcs<F>>::MultiProof>,
        widths: &[usize],
    ) {
        match openings {
            QueryOpenings::Base(opening) => {
                opening.rows = widths.iter().map(|&width| vec![F::ZERO; width]).collect();
            }
            QueryOpenings::Extension(opening) => {
                opening.rows = widths.iter().map(|&width| vec![EF::ZERO; width]).collect();
            }
        }
    }

    #[test]
    fn prepared_whir_current_next_partition_binds() {
        let mut native = whir_fixture();
        let batch = &mut native.rounds[0].evals[0];
        *batch = OpeningBatch::new(batch.current().to_vec(), vec![EF::ZERO]);

        assert!(matches!(
            Targets::input_shape(&native),
            Err(VerificationError::InvalidProofShape(_))
        ));
    }

    #[test]
    fn checked_whir_rejects_missing_final_polynomial_before_allocation() {
        let mut native = whir_fixture();
        native.rounds[0].whir.final_poly = None;

        assert!(matches!(
            <Targets as CheckedRecursive<EF>>::validate_input(&native),
            Err(VerificationError::InvalidProofShape(_))
        ));
    }

    #[test]
    fn prepared_whir_query_variant_binds() {
        let native = whir_fixture();
        let mut changed = native.clone();
        let openings = &mut changed.rounds[0].whir.rounds[0].openings;
        *openings = match openings {
            QueryOpenings::Base(opening) => QueryOpenings::Extension(SharedProofOpening {
                rows: opening
                    .rows
                    .iter()
                    .map(|row| row.iter().copied().map(EF::from).collect())
                    .collect(),
                proof: opening.proof.clone(),
            }),
            QueryOpenings::Extension(opening) => QueryOpenings::Base(SharedProofOpening {
                rows: opening
                    .rows
                    .iter()
                    .map(|row| row.iter().map(|_| F::ZERO).collect())
                    .collect(),
                proof: opening.proof.clone(),
            }),
        };

        assert!(Targets::input_shape(&native).unwrap() != Targets::input_shape(&changed).unwrap());
    }

    #[test]
    fn prepared_whir_equal_total_query_partition_differs() {
        let mut left = whir_fixture();
        let mut right = left.clone();
        set_query_rows(&mut left.rounds[0].whir.rounds[0].openings, &[1, 3]);
        set_query_rows(&mut right.rounds[0].whir.rounds[0].openings, &[2, 2]);

        assert!(Targets::input_shape(&left).unwrap() != Targets::input_shape(&right).unwrap());
    }

    #[test]
    fn prepared_whir_sumcheck_pow_count_binds() {
        let native = whir_fixture();
        let mut changed = native.clone();
        changed.rounds[0]
            .whir
            .initial_sumcheck
            .pow_witnesses
            .push(F::ZERO);

        assert!(Targets::input_shape(&native).unwrap() != Targets::input_shape(&changed).unwrap());
    }

    #[test]
    fn prepared_whir_missing_commitment_rejected() {
        let mut native = whir_fixture();
        native.rounds[0].whir.rounds[0].commitment = None;

        assert!(matches!(
            Targets::input_shape(&native),
            Err(VerificationError::InvalidProofShape(_))
        ));
    }

    #[test]
    fn prepared_whir_missing_final_poly_rejected() {
        let mut native = whir_fixture();
        native.rounds[0].whir.final_poly = None;

        assert!(matches!(
            Targets::input_shape(&native),
            Err(VerificationError::InvalidProofShape(_))
        ));
    }

    #[test]
    fn prepared_whir_final_sumcheck_option_binds() {
        let native = whir_fixture();
        assert!(native.rounds[0].whir.final_sumcheck.is_some());
        let mut changed = native.clone();
        changed.rounds[0].whir.final_sumcheck = None;

        assert!(Targets::input_shape(&native).unwrap() != Targets::input_shape(&changed).unwrap());
    }

    #[test]
    fn prepared_whir_outer_round_and_cap_counts_bind() {
        let native = whir_fixture();
        let mut extra_outer = native.clone();
        extra_outer.rounds.push(extra_outer.rounds[0].clone());
        assert!(
            Targets::input_shape(&native).unwrap() != Targets::input_shape(&extra_outer).unwrap()
        );

        let mut wider_cap = native.clone();
        let cap = wider_cap.rounds[0].whir.rounds[0]
            .commitment
            .as_mut()
            .unwrap();
        let root = cap.roots()[0];
        *cap = MerkleCap::new(vec![root; 2]);
        assert!(
            Targets::input_shape(&native).unwrap() != Targets::input_shape(&wider_cap).unwrap()
        );
    }

    #[test]
    fn prepared_whir_frontier_length_is_dynamic() {
        let native = whir_fixture();
        let mut changed = native.clone();
        match &mut changed.rounds[0].whir.final_openings {
            QueryOpenings::Base(opening) => opening.proof.sibling_hashes.push([F::ZERO; 8]),
            QueryOpenings::Extension(opening) => opening.proof.sibling_hashes.push([F::ZERO; 8]),
        }

        assert!(Targets::input_shape(&native).unwrap() == Targets::input_shape(&changed).unwrap());
    }

    #[test]
    fn prepared_whir_rejects_unsupported_digest_packing() {
        assert!(matches!(
            validate_digest_packing(8, 5),
            Err(VerificationError::InvalidProofShape(_))
        ));
        assert!(validate_digest_packing(8, 4).is_ok());
        assert!(validate_digest_packing(8, 1).is_ok());
    }

    #[test]
    fn borrowed_whir_context_checks_statement_axes_before_replay() {
        let (pcs, _commitment, coms, mut proof) = open_two_matrices();
        let context = WhirContextParams::from_native(&pcs.whir_config(8));
        let shapes: Vec<_> = coms
            .iter()
            .map(|(domain, openings)| (domain.log_size(), openings[0].1.len(), openings.len()))
            .collect();
        assert!(
            validate_whir_pcs_context::<F, EF, MyMmcs>(&proof.rounds[0], &context, &shapes,)
                .is_ok()
        );

        proof.rounds[0].evals[0] =
            OpeningBatch::new(proof.rounds[0].evals[0].current().to_vec(), vec![EF::ZERO]);
        assert!(matches!(
            validate_whir_pcs_context::<F, EF, MyMmcs>(&proof.rounds[0], &context, &shapes,),
            Err(VerificationError::InvalidProofShape(_))
        ));
    }

    #[test]
    fn checked_whir_n10_n15_context_binds_last_argument_and_ignored_payload_shape() {
        let (proof, params, layout, caps) = canonical_two_argument_fixture();
        let cap_refs = caps.iter().collect::<Vec<_>>();
        let retained = <Targets as CheckedWhirOpening<F, EF, CapTargets>>::validate_whir_context(
            &proof,
            &params,
            layout.opening_view(),
            &cap_refs,
        )
        .expect("canonical N=10/N=15 structure and following-phase caps validate");

        let mut bad_last = proof.clone();
        match &mut bad_last.rounds[1].whir.final_openings {
            QueryOpenings::Extension(opening) => opening.rows.last_mut().unwrap().pop(),
            QueryOpenings::Base(_) => unreachable!(),
        };
        assert!(
            <Targets as CheckedWhirOpening<F, EF, CapTargets>>::validate_whir_context(
                &bad_last,
                &params,
                layout.opening_view(),
                &cap_refs,
            )
            .is_err()
        );

        let mut fresh_ignored = proof.clone();
        fresh_ignored.rounds[1].whir.final_sumcheck = Some(sc(3, 5));
        assert!(
            <Targets as CheckedWhirOpening<F, EF, CapTargets>>::validate_whir_context(
                &fresh_ignored,
                &params,
                layout.opening_view(),
                &cap_refs,
            )
            .is_ok(),
            "zero-round final payload is semantically ignored"
        );
        assert!(
            <Targets as CheckedWhirOpening<F, EF, CapTargets>>::validate_whir_replacement(
                &fresh_ignored,
                &retained,
                layout.opening_view(),
                &cap_refs,
            )
            .is_err(),
            "a fresh-valid ignored payload still changes an existing circuit's allocation"
        );

        let mut alternate_cap = proof.clone();
        alternate_cap.rounds[1].whir.rounds[0].commitment =
            Some(MerkleCap::new(vec![[F::ZERO; 8]; 2]));
        assert!(
            <Targets as CheckedWhirOpening<F, EF, CapTargets>>::validate_whir_context(
                &alternate_cap,
                &params,
                layout.opening_view(),
                &cap_refs,
            )
            .is_ok(),
            "two roots fit the following phase's 2^13 tree"
        );
        assert!(
            <Targets as CheckedWhirOpening<F, EF, CapTargets>>::validate_whir_replacement(
                &alternate_cap,
                &retained,
                layout.opening_view(),
                &cap_refs,
            )
            .is_err(),
            "fresh-valid alternate cap cardinality cannot replace retained authority"
        );

        let mut ignored_pow = proof.clone();
        ignored_pow.rounds[1]
            .whir
            .initial_sumcheck
            .pow_witnesses
            .push(F::ZERO);
        assert!(
            <Targets as CheckedWhirOpening<F, EF, CapTargets>>::validate_whir_context(
                &ignored_pow,
                &params,
                layout.opening_view(),
                &cap_refs,
            )
            .is_ok()
        );
        assert!(
            <Targets as CheckedWhirOpening<F, EF, CapTargets>>::validate_whir_replacement(
                &ignored_pow,
                &retained,
                layout.opening_view(),
                &cap_refs,
            )
            .is_err()
        );

        let mut wrong_eval = proof.clone();
        wrong_eval.rounds[1].evals.pop();
        let mut wrong_ood = proof.clone();
        wrong_ood.rounds[1].whir.initial_ood_answers.clear();
        let mut wrong_fold = proof.clone();
        wrong_fold.rounds[1].whir.rounds[0]
            .sumcheck
            .polynomial_evaluations
            .push([EF::ZERO; 2]);
        let mut wrong_final = proof.clone();
        wrong_final.rounds[1].whir.final_poly = Some(Poly::new(vec![EF::ZERO; 2]));
        for malformed in [wrong_eval, wrong_ood, wrong_fold, wrong_final] {
            assert!(
                <Targets as CheckedWhirOpening<F, EF, CapTargets>>::validate_whir_context(
                    &malformed,
                    &params,
                    layout.opening_view(),
                    &cap_refs,
                )
                .is_err(),
                "a malformed last commitment must fail the whole-input pass"
            );
        }
    }
}
