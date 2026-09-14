//! Allocation-free structural validation for native FRI openings.

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;
#[cfg(test)]
use core::cell::Cell;

use p3_commit::{Mmcs, OpenedValues};
use p3_field::{ExtensionField, PrimeField64, TwoAdicField};
use p3_fri::{BatchMultiOpening, FriProof};

use super::{FriVerifierParams, NativeFriParams};
use crate::Target;
use crate::input_contract::FriOpeningLayout;
use crate::input_contract::stark_layout::NativeStarkLayout;
use crate::ops::PermConfig;
use crate::pcs::fri::targets::{FriPrivateAdvice, InputProofTargets, MerkleCapTargets};
use crate::traits::{CheckedRecursive, RecursiveExtensionMmcs, RecursiveMmcs};
use crate::verifier::{InputResourceUsage, VerificationError, VerifierLimits};

#[cfg(test)]
std::thread_local! {
    static FRI_FINISHER_CALLS: Cell<usize> = const { Cell::new(0) };
}

#[cfg(test)]
pub(crate) fn reset_fri_finisher_calls() {
    FRI_FINISHER_CALLS.with(|calls| calls.set(0));
}

#[cfg(test)]
pub(crate) fn fri_finisher_calls() -> usize {
    FRI_FINISHER_CALLS.with(Cell::get)
}

/// The scalar/layout result of the legacy context checker.
///
/// This is intentionally not public API and carries no commitment authority;
/// the checked adapter below only constructs [`ValidatedFriContext`] after it
/// has validated the borrowed input and phase caps.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct FriContextShape {
    native_query_count: usize,
    log_arities: Vec<usize>,
    input_matrix_counts: Vec<usize>,
    hiding_tail_shape: Option<Vec<Vec<Vec<usize>>>>,
}

/// Compact authority retained after complete native FRI validation.
///
/// The owned layout is only the small statement-routing metadata.  Proof
/// values, frontiers, PCS/MMCS instances, challengers, and RNG state are never
/// retained here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedFriContext {
    native: NativeFriParams,
    recursive: FriVerifierParams,
    layout: NativeStarkLayout<'static>,
    permutation: PermConfig,
    native_query_count: usize,
    log_arities: Vec<usize>,
    input_matrix_counts: Vec<usize>,
    input_cap_roots: Vec<usize>,
    phase_cap_roots: Vec<usize>,
    input_salt_elems: Option<usize>,
    phase_salt_elems: Option<usize>,
    hiding_tail_shape: Option<Vec<Vec<Vec<usize>>>>,
}

impl ValidatedFriContext {
    pub const fn native_query_count(&self) -> usize {
        self.native_query_count
    }

    pub fn log_arities(&self) -> &[usize] {
        &self.log_arities
    }

    pub fn input_matrix_counts(&self) -> &[usize] {
        &self.input_matrix_counts
    }

    pub fn hiding_tail_shape(&self) -> Option<&[Vec<Vec<usize>>]> {
        self.hiding_tail_shape.as_deref()
    }

    pub(crate) const fn layout(&self) -> &NativeStarkLayout<'static> {
        &self.layout
    }

    pub(crate) const fn native_params(&self) -> NativeFriParams {
        self.native
    }

    pub(crate) const fn recursive_params(&self) -> FriVerifierParams {
        self.recursive
    }
}

/// Checked commitment geometry used by the complete FRI adapter.
///
/// `checked_fri_public_values_len` is the exact length of this commitment's
/// `Recursive::get_values` output. Implementations must validate the borrowed
/// cap without extraction, copying, allocation, or PCS/MMCS access; custom
/// implementations are trusted declarations of that contract.
pub trait CheckedFriCommitment<EF: p3_field::Field>: CheckedRecursive<EF> {
    fn checked_fri_public_values_len(input: &Self::Input) -> Result<usize, VerificationError>;

    fn checked_fri_cap_roots(input: &Self::Input) -> Result<usize, VerificationError>;

    fn validate_fri_cap<I>(
        input: &Self::Input,
        permutation: PermConfig,
        index_bit_len: usize,
        heights: I,
    ) -> Result<usize, VerificationError>
    where
        I: Iterator<Item = usize> + Clone;
}

pub(crate) fn checked_cap_public_values_len<EF: p3_field::Field>(
    roots: usize,
    digest_elements: usize,
) -> Result<usize, VerificationError> {
    let count = checked_mul_len(roots, digest_elements, "cap lifted public values")?;
    check_vec_len::<EF>(count, "cap lifted public values")?;
    Ok(count)
}

/// Narrow checked opening capability for the built-in FRI target composition.
/// Input caps are supplied by the caller; phase caps are read from the proof
/// itself and validated with the exact phase commitment adapter.
pub trait CheckedFriOpening<EF: p3_field::Field, C: CheckedFriCommitment<EF>>:
    CheckedRecursive<EF>
{
    type PhaseCommitment: CheckedFriCommitment<EF>;

    /// Walk every proof-owned resource consumed by the built-in FRI targets.
    /// This is a borrowed, allocation-free capability of the audited ordinary
    /// and hiding Merkle compositions, not a promise for arbitrary targets.
    fn check_fri_resources(
        input: &Self::Input,
        limits: &VerifierLimits,
    ) -> Result<InputResourceUsage, VerificationError>;

    fn validate_fri_context(
        input: &Self::Input,
        native: &NativeFriParams,
        recursive: &FriVerifierParams,
        layout: FriOpeningLayout<'_>,
        input_caps: &[&C::Input],
    ) -> Result<ValidatedFriContext, VerificationError>;

    fn validate_fri_replacement(
        input: &Self::Input,
        expected: &ValidatedFriContext,
        candidate_layout: FriOpeningLayout<'_>,
        input_caps: &[&C::Input],
    ) -> Result<(), VerificationError>;
}

impl<F, EF, const DIGEST_ELEMS: usize> CheckedFriCommitment<EF>
    for MerkleCapTargets<F, DIGEST_ELEMS>
where
    F: p3_field::Field,
    EF: ExtensionField<F>,
{
    fn checked_fri_public_values_len(input: &Self::Input) -> Result<usize, VerificationError> {
        <Self as CheckedRecursive<EF>>::validate_input(input)?;
        checked_cap_public_values_len::<EF>(input.num_roots(), DIGEST_ELEMS)
    }

    fn checked_fri_cap_roots(input: &Self::Input) -> Result<usize, VerificationError> {
        <Self as CheckedRecursive<EF>>::validate_input(input)?;
        Ok(input.num_roots())
    }

    fn validate_fri_cap<I>(
        input: &Self::Input,
        permutation: PermConfig,
        index_bit_len: usize,
        heights: I,
    ) -> Result<usize, VerificationError>
    where
        I: Iterator<Item = usize> + Clone,
    {
        super::targets::validate_merkle_cap_context::<F, EF, DIGEST_ELEMS, I>(
            input,
            permutation,
            index_bit_len,
            heights,
        )?;
        <Self as CheckedFriCommitment<EF>>::checked_fri_public_values_len(input)?;
        Ok(input.num_roots())
    }
}

#[allow(clippy::type_complexity)]
pub(crate) fn check_fri_resource_limits<F, EF, RI, RF>(
    proof: &FriProof<EF, RF::Input, F, Vec<BatchMultiOpening<F, RI::Input>>>,
    hiding_tails: Option<&OpenedValues<EF>>,
    limits: &VerifierLimits,
) -> Result<InputResourceUsage, VerificationError>
where
    F: p3_field::Field,
    EF: ExtensionField<F>,
    RI: crate::traits::RecursiveMmcs<F, EF>,
    RF: crate::traits::RecursiveExtensionMmcs<F, EF>,
    RI::Proof: FriPrivateAdvice<EF, MultiProof = <RI::Input as Mmcs<F>>::MultiProof>,
    RF::Proof: FriPrivateAdvice<EF, MultiProof = <RF::Input as Mmcs<EF>>::MultiProof>,
    RF::Commitment: CheckedFriCommitment<EF, Input = <RF::Input as Mmcs<EF>>::Commitment>,
{
    let mut usage = InputResourceUsage::default();
    usage.add_rounds(
        limits,
        proof
            .commit_phase_openings
            .len()
            .max(proof.commit_phase_commits.len())
            .max(proof.commit_pow_witnesses.len()),
    )?;

    for batch in &proof.input_openings {
        usage.add_query_round(limits, batch.opened_values.len())?;
        for query in &batch.opened_values {
            for row in query {
                usage.check_matrix_width(limits, row.len())?;
                usage.add_scalar_elements(limits, row.len())?;
            }
        }
        <RI::Proof as FriPrivateAdvice<EF>>::add_private_resource_usage(
            &batch.opening_proof,
            &mut usage,
            limits,
        )?;
        usage.add_compressed_frontier_hashes(
            limits,
            <RI::Proof as FriPrivateAdvice<EF>>::compressed_frontier_hashes(&batch.opening_proof),
        )?;
    }

    for step in &proof.commit_phase_openings {
        usage.check_log_degree(limits, step.log_arity as usize)?;
        usage.add_query_round(limits, step.sibling_values.len())?;
        for row in &step.sibling_values {
            usage.check_matrix_width(limits, row.len())?;
            let coefficients = row.len().checked_mul(EF::DIMENSION).ok_or(
                VerificationError::ResourceArithmeticOverflow {
                    component: "scalar elements",
                },
            )?;
            usage.add_scalar_elements(limits, coefficients)?;
        }
        <RF::Proof as FriPrivateAdvice<EF>>::add_private_resource_usage(
            &step.opening_proof,
            &mut usage,
            limits,
        )?;
        usage.add_compressed_frontier_hashes(
            limits,
            <RF::Proof as FriPrivateAdvice<EF>>::compressed_frontier_hashes(&step.opening_proof),
        )?;
    }

    // Count commitments independently of openings. A malformed proof may have
    // unequal phase-vector lengths; resource accounting must still see every
    // supplied cap before contextual validation reports that mismatch.
    for commitment in &proof.commit_phase_commits {
        usage.add_cap_roots(limits, RF::Commitment::checked_fri_cap_roots(commitment)?)?;
        usage.add_scalar_elements(
            limits,
            RF::Commitment::checked_fri_public_values_len(commitment)?,
        )?;
    }

    if let Some(tails) = hiding_tails {
        for round in tails {
            for matrix in round {
                for point in matrix {
                    usage.check_matrix_width(limits, point.len())?;
                    usage.add_scalar_elements(limits, point.len())?;
                }
            }
        }
    }

    usage.add_final_poly_evaluations(limits, proof.final_poly.len())?;
    usage.add_scalar_elements(limits, proof.final_poly.len())?;
    usage.add_scalar_elements(limits, proof.commit_pow_witnesses.len())?;
    usage.add_scalar_elements(limits, 1)?;
    usage.check(limits)?;
    Ok(usage)
}

fn invalid(message: impl Into<alloc::string::String>) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}

fn checked_pow2(value: usize, label: &str) -> Result<usize, VerificationError> {
    if value >= usize::BITS as usize {
        return Err(invalid(format!("FRI {label} log exceeds machine word")));
    }
    1usize
        .checked_shl(value as u32)
        .ok_or_else(|| invalid(format!("FRI {label} height overflows")))
}

pub(crate) fn checked_add_len(
    left: usize,
    right: usize,
    label: &str,
) -> Result<usize, VerificationError> {
    left.checked_add(right)
        .ok_or_else(|| invalid(format!("FRI {label} length overflows")))
}

pub(crate) fn checked_mul_len(
    left: usize,
    right: usize,
    label: &str,
) -> Result<usize, VerificationError> {
    left.checked_mul(right)
        .ok_or_else(|| invalid(format!("FRI {label} length overflows")))
}

pub(crate) fn check_vec_len<T>(len: usize, label: &str) -> Result<(), VerificationError> {
    let bytes = checked_mul_len(len, core::mem::size_of::<T>(), label)?;
    if bytes > isize::MAX as usize {
        return Err(invalid(format!(
            "FRI {label} byte length is not representable"
        )));
    }
    Ok(())
}

pub(crate) fn checked_input_counts(
    base_width: usize,
    tail_width: usize,
    salt_width: usize,
) -> Result<(usize, usize), VerificationError> {
    let raw = checked_add_len(base_width, tail_width, "input raw width")?;
    let salted = checked_add_len(raw, salt_width, "input salted width")?;
    Ok((raw, salted))
}

pub(crate) fn checked_phase_counts(
    arity: usize,
    extension_dimension: usize,
    salt_width: usize,
) -> Result<(usize, usize, usize), VerificationError> {
    let full_base = checked_mul_len(arity, extension_dimension, "phase full width")?;
    let full_base = checked_add_len(full_base, salt_width, "phase salted width")?;
    let sibling_count = arity
        .checked_sub(1)
        .ok_or_else(|| invalid("FRI phase sibling count underflows"))?;
    let sibling_coefficients =
        checked_mul_len(sibling_count, extension_dimension, "phase sibling width")?;
    let private_values = checked_add_len(sibling_coefficients, salt_width, "phase private width")?;
    Ok((full_base, sibling_coefficients, private_values))
}

/// Check the per-height recursive target buffers used by grouped input leaves.
/// Native F groups stream their slices; only the recursive Target buffers are
/// materialized, and each height owns a separate buffer.
pub(crate) fn check_grouped_target_leaf_widths(
    grouped_leaf_widths: &[usize],
) -> Result<(), VerificationError> {
    for &width in grouped_leaf_widths {
        check_vec_len::<Target>(width, "grouped target input leaf")?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FriValueCounts {
    private_values: usize,
    public_values: usize,
}

impl FriValueCounts {
    #[allow(dead_code)]
    pub(crate) const fn private_values(self) -> usize {
        self.private_values
    }

    #[allow(dead_code)]
    pub(crate) const fn public_values(self) -> usize {
        self.public_values
    }
}

pub(crate) fn checked_flat_value_totals<EF: p3_field::Field>(
    input_private_total: usize,
    phase_private_total: usize,
    hiding_tail_total: usize,
    phase_cap_public_total: usize,
    commit_witness_count: usize,
    final_poly_len: usize,
) -> Result<FriValueCounts, VerificationError> {
    #[cfg(test)]
    FRI_FINISHER_CALLS.with(|calls| calls.set(calls.get().saturating_add(1)));
    let private_values = checked_add_len(
        input_private_total,
        phase_private_total,
        "private input and phase values",
    )?;
    let private_values = checked_add_len(private_values, hiding_tail_total, "private tail total")?;
    let public_values = checked_add_len(
        phase_cap_public_total,
        commit_witness_count,
        "public phase caps and witnesses",
    )?;
    let public_values = checked_add_len(public_values, final_poly_len, "public final polynomial")?;
    let public_values = checked_add_len(public_values, 1, "public query witness")?;
    check_vec_len::<EF>(private_values, "FRI private values")?;
    check_vec_len::<EF>(public_values, "FRI public values")?;
    Ok(FriValueCounts {
        private_values,
        public_values,
    })
}

#[allow(clippy::type_complexity)]
pub(crate) fn validate_counted_fri_raw<F, EF, RI, RF>(
    proof: &FriProof<EF, RF::Input, F, Vec<BatchMultiOpening<F, RI::Input>>>,
    hiding_tails: Option<&OpenedValues<EF>>,
    input_salt_elems: Option<usize>,
    phase_salt_elems: Option<usize>,
) -> Result<FriValueCounts, VerificationError>
where
    F: p3_field::Field,
    EF: ExtensionField<F>,
    RI: crate::traits::RecursiveMmcs<F, EF>,
    RF: crate::traits::RecursiveExtensionMmcs<F, EF>,
    RI::Proof: FriPrivateAdvice<EF, MultiProof = <RI::Input as Mmcs<F>>::MultiProof>,
    RF::Proof: FriPrivateAdvice<EF, MultiProof = <RF::Input as Mmcs<EF>>::MultiProof>,
    RF::Commitment: CheckedFriCommitment<EF, Input = <RF::Input as Mmcs<EF>>::Commitment>,
{
    super::targets::validate_builtin_fri_raw::<F, EF, RF, RI, crate::pcs::fri::targets::Witness<F>>(
        proof,
        input_salt_elems,
        phase_salt_elems,
    )?;
    crate::pcs::fri::targets::validate_fri_input::<
        F,
        EF,
        RF,
        InputProofTargets<F, EF, RI>,
        crate::pcs::fri::targets::Witness<F>,
    >(proof)?;

    let mut input_private_total = 0usize;
    for batch in &proof.input_openings {
        for query in &batch.opened_values {
            for row in query {
                input_private_total =
                    checked_add_len(input_private_total, row.len(), "FRI input row values")?;
            }
        }
        input_private_total = checked_add_len(
            input_private_total,
            <RI::Proof as FriPrivateAdvice<EF>>::checked_private_values_len(&batch.opening_proof)?,
            "FRI input advice values",
        )?;
    }

    let mut phase_private_total = 0usize;
    for step in &proof.commit_phase_openings {
        for row in &step.sibling_values {
            let coefficients =
                checked_mul_len(row.len(), EF::DIMENSION, "FRI phase sibling coefficients")?;
            phase_private_total = checked_add_len(
                phase_private_total,
                coefficients,
                "FRI phase sibling values",
            )?;
        }
        phase_private_total = checked_add_len(
            phase_private_total,
            <RF::Proof as FriPrivateAdvice<EF>>::checked_private_values_len(&step.opening_proof)?,
            "FRI phase advice values",
        )?;
    }

    let mut hiding_tail_total = 0usize;
    if let Some(tails) = hiding_tails {
        for round in tails {
            for matrix in round {
                for point in matrix {
                    hiding_tail_total =
                        checked_add_len(hiding_tail_total, point.len(), "FRI hiding tail values")?;
                }
            }
        }
    }

    let mut phase_cap_public_total = 0usize;
    for cap in &proof.commit_phase_commits {
        phase_cap_public_total = checked_add_len(
            phase_cap_public_total,
            RF::Commitment::checked_fri_public_values_len(cap)?,
            "FRI phase cap public values",
        )?;
    }

    checked_flat_value_totals::<EF>(
        input_private_total,
        phase_private_total,
        hiding_tail_total,
        phase_cap_public_total,
        proof.commit_pow_witnesses.len(),
        proof.final_poly.len(),
    )
}

fn validate_hiding_tail_partition(
    layout: FriOpeningLayout<'_>,
    tails: &OpenedValues<impl p3_field::Field>,
) -> Result<Vec<Vec<Vec<usize>>>, VerificationError> {
    if tails.len() != layout.commitment_count() {
        return Err(invalid("Hiding FRI tail commitment count mismatch"));
    }
    let mut shape = Vec::with_capacity(tails.len());
    for (ordinal, tail_round) in tails.iter().enumerate() {
        let expected = layout
            .matrix_count(ordinal)
            .map_err(|error| invalid(error.to_string()))?;
        if tail_round.len() != expected {
            return Err(invalid(format!(
                "Hiding FRI tail matrix count mismatch at commitment {ordinal}"
            )));
        }
        let mut round_shape = Vec::with_capacity(tail_round.len());
        for (matrix, (geometry, points)) in layout.matrices(ordinal).zip(tail_round).enumerate() {
            let expected_points = geometry.point_count();
            if expected_points != points.len() {
                return Err(invalid(format!(
                    "Hiding FRI tail point count mismatch at commitment {ordinal} matrix {matrix}"
                )));
            }
            let widths = points.iter().map(Vec::len).collect::<Vec<_>>();
            if widths.windows(2).any(|window| window[0] != window[1]) {
                return Err(invalid("Hiding FRI tail point widths disagree"));
            }
            round_shape.push(widths);
        }
        shape.push(round_shape);
    }
    Ok(shape)
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CoreValidation {
    query_count: usize,
    max_input_log: usize,
    total_reduction: usize,
    has_input_matrix: bool,
}

const MAX_FRI_COMMITMENTS: usize = 5;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CapValidation {
    core: CoreValidation,
    input_roots: [usize; MAX_FRI_COMMITMENTS],
    input_root_count: usize,
    phase_roots: [usize; usize::BITS as usize],
    phase_root_count: usize,
}

fn validate_hiding_tail_partition_borrowed(
    layout: FriOpeningLayout<'_>,
    tails: &OpenedValues<impl p3_field::Field>,
) -> Result<(), VerificationError> {
    if tails.len() != layout.commitment_count() {
        return Err(invalid("Hiding FRI tail commitment count mismatch"));
    }
    for (ordinal, tail_round) in tails.iter().enumerate() {
        let expected = layout
            .matrix_count(ordinal)
            .map_err(|error| invalid(error.to_string()))?;
        if tail_round.len() != expected {
            return Err(invalid(format!(
                "Hiding FRI tail matrix count mismatch at commitment {ordinal}"
            )));
        }
        for (matrix, (geometry, points)) in layout.matrices(ordinal).zip(tail_round).enumerate() {
            if geometry.point_count() != points.len() {
                return Err(invalid(format!(
                    "Hiding FRI tail point count mismatch at commitment {ordinal} matrix {matrix}"
                )));
            }
            let width = points.first().map_or(0, Vec::len);
            if points.iter().any(|point| point.len() != width) {
                return Err(invalid("Hiding FRI tail point widths disagree"));
            }
        }
    }
    Ok(())
}

/// Validate the complete native-vs-recursive FRI shape without transcript work,
/// target allocation, challenger sampling, or PCS/MMCS cloning.
#[allow(dead_code)]
pub(crate) fn validate_fri_context_core<F, EF, IM, FM, W>(
    proof: &FriProof<EF, FM, W, Vec<BatchMultiOpening<F, IM>>>,
    native: &NativeFriParams,
    recursive: &FriVerifierParams,
    layout: FriOpeningLayout<'_>,
    perm: PermConfig,
    hiding_tails: Option<&OpenedValues<EF>>,
) -> Result<FriContextShape, VerificationError>
where
    F: TwoAdicField + PrimeField64,
    EF: ExtensionField<F>,
    IM: Mmcs<F>,
    FM: Mmcs<EF>,
{
    let core = validate_fri_borrowed(
        proof,
        native,
        recursive,
        layout,
        perm,
        hiding_tails,
        None,
        None,
    )?;
    let log_arities = proof
        .commit_phase_openings
        .iter()
        .map(|opening| opening.log_arity as usize)
        .collect();
    let input_matrix_counts = (0..layout.commitment_count())
        .map(|ordinal| {
            layout
                .matrix_count(ordinal)
                .map_err(|error| invalid(error.to_string()))
        })
        .collect::<Result<_, _>>()?;
    Ok(FriContextShape {
        native_query_count: core.query_count,
        log_arities,
        input_matrix_counts,
        hiding_tail_shape: hiding_tails
            .map(|tails| validate_hiding_tail_partition(layout, tails))
            .transpose()?,
    })
}

#[allow(clippy::too_many_arguments)]
fn validate_fri_borrowed<F, EF, IM, FM, W>(
    proof: &FriProof<EF, FM, W, Vec<BatchMultiOpening<F, IM>>>,
    native: &NativeFriParams,
    recursive: &FriVerifierParams,
    layout: FriOpeningLayout<'_>,
    perm: PermConfig,
    hiding_tails: Option<&OpenedValues<EF>>,
    input_salt_elems: Option<usize>,
    phase_salt_elems: Option<usize>,
) -> Result<CoreValidation, VerificationError>
where
    F: TwoAdicField + PrimeField64,
    EF: ExtensionField<F>,
    IM: Mmcs<F>,
    FM: Mmcs<EF>,
{
    native
        .validate_field::<F>()
        .map_err(|error| invalid(format!("invalid native FRI parameters: {error}")))?;
    native
        .validate_recursive(recursive)
        .map_err(|error| invalid(format!("native/recursive FRI mismatch: {error}")))?;

    if let Some(tails) = hiding_tails {
        validate_hiding_tail_partition_borrowed(layout, tails)?;
    }

    let query_count = native.num_queries();
    if proof.commit_phase_commits.len() != proof.commit_phase_openings.len()
        || proof.commit_phase_commits.len() != proof.commit_pow_witnesses.len()
    {
        return Err(invalid("FRI commit phase list counts disagree"));
    }
    let final_len = checked_pow2(native.log_final_poly_len(), "final polynomial")?;
    if proof.final_poly.len() != final_len {
        return Err(invalid(format!(
            "FRI final polynomial length mismatch: expected {final_len}, got {}",
            proof.final_poly.len()
        )));
    }

    let commitment_count = layout.commitment_count();
    if proof.input_openings.len() != commitment_count {
        return Err(invalid(format!(
            "FRI input batch count mismatch: expected {}, got {}",
            commitment_count,
            proof.input_openings.len()
        )));
    }
    let mut max_input_height = 0usize;
    let mut has_input_matrix = false;
    for batch in 0..commitment_count {
        let expected_matrix_count = layout
            .matrix_count(batch)
            .map_err(|error| invalid(error.to_string()))?;
        if expected_matrix_count == 0 {
            return Err(invalid(format!(
                "FRI commitment {batch} has no planned matrices"
            )));
        }
        let batch_matrices = layout.matrices(batch);
        let opened = &proof.input_openings[batch].opened_values;
        if opened.len() != query_count {
            return Err(invalid(format!(
                "FRI input batch {batch} query count mismatch: expected {query_count}, got {}",
                opened.len()
            )));
        }
        for (query, rows) in opened.iter().enumerate() {
            if rows.len() != expected_matrix_count {
                return Err(invalid(format!(
                    "FRI input batch {batch} query {query} matrix count mismatch: expected {expected_matrix_count}, got {}",
                    rows.len()
                )));
            }
        }
        // Compare the untrusted proof rows before traversing a potentially
        // enormous quotient-matrix iterator. A malformed tiny proof must
        // reject from its explicit row axis without touching that metadata.
        let actual_matrix_count = batch_matrices.clone().count();
        if actual_matrix_count != expected_matrix_count {
            return Err(invalid(format!(
                "FRI commitment {batch} matrix count mismatch: expected {expected_matrix_count}, got {actual_matrix_count}"
            )));
        }
        let mut grouped_leaf_widths = [0usize; usize::BITS as usize + 1];
        for (matrix, geometry) in batch_matrices.enumerate() {
            let lde_height = geometry
                .log_height()
                .checked_add(native.log_blowup())
                .ok_or_else(|| invalid("FRI input LDE height overflows"))?;
            if lde_height > F::TWO_ADICITY {
                return Err(invalid(format!(
                    "FRI input batch {batch} exceeds field two-adicity"
                )));
            }
            checked_pow2(lde_height, "input LDE")?;
            max_input_height = max_input_height.max(lde_height);
            has_input_matrix = true;
            let tail_points =
                hiding_tails.map(|tails| tails.get(batch).and_then(|round| round.get(matrix)));
            let tail_width = if let Some(Some(points)) = tail_points {
                if points.len() != geometry.point_count() || points.is_empty() {
                    return Err(invalid(format!(
                        "Hiding FRI tail point count mismatch at commitment {batch} matrix {matrix}"
                    )));
                }
                let width = points[0].len();
                if points.iter().any(|point| point.len() != width) {
                    return Err(invalid("Hiding FRI tail point widths disagree"));
                }
                width
            } else if hiding_tails.is_some() {
                return Err(invalid("Hiding FRI tail matrix is missing"));
            } else {
                0
            };
            let (effective_base_width, effective_leaf_width) =
                checked_input_counts(geometry.width(), tail_width, input_salt_elems.unwrap_or(0))?;
            check_vec_len::<F>(effective_leaf_width, "input leaf")?;
            check_vec_len::<EF>(effective_leaf_width, "lifted input private")?;
            grouped_leaf_widths[lde_height] = grouped_leaf_widths[lde_height]
                .checked_add(effective_leaf_width)
                .ok_or_else(|| invalid("FRI grouped input leaf width overflows"))?;
            for (query, rows) in opened.iter().enumerate() {
                let row = &rows[matrix];
                if geometry.point_count() == 0 {
                    return Err(invalid(format!(
                        "FRI input batch {batch} matrix {matrix} has no opening points"
                    )));
                }
                if row.len() != effective_base_width {
                    return Err(invalid(format!(
                        "FRI input batch {batch} query {query} matrix {matrix} width mismatch: expected {effective_base_width}, got {}",
                        row.len()
                    )));
                }
            }
        }
        check_grouped_target_leaf_widths(&grouped_leaf_widths)?;
    }
    if !has_input_matrix {
        return Err(invalid("FRI has no non-empty input matrix"));
    }
    let mut total_reduction = 0usize;
    for (round, opening) in proof.commit_phase_openings.iter().enumerate() {
        let arity = opening
            .checked_log_arity(native.max_log_arity())
            .ok_or_else(|| {
                invalid(format!(
                    "FRI round {round} has invalid log_arity {}",
                    opening.log_arity
                ))
            })?;
        checked_pow2(arity, "fold arity")?;
        if opening.sibling_values.len() != query_count {
            return Err(invalid(format!(
                "FRI round {round} query count mismatch: expected {query_count}, got {}",
                opening.sibling_values.len()
            )));
        }
        let sibling_width = checked_pow2(arity, "fold arity")?
            .checked_sub(1)
            .ok_or_else(|| invalid("FRI fold sibling width underflows"))?;
        if opening
            .sibling_values
            .iter()
            .any(|row| row.len() != sibling_width)
        {
            return Err(invalid(format!("FRI round {round} sibling width mismatch")));
        }
        let arity_width = checked_pow2(arity, "fold arity")?;
        let (phase_leaf_width, sibling_coefficients, private_values) =
            checked_phase_counts(arity_width, EF::DIMENSION, phase_salt_elems.unwrap_or(0))?;
        check_vec_len::<F>(phase_leaf_width, "phase base leaf")?;
        check_vec_len::<EF>(private_values, "phase private values")?;
        check_vec_len::<Target>(sibling_coefficients, "phase sibling targets")?;
        total_reduction = total_reduction
            .checked_add(arity)
            .ok_or_else(|| invalid("FRI fold schedule overflows"))?;
    }

    let global_height = total_reduction
        .checked_add(native.log_blowup())
        .and_then(|height| height.checked_add(native.log_final_poly_len()))
        .ok_or_else(|| invalid("FRI global height overflows"))?;
    if global_height > F::TWO_ADICITY {
        return Err(invalid("FRI global height exceeds field two-adicity"));
    }
    if global_height != max_input_height {
        return Err(invalid(format!(
            "FRI global/input height mismatch: expected {max_input_height}, got {global_height}"
        )));
    }
    for batch in 0..commitment_count {
        for matrix in layout.matrices(batch) {
            let height = matrix
                .log_height()
                .checked_add(native.log_blowup())
                .ok_or_else(|| invalid("FRI matrix LDE height overflows"))?;
            let mut reached = global_height;
            let mut landed = height == reached;
            for opening in &proof.commit_phase_openings {
                reached = reached
                    .checked_sub(opening.log_arity as usize)
                    .ok_or_else(|| invalid("FRI fold schedule exceeds input height"))?;
                landed |= height == reached;
            }
            if !landed {
                return Err(invalid(format!(
                    "FRI matrix LDE height {height} is not reached by fold schedule"
                )));
            }
        }
    }

    let _ = perm;
    Ok(CoreValidation {
        query_count,
        max_input_log: max_input_height,
        total_reduction,
        has_input_matrix,
    })
}

/// Complete, cap-authoritative context validation used by checked FRI entry
/// points.  The old scalar checker is intentionally kept separate so legacy
/// arithmetic-only tests cannot mint this authority without real caps.
#[allow(clippy::too_many_arguments, clippy::type_complexity)]
fn validate_fri_borrowed_with_caps<F, EF, RI, RF>(
    proof: &FriProof<EF, RF::Input, F, Vec<BatchMultiOpening<F, RI::Input>>>,
    native: &NativeFriParams,
    recursive: &FriVerifierParams,
    layout: FriOpeningLayout<'_>,
    input_caps: &[&<RI::Commitment as crate::traits::Recursive<EF>>::Input],
    input_salt_elems: Option<usize>,
    phase_salt_elems: Option<usize>,
    hiding_tails: Option<&OpenedValues<EF>>,
) -> Result<CapValidation, VerificationError>
where
    F: TwoAdicField + PrimeField64,
    EF: ExtensionField<F>,
    RI: RecursiveMmcs<F, EF>,
    RF: RecursiveExtensionMmcs<F, EF>,
    RI::Proof: FriPrivateAdvice<EF, MultiProof = <RI::Input as Mmcs<F>>::MultiProof>,
    RF::Proof: FriPrivateAdvice<EF, MultiProof = <RF::Input as Mmcs<EF>>::MultiProof>,
    RI::Commitment: CheckedFriCommitment<EF>,
    RF::Commitment: CheckedFriCommitment<EF, Input = <RF::Input as Mmcs<EF>>::Commitment>,
{
    validate_counted_fri_raw::<F, EF, RI, RF>(
        proof,
        hiding_tails,
        input_salt_elems,
        phase_salt_elems,
    )?;
    let permutation = recursive.permutation_config();
    let commitment_count = layout.commitment_count();
    if commitment_count > MAX_FRI_COMMITMENTS {
        return Err(invalid("FRI commitment role count exceeds checked maximum"));
    }
    if input_caps.len() != commitment_count {
        return Err(invalid(format!(
            "FRI input cap count mismatch: expected {commitment_count}, got {}",
            input_caps.len()
        )));
    }
    let phase_cap_count = proof.commit_phase_commits.len();
    if phase_cap_count > usize::BITS as usize {
        return Err(invalid(
            "FRI phase count exceeds checked machine-word bound",
        ));
    }

    let core = validate_fri_borrowed(
        proof,
        native,
        recursive,
        layout,
        permutation,
        hiding_tails,
        input_salt_elems,
        phase_salt_elems,
    )?;
    let index_bit_len = core
        .total_reduction
        .checked_add(native.log_blowup())
        .and_then(|total| total.checked_add(native.log_final_poly_len()))
        .ok_or_else(|| invalid("FRI index-bit length overflows"))?;

    let mut input_roots = [0usize; MAX_FRI_COMMITMENTS];
    for (ordinal, cap) in input_caps.iter().enumerate() {
        let heights = layout.matrices(ordinal).map(|matrix| {
            let log_height = matrix
                .log_height()
                .checked_add(native.log_blowup())
                .unwrap_or(0);
            checked_pow2(log_height, "input cap height").unwrap_or(0)
        });
        input_roots[ordinal] =
            RI::Commitment::validate_fri_cap(cap, permutation, index_bit_len, heights)?;
    }

    let mut phase_roots = [0usize; usize::BITS as usize];
    let mut current = index_bit_len;
    for (round, cap) in proof.commit_phase_commits.iter().enumerate() {
        let arity = proof.commit_phase_openings[round].log_arity as usize;
        current = current
            .checked_sub(arity)
            .ok_or_else(|| invalid("FRI phase schedule underflows"))?;
        let height = checked_pow2(current, "phase cap height")?;
        phase_roots[round] = RF::Commitment::validate_fri_cap(
            cap,
            permutation,
            index_bit_len,
            [height].into_iter(),
        )?;
    }

    Ok(CapValidation {
        core,
        input_roots,
        input_root_count: commitment_count,
        phase_roots,
        phase_root_count: phase_cap_count,
    })
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub(crate) fn validate_fri_context_with_caps<F, EF, RI, RF>(
    proof: &FriProof<EF, RF::Input, F, Vec<BatchMultiOpening<F, RI::Input>>>,
    native: &NativeFriParams,
    recursive: &FriVerifierParams,
    layout: FriOpeningLayout<'_>,
    input_caps: &[&<RI::Commitment as crate::traits::Recursive<EF>>::Input],
    input_salt_elems: Option<usize>,
    phase_salt_elems: Option<usize>,
    hiding_tails: Option<&OpenedValues<EF>>,
) -> Result<ValidatedFriContext, VerificationError>
where
    F: TwoAdicField + PrimeField64,
    EF: ExtensionField<F>,
    RI: RecursiveMmcs<F, EF>,
    RF: RecursiveExtensionMmcs<F, EF>,
    RI::Proof: FriPrivateAdvice<EF, MultiProof = <RI::Input as Mmcs<F>>::MultiProof>,
    RF::Proof: FriPrivateAdvice<EF, MultiProof = <RF::Input as Mmcs<EF>>::MultiProof>,
    RI::Commitment: CheckedFriCommitment<EF>,
    RF::Commitment: CheckedFriCommitment<EF, Input = <RF::Input as Mmcs<EF>>::Commitment>,
{
    let permutation = recursive.permutation_config();
    let validated = validate_fri_borrowed_with_caps::<F, EF, RI, RF>(
        proof,
        native,
        recursive,
        layout,
        input_caps,
        input_salt_elems,
        phase_salt_elems,
        hiding_tails,
    )?;

    // Salt metadata is static adapter authority; actual rows are checked by
    // the built-in raw multiproof adapters before this function is called.
    if input_salt_elems == Some(0) || phase_salt_elems == Some(0) {
        // Some(0) is a valid native representation; retain it distinctly from
        // None and leave row-level acceptance to the raw adapter.
    }

    let hiding_tail_shape = hiding_tails
        .map(|tails| validate_hiding_tail_partition(layout, tails))
        .transpose()?;
    let input_matrix_counts = (0..layout.commitment_count())
        .map(|ordinal| {
            layout
                .matrix_count(ordinal)
                .map_err(|error| invalid(error.to_string()))
        })
        .collect::<Result<_, _>>()?;

    Ok(ValidatedFriContext {
        native: *native,
        recursive: *recursive,
        layout: layout.to_owned_layout(),
        permutation,
        native_query_count: validated.core.query_count,
        log_arities: proof
            .commit_phase_openings
            .iter()
            .map(|opening| opening.log_arity as usize)
            .collect(),
        input_matrix_counts,
        input_cap_roots: validated.input_roots[..validated.input_root_count].to_vec(),
        phase_cap_roots: validated.phase_roots[..validated.phase_root_count].to_vec(),
        input_salt_elems,
        phase_salt_elems,
        hiding_tail_shape,
    })
}

fn validate_hiding_tail_compatibility(
    tails: Option<&OpenedValues<impl p3_field::Field>>,
    expected: &Option<Vec<Vec<Vec<usize>>>>,
) -> Result<(), VerificationError> {
    match (tails, expected) {
        (None, None) => Ok(()),
        (Some(_), None) | (None, Some(_)) => {
            Err(invalid("FRI retained hiding-tail presence mismatch"))
        }
        (Some(tails), Some(expected)) => {
            if tails.len() != expected.len() {
                return Err(invalid(
                    "FRI retained hiding-tail commitment count mismatch",
                ));
            }
            for (ordinal, (tail_round, expected_round)) in
                tails.iter().zip(expected.iter()).enumerate()
            {
                if tail_round.len() != expected_round.len() {
                    return Err(invalid(format!(
                        "FRI retained hiding-tail matrix count mismatch at commitment {ordinal}"
                    )));
                }
                for (matrix, (points, expected_points)) in
                    tail_round.iter().zip(expected_round.iter()).enumerate()
                {
                    if points.len() != expected_points.len()
                        || points
                            .iter()
                            .zip(expected_points.iter())
                            .any(|(point, width)| point.len() != *width)
                    {
                        return Err(invalid(format!(
                            "FRI retained hiding-tail point partition mismatch at commitment {ordinal} matrix {matrix}"
                        )));
                    }
                }
            }
            Ok(())
        }
    }
}

#[allow(clippy::too_many_arguments)]
#[allow(clippy::type_complexity)]
pub(crate) fn validate_fri_replacement_with_caps<F, EF, RI, RF>(
    proof: &FriProof<EF, RF::Input, F, Vec<BatchMultiOpening<F, RI::Input>>>,
    native: &NativeFriParams,
    recursive: &FriVerifierParams,
    expected: &ValidatedFriContext,
    candidate_layout: FriOpeningLayout<'_>,
    input_caps: &[&<RI::Commitment as crate::traits::Recursive<EF>>::Input],
    input_salt_elems: Option<usize>,
    phase_salt_elems: Option<usize>,
    hiding_tails: Option<&OpenedValues<EF>>,
) -> Result<(), VerificationError>
where
    F: TwoAdicField + PrimeField64,
    EF: ExtensionField<F>,
    RI: RecursiveMmcs<F, EF>,
    RF: RecursiveExtensionMmcs<F, EF>,
    RI::Proof: FriPrivateAdvice<EF, MultiProof = <RI::Input as Mmcs<F>>::MultiProof>,
    RF::Proof: FriPrivateAdvice<EF, MultiProof = <RF::Input as Mmcs<EF>>::MultiProof>,
    RI::Commitment: CheckedFriCommitment<EF>,
    RF::Commitment: CheckedFriCommitment<EF, Input = <RF::Input as Mmcs<EF>>::Commitment>,
{
    if !candidate_layout.matches_layout(expected.layout()) {
        return Err(invalid("FRI retained layout mismatch"));
    }
    let validated = validate_fri_borrowed_with_caps::<F, EF, RI, RF>(
        proof,
        native,
        recursive,
        candidate_layout,
        input_caps,
        input_salt_elems,
        phase_salt_elems,
        hiding_tails,
    )?;
    if validated.core.query_count != expected.native_query_count
        || input_salt_elems != expected.input_salt_elems
        || phase_salt_elems != expected.phase_salt_elems
    {
        return Err(invalid("FRI retained scalar metadata mismatch"));
    }
    if validated.input_roots[..validated.input_root_count] != expected.input_cap_roots
        || validated.phase_roots[..validated.phase_root_count] != expected.phase_cap_roots
    {
        return Err(invalid("FRI retained cap root count mismatch"));
    }
    if proof.commit_phase_openings.len() != expected.log_arities.len()
        || proof
            .commit_phase_openings
            .iter()
            .map(|opening| opening.log_arity as usize)
            .ne(expected.log_arities.iter().copied())
    {
        return Err(invalid("FRI retained fold schedule mismatch"));
    }
    if candidate_layout.commitment_count() != expected.input_matrix_counts.len()
        || (0..candidate_layout.commitment_count()).any(|ordinal| {
            candidate_layout.matrix_count(ordinal).ok()
                != expected.input_matrix_counts.get(ordinal).copied()
        })
    {
        return Err(invalid("FRI retained matrix partition mismatch"));
    }
    validate_hiding_tail_compatibility(hiding_tails, &expected.hiding_tail_shape)
}
