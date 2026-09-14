//! Allocation-free structural validation for native FRI openings.

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use p3_commit::{Mmcs, OpenedValues};
use p3_field::{ExtensionField, PrimeField64, TwoAdicField};
use p3_fri::{BatchMultiOpening, FriProof};

use super::{FriVerifierParams, NativeFriParams};
use crate::Target;
use crate::input_contract::FriOpeningLayout;
use crate::input_contract::stark_layout::NativeStarkLayout;
use crate::ops::PermConfig;
use crate::pcs::fri::targets::MerkleCapTargets;
use crate::traits::CheckedRecursive;
use crate::verifier::VerificationError;

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
/// The implementation deliberately receives a borrowed cap and returns only
/// its root count.  It never copies cap entries or acquires an MMCS instance.
pub trait CheckedFriCommitment<EF: p3_field::Field>: CheckedRecursive<EF> {
    fn validate_fri_cap<I>(
        input: &Self::Input,
        permutation: PermConfig,
        index_bit_len: usize,
        heights: I,
    ) -> Result<usize, VerificationError>
    where
        I: Iterator<Item = usize> + Clone;
}

/// Narrow checked opening capability for the built-in FRI target composition.
/// Input caps are supplied by the caller; phase caps are read from the proof
/// itself and validated with the exact phase commitment adapter.
pub trait CheckedFriOpening<EF: p3_field::Field, C: CheckedFriCommitment<EF>>:
    CheckedRecursive<EF>
{
    type PhaseCommitment: CheckedFriCommitment<EF>;

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
        Ok(input.num_roots())
    }
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

#[allow(dead_code)]
pub(crate) fn checked_flat_value_totals(
    query_count: usize,
    input_per_query: usize,
    phase_per_query: usize,
    hiding_tail_total: usize,
    phase_cap_values: usize,
    phase_count: usize,
    final_poly_len: usize,
) -> Result<(usize, usize), VerificationError> {
    let per_query = checked_add_len(input_per_query, phase_per_query, "private per-query")?;
    let private_values = checked_mul_len(query_count, per_query, "private value total")?;
    let private_values = checked_add_len(private_values, hiding_tail_total, "private tail total")?;
    let public_values = checked_add_len(phase_cap_values, phase_count, "public phase values")?;
    let public_values = checked_add_len(public_values, final_poly_len, "public final polynomial")?;
    let public_values = checked_add_len(public_values, 1, "public query witness")?;
    Ok((private_values, public_values))
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
        for width in grouped_leaf_widths {
            check_vec_len::<F>(width, "grouped input leaf")?;
            check_vec_len::<Target>(width, "grouped target input leaf")?;
        }
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
#[allow(clippy::too_many_arguments)]
fn validate_fri_borrowed_with_caps<F, EF, IM, FM, W, C, PC>(
    proof: &FriProof<EF, FM, W, Vec<BatchMultiOpening<F, IM>>>,
    native: &NativeFriParams,
    recursive: &FriVerifierParams,
    layout: FriOpeningLayout<'_>,
    input_caps: &[&C::Input],
    input_salt_elems: Option<usize>,
    phase_salt_elems: Option<usize>,
    hiding_tails: Option<&OpenedValues<EF>>,
) -> Result<CapValidation, VerificationError>
where
    F: TwoAdicField + PrimeField64,
    EF: ExtensionField<F>,
    IM: Mmcs<F, Commitment = C::Input>,
    FM: Mmcs<EF, Commitment = PC::Input>,
    C: CheckedFriCommitment<EF>,
    PC: CheckedFriCommitment<EF>,
{
    let permutation = recursive.permutation_config.ok_or_else(|| {
        invalid("checked FRI context requires a recursive MMCS permutation configuration")
    })?;
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
        input_roots[ordinal] = C::validate_fri_cap(cap, permutation, index_bit_len, heights)?;
    }

    let mut phase_roots = [0usize; usize::BITS as usize];
    let mut current = index_bit_len;
    for (round, cap) in proof.commit_phase_commits.iter().enumerate() {
        let arity = proof.commit_phase_openings[round].log_arity as usize;
        current = current
            .checked_sub(arity)
            .ok_or_else(|| invalid("FRI phase schedule underflows"))?;
        let height = checked_pow2(current, "phase cap height")?;
        phase_roots[round] =
            PC::validate_fri_cap(cap, permutation, index_bit_len, [height].into_iter())?;
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
pub(crate) fn validate_fri_context_with_caps<F, EF, IM, FM, W, C, PC>(
    proof: &FriProof<EF, FM, W, Vec<BatchMultiOpening<F, IM>>>,
    native: &NativeFriParams,
    recursive: &FriVerifierParams,
    layout: FriOpeningLayout<'_>,
    input_caps: &[&C::Input],
    input_salt_elems: Option<usize>,
    phase_salt_elems: Option<usize>,
    hiding_tails: Option<&OpenedValues<EF>>,
) -> Result<ValidatedFriContext, VerificationError>
where
    F: TwoAdicField + PrimeField64,
    EF: ExtensionField<F>,
    IM: Mmcs<F, Commitment = C::Input>,
    FM: Mmcs<EF, Commitment = PC::Input>,
    C: CheckedFriCommitment<EF>,
    PC: CheckedFriCommitment<EF>,
{
    let permutation = recursive.permutation_config.ok_or_else(|| {
        invalid("checked FRI context requires a recursive MMCS permutation configuration")
    })?;
    let validated = validate_fri_borrowed_with_caps::<F, EF, IM, FM, W, C, PC>(
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
pub(crate) fn validate_fri_replacement_with_caps<F, EF, IM, FM, W, C, PC>(
    proof: &FriProof<EF, FM, W, Vec<BatchMultiOpening<F, IM>>>,
    native: &NativeFriParams,
    recursive: &FriVerifierParams,
    expected: &ValidatedFriContext,
    candidate_layout: FriOpeningLayout<'_>,
    input_caps: &[&C::Input],
    input_salt_elems: Option<usize>,
    phase_salt_elems: Option<usize>,
    hiding_tails: Option<&OpenedValues<EF>>,
) -> Result<(), VerificationError>
where
    F: TwoAdicField + PrimeField64,
    EF: ExtensionField<F>,
    IM: Mmcs<F, Commitment = C::Input>,
    FM: Mmcs<EF, Commitment = PC::Input>,
    C: CheckedFriCommitment<EF>,
    PC: CheckedFriCommitment<EF>,
{
    if !candidate_layout.matches_layout(expected.layout()) {
        return Err(invalid("FRI retained layout mismatch"));
    }
    let validated = validate_fri_borrowed_with_caps::<F, EF, IM, FM, W, C, PC>(
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
