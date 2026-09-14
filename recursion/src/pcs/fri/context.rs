//! Allocation-free structural validation for native FRI openings.

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use p3_commit::{Mmcs, OpenedValues};
use p3_field::{ExtensionField, PrimeField64, TwoAdicField};
use p3_fri::{BatchMultiOpening, FriProof};

use super::{FriVerifierParams, NativeFriParams};
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

    pub(crate) fn input_cap_roots(&self) -> &[usize] {
        &self.input_cap_roots
    }

    pub(crate) fn phase_cap_roots(&self) -> &[usize] {
        &self.phase_cap_roots
    }

    pub(crate) const fn native_params(&self) -> NativeFriParams {
        self.native
    }

    pub(crate) const fn recursive_params(&self) -> FriVerifierParams {
        self.recursive
    }

    pub(crate) const fn input_salt_elems(&self) -> Option<usize> {
        self.input_salt_elems
    }

    pub(crate) const fn phase_salt_elems(&self) -> Option<usize> {
        self.phase_salt_elems
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
            let effective_base_width = geometry
                .width()
                .checked_add(tail_width)
                .ok_or_else(|| invalid("FRI effective input width overflows"))?;
            let effective_leaf_width = effective_base_width
                .checked_add(input_salt_elems.unwrap_or(0))
                .ok_or_else(|| invalid("FRI salted input width overflows"))?;
            if effective_leaf_width
                .checked_mul(core::mem::size_of::<F>())
                .filter(|bytes| *bytes <= isize::MAX as usize)
                .is_none()
            {
                return Err(invalid("FRI input leaf byte width overflows"));
            }
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
        if grouped_leaf_widths.iter().any(|width| {
            width
                .checked_mul(core::mem::size_of::<F>())
                .is_none_or(|bytes| bytes > isize::MAX as usize)
        }) {
            return Err(invalid("FRI grouped input leaf byte width overflows"));
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
        let phase_leaf_width = checked_pow2(arity, "fold arity")?
            .checked_mul(EF::DIMENSION)
            .and_then(|width| width.checked_add(phase_salt_elems.unwrap_or(0)))
            .ok_or_else(|| invalid("FRI phase leaf width overflows"))?;
        if phase_leaf_width
            .checked_mul(core::mem::size_of::<EF>())
            .filter(|bytes| *bytes <= isize::MAX as usize)
            .is_none()
        {
            return Err(invalid("FRI phase leaf byte width overflows"));
        }
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
    let view = layout;
    if input_caps.len() != view.commitment_count() {
        return Err(invalid(format!(
            "FRI input cap count mismatch: expected {}, got {}",
            view.commitment_count(),
            input_caps.len()
        )));
    }
    let phase_cap_count = proof.commit_phase_commits.len();
    let core = validate_fri_borrowed(
        proof,
        native,
        recursive,
        view,
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
    let mut input_cap_roots = Vec::with_capacity(input_caps.len());
    for (ordinal, cap) in input_caps.iter().enumerate() {
        let heights = view.matrices(ordinal).map(|matrix| {
            let log_height = matrix
                .log_height()
                .checked_add(native.log_blowup())
                .unwrap_or(0);
            checked_pow2(log_height, "input cap height").unwrap_or(0)
        });
        let roots = C::validate_fri_cap(cap, permutation, index_bit_len, heights)?;
        input_cap_roots.push(roots);
    }

    let mut phase_cap_roots = Vec::with_capacity(phase_cap_count);
    let mut current = index_bit_len;
    for (round, cap) in proof.commit_phase_commits.iter().enumerate() {
        let arity = proof.commit_phase_openings[round].log_arity as usize;
        current = current
            .checked_sub(arity)
            .ok_or_else(|| invalid("FRI phase schedule underflows"))?;
        let height = checked_pow2(current, "phase cap height")?;
        let roots = PC::validate_fri_cap(cap, permutation, index_bit_len, [height].into_iter())?;
        phase_cap_roots.push(roots);
    }

    // Salt metadata is static adapter authority; actual rows are checked by
    // the built-in raw multiproof adapters before this function is called.
    if input_salt_elems == Some(0) || phase_salt_elems == Some(0) {
        // Some(0) is a valid native representation; retain it distinctly from
        // None and leave row-level acceptance to the raw adapter.
    }

    let hiding_tail_shape = hiding_tails
        .map(|tails| validate_hiding_tail_partition(view, tails))
        .transpose()?;
    let input_matrix_counts = (0..view.commitment_count())
        .map(|ordinal| {
            view.matrix_count(ordinal)
                .map_err(|error| invalid(error.to_string()))
        })
        .collect::<Result<_, _>>()?;

    Ok(ValidatedFriContext {
        native: *native,
        recursive: *recursive,
        layout: layout.to_owned_layout(),
        permutation,
        native_query_count: core.query_count,
        log_arities: proof
            .commit_phase_openings
            .iter()
            .map(|opening| opening.log_arity as usize)
            .collect(),
        input_matrix_counts,
        input_cap_roots,
        phase_cap_roots,
        input_salt_elems,
        phase_salt_elems,
        hiding_tail_shape,
    })
}
