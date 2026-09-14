//! Allocation-free structural validation for native FRI openings.

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use p3_commit::{Mmcs, OpenedValues};
use p3_field::{ExtensionField, PrimeField64, TwoAdicField};
use p3_fri::{BatchMultiOpening, FriProof};

use super::{FriVerifierParams, NativeFriParams};
use crate::input_contract::stark_layout::NativeStarkLayout;
use crate::input_contract::{FriMatrixGeometry, FriOpeningLayout};
use crate::ops::PermConfig;
use crate::pcs::fri::targets::MerkleCapTargets;
use crate::traits::CheckedRecursive;
use crate::verifier::VerificationError;

/// The scalar/layout result of the legacy context checker.
///
/// This is intentionally not public API and carries no commitment authority;
/// the checked adapter below only constructs [`ValidatedFriContext`] after it
/// has validated the borrowed input and phase caps.
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

fn layout_matrices(
    layout: FriOpeningLayout<'_>,
) -> Result<Vec<Vec<FriMatrixGeometry>>, VerificationError> {
    (0..layout.commitment_count())
        .map(|ordinal| {
            let expected = layout
                .matrix_count(ordinal)
                .map_err(|error| invalid(error.to_string()))?;
            let matrices: Vec<_> = layout.matrices(ordinal).collect();
            if matrices.len() != expected || matrices.is_empty() {
                return Err(invalid(format!(
                    "FRI commitment {ordinal} matrix count mismatch: expected {expected}, got {}",
                    matrices.len()
                )));
            }
            Ok(matrices)
        })
        .collect()
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
        for (matrix, points) in tail_round.iter().enumerate() {
            let expected_points = layout
                .matrices(ordinal)
                .nth(matrix)
                .map(|m| m.point_count());
            if expected_points != Some(points.len()) {
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

/// Validate the complete native-vs-recursive FRI shape without transcript work,
/// target allocation, challenger sampling, or PCS/MMCS cloning.
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

    let matrices = layout_matrices(layout)?;
    if proof.input_openings.len() != matrices.len() {
        return Err(invalid(format!(
            "FRI input batch count mismatch: expected {}, got {}",
            matrices.len(),
            proof.input_openings.len()
        )));
    }
    let mut max_input_height = 0usize;
    let mut input_matrix_counts = Vec::with_capacity(matrices.len());
    for (batch, batch_matrices) in matrices.iter().enumerate() {
        input_matrix_counts.push(batch_matrices.len());
        for matrix in batch_matrices {
            let lde_height = matrix
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
        }
        let opened = &proof.input_openings[batch].opened_values;
        if opened.len() != query_count {
            return Err(invalid(format!(
                "FRI input batch {batch} query count mismatch: expected {query_count}, got {}",
                opened.len()
            )));
        }
        for (query, rows) in opened.iter().enumerate() {
            if rows.len() != batch_matrices.len() {
                return Err(invalid(format!(
                    "FRI input batch {batch} query {query} matrix count mismatch: expected {}, got {}",
                    batch_matrices.len(),
                    rows.len()
                )));
            }
            for (matrix, (row, geometry)) in rows.iter().zip(batch_matrices).enumerate() {
                if geometry.point_count() == 0 {
                    return Err(invalid(format!(
                        "FRI input batch {batch} matrix {matrix} has no opening points"
                    )));
                }
                if row.len() != geometry.width() {
                    return Err(invalid(format!(
                        "FRI input batch {batch} query {query} matrix {matrix} width mismatch: expected {}, got {}",
                        geometry.width(),
                        row.len()
                    )));
                }
            }
        }
    }
    if max_input_height == 0 {
        return Err(invalid("FRI has no non-empty input matrix"));
    }
    let mut log_arities = Vec::with_capacity(proof.commit_phase_openings.len());
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
        total_reduction = total_reduction
            .checked_add(arity)
            .ok_or_else(|| invalid("FRI fold schedule overflows"))?;
        log_arities.push(arity);
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
    let mut reached = Vec::with_capacity(log_arities.len() + 1);
    let mut current = global_height;
    reached.push(current);
    for arity in &log_arities {
        current = current
            .checked_sub(*arity)
            .ok_or_else(|| invalid("FRI fold schedule exceeds input height"))?;
        reached.push(current);
    }
    for batch in &matrices {
        for matrix in batch {
            let height = matrix
                .log_height()
                .checked_add(native.log_blowup())
                .ok_or_else(|| invalid("FRI matrix LDE height overflows"))?;
            if !reached.contains(&height) {
                return Err(invalid(format!(
                    "FRI matrix LDE height {height} is not reached by fold schedule"
                )));
            }
        }
    }

    let hiding_tail_shape = if let Some(tails) = hiding_tails {
        if tails.len() != matrices.len() {
            return Err(invalid("Hiding FRI tail round count mismatch"));
        }
        let mut shape = Vec::with_capacity(tails.len());
        for (round, (tail_round, batch_matrices)) in tails.iter().zip(&matrices).enumerate() {
            if tail_round.len() != batch_matrices.len() {
                return Err(invalid(format!(
                    "Hiding FRI tail round {round} matrix count mismatch"
                )));
            }
            let mut matrices_shape = Vec::with_capacity(tail_round.len());
            for (matrix, (tail_matrix, geometry)) in
                tail_round.iter().zip(batch_matrices).enumerate()
            {
                if tail_matrix.len() != geometry.point_count() {
                    return Err(invalid(format!(
                        "Hiding FRI tail round {round} matrix {matrix} point count mismatch"
                    )));
                }
                matrices_shape.push(tail_matrix.iter().map(Vec::len).collect());
            }
            shape.push(matrices_shape);
        }
        Some(shape)
    } else {
        None
    };

    let _ = perm;
    Ok(FriContextShape {
        native_query_count: query_count,
        log_arities,
        input_matrix_counts,
        hiding_tail_shape,
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
    phase_caps: &[&PC::Input],
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
    let owned_layout = layout.to_owned_layout();
    let view = owned_layout.opening_view();
    let shape = validate_fri_context_core(proof, native, recursive, view, permutation, None)?;

    if input_caps.len() != view.commitment_count() {
        return Err(invalid(format!(
            "FRI input cap count mismatch: expected {}, got {}",
            view.commitment_count(),
            input_caps.len()
        )));
    }
    if phase_caps.len() != proof.commit_phase_commits.len() {
        return Err(invalid("FRI phase cap count mismatch"));
    }

    let index_bit_len = shape
        .log_arities
        .iter()
        .try_fold(native.log_blowup(), |total, arity| {
            total.checked_add(*arity)
        })
        .and_then(|total| total.checked_add(native.log_final_poly_len()))
        .ok_or_else(|| invalid("FRI index-bit length overflows"))?;
    let mut input_cap_roots = Vec::with_capacity(input_caps.len());
    for (ordinal, cap) in input_caps.iter().enumerate() {
        let heights = view.matrices(ordinal).map(|matrix| {
            let log_height = matrix
                .log_height()
                .checked_add(native.log_blowup())
                .ok_or_else(|| invalid("FRI input LDE height overflows"))?;
            checked_pow2(log_height, "input cap height")
        });
        let heights = heights.collect::<Result<Vec<_>, _>>()?;
        let roots = C::validate_fri_cap(cap, permutation, index_bit_len, heights.iter().copied())?;
        input_cap_roots.push(roots);
    }

    let mut phase_cap_roots = Vec::with_capacity(phase_caps.len());
    let mut current = index_bit_len
        .checked_sub(native.log_blowup())
        .and_then(|height| height.checked_sub(native.log_final_poly_len()))
        .ok_or_else(|| invalid("FRI phase schedule underflows"))?;
    for (round, cap) in phase_caps.iter().enumerate() {
        let arity = shape.log_arities[round];
        current = current
            .checked_sub(arity)
            .ok_or_else(|| invalid("FRI phase schedule underflows"))?;
        let height = checked_pow2(
            current
                .checked_add(native.log_final_poly_len())
                .ok_or_else(|| invalid("FRI phase cap height overflows"))?,
            "phase cap height",
        )?;
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

    Ok(ValidatedFriContext {
        native: *native,
        recursive: *recursive,
        layout: owned_layout,
        permutation,
        native_query_count: shape.native_query_count,
        log_arities: shape.log_arities,
        input_matrix_counts: shape.input_matrix_counts,
        input_cap_roots,
        phase_cap_roots,
        input_salt_elems,
        phase_salt_elems,
        hiding_tail_shape,
    })
}
