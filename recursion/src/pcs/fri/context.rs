//! Allocation-free structural validation for native FRI openings.

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

use p3_commit::{Mmcs, OpenedValues};
use p3_field::{ExtensionField, PrimeField64, TwoAdicField};
use p3_fri::{BatchMultiOpening, FriProof};

use super::{FriVerifierParams, NativeFriParams};
use crate::input_contract::{FriMatrixGeometry, FriOpeningLayout};
use crate::ops::PermConfig;
use crate::verifier::VerificationError;

/// Compact context retained after pure FRI validation for later checked packing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedFriContext {
    native_query_count: usize,
    log_arities: Vec<usize>,
    input_matrix_counts: Vec<usize>,
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
            let matrices: Vec<_> = layout.matrices(ordinal).collect();
            if matrices.is_empty() {
                return Err(invalid(format!(
                    "FRI commitment {ordinal} has no planned matrices"
                )));
            }
            Ok(matrices)
        })
        .collect()
}

/// Validate the complete native-vs-recursive FRI shape without transcript work,
/// target allocation, challenger sampling, or PCS/MMCS cloning.
pub fn validate_fri_context<F, EF, IM, FM, W>(
    proof: &FriProof<EF, FM, W, Vec<BatchMultiOpening<F, IM>>>,
    native: &NativeFriParams,
    recursive: &FriVerifierParams,
    layout: FriOpeningLayout<'_>,
    perm: PermConfig,
    hiding_tails: Option<&OpenedValues<EF>>,
) -> Result<ValidatedFriContext, VerificationError>
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
    let domain_heights: Vec<_> = matrices
        .iter()
        .flat_map(|batch| batch.iter())
        .map(|matrix| {
            checked_pow2(
                matrix
                    .log_height()
                    .checked_add(native.log_blowup())
                    .ok_or_else(|| invalid("FRI input domain height overflows"))?,
                "input domain",
            )
        })
        .collect::<Result<_, _>>()?;
    if perm.is_arity4_shape() {
        crate::pcs::mmcs::validate_arity4_cap_geometry(&domain_heights, 1)
            .map_err(|error| invalid(error.to_string()))?;
    } else {
        crate::pcs::mmcs::validate_binary_cap_count(1, max_input_height)
            .map_err(|error| invalid(error.to_string()))?;
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

    Ok(ValidatedFriContext {
        native_query_count: query_count,
        log_arities,
        input_matrix_counts,
        hiding_tail_shape,
    })
}
