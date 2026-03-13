//! Input resolution logic for Poseidon2 permutation execution.

use alloc::vec;
use alloc::vec::Vec;

use p3_field::Field;

use crate::CircuitError;
use crate::ops::ExecutionContext;
use crate::types::WitnessId;

/// Number of extension elements per slot in 4-ary layout (4 slots over width_ext).
const ARITY_4_SLOTS: usize = 4;

/// Build the complete resolved input array for a Poseidon2 permutation.
///
/// Resolves all width_ext input limbs in one pass, then applies the merkle swap
/// permutation if needed. `pos_in_group` is the position in the group at this level
/// (0 or 1 for binary; 0..4 for 4-ary). For binary the low bit controls swap; for
/// 4-ary with three siblings, state is laid out as four slots with current at
/// pos_in_group and siblings in the other slots.
#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_all_inputs<F: Field>(
    new_start: bool,
    merkle_path: bool,
    pos_in_group: usize,
    inputs: &[Vec<WitnessId>],
    private_inputs: Option<&[F]>,
    ctx: &ExecutionContext<'_, F>,
    last_output: Option<&[F]>,
    width_ext: usize,
    rate_ext: usize,
    merkle_arity: u8,
) -> Result<Vec<F>, CircuitError> {
    let mut resolved = init_base_state(
        new_start,
        merkle_path,
        last_output,
        width_ext,
        rate_ext,
        ctx,
    )?;
    let use_4ary_layout = merkle_arity == 4
        && private_inputs.map(|p| p.len()).unwrap_or(0) == 6
        && width_ext.is_multiple_of(ARITY_4_SLOTS);
    if use_4ary_layout {
        apply_4ary_layout(
            &mut resolved,
            last_output,
            private_inputs.unwrap(),
            pos_in_group,
            width_ext,
        );
    } else {
        apply_private_sibling(
            &mut resolved,
            private_inputs,
            merkle_path,
            rate_ext,
            width_ext,
        );
    }
    apply_ctl_inputs(&mut resolved, inputs, ctx, width_ext)?;
    let swap = merkle_path && !use_4ary_layout && (pos_in_group & 1) != 0;
    apply_merkle_swap(&mut resolved, swap, merkle_path, rate_ext);
    Ok(resolved)
}

/// Initialize the base state: zeros for new_start, or chain from previous output.
fn init_base_state<F: Field>(
    new_start: bool,
    merkle_path: bool,
    last_output: Option<&[F]>,
    width_ext: usize,
    rate_ext: usize,
    ctx: &ExecutionContext<'_, F>,
) -> Result<Vec<F>, CircuitError> {
    let mut resolved = vec![F::ZERO; width_ext];

    if new_start {
        // For non-merkle new_start, all zeros (already done).
        // For merkle new_start, leave capacity as zero (filled by CTL/private later).
        return Ok(resolved);
    }

    let prev = last_output.ok_or_else(|| CircuitError::Poseidon2ChainMissingPreviousState {
        operation_index: ctx.operation_id(),
    })?;

    if merkle_path {
        // In merkle mode, only chain the rate portion from previous output
        let n = rate_ext.min(prev.len());
        resolved[..n].copy_from_slice(&prev[..n]);
    } else {
        // In normal mode, chain the entire state
        let n = width_ext.min(prev.len());
        resolved[..n].copy_from_slice(&prev[..n]);
    }

    Ok(resolved)
}

/// 4-ary layout: four slots of width_ext/4 elements; current at pos_in_group, three siblings elsewhere.
/// private_inputs must have 6 elements (3 siblings × 2 ext). Missing slot bytes are filled with zero.
fn apply_4ary_layout<F: Field>(
    resolved: &mut [F],
    last_output: Option<&[F]>,
    private_inputs: &[F],
    pos_in_group: usize,
    width_ext: usize,
) {
    let slot_size = width_ext / ARITY_4_SLOTS;
    for i in 0..ARITY_4_SLOTS {
        let start = i * slot_size;
        let end = (i + 1) * slot_size;
        if i == pos_in_group {
            if let Some(prev) = last_output {
                let n = slot_size.min(prev.len());
                resolved[start..start + n].copy_from_slice(&prev[..n]);
                for j in n..slot_size {
                    resolved[start + j] = F::ZERO;
                }
            } else {
                for r in resolved.iter_mut().take(end).skip(start) {
                    *r = F::ZERO;
                }
            }
        } else {
            let s = if i < pos_in_group { i } else { i - 1 };
            let src_start = s * 2;
            let n = slot_size
                .min(2)
                .min(private_inputs.len().saturating_sub(src_start));
            resolved[start..start + n].copy_from_slice(&private_inputs[src_start..src_start + n]);
            for j in n..slot_size {
                resolved[start + j] = F::ZERO;
            }
        }
    }
}

/// Fill sibling slots in merkle mode from private data.
fn apply_private_sibling<F: Field>(
    resolved: &mut [F],
    private_inputs: Option<&[F]>,
    merkle_path: bool,
    rate_ext: usize,
    width_ext: usize,
) {
    if let Some(private) = private_inputs
        && merkle_path
    {
        for (i, &p) in private.iter().enumerate().take(rate_ext) {
            if rate_ext + i < width_ext {
                resolved[rate_ext + i] = p;
            }
        }
    }
}

/// Overwrite resolved values with witness values from CTL inputs.
fn apply_ctl_inputs<F: Field>(
    resolved: &mut [F],
    inputs: &[Vec<WitnessId>],
    ctx: &ExecutionContext<'_, F>,
    width_ext: usize,
) -> Result<(), CircuitError> {
    for i in 0..width_ext {
        if inputs.len() > i && inputs[i].len() == 1 {
            let wid = inputs[i][0];
            let val = ctx.get_witness(wid)?;
            resolved[i] = val;
        }
    }
    Ok(())
}

/// Swap rate halves when mmcs_bit=1 in merkle mode.
fn apply_merkle_swap<F: Field>(
    resolved: &mut [F],
    mmcs_bit: bool,
    merkle_path: bool,
    rate_ext: usize,
) {
    if merkle_path && mmcs_bit {
        // Swap the first rate_ext elements with the next rate_ext elements
        for i in 0..rate_ext {
            resolved.swap(i, rate_ext + i);
        }
    }
}
