//! Input resolution logic for Poseidon2 permutation execution.

use alloc::vec;
use alloc::vec::Vec;

use p3_field::Field;

use crate::CircuitError;
use crate::ops::ExecutionContext;
use crate::types::WitnessId;

/// Build the complete resolved input array for a Poseidon2 permutation.
///
/// Resolves all width_ext input limbs in one pass, then applies the merkle swap
/// permutation if needed. For merkle_arity > 2, child layout (current digest +
/// siblings + dummy digests) can be applied in a later step; for 2 we keep the
/// existing binary behaviour (one sibling, mmcs_bit swap).
#[allow(clippy::too_many_arguments)]
pub(crate) fn resolve_all_inputs<F: Field>(
    new_start: bool,
    merkle_path: bool,
    mmcs_bit: bool,
    inputs: &[Vec<WitnessId>],
    private_inputs: Option<&[F]>,
    ctx: &ExecutionContext<'_, F>,
    last_output: Option<&[F]>,
    width_ext: usize,
    rate_ext: usize,
    merkle_arity: u8,
) -> Result<Vec<F>, CircuitError> {
    let _ = merkle_arity;
    let mut resolved = init_base_state(
        new_start,
        merkle_path,
        last_output,
        width_ext,
        rate_ext,
        ctx,
    )?;
    apply_private_sibling(
        &mut resolved,
        private_inputs,
        merkle_path,
        rate_ext,
        width_ext,
    );
    apply_ctl_inputs(&mut resolved, inputs, ctx, width_ext)?;
    apply_merkle_swap(&mut resolved, mmcs_bit, merkle_path, rate_ext);
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
