use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::cmp::Reverse;

use itertools::Itertools;
use p3_field::{Dup, Field};
use p3_matrix::Dimensions;

use crate::builder::{CircuitBuilder, CircuitBuilderError};
use crate::ops::{PermCall, PermConfig};
use crate::types::ExprId;
use crate::{CircuitError, NonPrimitiveOpId};

/// Given a vector with the openings and dimensions it formats the openings
/// into a vec of size `max_height`, where each entry contains the openings
/// corresponding to that height. Openings for heights that do not exist in the
/// input are empty vectors.
pub fn format_openings<T: Dup + alloc::fmt::Debug>(
    openings: &[Vec<T>],
    dimensions: &[Dimensions],
    max_height_log: usize,
    permutation_config: impl Into<PermConfig>,
) -> Result<Vec<Vec<T>>, CircuitError> {
    let permutation_config: PermConfig = permutation_config.into();
    if openings.len() > 1 << max_height_log {
        return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
            op: permutation_config.npo_type_id(),
            expected: format!("at most {}", max_height_log),
            got: openings.len(),
        });
    }

    let mut heights_tallest_first = dimensions
        .iter()
        .enumerate()
        .sorted_by_key(|(_, dims)| Reverse(dims.height))
        .peekable();

    // Matrix heights that round up to the same power of two must be equal
    if !heights_tallest_first
        .clone()
        .map(|(_, dims)| dims.height)
        .tuple_windows()
        .all(|(curr, next)| curr == next || curr.next_power_of_two() != next.next_power_of_two())
    {
        return Err(CircuitError::InconsistentMatrixHeights {
            details: "Heights that round up to the same power of two must be equal".to_string(),
        });
    }

    let mut formatted_openings = vec![vec![]; max_height_log];
    for (curr_height, opening) in formatted_openings
        .iter_mut()
        .enumerate()
        .map(|(i, leaf)| (1 << (max_height_log - i), leaf))
    {
        // Get the initial height padded to a power of two. As heights_tallest_first is sorted,
        // the initial height will be the maximum height.
        // Returns an error if either:
        //              1. proof.len() != log_max_height
        //              2. heights_tallest_first is empty.
        let new_opening = heights_tallest_first
            .peeking_take_while(|(_, dims)| dims.height.next_power_of_two() == curr_height)
            .flat_map(|(i, _)| openings[i].iter().map(Dup::dup))
            .collect();
        *opening = new_opening;
    }
    Ok(formatted_openings)
}

impl<F: Field> CircuitBuilder<F> {
    /// Verify a Merkle path in the circuit.
    ///
    /// `openings_expr` contains the row digests at each tree level. When its length equals
    /// `directions_expr.len()`, every entry corresponds to a sibling-compression step.
    /// When its length is `directions_expr.len() + 1`, the extra trailing entry is a
    /// **tail digest**: it is compressed into the running hash *after* the last sibling
    /// step but *before* the root comparison. This mirrors the native MMCS behaviour
    /// where matrices at the cap level are injected after the final proof sibling.
    pub fn add_mmcs_verify(
        &mut self,
        permutation_config: impl Into<PermConfig>,
        openings_expr: &[Vec<ExprId>],
        directions_expr: &[ExprId],
        root_expr: &[ExprId],
    ) -> Result<Vec<NonPrimitiveOpId>, CircuitBuilderError> {
        let permutation_config: PermConfig = permutation_config.into();
        let width_ext = permutation_config.width_ext();
        let rate_ext = permutation_config.rate_ext();
        let mut op_ids = Vec::with_capacity(openings_expr.len());
        let mut output = vec![None; width_ext];
        let zero = self.define_const(F::ZERO);

        // When the Merkle cap spans the entire tree there is no authentication path
        // (`path_depth == 0`): the single leaf digest is itself the committed root, so it
        // is connected directly to the claimed root with no compression.
        if directions_expr.is_empty() {
            let leaf: &[ExprId] = openings_expr.first().map_or(&[], Vec::as_slice);
            if leaf.len() != root_expr.len() {
                return Err(CircuitBuilderError::InvalidDimension {
                    expected: leaf.len(),
                    actual: root_expr.len(),
                });
            }
            for (o, r) in leaf.iter().zip(root_expr.iter()) {
                self.connect(*o, *r);
            }
            return Ok(op_ids);
        }

        let has_tail = openings_expr.len() > directions_expr.len()
            && !openings_expr[directions_expr.len()].is_empty();

        let path_openings = &openings_expr[..directions_expr.len()];

        for (i, (row_digest, direction)) in path_openings.iter().zip(directions_expr).enumerate() {
            let is_first = i == 0;
            let is_last_direction = i == directions_expr.len() - 1;
            let is_final = is_last_direction && !has_tail;

            if !is_first && !row_digest.is_empty() {
                let mut inputs = vec![None; width_ext];
                for (j, &d) in row_digest.iter().take(rate_ext).enumerate() {
                    inputs[rate_ext + j] = Some(d);
                }
                let _ = self.add_perm(
                    permutation_config,
                    &PermCall {
                        new_start: false,
                        merkle_path: true,
                        mmcs_bit: Some(zero),
                        mmcs_bit2: None,
                        inputs,
                        out_ctl: vec![false; rate_ext],
                        return_all_outputs: false,
                        mmcs_index_sum: None,
                    },
                )?;
            }

            let mut inputs = vec![None; width_ext];
            if is_first {
                for (j, &d) in row_digest.iter().take(rate_ext).enumerate() {
                    inputs[j] = Some(d);
                }
            }
            let (op_id, maybe_output) = self.add_perm(
                permutation_config,
                &PermCall {
                    new_start: is_first,
                    merkle_path: true,
                    mmcs_bit: Some(*direction),
                    mmcs_bit2: None,
                    inputs,
                    out_ctl: vec![is_final; rate_ext],
                    return_all_outputs: false,
                    mmcs_index_sum: None,
                },
            )?;
            op_ids.push(op_id);
            output = maybe_output;
        }

        if has_tail {
            let tail = &openings_expr[directions_expr.len()];
            let mut inputs = vec![None; width_ext];
            for (j, &t) in tail.iter().take(rate_ext).enumerate() {
                inputs[rate_ext + j] = Some(t);
            }
            let (_, tail_output) = self.add_perm(
                permutation_config,
                &PermCall {
                    new_start: false,
                    merkle_path: true,
                    mmcs_bit: Some(zero),
                    mmcs_bit2: None,
                    inputs,
                    out_ctl: vec![true; rate_ext],
                    return_all_outputs: false,
                    mmcs_index_sum: None,
                },
            )?;
            output = tail_output;
        }

        let output = output
            .into_iter()
            .take(rate_ext)
            .map(|x| {
                x.ok_or_else(|| CircuitBuilderError::MalformedNonPrimitiveOutputs {
                    op_id: *op_ids.last().unwrap(),
                    details: "Expected output from last Poseidon2Perm call".to_string(),
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        // The claimed root must have exactly as many limbs as the computed root digest.
        if output.len() != root_expr.len() {
            return Err(CircuitBuilderError::InvalidDimension {
                expected: output.len(),
                actual: root_expr.len(),
            });
        }
        for (o, r) in output.iter().zip(root_expr.iter()) {
            self.connect(*o, *r);
        }
        Ok(op_ids)
    }

    /// Verify a 4-to-1 (quaternary) MMCS Merkle path in the circuit.
    ///
    /// Issues `1 + directions_expr.len()` permutation rows in a single Merkle
    /// chain, matching native arity-4 MMCS verification:
    ///
    /// 1. **Leaf-hash row** (`new_start = true`, `merkle_path = true`). Absorbs
    ///    `leaf_data` directly into `inputs[0..len]`, runs the wide permutation,
    ///    and the first `capacity_ext` extension limbs of the output become the
    ///    level-0 running hash. The direction bits on this row are unused (no
    ///    chain placement, no index update on `new_start`); they are pinned to a
    ///    zero const.
    /// 2. **Compression rows** (`new_start = false`, `merkle_path = true`, with
    ///    `direction_pair[i]`). The previous row's running hash chains into chunk
    ///    `pos = mmcs_bit + 2 · mmcs_bit2` via the AIR's arity-4 placement
    ///    constraint, and the 3 sibling digests fill the other chunks (provided as
    ///    [`Poseidon2PermPrivateData::sibling`] / [`Poseidon1PermPrivateData::sibling`],
    ///    length `3 · capacity_ext` extension limbs). Their input slots stay empty
    ///    (`in_ctl = false`).
    ///
    /// Returns the op-ids of those `1 + directions_expr.len()` rows in order. The
    /// leaf-hash row gets no sibling private data (it has no siblings); each
    /// compression row gets 3 sibling digests via [`perm_private_data`].
    ///
    /// # Parameters
    /// * `permutation_config` — must satisfy `width_ext == 4 · capacity_ext`
    ///   (e.g. `KOALA_BEAR_D1_W32` / `KOALA_BEAR_D4_W32`).
    /// * `leaf_data` — flattened lifted-EF leaf row data. **Must** fit in
    ///   `rate_ext` slots; multi-chunk leaf hashing is the caller's responsibility
    ///   (the recursion layer sponges down to a single-row digest first).
    /// * `directions_expr[i] = [low, high]` — 2-bit position selector at level `i`.
    /// * `root_expr` — `capacity_ext` extension targets pinned to the native MMCS
    ///   root (the first `capacity_ext · D = DIGEST_ELEMS` base elements form the
    ///   native digest after recomposition).
    pub fn add_mmcs_verify_arity4(
        &mut self,
        permutation_config: impl Into<PermConfig>,
        leaf_data: &[ExprId],
        directions_expr: &[[ExprId; 2]],
        root_expr: &[ExprId],
    ) -> Result<Vec<NonPrimitiveOpId>, CircuitBuilderError> {
        let permutation_config: PermConfig = permutation_config.into();
        let width_ext = permutation_config.width_ext();
        let rate_ext = permutation_config.rate_ext();
        let capacity_ext = permutation_config.capacity_ext();

        if !permutation_config.is_arity4_shape() {
            return Err(CircuitBuilderError::Poseidon2ConfigMismatch {
                expected: "width_ext == 4 * capacity_ext for 4-to-1 MMCS".to_string(),
                got: format!("width_ext = {width_ext}, capacity_ext = {capacity_ext}"),
            });
        }
        if directions_expr.is_empty() {
            return Err(CircuitBuilderError::Poseidon2ConfigMismatch {
                expected: "at least one Merkle level".to_string(),
                got: "no levels provided".to_string(),
            });
        }
        if leaf_data.len() > rate_ext {
            return Err(CircuitBuilderError::Poseidon2ConfigMismatch {
                expected: format!("leaf_data.len() <= rate_ext ({rate_ext})"),
                got: format!(
                    "leaf_data.len() = {}; multi-chunk leaf hashing is not handled here",
                    leaf_data.len()
                ),
            });
        }
        if root_expr.len() != capacity_ext {
            return Err(CircuitBuilderError::InvalidDimension {
                expected: capacity_ext,
                actual: root_expr.len(),
            });
        }

        let zero = self.define_const(F::ZERO);
        let mut op_ids = Vec::with_capacity(1 + directions_expr.len());

        // 1. Leaf-hash row. Absorbs `leaf_data`; its output is the level-0 running
        //    hash. Direction bits are ignored on `new_start = true` rows by both
        //    the placement constraint (gated by `merkle_chain_sel = 0`) and the
        //    index-update recurrence (gated by `not_new_start = 0`); pin them to
        //    zero so callers don't have to allocate dummies.
        let mut leaf_inputs = vec![None; width_ext];
        for (j, &d) in leaf_data.iter().enumerate() {
            leaf_inputs[j] = Some(d);
        }
        let (op_id_leaf, _) = self.add_perm(
            permutation_config,
            &PermCall {
                new_start: true,
                merkle_path: true,
                mmcs_bit: Some(zero),
                mmcs_bit2: Some(zero),
                inputs: leaf_inputs,
                out_ctl: vec![false; rate_ext],
                return_all_outputs: false,
                mmcs_index_sum: None,
            },
        )?;
        op_ids.push(op_id_leaf);

        // 2. Compression rows. The previous row's running hash is chained into
        //    chunk `pos = mmcs_bit + 2 · mmcs_bit2` by the AIR; sibling private
        //    data fills the other 3 chunks. The last row exposes its output via
        //    CTL so we can `connect(...)` it to `root_expr`.
        let mut output: Vec<Option<ExprId>> = vec![None; width_ext];
        for (level, direction_pair) in directions_expr.iter().enumerate() {
            let is_last = level == directions_expr.len() - 1;
            let (op_id, maybe_output) = self.add_perm(
                permutation_config,
                &PermCall {
                    new_start: false,
                    merkle_path: true,
                    mmcs_bit: Some(direction_pair[0]),
                    mmcs_bit2: Some(direction_pair[1]),
                    inputs: vec![None; width_ext],
                    out_ctl: vec![is_last; rate_ext],
                    return_all_outputs: false,
                    mmcs_index_sum: None,
                },
            )?;
            op_ids.push(op_id);
            output = maybe_output;
        }

        // 3. Connect the first `capacity_ext` EF limbs of the final output
        //    (= the native arity-4 digest) to the root.
        for (o, r) in output.iter().take(capacity_ext).zip(root_expr.iter()) {
            self.connect(
                o.ok_or_else(|| CircuitBuilderError::MalformedNonPrimitiveOutputs {
                    op_id: *op_ids.last().unwrap(),
                    details: "Expected output from last arity-4 Poseidon2Perm call".to_string(),
                })?,
                *r,
            );
        }
        Ok(op_ids)
    }
}
