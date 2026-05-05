use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::cmp::Reverse;

use itertools::Itertools;
use p3_field::{Dup, Field};
use p3_matrix::Dimensions;

use crate::builder::{CircuitBuilder, CircuitBuilderError};
use crate::ops::{NpoTypeId, Poseidon2Config, Poseidon2PermCall};
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
    permutation_config: Poseidon2Config,
) -> Result<Vec<Vec<T>>, CircuitError> {
    if openings.len() > 1 << max_height_log {
        return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
            op: NpoTypeId::poseidon2_perm(permutation_config),
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

/// Number of rounds per Blake3 compression.
const BLAKE3_ROUNDS_PER_COMPRESSION: usize = 8;
/// Number of 16-bit limbs in the Blake3 chaining value output.
const BLAKE3_CV_LIMBS: usize = 16;

impl<F: Field> CircuitBuilder<F> {
    /// Verify a Blake3 Merkle membership proof in the circuit.
    ///
    /// Emits `depth` compressions (each 8 round ops). Every compression uses
    /// `new_start = true` (parent-node compression always starts from IV).
    /// The final compression exposes its cv_out via CTL and connects it to
    /// `root_expr`.
    ///
    /// Returns all op IDs (8 * depth total) so the caller can set
    /// [`Blake3PrivateData`](crate::ops::blake3::Blake3PrivateData) for each
    /// round. The 64-byte message per compression is supplied as 8 rounds of
    /// 8 bytes each via private data.
    pub fn add_blake3_merkle_verify(
        &mut self,
        depth: usize,
        root_expr: &[ExprId],
    ) -> Result<Vec<NonPrimitiveOpId>, CircuitBuilderError> {
        use crate::ops::blake3::call::Blake3Call;

        let mut op_ids = Vec::with_capacity(depth * BLAKE3_ROUNDS_PER_COMPRESSION);

        for level in 0..depth {
            let is_final_level = level == depth - 1;

            for round in 0..BLAKE3_ROUNDS_PER_COMPRESSION {
                let is_first_round = round == 0;
                let is_last_round = round == BLAKE3_ROUNDS_PER_COMPRESSION - 1;

                let (op_id, outputs) = self.add_blake3_round(&Blake3Call {
                    new_start: true,
                    is_new_blake: is_first_round,
                    is_hash_output: is_last_round && is_final_level,
                    inputs: vec![None; BLAKE3_CV_LIMBS],
                })?;
                op_ids.push(op_id);

                if is_last_round && is_final_level {
                    for (o, r) in outputs.iter().zip(root_expr.iter()) {
                        let out = o.ok_or_else(|| {
                            CircuitBuilderError::MalformedNonPrimitiveOutputs {
                                op_id,
                                details: "Expected output from last Blake3 round".into(),
                            }
                        })?;
                        self.connect(out, *r);
                    }
                }
            }
        }
        Ok(op_ids)
    }
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
        permutation_config: Poseidon2Config,
        openings_expr: &[Vec<ExprId>],
        directions_expr: &[ExprId],
        root_expr: &[ExprId],
    ) -> Result<Vec<NonPrimitiveOpId>, CircuitBuilderError> {
        let width_ext = permutation_config.width_ext();
        let rate_ext = permutation_config.rate_ext();
        let mut op_ids = Vec::with_capacity(openings_expr.len());
        let mut output = vec![None; width_ext];
        let zero = self.define_const(F::ZERO);

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
                let _ = self.add_poseidon2_perm(&Poseidon2PermCall {
                    config: permutation_config,
                    new_start: false,
                    merkle_path: true,
                    mmcs_bit: Some(zero),
                    inputs,
                    out_ctl: vec![false; rate_ext],
                    return_all_outputs: false,
                    mmcs_index_sum: None,
                })?;
            }

            let mut inputs = vec![None; width_ext];
            if is_first {
                for (j, &d) in row_digest.iter().take(rate_ext).enumerate() {
                    inputs[j] = Some(d);
                }
            }
            let (op_id, maybe_output) = self.add_poseidon2_perm(&Poseidon2PermCall {
                config: permutation_config,
                new_start: is_first,
                merkle_path: true,
                mmcs_bit: Some(*direction),
                inputs,
                out_ctl: vec![is_final; rate_ext],
                return_all_outputs: false,
                mmcs_index_sum: None,
            })?;
            op_ids.push(op_id);
            output = maybe_output;
        }

        if has_tail {
            let tail = &openings_expr[directions_expr.len()];
            let mut inputs = vec![None; width_ext];
            for (j, &t) in tail.iter().take(rate_ext).enumerate() {
                inputs[rate_ext + j] = Some(t);
            }
            let (_, tail_output) = self.add_poseidon2_perm(&Poseidon2PermCall {
                config: permutation_config,
                new_start: false,
                merkle_path: true,
                mmcs_bit: Some(zero),
                inputs,
                out_ctl: vec![true; rate_ext],
                return_all_outputs: false,
                mmcs_index_sum: None,
            })?;
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
        for (o, r) in output.iter().zip(root_expr.iter()) {
            self.connect(*o, *r);
        }
        Ok(op_ids)
    }
}
