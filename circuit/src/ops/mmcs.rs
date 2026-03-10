use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::cmp::Reverse;

use itertools::Itertools;
use p3_field::Field;
use p3_matrix::Dimensions;

use crate::builder::{CircuitBuilder, CircuitBuilderError};
use crate::op::{NpoTypeId, Poseidon2Config};
use crate::ops::Poseidon2PermCall;
use crate::types::ExprId;
use crate::{CircuitError, NonPrimitiveOpId};

/// Given a vector with the openings and dimensions it formats the openings
/// into a vec of size `max_height`, where each entry contains the openings
/// corresponding to that height. Openings for heights that do not exist in the
/// input are empty vectors.
pub fn format_openings<T: Clone + alloc::fmt::Debug>(
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
            .flat_map(|(i, _)| openings[i].clone())
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

    /// Verify a 4-ary Merkle path in the circuit.
    ///
    /// Uses 4-to-1 Poseidon2 compression. Consumes 2 index bits per level.
    /// Allocates public inputs for the 3 siblings per level; the caller must set them from the proof.
    ///
    /// Returns `(op_ids, sibling_inputs)` where `sibling_inputs[level]` contains 3 siblings
    /// (each `rate_ext` elements) in order: [s0, s1, s2].
    pub fn add_mmcs_verify_4ary(
        &mut self,
        permutation_config: Poseidon2Config,
        openings_expr: &[Vec<ExprId>],
        index_bits: &[ExprId],
        root_expr: &[ExprId],
    ) -> Result<(Vec<NonPrimitiveOpId>, Vec<Vec<ExprId>>), CircuitBuilderError> {
        let rate_ext = permutation_config.rate_ext();
        let path_depth = index_bits.len() / 2;
        if index_bits.len() != path_depth * 2 {
            return Err(CircuitBuilderError::MalformedCircuit {
                details: "index_bits.len() must be even for 4-ary (2 bits per level)".to_string(),
            });
        }

        let has_tail = openings_expr.len() > path_depth && !openings_expr[path_depth].is_empty();
        if has_tail {
            return Err(CircuitBuilderError::MalformedCircuit {
                details: "4-ary MMCS verify does not yet support tail digest".to_string(),
            });
        }
        let path_openings = &openings_expr[..path_depth];

        if path_depth == 0 {
            let leaf = openings_expr
                .first()
                .ok_or(CircuitBuilderError::MalformedCircuit {
                    details: "4-ary path_depth=0 requires at least one opening".to_string(),
                })?;
            for (o, r) in leaf.iter().take(rate_ext).zip(root_expr.iter()) {
                self.connect(*o, *r);
            }
            return Ok((Vec::new(), Vec::new()));
        }

        let mut sibling_inputs = Vec::with_capacity(path_depth);
        for _ in 0..path_depth {
            let mut level_siblings = Vec::with_capacity(3 * rate_ext);
            for _ in 0..3 {
                for _ in 0..rate_ext {
                    level_siblings.push(self.alloc_public_input("mmcs_4ary_sibling"));
                }
            }
            sibling_inputs.push(level_siblings);
        }

        let one = self.define_const(F::ONE);
        let mut current = vec![None; rate_ext];
        let op_ids = Vec::new();

        for (level, row_digest) in path_openings.iter().enumerate() {
            let bit0 = index_bits[2 * level];
            let bit1 = index_bits[2 * level + 1];
            let not_bit0 = self.sub(one, bit0);
            let not_bit1 = self.sub(one, bit1);
            let eq0 = self.mul(not_bit0, not_bit1);
            let eq1 = self.mul(bit0, not_bit1);
            let eq2 = self.mul(not_bit0, bit1);
            let eq3 = self.mul(bit0, bit1);

            let s0: Vec<ExprId> = (0..rate_ext).map(|j| sibling_inputs[level][j]).collect();
            let s1: Vec<ExprId> = (0..rate_ext)
                .map(|j| sibling_inputs[level][rate_ext + j])
                .collect();
            let s2: Vec<ExprId> = (0..rate_ext)
                .map(|j| sibling_inputs[level][2 * rate_ext + j])
                .collect();

            let cur: Vec<ExprId> = if level == 0 {
                let c: Vec<ExprId> = row_digest.iter().take(rate_ext).copied().collect();
                if c.len() < rate_ext {
                    return Err(CircuitBuilderError::MalformedCircuit {
                        details: format!(
                            "4-ary level 0 row_digest has {} elements, need {}",
                            c.len(),
                            rate_ext
                        ),
                    });
                }
                c
            } else {
                current.iter().map(|o| o.expect("current set")).collect()
            };

            let mut c0 = Vec::with_capacity(rate_ext);
            let mut c1 = Vec::with_capacity(rate_ext);
            let mut c2 = Vec::with_capacity(rate_ext);
            let mut c3 = Vec::with_capacity(rate_ext);
            for j in 0..rate_ext {
                let s01 = self.select(eq0, s0[j], s1[j]);
                let s12 = self.select(eq1, s1[j], s2[j]);
                let s02 = self.select(eq0, s1[j], s12);
                c0.push(self.select(eq0, cur[j], s0[j]));
                c1.push(self.select(eq1, cur[j], s01));
                c2.push(self.select(eq2, cur[j], s02));
                c3.push(self.select(eq3, cur[j], s2[j]));
            }
            let mut children = Vec::with_capacity(4 * rate_ext);
            children.extend(c0);
            children.extend(c1);
            children.extend(c2);
            children.extend(c3);

            let out = self.add_poseidon2_compress_4to1(&permutation_config, &children)?;
            for (i, o) in out.into_iter().enumerate() {
                current[i] = Some(o);
            }
        }

        let output: Vec<ExprId> = current.iter().map(|o| o.expect("output set")).collect();
        for (o, r) in output.iter().zip(root_expr.iter()) {
            self.connect(*o, *r);
        }

        Ok((op_ids, sibling_inputs))
    }
}
