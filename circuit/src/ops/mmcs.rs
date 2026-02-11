use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::cmp::Reverse;

use itertools::Itertools;
use p3_field::Field;
use p3_matrix::Dimensions;

use crate::builder::{CircuitBuilder, CircuitBuilderError};
use crate::op::{NonPrimitiveOpType, Poseidon2Config};
use crate::ops::Poseidon2PermCall;
use crate::ops::poseidon2_perm::Poseidon2PermOps;
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
            op: NonPrimitiveOpType::Poseidon2Perm(permutation_config),
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

pub fn add_mmcs_verify<F: Field>(
    builder: &mut CircuitBuilder<F>,
    permutation_config: Poseidon2Config,
    openings_expr: &[Vec<ExprId>],
    directions_expr: &[ExprId],
    root_expr: &[ExprId],
) -> Result<Vec<NonPrimitiveOpId>, CircuitBuilderError> {
    // We return only the operations that require private data.
    let mut op_ids = Vec::with_capacity(openings_expr.len());
    let mut output = [None, None, None, None];
    let zero = builder.add_const(F::ZERO);
    for (i, (row_digest, direction)) in openings_expr.iter().zip(directions_expr).enumerate() {
        let is_first = i == 0;
        let is_last = i == directions_expr.len() - 1;
        // Extra row (if any) must be combined before the main sibling step.
        if !is_first && !row_digest.is_empty() {
            let _ = builder.add_poseidon2_perm(Poseidon2PermCall {
                config: permutation_config,
                new_start: false,
                merkle_path: true,
                mmcs_bit: Some(zero), // Extra row is always a left child
                inputs: [None, None, Some(row_digest[0]), Some(row_digest[1])],
                out_ctl: [false, false],
                return_all_outputs: false,
                mmcs_index_sum: None,
            })?;
        }

        let (op_id, maybe_output) = builder.add_poseidon2_perm(Poseidon2PermCall {
            config: permutation_config,
            new_start: is_first,
            merkle_path: true,
            mmcs_bit: Some(*direction),
            inputs: if is_first {
                [Some(row_digest[0]), Some(row_digest[1]), None, None]
            } else {
                [None, None, None, None]
            },
            out_ctl: [is_last, is_last],
            return_all_outputs: false,
            mmcs_index_sum: None,
        })?;
        op_ids.push(op_id);
        output = maybe_output;
    }
    // Only outputs 0-1 are CTL-exposed for MMCS verification
    let output = [output[0], output[1]]
        .into_iter()
        .map(|x| {
            x.ok_or_else(|| CircuitBuilderError::MalformedNonPrimitiveOutputs {
                op_id: *op_ids.last().unwrap(),
                details: "Expected output from last Poseidon2Perm call".to_string(),
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    builder.connect(output[0], root_expr[0]);
    builder.connect(output[1], root_expr[1]);
    Ok(op_ids)
}
