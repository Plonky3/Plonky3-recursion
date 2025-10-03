// TODO:  This is here becasue mmcs in TwoAdicFriPcs is pub(crate).

use alloc::vec::Vec;
use core::cmp::Reverse;

use itertools::Itertools;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, MerkleOps, NonPrimitiveOpId};
use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_matrix::Dimensions;

use crate::Target;
use crate::recursive_pcs::HashTargets;

/// Recursive verison of `verify_circuit_batch`. Adds a ircuit that verifies an opened batch of rows with respect to a given commitment.
///
/// - `circuit`: The circuit builder to which we add the verify_batch circuit
/// - `commit`: The merkle root of the tree.
/// - `dimensions`: A vector of the dimensions of the matrices committed to.
/// - `directions`: The binary decomposition of the index of a leaf in the tree.
/// - `opened_values`: A vector of matrix rows. Assume that the tallest matrix committed
///   to has height `2^n >= M_tall.height() > 2^{n - 1}` and the `j`th matrix has height
///   `2^m >= Mj.height() > 2^{m - 1}`. Then `j`'th value of opened values must be the row `Mj[index >> (m - n)]`.
/// - `proof`: A vector of sibling nodes. The `i`th element should be the node at level `i`
///   with index `(index << i) ^ 1`.
///
/// Returns the new merkle_verify gate, otherwise returns an error.
pub fn verify_batch_circuit<F, EF, const DIGEST_ELEMS: usize>(
    circuit: &mut CircuitBuilder<EF>,
    commitment: &HashTargets<F, DIGEST_ELEMS>,
    dimensions: &[Dimensions],
    index_bits: &[Target],
    opened_values: &[Vec<Target>],
) -> Result<NonPrimitiveOpId, CircuitBuilderError>
where
    F: Field + TwoAdicField,
    EF: ExtensionField<F>,
{
    // Check that the openings have the correct shape.
    if dimensions.len() != opened_values.len() {
        panic!("Wrong batch size"); // TODO: Add errors
    }

    // TODO: Disabled for now since TwoAdicFriPcs and CirclePcs currently pass 0 for width.
    // for (dims, opened_vals) in zip_eq(dimensions.iter(), opened_values) {
    //     if opened_vals.len() != dims.width {
    //         return Err(WrongWidth);
    //     }
    // }

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
        panic!("Heights that round up to the same power of two must be equal"); //TODO: Add errors
    }

    // Get the initial height padded to a power of two. As heights_tallest_first is sorted,
    // the initial height will be the maximum height.
    // Returns an error if either:
    //              1. proof.len() != log_max_height
    //              2. heights_tallest_first is empty.
    let curr_height_padded = match heights_tallest_first.peek() {
        Some((_, dims)) => {
            let max_height = dims.height.next_power_of_two();
            max_height
        }
        None => panic!("No dimensions provided"), // TODO: Add errors
    };

    // Hash all matrix openings at the current height.
    // TODO: The root should be the hash of all matrix openings at the current height.
    let leaf: Vec<Target> = heights_tallest_first
        .peeking_take_while(|(_, dims)| dims.height.next_power_of_two() == curr_height_padded)
        .map(|(i, _)| {
            if opened_values[i].len() < DIGEST_ELEMS / EF::DIMENSION {
                let mut padded_values = opened_values[i].clone();
                padded_values.extend(
                    (0..(DIGEST_ELEMS / EF::DIMENSION - opened_values[i].len()))
                        .map(|_| circuit.add_const(EF::ZERO)),
                );
                padded_values
            } else if opened_values[i].len() > DIGEST_ELEMS / EF::DIMENSION {
                opened_values[i][0..DIGEST_ELEMS].to_vec()
            } else {
                opened_values[i].clone()
            }
        })
        .collect::<Vec<Vec<Target>>>()[0]
        .clone();

    circuit.add_merkle_verify(&leaf, index_bits, &commitment.hash_targets)
}
