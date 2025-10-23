// TODO:  This is here becasue mmcs in TwoAdicFriPcs is pub(crate).

use alloc::vec::Vec;

use p3_circuit::op::NonPrimitiveOpType;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, CircuitRunner, MmcsOps, NonPrimitiveOpId};
use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_matrix::Dimensions;

use crate::Target;

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
pub fn verify_batch_circuit<F, EF>(
    circuit: &mut CircuitBuilder<EF>,
    commitment: &[Target],
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

    // Ensure MMCS is enabled and get the configuration if so.
    let mmcs_config =
        if let Some(op_config) = circuit.get_op_config(&NonPrimitiveOpType::MmcsVerify) {
            let mmcs_config = match op_config {
                p3_circuit::op::NonPrimitiveOpConfig::MmcsVerifyConfig(cfg) => cfg,
                _ => panic!("Expected MmcsVerifyConfig"), // TODO: Add errors
            };

            // Check that the number of digest limbs matches the configuration.
            let digest_elems = mmcs_config.ext_field_digest_elems;
            if commitment.len() != digest_elems {
                panic!("Incorrect commitment size"); // TODO: Add errors
            }
            mmcs_config.clone()
        } else {
            return Err(CircuitBuilderError::OpNotAllowed {
                op: NonPrimitiveOpType::MmcsVerify,
            });
        };

    // TODO: Disabled for now since TwoAdicFriPcs and CirclePcs currently pass 0 for width.
    // for (dims, opened_vals) in zip_eq(dimensions.iter(), opened_values) {
    //     if opened_vals.len() != dims.width {
    //         return Err(WrongWidth);
    //     }
    // }

    let leaves = mmcs_config
        .format_leaves(opened_values, dimensions, index_bits.len())
        .map_err(
            |_| CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                // TODO: I this the error we want?
                op: NonPrimitiveOpType::MmcsVerify,
            },
        )?
        .into_iter()
        .map(
            |leaf| // Get the initial height padded to a power of two. As heights_tallest_first is sorted,
        // the initial height will be the maximum height.
        // Returns an error if either:
        //              1. proof.len() != log_max_height
        //              2. heights_tallest_first is empty.
        {
            // TODO: This should be replaced with propoer hashing. In the meantime we pad/truncate
            // the leaf to the correct size.
            let mut row_digest = leaf;
            if row_digest.len() > 0 && row_digest.len() < mmcs_config.ext_field_digest_elems {
                row_digest.extend(
                    (0..(mmcs_config.ext_field_digest_elems - row_digest.len()))
                        .map(|_| {
                            let widx = circuit.add_const(EF::ZERO); widx
                        }),
                );
            } else if row_digest.len() > mmcs_config.ext_field_digest_elems {
                row_digest = row_digest[0..mmcs_config.ext_field_digest_elems].to_vec()
            }
            row_digest
        },
        )
        .collect::<Vec<Vec<Target>>>();

    circuit.add_mmcs_verify(&leaves, index_bits, &commitment)
}
