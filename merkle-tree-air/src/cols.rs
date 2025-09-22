use core::borrow::{Borrow, BorrowMut};

use itertools::izip;
use p3_circuit::tables::MerkleTrace;
use p3_field::{BasedVectorSpace, Field};
use p3_matrix::dense::RowMajorMatrix;

use crate::air::MerkleVerifyAir;

#[derive(Debug)]
#[repr(C)]
pub struct MerkleTreeCols<T, const DIGEST_ELEMS: usize, const MAX_TREE_HEIGHT: usize> {
    /// Bits of the leaf index we are currently verifying.
    pub index_bits: [T; MAX_TREE_HEIGHT],
    /// Max height of the Merkle trees, which is equal to the index's bit length.
    /// Transparent column.
    pub length: T,
    /// One-hot encoding of the height within the Merkle tree.
    pub height_encoding: [T; MAX_TREE_HEIGHT],
    /// Sibling we are currently processing.
    pub sibling: [T; DIGEST_ELEMS],
    /// Current state of the hash, which we are updating.
    pub state: [T; DIGEST_ELEMS],
    /// The state index in the witness table
    pub state_index: T,
    /// Whether this is the final step of the Merkle
    /// tree verification for this index.
    pub is_final: T,
    /// Whether there is an extra step for the current height (due to batching).
    /// Transparent column.
    pub is_extra: T,
    /// The height at the extra step. Transparent column.
    pub extra_height: T,
}

pub(crate) fn get_num_merkle_tree_cols<const DIGEST_ELEMS: usize, const MAX_TREE_HEIGHT: usize>()
-> usize {
    size_of::<MerkleTreeCols<u8, DIGEST_ELEMS, MAX_TREE_HEIGHT>>()
}

impl<T, const DIGEST_ELEMS: usize, const MAX_TREE_HEIGHT: usize>
    Borrow<MerkleTreeCols<T, DIGEST_ELEMS, MAX_TREE_HEIGHT>> for [T]
{
    fn borrow(&self) -> &MerkleTreeCols<T, DIGEST_ELEMS, MAX_TREE_HEIGHT> {
        let num_merkle_tree_cols = get_num_merkle_tree_cols::<DIGEST_ELEMS, MAX_TREE_HEIGHT>();
        debug_assert_eq!(self.len(), num_merkle_tree_cols);
        let (prefix, shorts, suffix) =
            unsafe { self.align_to::<MerkleTreeCols<T, DIGEST_ELEMS, MAX_TREE_HEIGHT>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T, const DIGEST_ELEMS: usize, const MAX_TREE_HEIGHT: usize>
    BorrowMut<MerkleTreeCols<T, DIGEST_ELEMS, MAX_TREE_HEIGHT>> for [T]
{
    fn borrow_mut(&mut self) -> &mut MerkleTreeCols<T, DIGEST_ELEMS, MAX_TREE_HEIGHT> {
        debug_assert_eq!(
            self.len(),
            get_num_merkle_tree_cols::<DIGEST_ELEMS, MAX_TREE_HEIGHT>()
        );
        let (prefix, shorts, suffix) =
            unsafe { self.align_to_mut::<MerkleTreeCols<T, DIGEST_ELEMS, MAX_TREE_HEIGHT>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

impl<F: Field, const DIGEST_ELEMS: usize, const MAX_TREE_HEIGHT: usize>
    MerkleVerifyAir<F, DIGEST_ELEMS, MAX_TREE_HEIGHT>
{
    pub fn trace_to_matrix<ExtF: BasedVectorSpace<F>>(
        trace: &MerkleTrace<ExtF>,
    ) -> RowMajorMatrix<F> {
        // Compute the number of rows exactly: whenever the height changes, we need an extra row.
        let height = trace
            .merkle_paths
            .iter()
            .map(|path| path.left_values.len() + 1)
            .sum::<usize>();
        let padded_height = height.next_power_of_two();

        let width = get_num_merkle_tree_cols::<DIGEST_ELEMS, MAX_TREE_HEIGHT>();

        let mut matrix = RowMajorMatrix::new(F::zero_vec(padded_height * width), width);

        let (prefix, rows, suffix) = unsafe {
            matrix
                .values
                .align_to_mut::<MerkleTreeCols<F, DIGEST_ELEMS, MAX_TREE_HEIGHT>>()
        };
        assert!(prefix.is_empty(), "Alignment should match");
        assert!(suffix.is_empty(), "Alignment should match");
        assert_eq!(rows.len(), padded_height);

        let mut row_counter = 0;
        for path in trace.merkle_paths.iter() {
            let max_height = path.is_extra.iter().filter(|is_extra| !*is_extra).count();

            let index_bits = path
                .path_directions
                .iter()
                .zip(path.is_extra.iter())
                .filter(|(_, is_extra)| !*is_extra)
                .map(|(dir, _)| F::from_bool(*dir))
                // Pad with zeroes if necessary.
                .chain(core::iter::repeat_n(F::ZERO, MAX_TREE_HEIGHT - max_height))
                .collect::<Vec<_>>()
                .try_into()
                .expect("TODO: this needs an error");

            let mut row_height = 0;
            for (left_value, left_index, right_value, is_extra) in izip!(
                path.left_values.iter(),
                path.left_index.iter(),
                path.right_values.iter(),
                path.is_extra.iter()
            ) {
                let row = &mut rows[row_counter];

                // Fill the state with the right ammount of base field elements
                debug_assert_eq!(DIGEST_ELEMS, left_value.len() * ExtF::DIMENSION);
                let mut i = 0;
                for values in left_value {
                    for value in values.as_basis_coefficients_slice() {
                        row.state[i] = *value;
                        i += 1;
                    }
                }
                row.state_index = F::from_u32(*left_index);

                // Fill the sibling with the right ammount of base field elements
                debug_assert_eq!(DIGEST_ELEMS, left_value.len() * ExtF::DIMENSION);
                let mut i = 0;
                for values in right_value {
                    for value in values.as_basis_coefficients_slice() {
                        row.sibling[i] = *value;
                        i += 1;
                    }
                }
                row.index_bits = index_bits;
                row.height_encoding[row_height] = F::ONE;
                row.length = F::from_usize(max_height);
                row.is_extra = F::from_bool(*is_extra);
                row_counter += 1;
                if !*is_extra {
                    row_height += 1
                }
            }

            // Final row. The one-hot-encoded height_encoding remains unchanged.
            let row = &mut rows[row_counter];

            // Fill the state with the right ammount of base field elements
            let last_state = path.left_values.last().expect("Left values can't be empty");
            debug_assert_eq!(DIGEST_ELEMS, last_state.len() * ExtF::DIMENSION);
            let mut i = 0;
            for values in last_state {
                for value in values.as_basis_coefficients_slice() {
                    row.state[i] = *value;
                    i += 1;
                }
            }
            row.height_encoding[max_height - 1] = F::ONE;
            row.length = F::from_usize(max_height);
            row.index_bits = index_bits;
            row.is_final = F::ONE;

            row_counter += 1;
        }

        matrix
    }
}

// TODO: This is already in circuit-prove but can't be imported bc of cyclic impots
/// Helper to pad trace values to power-of-two height by repeating the last row
pub fn pad_to_power_of_two<F: Field>(values: &mut Vec<F>, width: usize, original_height: usize) {
    if original_height == 0 {
        // Empty trace - just ensure we have at least one row of zeros
        values.resize(width, F::ZERO);
        return;
    }

    let target_height = original_height.next_power_of_two();
    if target_height == original_height {
        return; // Already power of two
    }

    // Repeat the last row to reach target height
    let last_row_start = (original_height - 1) * width;
    let last_row: Vec<F> = values[last_row_start..original_height * width].to_vec();

    for _ in original_height..target_height {
        values.extend_from_slice(&last_row);
    }
}
