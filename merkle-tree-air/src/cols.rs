use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::borrow::{Borrow, BorrowMut};

use itertools::izip;
use p3_baby_bear::BabyBear;
use p3_field::extension::BinomiallyExtendable;
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeField, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;

use crate::air::MerkleVerifyAir;
use crate::compress::FieldCompression;

/// Merkle verification table (simplified: single field elements) containing
/// the verification of several merkle paths.
#[derive(Debug, Clone)]
pub struct MerkleTrace<F> {
    /// All the merkle paths computed in this trace
    pub merkle_paths: Vec<MerklePathTrace<F>>,
}

/// A single Merkle Path verification table (simplified: single field elements)
#[derive(Debug, Clone)]
pub struct MerklePathTrace<F> {
    /// Left operand values (current hash)
    pub left_values: Vec<Vec<F>>,
    /// Left operand indices
    pub left_index: Vec<u32>,
    /// Right operand values (sibling hash)
    pub right_values: Vec<Vec<F>>,
    /// Right operand indices (not on witness bus - private)
    pub right_index: Vec<u32>,
    /// Path direction bits (0 = left, 1 = right) - private
    pub path_directions: Vec<bool>,
    /// Indicates if the current row is processing a smaller
    /// matrix of the Mmcs.
    pub is_extra: Vec<bool>,
}

impl<F> MerklePathTrace<F> {
    pub fn new() -> Self {
        MerklePathTrace {
            left_values: Vec::new(),
            left_index: Vec::new(),
            right_values: Vec::new(),
            right_index: Vec::new(),
            path_directions: Vec::new(),
            is_extra: Vec::new(),
        }
    }
}

/// Private Merkle path data for fake Merkle verification (simplified)
///
/// This represents the private witness information that the prover needs
/// to demonstrate knowledge of a valid Merkle path from leaf to root.
/// In a real implementation, this would contain cryptographic hash values
/// and tree structure information.
///
/// Note: This is a simplified "fake" implementation for demonstration.
/// Production Merkle verification would use proper cryptographic hashes
/// and handle multi-element hash digests, not single field elements.
#[derive(Debug, Clone, PartialEq)]
pub struct MerklePrivateData<F> {
    /// Sibling hash values along the Merkle path
    ///
    /// For each level of the tree (from leaf to root), contains the
    /// sibling hash needed to compute the parent hash. It might optionally
    /// include the hash of the row of a smaller matrix in the Mmcs.
    pub path_siblings: Vec<(Vec<F>, Option<Vec<F>>)>,

    /// Direction bits indicating path through the tree
    ///
    /// For each level: `false` = current node is left child,
    /// `true` = current node is right child. Used to determine
    /// hash input ordering: `hash(current, sibling)` vs `hash(sibling, current)`.
    pub path_directions: Vec<bool>,
}

impl<F: Clone> MerklePrivateData<F> {
    pub fn to_trace<C, const HASH_ELEMS: usize, const D: usize>(
        &self,
        compress: &C,
        leaf_index: u32,
        leaf_value: [F; HASH_ELEMS],
    ) -> Result<MerklePathTrace<F>, String>
    where
        C: FieldCompression<BabyBear, F, D, 2, HASH_ELEMS>,
    {
        let mut trace = MerklePathTrace::new();
        let mut state = leaf_value;

        // For each step in the Merkle path
        for ((sibling_value, extra_sibling_value), &direction) in
            self.path_siblings.iter().zip(self.path_directions.iter())
        {
            let sibling_value: [F; HASH_ELEMS] = sibling_value
                .clone()
                .try_into()
                .map_err(|_| "Incorrect size of hahses")?;
            // Current hash becomes left operand
            trace.left_values.push(state.to_vec());
            // TODO: What is the address of this value?
            trace.left_index.push(leaf_index); // Points to witness bus

            // Sibling becomes right operand (private data - not on witness bus)
            trace.right_values.push(sibling_value.to_vec());
            trace.right_index.push(0); // Not on witness bus - private data

            // Compute parent hash (simple mock hash: left + right + direction)
            let parent_hash = if direction {
                compress.compress_field([state, sibling_value])
            } else {
                compress.compress_field([sibling_value, state])
            };

            trace.path_directions.push(direction);
            trace.is_extra.push(false);

            // Update current hash for next iteration
            state = parent_hash;

            // If there's an extra sibling we push another row to the trace
            if let Some(extra_sibling_value) = extra_sibling_value {
                let extra_sibling_value: [F; HASH_ELEMS] =
                    extra_sibling_value
                        .clone()
                        .try_into()
                        .map_err(|_| "Incorrect size of hahses")?;
                trace.left_values.push(state.to_vec());
                trace.left_index.push(leaf_index);

                trace.right_values.push(extra_sibling_value.to_vec());
                trace.right_index.push(0); // TODO: This should have an address on the witness table

                let parent_hash = compress.compress_field([state, extra_sibling_value.clone()]);
                trace.path_directions.push(direction);
                trace.is_extra.push(true);

                state = parent_hash.clone();
            }
        }
        Ok(trace)
    }
}

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
        let padded_height = if height > 0 {
            height.next_power_of_two()
        } else {
            0
        };

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

            // We start at the highest height. It corresponds to the length of the siblings. In `verify_batch`, `cur_height_padded` is divided by 2 at each step. So the initial `cur_height_padded` should be `1 << max_height`.
            let mut cur_height_padded = 1 << max_height;

            let index_bits = path
                .path_directions
                .iter()
                .zip(path.is_extra.iter())
                .filter(|(_, is_extra)| !*is_extra)
                .map(|(dir, _)| F::from_bool(*dir))
                // Pad with zeroes if necessary.
                .chain(core::iter::repeat(F::ZERO).take(MAX_TREE_HEIGHT - max_height))
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
