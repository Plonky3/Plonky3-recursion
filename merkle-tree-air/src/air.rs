use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ops::Range;

use itertools::izip;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_circuit::MerkleTrace;
use p3_circuit::op::MerkleVerifyConfig;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

/// Configuration for the merkle table AIR rows.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct MerkleTableConfig {
    /// The number of base field elements in a digest.
    digest_elems: usize,
    /// The maximum height of the merkle tree.
    max_tree_height: usize,
    /// The number of base field elements used to represent the index of a digest.
    digest_addresses: usize,
    /// Whether digests are packed into extension field elements or not.
    packing: bool,
}

impl<T> From<MerkleVerifyConfig<T>> for MerkleTableConfig {
    fn from(value: MerkleVerifyConfig<T>) -> Self {
        Self {
            digest_elems: value.base_field_digest_elems,
            max_tree_height: value.max_tree_height,
            digest_addresses: value.ext_field_digest_elems,
            packing: value.is_packing(),
        }
    }
}

impl MerkleTableConfig {
    pub fn width(&self) -> usize {
        self.max_tree_height // index_bits
        + 1 // length
        + self.max_tree_height // height_encoding
        + self.digest_elems // sibling
        + self.digest_elems  // state
        + self.digest_addresses // state_index
        + 1 // is_final
        + 1 // is_extra
        + 1 // extra_height}
    }
}

/// AIR for the Merkle verification table. Each row corresponds to one hash operation in the Merkle path verification.
/// In each row we store:
/// - `index_bits`: The binary decomposition of the index of the leaf being verified, padded
///   to `max_tree_height` bits.
/// - `length`: The length of the Merkle path (i.e., the height of the tree).
/// - `height_encoding`: One-hot encoding of the current height in the Merkle path.
/// - `sibling`: The sibling node at the current height.    
/// - `state`: The current hash state (the result of hashing the leaf with siblings up to the current height).
/// - `state_index`: The index of the current in the witness table.
/// - `is_final`: Whether this is the final row for this Merkle path (i.e., the one that outputs the root).
/// - `is_extra`: Whether this row is hashing the row of a smaller matrix in the Mmcs.
pub struct MerkleVerifyAir<F>
where
    F: Field,
{
    config: MerkleTableConfig,
    _phantom: PhantomData<F>,
}

impl<F: Field> BaseAir<F> for MerkleVerifyAir<F>
where
    F: Field,
    F: Eq,
{
    fn width(&self) -> usize {
        self.config.width()
    }
}

impl<AB: AirBuilder> Air<AB> for MerkleVerifyAir<AB::F>
where
    AB::F: PrimeField,
    AB::F: Eq,
{
    #[inline]
    fn eval(&self, builder: &mut AB) {
        // TODO: Since the user is free to not add Merkle gates, it may happen that the Merkle table configuration
        // is the default (all values 0). Given that the Merkle AIR proof is always included, we need to handle the case where no
        // Merkle config was provided and skip evaluation.
        if self.config.max_tree_height == 0 {
            return;
        }
        let main = builder.main();
        let (local, next) = (
            main.row_slice(0).expect("The matrix is empty?"),
            main.row_slice(1).expect("The matrix only has 1 row?"),
        );

        let index_bits = &local[self.index_bits()];
        let next_index_bits = &next[self.index_bits()];
        let length = &local[self.length()];
        let next_length = &next[self.length()];
        let sibling = &local[self.sibling()];
        let state = &local[self.state()];
        let height_encoding = &local[self.height_encoding()];
        let next_height_encoding = &next[self.height_encoding()];
        let is_final = &local[self.is_final()];
        let next_is_final = &next[self.is_final()];
        let is_extra = &local[self.is_extra()];

        // Assert that the height encoding is boolean.
        for height_encoding_bit in height_encoding {
            builder.assert_bool(height_encoding_bit.clone());
        }

        // Assert that there is at most one height encoding index that is equal to 1.
        let mut is_real = AB::Expr::ZERO;
        for height_encoding_bit in height_encoding {
            is_real += height_encoding_bit.clone();
        }
        builder.assert_bool(is_real.clone());

        // If the current row is a padding row, the next row must also be a padding row.
        let mut next_is_real = AB::Expr::ZERO;
        for next_height_encoding_bit in next_height_encoding {
            next_is_real += next_height_encoding_bit.clone();
        }
        builder
            .when_transition()
            .when(AB::Expr::ONE - is_real.clone())
            .assert_zero(next_is_real.clone());

        // Assert that the index bits are boolean.
        for index_bit in index_bits {
            builder.assert_bool(index_bit.clone());
        }

        // Within the same execution, index bits are unchanged.
        for (index_bit, next_index_bit) in index_bits.iter().zip(next_index_bits.iter()) {
            builder
                .when_transition()
                .when(AB::Expr::ONE - is_final.clone())
                .assert_zero(index_bit.clone() - next_index_bit.clone());
        }

        // `is_extra` may only be set before a hash with a sibling at the current height.
        // So `local.is_extra`, `local.is_final` and `next.is_final` cannot be set at the same time.
        builder.assert_bool(is_extra.clone() + is_final.clone() + next_is_final.clone());

        // Assert that the height encoding is updated correctly.
        for i in 0..height_encoding.len() {
            // When we are processing an extra hash, the height encoding does not change.
            builder
                .when(is_extra.clone())
                .when_transition()
                .assert_zero(height_encoding[i].clone() - next_height_encoding[i].clone());
            // When the next row is a final row, the height encoding does not change:
            // the final row is an extra row used to store the output of the last hash.
            builder
                .when(next_is_final.clone())
                .when_transition()
                .assert_zero(height_encoding[i].clone() - next_height_encoding[i].clone());
            // During one merkle batch verification, and when the current row is not `is_extra` and neither the current nor the next row are final, the height encoding is shifted.
            builder
                .when_transition()
                .when(AB::Expr::ONE - (is_extra.clone() + next_is_final.clone() + is_final.clone()))
                .assert_zero(
                    height_encoding[i].clone()
                        - next_height_encoding[(i + 1) % self.config.max_tree_height].clone(),
                );
        }
        // At the start, the height encoding is 1.
        builder
            .when_first_row()
            .when(is_real)
            .assert_zero(AB::Expr::ONE - height_encoding[0].clone());
        // When the next row is real and the current row is final, then the next height encoding should be 1.
        builder
            .when_transition()
            .when(next_is_real.clone())
            .when(is_final.clone())
            .assert_zero(AB::Expr::ONE - next_height_encoding[0].clone());

        // Assert that we reach the maximal height.
        let mut sum = AB::Expr::ZERO;
        for (i, height_encoding_bit) in height_encoding.iter().enumerate() {
            sum += height_encoding_bit.clone() * AB::Expr::from_usize(i + 1);
        }
        builder
            .when(is_final.clone())
            .assert_zero(sum - length.clone());

        builder
            .when_transition()
            .when(AB::Expr::ONE - is_final.clone())
            .assert_zero(length.clone() - next_length.clone());

        // `cur_hash` corresponds to the columns that need to be sent to the hash table. It is one of:
        // - (state, sibling) when we are hashing the current state with the sibling (current index bit is 0)
        // - (sibling, state) when we are hashing the sibling with the current state; (current index bit is 1)
        // - (state, extra_sibling) when we are hashing the current state with an extra sibling (when `is_extra` is set)
        let mut cur_to_hash = vec![AB::Expr::ZERO; 2 * self.config.digest_elems];
        for i in 0..self.config.digest_elems {
            for j in 0..self.config.max_tree_height {
                cur_to_hash[i] += height_encoding[j].clone()
                    * (index_bits[j].clone() * sibling[i].clone()
                        + (AB::Expr::ONE - index_bits[j].clone()) * state[i].clone());
                cur_to_hash[self.config.digest_addresses + i] += index_bits[j].clone()
                    * (index_bits[j].clone() * sibling[i].clone()
                        + (AB::Expr::ONE - height_encoding[j].clone()) * state[i].clone());
            }
            let tmp = cur_to_hash[i].clone();
            cur_to_hash[i] +=
                (AB::Expr::ONE - is_extra.clone()) * tmp + AB::Expr::ONE * state[i].clone();
            let tmp = cur_to_hash[self.config.digest_elems + i].clone();
            cur_to_hash[self.config.digest_elems + i] +=
                (AB::Expr::ONE - is_extra.clone()) * tmp + AB::Expr::ONE * sibling[i].clone();
        }

        // Interactions:
        // Receive (index, initial_root).
        // We send `(cur_hash, next_state)` to the Hash table to check the output, with filter `is_final`.
        // We also need an interaction when `is_extra` is set, as it corresponds to the hash of opened values at another height.
        // When `is_final`, we send the root to FRI (which receives the actual root, so that we can check the equality).
    }
}

impl<F: Field> MerkleVerifyAir<F> {
    pub fn new(config: MerkleTableConfig) -> Self {
        MerkleVerifyAir {
            config,
            _phantom: PhantomData,
        }
    }

    pub fn index_bits(&self) -> Range<usize> {
        0..self.config.max_tree_height
    }
    pub fn length(&self) -> usize {
        self.index_bits().end
    }
    pub fn height_encoding(&self) -> Range<usize> {
        self.length() + 1..self.length() + 1 + self.config.max_tree_height
    }
    pub fn sibling(&self) -> Range<usize> {
        self.height_encoding().end..self.height_encoding().end + self.config.digest_elems
    }
    pub fn state(&self) -> Range<usize> {
        self.sibling().end..self.sibling().end + self.config.digest_elems
    }
    pub fn state_index(&self) -> Range<usize> {
        self.state().end..self.state().end + self.config.digest_addresses
    }
    pub fn is_final(&self) -> usize {
        self.state_index().end
    }
    pub fn is_extra(&self) -> usize {
        self.is_final() + 1
    }
    pub fn is_extra_height(&self) -> usize {
        self.is_extra() + 1
    }

    pub fn trace_to_matrix<ExtF: BasedVectorSpace<F>>(
        config: &MerkleTableConfig,
        trace: &MerkleTrace<ExtF>,
    ) -> RowMajorMatrix<F> {
        let &MerkleTableConfig {
            digest_elems,
            max_tree_height,
            digest_addresses,
            packing,
        } = config;
        let width = config.width();
        // Compute the number of rows exactly: whenever the height changes, we need an extra row.
        let row_count = trace
            .merkle_paths
            .iter()
            .map(|path| path.left_values.len() + 1)
            .sum::<usize>();

        let mut values = Vec::with_capacity(width * row_count);

        // TODO: Since the user is free to not add Merkle gates, it may happen that the Merkle table configuration
        // is the default. Given that the Merkle AIR proof is always included, we need to handle the case where no
        // Merkle config was provided and skip trace generation.
        if config.max_tree_height != 0 {
            for path in trace.merkle_paths.iter() {
                let max_height = path.is_extra.iter().filter(|is_extra| !*is_extra).count();

                let index_bits = path
                    .path_directions
                    .iter()
                    .zip(path.is_extra.iter())
                    .filter(|(_, is_extra)| !*is_extra)
                    .map(|(dir, _)| F::from_bool(*dir))
                    // Pad with zeroes if necessary.
                    .chain(core::iter::repeat_n(F::ZERO, max_tree_height - max_height))
                    .collect::<Vec<_>>();

                let mut row_height = 0;
                for (left_value, left_index, right_value, is_extra) in izip!(
                    path.left_values.iter(),
                    path.left_index.iter(),
                    path.right_values.iter(),
                    path.is_extra.iter()
                ) {
                    // Start filling a new row with the index bits
                    debug_assert_eq!(index_bits.len(), max_tree_height);
                    values.extend_from_slice(&index_bits);

                    // Add the length of the path
                    values.push(F::from_usize(max_height));

                    // height encoding
                    if row_height > 0 {
                        values.extend_from_slice(&vec![F::ZERO; row_height]);
                    }
                    values.push(F::ONE);
                    if row_height < max_tree_height {
                        values.extend_from_slice(&vec![F::ZERO; max_tree_height - row_height - 1]);
                    }

                    // sibling and state
                    debug_assert!(if packing {
                        digest_elems == left_value.len() * ExtF::DIMENSION
                    } else {
                        digest_elems == left_value.len()
                    });
                    values.extend(left_value.iter().flat_map(|xs| {
                        if config.packing {
                            xs.as_basis_coefficients_slice()
                        } else {
                            &xs.as_basis_coefficients_slice()[0..1]
                        }
                    }));

                    debug_assert!(if packing {
                        digest_elems == right_value.len() * ExtF::DIMENSION
                    } else {
                        digest_elems == right_value.len()
                    });
                    values.extend(right_value.iter().flat_map(|xs| {
                        if config.packing {
                            xs.as_basis_coefficients_slice()
                        } else {
                            &xs.as_basis_coefficients_slice()[0..1]
                        }
                    }));

                    // state index
                    values.extend(left_index.iter().map(|idx| F::from_u32(*idx)));

                    // is final
                    values.push(F::ZERO);

                    // is extra
                    values.push(F::from_bool(*is_extra));
                    // extra_height
                    if !*is_extra {
                        // Add extra height
                        values.push(F::ZERO);
                        row_height += 1;
                    } else {
                        values.push(F::from_usize(row_height));
                    }

                    debug_assert_eq!(values.len() % width, 0);
                }

                // Final row. The one-hot-encoded height_encoding remains unchanged.

                // Start filling a new row with the index bits
                values.extend_from_slice(&index_bits);
                // Add the length of the path
                values.push(F::from_usize(max_height));
                // height encoding
                let row_height = if *path.is_extra.last().unwrap_or(&true) {
                    row_height
                } else {
                    row_height - 1
                };
                if row_height > 0 {
                    values.extend_from_slice(&vec![F::ZERO; row_height]);
                }
                values.push(F::ONE);
                if row_height < max_tree_height {
                    values.extend_from_slice(&vec![F::ZERO; max_tree_height - row_height - 1]);
                }
                // sibling and state
                let left_value = path.left_values.last().expect("Left values can't be empty");
                debug_assert!(if packing {
                    digest_elems == left_value.len() * ExtF::DIMENSION
                } else {
                    digest_elems == left_value.len()
                });
                values.extend(left_value.iter().flat_map(|xs| {
                    if config.packing {
                        xs.as_basis_coefficients_slice()
                    } else {
                        &xs.as_basis_coefficients_slice()[0..1]
                    }
                }));
                values.extend(vec![F::ZERO; digest_elems]);

                // state index
                values.extend(vec![F::ZERO; digest_addresses]);

                // is final
                values.push(F::ONE);
                // is extra
                values.push(F::ZERO);
                // extra_height
                values.push(F::ZERO);
            }
        }

        pad_to_power_of_two(&mut values, width, row_count);

        RowMajorMatrix::new(values, width)
    }
}

/// Helper to pad trace values to power-of-two height with zeroes
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

    for _ in original_height..target_height {
        values.extend_from_slice(&vec![F::ZERO; width]);
    }
}
