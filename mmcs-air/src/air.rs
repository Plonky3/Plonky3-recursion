use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ops::Range;

use itertools::izip;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_circuit::MmcsTrace;
use p3_circuit::ops::MmcsVerifyConfig;
use p3_circuit::utils::pad_to_power_of_two;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

pub struct MmcsVerifyCols<'a, T> {
    pub index_bits: &'a [T],
    pub length: &'a T,
    pub height_encoding: &'a [T],
    pub sibling: &'a [T],
    pub state: &'a [T],
    pub state_index: &'a [T],
    pub is_final: &'a T,
    pub is_extra: &'a T,
    pub is_extra_height: &'a T,
}

/// Configuration for the mmcs table AIR rows.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct MmcsTableConfig {
    /// The number of base field elements in a digest.
    digest_elems: usize,
    /// The maximum height of the mmcs tree.
    max_tree_height: usize,
    /// The number of base field elements used to represent the index of a digest.
    digest_addresses: usize,
    /// Whether digests are packed into extension field elements or not.
    packing: bool,
}

impl From<MmcsVerifyConfig> for MmcsTableConfig {
    fn from(value: MmcsVerifyConfig) -> Self {
        Self {
            digest_elems: value.base_field_digest_elems,
            max_tree_height: value.max_tree_height,
            digest_addresses: value.ext_field_digest_elems,
            packing: value.is_packing(),
        }
    }
}

impl MmcsTableConfig {
    pub fn width(&self) -> usize {
        self.max_tree_height // index_bits
        + 1 // length
        + self.max_tree_height // height_encoding
        + self.digest_elems // sibling
        + self.digest_elems  // state
        + self.digest_addresses // state_index
        + 1 // is_final
        + 1 // is_extra
        + 1 // extra_height
    }
}

/// AIR for the Mmcs verification table. Each row corresponds to one hash operation in the Mmcs path verification.
/// In each row we store:
/// - `index_bits`: The binary decomposition of the index of the leaf being verified, padded
///   to `max_tree_height` bits.
/// - `length`: The length of the Mmcs path (i.e., the height of the tree).
/// - `height_encoding`: One-hot encoding of the current height in the Mmcs path.
/// - `sibling`: The sibling node at the current height.
/// - `state`: The current hash state (the result of hashing the leaf with siblings up to the current height).
/// - `state_index`: The index of the current in the witness table.
/// - `is_final`: Whether this is the final row for this Mmcs path (i.e., the one that outputs the root).
/// - `is_extra`: Whether this row is hashing the row of a smaller matrix in the Mmcs.
pub struct MmcsVerifyAir<F>
where
    F: Field,
{
    config: MmcsTableConfig,
    _phantom: PhantomData<F>,
}

impl<F: Field> BaseAir<F> for MmcsVerifyAir<F>
where
    F: Field,
    F: Eq,
{
    fn width(&self) -> usize {
        self.config.width()
    }
}

impl<AB: AirBuilder> Air<AB> for MmcsVerifyAir<AB::F>
where
    AB::F: PrimeField,
    AB::F: Eq,
{
    #[inline]
    fn eval(&self, builder: &mut AB) {
        // TODO: Since the user is free to not add Mmcs gates, it may happen that the Mmcs table configuration
        // is the default (all values 0). Given that the Mmcs AIR proof is always included, we need to handle the case where no
        // Mmcs config was provided and skip evaluation.
        if self.config.max_tree_height == 0 {
            return;
        }
        let main = builder.main();
        let local_row = main.row_slice(0).expect("The matrix is empty?");
        let next_row = main.row_slice(1).expect("The matrix only has 1 row?");

        let local = self.get_cols(&local_row);
        let next = self.get_cols(&next_row);

        let index_bits = local.index_bits;
        let next_index_bits = next.index_bits;
        let length = local.length;
        let next_length = next.length;
        let sibling = local.sibling;
        let state = local.state;
        let height_encoding = local.height_encoding;
        let next_height_encoding = next.height_encoding;
        let is_final = local.is_final;
        let next_is_final = next.is_final;
        let is_extra = local.is_extra;
        let next_is_extra = next.is_extra;

        builder.assert_bool(is_final.clone());
        builder.assert_bool(next_is_final.clone());
        builder.assert_bool(is_extra.clone());
        builder.assert_bool(next_is_extra.clone());

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
            // During one mmcs batch verification, and when the current row is not `is_extra` and neither the current nor the next row are final, the height encoding is shifted.
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
        // TODO: These values are not yet wired anywhere. Once we thread hash-table CTLs, move these expressions into
        // the interaction wiring rather than keeping separate columns.
        let mut cur_to_hash = vec![AB::Expr::ZERO; 2 * self.config.digest_elems];
        for i in 0..self.config.digest_elems {
            let mut left = AB::Expr::ZERO;
            let mut right = AB::Expr::ZERO;
            for j in 0..self.config.max_tree_height {
                let gate = height_encoding[j].clone();
                let idx_bit = index_bits[j].clone();
                let state_term = state[i].clone();
                let sibling_term = sibling[i].clone();

                left += gate.clone()
                    * ((AB::Expr::ONE - idx_bit.clone()) * state_term.clone()
                        + idx_bit.clone() * sibling_term.clone());
                right += gate
                    * (idx_bit.clone() * state_term.clone()
                        + (AB::Expr::ONE - idx_bit.clone()) * sibling_term.clone());
            }
            cur_to_hash[i] =
                (AB::Expr::ONE - is_extra.clone()) * left + is_extra.clone() * state[i].clone();
            cur_to_hash[self.config.digest_elems + i] =
                (AB::Expr::ONE - is_extra.clone()) * right + is_extra.clone() * sibling[i].clone();
        }

        // Interactions:
        // Receive (index, initial_root).
        // We send `(cur_hash, next_state)` to the Hash table to check the output, with filter `is_final`.
        // We also need an interaction when `is_extra` is set, as it corresponds to the hash of opened values at another height.
        // When `is_final`, we send the root to FRI (which receives the actual root, so that we can check the equality).
    }
}

impl<F: Field> MmcsVerifyAir<F> {
    pub const fn new(config: MmcsTableConfig) -> Self {
        MmcsVerifyAir {
            config,
            _phantom: PhantomData,
        }
    }

    pub fn get_cols<'a, T>(&self, row: &'a [T]) -> MmcsVerifyCols<'a, T> {
        let index_bits_range = self.index_bits();
        let length_idx = self.length();
        let height_encoding_range = self.height_encoding();
        let sibling_range = self.sibling();
        let state_range = self.state();
        let state_index_range = self.state_index();
        let is_final_idx = self.is_final();
        let is_extra_idx = self.is_extra();
        let is_extra_height_idx = self.is_extra_height();

        MmcsVerifyCols {
            index_bits: &row[index_bits_range],
            length: &row[length_idx],
            height_encoding: &row[height_encoding_range],
            sibling: &row[sibling_range],
            state: &row[state_range],
            state_index: &row[state_index_range],
            is_final: &row[is_final_idx],
            is_extra: &row[is_extra_idx],
            is_extra_height: &row[is_extra_height_idx],
        }
    }

    pub const fn index_bits(&self) -> Range<usize> {
        0..self.config.max_tree_height
    }

    pub const fn length(&self) -> usize {
        self.index_bits().end
    }

    pub const fn height_encoding(&self) -> Range<usize> {
        self.length() + 1..self.length() + 1 + self.config.max_tree_height
    }

    pub const fn sibling(&self) -> Range<usize> {
        self.height_encoding().end..self.height_encoding().end + self.config.digest_elems
    }

    pub const fn state(&self) -> Range<usize> {
        self.sibling().end..self.sibling().end + self.config.digest_elems
    }

    pub const fn state_index(&self) -> Range<usize> {
        self.state().end..self.state().end + self.config.digest_addresses
    }

    pub const fn is_final(&self) -> usize {
        self.state_index().end
    }

    pub const fn is_extra(&self) -> usize {
        self.is_final() + 1
    }

    pub const fn is_extra_height(&self) -> usize {
        self.is_extra() + 1
    }

    pub fn trace_to_matrix<ExtF: BasedVectorSpace<F>>(
        config: &MmcsTableConfig,
        trace: &MmcsTrace<ExtF>,
    ) -> RowMajorMatrix<F> {
        let &MmcsTableConfig {
            digest_elems,
            max_tree_height,
            digest_addresses,
            packing,
        } = config;
        let width = config.width();
        // Compute the number of rows exactly: whenever the height changes, we need an extra row.
        let row_count = trace
            .mmcs_paths
            .iter()
            .map(|path| path.left_values.len() + 1)
            .sum::<usize>();

        let mut values = Vec::with_capacity(width * row_count);

        // TODO: Since the user is free to not add Mmcs gates, it may happen that the Mmcs table configuration
        // is the default. Given that the Mmcs AIR proof is always included, we need to handle the case where no
        // Mmcs config was provided and skip trace generation.
        if config.max_tree_height != 0 {
            for path in trace.mmcs_paths.iter() {
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
                    // TODO: When there's no leaf the index of right
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
                let left_value = if path.final_value.is_empty() {
                    path.left_values.last().expect("Left values can't be empty")
                } else {
                    &path.final_value
                };
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
                if path.final_index.is_empty() {
                    values.extend(vec![F::ZERO; digest_addresses]);
                } else {
                    debug_assert_eq!(path.final_index.len(), digest_addresses);
                    values.extend(path.final_index.iter().map(|idx| F::from_u32(*idx)));
                }

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

#[cfg(test)]
mod test {

    use alloc::vec;
    use alloc::vec::Vec;
    use core::array;

    use p3_baby_bear::BabyBear;
    use p3_challenger::{HashChallenger, SerializingChallenger32};
    use p3_circuit::WitnessId;
    use p3_circuit::ops::MmcsVerifyConfig;
    use p3_circuit::tables::{MmcsPrivateData, MmcsTrace};
    use p3_commit::ExtensionMmcs;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{TwoAdicFriPcs, create_benchmark_fri_params};
    use p3_keccak::{Keccak256Hash, KeccakF};
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_symmetric::{
        CompressionFunctionFromHasher, PaddingFreeSponge, PseudoCompressionFunction,
        SerializingHasher,
    };
    use p3_uni_stark::{StarkConfig, prove, verify};
    use rand::rngs::SmallRng;
    use rand::{Rng, SeedableRng};

    use crate::air::MmcsVerifyAir;

    #[derive(Clone)]
    struct MockCompression {}

    impl PseudoCompressionFunction<[BabyBear; 8], 2> for MockCompression {
        fn compress(&self, input: [[BabyBear; 8]; 2]) -> [BabyBear; 8] {
            input[0]
        }
    }

    #[test]
    fn prove_mmcs_verify_poseidon() -> Result<
        (),
        p3_uni_stark::VerificationError<
            p3_fri::verifier::FriError<
                p3_merkle_tree::MerkleTreeError,
                p3_merkle_tree::MerkleTreeError,
            >,
        >,
    > {
        type Val = BabyBear;
        const NUM_INPUTS: usize = 4;
        const HEIGHT: usize = 8;
        const DIGEST_ELEMS: usize = 8;

        // Generate random inputs.

        let mut rng = SmallRng::seed_from_u64(1);

        let mmcs_config = MmcsVerifyConfig::babybear_default();
        let compress = MockCompression {};

        let leaves: Vec<Vec<Vec<Val>>> = (0..NUM_INPUTS)
            .map(|_| {
                (0..HEIGHT)
                    .map(|j| {
                        if j == HEIGHT / 2 || j == 0 {
                            vec![rng.random::<Val>(); DIGEST_ELEMS]
                        } else {
                            vec![]
                        }
                    })
                    .collect::<Vec<Vec<Val>>>()
            })
            .collect();
        let private_data: [MmcsPrivateData<Val>; NUM_INPUTS] = array::from_fn(|i| {
            let path_siblings: Vec<Vec<Val>> = (0..HEIGHT)
                .map(|_| vec![rng.random::<Val>(); DIGEST_ELEMS])
                .collect();
            let directions: [bool; HEIGHT] = array::from_fn(|_| rng.random::<bool>());
            MmcsPrivateData::new(
                &compress,
                &mmcs_config,
                &leaves[i],
                &path_siblings,
                &directions,
            )
            .expect("The size of all digests is DIGEST_ELEMS")
        });

        let trace = MmcsTrace {
            mmcs_paths: private_data
                .iter()
                .zip(leaves)
                .map(|(data, leaves)| {
                    data.to_trace(
                        &mmcs_config,
                        &leaves,
                        &leaves
                            .iter()
                            .map(|leaf| leaf.iter().map(|_| WitnessId(0)).collect())
                            .collect::<Vec<Vec<WitnessId>>>(),
                        &[WitnessId(0); DIGEST_ELEMS],
                    )
                    .unwrap()
                })
                .collect(),
        };

        // Create the AIR.
        let mmcs_table_config = mmcs_config.into();
        let air = MmcsVerifyAir::<Val>::new(mmcs_table_config);

        // Generate trace for Mmcs tree table.
        let trace = MmcsVerifyAir::<Val>::trace_to_matrix(&mmcs_table_config, &trace);

        // Create the STARK config.
        type Challenge = BinomialExtensionField<Val, 4>;
        type FieldHash = SerializingHasher<U64Hash>;
        type ByteHash = Keccak256Hash;
        let byte_hash = ByteHash {};
        type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
        let u64_hash = U64Hash::new(KeccakF {});
        let field_hash = FieldHash::new(u64_hash);
        type MyCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
        type ValMmcs = MerkleTreeMmcs<
            [Val; p3_keccak::VECTOR_LEN],
            [u64; p3_keccak::VECTOR_LEN],
            FieldHash,
            MyCompress,
            4,
        >;

        let compress = MyCompress::new(u64_hash);
        let val_mmcs = ValMmcs::new(field_hash, compress);

        type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

        type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
        let challenger = Challenger::from_hasher(vec![], byte_hash);

        let fri_params = create_benchmark_fri_params(challenge_mmcs);

        type Dft = p3_dft::Radix2Bowers;
        let dft = Dft::default();

        type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
        let pcs = Pcs::new(dft, val_mmcs, fri_params);

        type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
        let config = MyConfig::new(pcs, challenger);

        let proof = prove(&config, &air, trace, &[]);

        // Verify the proof.
        verify(&config, &air, &proof,&[])
    }
}
