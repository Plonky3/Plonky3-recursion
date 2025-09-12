use alloc::vec;
use alloc::vec::Vec;
use core::borrow::{Borrow, BorrowMut};
use core::cmp::Reverse;
use core::fmt::Debug;
use core::marker::PhantomData;

use itertools::Itertools;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{Field, PackedField, PrimeCharacteristicRing, PrimeField};
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::{Dimensions, Matrix};
use p3_symmetric::FieldCompression;
// `DIGEST_ELEMS` is the number of digest elements of the hash. `MAX_TREE_HEIGHT` is the maximal tree height that can be handled by the AIR.
pub struct MerkleTreeAir<F, C, const DIGEST_ELEMS: usize, const MAX_TREE_HEIGHT: usize>
where
    F: PrimeField,
    C: FieldCompression<F, 2, DIGEST_ELEMS>,
{
    pub compress: C,
    _phantom: PhantomData<F>,
}

impl<F: PrimeField, C, const DIGEST_ELEMS: usize, const MAX_TREE_HEIGHT: usize>
    MerkleTreeAir<F, C, DIGEST_ELEMS, MAX_TREE_HEIGHT>
where
    C: FieldCompression<F, 2, DIGEST_ELEMS>,
{
    #[allow(unused)]
    fn new(compress: C) -> Self {
        Self {
            compress,
            _phantom: PhantomData,
        }
    }
}

impl<F: PrimeField, C, const DIGEST_ELEMS: usize, const MAX_TREE_HEIGHT: usize> BaseAir<F>
    for MerkleTreeAir<F, C, DIGEST_ELEMS, MAX_TREE_HEIGHT>
where
    F: Field,
    C: FieldCompression<F, 2, DIGEST_ELEMS> + Sync,
{
    fn width(&self) -> usize {
        get_num_merkle_tree_cols::<DIGEST_ELEMS, MAX_TREE_HEIGHT>()
    }
}

impl<AB: AirBuilder, C, const DIGEST_ELEMS: usize, const MAX_TREE_HEIGHT: usize> Air<AB>
    for MerkleTreeAir<AB::F, C, DIGEST_ELEMS, MAX_TREE_HEIGHT>
where
    AB::F: PrimeField,
    C: FieldCompression<AB::F, 2, DIGEST_ELEMS> + Sync,
{
    #[inline]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (
            main.row_slice(0).expect("The matrix is empty?"),
            main.row_slice(1).expect("The matrix only has 1 row?"),
        );
        let local: &MerkleTreeCols<AB::Var, DIGEST_ELEMS, MAX_TREE_HEIGHT> = (*local).borrow();
        let next: &MerkleTreeCols<AB::Var, DIGEST_ELEMS, MAX_TREE_HEIGHT> = (*next).borrow();

        // Assert that the height encoding is boolean.
        for i in 0..local.height_encoding.len() {
            builder.assert_bool(local.height_encoding[i].clone());
        }

        // Assert that there is at most one height encoding index that is equal to 1.
        let mut is_real = AB::Expr::ZERO;
        for i in 0..MAX_TREE_HEIGHT {
            is_real += local.height_encoding[i].clone();
        }
        builder.assert_bool(is_real.clone());

        // If the current row is a padding row, the next row must also be a padding row.
        let mut next_is_real = AB::Expr::ZERO;
        for i in 0..MAX_TREE_HEIGHT {
            next_is_real += next.height_encoding[i].clone();
        }
        builder
            .when_transition()
            .when(AB::Expr::ONE - is_real)
            .assert_zero(next_is_real.clone());

        // Assert that the index bits are boolean.
        for i in 0..local.index_bits.len() {
            builder.assert_bool(local.index_bits[i].clone());
        }

        // Within the same execution, index bits are unchanged.
        for i in 0..local.index_bits.len() {
            builder
                .when_transition()
                .when(AB::Expr::ONE - local.is_final.clone())
                .assert_zero(local.index_bits[i].clone() - next.index_bits[i].clone());
        }

        // `is_extra` may only be set before a hash with a sibling at the current height.
        // So `local.is_extra` and `local.is_final` cannot be set at the same time.
        builder
            .assert_bool(local.is_extra.clone() + local.is_final.clone() + next.is_final.clone());

        // Assert that the height encoding is updated correctly.
        for i in 0..local.height_encoding.len() {
            // When we are processing an extra hash, the height encoding does not change.
            builder
                .when(local.is_extra.clone())
                .when_transition()
                .assert_zero(local.height_encoding[i].clone() - next.height_encoding[i].clone());
            // When the next row is a final row, the height encoding does not change:
            // the final row is an extra row used to store the output of the last hash.
            builder
                .when(next.is_final.clone())
                .when_transition()
                .assert_zero(local.height_encoding[i].clone() - next.height_encoding[i].clone());
            // During one merkle batch verification, and when the current row is not `is_extra` and the next row is not final, the height encoding is shifted.
            builder
                .when_transition()
                .when(
                    AB::Expr::ONE
                        - (local.is_extra.clone() + next.is_final.clone() + local.is_final.clone()),
                )
                .assert_zero(
                    local.height_encoding[i].clone()
                        - next.height_encoding[(i + 1) % MAX_TREE_HEIGHT].clone(),
                );
        }
        // At the start, the height encoding is 1.
        builder
            .when_first_row()
            .assert_zero(AB::Expr::ONE - local.height_encoding[0].clone());
        // When the next row is real and the current row is final, then the next height encoding should be 1.
        builder
            .when_transition()
            .when(next_is_real.clone())
            .when(local.is_final.clone())
            .assert_zero(AB::Expr::ONE - next.height_encoding[0].clone());

        // Assert that we reach the maximal height.
        let mut sum = AB::Expr::ZERO;
        for i in 0..MAX_TREE_HEIGHT {
            sum += local.height_encoding[i].clone() * AB::Expr::from_usize(i + 1);
        }
        builder
            .when(local.is_final.clone())
            .assert_zero(sum - local.length.clone());

        builder
            .when_transition()
            .when(AB::Expr::ONE - local.is_final.clone())
            .assert_zero(local.length.clone() - next.length.clone());

        // `cur_hash` corresponds to the columns that need to be sent to the hash table. It is one of:
        // - (state, sibling) when we are hashing the current state with the sibling (current index bit is 0)
        // - (sibling, state) when we are hashing the sibling with the current state; (current index bit is 1)
        // - (state, extra_sibling) when we are hashing the current state with an extra sibling (when `is_extra` is set)
        let mut cur_to_hash = vec![AB::Expr::ZERO; 2 * DIGEST_ELEMS];
        for i in 0..DIGEST_ELEMS {
            for j in 0..DIGEST_ELEMS {
                cur_to_hash[i] += local.height_encoding[j].clone()
                    * (local.index_bits[j].clone() * local.sibling[j].clone()
                        + (AB::Expr::ONE - local.index_bits[j].clone()) * local.state[j].clone());
                cur_to_hash[DIGEST_ELEMS + i] += local.index_bits[j].clone()
                    * (local.index_bits[j].clone() * local.sibling[j].clone()
                        + (AB::Expr::ONE - local.height_encoding[j].clone())
                            * local.state[j].clone());
            }
            let tmp = cur_to_hash[i].clone();
            cur_to_hash[i] += (AB::Expr::ONE - local.is_extra.clone()) * tmp
                + AB::Expr::ONE * local.state[i].clone();
            let tmp = cur_to_hash[DIGEST_ELEMS + i].clone();
            cur_to_hash[DIGEST_ELEMS + i] += (AB::Expr::ONE - local.is_extra.clone()) * tmp
                + AB::Expr::ONE * local.sibling[i].clone();
        }

        // Interactions:
        // Receive (index, initial_root).
        // We send `(cur_hash, next_state)` to the Hash table to check the output, with filter `is_final`.
        // We also need an interaction when `is_extra` is set, as it corresponds to the hash of opened values at another height.
        // When `is_final`, we send the root to FRI (which receives the actual root, so that we can check the equality).
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct MerkleTreeCols<T, const DIGEST_ELEMS: usize, const MAX_TREE_HEIGHT: usize> {
    /// Bits of the leaf index we are currently verifying.
    pub index_bits: [T; DIGEST_ELEMS],
    /// Max height of the Merkle trees, which is equal to the index's bit length.
    /// Transparent column.
    pub length: T,
    /// One-hot encoding of the height within the Merkle tree.
    pub height_encoding: [T; MAX_TREE_HEIGHT],
    /// Sibling we are currently processing.
    pub sibling: [T; DIGEST_ELEMS],
    /// Current state of the hash, which we are updating.
    pub state: [T; DIGEST_ELEMS],
    /// Whether this is the final step of the Merkle
    /// tree verification for this index.
    pub is_final: T,
    /// Whether there is an extra step for the current height (due to batching).
    /// Transparent column.
    pub is_extra: T,
    /// The height at the extra step. Transparent column.
    pub extra_height: T,
}

fn get_num_merkle_tree_cols<const DIGEST_ELEMS: usize, const MAX_TREE_HEIGHT: usize>() -> usize {
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

type MerkleTreeInputs<F, const DIGEST_ELEMS: usize> = (
    // Initial computed root: hash of all the leaves.
    [F; DIGEST_ELEMS],
    // Index
    usize,
    // Sibling, and optional extra hash (corresponding to the hash of the leaves of a new tree)
    Vec<([F; DIGEST_ELEMS], Option<[F; DIGEST_ELEMS]>)>,
);

impl<F: PrimeField, C, const DIGEST_ELEMS: usize, const MAX_TREE_HEIGHT: usize>
    MerkleTreeAir<F, C, DIGEST_ELEMS, MAX_TREE_HEIGHT>
where
    C: FieldCompression<F, 2, DIGEST_ELEMS>,
{
    pub fn generate_trace_rows(
        &self,
        inputs: &[MerkleTreeInputs<F, DIGEST_ELEMS>],
    ) -> RowMajorMatrix<<F as PackedField>::Scalar> {
        // Compute the number of rows exactly: whenever the height changes, we need an extra row.
        let mut max_num_rows: usize = 0;
        for (_, _, siblings) in inputs {
            for (_, o_s) in siblings {
                max_num_rows += 1;
                if o_s.is_some() {
                    max_num_rows += 1;
                }
            }
        }
        // Count padding rows.
        max_num_rows = max_num_rows.next_power_of_two();
        let num_merkle_tree_cols = get_num_merkle_tree_cols::<DIGEST_ELEMS, MAX_TREE_HEIGHT>();
        let trace_length = max_num_rows * num_merkle_tree_cols;

        let mut trace = RowMajorMatrix::new(F::zero_vec(trace_length), num_merkle_tree_cols);

        let (prefix, rows, suffix) = unsafe {
            trace
                .values
                .align_to_mut::<MerkleTreeCols<F, DIGEST_ELEMS, MAX_TREE_HEIGHT>>()
        };
        assert!(prefix.is_empty(), "Alignment should match");
        assert!(suffix.is_empty(), "Alignment should match");
        assert_eq!(rows.len(), max_num_rows);

        let mut row_counter = 0;
        for input in inputs {
            let max_height = input.2.len();

            // We start at the highest height. It corresponds to the length of the siblings.
            let mut cur_height_padded = 1 << max_height;
            let initial_root = input.0;
            let mut state = initial_root;

            let mut index = input.1;
            let mut index_bits = [F::ZERO; DIGEST_ELEMS];
            for (i, idx) in index_bits.iter_mut().enumerate().take(DIGEST_ELEMS) {
                *idx = F::from_usize((index >> i) & 1);
            }

            for (row_height, &(sibling, o_sibling)) in input.2.iter().enumerate() {
                let row = &mut rows[row_counter];
                row.state = state;
                row.index_bits = index_bits;
                row.height_encoding[row_height] = F::ONE;
                row.length = F::from_usize(max_height);
                row_counter += 1;
                let (left, right) = if index & 1 == 0 {
                    (state, sibling)
                } else {
                    (sibling, state)
                };

                // Combine the current node with the sibling node to get the parent node.
                state = self.compress.compress_field([left, right]);
                index >>= 1;
                cur_height_padded >>= 1;

                if let Some(extra_sibling) = o_sibling {
                    // There is an extra row.
                    let row = &mut rows[row_counter];
                    row.state = state;
                    row.length = F::from_usize(max_height);
                    row.is_extra = F::ONE;
                    row.extra_height = F::from_usize(cur_height_padded);
                    row.index_bits = index_bits;
                    row.height_encoding[row_height + 1] = F::ONE;

                    row_counter += 1;
                    // If there are new matrix rows, hash the rows together and then combine with the current root.
                    row.sibling = extra_sibling;

                    state = self.compress.compress_field([state, extra_sibling]);
                }
            }

            // Final row. The one-hot-encoded height_encoding remains unchanged.
            let row = &mut rows[row_counter];
            row.state = state;
            row.height_encoding[max_height - 1] = F::ONE;
            row.length = F::from_usize(max_height);
            row.index_bits = index_bits;
            row.is_final = F::ONE;

            row_counter += 1;
        }

        trace
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
    use core::array;

    use p3_challenger::{HashChallenger, SerializingChallenger32};
    use p3_commit::ExtensionMmcs;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{TwoAdicFriPcs, create_benchmark_fri_params};
    use p3_keccak::{Keccak256Hash, KeccakF};
    use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear};
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_symmetric::{
        CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher, TruncatedPermutation,
    };
    use p3_uni_stark::{StarkConfig, prove, verify};
    use rand::rngs::SmallRng;
    use rand::{Rng, SeedableRng};

    type Val = KoalaBear;
    type FieldHash = SerializingHasher<U64Hash>;
    type Poseidon2Compression<Perm16> = TruncatedPermutation<Perm16, 2, 8, 16>;

    const NUM_INPUTS: usize = 4;
    const HEIGHT: usize = 8;
    const DIGEST_ELEMS: usize = 8;
    const MAX_TREE_HEIGHT: usize = 8;

    // Generate random inputs.
    let mut rng = SmallRng::seed_from_u64(1);
    let roots: [_; NUM_INPUTS] = array::from_fn(|_| rng.random::<[Val; DIGEST_ELEMS]>());
    let indices: [_; NUM_INPUTS] = array::from_fn(|_| rng.random::<u32>() as usize);

    // We generate the siblings, with an extra hash at half the height for half of the inputs.
    let siblings: [[_; HEIGHT]; NUM_INPUTS] = array::from_fn(|i| {
        if i % 2 == 0 {
            array::from_fn(|j| {
                if j == HEIGHT / 2 {
                    (
                        rng.random::<[Val; DIGEST_ELEMS]>(),
                        Some(rng.random::<[Val; DIGEST_ELEMS]>()),
                    )
                } else {
                    (rng.random::<[Val; DIGEST_ELEMS]>(), None)
                }
            })
        } else {
            array::from_fn(|_| (rng.random::<[Val; DIGEST_ELEMS]>(), None))
        }
    });

    let inputs = (0..NUM_INPUTS)
        .map(|i| (roots[i], indices[i], siblings[i].to_vec()))
        .collect::<Vec<_>>();

    let perm16 = Poseidon2KoalaBear::<16>::new_from_rng_128(&mut rng);

    let compress = Poseidon2Compression::new(perm16);

    // Create the AIR.
    let air = MerkleTreeAir::<Val, _, DIGEST_ELEMS, MAX_TREE_HEIGHT>::new(compress);

    // Generate trace for Merkle tree table.
    let trace = air.generate_trace_rows(&inputs);

    // Prove with Keccak.
    type Challenge = BinomialExtensionField<Val, 4>;

    type ByteHash = Keccak256Hash;
    let byte_hash = ByteHash {};

    type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
    let u64_hash = U64Hash::new(KeccakF {});

    let field_hash = FieldHash::new(u64_hash);

    type MyCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
    let compress = MyCompress::new(u64_hash);

    type ValMmcs = MerkleTreeMmcs<
        [Val; p3_keccak::VECTOR_LEN],
        [u64; p3_keccak::VECTOR_LEN],
        FieldHash,
        MyCompress,
        4,
    >;

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

    let proof = prove(&config, &air, trace, &vec![]);

    // Verify the proof.
    verify(&config, &air, &proof, &vec![])
}

#[test]
fn prove_mmcs_verify_keccak() -> Result<
    (),
    p3_uni_stark::VerificationError<
        p3_fri::verifier::FriError<
            p3_merkle_tree::MerkleTreeError,
            p3_merkle_tree::MerkleTreeError,
        >,
    >,
> {
    use core::array;

    use p3_challenger::{HashChallenger, SerializingChallenger32};
    use p3_commit::ExtensionMmcs;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{TwoAdicFriPcs, create_benchmark_fri_params};
    use p3_keccak::{Keccak256Hash, KeccakF};
    use p3_koala_bear::KoalaBear;
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
    use p3_uni_stark::{StarkConfig, prove, verify};
    use rand::rngs::SmallRng;
    use rand::{Rng, SeedableRng};

    type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, DIGEST_ELEMS>;
    type Val = KoalaBear;
    type FieldHash = SerializingHasher<U64Hash>;

    const NUM_INPUTS: usize = 4;
    const HEIGHT: usize = 8;
    const DIGEST_ELEMS: usize = 4;
    const MAX_TREE_HEIGHT: usize = 8;

    // Generate random inputs.
    let mut rng = SmallRng::seed_from_u64(1);
    let roots: [_; NUM_INPUTS] = array::from_fn(|_| rng.random::<[Val; DIGEST_ELEMS]>());
    let indices: [_; NUM_INPUTS] = array::from_fn(|_| rng.random::<u32>() as usize);

    // We generate the siblings, with an extra hash at half the height for half of the inputs.
    let siblings: [[_; HEIGHT]; NUM_INPUTS] = array::from_fn(|i| {
        if i % 2 == 0 {
            array::from_fn(|j| {
                if j == HEIGHT / 2 {
                    (
                        rng.random::<[Val; DIGEST_ELEMS]>(),
                        Some(rng.random::<[Val; DIGEST_ELEMS]>()),
                    )
                } else {
                    (rng.random::<[Val; DIGEST_ELEMS]>(), None)
                }
            })
        } else {
            array::from_fn(|_| (rng.random::<[Val; DIGEST_ELEMS]>(), None))
        }
    });

    let inputs = (0..NUM_INPUTS)
        .map(|i| {
            (
                roots[i],
                indices[i],
                siblings[i].to_vec(),
                // extra_heights[i].to_vec(),
            )
        })
        .collect::<Vec<_>>();

    let u64_hash = U64Hash::new(KeccakF {});

    type MyCompress = CompressionFunctionFromHasher<U64Hash, 2, DIGEST_ELEMS>;
    let compress = MyCompress::new(u64_hash);

    // Create the AIR.
    let air =
        MerkleTreeAir::<Val, MyCompress, DIGEST_ELEMS, MAX_TREE_HEIGHT>::new(compress.clone());

    // Generate trace for Merkle tree table.
    let trace = air.generate_trace_rows(&inputs);

    // Prove with Keccak.
    type Challenge = BinomialExtensionField<Val, 4>;

    type ByteHash = Keccak256Hash;
    let byte_hash = ByteHash {};

    let field_hash = FieldHash::new(u64_hash);

    type ValMmcs = MerkleTreeMmcs<
        [Val; p3_keccak::VECTOR_LEN],
        [u64; p3_keccak::VECTOR_LEN],
        FieldHash,
        MyCompress,
        4,
    >;

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

    let proof = prove(&config, &air, trace, &vec![]);

    // Verify the proof.
    verify(&config, &air, &proof, &vec![])
}
