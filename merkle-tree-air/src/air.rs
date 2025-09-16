use alloc::vec;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::marker::PhantomData;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_baby_bear::{BabyBearParameters, Poseidon2BabyBear};
use p3_field::{Field, PackedValue, PrimeCharacteristicRing, PrimeField};
use p3_matrix::Matrix;
use p3_symmetric::PseudoCompressionFunction;

use crate::cols::{MerklePrivateData, MerkleTrace, MerkleTreeCols, get_num_merkle_tree_cols};
// `DIGEST_ELEMS` is the number of digest elements of the hash. `MAX_TREE_HEIGHT` is the maximal tree height that can be handled by the AIR.
pub struct MerkleVerifyAir<F, const DIGEST_ELEMS: usize, const MAX_TREE_HEIGHT: usize>
where
    F: Field,
{
    _phantom: PhantomData<F>,
}

impl<F: Field, const DIGEST_ELEMS: usize, const MAX_TREE_HEIGHT: usize>
    MerkleVerifyAir<F, DIGEST_ELEMS, MAX_TREE_HEIGHT>
{
    pub fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }
}

impl<F: Field, const DIGEST_ELEMS: usize, const MAX_TREE_HEIGHT: usize> BaseAir<F>
    for MerkleVerifyAir<F, DIGEST_ELEMS, MAX_TREE_HEIGHT>
where
    F: Field,
    F: Eq,
{
    fn width(&self) -> usize {
        get_num_merkle_tree_cols::<DIGEST_ELEMS, MAX_TREE_HEIGHT>()
    }
}

impl<AB: AirBuilder, const DIGEST_ELEMS: usize, const MAX_TREE_HEIGHT: usize> Air<AB>
    for MerkleVerifyAir<AB::F, DIGEST_ELEMS, MAX_TREE_HEIGHT>
where
    AB::F: PrimeField,
    AB::F: Eq,
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
        // So `local.is_extra`, `local.is_final` and `next.is_final` cannot be set at the same time.
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
            // During one merkle batch verification, and when the current row is not `is_extra` and neither the current nor the next row are final, the height encoding is shifted.
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

    use p3_baby_bear::BabyBear;
    use p3_challenger::{HashChallenger, SerializingChallenger32};
    use p3_commit::ExtensionMmcs;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{TwoAdicFriPcs, create_benchmark_fri_params};
    use p3_keccak::{Keccak256Hash, KeccakF};
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_symmetric::{
        CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher, TruncatedPermutation,
    };
    use p3_uni_stark::{StarkConfig, prove, verify};
    use rand::rngs::SmallRng;
    use rand::{Rng, SeedableRng};

    type Val = BabyBear;
    type FieldHash = SerializingHasher<U64Hash>;
    type Poseidon2Compression<Perm16> = TruncatedPermutation<Perm16, 2, 8, 16>;

    const NUM_INPUTS: usize = 4;
    const HEIGHT: usize = 8;
    const DIGEST_ELEMS: usize = 4;
    const MAX_TREE_HEIGHT: usize = 8;

    // Generate random inputs.

    let mut rng = SmallRng::seed_from_u64(1);
    let private_data: [MerklePrivateData<Val>; NUM_INPUTS] = array::from_fn(|i| {
        let path_siblings = if i % 2 == 0 {
            (0..HEIGHT)
                .map(|j| {
                    if j == HEIGHT / 2 {
                        (
                            vec![rng.random::<Val>(); DIGEST_ELEMS],
                            Some(vec![rng.random::<Val>(); DIGEST_ELEMS]),
                        )
                    } else {
                        (vec![rng.random::<Val>(); DIGEST_ELEMS], None)
                    }
                })
                .collect()
        } else {
            vec![(vec![rng.random::<Val>(); DIGEST_ELEMS], None); HEIGHT]
        };
        let path_directions = vec![rng.random::<bool>(); HEIGHT];
        MerklePrivateData {
            path_siblings,
            path_directions,
        }
    });

    let public_data = [[rng.random::<Val>(); DIGEST_ELEMS]; NUM_INPUTS];

    type ByteHash = Keccak256Hash;
    let byte_hash = ByteHash {};

    type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
    let u64_hash = U64Hash::new(KeccakF {});

    let field_hash = FieldHash::new(u64_hash);

    type MyCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
    let compress = MyCompress::new(u64_hash);

    let leaf_index = |x: &Vec<bool>| {
        x.iter()
            .enumerate()
            .filter(|(_, dir)| **dir)
            .map(|(i, _)| 1 << i)
            .sum()
    };

    let trace = MerkleTrace {
        merkle_paths: private_data
            .iter()
            .zip(public_data.iter())
            .map(|(data, leaf)| {
                data.to_trace::<_, _, 1>(&compress, leaf_index(&data.path_directions), *leaf)
                    .unwrap()
            })
            .collect(),
    };

    // Create the AIR.
    let air = MerkleVerifyAir::<Val, DIGEST_ELEMS, MAX_TREE_HEIGHT>::new();

    // Generate trace for Merkle tree table.
    let trace = MerkleVerifyAir::<Val, DIGEST_ELEMS, MAX_TREE_HEIGHT>::trace_to_matrix(&trace);

    // Prove with Keccak.
    type Challenge = BinomialExtensionField<Val, 4>;

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
