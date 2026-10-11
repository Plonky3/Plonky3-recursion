//! Arity-4 byte-hash Merkle trees: the circuit's level schedule matches p3's
//! `MerkleTreeMmcs`.

use p3_binary_field::BinaryField8;
use p3_circuit::ops::MmcsAritySchedule;
use p3_commit::Mmcs;
use p3_field::PrimeCharacteristicRing;
use p3_keccak::Keccak256Hash;
use p3_matrix::Dimensions;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, SerializingHasher};
use proptest::prelude::*;

type FieldHash = SerializingHasher<Keccak256Hash>;
type KeccakMmcs<const N: usize> = MerkleTreeMmcs<
    BinaryField8,
    u8,
    FieldHash,
    CompressionFunctionFromHasher<Keccak256Hash, N, 32>,
    N,
    32,
>;

const fn keccak_mmcs<const N: usize>(cap_height: usize) -> KeccakMmcs<N> {
    KeccakMmcs::new(
        FieldHash::new(Keccak256Hash),
        CompressionFunctionFromHasher::new(Keccak256Hash),
        cap_height,
    )
}

/// `max_height` and the shorter heights its tree can inject,
/// `ceil(max_height / 2^k)` for `k >= 1`, selected by the bits of `mask`.
fn ladder(max_height: usize, mask: u64) -> Vec<usize> {
    let rungs = max_height.next_power_of_two().ilog2();
    let mut heights = vec![max_height];
    heights.extend(
        (1..=rungs)
            .filter(|k| mask >> (k - 1) & 1 == 1)
            .map(|k| ((max_height - 1) >> k) + 1),
    );
    heights
}

/// The levels and siblings an opening walks under each cap height match p3,
/// which derives them from the dimensions alone.
fn check_proof_schedule<const N: usize>(
    heights: &[usize],
    cap_heights: impl IntoIterator<Item = usize>,
) -> MmcsAritySchedule {
    let schedule = MmcsAritySchedule::new::<N>(heights).unwrap();
    let dims: Vec<_> = heights
        .iter()
        .map(|&height| Dimensions { width: 1, height })
        .collect();
    for cap_height in cap_heights {
        let expected = keccak_mmcs::<N>(cap_height)
            .proof_arity_schedule(&dims)
            .unwrap();
        assert_eq!(
            schedule.steps()[..schedule.proof_levels(cap_height)],
            expected,
            "arity {N}, heights {heights:?}, cap height {cap_height}"
        );
        assert_eq!(
            schedule.proof_siblings(cap_height),
            expected.iter().map(|step| step - 1).sum::<usize>()
        );
    }
    schedule
}

/// Every cap height, including one past the tree: the walked levels match
/// p3, and a committed tree's cap of each height has `cap_len` roots.
fn check_tree<const N: usize>(heights: &[usize]) {
    let levels = MmcsAritySchedule::new::<N>(heights).unwrap().steps().len();
    let schedule = check_proof_schedule::<N>(heights, 0..=levels + 1);
    let matrices = heights
        .iter()
        .map(|&height| RowMajorMatrix::new(vec![BinaryField8::ZERO; height], 1))
        .collect();
    let (_, tree) = keccak_mmcs::<N>(0).commit(matrices);
    for cap_height in 0..=levels {
        assert_eq!(
            tree.cap(cap_height).num_roots(),
            schedule.cap_len(cap_height),
            "arity {N}, heights {heights:?}, cap height {cap_height}"
        );
    }
    assert_eq!(schedule.cap_len(levels + 1), schedule.cap_len(levels));
}

#[test]
fn schedules_match_p3_trees_for_every_small_height_ladder() {
    for max_height in 1..=40usize {
        for mask in 0..1u64 << max_height.next_power_of_two().ilog2() {
            let heights = ladder(max_height, mask);
            check_tree::<2>(&heights);
            check_tree::<4>(&heights);
        }
    }
}

/// A single `2^k`-row matrix needs `ceil(k / 2)` four-way levels instead of
/// `k` pairwise ones; for odd `k` the top group pads two digests to four.
#[test]
fn single_matrix_trees_halve_their_levels() {
    for k in 0..=40usize {
        let schedule = MmcsAritySchedule::new::<4>(&[1 << k]).unwrap();
        assert_eq!(schedule.steps(), vec![4; k.div_ceil(2)], "height 2^{k}");
        assert_eq!(
            MmcsAritySchedule::new::<2>(&[1 << k]).unwrap().steps(),
            vec![2; k]
        );
        // Two cap levels hold sixteen roots once the tree has them.
        assert_eq!(schedule.cap_len(2), 4usize.pow(k.div_ceil(2).min(2) as u32));
    }
}

#[test]
fn schedules_reject_heights_no_tree_has() {
    for heights in [&[][..], &[0], &[8, 3], &[7, 3], &[usize::MAX]] {
        assert!(
            MmcsAritySchedule::new::<4>(heights).is_err(),
            "heights {heights:?}"
        );
    }
    assert!(MmcsAritySchedule::new::<3>(&[8]).is_err());
    assert!(MmcsAritySchedule::new::<1>(&[8]).is_err());
}

proptest! {
    #[test]
    fn schedules_match_p3_for_tall_height_ladders(
        log_max in 1u32..=40,
        offset in any::<u64>(),
        mask in any::<u64>(),
        cap_height in 0usize..24,
    ) {
        let half = 1usize << (log_max - 1);
        let max_height = half + 1 + offset as usize % half;
        let heights = ladder(max_height, mask);
        check_proof_schedule::<2>(&heights, [0, cap_height]);
        check_proof_schedule::<4>(&heights, [0, cap_height]);
    }
}
