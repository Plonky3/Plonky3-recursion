//! Arity-2 and arity-4 byte-hash Merkle trees: the circuit's level schedule
//! and openings match p3's `MerkleTreeMmcs` under the native binary and prime
//! hosts.

use core::hash::Hash;

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField8, BinaryField128, Poly64, TowerLevel};
use p3_blake3::Blake3;
use p3_circuit::ops::binary_encoding::{NativeBinaryEncoding, PrimeBinaryEncoding};
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::{ByteHash, MmcsAritySchedule, bytes_to_limbs};
use p3_circuit::{AluOpKind, CircuitBuilder, ExprId, WitnessId};
use p3_commit::Mmcs;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_keccak::Keccak256Hash;
use p3_matrix::dense::RowMajorMatrix;
use p3_matrix::{Dimensions, Matrix};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, SerializingHasher};
use proptest::prelude::*;

type ByteMmcs<Hs, const N: usize> = MerkleTreeMmcs<
    BinaryField8,
    u8,
    SerializingHasher<Hs>,
    CompressionFunctionFromHasher<Hs, N, 32>,
    N,
    32,
>;

const fn byte_mmcs<Hs: Copy, const N: usize>(hasher: Hs, cap_height: usize) -> ByteMmcs<Hs, N> {
    ByteMmcs::new(
        SerializingHasher::new(hasher),
        CompressionFunctionFromHasher::new(hasher),
        cap_height,
    )
}

const fn keccak_mmcs<const N: usize>(cap_height: usize) -> ByteMmcs<Keccak256Hash, N> {
    byte_mmcs(Keccak256Hash, cap_height)
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

/// A circuit field for the opening gadget, with its byte hash enabled.
struct Carrier<F: Field + Eq + Hash, Hs = Keccak256Hash> {
    builder: fn() -> CircuitBuilder<F>,
    /// A word plus `2^16`: equal to it in the low sixteen bits, but no
    /// sixteen-bit word.
    widen: fn(F) -> F,
    /// The byte hash and the p3 hasher of its trees.
    hash: ByteHash,
    hasher: Hs,
}

fn native<F: BinaryCoordinateField>() -> Carrier<F> {
    Carrier {
        builder: || {
            let mut b = CircuitBuilder::new();
            b.enable_native_keccak_f1600().unwrap();
            b
        },
        widen: |word| word + F::from_raw_coordinates(1 << 16).unwrap(),
        hash: ByteHash::Keccak256,
        hasher: Keccak256Hash,
    }
}

fn prime() -> Carrier<BabyBear> {
    Carrier {
        builder: || {
            let mut b = CircuitBuilder::new();
            b.enable_keccak_f1600::<BabyBear>();
            b
        },
        widen: |word| word + BabyBear::from_u32(1 << 16),
        hash: ByteHash::Keccak256,
        hasher: Keccak256Hash,
    }
}

fn native_blake3<F: BinaryCoordinateField>() -> Carrier<F, Blake3> {
    Carrier {
        builder: || {
            let mut b = CircuitBuilder::new();
            b.enable_native_blake3_compress().unwrap();
            b
        },
        widen: |word| word + F::from_raw_coordinates(1 << 16).unwrap(),
        hash: ByteHash::Blake3,
        hasher: Blake3,
    }
}

fn prime_blake3() -> Carrier<BabyBear, Blake3> {
    Carrier {
        builder: || {
            let mut b = CircuitBuilder::new();
            b.enable_blake3_compress::<BabyBear>();
            b
        },
        widen: |word| word + BabyBear::from_u32(1 << 16),
        hash: ByteHash::Blake3,
        hasher: Blake3,
    }
}

/// Matrix `m` of a commitment, whose rows start with their distinct index so
/// that every leaf and node digest differs. Word rows have an even byte width
/// and byte rows an odd one.
fn matrices(heights: &[usize], words: bool) -> Vec<RowMajorMatrix<BinaryField8>> {
    heights
        .iter()
        .enumerate()
        .map(|(m, &height)| {
            let width = if words { 2 * m + 2 } else { 2 * m + 3 };
            let values = (0..height)
                .flat_map(|row| {
                    (0..width).map(move |column| match column {
                        0 => row as u8,
                        1 => (row >> 8) as u8 ^ m as u8,
                        _ => (row * 37 + column * 101 + m * 19 + 129) as u8,
                    })
                })
                .map(BinaryField8::from_repr)
                .collect();
            RowMajorMatrix::new(values, width)
        })
        .collect()
}

/// Opens `index` of a p3 arity-`N` tree over matrices of `heights` and checks
/// that the gadget accepts exactly that opening. Every opened row, sibling,
/// sibling order within a group, index bit and the selected cap root is
/// bound, while the other cap roots are not read. Every sibling word is an
/// input word of one node hash, which bounds it to sixteen bits as a native
/// hash block input (a Keccak lane or a Blake3 block word) or through the
/// prime host's word decomposition, so a sibling word widened past sixteen
/// bits is rejected with no range check of its own.
fn check_opening<F, H, Hs, const N: usize>(
    carrier: &Carrier<F, Hs>,
    heights: &[usize],
    cap_height: usize,
    index: usize,
    words: bool,
) where
    F: Field + Eq + Hash,
    H: BinaryCircuitHost<F>,
    Hs: CryptographicHasher<u8, [u8; 32]> + Copy + Sync,
{
    let mmcs = byte_mmcs::<Hs, N>(carrier.hasher, cap_height);
    let matrices = matrices(heights, words);
    let dims: Vec<_> = matrices.iter().map(Matrix::dimensions).collect();
    let (commitment, data) = mmcs.commit(matrices);
    let opening = mmcs.open_batch(index, &data);
    mmcs.verify_batch(&commitment, &dims, index, (&opening).into())
        .unwrap();
    let schedule = MmcsAritySchedule::new::<N>(heights).unwrap();
    let proof = &opening.opening_proof;
    let roots = commitment.roots();
    assert_eq!(proof.len(), schedule.proof_siblings(cap_height));
    assert_eq!(roots.len(), schedule.cap_len(cap_height));
    let walked = &schedule.steps()[..schedule.proof_levels(cap_height)];
    let log_max = heights.iter().max().unwrap().next_power_of_two().ilog2() as usize;

    let mut b = (carrier.builder)();
    let mut inputs = |count| (0..count).map(|_| b.public_input()).collect::<Vec<_>>();
    let rows: Vec<_> = dims
        .iter()
        .map(|d| inputs(if words { d.width / 2 } else { d.width }))
        .collect();
    let bits = inputs(log_max);
    let siblings: Vec<_> = proof.iter().map(|_| inputs(16)).collect();
    let cap: Vec<_> = roots.iter().map(|_| inputs(16)).collect();
    if words {
        b.verify_byte_hash_mmcs_opening_words_with_host_arity::<H, N>(
            carrier.hash,
            &rows,
            heights,
            &bits,
            &siblings,
            &cap,
        )
    } else {
        b.verify_byte_hash_mmcs_opening_bytes_with_host_arity::<H, N>(
            carrier.hash,
            &rows,
            heights,
            &bits,
            &siblings,
            &cap,
        )
    }
    .unwrap();
    let circuit = b.build().unwrap();

    // Sixteen-bit inputs, with index bits 0 or 1.
    let mut raw: Vec<u16> = Vec::new();
    let mut row_ends = Vec::new();
    for row in &opening.opened_values {
        let bytes: Vec<u8> = row.iter().map(|x| x.to_repr()).collect();
        if words {
            raw.extend(bytes_to_limbs(&bytes));
        } else {
            raw.extend(bytes.into_iter().map(u16::from));
        }
        row_ends.push(raw.len());
    }
    let bits_start = raw.len();
    raw.extend((0..log_max).map(|bit| (index >> bit & 1) as u16));
    let siblings_start = raw.len();
    for digest in proof.iter().chain(roots) {
        raw.extend(bytes_to_limbs(digest));
    }
    let cap_start = siblings_start + 16 * proof.len();
    let encode = |raw: &[u16]| -> Vec<F> {
        raw.iter()
            .enumerate()
            .map(|(i, &word)| {
                if (bits_start..siblings_start).contains(&i) {
                    F::from_bool(word == 1)
                } else {
                    H::encode_u16(word).unwrap()
                }
            })
            .collect()
    };
    let runs_public = |public: &[F]| {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(public)
            .and_then(|()| runner.run())
            .is_ok()
    };
    let runs = |raw: &[u16]| runs_public(&encode(raw));
    let flipped = |position: usize| {
        let mut wrong = raw.clone();
        wrong[position] ^= 1;
        wrong
    };
    let widened = |position: usize| {
        let mut wrong = encode(&raw);
        wrong[position] = (carrier.widen)(wrong[position]);
        wrong
    };
    let label =
        format!("heights {heights:?}, cap height {cap_height}, index {index}, words {words}");

    assert!(runs(&raw), "honest opening, {label}");
    for &end in &row_ends {
        assert!(!runs(&flipped(end - 1)), "row ending at {end}, {label}");
    }
    assert!(!runs_public(&widened(0)), "widened row input, {label}");
    for bit in bits_start..siblings_start {
        assert!(
            !runs(&flipped(bit)),
            "index bit {}, {label}",
            bit - bits_start
        );
    }
    for sibling in 0..proof.len() {
        let start = siblings_start + 16 * sibling;
        assert!(!runs(&flipped(start + 7)), "sibling {sibling}, {label}");
        assert!(
            !runs_public(&widened(start)),
            "widened sibling {sibling}, {label}"
        );
    }
    // Two siblings of one group swap positions; only equal (padding) digests
    // swap unnoticed.
    let mut group_start = 0;
    for &step in walked {
        for pair in group_start..group_start + step - 2 {
            let mut swapped = raw.clone();
            for i in 0..16 {
                swapped.swap(
                    siblings_start + 16 * pair + i,
                    siblings_start + 16 * (pair + 1) + i,
                );
            }
            assert_eq!(
                runs(&swapped),
                proof[pair] == proof[pair + 1],
                "siblings {pair} and {} swapped, {label}",
                pair + 1
            );
        }
        group_start += step - 1;
    }
    let cap_index = index / walked.iter().product::<usize>();
    for root in 0..roots.len() {
        assert_eq!(
            runs(&flipped(cap_start + 16 * root + 5)),
            root != cap_index,
            "cap root {root}, {label}"
        );
    }
}

/// Single matrices of `2^k` rows for odd and even `k`, under caps of up to two
/// levels at arity four, whose odd top groups pad two digests to four, and of
/// up to four levels at arity two; then mixed heights with injections,
/// pairwise bridges and a tallest height of seven rows.
fn check_openings<F, H, Hs, const N: usize>(carrier: &Carrier<F, Hs>)
where
    F: Field + Eq + Hash,
    H: BinaryCircuitHost<F>,
    Hs: CryptographicHasher<u8, [u8; 32]> + Copy + Sync,
{
    for words in [false, true] {
        for k in 1..=5usize {
            let height = 1 << k;
            let mut indices = vec![0, 5 % height, 10 % height, height - 1];
            indices.sort_unstable();
            indices.dedup();
            let max_cap = if N == 4 {
                k.div_ceil(2).min(2)
            } else {
                k.min(4)
            };
            for cap_height in 0..=max_cap {
                for &index in &indices {
                    check_opening::<F, H, Hs, N>(carrier, &[height], cap_height, index, words);
                }
            }
        }
        for (heights, top_cap) in [
            (&[7, 4, 2, 1][..], 0),
            (&[8, 4], 1),
            (&[16, 4], 1),
            (&[32, 8, 2], 1),
            (&[32, 16], 1),
        ] {
            let max_height = heights[0];
            for cap_height in 0..=top_cap {
                for index in [0, 3, max_height - 1] {
                    check_opening::<F, H, Hs, N>(carrier, heights, cap_height, index, words);
                }
            }
        }
    }
}

#[test]
fn native_tower_openings_match_p3_arity_four_trees() {
    check_openings::<BinaryField128, NativeBinaryEncoding, _, 4>(&native());
}

#[test]
fn native_polynomial_openings_match_p3_arity_four_trees() {
    check_openings::<Poly64, NativeBinaryEncoding, _, 4>(&native());
}

#[test]
fn prime_openings_match_p3_arity_four_trees() {
    check_openings::<BabyBear, PrimeBinaryEncoding<BabyBear>, _, 4>(&prime());
}

/// A Blake3 node hashes its 128 digest bytes as two blocks of one chunk.
#[test]
fn prime_blake3_openings_match_p3_arity_four_trees() {
    check_openings::<BabyBear, PrimeBinaryEncoding<BabyBear>, _, 4>(&prime_blake3());
}

/// Under native Blake3 an arity-two node is one compression and an arity-four
/// node two, every digest word a direct block input.
#[test]
fn native_blake3_openings_match_p3_trees() {
    check_openings::<BinaryField128, NativeBinaryEncoding, _, 2>(&native_blake3());
    check_openings::<BinaryField128, NativeBinaryEncoding, _, 4>(&native_blake3());
    check_openings::<Poly64, NativeBinaryEncoding, _, 2>(&native_blake3());
    check_openings::<Poly64, NativeBinaryEncoding, _, 4>(&native_blake3());
}

/// Every height ladder of up to sixteen rows, one index each: the root binds
/// the level each shorter matrix is injected at, which the schedule parity
/// tests do not compare.
#[test]
fn native_openings_match_p3_arity_four_trees_for_every_small_height_ladder() {
    for max_height in 1..=16usize {
        for mask in 0..1u64 << max_height.next_power_of_two().ilog2() {
            let heights = ladder(max_height, mask);
            let index = mask as usize % max_height;
            for words in [false, true] {
                check_opening::<Poly64, NativeBinaryEncoding, _, 4>(
                    &native(),
                    &heights,
                    0,
                    index,
                    words,
                );
            }
        }
    }
}

/// Index bits are Boolean. The first four rows of a sixteen-row matrix are
/// equal, so an opening of index 0 places the same digest in every slot of
/// the first level whatever the flags of that level's two index bits: the
/// opening holds with either bit 0 or 1, and with `non_boolean` only the
/// Booleanity check of that bit fails.
fn check_non_boolean_index_bits<F: Field + Eq + Hash, H: BinaryCircuitHost<F>>(
    carrier: &Carrier<F>,
    non_boolean: F,
) {
    let mmcs = keccak_mmcs::<4>(0);
    let values = (0..16u8)
        .flat_map(|row| [row / 4, 0x5a ^ (row / 4)])
        .map(BinaryField8::from_repr)
        .collect();
    let (commitment, data) = mmcs.commit(vec![RowMajorMatrix::new(values, 2)]);
    let opening = mmcs.open_batch(0, &data);
    let proof = &opening.opening_proof;
    assert!(proof[..3].iter().all(|sibling| *sibling == proof[0]));

    let mut b = (carrier.builder)();
    let mut inputs = |count| (0..count).map(|_| b.public_input()).collect::<Vec<_>>();
    let rows = [inputs(1)];
    let bits = inputs(4);
    let siblings: Vec<_> = proof.iter().map(|_| inputs(16)).collect();
    let cap = [inputs(16)];
    b.verify_byte_hash_mmcs_opening_words_with_host_arity::<H, 4>(
        ByteHash::Keccak256,
        &rows,
        &[16],
        &bits,
        &siblings,
        &cap,
    )
    .unwrap();
    let circuit = b.build().unwrap();

    let encode = |bytes: &[u8]| {
        bytes_to_limbs(bytes)
            .into_iter()
            .map(|word| H::encode_u16(word).unwrap())
            .collect::<Vec<F>>()
    };
    let row: Vec<u8> = opening.opened_values[0]
        .iter()
        .map(|x| x.to_repr())
        .collect();
    let mut public = encode(&row);
    let bits_start = public.len();
    public.extend([F::ZERO; 4]);
    for digest in proof.iter().chain(commitment.roots()) {
        public.extend(encode(digest));
    }
    // The runner forwards `BoolCheck` operands, so every run completes. This
    // returns the witnesses of the rows whose `b·(b − 1) = 0` the ALU AIR
    // rejects.
    let non_boolean_rows = |position: usize, bit: F| -> Vec<WitnessId> {
        let mut public = public.clone();
        public[bits_start + position] = bit;
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public).unwrap();
        let alu = runner.run().unwrap().alu_trace;
        alu.op_kind
            .iter()
            .zip(&alu.values)
            .zip(&alu.indices)
            .filter(|&((&kind, &[value, ..]), _)| {
                kind == AluOpKind::BoolCheck && !(value * (value - F::ONE)).is_zero()
            })
            .map(|(_, &[witness, ..])| witness)
            .collect()
    };
    for (position, bit) in bits[..2].iter().enumerate() {
        for boolean in [F::ZERO, F::ONE] {
            assert!(
                non_boolean_rows(position, boolean).is_empty(),
                "index bit {position} = {boolean:?}"
            );
        }
        assert_eq!(
            non_boolean_rows(position, non_boolean),
            [circuit.expr_to_widx[bit]],
            "index bit {position} non-Boolean"
        );
    }
}

#[test]
fn non_boolean_index_bits_fail_their_booleanity_check() {
    check_non_boolean_index_bits::<BinaryField128, NativeBinaryEncoding>(
        &native(),
        BinaryField128::from_raw_coordinates(2).unwrap(),
    );
    check_non_boolean_index_bits::<Poly64, NativeBinaryEncoding>(
        &native(),
        Poly64::from_raw_coordinates(2).unwrap(),
    );
    check_non_boolean_index_bits::<BabyBear, PrimeBinaryEncoding<BabyBear>>(
        &prime(),
        BabyBear::TWO,
    );
}

/// At arity two the arity entry points build the pairwise opening: the same
/// expressions, witnesses and operations.
fn check_pairwise_identity<F: Field + Eq + Hash, H: BinaryCircuitHost<F>>(carrier: &Carrier<F>) {
    for words in [false, true] {
        let build = |through_arity: bool| {
            let mut b = (carrier.builder)();
            let mut inputs = |count| (0..count).map(|_| b.public_input()).collect::<Vec<_>>();
            let rows = [inputs(3), inputs(2)];
            let bits = inputs(3);
            let siblings: Vec<_> = (0..2).map(|_| inputs(16)).collect();
            let cap: Vec<_> = (0..2).map(|_| inputs(16)).collect();
            let (hash, heights) = (ByteHash::Keccak256, [8, 4]);
            match (through_arity, words) {
                (false, true) => b.verify_byte_hash_mmcs_opening_words_with_host::<H>(
                    hash, &rows, &heights, &bits, &siblings, &cap,
                ),
                (true, true) => b.verify_byte_hash_mmcs_opening_words_with_host_arity::<H, 2>(
                    hash, &rows, &heights, &bits, &siblings, &cap,
                ),
                (false, false) => b.verify_byte_hash_mmcs_opening_bytes_with_host::<H>(
                    hash, &rows, &heights, &bits, &siblings, &cap,
                ),
                (true, false) => b.verify_byte_hash_mmcs_opening_bytes_with_host_arity::<H, 2>(
                    hash, &rows, &heights, &bits, &siblings, &cap,
                ),
            }
            .unwrap();
            b.build().unwrap()
        };
        let (pairwise, through_arity) = (build(false), build(true));
        assert_eq!(pairwise.witness_count, through_arity.witness_count);
        assert_eq!(pairwise.expr_to_widx, through_arity.expr_to_widx);
        assert_eq!(
            format!("{:?}", pairwise.ops),
            format!("{:?}", through_arity.ops)
        );
    }
}

#[test]
fn arity_two_is_the_pairwise_opening() {
    check_pairwise_identity::<BinaryField128, NativeBinaryEncoding>(&native());
    check_pairwise_identity::<Poly64, NativeBinaryEncoding>(&native());
    check_pairwise_identity::<BabyBear, PrimeBinaryEncoding<BabyBear>>(&prime());
}

/// A path through a `2^6`-row tree hashes its leaf and then three four-digest
/// nodes instead of six pairwise ones, each node one Keccak-f call.
#[test]
fn arity_four_halves_the_keccak_calls_of_a_path() {
    let calls = |arity4: bool| {
        let mut b = (native::<Poly64>().builder)();
        let mut inputs = |count| (0..count).map(|_| b.public_input()).collect::<Vec<_>>();
        let row = inputs(2);
        let bits = inputs(6);
        let siblings: Vec<_> = (0..if arity4 { 9 } else { 6 })
            .map(|_| inputs(16))
            .collect();
        let (rows, cap) = ([row], [inputs(16)]);
        let (hash, heights) = (ByteHash::Keccak256, [64]);
        if arity4 {
            b.verify_byte_hash_mmcs_opening_words_with_host_arity::<NativeBinaryEncoding, 4>(
                hash, &rows, &heights, &bits, &siblings, &cap,
            )
        } else {
            b.verify_byte_hash_mmcs_opening_words_with_host_arity::<NativeBinaryEncoding, 2>(
                hash, &rows, &heights, &bits, &siblings, &cap,
            )
        }
        .unwrap();
        b.construction_usage().unwrap().non_primitive_calls
    };
    assert_eq!(calls(false), 1 + 6);
    assert_eq!(calls(true), 1 + 3);
}

/// Shapes no arity-4 tree has fail before any constraint is added: another
/// arity, a cap size or sibling count off the schedule, a matrix injected
/// above the cap layer, a wrong index width and a short digest.
#[test]
fn malformed_arity_four_openings_are_rejected_before_mutation() {
    type H = NativeBinaryEncoding;
    let hash = ByteHash::Keccak256;
    let mut b = (native::<BinaryField128>().builder)();
    let input = b.public_input();
    let digests = |count: usize| vec![vec![ExprId::ZERO; 16]; count];
    let bits = |count: usize| vec![ExprId::ZERO; count];
    let row = vec![vec![input]];
    let two_rows = vec![vec![input], vec![input]];
    assert!(
        b.verify_byte_hash_mmcs_opening_words_with_host_arity::<H, 8>(
            hash,
            &row,
            &[16],
            &bits(4),
            &digests(3),
            &digests(4),
        )
        .is_err()
    );
    for (rows, heights, index_bits, siblings, cap) in [
        // Caps of 1, 4 and 16 roots exist; 2 do not.
        (&row, &[16][..], bits(4), digests(5), digests(2)),
        // A four-root cap leaves one walked level of three siblings.
        (&row, &[16], bits(4), digests(4), digests(4)),
        // The single row injects after the top level, inside the cap.
        (&two_rows, &[16, 1], bits(4), digests(3), digests(4)),
        (&row, &[16], bits(5), digests(3), digests(4)),
        (
            &row,
            &[16],
            bits(4),
            vec![vec![ExprId::ZERO; 15]; 3],
            digests(4),
        ),
    ] {
        assert!(
            b.verify_byte_hash_mmcs_opening_words_with_host_arity::<H, 4>(
                hash,
                rows,
                heights,
                &index_bits,
                &siblings,
                &cap,
            )
            .is_err(),
            "heights {heights:?}, {} siblings, {} roots",
            siblings.len(),
            cap.len()
        );
        assert!(
            b.verify_byte_hash_mmcs_opening_bytes_with_host_arity::<H, 4>(
                hash,
                rows,
                heights,
                &index_bits,
                &siblings,
                &cap,
            )
            .is_err()
        );
    }
    let rejected = b.build().unwrap();
    let mut control = (native::<BinaryField128>().builder)();
    control.public_input();
    let control = control.build().unwrap();
    assert_eq!(rejected.witness_count, control.witness_count);
    assert_eq!(rejected.expr_to_widx, control.expr_to_widx);
    assert_eq!(format!("{:?}", rejected.ops), format!("{:?}", control.ops));
}
