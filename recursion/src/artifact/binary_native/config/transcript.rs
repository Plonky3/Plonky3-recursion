//! Byte transcript of the native challenger and its proof-of-work search.

use alloc::vec::Vec;
use core::iter::repeat;
use core::ops::Range;
use core::sync::atomic::{AtomicU64, Ordering};

use p3_binary_field::TowerLevel;
use p3_challenger::{CanObserve, CanSample};
use p3_circuit::ops::ByteHash;
use p3_keccak::{KeccakF, VECTOR_LEN};
use p3_maybe_rayon::prelude::*;
use p3_symmetric::{CryptographicHasher, Permutation};

use super::BinaryNativeHash;

/// Headroom, in bits, that a grinding request leaves below the width of the
/// candidate space: `2^8` expected witnesses, as `BinaryChallenger` requires.
const GRIND_MARGIN_BITS: usize = 8;

/// Consecutive candidates a worker takes at a time and scans in order.
const GRIND_CHUNK: u64 = 1 << 10;

/// Message bytes Keccak-256 absorbs per permutation.
const KECCAK_RATE: usize = 136;

/// Keccak-256 state word holding the last eight digest bytes.
const KECCAK_LAST_DIGEST_WORD: usize = 3;

/// Byte transcript over the native hash.
///
/// Observed bytes accumulate as pending input. A draw from an empty output
/// hashes the pending input, keeps the digest as the next pending input, and
/// serves the digest's bytes from last to first. This is the transcript of
/// `p3_challenger::HashChallenger<u8, BinaryNativeHash, 32>`, with the pending
/// input visible to the witness search.
#[derive(Clone)]
pub(super) struct NativeTranscript {
    input: Vec<u8>,
    output: Vec<u8>,
    hash: BinaryNativeHash,
}

impl NativeTranscript {
    pub(super) const fn new(initial: Vec<u8>, hash: ByteHash) -> Self {
        Self {
            input: initial,
            output: Vec::new(),
            hash: BinaryNativeHash(hash),
        }
    }

    fn flush(&mut self) {
        let digest = self.hash.hash_iter_slices([self.input.as_slice()]);
        self.input.clear();
        self.input.extend_from_slice(&digest);
        self.output.clear();
        self.output.extend_from_slice(&digest);
    }

    /// The smallest-index proof-of-work witness for `bits` against this transcript.
    ///
    /// Candidates, their order, the search range and the panics are those of
    /// `p3_binary_field::BinaryChallenger::grind`. Of the valid candidates the
    /// first is returned, so the witness does not depend on thread scheduling.
    /// The transcript is not advanced.
    ///
    /// # Panics
    /// Panics unless `bits + GRIND_MARGIN_BITS <= min(F::bits(), 64)`.
    pub(super) fn grind<F: TowerLevel>(&self, bits: usize) -> F {
        if bits == 0 {
            return F::ZERO;
        }
        assert!(bits < (usize::BITS as usize));
        assert!(
            bits + GRIND_MARGIN_BITS <= F::bits().min(u64::BITS as usize),
            "requested bit count leaves too small a margin against the witness field's size"
        );
        let num_candidates = if F::bits() >= u64::BITS as usize {
            u64::MAX
        } else {
            1u64 << F::bits()
        };

        // Checking a witness observes its bytes and then draws, which hashes the
        // pending input followed by those bytes. The pending input is absorbed once.
        let prefix = Prefix::new(self.hash.0, &self.input, F::NUM_BYTES);
        let mask = (1u64 << bits) - 1;

        // Workers take chunks in increasing order and stop at the first chunk
        // that starts past the best witness found so far. Every chunk below the
        // final best is therefore scanned, which makes it the smallest passing
        // index without a barrier between workers.
        let next_chunk = AtomicU64::new(0);
        let best = AtomicU64::new(u64::MAX);
        (0..current_num_threads()).into_par_iter().for_each(|_| {
            loop {
                let chunk = next_chunk.fetch_add(1, Ordering::Relaxed);
                let low = chunk.saturating_mul(GRIND_CHUNK);
                if low >= num_candidates.min(best.load(Ordering::Relaxed)) {
                    break;
                }
                let high = low.saturating_add(GRIND_CHUNK).min(num_candidates);
                if let Some(index) = prefix.first_pass::<F>(low..high, mask) {
                    best.fetch_min(index, Ordering::Relaxed);
                }
            }
        });
        // `u64::MAX` is never a candidate index: the range stops below it.
        let index = best.into_inner();
        assert!(index < num_candidates, "failed to find witness");
        candidate(index)
    }
}

impl CanObserve<u8> for NativeTranscript {
    fn observe(&mut self, value: u8) {
        self.output.clear();
        self.input.push(value);
    }

    fn observe_slice(&mut self, values: &[u8]) {
        if !values.is_empty() {
            self.output.clear();
            self.input.extend_from_slice(values);
        }
    }
}

impl CanSample<u8> for NativeTranscript {
    fn sample(&mut self) -> u8 {
        if self.output.is_empty() {
            self.flush();
        }
        self.output.pop().expect("a flush leaves a whole digest")
    }
}

/// The `index`-th grinding candidate: the element whose low bytes are those of `index`.
fn candidate<F: TowerLevel>(index: u64) -> F {
    F::from_le_byte_iter(index.to_le_bytes().into_iter().chain(repeat(0)))
}

/// The bytes `BinaryChallenger` absorbs when it observes `value`, and their count.
fn observed_bytes<F: TowerLevel>(value: F) -> ([u8; 16], usize) {
    let mut bytes = [0; 16];
    for (slot, byte) in bytes.iter_mut().zip(value.into_bytes()) {
        *slot = byte;
    }
    (bytes, F::NUM_BYTES)
}

/// The value of a bit draw from a digest ending in `last`: the draw consumes
/// the digest's bytes last to first and reads them as a little-endian integer.
const fn draw(last: [u8; 8]) -> u64 {
    u64::from_be_bytes(last)
}

/// The native hash with a fixed prefix absorbed, ready to finish the message of
/// each grinding candidate. One is built per grind and shared by its workers.
#[allow(clippy::large_enum_variant)]
enum Prefix {
    Keccak256(KeccakPrefix),
    Blake3(blake3::Hasher),
}

impl Prefix {
    /// `BinaryNativeHash(hash)` after absorbing `prefix`, for candidates of
    /// `witness_len` bytes.
    fn new(hash: ByteHash, prefix: &[u8], witness_len: usize) -> Self {
        match hash {
            ByteHash::Keccak256 => Self::Keccak256(KeccakPrefix::new(prefix, witness_len)),
            ByteHash::Blake3 => {
                let mut state = blake3::Hasher::new();
                state.update(prefix);
                Self::Blake3(state)
            }
        }
    }

    /// The smallest index in `range` whose candidate passes: the digest of the
    /// prefix followed by the candidate's bytes draws zero under `mask`.
    fn first_pass<F: TowerLevel>(&self, range: Range<u64>, mask: u64) -> Option<u64> {
        match self {
            Self::Keccak256(prefix) => prefix.first_pass::<F>(range, mask),
            Self::Blake3(prefix) => range.into_iter().find(|&index| {
                let (bytes, len) = observed_bytes(candidate::<F>(index));
                let mut state = prefix.clone();
                state.update(&bytes[..len]);
                let digest = state.finalize();
                let last = digest.as_bytes()[24..].try_into().expect("eight bytes");
                draw(last) & mask == 0
            }),
        }
    }
}

/// Keccak-256 with the whole rate blocks of a prefix absorbed.
///
/// The rest of every candidate's message is the same apart from the witness:
///
/// ```text
///     [ rest of prefix | witness | 0x01 | 0x00 ... 0x00 | 0x80 ]
///                      ^ witness_at                       ^ num_blocks * KECCAK_RATE - 1
/// ```
///
/// This is Keccak's `pad10*1` with the original domain byte; when the message
/// ends one byte short of a block, both marks fall in one byte, `0x81`. It is
/// finished for `VECTOR_LEN` candidates at once, one per permutation lane.
struct KeccakPrefix {
    state: [u64; 25],
    blocks: [u8; 2 * KECCAK_RATE],
    witness_at: usize,
    num_blocks: usize,
}

impl KeccakPrefix {
    fn new(prefix: &[u8], witness_len: usize) -> Self {
        let (whole, rest) = prefix.split_at(prefix.len() - prefix.len() % KECCAK_RATE);
        let mut state = [0; 25];
        for block in whole.as_chunks::<KECCAK_RATE>().0 {
            for (word, bytes) in state.iter_mut().zip(block.as_chunks::<8>().0) {
                *word ^= u64::from_le_bytes(*bytes);
            }
            KeccakF.permute_mut(&mut state);
        }
        // A rest shorter than a block and a witness of at most 16 bytes fit in two blocks.
        let len = rest.len() + witness_len;
        let num_blocks = len / KECCAK_RATE + 1;
        let mut blocks = [0; 2 * KECCAK_RATE];
        blocks[..rest.len()].copy_from_slice(rest);
        blocks[len] ^= 0x01;
        blocks[num_blocks * KECCAK_RATE - 1] ^= 0x80;
        Self {
            state,
            blocks,
            witness_at: rest.len(),
            num_blocks,
        }
    }

    /// [`Prefix::first_pass`], one lane group of candidates per permutation.
    fn first_pass<F: TowerLevel>(&self, range: Range<u64>, mask: u64) -> Option<u64> {
        let mut lanes = [self.blocks; VECTOR_LEN];
        let mut first = range.start;
        while first < range.end {
            let count = (range.end - first).min(VECTOR_LEN as u64) as usize;
            // Spare lanes of a short final group repeat its first candidate.
            for (lane, blocks) in lanes.iter_mut().enumerate() {
                let index = if lane < count {
                    first + lane as u64
                } else {
                    first
                };
                let (bytes, len) = observed_bytes(candidate::<F>(index));
                blocks[self.witness_at..][..len].copy_from_slice(&bytes[..len]);
            }
            let mut state = self.state.map(|word| [word; VECTOR_LEN]);
            for block in 0..self.num_blocks {
                let offset = block * KECCAK_RATE;
                // Each state word is built across all lanes and stored whole: the
                // permutation loads it as one vector, and a partly written word
                // cannot be forwarded into that load.
                for (word, lane_words) in state[..KECCAK_RATE / 8].iter_mut().enumerate() {
                    let at = offset + 8 * word;
                    *lane_words = core::array::from_fn(|lane| {
                        let bytes = &lanes[lane][at..][..8];
                        lane_words[lane]
                            ^ u64::from_le_bytes(bytes.try_into().expect("eight bytes"))
                    });
                }
                KeccakF.permute_mut(&mut state);
            }
            // The digest is the first four state words, little-endian.
            let passes =
                |lane: usize| draw(state[KECCAK_LAST_DIGEST_WORD][lane].to_le_bytes()) & mask == 0;
            if let Some(lane) = (0..count).find(|&lane| passes(lane)) {
                return Some(first + lane as u64);
            }
            first += count as u64;
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use p3_binary_field::{
        BinaryChallenger, BinaryField8, BinaryField16, BinaryField32, BinaryField64,
        BinaryField128, Poly64, TowerLevel,
    };
    use p3_challenger::{
        CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, GrindingChallenger,
        HashChallenger,
    };
    use p3_circuit::ops::ByteHash;
    use p3_field::PrimeCharacteristicRing;
    use p3_keccak::Keccak256Hash;
    use p3_merkle_tree::MerkleCap;
    use p3_symmetric::CryptographicHasher;
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    use super::super::{BinaryNativeChallenger, BinaryNativeHash, NativeAlphabet};
    use super::{GRIND_CHUNK, KeccakPrefix, VECTOR_LEN, candidate, draw, observed_bytes};

    const HASHES: [ByteHash; 2] = [ByteHash::Keccak256, ByteHash::Blake3];

    /// The transcript the native challenger must reproduce byte for byte.
    type Reference<F> = BinaryChallenger<F, HashChallenger<u8, BinaryNativeHash, 32>>;

    fn pair<F>(initial: &[u8], hash: ByteHash) -> (BinaryNativeChallenger<F>, Reference<F>) {
        (
            BinaryNativeChallenger::fresh(initial.to_vec(), hash),
            Reference::from_hasher(initial.to_vec(), BinaryNativeHash(hash)),
        )
    }

    fn element<F: TowerLevel>(rng: &mut StdRng) -> F {
        let mut bytes = [0; 16];
        rng.fill_bytes(&mut bytes);
        F::from_le_byte_iter(bytes.into_iter())
    }

    fn below(rng: &mut StdRng, bound: usize) -> usize {
        (rng.next_u64() % bound as u64) as usize
    }

    /// The witness is the first candidate the reference accepts: every
    /// earlier candidate fails `BinaryChallenger`'s own check.
    fn assert_first_valid<F: NativeAlphabet>(reference: &Reference<F>, bits: usize, witness: F) {
        let mut index = 0;
        while candidate::<F>(index) != witness {
            assert!(
                !reference.clone().check_witness(bits, candidate(index)),
                "candidate {index} passes before the returned witness"
            );
            index += 1;
            assert!(index < 1 << 20, "witness is not a grinding candidate");
        }
        assert!(reference.clone().check_witness(bits, witness));
    }

    /// Random observe, sample, bit-draw, grind and check sequences give the
    /// same draws and the same verdicts as `BinaryChallenger` over
    /// `HashChallenger`, and leave the same transcript behind.
    fn assert_same_transcript<F: NativeAlphabet>(seed: u64, max_grind_bits: usize) {
        for hash in HASHES {
            let mut rng = StdRng::seed_from_u64(seed);
            let mut initial = vec![0; below(&mut rng, 300)];
            rng.fill_bytes(&mut initial);
            let (mut native, mut reference) = pair::<F>(&initial, hash);
            for _ in 0..120 {
                match below(&mut rng, 7) {
                    0 => {
                        let value = element::<F>(&mut rng);
                        native.observe(value);
                        reference.observe(value);
                    }
                    1 => {
                        let roots: Vec<[u8; 32]> = (0..1 << below(&mut rng, 3))
                            .map(|_| {
                                let mut root = [0; 32];
                                rng.fill_bytes(&mut root);
                                root
                            })
                            .collect();
                        native.observe(MerkleCap::<F, [u8; 32]>::new(roots.clone()));
                        reference.observe(MerkleCap::<F, [u8; 32]>::new(roots));
                    }
                    2 => assert_eq!(
                        CanSample::<F>::sample(&mut native),
                        CanSample::<F>::sample(&mut reference)
                    ),
                    3 => {
                        let bits = below(&mut rng, 64);
                        assert_eq!(native.sample_bits(bits), reference.sample_bits(bits));
                    }
                    4 => {
                        let bits = below(&mut rng, 41);
                        assert_eq!(
                            native.sample_uniform_bits::<true>(bits).unwrap(),
                            reference.sample_uniform_bits::<true>(bits).unwrap()
                        );
                    }
                    5 => {
                        let bits = below(&mut rng, max_grind_bits + 1);
                        let witness = native.grind(bits);
                        if bits == 0 {
                            assert_eq!(witness, F::ZERO);
                        } else {
                            assert_first_valid(&reference, bits, witness);
                        }
                        assert!(reference.check_witness(bits, witness));
                    }
                    _ => {
                        let bits = below(&mut rng, 5);
                        let witness = element::<F>(&mut rng);
                        assert_eq!(
                            native.check_witness(bits, witness),
                            reference.check_witness(bits, witness)
                        );
                    }
                }
            }
            let native_tail: [F; 4] = native.sample_array();
            let reference_tail: [F; 4] = reference.sample_array();
            assert_eq!(native_tail, reference_tail);
        }
    }

    #[test]
    fn random_sequences_match_the_hash_challenger_transcript() {
        for seed in 0..6 {
            assert_same_transcript::<BinaryField16>(seed, 6);
            assert_same_transcript::<BinaryField32>(seed, 6);
            assert_same_transcript::<BinaryField64>(seed, 6);
            assert_same_transcript::<BinaryField128>(seed, 6);
            assert_same_transcript::<Poly64>(seed, 6);
        }
    }

    /// Checking a witness hashes the pending input followed by the witness.
    /// The pending input is cut at and around a Keccak rate block (136 bytes),
    /// the message with each witness width ends one byte short of, at and past
    /// a block, and the pending input spans two Blake3 chunks (1,024 bytes).
    #[test]
    fn grinding_matches_the_reference_check_at_block_edges() {
        fn check<F: NativeAlphabet>(hash: ByteHash, len: usize, bits: usize) {
            let initial: Vec<u8> = (0..len).map(|i| (i * 37 + len) as u8).collect();
            let (mut native, mut reference) = pair::<F>(&initial, hash);
            let witness = native.grind(bits);
            assert_first_valid(&reference, bits, witness);
            assert!(reference.check_witness(bits, witness));
            let native_tail: [F; 2] = native.sample_array();
            let reference_tail: [F; 2] = reference.sample_array();
            assert_eq!(native_tail, reference_tail);
        }
        for hash in HASHES {
            for len in [
                0, 1, 64, 119, 120, 121, 127, 131, 133, 135, 136, 137, 255, 304, 1008, 1024, 1072,
            ] {
                check::<BinaryField16>(hash, len, 8);
                check::<BinaryField32>(hash, len, 9);
                check::<BinaryField128>(hash, len, 9);
                check::<Poly64>(hash, len, 9);
            }
        }
    }

    /// Native proofs with grinding are reproducible: the witness depends on
    /// the transcript only, not on how many threads search or which of them
    /// scans which chunk.
    #[test]
    fn grinding_is_deterministic_across_thread_counts() {
        const BITS: usize = 14;
        const THREADS: [usize; 3] = [1, 2, 4];
        // A witness past four chunks for every worker of the widest pool.
        let past = 4 * GRIND_CHUNK * THREADS[2] as u64;
        for hash in HASHES {
            let (base, reference) = pair::<BinaryField128>(b"determinism", hash);
            let (native, reference, index) = (0u64..64)
                .find_map(|label| {
                    let mut native = base.clone();
                    native.observe(BinaryField128::from_le_byte_iter(
                        label.to_le_bytes().into_iter().chain([0; 8]),
                    ));
                    let witness = native.clone().grind(BITS);
                    let index = (0..)
                        .find(|&i| candidate::<BinaryField128>(i) == witness)
                        .unwrap();
                    let mut reference = reference.clone();
                    reference.observe(BinaryField128::from_le_byte_iter(
                        label.to_le_bytes().into_iter().chain([0; 8]),
                    ));
                    (index > past).then_some((native, reference, index))
                })
                .expect("some label puts the witness past four chunks per worker");
            for threads in THREADS {
                let witness = rayon::ThreadPoolBuilder::new()
                    .num_threads(threads)
                    .build()
                    .unwrap()
                    .install(|| native.clone().grind(BITS));
                assert_eq!(witness, candidate(index), "{threads} threads");
            }
            assert_first_valid(&reference, BITS, candidate(index));
        }
    }

    /// Keccak candidates are finished a lane group at a time. Every candidate of
    /// any range, including those of a short final group, is judged on its own
    /// digest, and the first passing one in order is returned.
    #[test]
    fn keccak_lane_groups_judge_every_candidate_of_a_range() {
        fn check<F: TowerLevel>(len: usize) {
            let prefix: Vec<u8> = (0..len).map(|i| (i * 29 + 3) as u8).collect();
            let longest = 3 * VECTOR_LEN as u64 + 1;
            let draws: Vec<u64> = (0..2 * longest)
                .map(|index| {
                    let (bytes, n) = observed_bytes(candidate::<F>(index));
                    let digest = Keccak256Hash.hash_iter_slices([prefix.as_slice(), &bytes[..n]]);
                    draw(digest[24..].try_into().unwrap())
                })
                .collect();
            let keccak = KeccakPrefix::new(&prefix, F::NUM_BYTES);
            for mask in [1, 3, 7] {
                for start in 0..longest {
                    for end in start..=start + longest {
                        let expected = (start..end).find(|&i| draws[i as usize] & mask == 0);
                        assert_eq!(keccak.first_pass::<F>(start..end, mask), expected);
                    }
                }
            }
        }
        for len in [0, 1, 119, 120, 127, 131, 133, 135, 136, 137, 255, 1072] {
            check::<BinaryField16>(len);
            check::<BinaryField32>(len);
            check::<BinaryField128>(len);
            check::<Poly64>(len);
        }
    }

    #[test]
    fn grinding_zero_bits_returns_zero_and_leaves_the_transcript() {
        for hash in HASHES {
            let (mut native, mut reference) = pair::<BinaryField8>(b"zero", hash);
            assert_eq!(native.grind(0), BinaryField8::ZERO);
            let native_tail: [BinaryField8; 40] = native.sample_array();
            let reference_tail: [BinaryField8; 40] = reference.sample_array();
            assert_eq!(native_tail, reference_tail);
        }
    }

    #[test]
    #[should_panic = "requested bit count leaves too small a margin"]
    fn grinding_inside_the_margin_panics() {
        let (mut native, _) = pair::<BinaryField32>(b"margin", ByteHash::Keccak256);
        let _ = native.grind(25);
    }

    #[test]
    #[should_panic = "requested bit count leaves too small a margin"]
    fn grinding_beyond_the_counter_margin_panics() {
        let (mut native, _) = pair::<BinaryField128>(b"margin", ByteHash::Blake3);
        let _ = native.grind(57);
    }
}
