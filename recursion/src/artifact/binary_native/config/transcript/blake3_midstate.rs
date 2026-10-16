//! BLAKE3 proof-of-work search from a midstate, four candidates per compression.

#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
use core::arch::aarch64;
use core::array;
use core::ops::Range;

use p3_circuit::ops::blake3_compress::{
    BLAKE3_BLOCK_BYTES, BLAKE3_CHUNK_BYTES, BLAKE3_INPUT_WORDS, BLAKE3_IV, blake3_compress,
    blake3_flags,
};

use super::draw;

/// Candidates finished per compression, one per lane.
const LANES: usize = 4;

/// BLAKE3's permutation of the message words between rounds.
const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// The lanes the search runs on: NEON vectors where the build enables NEON, arrays elsewhere.
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
type Vector = core::arch::aarch64::uint32x4_t;
#[cfg(not(all(target_arch = "aarch64", target_feature = "neon")))]
type Vector = [u32; LANES];

/// BLAKE3 with the whole blocks of a prefix compressed, for candidates that end the message
/// inside the final block of its only chunk.
///
/// Every candidate's message is the same apart from the candidate, and its final block is
///
/// ```text
///     [ rest of prefix | candidate | 0x00 ... 0x00 ]
///                      ^ prefix.len() % 64
///                                  ^ block_len
/// ```
///
/// A message of one chunk is hashed by its chunk alone, so this block's compression under the
/// chaining value of the blocks before it, with `CHUNK_END | ROOT` (and `CHUNK_START` when it is
/// also the first block) and the message's length within it, outputs the digest.
pub(super) struct Blake3Midstate {
    cv: [u32; 8],
    block: [u32; 16],
    /// The words of `block` that the candidate's index bytes fall in.
    index_words: Range<usize>,
    /// The bit at which the index starts in the first of those words.
    index_shift: u32,
    /// Every index below this fits in the candidate's bytes.
    index_limit: u64,
    block_len: u32,
    flags: u32,
}

impl Blake3Midstate {
    /// The midstate of `prefix` for candidates of `witness_len` bytes, or `None` when the message
    /// spans more than one chunk or a candidate does not fit in the final block.
    pub(super) fn new(prefix: &[u8], witness_len: usize) -> Option<Self> {
        let witness_at = prefix.len() % BLAKE3_BLOCK_BYTES;
        let block_len = witness_at + witness_len;
        if prefix.len() + witness_len > BLAKE3_CHUNK_BYTES || block_len > BLAKE3_BLOCK_BYTES {
            return None;
        }
        let (whole, rest) = prefix.split_at(prefix.len() - witness_at);
        let mut cv = BLAKE3_IV;
        for (i, block) in whole.as_chunks::<BLAKE3_BLOCK_BYTES>().0.iter().enumerate() {
            let flags = if i == 0 { blake3_flags::CHUNK_START } else { 0 };
            let mut input = [0; BLAKE3_INPUT_WORDS];
            input[..16].copy_from_slice(&le_words(block));
            input[16..24].copy_from_slice(&cv);
            input[26] = BLAKE3_BLOCK_BYTES as u32;
            input[27] = flags;
            cv.copy_from_slice(&blake3_compress(&input)[..8]);
        }
        let mut block = [0; BLAKE3_BLOCK_BYTES];
        block[..rest.len()].copy_from_slice(rest);
        let mut flags = blake3_flags::CHUNK_END | blake3_flags::ROOT;
        if whole.is_empty() {
            flags |= blake3_flags::CHUNK_START;
        }
        // A candidate's bytes are the little-endian bytes of its index, zero past the eighth,
        // and the block holds zeros where they go.
        let index_len = witness_len.min(8);
        Some(Self {
            cv,
            block: le_words(&block),
            index_words: witness_at / 4..(witness_at + index_len).div_ceil(4),
            index_shift: 8 * (witness_at % 4) as u32,
            index_limit: 1u64.checked_shl(8 * witness_len as u32).unwrap_or(u64::MAX),
            block_len: block_len as u32,
            flags,
        })
    }

    /// The smallest index in `range` whose candidate passes, judging `LANES` consecutive
    /// candidates per compression in index order.
    ///
    /// # Panics
    /// Panics if an index of `range` has more bytes than a candidate.
    pub(super) fn first_pass(&self, range: Range<u64>, mask: u64) -> Option<u64> {
        assert!(
            range.end <= self.index_limit,
            "candidate indices exceed the candidate's bytes"
        );
        let mut message: [Vector; 16] = self.block.map(Lanes::splat);
        let mut first = range.start;
        while first < range.end {
            let count = (range.end - first).min(LANES as u64) as usize;
            // Spare lanes of a short final group repeat its first candidate.
            let indices = array::from_fn(|lane| {
                if lane < count {
                    first + lane as u64
                } else {
                    first
                }
            });
            let digest = self.compress_group(&mut message, indices);
            let (penultimate, last) = (digest[6].to_array(), digest[7].to_array());
            let passes = |lane: usize| draw(digest_tail(penultimate[lane], last[lane])) & mask == 0;
            if let Some(lane) = (0..count).find(|&lane| passes(lane)) {
                return Some(first + lane as u64);
            }
            first += count as u64;
        }
        None
    }

    /// The digest words of the candidates `indices`, one per lane: their index bytes are written
    /// into `message`, which holds the final block in every other word.
    fn compress_group(&self, message: &mut [Vector; 16], indices: [u64; LANES]) -> [Vector; 8] {
        let shifted = indices.map(|index| u128::from(index) << self.index_shift);
        for (i, word) in self.index_words.clone().enumerate() {
            message[word] = Lanes::from_array(array::from_fn(|lane| {
                self.block[word] | (shifted[lane] >> (32 * i)) as u32
            }));
        }
        compress(&self.cv, message, self.block_len, self.flags)
    }
}

/// The little-endian 32-bit words of a block.
fn le_words(block: &[u8; BLAKE3_BLOCK_BYTES]) -> [u32; 16] {
    array::from_fn(|i| u32::from_le_bytes(block.as_chunks::<4>().0[i]))
}

/// The last eight digest bytes, from the digest's last two words.
fn digest_tail(penultimate: u32, last: u32) -> [u8; 8] {
    let mut tail = [0; 8];
    tail[..4].copy_from_slice(&penultimate.to_le_bytes());
    tail[4..].copy_from_slice(&last.to_le_bytes());
    tail
}

/// Four 32-bit words, one per lane, with the operations of a BLAKE3 round.
trait Lanes: Copy {
    fn splat(word: u32) -> Self;
    fn from_array(words: [u32; LANES]) -> Self;
    fn to_array(self) -> [u32; LANES];
    fn wrapping_add(self, other: Self) -> Self;
    fn xor(self, other: Self) -> Self;
    fn rotate_right_16(self) -> Self;
    fn rotate_right_12(self) -> Self;
    fn rotate_right_8(self) -> Self;
    fn rotate_right_7(self) -> Self;
}

#[cfg(any(test, not(all(target_arch = "aarch64", target_feature = "neon"))))]
impl Lanes for [u32; LANES] {
    fn splat(word: u32) -> Self {
        [word; LANES]
    }

    fn from_array(words: [u32; LANES]) -> Self {
        words
    }

    fn to_array(self) -> [u32; LANES] {
        self
    }

    fn wrapping_add(self, other: Self) -> Self {
        array::from_fn(|lane| self[lane].wrapping_add(other[lane]))
    }

    fn xor(self, other: Self) -> Self {
        array::from_fn(|lane| self[lane] ^ other[lane])
    }

    fn rotate_right_16(self) -> Self {
        self.map(|word| word.rotate_right(16))
    }

    fn rotate_right_12(self) -> Self {
        self.map(|word| word.rotate_right(12))
    }

    fn rotate_right_8(self) -> Self {
        self.map(|word| word.rotate_right(8))
    }

    fn rotate_right_7(self) -> Self {
        self.map(|word| word.rotate_right(7))
    }
}

// Each intrinsic below needs NEON and nothing else: none reads or writes memory.
#[cfg(all(target_arch = "aarch64", target_feature = "neon"))]
impl Lanes for core::arch::aarch64::uint32x4_t {
    fn splat(word: u32) -> Self {
        // SAFETY: the build enables NEON, so the CPU running it has NEON.
        unsafe { aarch64::vdupq_n_u32(word) }
    }

    fn from_array(words: [u32; LANES]) -> Self {
        let pair = |low: u32, high: u32| u64::from(low) | (u64::from(high) << 32);
        // SAFETY: the build enables NEON, so the CPU running it has NEON.
        unsafe {
            aarch64::vcombine_u32(
                aarch64::vcreate_u32(pair(words[0], words[1])),
                aarch64::vcreate_u32(pair(words[2], words[3])),
            )
        }
    }

    fn to_array(self) -> [u32; LANES] {
        // SAFETY: the build enables NEON, so the CPU running it has NEON.
        unsafe {
            [
                aarch64::vgetq_lane_u32::<0>(self),
                aarch64::vgetq_lane_u32::<1>(self),
                aarch64::vgetq_lane_u32::<2>(self),
                aarch64::vgetq_lane_u32::<3>(self),
            ]
        }
    }

    fn wrapping_add(self, other: Self) -> Self {
        // SAFETY: the build enables NEON, so the CPU running it has NEON.
        unsafe { aarch64::vaddq_u32(self, other) }
    }

    fn xor(self, other: Self) -> Self {
        // SAFETY: the build enables NEON, so the CPU running it has NEON.
        unsafe { aarch64::veorq_u32(self, other) }
    }

    fn rotate_right_16(self) -> Self {
        // SAFETY: the build enables NEON, so the CPU running it has NEON.
        unsafe {
            let halves = aarch64::vreinterpretq_u16_u32(self);
            aarch64::vreinterpretq_u32_u16(aarch64::vrev32q_u16(halves))
        }
    }

    fn rotate_right_12(self) -> Self {
        // SAFETY: the build enables NEON, so the CPU running it has NEON.
        unsafe { aarch64::vsriq_n_u32::<12>(aarch64::vshlq_n_u32::<20>(self), self) }
    }

    fn rotate_right_8(self) -> Self {
        // SAFETY: the build enables NEON, so the CPU running it has NEON.
        unsafe { aarch64::vsriq_n_u32::<8>(aarch64::vshlq_n_u32::<24>(self), self) }
    }

    fn rotate_right_7(self) -> Self {
        // SAFETY: the build enables NEON, so the CPU running it has NEON.
        unsafe { aarch64::vsriq_n_u32::<7>(aarch64::vshlq_n_u32::<25>(self), self) }
    }
}

/// BLAKE3's quarter-round on state words `a`, `b`, `c`, `d` with message words `x`, `y`.
#[inline(always)]
fn g<V: Lanes>(state: &mut [V; 16], [a, b, c, d]: [usize; 4], x: V, y: V) {
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(x);
    state[d] = state[d].xor(state[a]).rotate_right_16();
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = state[b].xor(state[c]).rotate_right_12();
    state[a] = state[a].wrapping_add(state[b]).wrapping_add(y);
    state[d] = state[d].xor(state[a]).rotate_right_8();
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = state[b].xor(state[c]).rotate_right_7();
}

/// The first eight output words of the BLAKE3 compression of one block per lane under the
/// chaining value `cv`, with counter zero, `block_len` and `flags`.
fn compress<V: Lanes>(cv: &[u32; 8], block: &[V; 16], block_len: u32, flags: u32) -> [V; 8] {
    let mut state = [
        cv[0],
        cv[1],
        cv[2],
        cv[3],
        cv[4],
        cv[5],
        cv[6],
        cv[7],
        BLAKE3_IV[0],
        BLAKE3_IV[1],
        BLAKE3_IV[2],
        BLAKE3_IV[3],
        0,
        0,
        block_len,
        flags,
    ]
    .map(V::splat);
    let mut m = *block;
    for round in 0..7 {
        g(&mut state, [0, 4, 8, 12], m[0], m[1]);
        g(&mut state, [1, 5, 9, 13], m[2], m[3]);
        g(&mut state, [2, 6, 10, 14], m[4], m[5]);
        g(&mut state, [3, 7, 11, 15], m[6], m[7]);
        g(&mut state, [0, 5, 10, 15], m[8], m[9]);
        g(&mut state, [1, 6, 11, 12], m[10], m[11]);
        g(&mut state, [2, 7, 8, 13], m[12], m[13]);
        g(&mut state, [3, 4, 9, 14], m[14], m[15]);
        if round < 6 {
            m = array::from_fn(|i| m[MSG_PERMUTATION[i]]);
        }
    }
    array::from_fn(|i| state[i].xor(state[i + 8]))
}

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use core::array;

    use p3_binary_field::{
        BinaryField16, BinaryField32, BinaryField64, BinaryField128, Poly64, TowerLevel,
    };
    use p3_circuit::ops::blake3_compress::{BLAKE3_INPUT_WORDS, blake3_compress};
    use rand::rngs::StdRng;
    use rand::{Rng, SeedableRng};

    use super::super::{candidate, draw, observed_bytes};
    use super::{Blake3Midstate, LANES, Lanes, Vector, compress};

    /// The BLAKE3 digest of `prefix` followed by the bytes of candidate `index`.
    fn hasher_digest<F: TowerLevel>(prefix: &[u8], index: u64) -> [u8; 32] {
        let (bytes, len) = observed_bytes(candidate::<F>(index));
        let mut hasher = blake3::Hasher::new();
        hasher.update(prefix);
        hasher.update(&bytes[..len]);
        *hasher.finalize().as_bytes()
    }

    fn hasher_draw<F: TowerLevel>(prefix: &[u8], index: u64) -> u64 {
        draw(hasher_digest::<F>(prefix, index)[24..].try_into().unwrap())
    }

    fn assert_lanes_match_the_scalar_compression<V: Lanes>(rng: &mut StdRng) {
        let cv: [u32; 8] = array::from_fn(|_| rng.next_u32());
        let block: [[u32; LANES]; 16] = array::from_fn(|_| array::from_fn(|_| rng.next_u32()));
        let block_len = rng.next_u32() % 65;
        let flags = rng.next_u32() % 16;
        let out = compress(&cv, &block.map(V::from_array), block_len, flags).map(V::to_array);
        for lane in 0..LANES {
            let mut input = [0; BLAKE3_INPUT_WORDS];
            for (word, lanes) in input.iter_mut().zip(&block) {
                *word = lanes[lane];
            }
            input[16..24].copy_from_slice(&cv);
            input[26] = block_len;
            input[27] = flags;
            let expected = blake3_compress(&input);
            for (word, lanes) in out.iter().enumerate() {
                assert_eq!(lanes[lane], expected[word], "lane {lane}, word {word}");
            }
        }
    }

    /// Each lane is one BLAKE3 compression of its own block, on the portable lanes and on the
    /// lanes the search runs on.
    #[test]
    fn lane_compressions_match_the_scalar_compression() {
        let mut rng = StdRng::seed_from_u64(3);
        for _ in 0..64 {
            assert_lanes_match_the_scalar_compression::<[u32; LANES]>(&mut rng);
            assert_lanes_match_the_scalar_compression::<Vector>(&mut rng);
        }
    }

    /// Wherever the midstate applies, it gives each candidate the digest the `Hasher` path
    /// computes, and the same first passing index; it applies exactly when the candidate ends a
    /// one-chunk message inside its final block. Prefixes end at every offset in the first,
    /// second and last block of a chunk, under every witness width.
    #[test]
    fn midstate_matches_the_hasher_at_every_block_offset_and_witness_width() {
        fn check<F: TowerLevel>(len: usize) {
            let prefix: Vec<u8> = (0..len).map(|i| (i * 53 + len) as u8).collect();
            let width = F::NUM_BYTES;
            let midstate = Blake3Midstate::new(&prefix, width);
            let fits = len % 64 + width <= 64 && len + width <= 1024;
            assert_eq!(midstate.is_some(), fits, "prefix {len}, witness {width}");
            let Some(midstate) = midstate else {
                return;
            };
            // Indices around every byte boundary of the index words, below the candidate count.
            let limit = if F::bits() >= 64 {
                u64::MAX
            } else {
                1 << F::bits()
            };
            let indices: Vec<u64> = (0..64)
                .flat_map(|bit| [(1u64 << bit) - 1, 1u64 << bit])
                .chain([0x0123_4567_89AB_CDEF, u64::MAX])
                .filter(|&index| index < limit)
                .collect();
            for group in indices.chunks(LANES) {
                let lanes = array::from_fn(|lane| group[lane.min(group.len() - 1)]);
                let mut message = midstate.block.map(Lanes::splat);
                let words = midstate
                    .compress_group(&mut message, lanes)
                    .map(Lanes::to_array);
                for (lane, &index) in lanes.iter().enumerate() {
                    let digest: Vec<u8> = words
                        .iter()
                        .flat_map(|word| word[lane].to_le_bytes())
                        .collect();
                    assert_eq!(
                        digest,
                        hasher_digest::<F>(&prefix, index),
                        "prefix {len}, witness {width}, index {index}"
                    );
                }
            }
            for mask in [1, 3] {
                let expected = (5..37).find(|&index| hasher_draw::<F>(&prefix, index) & mask == 0);
                assert_eq!(midstate.first_pass(5..37, mask), expected);
            }
        }
        for len in (0..128).chain(960..1024) {
            check::<BinaryField16>(len);
            check::<BinaryField32>(len);
            check::<BinaryField64>(len);
            check::<Poly64>(len);
            check::<BinaryField128>(len);
        }
    }

    /// Lanes are judged in index order: of two passing candidates in one compression, the
    /// smaller index is returned.
    #[test]
    fn two_passing_candidates_in_one_lane_group_return_the_smaller() {
        let prefix: Vec<u8> = (0..304).map(|i| (i * 29 + 3) as u8).collect();
        let midstate = Blake3Midstate::new(&prefix, 16).unwrap();
        let mask = 3;
        let mut groups = 0;
        for first in (0..1024).step_by(LANES) {
            let passing: Vec<u64> = (first..first + LANES as u64)
                .filter(|&index| hasher_draw::<BinaryField128>(&prefix, index) & mask == 0)
                .collect();
            if passing.len() >= 2 && passing[0] != first {
                groups += 1;
                assert_eq!(
                    midstate.first_pass(first..first + LANES as u64, mask),
                    Some(passing[0])
                );
            }
        }
        assert!(
            groups > 0,
            "no lane group with two passing candidates past its first lane"
        );
    }

    /// Every candidate of any range, including those of a short final group, is judged on its
    /// own digest, and the first passing one in order is returned.
    #[test]
    fn blake3_lane_groups_judge_every_candidate_of_a_range() {
        fn check<F: TowerLevel>(len: usize) {
            let prefix: Vec<u8> = (0..len).map(|i| (i * 29 + 3) as u8).collect();
            let midstate = Blake3Midstate::new(&prefix, F::NUM_BYTES).unwrap();
            let longest = 3 * LANES as u64 + 1;
            let draws: Vec<u64> = (0..2 * longest)
                .map(|index| hasher_draw::<F>(&prefix, index))
                .collect();
            for mask in [1, 3, 7] {
                for start in 0..longest {
                    for end in start..=start + longest {
                        let expected = (start..end).find(|&i| draws[i as usize] & mask == 0);
                        assert_eq!(midstate.first_pass(start..end, mask), expected);
                    }
                }
            }
        }
        for len in [0, 1, 48, 64, 304, 1008] {
            check::<BinaryField16>(len);
            check::<BinaryField128>(len);
            check::<Poly64>(len);
        }
    }
}
