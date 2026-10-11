//! The level layout and openings of byte-hash Merkle trees whose nodes
//! compress more than two digests.

use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};

use p3_field::Field;
use p3_util::log2_ceil_usize;

use super::{ByteHash, DIGEST_LIMBS};
use crate::builder::CircuitBuilderError;
use crate::ops::binary_host::BinaryCircuitHost;
use crate::types::ExprId;

/// The levels of a byte-hash `MerkleTreeMmcs` of compression arity `N`,
/// derived from the committed matrix heights alone, never from a proof.
///
/// This replays the native tree layout. Each layer of digests is padded with
/// default (all-zero) digests to a whole number of `N`-digest groups, or to a
/// single group when it holds between two and `N - 1` digests. A level
/// compresses groups of `N` digests, or pairs followed by `N - 2` default
/// digests when a shorter matrix must be injected before the layer an `N`-ary
/// level would reach. The matrices of one height are injected right after the
/// first level whose unpadded output width rounds up to the same power of two
/// as that height. A cap of `c` levels holds the top `min(c, levels)` levels.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MmcsAritySchedule {
    /// The compression arity of each level, from the leaves up: `N` or `2`.
    steps: Vec<usize>,
    /// The height whose matrices are injected right after each level.
    injected: Vec<Option<usize>>,
}

impl MmcsAritySchedule {
    /// The schedule of a commitment to matrices of the given heights.
    ///
    /// # Errors
    ///
    /// [`CircuitBuilderError::NonPrimitiveOpArity`] if `N` is not a power of
    /// two of at least two; if no height is positive or the tallest needs
    /// `usize::BITS` index bits; if a height is not `ceil(max_height / 2^k)`
    /// for some `k`, the only heights a tree can inject; if a height is never
    /// reached by a layer; or if the levels consume `usize::BITS` index bits.
    pub fn new<const N: usize>(heights: &[usize]) -> Result<Self, CircuitBuilderError> {
        let error = |expected: String, got: usize| CircuitBuilderError::NonPrimitiveOpArity {
            op: "MmcsAritySchedule",
            expected,
            got,
        };
        if N < 2 || !N.is_power_of_two() {
            return Err(error(
                "a power-of-two compression arity of at least two".into(),
                N,
            ));
        }
        let max_height = heights.iter().copied().max().unwrap_or(0);
        let log_max = log2_ceil_usize(max_height);
        if max_height == 0 || log_max >= usize::BITS as usize {
            return Err(error(
                format!("a tallest height of 1 to 2^{}", usize::BITS - 1),
                max_height,
            ));
        }
        // A height `h` sits `k = log_max - ceil(log2(h))` levels of halving up
        // and must be `ceil(max_height / 2^k)`.
        for &height in heights {
            let reduced = log_max - log2_ceil_usize(height.max(1));
            if height != ((max_height - 1) >> reduced) + 1 {
                return Err(error(
                    format!("a height of ceil({max_height} / 2^k)"),
                    height,
                ));
            }
        }

        // The heights injected above the leaf layer, tallest first.
        let leaf_bucket = max_height.next_power_of_two();
        let mut pending: Vec<usize> = heights
            .iter()
            .copied()
            .filter(|height| height.next_power_of_two() != leaf_bucket)
            .collect();
        pending.sort_unstable_by(|a, b| b.cmp(a));
        pending.dedup();
        let mut pending = pending.into_iter().peekable();

        let mut steps = Vec::new();
        let mut injected = Vec::new();
        let mut padded = padded_len(max_height, N);
        while padded > 1 {
            // A pairwise level bridges to a shorter matrix that a full
            // `N`-ary level would skip over.
            let step = if padded < N
                || pending
                    .clone()
                    .any(|height| height.next_power_of_two() > (padded / N).next_power_of_two())
            {
                2
            } else {
                N
            };
            let next = padded / step;
            steps.push(step);
            // The matrices of the height this layer reaches are injected here
            // and stop driving the steps.
            injected.push(
                pending.next_if(|height| height.next_power_of_two() == next.next_power_of_two()),
            );
            padded = padded_len(next, N);
        }
        if let Some(height) = pending.next() {
            return Err(error("a height the tree injects".into(), height));
        }
        let schedule = Self { steps, injected };
        if schedule.index_bits() >= usize::BITS as usize {
            return Err(error(
                format!("levels consuming fewer than {} index bits", usize::BITS),
                schedule.index_bits(),
            ));
        }
        Ok(schedule)
    }

    /// The compression arity of each level, from the leaves up.
    pub fn steps(&self) -> &[usize] {
        &self.steps
    }

    /// The levels an opening walks under a cap of `cap_height` levels.
    pub fn proof_levels(&self, cap_height: usize) -> usize {
        self.steps.len() - cap_height.min(self.steps.len())
    }

    /// The sibling digests of an opening under a cap of `cap_height` levels:
    /// `step - 1` for each level it walks.
    pub fn proof_siblings(&self, cap_height: usize) -> usize {
        self.steps[..self.proof_levels(cap_height)]
            .iter()
            .map(|step| step - 1)
            .sum()
    }

    /// The roots of a cap of `cap_height` levels: the product of their steps.
    pub fn cap_len(&self, cap_height: usize) -> usize {
        self.steps[self.proof_levels(cap_height)..].iter().product()
    }

    /// The index width the levels consume, `log2(step)` bits each. It is at
    /// least `ceil(log2(max_height))`, and an index below `max_height` has zero
    /// bits past that.
    fn index_bits(&self) -> usize {
        self.steps
            .iter()
            .map(|step| step.trailing_zeros() as usize)
            .sum()
    }
}

/// The length a layer of `raw_len` digests is padded to so that the next
/// level compresses whole groups of `n`.
const fn padded_len(raw_len: usize, n: usize) -> usize {
    if raw_len <= 1 {
        raw_len
    } else if raw_len >= n {
        raw_len.div_ceil(n) * n
    } else {
        n
    }
}

impl<F> crate::CircuitBuilder<F>
where
    F: Field + Eq + core::hash::Hash,
{
    /// [`Self::verify_byte_hash_mmcs_opening_words_with_host`] for a tree whose
    /// nodes compress `N` digests (`CompressionFunctionFromHasher<hash, N, 32>`),
    /// `N` being two or four.
    ///
    /// Arity two is exactly that opening. At arity four the levels follow
    /// [`MmcsAritySchedule::new`] for `heights`, as p3's `MerkleTreeMmcs` walks
    /// them:
    ///
    /// - `index_bits` are the `ceil(log2(max_height))` little-endian bits of the
    ///   index, whose higher bits are zero. A level of `step` children takes the
    ///   next `log2(step)` bits as the current digest's position in its group.
    /// - `siblings` holds, from the leaves up, each walked level's `step - 1`
    ///   sibling digests in increasing position, skipping the current digest's.
    /// - A level compresses its group padded with default (all-zero) digests to
    ///   four, and an injection compresses the digest, the hash of the injected
    ///   rows and two default digests.
    /// - The cap holds the roots of some number of top levels, padding roots
    ///   included, and the remaining index bits select the root the digest must
    ///   equal.
    ///
    /// # Errors
    ///
    /// [`CircuitBuilderError::NonPrimitiveOpArity`] for another arity, for a
    /// sibling count or cap size the schedule does not have, or for a matrix
    /// injected above the cap layer; otherwise as
    /// [`Self::verify_byte_hash_mmcs_opening_words_with_host`] and
    /// [`MmcsAritySchedule::new`].
    #[allow(clippy::too_many_arguments)]
    pub fn verify_byte_hash_mmcs_opening_words_with_host_arity<H, const N: usize>(
        &mut self,
        hash: ByteHash,
        rows: &[Vec<ExprId>],
        heights: &[usize],
        index_bits: &[ExprId],
        siblings: &[Vec<ExprId>],
        cap: &[Vec<ExprId>],
    ) -> Result<(), CircuitBuilderError>
    where
        H: BinaryCircuitHost<F>,
    {
        match N {
            2 => self.verify_byte_hash_mmcs_opening_words_with_host::<H>(
                hash, rows, heights, index_bits, siblings, cap,
            ),
            4 => {
                H::check_hash(hash)?;
                self.verify_byte_hash_mmcs_arity4_opening_with(
                    rows,
                    heights,
                    index_bits,
                    siblings,
                    cap,
                    |builder, row| H::hash_words(builder, hash, row),
                    |builder, inputs| H::compress_n(builder, hash, inputs),
                )
            }
            _ => Err(arity_error(N)),
        }
    }

    /// [`Self::verify_byte_hash_mmcs_opening_bytes_with_host`] for a tree whose
    /// nodes compress `N` digests, `N` being two or four. Levels, index bits,
    /// siblings and cap follow
    /// [`Self::verify_byte_hash_mmcs_opening_words_with_host_arity`].
    ///
    /// # Errors
    ///
    /// As [`Self::verify_byte_hash_mmcs_opening_words_with_host_arity`] and
    /// [`Self::verify_byte_hash_mmcs_opening_bytes_with_host`].
    #[allow(clippy::too_many_arguments)]
    pub fn verify_byte_hash_mmcs_opening_bytes_with_host_arity<H, const N: usize>(
        &mut self,
        hash: ByteHash,
        rows: &[Vec<ExprId>],
        heights: &[usize],
        index_bits: &[ExprId],
        siblings: &[Vec<ExprId>],
        cap: &[Vec<ExprId>],
    ) -> Result<(), CircuitBuilderError>
    where
        H: BinaryCircuitHost<F>,
    {
        match N {
            2 => self.verify_byte_hash_mmcs_opening_bytes_with_host::<H>(
                hash, rows, heights, index_bits, siblings, cap,
            ),
            4 => {
                H::check_hash(hash)?;
                self.verify_byte_hash_mmcs_arity4_opening_with(
                    rows,
                    heights,
                    index_bits,
                    siblings,
                    cap,
                    |builder, row| {
                        let digest = H::hash_bytes(builder, hash, row)?;
                        H::words_from_bytes(builder, &digest)
                    },
                    |builder, inputs| H::compress_n(builder, hash, inputs),
                )
            }
            _ => Err(arity_error(N)),
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn verify_byte_hash_mmcs_arity4_opening_with(
        &mut self,
        rows: &[Vec<ExprId>],
        heights: &[usize],
        index_bits: &[ExprId],
        siblings: &[Vec<ExprId>],
        cap: &[Vec<ExprId>],
        mut hash_rows: impl FnMut(&mut Self, &[ExprId]) -> Result<Vec<ExprId>, CircuitBuilderError>,
        mut compress: impl FnMut(&mut Self, &[&[ExprId]]) -> Result<Vec<ExprId>, CircuitBuilderError>,
    ) -> Result<(), CircuitBuilderError> {
        const ARITY: usize = 4;
        let shape_error = |expected: String, got: usize| CircuitBuilderError::NonPrimitiveOpArity {
            op: "MmcsOpening",
            expected,
            got,
        };
        let log_max = index_bits.len();
        if log_max >= usize::BITS as usize {
            return Err(shape_error(
                format!("fewer than {} index bits", usize::BITS),
                log_max,
            ));
        }
        if rows.is_empty() || rows.len() != heights.len() {
            return Err(shape_error(
                format!("one height per opened row ({})", rows.len()),
                heights.len(),
            ));
        }
        let schedule = MmcsAritySchedule::new::<ARITY>(heights)?;
        let max_height = heights.iter().copied().max().unwrap_or(0);
        if log2_ceil_usize(max_height) != log_max {
            return Err(shape_error(
                format!("a tallest matrix of height needing {log_max} index bits"),
                max_height,
            ));
        }
        let cap_height = (0..=schedule.steps.len())
            .find(|&levels| schedule.cap_len(levels) == cap.len())
            .ok_or_else(|| {
                shape_error("the roots of some number of top levels".into(), cap.len())
            })?;
        let walked = schedule.proof_levels(cap_height);
        let expected_siblings = schedule.proof_siblings(cap_height);
        if siblings.len() != expected_siblings {
            return Err(shape_error(
                format!("{expected_siblings} siblings"),
                siblings.len(),
            ));
        }
        if let Some(&height) = schedule.injected[walked..].iter().flatten().next() {
            return Err(shape_error(
                "matrices injected no higher than the cap layer".into(),
                height,
            ));
        }
        for digest in siblings.iter().chain(cap) {
            if digest.len() != DIGEST_LIMBS {
                return Err(shape_error(
                    format!("{DIGEST_LIMBS} limbs per digest"),
                    digest.len(),
                ));
            }
        }

        // The concatenated rows of every matrix of one height, in commitment order.
        let rows_at = |height: usize| -> Vec<ExprId> {
            rows.iter()
                .zip(heights)
                .filter(|&(_, &h)| h == height)
                .flat_map(|(row, _)| row.iter().copied())
                .collect()
        };

        for &bit in index_bits {
            self.assert_bool(bit);
        }
        if !max_height.is_power_of_two() {
            self.assert_bits_at_most(index_bits, max_height - 1);
        }
        // A group padded past the real digests reads index bits above the
        // index width, which are zero.
        let zero = self.define_const(F::ZERO);
        let mut bits = index_bits.to_vec();
        bits.resize(schedule.index_bits(), zero);
        let default = vec![zero; DIGEST_LIMBS];

        let mut node = hash_rows(self, &rows_at(max_height))?;
        let mut read_bits = 0;
        let mut remaining_siblings = siblings;
        for (&step, &injected) in schedule.steps.iter().zip(&schedule.injected).take(walked) {
            let width = step.trailing_zeros() as usize;
            let (group, rest) = remaining_siblings.split_at(step - 1);
            remaining_siblings = rest;
            let slots = self.mmcs_group_slots(&node, group, &bits[read_bits..read_bits + width])?;
            read_bits += width;
            let mut inputs: Vec<&[ExprId]> = slots.iter().map(Vec::as_slice).collect();
            inputs.resize(ARITY, &default);
            node = compress(self, &inputs)?;
            if let Some(height) = injected {
                let digest = hash_rows(self, &rows_at(height))?;
                node = compress(self, &[&node, &digest, &default, &default])?;
            }
            self.check_construction_limits()?;
        }

        // The remaining index bits pick the cap root, one multiplexer layer per
        // bit; a zero padding bit keeps the even candidates.
        let mut candidates: Vec<Vec<ExprId>> = cap.to_vec();
        for &bit in &bits[read_bits..] {
            candidates = candidates
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| {
                    let digest = pair[0]
                        .iter()
                        .zip(&pair[1])
                        .map(|(&even, &odd)| self.select(bit, odd, even))
                        .collect();
                    self.check_construction_limits()?;
                    Ok(digest)
                })
                .collect::<Result<_, CircuitBuilderError>>()?;
        }
        for (&computed, &expected) in node.iter().zip(&candidates[0]) {
            self.connect(computed, expected);
        }
        self.check_construction_limits()?;
        Ok(())
    }

    /// The inputs of one level's compression before default padding: the
    /// current digest at the position whose little-endian bits are `bits`,
    /// and the siblings in increasing position in the other slots.
    ///
    /// Under Boolean bits the slots hold exactly the current digest and the
    /// siblings, each once. Four slots use the one-hot flags `h_p` of the
    /// position `p = b0 + 2 b1`, six products per word.
    fn mmcs_group_slots(
        &mut self,
        node: &[ExprId],
        siblings: &[Vec<ExprId>],
        bits: &[ExprId],
    ) -> Result<Vec<Vec<ExprId>>, CircuitBuilderError> {
        match (bits, siblings) {
            (&[bit], [sibling]) => {
                let (left, right) = self.order_digest_pair(bit, node, sibling);
                Ok(vec![left, right])
            }
            (&[low, high], [first, second, third]) => {
                let h3 = self.mul(low, high);
                let h1 = self.sub(low, h3);
                let h2 = self.sub(high, h3);
                let one = self.define_const(F::ONE);
                let not_low = self.sub(one, low);
                let h0 = self.sub(not_low, h2);
                let mut slots = vec![Vec::new(); 4];
                for (((&current, &s0), &s1), &s2) in node.iter().zip(first).zip(second).zip(third) {
                    // Slot 0: the current word at position 0, else `s0`.
                    slots[0].push(self.select(h0, current, s0));
                    // Slot 1: `s0` at position 0, the current word at 1, else `s1`.
                    let current_minus_s1 = self.sub(current, s1);
                    let below = self.select(h0, s0, s1);
                    slots[1].push(self.mul_add(h1, current_minus_s1, below));
                    // Slot 2: the current word at position 2, `s2` at 3, else `s1`.
                    let s2_minus_s1 = self.sub(s2, s1);
                    let above = self.mul_add(h2, current_minus_s1, s1);
                    slots[2].push(self.mul_add(h3, s2_minus_s1, above));
                    // Slot 3: the current word at position 3, else `s2`.
                    slots[3].push(self.select(h3, current, s2));
                }
                Ok(slots)
            }
            _ => Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "MmcsOpening",
                expected: "a level of two or four children".into(),
                got: siblings.len() + 1,
            }),
        }
    }
}

fn arity_error(arity: usize) -> CircuitBuilderError {
    CircuitBuilderError::NonPrimitiveOpArity {
        op: "MmcsOpening",
        expected: "a compression arity of two or four".into(),
        got: arity,
    }
}
