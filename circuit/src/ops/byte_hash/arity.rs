//! The level layout of byte-hash Merkle trees whose nodes compress more than
//! two digests.

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use p3_util::log2_ceil_usize;

use crate::builder::CircuitBuilderError;

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
            pending.next_if(|height| height.next_power_of_two() == next.next_power_of_two());
            padded = padded_len(next, N);
        }
        if let Some(height) = pending.next() {
            return Err(error("a height the tree injects".into(), height));
        }
        let schedule = Self { steps };
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
