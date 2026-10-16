//! Compression arity and geometry of the byte-digest Merkle trees that binary
//! WHIR commitments open.

/// How many child digests one node of a byte-digest Merkle tree compresses:
/// the `N` of `MerkleTreeMmcs<_, u8, _, CompressionFunctionFromHasher<_, N, 32>, N, 32>`.
///
/// A tree over `2^h` rows has [`Self::levels`] levels. A cap height counts the
/// top levels the cap replaces, so a cap of `c` levels holds `N^c` roots and an
/// opening walks the `levels - c` levels below it, `N - 1` siblings each.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub enum MerkleArity {
    /// Pairwise nodes: one level per index bit.
    #[default]
    Two,
    /// Four-digest nodes: one level per two index bits. When `h` is odd, the
    /// top level pads its two real children with two default digests.
    Four,
}

impl MerkleArity {
    /// The digests one node compresses.
    pub const fn digests(self) -> usize {
        match self {
            Self::Two => 2,
            Self::Four => 4,
        }
    }

    /// The index bits one level consumes.
    const fn level_bits(self) -> usize {
        match self {
            Self::Two => 1,
            Self::Four => 2,
        }
    }

    /// The levels of a tree over `2^log_height` rows.
    pub const fn levels(self, log_height: usize) -> usize {
        log_height.div_ceil(self.level_bits())
    }

    /// The roots of a cap of `cap_height` levels, or `None` when they
    /// overflow `usize`.
    pub const fn cap_roots(self, cap_height: usize) -> Option<usize> {
        match cap_height.checked_mul(self.level_bits()) {
            Some(bits) if bits < usize::BITS as usize => Some(1 << bits),
            _ => None,
        }
    }

    /// The sibling digests of one opening of a tree over `2^log_height` rows
    /// under a cap of `cap_height` levels, or `None` when the cap is taller
    /// than the tree.
    pub const fn path_siblings(self, log_height: usize, cap_height: usize) -> Option<usize> {
        match self.levels(log_height).checked_sub(cap_height) {
            Some(walked) => Some(walked * (self.digests() - 1)),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use p3_circuit::ops::MmcsAritySchedule;

    use super::MerkleArity;

    /// The closed forms are the single-matrix case of the schedule the
    /// in-circuit opening walks, at every height and cap the tree has.
    #[test]
    fn geometry_matches_the_circuit_schedule_of_one_matrix() {
        for log_height in 0..=20 {
            let height = [1usize << log_height];
            for (arity, schedule) in [
                (
                    MerkleArity::Two,
                    MmcsAritySchedule::new::<2>(&height).unwrap(),
                ),
                (
                    MerkleArity::Four,
                    MmcsAritySchedule::new::<4>(&height).unwrap(),
                ),
            ] {
                let levels = arity.levels(log_height);
                assert_eq!(schedule.steps().len(), levels);
                for cap in 0..=levels {
                    assert_eq!(arity.cap_roots(cap), Some(schedule.cap_len(cap)));
                    assert_eq!(
                        arity.path_siblings(log_height, cap),
                        Some(schedule.proof_siblings(cap))
                    );
                }
                assert_eq!(arity.path_siblings(log_height, levels + 1), None);
            }
        }
    }

    #[test]
    fn cap_roots_refuse_overflow() {
        let bits = usize::BITS as usize;
        assert_eq!(MerkleArity::Two.cap_roots(bits - 1), Some(1 << (bits - 1)));
        assert_eq!(MerkleArity::Two.cap_roots(bits), None);
        assert_eq!(
            MerkleArity::Four.cap_roots(bits / 2 - 1),
            Some(1 << (bits - 2))
        );
        assert_eq!(MerkleArity::Four.cap_roots(bits / 2), None);
        assert_eq!(MerkleArity::Four.cap_roots(usize::MAX), None);
    }
}
