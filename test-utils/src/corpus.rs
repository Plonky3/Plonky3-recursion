//! Deterministic, bounded test-data support for assurance tests.

/// Default number of cheap assurance cases executed by ordinary test runs.
pub const DEFAULT_CASES: u32 = 8;

/// Maximum number of cheap assurance cases accepted by test-local environment parsers.
pub const MAX_CASES: u32 = 1024;

/// The explicit seed range for a deterministic assurance corpus.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CorpusSpec {
    pub start_seed: u64,
    pub cases: u32,
}

/// Visit `cases` consecutive wrapping seeds, independent of execution order.
pub fn for_each_case(spec: CorpusSpec, mut visit: impl FnMut(u64)) {
    for case_index in 0..spec.cases {
        visit(spec.start_seed.wrapping_add(u64::from(case_index)));
    }
}

/// Derive a deterministic family substream from a case seed and fixed family tag.
pub const fn derive_family_seed(case_seed: u64, family_tag: u64) -> u64 {
    splitmix64(case_seed ^ family_tag)
}

/// A small deterministic SplitMix64 generator for test data only.
///
/// This generator is reproducible across platforms. It is not a security or prover RNG.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CaseRng {
    state: u64,
}

impl CaseRng {
    pub const fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub const fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9e37_79b9_7f4a_7c15);
        splitmix64_without_increment(self.state)
    }
}

const fn splitmix64(value: u64) -> u64 {
    splitmix64_without_increment(value.wrapping_add(0x9e37_79b9_7f4a_7c15))
}

const fn splitmix64_without_increment(mut value: u64) -> u64 {
    value = (value ^ (value >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    value = (value ^ (value >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    value ^ (value >> 31)
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use super::{CaseRng, CorpusSpec, derive_family_seed, for_each_case};

    #[test]
    fn explicit_seed_derivation_is_reproducible_and_order_independent() {
        let spec = CorpusSpec {
            start_seed: 41,
            cases: 4,
        };
        let mut first = vec![];
        let mut second = vec![];
        for_each_case(spec, |case| first.push(case));
        for_each_case(spec, |case| second.push(case));

        assert_eq!(first, vec![41, 42, 43, 44]);
        assert_eq!(first, second);
        assert_eq!(
            derive_family_seed(41, 0x434f_5250_5553),
            0x2bb7_0a06_bdce_aa05
        );
        assert_ne!(
            derive_family_seed(41, 0x434f_5250_5553),
            derive_family_seed(41, 0x434f_5250_5554)
        );
    }

    #[test]
    fn case_rng_has_a_fixed_nonzero_regression_stream() {
        let mut rng = CaseRng::new(7);
        assert_eq!(
            [rng.next_u64(), rng.next_u64(), rng.next_u64()],
            [0x63cbe1e459320dd7, 0x044c3cd7f43c661c, 0xe6984080bab12a02,]
        );
    }
}
