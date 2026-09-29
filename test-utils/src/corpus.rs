//! Deterministic, bounded test-data support for assurance tests.

use alloc::string::String;

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

/// Parse the small proof corpus used by bounded assurance tests.
pub fn parse_proof_corpus(
    start_seed: Option<&str>,
    proof_cases: Option<&str>,
) -> Result<CorpusSpec, String> {
    const MAX_PROOF_CASES: u32 = 8;

    let start_seed = match start_seed {
        Some(raw) => raw
            .parse::<u64>()
            .map_err(|_| alloc::format!("P3_ASSURANCE_START_SEED must be a u64, got {raw:?}"))?,
        None => 0,
    };
    let cases = match proof_cases {
        Some(raw) => raw.parse::<u32>().map_err(|_| {
            alloc::format!(
                "P3_ASSURANCE_PROOF_CASES must be a u32 in 1..={MAX_PROOF_CASES}, got {raw:?}"
            )
        })?,
        None => 1,
    };
    if !(1..=MAX_PROOF_CASES).contains(&cases) {
        return Err(alloc::format!(
            "P3_ASSURANCE_PROOF_CASES must be in 1..={MAX_PROOF_CASES}, got {cases}"
        ));
    }
    Ok(CorpusSpec { start_seed, cases })
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

    use super::{CaseRng, CorpusSpec, derive_family_seed, for_each_case, parse_proof_corpus};

    #[test]
    fn proof_corpus_defaults_each_unspecified_field_independently() {
        assert_eq!(
            parse_proof_corpus(None, None),
            Ok(CorpusSpec {
                start_seed: 0,
                cases: 1
            })
        );
        assert_eq!(
            parse_proof_corpus(Some("42"), None),
            Ok(CorpusSpec {
                start_seed: 42,
                cases: 1
            })
        );
        assert_eq!(
            parse_proof_corpus(None, Some("4")),
            Ok(CorpusSpec {
                start_seed: 0,
                cases: 4
            })
        );
    }

    #[test]
    fn proof_corpus_accepts_seed_and_case_boundaries() {
        assert_eq!(
            parse_proof_corpus(Some("18446744073709551615"), Some("8")),
            Ok(CorpusSpec {
                start_seed: u64::MAX,
                cases: 8
            })
        );
        assert_eq!(
            parse_proof_corpus(Some("0"), Some("1")),
            Ok(CorpusSpec {
                start_seed: 0,
                cases: 1
            })
        );
    }

    #[test]
    fn proof_corpus_rejects_malformed_and_overflowing_seeds_first() {
        for raw in ["", "nope", "18446744073709551616"] {
            assert_eq!(
                parse_proof_corpus(Some(raw), Some("0")),
                Err(alloc::format!(
                    "P3_ASSURANCE_START_SEED must be a u64, got {raw:?}"
                ))
            );
        }
    }

    #[test]
    fn proof_corpus_rejects_malformed_and_out_of_range_case_counts() {
        for raw in ["", "nope", "4294967296"] {
            assert_eq!(
                parse_proof_corpus(None, Some(raw)),
                Err(alloc::format!(
                    "P3_ASSURANCE_PROOF_CASES must be a u32 in 1..=8, got {raw:?}"
                ))
            );
        }
        for (raw, count) in [("0", 0), ("9", 9)] {
            assert_eq!(
                parse_proof_corpus(None, Some(raw)),
                Err(alloc::format!(
                    "P3_ASSURANCE_PROOF_CASES must be in 1..=8, got {count}"
                ))
            );
        }
    }

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
