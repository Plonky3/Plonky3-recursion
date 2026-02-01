use p3_circuit::op::Poseidon2Config;
use p3_fri::FriParameters;

/// FRI verifier parameters (subset needed for verification).
///
/// These parameters are extracted from the full `FriParameters` and contain
/// only the information needed during verification (not proving).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FriVerifierParams {
    /// Log₂ of the blowup factor (rate = 1/blowup)
    pub log_blowup: usize,
    /// Log₂ of the final polynomial length (after all folding rounds)
    pub log_final_poly_len: usize,
    /// Number of commit-phase proof-of-work bits required
    pub commit_pow_bits: usize,
    /// Number of query proof-of-work bits required
    pub query_pow_bits: usize,
    /// Poseidon2 permutation configuration for MMCS verification.
    /// When `Some`, recursive MMCS verification is performed.
    /// When `None`, only arithmetic verification is performed (for testing).
    pub permutation_config: Option<Poseidon2Config>,
}

impl FriVerifierParams {
    /// Create params with MMCS verification enabled.
    pub fn with_mmcs(
        log_blowup: usize,
        log_final_poly_len: usize,
        commit_pow_bits: usize,
        query_pow_bits: usize,
        permutation_config: Poseidon2Config,
    ) -> Self {
        Self {
            log_blowup,
            log_final_poly_len,
            commit_pow_bits,
            query_pow_bits,
            permutation_config: Some(permutation_config),
        }
    }

    /// Create params without MMCS verification (arithmetic-only, for testing).
    pub fn arithmetic_only(
        log_blowup: usize,
        log_final_poly_len: usize,
        commit_pow_bits: usize,
        query_pow_bits: usize,
    ) -> Self {
        Self {
            log_blowup,
            log_final_poly_len,
            commit_pow_bits,
            query_pow_bits,
            permutation_config: None,
        }
    }
}

impl<M> From<&FriParameters<M>> for FriVerifierParams {
    /// Creates params without MMCS verification by default.
    /// Use `with_mmcs` or set `permutation_config` manually to enable MMCS verification.
    fn from(params: &FriParameters<M>) -> Self {
        Self {
            log_blowup: params.log_blowup,
            log_final_poly_len: params.log_final_poly_len,
            commit_pow_bits: params.commit_proof_of_work_bits,
            query_pow_bits: params.query_proof_of_work_bits,
            permutation_config: None,
        }
    }
}

/// Maximum number of bits used for query index decomposition in FRI verification circuits.
///
/// This is a fixed size to avoid const generic complexity. The circuit decomposes each
/// query index into this many bits, but only uses the first `log_max_height` bits that
/// are actually needed.
///
/// This value is set to 31 bits because:
/// - Query indices are sampled as field elements in the base field (BabyBear/KoalaBear)
/// - BabyBear: p = 2^31 - 2^27 + 1 (31-bit prime)
/// - KoalaBear: p = 2^31 - 2^24 + 1 (31-bit prime)
/// - Field elements fit in 31 bits, so 31 bits is sufficient
///
/// For Goldilocks (64-bit field), this would need to be increased, but that's not
/// currently supported in the recursion circuit.
pub const MAX_QUERY_INDEX_BITS: usize = 31;
