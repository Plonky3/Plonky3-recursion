use p3_circuit::ops::Poseidon2Config;
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
    /// Merkle arity used by the MMCS (2 for binary, 4 for quaternary).
    /// This controls how many direction bits and siblings per level are
    /// expected by the recursive MMCS verifier. For now we support small
    /// powers of two, typically 2 or 4.
    pub merkle_arity: u8,
}

impl FriVerifierParams {
    /// Create params with MMCS verification enabled.
    pub const fn with_mmcs(
        log_blowup: usize,
        log_final_poly_len: usize,
        commit_pow_bits: usize,
        query_pow_bits: usize,
        permutation_config: Poseidon2Config,
    ) -> Self {
        // Default to binary Merkle unless overridden by the caller.
        Self {
            log_blowup,
            log_final_poly_len,
            commit_pow_bits,
            query_pow_bits,
            permutation_config: Some(permutation_config),
            merkle_arity: 2,
        }
    }

    /// Create params with MMCS verification enabled and an explicit Merkle arity.
    ///
    /// Use this when the underlying PCS/MMCS uses a higher arity such as 4.
    pub const fn with_mmcs_and_merkle_arity(
        log_blowup: usize,
        log_final_poly_len: usize,
        commit_pow_bits: usize,
        query_pow_bits: usize,
        permutation_config: Poseidon2Config,
        merkle_arity: u8,
    ) -> Self {
        Self {
            log_blowup,
            log_final_poly_len,
            commit_pow_bits,
            query_pow_bits,
            permutation_config: Some(permutation_config),
            merkle_arity,
        }
    }

    /// Create params without MMCS verification (arithmetic-only, for testing).
    pub const fn arithmetic_only(
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
            merkle_arity: 2,
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
            merkle_arity: 2,
        }
    }
}
