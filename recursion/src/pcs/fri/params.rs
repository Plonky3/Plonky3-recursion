use p3_circuit::op::Poseidon2Config;
use p3_fri::FriParameters;

/// Merkle tree arity for MMCS verification.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum MmcsArity {
    /// Binary (2-ary) Merkle trees.
    #[default]
    Binary2,
    /// Quaternary (4-ary) Merkle trees with 4-to-1 Poseidon2 compression.
    Quaternary4,
}

impl MmcsArity {
    pub const fn is_4ary(self) -> bool {
        matches!(self, MmcsArity::Quaternary4)
    }
}

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
    /// Merkle tree arity for MMCS (2-ary or 4-ary).
    pub mmcs_arity: MmcsArity,
}

impl FriVerifierParams {
    /// Create params with MMCS verification enabled (binary Merkle).
    pub const fn with_mmcs(
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
            mmcs_arity: MmcsArity::Binary2,
        }
    }

    /// Create params with 4-ary MMCS verification.
    pub const fn with_mmcs_4ary(
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
            mmcs_arity: MmcsArity::Quaternary4,
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
            mmcs_arity: MmcsArity::Binary2,
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
            mmcs_arity: MmcsArity::Binary2,
        }
    }
}
