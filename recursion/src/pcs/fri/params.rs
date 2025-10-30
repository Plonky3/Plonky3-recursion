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
    /// Number of proof-of-work bits required
    pub pow_bits: usize,
}

impl<M> From<&FriParameters<M>> for FriVerifierParams {
    fn from(params: &FriParameters<M>) -> Self {
        Self {
            log_blowup: params.log_blowup,
            log_final_poly_len: params.log_final_poly_len,
            pow_bits: params.proof_of_work_bits,
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
