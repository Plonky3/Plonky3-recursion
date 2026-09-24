use p3_circuit::ops::PermConfig;
use p3_field::{PrimeField64, TwoAdicField};
use p3_fri::FriParameters;
use thiserror::Error;

/// Errors found while copying native FRI scalar configuration into the
/// recursive verifier's declaration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FriInputError {
    #[error("native FRI must require at least one query")]
    ZeroQueries,
    #[error("native FRI max folding arity must be positive")]
    ZeroMaxLogArity,
    #[error("native FRI log parameter {name} is not representable")]
    LogNotRepresentable { name: &'static str },
    #[error("native FRI height logs overflow")]
    HeightOverflow,
    #[error("native FRI height cannot be represented by the machine word")]
    HeightExceedsWord,
    #[error("native FRI height exceeds field two-adicity")]
    HeightExceedsTwoAdicity,
    #[error("native FRI max arity exceeds field two-adicity")]
    MaxArityExceedsTwoAdicity,
    #[error("native FRI {name} proof-of-work bits are not supported by the field/word limits")]
    PowBitsOutOfRange { name: &'static str },
    #[error(
        "native FRI batch-phase proof of work ({bits} bits) is not supported by the recursive verifier"
    )]
    UnsupportedBatchPow { bits: usize },
    #[error("native FRI scalar {name} does not match recursive parameters")]
    ScalarMismatch { name: &'static str },
    #[error("native FRI has {native} queries but recursive verifier requires {minimum}")]
    QueryFloor { native: usize, minimum: usize },
}

/// Errors constructing production recursive FRI parameters.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FriVerifierParamsError {
    #[error("FRI verifier requires at least one query")]
    ZeroQueries,
    #[error("FRI verifier max folding arity must be positive")]
    ZeroMaxLogArity,
    #[error("FRI verifier log parameter {name} is not representable")]
    LogNotRepresentable { name: &'static str },
    #[error("FRI verifier fold/domain exponent sum overflows usize")]
    HeightOverflow,
}

/// The checked scalar FRI declaration retained by built-in recursion configs.
///
/// This is deliberately only scalar metadata.  It does not clone or expose a
/// PCS, MMCS, RNG, challenger, or proof.  A config implementation still
/// promises that this declaration describes its opaque PCS; the constructor
/// validates that the declaration itself is safe to use.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeFriParams {
    log_blowup: usize,
    log_final_poly_len: usize,
    max_log_arity: usize,
    num_queries: usize,
    commit_pow_bits: usize,
    query_pow_bits: usize,
}

impl NativeFriParams {
    /// Copy and validate scalar metadata from the exact native parameters used
    /// to construct a PCS.
    pub fn try_from_native<F, M>(params: &FriParameters<M>) -> Result<Self, FriInputError>
    where
        F: PrimeField64 + TwoAdicField,
    {
        if params.num_queries == 0 {
            return Err(FriInputError::ZeroQueries);
        }
        if params.max_log_arity == 0 {
            return Err(FriInputError::ZeroMaxLogArity);
        }
        // The recursive FRI verifier replays no batch-phase grind, so it only accepts the zero
        // difficulty, at which the native transcript absorbs nothing for that phase.
        if params.batch_proof_of_work_bits != 0 {
            return Err(FriInputError::UnsupportedBatchPow {
                bits: params.batch_proof_of_work_bits,
            });
        }
        for (name, value) in [
            ("log_blowup", params.log_blowup),
            ("log_final_poly_len", params.log_final_poly_len),
            ("max_log_arity", params.max_log_arity),
        ] {
            if value >= usize::BITS as usize || u32::try_from(value).is_err() {
                return Err(FriInputError::LogNotRepresentable { name });
            }
        }
        for (name, bits) in [
            ("commit", params.commit_proof_of_work_bits),
            ("query", params.query_proof_of_work_bits),
        ] {
            if bits >= usize::BITS as usize
                || (bits != 0
                    && (1u64.checked_shl(bits as u32).is_none()
                        || 1u64.checked_shl(bits as u32).unwrap() >= F::ORDER_U64))
            {
                return Err(FriInputError::PowBitsOutOfRange { name });
            }
        }
        let snapshot = Self {
            log_blowup: params.log_blowup,
            log_final_poly_len: params.log_final_poly_len,
            max_log_arity: params.max_log_arity,
            num_queries: params.num_queries,
            commit_pow_bits: params.commit_proof_of_work_bits,
            query_pow_bits: params.query_proof_of_work_bits,
        };
        snapshot.validate_field::<F>()?;
        Ok(snapshot)
    }

    pub const fn log_blowup(&self) -> usize {
        self.log_blowup
    }

    pub const fn log_final_poly_len(&self) -> usize {
        self.log_final_poly_len
    }

    pub const fn max_log_arity(&self) -> usize {
        self.max_log_arity
    }

    pub const fn num_queries(&self) -> usize {
        self.num_queries
    }

    pub const fn commit_pow_bits(&self) -> usize {
        self.commit_pow_bits
    }

    pub const fn query_pow_bits(&self) -> usize {
        self.query_pow_bits
    }

    /// Revalidate the scalar snapshot against the actual base field used by a
    /// verifier.  This is required when metadata crosses an erased config
    /// boundary and prevents reusing a snapshot under an incompatible field.
    pub fn validate_field<F>(&self) -> Result<(), FriInputError>
    where
        F: PrimeField64 + TwoAdicField,
    {
        for (name, value) in [
            ("log_blowup", self.log_blowup),
            ("log_final_poly_len", self.log_final_poly_len),
            ("max_log_arity", self.max_log_arity),
        ] {
            if value >= usize::BITS as usize || u32::try_from(value).is_err() {
                return Err(FriInputError::LogNotRepresentable { name });
            }
        }
        let height = self
            .log_blowup
            .checked_add(self.log_final_poly_len)
            .ok_or(FriInputError::HeightOverflow)?;
        if height >= usize::BITS as usize {
            return Err(FriInputError::HeightExceedsWord);
        }
        if height > F::TWO_ADICITY {
            return Err(FriInputError::HeightExceedsTwoAdicity);
        }
        if self.max_log_arity > F::TWO_ADICITY {
            return Err(FriInputError::MaxArityExceedsTwoAdicity);
        }
        for (name, bits) in [
            ("commit", self.commit_pow_bits),
            ("query", self.query_pow_bits),
        ] {
            if bits >= usize::BITS as usize
                || (bits != 0
                    && (1u64.checked_shl(bits as u32).is_none()
                        || 1u64.checked_shl(bits as u32).unwrap() >= F::ORDER_U64))
            {
                return Err(FriInputError::PowBitsOutOfRange { name });
            }
        }
        Ok(())
    }

    /// Compare the native declaration with recursive parameters.  Native Q
    /// is exact; recursive Q is a documented minimum floor.
    pub fn validate_recursive(&self, recursive: &FriVerifierParams) -> Result<(), FriInputError> {
        for (name, native, recursive) in [
            ("log_blowup", self.log_blowup, recursive.log_blowup),
            (
                "log_final_poly_len",
                self.log_final_poly_len,
                recursive.log_final_poly_len,
            ),
            ("max_log_arity", self.max_log_arity, recursive.max_log_arity),
            (
                "commit_pow_bits",
                self.commit_pow_bits,
                recursive.commit_pow_bits,
            ),
            (
                "query_pow_bits",
                self.query_pow_bits,
                recursive.query_pow_bits,
            ),
        ] {
            if native != recursive {
                return Err(FriInputError::ScalarMismatch { name });
            }
        }
        if self.num_queries < recursive.num_queries {
            return Err(FriInputError::QueryFloor {
                native: self.num_queries,
                minimum: recursive.num_queries,
            });
        }
        Ok(())
    }
}

/// FRI verifier parameters (subset needed for verification).
///
/// These parameters are extracted from the full `FriParameters` and contain
/// only the information needed during verification (not proving).
///
/// Fields are private so production code cannot forge an unchecked parameter
/// set or omit the MMCS permutation configuration.
///
/// ```compile_fail
/// use p3_recursion::pcs::fri::FriVerifierParams;
/// let params: FriVerifierParams = unimplemented!();
/// let FriVerifierParams { num_queries, .. } = params;
/// ```
///
/// The former arithmetic-only constructor is deliberately unavailable on the
/// production type.
///
/// ```compile_fail
/// use p3_recursion::pcs::fri::FriVerifierParams;
/// let _ = FriVerifierParams::unsafe_arithmetic_only_for_tests(1, 0, 0, 0);
/// ```
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FriVerifierParams {
    /// Log₂ of the blowup factor (rate = 1/blowup)
    log_blowup: usize,
    /// Log₂ of the final polynomial length (after all folding rounds)
    log_final_poly_len: usize,
    /// Log₂ of the largest folding arity a commit-phase round may use.
    ///
    /// Since Plonky3 0.8 the fold schedule is derived from this cap and the input heights, and
    /// the cap is bound into the FRI transcript's domain separator.
    max_log_arity: usize,
    /// Number of commit-phase proof-of-work bits required
    commit_pow_bits: usize,
    /// Number of query proof-of-work bits required
    query_pow_bits: usize,
    /// Minimum number of FRI query proofs required for soundness.
    ///
    /// The recursive verifier enforces `fri_proof_num_queries(proof) >= num_queries`
    /// at circuit-construction time. A circuit built from a proof with fewer
    /// queries than this threshold is rejected with `InvalidProofShape`.
    ///
    num_queries: usize,
    /// Mandatory permutation configuration for MMCS verification.
    permutation_config: PermConfig,
}

impl FriVerifierParams {
    /// Create params with MMCS verification enabled.
    ///
    /// `num_queries` is the minimum number of FRI query proofs required for soundness.
    /// The circuit verifier enforces this bound at build time and rejects proofs
    /// that carry fewer queries than required.
    pub fn try_with_mmcs(
        log_blowup: usize,
        log_final_poly_len: usize,
        max_log_arity: usize,
        commit_pow_bits: usize,
        query_pow_bits: usize,
        num_queries: usize,
        permutation_config: impl Into<PermConfig>,
    ) -> Result<Self, FriVerifierParamsError> {
        if num_queries == 0 {
            return Err(FriVerifierParamsError::ZeroQueries);
        }
        for (name, value) in [
            ("log_blowup", log_blowup),
            ("log_final_poly_len", log_final_poly_len),
            ("max_log_arity", max_log_arity),
            ("commit_pow_bits", commit_pow_bits),
            ("query_pow_bits", query_pow_bits),
        ] {
            if value >= usize::BITS as usize || u32::try_from(value).is_err() {
                return Err(FriVerifierParamsError::LogNotRepresentable { name });
            }
        }
        let height = log_blowup
            .checked_add(log_final_poly_len)
            .ok_or(FriVerifierParamsError::HeightOverflow)?;
        if height >= usize::BITS as usize {
            return Err(FriVerifierParamsError::HeightOverflow);
        }
        if max_log_arity == 0 {
            return Err(FriVerifierParamsError::ZeroMaxLogArity);
        }
        Ok(Self {
            log_blowup,
            log_final_poly_len,
            max_log_arity,
            commit_pow_bits,
            query_pow_bits,
            num_queries,
            permutation_config: permutation_config.into(),
        })
    }

    /// Compatibility constructor for existing callers. New fallible callers
    /// should prefer [`Self::try_with_mmcs`].
    pub fn with_mmcs(
        log_blowup: usize,
        log_final_poly_len: usize,
        max_log_arity: usize,
        commit_pow_bits: usize,
        query_pow_bits: usize,
        num_queries: usize,
        permutation_config: impl Into<PermConfig>,
    ) -> Self {
        Self::try_with_mmcs(
            log_blowup,
            log_final_poly_len,
            max_log_arity,
            commit_pow_bits,
            query_pow_bits,
            num_queries,
            permutation_config,
        )
        .expect("invalid production FRI verifier parameters")
    }

    pub const fn log_blowup(&self) -> usize {
        self.log_blowup
    }
    pub const fn log_final_poly_len(&self) -> usize {
        self.log_final_poly_len
    }
    pub const fn max_log_arity(&self) -> usize {
        self.max_log_arity
    }
    pub const fn commit_pow_bits(&self) -> usize {
        self.commit_pow_bits
    }
    pub const fn query_pow_bits(&self) -> usize {
        self.query_pow_bits
    }
    pub const fn num_queries(&self) -> usize {
        self.num_queries
    }
    pub const fn permutation_config(&self) -> PermConfig {
        self.permutation_config
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_circuit::ops::Poseidon2Config;
    use p3_fri::FriParameters;
    use p3_goldilocks::Goldilocks;

    use super::*;

    fn p2() -> PermConfig {
        PermConfig::poseidon2(Poseidon2Config::KOALA_BEAR_D4_W16)
    }

    /// The only safe constructor must always produce MMCS-enabled params, so a
    /// production verifier builder cannot accidentally skip commitment opening
    /// checks.
    #[test]
    fn with_mmcs_always_enables_mmcs_verification() {
        let params = FriVerifierParams::with_mmcs(1, 0, 1, 0, 0, 1, p2());
        assert_eq!(params.permutation_config(), p2());
    }

    /// `with_mmcs` must store the caller-supplied `num_queries` unchanged.
    /// The recursive verifier enforces `fri_proof_num_queries(proof) >= num_queries`
    /// at circuit-construction time; an incorrect stored value silently weakens
    /// FRI soundness.
    #[test]
    fn with_mmcs_stores_num_queries() {
        let params = FriVerifierParams::with_mmcs(2, 0, 1, 0, 16, 42, p2());
        assert_eq!(
            params.num_queries, 42,
            "with_mmcs must store num_queries exactly"
        );
    }

    #[test]
    fn with_mmcs_rejects_a_combined_height_at_the_word_boundary() {
        assert_eq!(
            FriVerifierParams::try_with_mmcs(usize::BITS as usize - 1, 1, 1, 0, 0, 1, p2(),),
            Err(FriVerifierParamsError::HeightOverflow)
        );
    }

    fn native(
        log_blowup: usize,
        log_final_poly_len: usize,
        max_log_arity: usize,
        num_queries: usize,
        commit_pow_bits: usize,
        query_pow_bits: usize,
    ) -> FriParameters<()> {
        FriParameters {
            log_blowup,
            log_final_poly_len,
            max_log_arity,
            num_queries,
            batch_proof_of_work_bits: 0,
            commit_proof_of_work_bits: commit_pow_bits,
            query_proof_of_work_bits: query_pow_bits,
            mmcs: (),
        }
    }

    #[test]
    fn native_snapshot_rejects_zero_folds_queries_and_field_pow() {
        assert_eq!(
            NativeFriParams::try_from_native::<BabyBear, _>(&native(1, 0, 0, 2, 0, 0)),
            Err(FriInputError::ZeroMaxLogArity)
        );
        assert_eq!(
            NativeFriParams::try_from_native::<BabyBear, _>(&native(1, 0, 1, 0, 0, 0)),
            Err(FriInputError::ZeroQueries)
        );
        assert_eq!(
            NativeFriParams::try_from_native::<BabyBear, _>(&native(1, 0, 1, 2, 31, 0)),
            Err(FriInputError::PowBitsOutOfRange { name: "commit" })
        );
    }

    #[test]
    fn native_snapshot_preserves_exact_queries_and_recursive_floor() {
        let snapshot =
            NativeFriParams::try_from_native::<BabyBear, _>(&native(1, 0, 1, 1, 0, 0)).unwrap();
        assert_eq!(snapshot.num_queries(), 1);
        assert!(snapshot.validate_field::<BabyBear>().is_ok());
        let local_floor = FriVerifierParams::with_mmcs(1, 0, 1, 0, 0, 2, p2());
        assert_eq!(
            snapshot.validate_recursive(&local_floor),
            Err(FriInputError::QueryFloor {
                native: 1,
                minimum: 2,
            })
        );

        let positive =
            NativeFriParams::try_from_native::<BabyBear, _>(&native(1, 0, 1, 4, 0, 0)).unwrap();
        assert_eq!(positive.num_queries(), 4);
        assert!(positive.validate_recursive(&local_floor).is_ok());
    }

    #[test]
    fn native_snapshot_rejects_each_recursive_scalar_mismatch() {
        let snapshot =
            NativeFriParams::try_from_native::<BabyBear, _>(&native(1, 0, 1, 2, 0, 0)).unwrap();
        for (params, name) in [
            (
                FriVerifierParams::with_mmcs(2, 0, 1, 0, 0, 2, p2()),
                "log_blowup",
            ),
            (
                FriVerifierParams::with_mmcs(1, 1, 1, 0, 0, 2, p2()),
                "log_final_poly_len",
            ),
            (
                FriVerifierParams::with_mmcs(1, 0, 2, 0, 0, 2, p2()),
                "max_log_arity",
            ),
            (
                FriVerifierParams::with_mmcs(1, 0, 1, 1, 0, 2, p2()),
                "commit_pow_bits",
            ),
            (
                FriVerifierParams::with_mmcs(1, 0, 1, 0, 1, 2, p2()),
                "query_pow_bits",
            ),
        ] {
            assert_eq!(
                snapshot.validate_recursive(&params),
                Err(FriInputError::ScalarMismatch { name })
            );
        }
    }

    #[test]
    fn native_snapshot_rejects_height_overflow_and_field_height() {
        assert_eq!(
            NativeFriParams::try_from_native::<BabyBear, _>(&native(usize::MAX, 1, 1, 2, 0, 0)),
            Err(FriInputError::LogNotRepresentable { name: "log_blowup" })
        );
        assert_eq!(
            NativeFriParams::try_from_native::<BabyBear, _>(&native(
                BabyBear::TWO_ADICITY,
                1,
                1,
                2,
                0,
                0
            )),
            Err(FriInputError::HeightExceedsTwoAdicity)
        );
        let word_limited = NativeFriParams {
            log_blowup: usize::BITS as usize,
            log_final_poly_len: 0,
            max_log_arity: 1,
            num_queries: 1,
            commit_pow_bits: 0,
            query_pow_bits: 0,
        };
        assert_eq!(
            word_limited.validate_field::<BabyBear>(),
            Err(FriInputError::LogNotRepresentable { name: "log_blowup" })
        );
        let combined_word_limited = NativeFriParams {
            log_blowup: usize::BITS as usize - 1,
            log_final_poly_len: 1,
            max_log_arity: 1,
            num_queries: 1,
            commit_pow_bits: 0,
            query_pow_bits: 0,
        };
        assert_eq!(
            combined_word_limited.validate_field::<BabyBear>(),
            Err(FriInputError::HeightExceedsWord)
        );
    }

    #[test]
    fn native_snapshot_revalidates_against_the_actual_field() {
        let snapshot = NativeFriParams::try_from_native::<Goldilocks, _>(&native(
            BabyBear::TWO_ADICITY + 1,
            0,
            1,
            2,
            0,
            0,
        ))
        .unwrap();
        assert!(snapshot.validate_field::<Goldilocks>().is_ok());
        assert_eq!(
            snapshot.validate_field::<BabyBear>(),
            Err(FriInputError::HeightExceedsTwoAdicity)
        );
    }
}
