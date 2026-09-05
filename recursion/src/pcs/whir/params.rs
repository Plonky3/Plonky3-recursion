//! Verifier parameters for the WHIR recursive verifier.

use alloc::vec::Vec;
use core::fmt;

use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::ops::PermConfig;
use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_sumcheck::strategy::VariableOrder;
use p3_whir::parameters::WhirConfig;
use thiserror::Error;

/// Which phase of the WHIR protocol a verifier-params derivation error occurred in.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WhirPhase {
    /// An intermediate STIR round, 0-indexed.
    Round(usize),
    /// The final STIR/consistency phase.
    Final,
}

impl fmt::Display for WhirPhase {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Round(i) => write!(f, "round {i}"),
            Self::Final => write!(f, "final phase"),
        }
    }
}

/// Errors deriving in-circuit WHIR verifier parameters from a `WhirConfig`.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum WhirVerifierParamsError {
    /// A phase's STIR query count meets or exceeds its folded domain size.
    ///
    /// Native `get_challenge_stir_queries` enumerates the whole folded domain
    /// deterministically with zero challenger draws whenever
    /// `num_queries >= folded_domain_size`; the in-circuit verifier always
    /// draws exactly `num_queries` samples and does not yet mirror that
    /// branch. Handling it in-circuit is tracked as a follow-on task.
    #[error(
        "{phase}: num_queries ({num_queries}) >= folded_domain_size ({folded_domain_size}); \
         saturating STIR query counts are not yet supported in-circuit"
    )]
    SaturatingQueryCountUnsupported {
        /// The phase that would saturate.
        phase: WhirPhase,
        /// The configured number of STIR queries for that phase.
        num_queries: usize,
        /// `domain_size >> folding_factor` for that phase.
        folded_domain_size: usize,
    },
}

/// Per-round configuration extracted from a `WhirConfig` for in-circuit use.
#[derive(Clone, Debug)]
pub struct WhirRoundParams<F> {
    /// Number of out-of-domain evaluation samples for this round.
    pub ood_samples: usize,
    /// Number of STIR proximity queries.
    pub num_queries: usize,
    /// PoW bits for the after-commitment grinding phase.
    pub pow_bits: usize,
    /// PoW bits for the folding sumcheck within this round.
    pub folding_pow_bits: usize,
    /// Number of variables folded in this round (= folding_factor for the round's sumcheck).
    pub folding_factor: usize,
    /// Size of the evaluation domain before folding in this round.
    pub domain_size: usize,
    /// Two-adic generator of the folded evaluation domain (for computing STIR domain points).
    pub folded_domain_gen: F,
    /// Number of multilinear variables remaining after folding in this round.
    pub num_variables: usize,
}

/// Verifier parameters for the WHIR recursive verifier.
///
/// Mirrors the verification-relevant subset of `WhirConfig`, stripped of all proving
/// machinery (DFT, Mmcs prover data, phantom types). Carry this alongside the circuit
/// instead of threading the full `WhirConfig<EF, F, Ch>` into the verifier.
#[derive(Clone, Debug)]
pub struct WhirVerifierParams<F> {
    /// Number of multilinear variables in the original polynomial.
    pub num_variables: usize,
    /// Number of OOD evaluation samples at the initial commitment phase.
    pub commitment_ood_samples: usize,
    /// PoW bits for the initial folding sumcheck (before any intermediate rounds).
    pub starting_folding_pow_bits: usize,
    /// Per-round configuration for each intermediate STIR round.
    pub round_params: Vec<WhirRoundParams<F>>,
    /// Number of variables in the final polynomial sent in the clear.
    pub final_poly_num_variables: usize,
    /// Number of STIR queries in the final proximity test.
    pub final_queries: usize,
    /// PoW bits for the final STIR query phase.
    pub final_pow_bits: usize,
    /// Number of sumcheck rounds in the final phase (`0` means no final sumcheck).
    pub final_sumcheck_rounds: usize,
    /// Number of variables folded to enter the final phase
    /// (= `final_round_config().folding_factor`).
    ///
    /// This is the quantity `WhirVerifier::verify_stir_challenges` uses to size the
    /// final STIR query domain and Merkle leaf width. It is distinct from
    /// `final_sumcheck_rounds`, which counts the plain-sumcheck rounds performed
    /// *after* that fold; the two coincide only for specific arities.
    pub final_folding_factor: usize,
    /// PoW bits for the final folding sumcheck.
    pub final_folding_pow_bits: usize,
    /// Folding variable order (Prefix or Suffix).
    pub variable_order: VariableOrder,
    /// Domain size entering the final phase (= `final_round_config().domain_size`).
    pub final_domain_size: usize,
    /// Two-adic generator of the final folded domain (= `final_round_config().folded_domain_gen`).
    pub final_folded_domain_gen: F,
    /// Permutation config for MMCS path verification.
    /// `None` skips MMCS verification — **unsound**, test-only via
    /// [`Self::unsafe_arithmetic_only_for_tests`].
    pub permutation_config: Option<PermConfig>,
}

impl<F: Field> WhirVerifierParams<F> {
    /// Derive verifier params from a concrete `WhirConfig`.
    ///
    /// # Errors
    ///
    /// Returns [`WhirVerifierParamsError::SaturatingQueryCountUnsupported`] if any
    /// round, or the final phase, would ask for at least as many STIR queries as its
    /// folded domain has positions. Native sampling handles that case by
    /// deterministically enumerating the whole domain with no challenger draws; the
    /// in-circuit verifier always draws exactly `num_queries` samples and does not yet
    /// mirror that branch.
    pub fn from_config<EF, Ch>(
        config: &WhirConfig<EF, F, Ch>,
        variable_order: VariableOrder,
        permutation_config: impl Into<PermConfig>,
    ) -> Result<Self, WhirVerifierParamsError>
    where
        F: TwoAdicField,
        EF: ExtensionField<F> + TwoAdicField,
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        let n_rounds = config.n_rounds();
        let round_params = (0..n_rounds)
            .map(|i| {
                let rp = &config.round_parameters[i];
                let folded_domain_size = rp.domain_size >> rp.folding_factor;
                if rp.num_queries >= folded_domain_size {
                    return Err(WhirVerifierParamsError::SaturatingQueryCountUnsupported {
                        phase: WhirPhase::Round(i),
                        num_queries: rp.num_queries,
                        folded_domain_size,
                    });
                }
                Ok(WhirRoundParams {
                    ood_samples: rp.ood_samples,
                    num_queries: rp.num_queries,
                    pow_bits: rp.pow_bits,
                    folding_pow_bits: rp.folding_pow_bits,
                    folding_factor: rp.folding_factor,
                    domain_size: rp.domain_size,
                    folded_domain_gen: rp.folded_domain_gen,
                    num_variables: rp.num_variables,
                })
            })
            .collect::<Result<Vec<_>, _>>()?;

        let final_round_config = config.final_round_config();
        let final_folded_domain_size =
            final_round_config.domain_size >> final_round_config.folding_factor;
        if config.final_queries >= final_folded_domain_size {
            return Err(WhirVerifierParamsError::SaturatingQueryCountUnsupported {
                phase: WhirPhase::Final,
                num_queries: config.final_queries,
                folded_domain_size: final_folded_domain_size,
            });
        }

        Ok(Self {
            num_variables: config.num_variables,
            commitment_ood_samples: config.commitment_ood_samples,
            starting_folding_pow_bits: config.starting_folding_pow_bits,
            round_params,
            final_poly_num_variables: final_round_config.num_variables,
            final_queries: config.final_queries,
            final_pow_bits: config.final_pow_bits,
            final_sumcheck_rounds: config.final_sumcheck_rounds,
            final_folding_factor: final_round_config.folding_factor,
            final_folding_pow_bits: config.final_folding_pow_bits,
            variable_order,
            final_domain_size: final_round_config.domain_size,
            final_folded_domain_gen: final_round_config.folded_domain_gen,
            permutation_config: Some(permutation_config.into()),
        })
    }

    /// Create params **without MMCS verification** (arithmetic-only).
    ///
    /// # Safety / soundness
    ///
    /// A verifier built from these params checks the WHIR arithmetic (sumcheck,
    /// constraint evaluation, fold value) but does **not** verify Merkle/MMCS
    /// commitment openings. This is **unsound for production use**: a prover can
    /// open commitments to arbitrary values without detection.
    ///
    /// Use only for tests that isolate the arithmetic path.
    ///
    /// # Errors
    ///
    /// See [`Self::from_config`].
    pub fn unsafe_arithmetic_only_for_tests<EF, Ch>(
        config: &WhirConfig<EF, F, Ch>,
        variable_order: VariableOrder,
        permutation_config: impl Into<PermConfig>,
    ) -> Result<Self, WhirVerifierParamsError>
    where
        F: TwoAdicField,
        EF: ExtensionField<F> + TwoAdicField,
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        let mut params = Self::from_config(config, variable_order, permutation_config)?;
        params.permutation_config = None;
        Ok(params)
    }

    /// Number of intermediate STIR rounds.
    pub const fn n_rounds(&self) -> usize {
        self.round_params.len()
    }

    /// Folding factor (= round sumcheck length) for the given round index.
    ///
    /// - Round `0..n_rounds()`: the initial folding factor is the length of `initial_sumcheck`.
    /// - Round `n_rounds()`: the folding factor applied to enter the final phase
    ///   (`final_folding_factor`), *not* the final plain-sumcheck length
    ///   (`final_sumcheck_rounds`) — the two are distinct quantities that coincide
    ///   only for specific arities.
    ///
    /// The initial folding factor is stored implicitly via the `initial_sumcheck` length in the proof.
    /// This method queries the `round_params[i].folding_factor` for intermediate rounds.
    pub fn round_folding_factor(&self, round: usize) -> usize {
        if round < self.n_rounds() {
            self.round_params[round].folding_factor
        } else {
            self.final_folding_factor
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear;
    use p3_field::extension::BinomialExtensionField;
    use p3_sumcheck::layout::{Layout, PrefixProver};
    use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};

    use super::*;
    use crate::pcs::whir::uni::recursive_pcs::DummyChallenger;

    type BF = BabyBear;
    type EF = BinomialExtensionField<BF, 4>;

    /// `NUM_VARIABLES = 4` with this schedule has zero intermediate rounds: the
    /// only fold (factor 4) takes the starting domain (32 positions) straight
    /// into the final phase, leaving a folded domain of `32 >> 4 = 2`
    /// positions. `final_queries = 35 >= 2`, so native sampling would enumerate
    /// the whole domain with no challenger draws, which the in-circuit verifier
    /// does not yet mirror.
    fn saturating_protocol_params() -> ProtocolParameters {
        ProtocolParameters {
            security_level: 32,
            pow_bits: 0,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(4),
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: 1,
        }
    }

    /// The same schedule at `NUM_VARIABLES = 12` has one intermediate round and
    /// a final phase that does not saturate; `whir_verifier.rs`'s and
    /// `verifier.rs`'s own baselines already exercise this arity end to end.
    fn non_saturating_protocol_params() -> ProtocolParameters {
        ProtocolParameters {
            security_level: 32,
            pow_bits: 0,
            round_log_inv_rates: vec![4],
            folding_factor: FoldingFactor::Constant(4),
            soundness_type: SecurityAssumption::CapacityBound,
            starting_log_inv_rate: 1,
        }
    }

    #[test]
    fn from_config_rejects_a_saturating_final_phase() {
        let config =
            WhirConfig::<EF, BF, DummyChallenger<BF>>::new(4, saturating_protocol_params())
                .expect("config is valid, only its final-phase query count saturates");
        assert_eq!(
            config.n_rounds(),
            0,
            "this schedule has no intermediate rounds"
        );

        let err = WhirVerifierParams::<BF>::from_config(
            &config,
            PrefixProver::<BF, EF>::variable_order(),
            p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
        )
        .expect_err("final_queries=35 >= folded_domain_size=2 must be rejected");

        assert_eq!(
            err,
            WhirVerifierParamsError::SaturatingQueryCountUnsupported {
                phase: WhirPhase::Final,
                num_queries: 35,
                folded_domain_size: 2,
            }
        );
    }

    #[test]
    fn from_config_accepts_a_non_saturating_config() {
        let config =
            WhirConfig::<EF, BF, DummyChallenger<BF>>::new(12, non_saturating_protocol_params())
                .expect("config is valid");
        assert_eq!(config.n_rounds(), 1);

        WhirVerifierParams::<BF>::from_config(
            &config,
            PrefixProver::<BF, EF>::variable_order(),
            p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
        )
        .expect("this arity does not saturate any phase");
    }
}
