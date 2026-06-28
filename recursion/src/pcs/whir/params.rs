//! Verifier parameters for the WHIR recursive verifier.

use alloc::vec::Vec;

use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::ops::PermConfig;
use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_sumcheck::strategy::VariableOrder;
use p3_whir::parameters::WhirConfig;

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
    pub fn from_config<EF, Ch>(
        config: &WhirConfig<EF, F, Ch>,
        variable_order: VariableOrder,
        permutation_config: impl Into<PermConfig>,
    ) -> Self
    where
        F: TwoAdicField,
        EF: ExtensionField<F> + TwoAdicField,
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        let n_rounds = config.n_rounds();
        let round_params = (0..n_rounds)
            .map(|i| {
                let rp = &config.round_parameters[i];
                WhirRoundParams {
                    ood_samples: rp.ood_samples,
                    num_queries: rp.num_queries,
                    pow_bits: rp.pow_bits,
                    folding_pow_bits: rp.folding_pow_bits,
                    folding_factor: rp.folding_factor,
                    domain_size: rp.domain_size,
                    folded_domain_gen: rp.folded_domain_gen,
                    num_variables: rp.num_variables,
                }
            })
            .collect();

        let final_round_config = config.final_round_config();

        Self {
            num_variables: config.num_variables,
            commitment_ood_samples: config.commitment_ood_samples,
            starting_folding_pow_bits: config.starting_folding_pow_bits,
            round_params,
            final_poly_num_variables: final_round_config.num_variables,
            final_queries: config.final_queries,
            final_pow_bits: config.final_pow_bits,
            final_sumcheck_rounds: config.final_sumcheck_rounds,
            final_folding_pow_bits: config.final_folding_pow_bits,
            variable_order,
            final_domain_size: final_round_config.domain_size,
            final_folded_domain_gen: final_round_config.folded_domain_gen,
            permutation_config: Some(permutation_config.into()),
        }
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
    pub fn unsafe_arithmetic_only_for_tests<EF, Ch>(
        config: &WhirConfig<EF, F, Ch>,
        variable_order: VariableOrder,
        permutation_config: impl Into<PermConfig>,
    ) -> Self
    where
        F: TwoAdicField,
        EF: ExtensionField<F> + TwoAdicField,
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        let mut params = Self::from_config(config, variable_order, permutation_config);
        params.permutation_config = None;
        params
    }

    /// Number of intermediate STIR rounds.
    pub const fn n_rounds(&self) -> usize {
        self.round_params.len()
    }

    /// Folding factor (= round sumcheck length) for the given round index.
    ///
    /// - Round `0..n_rounds()`: the initial folding factor is the length of `initial_sumcheck`.
    /// - Round `n_rounds()`: the final sumcheck length.
    ///
    /// The initial folding factor is stored implicitly via the `initial_sumcheck` length in the proof.
    /// This method queries the `round_params[i].folding_factor` for intermediate rounds.
    pub fn round_folding_factor(&self, round: usize) -> usize {
        if round < self.n_rounds() {
            self.round_params[round].folding_factor
        } else {
            self.final_sumcheck_rounds
        }
    }
}
