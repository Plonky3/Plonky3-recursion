//! Arity-dependent codeword rates shared by native verification and transcript replay.

use p3_whir::parameters::ProtocolParameters;

use crate::pcs::whir::params::WhirVerifierParamsError;
use crate::pcs::whir::uni::plan::initial_layout_folding;
use crate::pcs::whir::uni::recursive_pcs::validate_round_config_inputs;

/// How to derive intermediate codeword rates for each commitment's arity.
///
/// A larger first domain reduction saves prover hashing at the cost of more
/// proximity queries. It does not change the initial rate or security target.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WhirRatePolicy {
    /// Preserve native automatic rates or the caller's explicit rate vector.
    #[default]
    Native,
    /// Shrink the first intermediate domain by `2^bits`, then halve later domains.
    ///
    /// Native automatic rates correspond to one bit. This policy requires an
    /// empty `round_log_inv_rates` vector and a positive first intermediate rate.
    FirstRoundReduction(usize),
}

impl WhirRatePolicy {
    pub(crate) fn validate(
        self,
        protocol: &ProtocolParameters,
    ) -> Result<(), WhirVerifierParamsError> {
        if let Self::FirstRoundReduction(bits) = self {
            if !protocol.round_log_inv_rates.is_empty() {
                return Err(WhirVerifierParamsError::InvalidRatePolicy(
                    "an adaptive policy cannot be combined with explicit round rates",
                ));
            }
            let first = initial_layout_folding(&protocol.folding_factor)
                .ok_or(WhirVerifierParamsError::UnsupportedFoldingFactor)?;
            let max = protocol
                .starting_log_inv_rate
                .checked_add(first)
                .ok_or(WhirVerifierParamsError::RateArithmeticOverflow { round: 0 })?;
            if bits == 0 || bits >= max {
                return Err(WhirVerifierParamsError::InvalidRatePolicy(
                    "first domain reduction must be positive and leave a positive inverse rate",
                ));
            }
        }
        Ok(())
    }

    pub(crate) fn resolve(
        self,
        arity: usize,
        protocol: &ProtocolParameters,
    ) -> Result<ProtocolParameters, WhirVerifierParamsError> {
        self.validate(protocol)?;
        validate_round_config_inputs(arity, protocol)?;
        let mut resolved = protocol.clone();
        if let Self::FirstRoundReduction(bits) = self {
            let schedule = protocol
                .folding_factor
                .compute_folding_schedule(arity)
                .map_err(p3_whir::parameters::WhirConfigError::FoldingFactor)?;
            let mut rate = protocol.starting_log_inv_rate;
            for (round, &fold) in schedule.iter().take(schedule.len() - 1).enumerate() {
                rate = rate
                    .checked_add(fold)
                    .and_then(|rate| rate.checked_sub(if round == 0 { bits } else { 1 }))
                    .ok_or(WhirVerifierParamsError::RateArithmeticOverflow { round })?;
                resolved.round_log_inv_rates.push(rate);
            }
        }
        Ok(resolved)
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::DuplexChallenger;
    use p3_field::extension::BinomialExtensionField;
    use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig};

    use super::*;

    type EF = BinomialExtensionField<BabyBear, 4>;
    type Ch = DuplexChallenger<BabyBear, Poseidon2BabyBear<16>, 16, 8>;

    fn protocol() -> ProtocolParameters {
        ProtocolParameters {
            starting_log_inv_rate: 2,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(4),
            soundness_type: SecurityAssumption::CapacityBound,
            security_level: 64,
            pow_bits: 15,
        }
    }

    #[test]
    fn extra_initial_reduction_shrinks_every_intermediate_codeword() {
        for arity in 4..=25 {
            let original = protocol();
            let native = WhirConfig::<EF, BabyBear, Ch>::new(arity, original.clone()).unwrap();
            for reduction in [2, 3] {
                let resolved = WhirRatePolicy::FirstRoundReduction(reduction)
                    .resolve(arity, &original)
                    .unwrap();
                let tuned = WhirConfig::<EF, BabyBear, Ch>::new(arity, resolved).unwrap();
                assert_eq!(native.n_rounds(), tuned.n_rounds());
                assert_eq!(native.num_variables(), tuned.num_variables());
                for (index, (old, new)) in native
                    .round_parameters()
                    .iter()
                    .zip(tuned.round_parameters())
                    .enumerate()
                {
                    assert_eq!(old.num_variables, new.num_variables);
                    // A round queries the previous codeword, so round 0 is unchanged.
                    assert_eq!(
                        old.domain_size,
                        new.domain_size << if index == 0 { 0 } else { reduction - 1 }
                    );
                }
                assert_eq!(
                    native.final_round_config().domain_size,
                    tuned.final_round_config().domain_size
                        << if native.n_rounds() == 0 {
                            0
                        } else {
                            reduction - 1
                        }
                );
            }
        }
    }

    #[test]
    fn varying_folds_use_the_actual_first_transition() {
        let mut original = protocol();
        original.folding_factor = FoldingFactor::ConstantFromSecondRound(5, 3);
        let resolved = WhirRatePolicy::FirstRoundReduction(3)
            .resolve(22, &original)
            .unwrap();
        assert_eq!(resolved.round_log_inv_rates, vec![4, 6, 8, 10]);
    }

    #[test]
    fn native_policy_preserves_explicit_rates() {
        let mut original = protocol();
        original.round_log_inv_rates = vec![3, 6, 9];
        let resolved = WhirRatePolicy::Native.resolve(22, &original).unwrap();
        assert_eq!(resolved.round_log_inv_rates, original.round_log_inv_rates);
        assert!(
            WhirRatePolicy::FirstRoundReduction(3)
                .resolve(22, &original)
                .is_err()
        );
    }

    #[test]
    fn invalid_reductions_fail_before_native_config_derivation() {
        for reduction in [0, 6, usize::MAX] {
            assert!(
                WhirRatePolicy::FirstRoundReduction(reduction)
                    .resolve(22, &protocol())
                    .is_err()
            );
        }
    }
    fn check_opening_security<F, EF, Perm, const W: usize, const R: usize, const D: usize>(
        perm: Perm,
    ) where
        F: p3_field::TwoAdicField
            + p3_field::PrimeField64
            + p3_field::UniformSamplingField
            + p3_challenger::fs::TranscriptField
            + Ord,
        EF: p3_field::ExtensionField<F> + p3_field::TwoAdicField,
        Perm: p3_symmetric::CryptographicPermutation<[F; W]>
            + p3_symmetric::CryptographicPermutation<[F::Packing; W]>
            + Clone,
        [F; D]: serde::Serialize + for<'de> serde::Deserialize<'de>,
    {
        use p3_dft::Radix2DFTSmallBatch;
        use p3_merkle_tree::MerkleTreeMmcs;
        use p3_sumcheck::PrescribedPointPcs;
        use p3_sumcheck::layout::PrefixProver;
        use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
        use p3_whir::pcs::prover::WhirProver;

        use crate::pcs::whir::uni::pcs::round_schedule;

        let mmcs = MerkleTreeMmcs::<F::Packing, F::Packing, _, _, 2, D>::new(
            PaddingFreeSponge::<Perm, W, R, D>::new(perm.clone()),
            TruncatedPermutation::<Perm, 2, D, W>::new(perm),
            0,
        );
        let dft = Radix2DFTSmallBatch::<F>::default();
        // Include every concrete arity across the direct-send and round-count boundaries.
        for log_height in 4..=17.min(F::TWO_ADICITY - 10) {
            let shapes = [(log_height, 48), (log_height - 1, 166), (log_height, 4)];
            let points = vec![vec![EF::from_u32(7), EF::from_u32(13)]; shapes.len()];
            let schedule = round_schedule::<F, EF>(&shapes, &points, 4);
            let report = |protocol: ProtocolParameters, policy: WhirRatePolicy| {
                let config = WhirConfig::<EF, F, DuplexChallenger<F, Perm, W, R>>::new(
                    schedule.stacked_num_variables,
                    policy
                        .resolve(schedule.stacked_num_variables, &protocol)
                        .unwrap(),
                )
                .unwrap();
                WhirProver::<EF, F, _, _, DuplexChallenger<F, Perm, W, R>, PrefixProver<F, EF>>::new(
                    config, dft.clone(), mmcs.clone(),
                ).prescribed_security(&schedule.protocol).unwrap()
            };
            let native = report(protocol(), WhirRatePolicy::Native);
            let mut tuned_protocol = protocol();
            tuned_protocol.security_level = 66;
            tuned_protocol.pow_bits = 18;
            let tuned = report(tuned_protocol, WhirRatePolicy::FirstRoundReduction(2));
            assert!(tuned.candidates().is_some());
            assert!(
                tuned.error().bits() >= native.error().bits(),
                "arity {}: candidate {}, native {}",
                schedule.stacked_num_variables,
                tuned.error().bits(),
                native.error().bits()
            );
            assert_eq!(tuned.log2_max_candidates, native.log2_max_candidates);
        }
    }

    #[test]
    fn tuned_rates_preserve_baby_bear_d4_opening_security() {
        check_opening_security::<BabyBear, EF, _, 16, 8, 8>(
            p3_baby_bear::default_babybear_poseidon2_16(),
        );
    }

    #[test]
    fn tuned_rates_preserve_koala_bear_d4_opening_security() {
        type F = p3_koala_bear::KoalaBear;
        check_opening_security::<F, BinomialExtensionField<F, 4>, _, 16, 8, 8>(
            p3_koala_bear::default_koalabear_poseidon2_16(),
        );
    }

    #[test]
    fn tuned_rates_preserve_goldilocks_d2_opening_security() {
        type F = p3_goldilocks::Goldilocks;
        check_opening_security::<F, BinomialExtensionField<F, 2>, _, 8, 4, 4>(
            p3_goldilocks::default_goldilocks_poseidon2_8(),
        );
    }

    #[test]
    fn tuned_rates_preserve_koala_bear_d5_opening_security() {
        type F = p3_koala_bear::KoalaBear;
        check_opening_security::<
            F,
            p3_field::extension::QuinticTrinomialExtensionField<F>,
            _,
            16,
            8,
            8,
        >(p3_koala_bear::default_koalabear_poseidon2_16());
    }
}
