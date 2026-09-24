//! Verifier-side configuration for the WHIR-backed univariate PCS.

use alloc::vec::Vec;

use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::ops::PermConfig;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, NonPrimitiveOpId};
use p3_commit::{Mmcs, PolynomialSpace};
use p3_dft::TwoAdicSubgroupDft;
use p3_field::coset::TwoAdicMultiplicativeCoset;
use p3_field::{ExtensionField, PrimeField64, TwoAdicField};
use p3_merkle_tree::MerkleCap;
use p3_sumcheck::layout::Layout;
use p3_sumcheck::strategy::VariableOrder;
use p3_uni_stark::{StarkGenericConfig, Val};
use p3_whir::parameters::{ProtocolParameters, WhirConfig};

use crate::Target;
use crate::challenger::CircuitChallenger;
use crate::challenger_perm::ChallengerPermConfig;
use crate::pcs::whir::params::{WhirVerifierParams, WhirVerifierParamsError};
use crate::pcs::whir::uni::circuit::verify_whir_uni_circuit;
use crate::pcs::whir::uni::pcs::WhirUniPcs;
use crate::pcs::whir::uni::targets::WhirUniProofTargets;
use crate::traits::{ComsWithOpeningsTargets, Recursive, RecursivePcs};
use crate::types::{OpenedValuesTargetsWithLookups, RecursiveLagrangeSelectors};
use crate::verifier::{ObservableCommitment, VerificationError};

pub(crate) fn validate_round_config_inputs(
    stacked_num_variables: usize,
    protocol_params: &ProtocolParameters,
) -> Result<(), WhirVerifierParamsError> {
    let rate = protocol_params.starting_log_inv_rate;
    let exponent = stacked_num_variables.checked_add(rate).ok_or(
        WhirVerifierParamsError::InvalidStackedArity {
            arity: stacked_num_variables,
            rate,
        },
    )?;
    if exponent >= usize::BITS as usize {
        return Err(WhirVerifierParamsError::InvalidStackedArity {
            arity: stacked_num_variables,
            rate,
        });
    }

    let schedule = protocol_params
        .folding_factor
        .compute_folding_schedule(stacked_num_variables)
        .map_err(|error| {
            WhirVerifierParamsError::InvalidConfig(
                p3_whir::parameters::WhirConfigError::FoldingFactor(error),
            )
        })?;
    let num_rounds = schedule.len() - 1;
    if !protocol_params.round_log_inv_rates.is_empty()
        && protocol_params.round_log_inv_rates.len() != num_rounds
    {
        return Err(WhirVerifierParamsError::InvalidConfig(
            p3_whir::parameters::WhirConfigError::RoundRateCountMismatch {
                expected: num_rounds,
                actual: protocol_params.round_log_inv_rates.len(),
            },
        ));
    }
    if let p3_whir::parameters::FoldingFactor::PerRound(factors) = &protocol_params.folding_factor
        && factors.len() != num_rounds + 1
    {
        return Err(WhirVerifierParamsError::InvalidConfig(
            p3_whir::parameters::WhirConfigError::FoldingFactorCountMismatch {
                expected: num_rounds + 1,
                actual: factors.len(),
            },
        ));
    }
    let mut previous_rate = rate;
    for (round, &factor) in schedule.iter().take(num_rounds).enumerate() {
        let max_next_rate = previous_rate
            .checked_add(factor)
            .ok_or(WhirVerifierParamsError::RateArithmeticOverflow { round })?;
        let next_rate = protocol_params
            .round_log_inv_rates
            .get(round)
            .copied()
            .unwrap_or_else(|| previous_rate + (factor - 1));
        if next_rate > max_next_rate {
            // WhirConfig::new reports this semantic mismatch. Returning the
            // same typed variant here keeps its constructor panic-free even
            // for caller-mutated protocol values.
            return Err(WhirVerifierParamsError::InvalidConfig(
                p3_whir::parameters::WhirConfigError::RateGrowsDomain { round },
            ));
        }
        previous_rate = next_rate;
    }
    Ok(())
}

/// WHIR parameters shared by every commitment a proof carries.
///
/// A commitment's WHIR configuration depends on the arity of the stacked
/// polynomial it covers, which varies per commitment, so the per-round
/// [`WhirVerifierParams`] are derived on demand rather than stored.
///
/// Fields are private and the constructor requires a concrete MMCS permutation.
///
/// ```compile_fail
/// use p3_recursion::pcs::whir::uni::WhirUniVerifierParams;
/// let params: WhirUniVerifierParams<()> = unimplemented!();
/// let WhirUniVerifierParams { folding, .. } = params;
/// ```
///
/// ```compile_fail
/// use p3_recursion::pcs::whir::uni::WhirUniVerifierParams;
/// let _ = WhirUniVerifierParams::<()>::unsafe_arithmetic_only_for_tests();
/// ```
#[derive(Clone, Debug)]
pub struct WhirUniVerifierParams<F> {
    /// Protocol parameters used for every commitment.
    protocol_params: ProtocolParameters,
    /// First-round folding factor, read from `protocol_params`.
    folding: usize,
    /// Folding variable order declared by the prover's layout.
    variable_order: VariableOrder,
    /// Poseidon2 configuration for mandatory in-circuit MMCS path verification.
    permutation_config: PermConfig,
    _marker: core::marker::PhantomData<F>,
}

impl<F: TwoAdicField> WhirUniVerifierParams<F> {
    /// Builds the shared parameters.
    ///
    /// Returns an error unless the folding factor is a nonzero constant.
    pub fn new(
        protocol_params: ProtocolParameters,
        variable_order: VariableOrder,
        permutation_config: impl Into<PermConfig>,
    ) -> Result<Self, WhirVerifierParamsError> {
        if variable_order != VariableOrder::Prefix {
            return Err(WhirVerifierParamsError::UnsupportedVariableOrder { variable_order });
        }
        let p3_whir::parameters::FoldingFactor::Constant(folding) = protocol_params.folding_factor
        else {
            return Err(WhirVerifierParamsError::UnsupportedFoldingFactor);
        };
        if folding == 0 {
            return Err(WhirVerifierParamsError::UnsupportedFoldingFactor);
        }
        Ok(Self {
            protocol_params,
            folding,
            variable_order,
            permutation_config: permutation_config.into(),
            _marker: core::marker::PhantomData,
        })
    }

    /// WHIR verifier parameters for a commitment whose stacked polynomial has
    /// the given arity.
    ///
    /// # Errors
    /// Returns a typed error for invalid arithmetic/configuration or an
    /// unsupported saturating STIR query phase.
    pub fn round_params<EF, Ch>(
        &self,
        stacked_num_variables: usize,
    ) -> Result<WhirVerifierParams<F>, WhirVerifierParamsError>
    where
        EF: ExtensionField<F> + TwoAdicField,
        Ch: FieldChallenger<F> + GrindingChallenger<Witness = F>,
    {
        validate_round_config_inputs(stacked_num_variables, &self.protocol_params)?;
        let config =
            WhirConfig::<EF, F, Ch>::new(stacked_num_variables, self.protocol_params.clone())?;
        WhirVerifierParams::from_config(&config, self.variable_order, self.permutation_config)
    }

    pub const fn protocol_params(&self) -> &ProtocolParameters {
        &self.protocol_params
    }
    pub const fn folding(&self) -> usize {
        self.folding
    }
    pub const fn variable_order(&self) -> VariableOrder {
        self.variable_order
    }
    pub const fn permutation_config(&self) -> PermConfig {
        self.permutation_config
    }
}

#[cfg(test)]
mod validation_tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use p3_circuit::ops::Poseidon2Config;
    use p3_sumcheck::strategy::VariableOrder;
    use p3_whir::parameters::{FoldingFactor, SecurityAssumption};

    use super::*;

    #[test]
    fn nonconstant_folding_is_rejected_without_panicking() {
        let protocol = ProtocolParameters {
            starting_log_inv_rate: 1,
            round_log_inv_rates: Vec::new(),
            folding_factor: FoldingFactor::ConstantFromSecondRound(2, 2),
            soundness_type: SecurityAssumption::CapacityBound,
            security_level: 32,
            pow_bits: 0,
        };
        let result = std::panic::catch_unwind(|| {
            WhirUniVerifierParams::<p3_baby_bear::BabyBear>::new(
                protocol,
                VariableOrder::Prefix,
                Poseidon2Config::BABY_BEAR_D4_W16,
            )
        });
        let result = result.expect("invalid configuration must not panic");
        assert!(matches!(
            result,
            Err(WhirVerifierParamsError::UnsupportedFoldingFactor)
        ));
    }

    #[test]
    fn zero_folding_is_rejected_as_a_typed_error() {
        let protocol = ProtocolParameters {
            starting_log_inv_rate: 1,
            round_log_inv_rates: Vec::new(),
            folding_factor: FoldingFactor::Constant(0),
            soundness_type: SecurityAssumption::CapacityBound,
            security_level: 32,
            pow_bits: 0,
        };
        let result = WhirUniVerifierParams::<p3_baby_bear::BabyBear>::new(
            protocol,
            VariableOrder::Prefix,
            Poseidon2Config::BABY_BEAR_D4_W16,
        );
        assert!(matches!(
            result,
            Err(WhirVerifierParamsError::UnsupportedFoldingFactor)
        ));
    }

    #[test]
    fn suffix_variable_order_is_rejected_for_prefix_stacking() {
        let protocol = ProtocolParameters {
            starting_log_inv_rate: 1,
            round_log_inv_rates: Vec::new(),
            folding_factor: FoldingFactor::Constant(4),
            soundness_type: SecurityAssumption::CapacityBound,
            security_level: 32,
            pow_bits: 0,
        };
        let result = WhirUniVerifierParams::<p3_baby_bear::BabyBear>::new(
            protocol,
            VariableOrder::Suffix,
            Poseidon2Config::BABY_BEAR_D4_W16,
        );
        assert!(matches!(
            result,
            Err(WhirVerifierParamsError::UnsupportedVariableOrder {
                variable_order: VariableOrder::Suffix
            })
        ));
    }

    #[test]
    fn round_params_rejects_arity_and_explicit_rate_errors() {
        use p3_field::extension::BinomialExtensionField;

        type Base = p3_baby_bear::BabyBear;
        type Ext = BinomialExtensionField<Base, 4>;
        let protocol = ProtocolParameters {
            starting_log_inv_rate: 1,
            round_log_inv_rates: vec![4, 4],
            folding_factor: FoldingFactor::Constant(4),
            soundness_type: SecurityAssumption::CapacityBound,
            security_level: 32,
            pow_bits: 0,
        };
        let params = WhirUniVerifierParams::<Base>::new(
            protocol,
            VariableOrder::Prefix,
            Poseidon2Config::BABY_BEAR_D4_W16,
        )
        .expect("constructor only validates the scalar fold mode");
        assert!(matches!(
            params.round_params::<Ext, DummyChallenger<Base>>(usize::BITS as usize),
            Err(WhirVerifierParamsError::InvalidStackedArity { .. })
        ));

        let protocol = ProtocolParameters {
            starting_log_inv_rate: 1,
            round_log_inv_rates: vec![4, 4],
            folding_factor: FoldingFactor::Constant(4),
            soundness_type: SecurityAssumption::CapacityBound,
            security_level: 32,
            pow_bits: 0,
        };
        let params = WhirUniVerifierParams::<Base>::new(
            protocol,
            VariableOrder::Prefix,
            Poseidon2Config::BABY_BEAR_D4_W16,
        )
        .expect("constructor only validates the scalar fold mode");
        assert!(matches!(
            params.round_params::<Ext, DummyChallenger<Base>>(12),
            Err(WhirVerifierParamsError::InvalidConfig(_))
        ));
    }
}

/// Zero-sized stand-in for `WhirConfig`'s challenger type parameter, which the
/// verifier-side configuration never uses.
#[derive(Clone, Debug, Default)]
pub struct DummyChallenger<F>(core::marker::PhantomData<F>);

impl<F: p3_field::Field> p3_challenger::CanObserve<F> for DummyChallenger<F> {
    fn observe(&mut self, _value: F) {
        unreachable!("DummyChallenger only satisfies WhirConfig's phantom bound")
    }
}
impl<F: p3_field::Field> p3_challenger::CanSample<F> for DummyChallenger<F> {
    fn sample(&mut self) -> F {
        unreachable!("DummyChallenger only satisfies WhirConfig's phantom bound")
    }
}
impl<F: p3_field::Field> p3_challenger::CanSampleBits<usize> for DummyChallenger<F> {
    fn sample_bits(&mut self, _bits: usize) -> usize {
        unreachable!("DummyChallenger only satisfies WhirConfig's phantom bound")
    }
}
impl<F: p3_field::Field> p3_challenger::GrindingChallenger for DummyChallenger<F> {
    type Witness = F;
    fn grind(&mut self, _bits: usize) -> Self::Witness {
        unreachable!("DummyChallenger only satisfies WhirConfig's phantom bound")
    }
}
impl<F: p3_field::PrimeField64> p3_challenger::FieldChallenger<F> for DummyChallenger<F> {}

/// WHIR carries no per-query input-proof object, so the trait's `InputProof`
/// slot is filled by the unit type.
impl<F: p3_field::Field> Recursive<F> for () {
    type Input = ();

    fn new(_circuit: &mut CircuitBuilder<F>, _input: &Self::Input) -> Self {}

    fn get_values(_input: &Self::Input) -> Vec<F> {
        Vec::new()
    }
}

/// No WHIR variant in this adapter splits off random codewords.
const NO_RANDOM_OPENED_VALUES: &[Vec<Vec<Vec<Target>>>] = &[];

impl<SC, Dft, MT, Comm, L, const DIGEST_ELEMS: usize>
    RecursivePcs<
        SC,
        (),
        WhirUniProofTargets<Val<SC>, SC::Challenge, MT, DIGEST_ELEMS>,
        Comm,
        TwoAdicMultiplicativeCoset<Val<SC>>,
    > for WhirUniPcs<SC::Challenge, Val<SC>, Dft, MT, SC::Challenger, L>
where
    SC: StarkGenericConfig,
    Val<SC>: TwoAdicField + PrimeField64 + Ord,
    SC::Challenge: TwoAdicField + ExtensionField<Val<SC>>,
    Dft: TwoAdicSubgroupDft<Val<SC>> + Clone,
    MT: Mmcs<Val<SC>, Commitment = MerkleCap<Val<SC>, [Val<SC>; DIGEST_ELEMS]>> + Clone,
    Comm: Recursive<SC::Challenge> + ObservableCommitment,
    L: Layout<Val<SC>, SC::Challenge>,
{
    type VerifierParams = WhirUniVerifierParams<Val<SC>>;
    type RecursiveProof = WhirUniProofTargets<Val<SC>, SC::Challenge, MT, DIGEST_ELEMS>;

    /// WHIR's native `verify_at` interleaves per-commitment OOD sampling with its
    /// own opened-value observation (see `verify_whir_uni_circuit`/`build_round_claims`),
    /// so the generic caller must not pre-observe opened values on WHIR's behalf.
    const PRE_OBSERVES_OPENED_VALUES: bool = false;

    /// WHIR interleaves every challenge with a proof observation, so all of them
    /// are sampled inside [`Self::verify_circuit`]; nothing is produced here. This
    /// is correct precisely because [`Self::PRE_OBSERVES_OPENED_VALUES`] is `false`:
    /// the generic caller has not touched the transcript with opened values before
    /// this is called, so there is nothing to compensate for here.
    fn get_challenges_circuit<const WIDTH: usize, const RATE: usize, C: ChallengerPermConfig>(
        _circuit: &mut CircuitBuilder<SC::Challenge>,
        _challenger: &mut CircuitChallenger<WIDTH, RATE, C>,
        _proof_targets: &Self::RecursiveProof,
        _opened_values: &OpenedValuesTargetsWithLookups<SC>,
        _params: &Self::VerifierParams,
    ) -> Result<Vec<Target>, CircuitBuilderError> {
        Ok(Vec::new())
    }

    fn verify_circuit<const WIDTH: usize, const RATE: usize, C: ChallengerPermConfig>(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        _challenges: &[Target],
        challenger: &mut CircuitChallenger<WIDTH, RATE, C>,
        commitments_with_opening_points: &ComsWithOpeningsTargets<
            Comm,
            TwoAdicMultiplicativeCoset<Val<SC>>,
        >,
        opening_proof: &Self::RecursiveProof,
        params: &Self::VerifierParams,
    ) -> Result<Vec<NonPrimitiveOpId>, VerificationError> {
        verify_whir_uni_circuit::<Val<SC>, SC::Challenge, _, Comm>(
            circuit,
            challenger,
            params,
            commitments_with_opening_points,
            &opening_proof.rounds,
        )
    }

    /// Lagrange selectors and the vanishing inverse for a two-adic coset.
    ///
    /// With `u = point / shift` and `Z(u) = u^n - 1` over a domain of `n`
    /// points generated by `g`:
    /// `is_first_row = Z(u)/(u - 1)`, `is_last_row = Z(u)/(u - g^-1)`,
    /// `is_transition = u - g^-1`, `inv_vanishing = 1/Z(u)`.
    fn selectors_at_point_circuit(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        domain: &TwoAdicMultiplicativeCoset<Val<SC>>,
        point: &Target,
    ) -> RecursiveLagrangeSelectors {
        RecursiveLagrangeSelectors::two_adic_at_point(circuit, domain, *point)
    }

    fn evaluate_periodic_columns_at_point_circuit(
        &self,
        circuit: &mut CircuitBuilder<SC::Challenge>,
        domain: &TwoAdicMultiplicativeCoset<Val<SC>>,
        periodic_columns: &[Vec<Val<SC>>],
        point: Target,
    ) -> Result<Vec<Target>, VerificationError> {
        crate::verifier::evaluate_periodic_columns_circuit(circuit, domain, periodic_columns, point)
    }

    fn create_disjoint_domain(
        &self,
        trace_domain: TwoAdicMultiplicativeCoset<Val<SC>>,
        degree: usize,
    ) -> TwoAdicMultiplicativeCoset<Val<SC>> {
        trace_domain.create_disjoint_domain(degree)
    }

    fn split_domains(
        &self,
        trace_domain: &TwoAdicMultiplicativeCoset<Val<SC>>,
        degree: usize,
    ) -> Vec<TwoAdicMultiplicativeCoset<Val<SC>>> {
        trace_domain.split_domains(degree)
    }

    fn log_size(&self, trace_domain: &TwoAdicMultiplicativeCoset<Val<SC>>) -> usize {
        trace_domain.log_size()
    }

    fn first_point(&self, trace_domain: &TwoAdicMultiplicativeCoset<Val<SC>>) -> SC::Challenge {
        SC::Challenge::from(trace_domain.first_point())
    }

    fn get_fri_random_opened_values(_proof: &Self::RecursiveProof) -> &[Vec<Vec<Vec<Target>>>] {
        NO_RANDOM_OPENED_VALUES
    }
}
