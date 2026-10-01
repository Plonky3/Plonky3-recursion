//! Verifier parameters for the WHIR recursive verifier.

use alloc::vec::Vec;
use core::fmt;

use p3_challenger::{FieldChallenger, GrindingChallenger};
use p3_circuit::ops::PermConfig;
use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_sumcheck::strategy::VariableOrder;
use p3_whir::parameters::{RoundConfig, WhirConfig, WhirConfigError};
use p3_whir::transcript::WhirShape;
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
#[derive(Debug, Error)]
pub enum WhirVerifierParamsError {
    /// The supplied protocol parameters cannot derive a WHIR configuration.
    #[error("invalid WHIR configuration: {0}")]
    InvalidConfig(#[from] WhirConfigError),
    /// The recursive adapter requires a nonempty, positive native folding strategy.
    #[error("WHIR recursive verifier requires a positive native folding strategy")]
    UnsupportedFoldingFactor,
    /// Legacy variable-order error retained for source compatibility.
    /// The two current native orders are both supported by the recursive adapter.
    #[error("WHIR stacked univariate adapter cannot use variable order {variable_order:?}")]
    UnsupportedVariableOrder { variable_order: VariableOrder },
    /// The stacked polynomial arity cannot be represented by WHIR's integer geometry.
    #[error("stacked WHIR arity {arity} cannot form an initial domain with rate {rate}")]
    InvalidStackedArity { arity: usize, rate: usize },
    /// A derived round rate would overflow integer arithmetic.
    #[error("WHIR rate arithmetic overflows while deriving round {round}")]
    RateArithmeticOverflow { round: usize },
    /// An adaptive rate policy conflicts with explicit rates or invalid geometry.
    #[error("invalid WHIR rate policy: {0}")]
    InvalidRatePolicy(&'static str),
    /// A caller supplied config that does not match the canonical recursive derivation.
    #[error("WHIR derived configuration is inconsistent in {component}")]
    InconsistentDerivedConfig { component: &'static str },
    /// Legacy saturation error retained for source compatibility.
    ///
    /// Supported unstratified canonical configurations no longer emit this
    /// variant: both native and in-circuit verifiers enumerate the whole
    /// folded domain without challenger draws when the query count saturates.
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
    /// The domain allocates proximity queries to fixed strata, which the in-circuit verifier
    /// does not replay.
    #[error("WHIR recursive verifier does not support stratified query sampling")]
    UnsupportedStratifiedQueries,
}

/// Per-round configuration extracted from a `WhirConfig` for in-circuit use.
///
/// Instances are obtained from the checked [`WhirVerifierParams::round_params`] view. Their fields
/// remain private so callers cannot mutate or destructure the validated round schedule.
///
/// ```compile_fail,E0616
/// use p3_recursion::pcs::whir::WhirRoundParams;
///
/// fn mutate_query_count<F>(params: &mut WhirRoundParams<F>) {
///     params.num_queries = 0;
/// }
/// ```
///
/// ```compile_fail,E0451
/// use p3_recursion::pcs::whir::WhirRoundParams;
///
/// fn destructure_round<F>(params: WhirRoundParams<F>) {
///     let WhirRoundParams { num_queries, .. } = params;
/// }
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhirRoundParams<F> {
    /// Number of out-of-domain evaluation samples for this round.
    ood_samples: usize,
    /// Raw configured number of STIR proximity queries. The proof carries
    /// [`Self::num_query_openings`] rows after capping at the folded domain.
    num_queries: usize,
    /// PoW bits for the after-commitment grinding phase.
    pow_bits: usize,
    /// PoW bits for the folding sumcheck within this round.
    folding_pow_bits: usize,
    /// Number of variables folded from this round's queried codeword. The
    /// sumcheck after this round uses the next fold in the native schedule.
    folding_factor: usize,
    /// Size of the evaluation domain before folding in this round.
    domain_size: usize,
    /// Two-adic generator of the folded evaluation domain (for computing STIR domain points).
    folded_domain_gen: F,
    /// Number of multilinear variables remaining after folding in this round.
    num_variables: usize,
}

/// Verifier parameters for the WHIR recursive verifier.
///
/// Mirrors the verification-relevant subset of `WhirConfig`, stripped of all proving
/// machinery (DFT, Mmcs prover data, phantom types). Carry this alongside the circuit
/// instead of threading the full `WhirConfig<EF, F, Ch>` into the verifier.
///
/// Fields are private so callers must use the checked canonical derivation.
///
/// ```compile_fail
/// use p3_recursion::pcs::whir::WhirVerifierParams;
/// let params: WhirVerifierParams<()> = unimplemented!();
/// let WhirVerifierParams { num_variables, .. } = params;
/// ```
///
/// Arithmetic-only construction is confined to the verifier's private unit-test lane.
///
/// ```compile_fail
/// use p3_recursion::pcs::whir::WhirVerifierParams;
/// let _ = WhirVerifierParams::<()>::unsafe_arithmetic_only_for_tests();
/// ```
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WhirVerifierParams<F> {
    /// Number of multilinear variables in the original polynomial.
    num_variables: usize,
    /// Number of OOD evaluation samples at the initial commitment phase.
    commitment_ood_samples: usize,
    /// PoW bits for the initial folding sumcheck (before any intermediate rounds).
    starting_folding_pow_bits: usize,
    /// Per-round configuration for each intermediate STIR round.
    round_params: Vec<WhirRoundParams<F>>,
    /// Number of variables in the final polynomial sent in the clear.
    final_poly_num_variables: usize,
    /// Raw configured number of STIR queries in the final proximity test.
    /// The proof carries [`Self::final_query_openings`] rows.
    final_queries: usize,
    /// PoW bits for the final STIR query phase.
    final_pow_bits: usize,
    /// Number of sumcheck rounds in the final phase (`0` means no final sumcheck).
    final_sumcheck_rounds: usize,
    /// Number of variables folded to enter the final phase
    /// (= `final_round_config().folding_factor`).
    ///
    /// This is the quantity `WhirVerifier::verify_stir_challenges` uses to size the
    /// final STIR query domain and Merkle leaf width. It is distinct from
    /// `final_sumcheck_rounds`, which counts the plain-sumcheck rounds performed
    /// *after* that fold; the two coincide only for specific arities.
    final_folding_factor: usize,
    /// PoW bits for the final folding sumcheck.
    final_folding_pow_bits: usize,
    /// Folding variable order (Prefix or Suffix).
    variable_order: VariableOrder,
    /// Domain size entering the final phase (= `final_round_config().domain_size`).
    final_domain_size: usize,
    /// Two-adic generator of the final folded domain (= `final_round_config().folded_domain_gen`).
    final_folded_domain_gen: F,
    /// The native WHIR transcript shape, from which the domain-separator seed is derived.
    transcript_shape: WhirTranscriptShape,
    /// Permutation config for mandatory MMCS path verification.
    permutation_config: PermConfig,
}

/// The native [`WhirShape`] a verifier seeds its transcript from, compared structurally.
#[derive(Clone, Debug)]
pub struct WhirTranscriptShape(WhirShape);

impl PartialEq for WhirTranscriptShape {
    fn eq(&self, other: &Self) -> bool {
        // `WhirShape` does not implement `PartialEq`; its debug rendering covers every field.
        alloc::format!("{:?}", self.0) == alloc::format!("{:?}", other.0)
    }
}

impl Eq for WhirTranscriptShape {}

impl WhirTranscriptShape {
    /// The native shape for a WHIR opening of `num_opening_claims` claims.
    #[must_use]
    pub fn for_claims(&self, num_opening_claims: usize) -> WhirShape {
        WhirShape {
            num_opening_claims,
            ..self.0.clone()
        }
    }
}

impl<F: Field> WhirVerifierParams<F> {
    const fn round_config_matches(a: &RoundConfig, b: &RoundConfig) -> bool {
        a.pow_bits == b.pow_bits
            && a.folding_pow_bits == b.folding_pow_bits
            && a.num_queries == b.num_queries
            && a.ood_samples == b.ood_samples
            && a.num_variables == b.num_variables
            && a.folding_factor == b.folding_factor
            && a.log_inv_rate == b.log_inv_rate
            && a.domain_size == b.domain_size
            && a.log_folded_domain_size == b.log_folded_domain_size
    }

    /// Derive verifier params from a concrete `WhirConfig`.
    ///
    /// # Errors
    ///
    /// Returns a typed error for an invalid, noncanonical, stratified, or
    /// otherwise unsupported configuration. Saturated query counts are accepted;
    /// the raw counts and native transcript shape remain unchanged.
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
        crate::pcs::whir::uni::recursive_pcs::validate_round_config_inputs(
            config.num_variables(),
            config.params(),
        )?;
        // `WhirConfig` exposes its derived fields publicly for prover use.
        // Re-derive and compare before touching `final_round_config`, whose
        // unchecked arithmetic assumes those fields are internally coherent.
        let canonical =
            WhirConfig::<EF, F, Ch>::new(config.num_variables(), config.params().clone())?;
        if config.num_variables() != canonical.num_variables()
            || config.folding_schedule() != canonical.folding_schedule()
            || config.commitment_ood_samples() != canonical.commitment_ood_samples()
            || config.starting_folding_pow_bits() != canonical.starting_folding_pow_bits()
            || config.terminal() != canonical.terminal()
            || config.final_sumcheck_rounds() != canonical.final_sumcheck_rounds()
            || config.final_folding_pow_bits() != canonical.final_folding_pow_bits()
            || config.round_parameters().len() != canonical.round_parameters().len()
            || config
                .round_parameters()
                .iter()
                .zip(canonical.round_parameters())
                .any(|(a, b)| !Self::round_config_matches(a, b))
        {
            return Err(WhirVerifierParamsError::InconsistentDerivedConfig {
                component: "derived round schedule",
            });
        }

        // Shape construction uses derived geometry, so inspect domain metadata
        // only after the complete arithmetic schedule has been validated.
        // The claim count is bound per circuit; zero here is replaced when seeding.
        let supplied_shape = WhirShape::new(config, 0);
        let canonical_shape = WhirShape::new(&canonical, 0);
        if supplied_shape.stratified_queries {
            return Err(WhirVerifierParamsError::UnsupportedStratifiedQueries);
        }
        if supplied_shape.domain_id != canonical_shape.domain_id {
            return Err(WhirVerifierParamsError::InconsistentDerivedConfig {
                component: "transcript domain",
            });
        }

        let config = &canonical;
        let n_rounds = config.n_rounds();
        let round_params = (0..n_rounds)
            .map(|i| {
                let rp = &config.round_parameters()[i];
                WhirRoundParams {
                    ood_samples: rp.ood_samples,
                    num_queries: rp.num_queries,
                    pow_bits: rp.pow_bits,
                    folding_pow_bits: rp.folding_pow_bits,
                    folding_factor: rp.folding_factor,
                    domain_size: rp.domain_size,
                    folded_domain_gen: F::two_adic_generator(rp.log_folded_domain_size),
                    num_variables: rp.num_variables,
                }
            })
            .collect();

        let final_round_config = config.final_round_config();
        let terminal = config.terminal();
        Ok(Self {
            num_variables: config.num_variables(),
            commitment_ood_samples: config.commitment_ood_samples(),
            starting_folding_pow_bits: config.starting_folding_pow_bits(),
            round_params,
            final_poly_num_variables: final_round_config.num_variables,
            final_queries: terminal.num_queries,
            final_pow_bits: terminal.pow_bits,
            final_sumcheck_rounds: config.final_sumcheck_rounds(),
            final_folding_factor: final_round_config.folding_factor,
            final_folding_pow_bits: config.final_folding_pow_bits(),
            variable_order,
            final_domain_size: final_round_config.domain_size,
            final_folded_domain_gen: F::two_adic_generator(
                final_round_config.log_folded_domain_size,
            ),
            transcript_shape: WhirTranscriptShape(canonical_shape),
            permutation_config: permutation_config.into(),
        })
    }

    /// Number of intermediate STIR rounds.
    pub const fn n_rounds(&self) -> usize {
        self.round_params.len()
    }

    /// Folding factor of the codeword queried at the given round index.
    ///
    /// - Round `0..n_rounds()`: the factor for that round's queried codeword;
    ///   the following sumcheck uses the next factor.
    /// - Round `n_rounds()`: the folding factor applied to enter the final phase
    ///   (`final_folding_factor`), *not* the final plain-sumcheck length
    ///   (`final_sumcheck_rounds`) — the two are distinct quantities that coincide
    ///   only for specific arities.
    ///
    /// The initial sumcheck uses the first factor, which is also the factor
    /// attached to the first queried codeword.
    pub fn round_folding_factor(&self, round: usize) -> usize {
        if round < self.n_rounds() {
            self.round_params[round].folding_factor
        } else {
            self.final_folding_factor
        }
    }

    pub const fn num_variables(&self) -> usize {
        self.num_variables
    }
    pub const fn commitment_ood_samples(&self) -> usize {
        self.commitment_ood_samples
    }
    pub const fn starting_folding_pow_bits(&self) -> usize {
        self.starting_folding_pow_bits
    }
    pub fn round_params(&self) -> &[WhirRoundParams<F>] {
        &self.round_params
    }
    pub const fn final_poly_num_variables(&self) -> usize {
        self.final_poly_num_variables
    }
    pub const fn final_queries(&self) -> usize {
        self.final_queries
    }
    /// Number of final proof-opening rows, capped by the folded domain size.
    /// [`Self::final_queries`] retains the raw configured count.
    pub const fn final_query_openings(&self) -> usize {
        let folded = self.final_domain_size >> self.final_folding_factor;
        if self.final_queries < folded {
            self.final_queries
        } else {
            folded
        }
    }
    pub const fn final_pow_bits(&self) -> usize {
        self.final_pow_bits
    }
    pub const fn final_sumcheck_rounds(&self) -> usize {
        self.final_sumcheck_rounds
    }
    pub const fn final_folding_factor(&self) -> usize {
        self.final_folding_factor
    }
    pub const fn final_folding_pow_bits(&self) -> usize {
        self.final_folding_pow_bits
    }
    pub const fn variable_order(&self) -> VariableOrder {
        self.variable_order
    }
    pub const fn final_domain_size(&self) -> usize {
        self.final_domain_size
    }
    pub const fn final_folded_domain_gen(&self) -> F {
        self.final_folded_domain_gen
    }
    pub const fn permutation_config(&self) -> PermConfig {
        self.permutation_config
    }
    /// The native WHIR transcript shape these parameters were derived with.
    pub const fn transcript_shape(&self) -> &WhirTranscriptShape {
        &self.transcript_shape
    }
}

impl<F> WhirRoundParams<F> {
    pub const fn ood_samples(&self) -> usize {
        self.ood_samples
    }
    pub const fn num_queries(&self) -> usize {
        self.num_queries
    }
    /// Number of proof-opening rows for this round, capped by its folded
    /// domain size. [`Self::num_queries`] retains the raw configured count.
    pub const fn num_query_openings(&self) -> usize {
        let folded = self.domain_size >> self.folding_factor;
        if self.num_queries < folded {
            self.num_queries
        } else {
            folded
        }
    }
    pub const fn pow_bits(&self) -> usize {
        self.pow_bits
    }
    pub const fn folding_pow_bits(&self) -> usize {
        self.folding_pow_bits
    }
    pub const fn folding_factor(&self) -> usize {
        self.folding_factor
    }
    pub const fn domain_size(&self) -> usize {
        self.domain_size
    }
    pub const fn folded_domain_gen(&self) -> F
    where
        F: Copy,
    {
        self.folded_domain_gen
    }
    pub const fn num_variables(&self) -> usize {
        self.num_variables
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear;
    use p3_commit::Encoder;
    use p3_dft::Radix2DFTSmallBatch;
    use p3_field::extension::BinomialExtensionField;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_sumcheck::layout::{Layout, PrefixProver, SuffixProver};
    use p3_whir::domain::{WhirDomain, WhirQueryPoint};
    use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};

    use super::*;
    use crate::pcs::whir::uni::recursive_pcs::DummyChallenger;

    type BF = BabyBear;
    type EF = BinomialExtensionField<BF, 4>;

    struct TestDomain {
        dft: Radix2DFTSmallBatch<BF>,
        protocol_id: &'static [u8],
        stratified_queries: bool,
    }

    impl TestDomain {
        fn new(protocol_id: &'static [u8], stratified_queries: bool) -> Self {
            Self {
                dft: Radix2DFTSmallBatch::default(),
                protocol_id,
                stratified_queries,
            }
        }
    }

    impl Encoder<BF> for TestDomain {
        fn encode_batch(
            &self,
            message: RowMajorMatrix<BF>,
            log_inv_rate: usize,
        ) -> RowMajorMatrix<BF> {
            self.dft.encode_batch(message, log_inv_rate)
        }

        fn encode_batch_padded(
            &self,
            message: RowMajorMatrix<BF>,
            log_inv_rate: usize,
        ) -> RowMajorMatrix<BF> {
            self.dft.encode_batch_padded(message, log_inv_rate)
        }
    }

    impl WhirDomain<BF, EF> for TestDomain {
        fn protocol_id(&self) -> &'static [u8] {
            self.protocol_id
        }

        fn supports_security_assumption(&self, assumption: SecurityAssumption) -> bool {
            <Radix2DFTSmallBatch<BF> as WhirDomain<BF, EF>>::supports_security_assumption(
                &self.dft, assumption,
            )
        }

        fn stratified_queries(&self) -> bool {
            self.stratified_queries
        }

        fn max_log_domain_size(&self) -> usize {
            <Radix2DFTSmallBatch<BF> as WhirDomain<BF, EF>>::max_log_domain_size(&self.dft)
        }

        fn encode_extension_batch_padded(
            &self,
            message: RowMajorMatrix<EF>,
            log_inv_rate: usize,
        ) -> RowMajorMatrix<EF> {
            self.dft
                .encode_extension_batch_padded(message, log_inv_rate)
        }

        fn query_point(
            &self,
            log_domain_size: usize,
            num_variables: usize,
            index: usize,
        ) -> WhirQueryPoint<BF> {
            <Radix2DFTSmallBatch<BF> as WhirDomain<BF, EF>>::query_point(
                &self.dft,
                log_domain_size,
                num_variables,
                index,
            )
        }
    }

    /// `NUM_VARIABLES = 4` with this schedule has zero intermediate rounds: the
    /// only fold (factor 4) takes the starting domain (32 positions) straight
    /// into the final phase, leaving a folded domain of `32 >> 4 = 2`
    /// positions. `final_queries = 35 >= 2`, so native and in-circuit sampling
    /// enumerate the whole domain with no query-index challenger draws.
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

    fn checked_params(
        config: &WhirConfig<EF, BF, DummyChallenger<BF>>,
    ) -> Result<WhirVerifierParams<BF>, WhirVerifierParamsError> {
        WhirVerifierParams::from_config(
            config,
            PrefixProver::<BF, EF>::variable_order(),
            p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
        )
    }

    #[test]
    fn from_config_rejects_custom_transcript_domain_at_both_geometries() {
        let domain = TestDomain::new(b"custom-domain", false);
        for (num_variables, protocol) in [
            (4, saturating_protocol_params()),
            (12, non_saturating_protocol_params()),
        ] {
            let config = WhirConfig::<EF, BF, DummyChallenger<BF>>::new_with_domain(
                num_variables,
                protocol,
                &domain,
            )
            .expect("native custom-domain config is valid");
            assert!(matches!(
                checked_params(&config),
                Err(WhirVerifierParamsError::InconsistentDerivedConfig {
                    component: "transcript domain"
                })
            ));
        }
    }

    #[test]
    fn from_config_rejects_stratified_queries() {
        let config = WhirConfig::<EF, BF, DummyChallenger<BF>>::new_with_domain(
            4,
            saturating_protocol_params(),
            &TestDomain::new(b"", true),
        )
        .expect("native stratified config is valid");
        assert!(matches!(
            checked_params(&config),
            Err(WhirVerifierParamsError::UnsupportedStratifiedQueries)
        ));
    }

    #[test]
    fn from_config_rejects_stratification_before_custom_domain_identity() {
        let config = WhirConfig::<EF, BF, DummyChallenger<BF>>::new_with_domain(
            12,
            non_saturating_protocol_params(),
            &TestDomain::new(b"custom-domain", true),
        )
        .expect("native custom stratified config is valid");
        assert!(matches!(
            checked_params(&config),
            Err(WhirVerifierParamsError::UnsupportedStratifiedQueries)
        ));
    }

    #[test]
    fn from_config_accepts_canonical_dft_through_new_with_domain() {
        for (num_variables, protocol) in [
            (4, saturating_protocol_params()),
            (12, non_saturating_protocol_params()),
        ] {
            let canonical =
                WhirConfig::<EF, BF, DummyChallenger<BF>>::new(num_variables, protocol.clone())
                    .expect("canonical config is valid");
            let with_domain = WhirConfig::<EF, BF, DummyChallenger<BF>>::new_with_domain(
                num_variables,
                protocol,
                &Radix2DFTSmallBatch::<BF>::default(),
            )
            .expect("native canonical DFT config is valid");
            let expected = checked_params(&canonical).expect("canonical params are supported");
            let actual = checked_params(&with_domain).expect("canonical DFT params are supported");
            assert_eq!(actual, expected);
            assert_eq!(
                actual.transcript_shape(),
                &WhirTranscriptShape(WhirShape::new(&with_domain, 0))
            );
        }
    }

    #[test]
    fn full_parameter_identity_retains_query_grinding_bits() {
        let config =
            WhirConfig::<EF, BF, DummyChallenger<BF>>::new(12, non_saturating_protocol_params())
                .unwrap();
        let retained = WhirVerifierParams::<BF>::from_config(
            &config,
            PrefixProver::<BF, EF>::variable_order(),
            p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
        )
        .unwrap();

        let mut changed_round = retained.clone();
        changed_round.round_params[0].pow_bits += 1;
        assert_ne!(retained, changed_round);
        assert_eq!(
            crate::input_contract::whir::WhirContextParams::from_recursive(&retained),
            crate::input_contract::whir::WhirContextParams::from_recursive(&changed_round),
            "allocation shape intentionally omits query-grinding bits"
        );

        let mut changed_final = retained.clone();
        changed_final.final_pow_bits += 1;
        assert_ne!(retained, changed_final);
        assert_eq!(
            crate::input_contract::whir::WhirContextParams::from_recursive(&retained),
            crate::input_contract::whir::WhirContextParams::from_recursive(&changed_final),
            "allocation shape intentionally omits final query-grinding bits"
        );
    }

    #[test]
    fn from_config_accepts_a_saturating_final_phase_with_raw_identity() {
        let config =
            WhirConfig::<EF, BF, DummyChallenger<BF>>::new(4, saturating_protocol_params())
                .expect("the canonical saturated configuration is valid");
        assert_eq!(
            config.n_rounds(),
            0,
            "this schedule has no intermediate rounds"
        );

        let retained = WhirVerifierParams::<BF>::from_config(
            &config,
            PrefixProver::<BF, EF>::variable_order(),
            p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
        )
        .expect("final_queries=35 opens both folded-domain positions");

        assert_eq!(retained.final_queries(), 35);
        assert_eq!(retained.final_query_openings(), 2);
        let mut changed_raw_count = retained.clone();
        changed_raw_count.final_queries += 1;
        assert_eq!(changed_raw_count.final_query_openings(), 2);
        assert_ne!(retained, changed_raw_count);
        assert_ne!(
            crate::input_contract::whir::WhirContextParams::from_recursive(&retained),
            crate::input_contract::whir::WhirContextParams::from_recursive(&changed_raw_count),
            "equal opening cardinality must not erase the raw authority count"
        );
        assert_eq!(
            crate::input_contract::whir::WhirContextParams::from_recursive(&retained),
            crate::input_contract::whir::WhirContextParams::from_native(&config),
            "canonical context retains the raw query count"
        );
        assert_eq!(
            retained.transcript_shape(),
            &WhirTranscriptShape(WhirShape::new(&config, 0)),
            "transcript seeding retains the native shape"
        );
    }

    #[test]
    fn equality_saturated_intermediate_and_greater_final_keep_raw_counts() {
        let protocol = ProtocolParameters {
            security_level: 106,
            pow_bits: 0,
            round_log_inv_rates: vec![1],
            folding_factor: FoldingFactor::Constant(4),
            soundness_type: SecurityAssumption::UniqueDecoding,
            starting_log_inv_rate: 1,
        };
        let config = WhirConfig::<EF, BF, DummyChallenger<BF>>::new(11, protocol).unwrap();
        let retained = WhirVerifierParams::<BF>::from_config(
            &config,
            PrefixProver::<BF, EF>::variable_order(),
            p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
        )
        .unwrap();
        assert_eq!(retained.n_rounds(), 1);
        let round = &retained.round_params()[0];
        assert_eq!(round.domain_size() >> round.folding_factor(), 256);
        assert_eq!(round.num_queries(), 256);
        assert_eq!(round.num_query_openings(), 256);
        assert_eq!(
            retained.final_domain_size() >> retained.final_folding_factor(),
            16
        );
        assert_eq!(retained.final_queries(), 256);
        assert_eq!(retained.final_query_openings(), 16);
        assert_eq!(
            crate::input_contract::whir::WhirContextParams::from_recursive(&retained),
            crate::input_contract::whir::WhirContextParams::from_native(&config)
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

    #[test]
    fn from_config_accepts_canonical_suffix_metadata() {
        let config =
            WhirConfig::<EF, BF, DummyChallenger<BF>>::new(12, non_saturating_protocol_params())
                .expect("canonical native configuration is valid");
        let params = WhirVerifierParams::<BF>::from_config(
            &config,
            SuffixProver::<BF, EF>::variable_order(),
            p3_circuit::ops::Poseidon2Config::BABY_BEAR_D4_W16,
        )
        .expect("canonical Suffix metadata is supported by the low-level verifier");

        assert_eq!(params.variable_order(), VariableOrder::Suffix);
        assert_eq!(params.n_rounds(), config.n_rounds());
        assert_eq!(params.final_queries(), config.terminal().num_queries);
        assert_eq!(
            params.final_domain_size(),
            config.final_round_config().domain_size
        );
        assert_eq!(
            params.transcript_shape(),
            &WhirTranscriptShape(WhirShape::new(&config, 0))
        );
    }
}
