//! Validated released WHIR configurations and sealed native table layouts.
use p3_binary_field::BinaryField128;
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_sumcheck::layout::PrefixProver;
use p3_whir::pcs::WhirProverData;
use p3_whir::{FoldingFactor, ProtocolParameters, WhirConfig, WhirDomain, WhirProver};

use super::*;
use crate::pcs::binary::RecursiveBinaryWhirTowerField;
use crate::verifier::{InputResourceUsage, VerifierLimits};

mod sealed {
    pub trait Layout {}
    impl<F: p3_field::Field> Layout
        for p3_sumcheck::layout::PrefixProver<F, p3_binary_field::BinaryField128>
    where
        p3_binary_field::BinaryField128: p3_field::ExtensionField<F>,
    {
    }
    impl<F: p3_field::Field> Layout
        for p3_sumcheck::layout::SuffixProver<F, p3_binary_field::BinaryField128>
    where
        p3_binary_field::BinaryField128: p3_field::ExtensionField<F>,
    {
    }
}
/// Only the released native PrefixProver and SuffixProver layouts can enter
/// this complete family. Applications cannot supply a custom layout callback.
pub trait BinaryNativeWhirLayout<F>: Layout<F, BinaryField128> + Clone + sealed::Layout
where
    F: p3_field::Field,
    BinaryField128: ExtensionField<F>,
{
}
impl<F: p3_field::Field> BinaryNativeWhirLayout<F> for PrefixProver<F, BinaryField128> where
    BinaryField128: ExtensionField<F>
{
}
impl<F: p3_field::Field> BinaryNativeWhirLayout<F> for SuffixProver<F, BinaryField128> where
    BinaryField128: ExtensionField<F>
{
}

/// A validated additive domain and finite native schedule. The configuration
/// is private so every factory receives constructor-bounded parameter vectors.
#[derive(Clone)]
pub struct BinaryNativeWhirPcsParameters<F: p3_field::Field>
where
    BinaryField128: ExtensionField<F>,
{
    pub(in crate::artifact::binary_native) config:
        WhirConfig<BinaryField128, F, BinaryNativeChallenger<F>>,
    pub(in crate::artifact::binary_native) hash: ByteHash,
    pub(in crate::artifact::binary_native) cap_height: usize,
}
impl<F> BinaryNativeWhirPcsParameters<F>
where
    F: RecursiveBinaryWhirTowerField,
    BinaryField128: ExtensionField<F>,
    BinaryWhirDomain<F>: WhirDomain<F, BinaryField128>,
{
    pub fn new(
        num_variables: usize,
        parameters: ProtocolParameters,
        hash: ByteHash,
        cap_height: usize,
    ) -> Result<Self, VerificationError> {
        Self::with_limits(
            num_variables,
            parameters,
            hash,
            cap_height,
            &VerifierLimits::default(),
        )
    }
    /// Bounds schedule work before invoking the released constructor, then
    /// checks the actual required grinding rather than its nominal ceiling.
    pub fn with_limits(
        num_variables: usize,
        parameters: ProtocolParameters,
        hash: ByteHash,
        cap_height: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        let grind_limit = validate_parameters(
            num_variables,
            &parameters,
            cap_height,
            F::RAW_BITS,
            128,
            limits,
        )?;
        let config = WhirConfig::new_with_domain(
            num_variables,
            parameters,
            &BinaryWhirDomain::<F>::default(),
        )
        .map_err(|_| super::super::invalid("binary native WHIR configuration rejected"))?;
        if config.max_pow_bits() > grind_limit {
            return Err(VerificationError::ResourceLimitExceeded {
                component: "binary native WHIR grinding bits",
                actual: config.max_pow_bits(),
                limit: grind_limit,
            });
        }
        Ok(Self {
            config,
            hash,
            cap_height,
        })
    }
    pub fn configuration(&self) -> &WhirConfig<BinaryField128, F, BinaryNativeChallenger<F>> {
        &self.config
    }
    pub fn hash(&self) -> ByteHash {
        self.hash
    }
    pub fn cap_height(&self) -> usize {
        self.cap_height
    }
}

pub(in crate::artifact::binary_native) type NativeWhirPcs<F, L> =
    WhirProver<BinaryField128, F, BinaryWhirDomain<F>, NativeMmcs<F>, BinaryNativeChallenger<F>, L>;
/// Complete native WHIR configuration, constructed only by its checked owner.
pub struct BinaryNativeWhirConfig<F: p3_field::Field, L = SuffixProver<F, BinaryField128>>
where
    BinaryField128: ExtensionField<F>,
{
    pub(in crate::artifact::binary_native) main: NativeWhirPcs<F, L>,
    pub(in crate::artifact::binary_native) preprocessed: Option<NativeWhirPcs<F, L>>,
}
impl<F, L> MultiStarkConfig for BinaryNativeWhirConfig<F, L>
where
    F: RecursiveBinaryWhirTowerField
        + EncodableLevel
        + FoldAlphabet<BinaryField128>
        + PackedValue<Value = F>
        + Ord,
    BinaryField128: ExtensionField<F> + ChallengeField<F>,
    BinaryWhirDomain<F>: WhirDomain<F, BinaryField128>,
    L: BinaryNativeWhirLayout<F>,
{
    type Val = F;
    type Challenge = BinaryField128;
    type Challenger = BinaryNativeChallenger<F>;
    type Pcs = NativeWhirPcs<F, L>;
    fn pcs(&self) -> &Self::Pcs {
        &self.main
    }
    fn preprocessed_pcs(&self) -> &Self::Pcs {
        self.preprocessed
            .as_ref()
            .expect("validated native WHIR preprocessing")
    }
    fn collision_resistance_bits(&self) -> Option<usize> {
        Some(128)
    }
    fn min_num_variables(&self) -> usize {
        self.main.round_folding_factor(0)
    }
    fn build_witness(&self, tables: Vec<Table<F>>) -> Witness<F> {
        L::new_witness(tables, self.main.round_folding_factor(0))
    }
    fn committed_table<'a>(
        &self,
        data: &'a WhirProverData<F, BinaryField128, NativeMmcs<F>, L>,
        index: usize,
    ) -> &'a Table<F> {
        data.table(index)
    }
}

pub(super) fn validate_parameters(
    num_variables: usize,
    parameters: &ProtocolParameters,
    cap_height: usize,
    base_bits: usize,
    challenge_bits: usize,
    limits: &VerifierLimits,
) -> Result<usize, VerificationError> {
    let invalid = |message: &'static str| VerificationError::InvalidProofShape(message.into());
    let mut usage = InputResourceUsage::default();
    usage.add_rounds(limits, num_variables)?;
    if num_variables == 0 || parameters.starting_log_inv_rate == 0 {
        return Err(invalid(
            "binary native WHIR arity and initial rate must be positive",
        ));
    }
    let domain_bits = num_variables
        .checked_add(parameters.starting_log_inv_rate)
        .ok_or(VerificationError::ResourceArithmeticOverflow {
            component: "binary native WHIR domain",
        })?;
    let bound = limits
        .max_log_domain_or_degree
        .min(usize::BITS as usize - 1);
    if domain_bits > bound {
        return Err(VerificationError::ResourceLimitExceeded {
            component: "binary native WHIR domain bits",
            actual: domain_bits,
            limit: bound,
        });
    }
    if parameters.round_log_inv_rates.len() > num_variables - 1 {
        return Err(invalid(
            "binary native WHIR explicit rate count exceeds arity",
        ));
    }
    let factors = if let FoldingFactor::PerRound(factors) = &parameters.folding_factor {
        if factors.is_empty() || factors.len() > num_variables {
            return Err(invalid(
                "binary native WHIR explicit fold count exceeds arity",
            ));
        }
        factors.len()
    } else {
        0
    };
    usage.add_metadata_entries(limits, parameters.round_log_inv_rates.len())?;
    usage.add_metadata_entries(limits, factors)?;
    let grind_limit = base_bits
        .min(64)
        .saturating_sub(8)
        .min(usize::BITS as usize - 1);
    if parameters.security_level == 0
        || parameters.pow_bits >= parameters.security_level
        || parameters.security_level > challenge_bits - 1 + grind_limit
    {
        return Err(invalid(
            "binary native WHIR security parameters exceed the supported challenge and grinding budget",
        ));
    }
    if cap_height >= usize::BITS as usize || cap_height > domain_bits {
        return Err(invalid("binary native WHIR cap height exceeds its domain"));
    }
    usage.add_cap_roots(limits, 1usize << cap_height)?;
    Ok(grind_limit)
}
