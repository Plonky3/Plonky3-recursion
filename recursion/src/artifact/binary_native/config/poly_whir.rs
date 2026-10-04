//! Closed released polynomial WHIR configuration and native layouts.
use p3_binary_field::{Poly64, Poly192};
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_sumcheck::layout::PrefixProver;
use p3_whir::pcs::WhirProverData;
use p3_whir::{ProtocolParameters, WhirConfig, WhirProver};

use super::*;
use crate::verifier::VerifierLimits;

mod sealed {
    pub trait Layout {}
    impl Layout
        for p3_sumcheck::layout::PrefixProver<p3_binary_field::Poly64, p3_binary_field::Poly192>
    {
    }
    impl Layout
        for p3_sumcheck::layout::SuffixProver<p3_binary_field::Poly64, p3_binary_field::Poly192>
    {
    }
}
/// Only the released prefix and suffix layouts enter this complete family.
pub trait BinaryNativePolyWhirLayout: Layout<Poly64, Poly192> + Clone + sealed::Layout {}
impl BinaryNativePolyWhirLayout for PrefixProver<Poly64, Poly192> {}
impl BinaryNativePolyWhirLayout for SuffixProver<Poly64, Poly192> {}

/// Constructor-bounded, immutable native polynomial WHIR parameters.
#[derive(Clone)]
pub struct BinaryNativePolyWhirPcsParameters {
    pub(in crate::artifact::binary_native) config:
        WhirConfig<Poly192, Poly64, BinaryNativeChallenger<Poly64>>,
    pub(in crate::artifact::binary_native) hash: ByteHash,
    pub(in crate::artifact::binary_native) cap_height: usize,
}
impl BinaryNativePolyWhirPcsParameters {
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
    pub fn with_limits(
        num_variables: usize,
        parameters: ProtocolParameters,
        hash: ByteHash,
        cap_height: usize,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        let grind_limit = super::whir::validate_parameters(
            num_variables,
            &parameters,
            cap_height,
            64,
            192,
            limits,
        )?;
        let config = WhirConfig::new_with_domain(
            num_variables,
            parameters,
            &BinaryWhirDomain::<Poly64>::default(),
        )
        .map_err(|_| {
            super::super::invalid("binary native polynomial WHIR configuration rejected")
        })?;
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
    pub fn configuration(&self) -> &WhirConfig<Poly192, Poly64, BinaryNativeChallenger<Poly64>> {
        &self.config
    }
    pub fn hash(&self) -> ByteHash {
        self.hash
    }
    pub fn cap_height(&self) -> usize {
        self.cap_height
    }
}
pub(in crate::artifact::binary_native) type NativePolyWhirPcs<L> = WhirProver<
    Poly192,
    Poly64,
    BinaryWhirDomain<Poly64>,
    NativeMmcs<Poly64>,
    BinaryNativeChallenger<Poly64>,
    L,
>;
/// Native configuration constructed only by the checked proof owner.
pub struct BinaryNativePolyWhirConfig<L = SuffixProver<Poly64, Poly192>> {
    pub(in crate::artifact::binary_native) main: NativePolyWhirPcs<L>,
    pub(in crate::artifact::binary_native) preprocessed: Option<NativePolyWhirPcs<L>>,
}
impl<L: BinaryNativePolyWhirLayout> MultiStarkConfig for BinaryNativePolyWhirConfig<L> {
    type Val = Poly64;
    type Challenge = Poly192;
    type Challenger = BinaryNativeChallenger<Poly64>;
    type Pcs = NativePolyWhirPcs<L>;
    fn pcs(&self) -> &Self::Pcs {
        &self.main
    }
    fn preprocessed_pcs(&self) -> &Self::Pcs {
        self.preprocessed
            .as_ref()
            .expect("validated native polynomial WHIR preprocessing")
    }
    fn collision_resistance_bits(&self) -> Option<usize> {
        Some(128)
    }
    fn min_num_variables(&self) -> usize {
        self.main.round_folding_factor(0)
    }
    fn build_witness(&self, tables: Vec<Table<Poly64>>) -> Witness<Poly64> {
        L::new_witness(tables, self.main.round_folding_factor(0))
    }
    fn committed_table<'a>(
        &self,
        data: &'a WhirProverData<Poly64, Poly192, NativeMmcs<Poly64>, L>,
        index: usize,
    ) -> &'a Table<Poly64> {
        data.table(index)
    }
}
