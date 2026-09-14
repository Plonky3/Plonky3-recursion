use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
use p3_challenger::DuplexChallenger;
use p3_dft::Radix2DFTSmallBatch;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_sumcheck::layout::PrefixProver;
use p3_sumcheck::strategy::VariableOrder;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, StarkGenericConfig};

use super::{BuiltinConfigError, SuiteIdV1, WhirConfigV1};
use crate::pcs::whir::uni::{WhirUniPcs, WhirUniVerifierParams};
use crate::verifier::VerifierLimits;

pub(crate) type WhirMmcs<F, Perm> = MerkleTreeMmcs<
    <F as Field>::Packing,
    <F as Field>::Packing,
    PaddingFreeSponge<Perm, 16, 8, 8>,
    TruncatedPermutation<Perm, 2, 8, 16>,
    2,
    8,
>;

pub(crate) type WhirPcs<F, EF, Perm> = WhirUniPcs<
    EF,
    F,
    Radix2DFTSmallBatch<F>,
    WhirMmcs<F, Perm>,
    DuplexChallenger<F, Perm, 16, 8>,
    PrefixProver<F, EF>,
>;

/// Native WHIR proving config and the sealed recursive-verifier parameters
/// derived from the same exact descriptor.
#[derive(Clone, Debug)]
pub struct BuiltinWhirConfig<SC, F> {
    config: SC,
    descriptor: WhirConfigV1,
    whir_verifier_params: WhirUniVerifierParams<F>,
}

impl<SC, F> BuiltinWhirConfig<SC, F> {
    const fn new(
        config: SC,
        descriptor: WhirConfigV1,
        whir_verifier_params: WhirUniVerifierParams<F>,
    ) -> Self {
        Self {
            config,
            descriptor,
            whir_verifier_params,
        }
    }

    pub const fn descriptor(&self) -> &WhirConfigV1 {
        &self.descriptor
    }

    pub const fn whir_verifier_params(&self) -> &WhirUniVerifierParams<F> {
        &self.whir_verifier_params
    }

    pub const fn config(&self) -> &SC {
        &self.config
    }

    pub fn into_inner(self) -> SC {
        self.config
    }
}

impl<SC: StarkGenericConfig, F: Clone> StarkGenericConfig for BuiltinWhirConfig<SC, F> {
    type Pcs = SC::Pcs;
    type Challenge = SC::Challenge;
    type Challenger = SC::Challenger;

    fn pcs(&self) -> &Self::Pcs {
        self.config.pcs()
    }

    fn initialise_challenger(&self) -> Self::Challenger {
        self.config.initialise_challenger()
    }
}

macro_rules! whir_factory {
    (
        $alias:ident, $factory:ident, $field:ty, $challenge:ty, $perm:ty,
        $suite:expr, $perm_expr:expr
    ) => {
        pub type $alias = BuiltinWhirConfig<
            StarkConfig<
                WhirPcs<$field, $challenge, $perm>,
                $challenge,
                DuplexChallenger<$field, $perm, 16, 8>,
            >,
            $field,
        >;

        pub fn $factory(
            descriptor: &WhirConfigV1,
            limits: &VerifierLimits,
        ) -> Result<$alias, BuiltinConfigError> {
            if descriptor.suite() != $suite {
                return Err(BuiltinConfigError::WrongFactorySuite {
                    expected: $suite,
                    actual: descriptor.suite(),
                });
            }
            descriptor.validate(limits)?;
            let protocol = descriptor.protocol_parameters()?;
            let perm: $perm = $perm_expr;
            let mmcs: WhirMmcs<$field, $perm> = MerkleTreeMmcs::new(
                PaddingFreeSponge::new(perm.clone()),
                TruncatedPermutation::new(perm.clone()),
                descriptor.cap_height() as usize,
            );
            let challenger = DuplexChallenger::new(perm);
            let pcs = WhirUniPcs::new(
                protocol.clone(),
                Radix2DFTSmallBatch::default(),
                mmcs,
                challenger.clone(),
                descriptor.log_max_lde_height() as usize,
            );
            let verifier_params = WhirUniVerifierParams::<$field>::new(
                protocol,
                VariableOrder::Prefix,
                $suite.mmcs_permutation(),
            )
            .map_err(|_| BuiltinConfigError::InvalidWhirConfiguration)?;
            Ok(BuiltinWhirConfig::new(
                StarkConfig::new(pcs, challenger),
                descriptor.clone(),
                verifier_params,
            ))
        }
    };
}

whir_factory!(
    BabyBearD4Poseidon2WhirConfig,
    baby_bear_d4_poseidon2_whir,
    BabyBear,
    BinomialExtensionField<BabyBear, 4>,
    Poseidon2BabyBear<16>,
    SuiteIdV1::BabyBearD4Poseidon2Whir,
    default_babybear_poseidon2_16()
);

whir_factory!(
    KoalaBearD4Poseidon2WhirConfig,
    koala_bear_d4_poseidon2_whir,
    KoalaBear,
    BinomialExtensionField<KoalaBear, 4>,
    Poseidon2KoalaBear<16>,
    SuiteIdV1::KoalaBearD4Poseidon2Whir,
    default_koalabear_poseidon2_16()
);
