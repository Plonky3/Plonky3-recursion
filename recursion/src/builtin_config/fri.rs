use p3_baby_bear::{
    BabyBear, Poseidon1BabyBear, Poseidon2BabyBear, default_babybear_poseidon1_16,
    default_babybear_poseidon2_16, default_babybear_poseidon2_32,
};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::Field;
use p3_field::extension::{BinomialExtensionField, QuinticTrinomialExtensionField};
use p3_fri::{FriParameters, HidingFriPcs, TwoAdicFriPcs};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_koala_bear::{
    KoalaBear, Poseidon1KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon1_16,
    default_koalabear_poseidon2_16, default_koalabear_poseidon2_32,
};
use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::{StarkConfig, StarkGenericConfig};
use rand::rngs::Xoshiro256PlusPlus;
use rand::{CryptoRng, SeedableRng};

use super::{BuiltinConfigError, FriConfigV1, SuiteIdV1};
use crate::pcs::fri::{FriVerifierParams, NativeFriParams};
use crate::verifier::VerifierLimits;

type OrdinaryMmcs<
    F,
    Perm,
    const WIDTH: usize,
    const RATE: usize,
    const DIGEST: usize,
    const ARITY: usize,
> = MerkleTreeMmcs<
    <F as Field>::Packing,
    <F as Field>::Packing,
    PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST>,
    TruncatedPermutation<Perm, ARITY, DIGEST, WIDTH>,
    ARITY,
    DIGEST,
>;

type OrdinaryPcs<
    F,
    EF,
    Perm,
    const WIDTH: usize,
    const RATE: usize,
    const DIGEST: usize,
    const ARITY: usize,
> = TwoAdicFriPcs<
    F,
    Radix2DitParallel<F>,
    OrdinaryMmcs<F, Perm, WIDTH, RATE, DIGEST, ARITY>,
    ExtensionMmcs<F, EF, OrdinaryMmcs<F, Perm, WIDTH, RATE, DIGEST, ARITY>>,
>;

type RandomCodewordPcs<F, EF, Perm, R, const WIDTH: usize, const RATE: usize, const DIGEST: usize> =
    HidingFriPcs<
        F,
        Radix2DitParallel<F>,
        OrdinaryMmcs<F, Perm, WIDTH, RATE, DIGEST, 2>,
        ExtensionMmcs<F, EF, OrdinaryMmcs<F, Perm, WIDTH, RATE, DIGEST, 2>>,
        R,
    >;

type SaltedMmcs<F, Perm, R, const WIDTH: usize, const RATE: usize, const DIGEST: usize> =
    MerkleTreeHidingMmcs<
        <F as Field>::Packing,
        <F as Field>::Packing,
        PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST>,
        TruncatedPermutation<Perm, 2, DIGEST, WIDTH>,
        R,
        2,
        DIGEST,
        4,
    >;

type SaltedPcs<F, EF, Perm, R, const WIDTH: usize, const RATE: usize, const DIGEST: usize> =
    HidingFriPcs<
        F,
        Radix2DitParallel<F>,
        SaltedMmcs<F, Perm, R, WIDTH, RATE, DIGEST>,
        ExtensionMmcs<F, EF, SaltedMmcs<F, Perm, R, WIDTH, RATE, DIGEST>>,
        R,
    >;

/// A native proving config plus the exact validated descriptor retained for export.
#[derive(Clone, Debug)]
pub struct BuiltinFriConfig<SC> {
    config: SC,
    descriptor: FriConfigV1,
    native_fri_params: NativeFriParams,
    fri_verifier_params: FriVerifierParams,
}

impl<SC> BuiltinFriConfig<SC> {
    const fn new(
        config: SC,
        descriptor: FriConfigV1,
        native_fri_params: NativeFriParams,
        fri_verifier_params: FriVerifierParams,
    ) -> Self {
        Self {
            config,
            descriptor,
            native_fri_params,
            fri_verifier_params,
        }
    }

    pub const fn descriptor(&self) -> &FriConfigV1 {
        &self.descriptor
    }

    pub const fn native_fri_params(&self) -> NativeFriParams {
        self.native_fri_params
    }

    pub const fn fri_verifier_params(&self) -> FriVerifierParams {
        self.fri_verifier_params
    }

    pub const fn config(&self) -> &SC {
        &self.config
    }

    pub fn into_inner(self) -> SC {
        self.config
    }
}

impl<SC: StarkGenericConfig> StarkGenericConfig for BuiltinFriConfig<SC> {
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

fn checked_parameters<M>(
    descriptor: &FriConfigV1,
    limits: &VerifierLimits,
    expected: SuiteIdV1,
    mmcs: M,
) -> Result<(FriParameters<M>, NativeFriParams, FriVerifierParams), BuiltinConfigError> {
    if descriptor.suite() != expected {
        return Err(BuiltinConfigError::WrongFactorySuite {
            expected,
            actual: descriptor.suite(),
        });
    }
    descriptor.validate(limits)?;
    let params = FriParameters {
        max_log_arity: descriptor.max_log_arity() as usize,
        log_blowup: descriptor.log_blowup() as usize,
        log_final_poly_len: descriptor.log_final_poly_len() as usize,
        num_queries: descriptor.num_queries() as usize,
        commit_proof_of_work_bits: descriptor.commit_pow_bits() as usize,
        query_proof_of_work_bits: descriptor.query_pow_bits() as usize,
        mmcs,
    };
    let native = match expected.spec().field {
        super::FieldFamilyV1::BabyBear => NativeFriParams::try_from_native::<BabyBear, _>(&params),
        super::FieldFamilyV1::KoalaBear => {
            NativeFriParams::try_from_native::<KoalaBear, _>(&params)
        }
        super::FieldFamilyV1::Goldilocks => {
            NativeFriParams::try_from_native::<Goldilocks, _>(&params)
        }
    }
    .map_err(BuiltinConfigError::NativeFri)?;
    let recursive = FriVerifierParams::try_with_mmcs(
        params.log_blowup,
        params.log_final_poly_len,
        params.commit_proof_of_work_bits,
        params.query_proof_of_work_bits,
        params.num_queries,
        expected.mmcs_permutation(),
    )
    .map_err(BuiltinConfigError::RecursiveFri)?;
    Ok((params, native, recursive))
}

fn validate_factory_descriptor(
    descriptor: &FriConfigV1,
    limits: &VerifierLimits,
    expected: SuiteIdV1,
) -> Result<(), BuiltinConfigError> {
    if descriptor.suite() != expected {
        return Err(BuiltinConfigError::WrongFactorySuite {
            expected,
            actual: descriptor.suite(),
        });
    }
    descriptor.validate(limits)
}

/// Fixed 64-bit generator used only to derive the historical Goldilocks
/// Poseidon2 constants.  It is the algorithm selected by `SmallRng` on the
/// original 64-bit examples, made explicit so 32-bit builds get identical
/// constants.
pub fn fixed_goldilocks_poseidon2_8() -> Poseidon2Goldilocks<8> {
    let mut rng = Xoshiro256PlusPlus::seed_from_u64(1);
    Poseidon2Goldilocks::<8>::new_from_rng_128(&mut rng)
}

/// Width-16 counterpart of [`fixed_goldilocks_poseidon2_8`].
pub fn fixed_goldilocks_poseidon2_16() -> Poseidon2Goldilocks<16> {
    let mut rng = Xoshiro256PlusPlus::seed_from_u64(1);
    Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng)
}

macro_rules! ordinary_factory {
    (
        $alias:ident, $factory:ident, $field:ty, $challenge:ty,
        $challenger_perm:ty, $mmcs_perm:ty,
        $challenger_width:expr, $challenger_rate:expr,
        $mmcs_width:expr, $mmcs_rate:expr, $digest:expr, $arity:expr,
        $suite:expr, $challenger_expr:expr, $mmcs_expr:expr
    ) => {
        pub type $alias = BuiltinFriConfig<
            StarkConfig<
                OrdinaryPcs<
                    $field,
                    $challenge,
                    $mmcs_perm,
                    $mmcs_width,
                    $mmcs_rate,
                    $digest,
                    $arity,
                >,
                $challenge,
                DuplexChallenger<$field, $challenger_perm, $challenger_width, $challenger_rate>,
            >,
        >;

        pub fn $factory(
            descriptor: &FriConfigV1,
            limits: &VerifierLimits,
        ) -> Result<$alias, BuiltinConfigError> {
            validate_factory_descriptor(descriptor, limits, $suite)?;
            let input_perm: $mmcs_perm = $mmcs_expr;
            let input_mmcs: OrdinaryMmcs<
                $field,
                $mmcs_perm,
                $mmcs_width,
                $mmcs_rate,
                $digest,
                $arity,
            > = MerkleTreeMmcs::new(
                PaddingFreeSponge::new(input_perm.clone()),
                TruncatedPermutation::new(input_perm),
                descriptor.input_cap_height() as usize,
            );
            let commit_perm: $mmcs_perm = $mmcs_expr;
            let commit_mmcs: OrdinaryMmcs<
                $field,
                $mmcs_perm,
                $mmcs_width,
                $mmcs_rate,
                $digest,
                $arity,
            > = MerkleTreeMmcs::new(
                PaddingFreeSponge::new(commit_perm.clone()),
                TruncatedPermutation::new(commit_perm),
                descriptor.commit_cap_height() as usize,
            );
            let (fri_params, native, recursive) =
                checked_parameters(descriptor, limits, $suite, ExtensionMmcs::new(commit_mmcs))?;
            let pcs = TwoAdicFriPcs::new(Radix2DitParallel::default(), input_mmcs, fri_params);
            let config = StarkConfig::new(pcs, DuplexChallenger::new($challenger_expr));
            Ok(BuiltinFriConfig::new(
                config,
                *descriptor,
                native,
                recursive,
            ))
        }
    };
}

ordinary_factory!(
    BabyBearD4Poseidon2BinaryConfig, baby_bear_d4_poseidon2_binary,
    BabyBear, BinomialExtensionField<BabyBear, 4>, Poseidon2BabyBear<16>, Poseidon2BabyBear<16>,
    16, 8, 16, 8, 8, 2, SuiteIdV1::BabyBearD4Poseidon2BinaryFri,
    default_babybear_poseidon2_16(), default_babybear_poseidon2_16()
);
ordinary_factory!(
    BabyBearD4Poseidon1BinaryConfig, baby_bear_d4_poseidon1_binary,
    BabyBear, BinomialExtensionField<BabyBear, 4>, Poseidon1BabyBear<16>, Poseidon1BabyBear<16>,
    16, 8, 16, 8, 8, 2, SuiteIdV1::BabyBearD4Poseidon1BinaryFri,
    default_babybear_poseidon1_16(), default_babybear_poseidon1_16()
);
ordinary_factory!(
    KoalaBearD4Poseidon2BinaryConfig, koala_bear_d4_poseidon2_binary,
    KoalaBear, BinomialExtensionField<KoalaBear, 4>, Poseidon2KoalaBear<16>, Poseidon2KoalaBear<16>,
    16, 8, 16, 8, 8, 2, SuiteIdV1::KoalaBearD4Poseidon2BinaryFri,
    default_koalabear_poseidon2_16(), default_koalabear_poseidon2_16()
);
ordinary_factory!(
    KoalaBearD4Poseidon1BinaryConfig, koala_bear_d4_poseidon1_binary,
    KoalaBear, BinomialExtensionField<KoalaBear, 4>, Poseidon1KoalaBear<16>, Poseidon1KoalaBear<16>,
    16, 8, 16, 8, 8, 2, SuiteIdV1::KoalaBearD4Poseidon1BinaryFri,
    default_koalabear_poseidon1_16(), default_koalabear_poseidon1_16()
);
ordinary_factory!(
    GoldilocksD2Poseidon2BinaryConfig, goldilocks_d2_poseidon2_binary,
    Goldilocks, BinomialExtensionField<Goldilocks, 2>, Poseidon2Goldilocks<8>, Poseidon2Goldilocks<8>,
    8, 4, 8, 4, 4, 2, SuiteIdV1::GoldilocksD2Poseidon2BinaryFri,
    fixed_goldilocks_poseidon2_8(), fixed_goldilocks_poseidon2_8()
);
ordinary_factory!(
    GoldilocksD2Poseidon1BinaryConfig, goldilocks_d2_poseidon1_binary,
    Goldilocks, BinomialExtensionField<Goldilocks, 2>, p3_goldilocks::poseidon1::Poseidon1Goldilocks<8>, p3_goldilocks::poseidon1::Poseidon1Goldilocks<8>,
    8, 4, 8, 4, 4, 2, SuiteIdV1::GoldilocksD2Poseidon1BinaryFri,
    p3_goldilocks::poseidon1::default_goldilocks_poseidon1_8(), p3_goldilocks::poseidon1::default_goldilocks_poseidon1_8()
);
ordinary_factory!(
    KoalaBearD5Poseidon2BinaryConfig,
    koala_bear_d5_poseidon2_binary,
    KoalaBear,
    QuinticTrinomialExtensionField<KoalaBear>,
    Poseidon2KoalaBear<16>,
    Poseidon2KoalaBear<16>,
    16,
    8,
    16,
    8,
    8,
    2,
    SuiteIdV1::KoalaBearD5Poseidon2BinaryFri,
    default_koalabear_poseidon2_16(),
    default_koalabear_poseidon2_16()
);
ordinary_factory!(
    KoalaBearD5Poseidon1BinaryConfig,
    koala_bear_d5_poseidon1_binary,
    KoalaBear,
    QuinticTrinomialExtensionField<KoalaBear>,
    Poseidon1KoalaBear<16>,
    Poseidon1KoalaBear<16>,
    16,
    8,
    16,
    8,
    8,
    2,
    SuiteIdV1::KoalaBearD5Poseidon1BinaryFri,
    default_koalabear_poseidon1_16(),
    default_koalabear_poseidon1_16()
);
ordinary_factory!(
    BabyBearD4Poseidon2QuaternaryConfig, baby_bear_d4_poseidon2_quaternary,
    BabyBear, BinomialExtensionField<BabyBear, 4>, Poseidon2BabyBear<16>, Poseidon2BabyBear<32>,
    16, 8, 32, 24, 8, 4, SuiteIdV1::BabyBearD4Poseidon2QuaternaryFri,
    default_babybear_poseidon2_16(), default_babybear_poseidon2_32()
);
ordinary_factory!(
    KoalaBearD4Poseidon2QuaternaryConfig, koala_bear_d4_poseidon2_quaternary,
    KoalaBear, BinomialExtensionField<KoalaBear, 4>, Poseidon2KoalaBear<16>, Poseidon2KoalaBear<32>,
    16, 8, 32, 24, 8, 4, SuiteIdV1::KoalaBearD4Poseidon2QuaternaryFri,
    default_koalabear_poseidon2_16(), default_koalabear_poseidon2_32()
);
ordinary_factory!(
    GoldilocksD2Poseidon2QuaternaryConfig, goldilocks_d2_poseidon2_quaternary,
    Goldilocks, BinomialExtensionField<Goldilocks, 2>, Poseidon2Goldilocks<8>, Poseidon2Goldilocks<16>,
    8, 4, 16, 12, 4, 4, SuiteIdV1::GoldilocksD2Poseidon2QuaternaryFri,
    fixed_goldilocks_poseidon2_8(), fixed_goldilocks_poseidon2_16()
);
ordinary_factory!(
    KoalaBearD5Poseidon2QuaternaryConfig,
    koala_bear_d5_poseidon2_quaternary,
    KoalaBear,
    QuinticTrinomialExtensionField<KoalaBear>,
    Poseidon2KoalaBear<16>,
    Poseidon2KoalaBear<32>,
    16,
    8,
    32,
    24,
    8,
    4,
    SuiteIdV1::KoalaBearD5Poseidon2QuaternaryFri,
    default_koalabear_poseidon2_16(),
    default_koalabear_poseidon2_32()
);

macro_rules! random_codeword_factory {
    (
        $alias:ident, $factory:ident, $field:ty, $challenge:ty, $perm:ty,
        $width:expr, $rate:expr, $digest:expr, $suite:expr, $perm_expr:expr
    ) => {
        pub type $alias<R> = BuiltinFriConfig<
            StarkConfig<
                RandomCodewordPcs<$field, $challenge, $perm, R, $width, $rate, $digest>,
                $challenge,
                DuplexChallenger<$field, $perm, $width, $rate>,
            >,
        >;

        pub fn $factory<R>(
            descriptor: &FriConfigV1,
            limits: &VerifierLimits,
            rng: R,
        ) -> Result<$alias<R>, BuiltinConfigError>
        where
            R: CryptoRng + SeedableRng,
        {
            validate_factory_descriptor(descriptor, limits, $suite)?;
            let input_perm: $perm = $perm_expr;
            let input_mmcs: OrdinaryMmcs<$field, $perm, $width, $rate, $digest, 2> =
                MerkleTreeMmcs::new(
                    PaddingFreeSponge::new(input_perm.clone()),
                    TruncatedPermutation::new(input_perm),
                    descriptor.input_cap_height() as usize,
                );
            let commit_perm: $perm = $perm_expr;
            let commit_mmcs: OrdinaryMmcs<$field, $perm, $width, $rate, $digest, 2> =
                MerkleTreeMmcs::new(
                    PaddingFreeSponge::new(commit_perm.clone()),
                    TruncatedPermutation::new(commit_perm),
                    descriptor.commit_cap_height() as usize,
                );
            let (fri_params, native, recursive) =
                checked_parameters(descriptor, limits, $suite, ExtensionMmcs::new(commit_mmcs))?;
            let pcs = HidingFriPcs::new(
                Radix2DitParallel::default(),
                input_mmcs,
                fri_params,
                descriptor.num_random_codewords() as usize,
                rng,
            );
            let config = StarkConfig::new(pcs, DuplexChallenger::new($perm_expr));
            Ok(BuiltinFriConfig::new(
                config,
                *descriptor,
                native,
                recursive,
            ))
        }
    };
}

random_codeword_factory!(BabyBearD4Poseidon2RandomCodewordConfig, baby_bear_d4_poseidon2_random_codeword, BabyBear, BinomialExtensionField<BabyBear, 4>, Poseidon2BabyBear<16>, 16, 8, 8, SuiteIdV1::BabyBearD4Poseidon2RandomCodewordFri, default_babybear_poseidon2_16());
random_codeword_factory!(BabyBearD4Poseidon1RandomCodewordConfig, baby_bear_d4_poseidon1_random_codeword, BabyBear, BinomialExtensionField<BabyBear, 4>, Poseidon1BabyBear<16>, 16, 8, 8, SuiteIdV1::BabyBearD4Poseidon1RandomCodewordFri, default_babybear_poseidon1_16());
random_codeword_factory!(KoalaBearD4Poseidon2RandomCodewordConfig, koala_bear_d4_poseidon2_random_codeword, KoalaBear, BinomialExtensionField<KoalaBear, 4>, Poseidon2KoalaBear<16>, 16, 8, 8, SuiteIdV1::KoalaBearD4Poseidon2RandomCodewordFri, default_koalabear_poseidon2_16());
random_codeword_factory!(KoalaBearD4Poseidon1RandomCodewordConfig, koala_bear_d4_poseidon1_random_codeword, KoalaBear, BinomialExtensionField<KoalaBear, 4>, Poseidon1KoalaBear<16>, 16, 8, 8, SuiteIdV1::KoalaBearD4Poseidon1RandomCodewordFri, default_koalabear_poseidon1_16());
random_codeword_factory!(GoldilocksD2Poseidon2RandomCodewordConfig, goldilocks_d2_poseidon2_random_codeword, Goldilocks, BinomialExtensionField<Goldilocks, 2>, Poseidon2Goldilocks<8>, 8, 4, 4, SuiteIdV1::GoldilocksD2Poseidon2RandomCodewordFri, fixed_goldilocks_poseidon2_8());
random_codeword_factory!(GoldilocksD2Poseidon1RandomCodewordConfig, goldilocks_d2_poseidon1_random_codeword, Goldilocks, BinomialExtensionField<Goldilocks, 2>, p3_goldilocks::poseidon1::Poseidon1Goldilocks<8>, 8, 4, 4, SuiteIdV1::GoldilocksD2Poseidon1RandomCodewordFri, p3_goldilocks::poseidon1::default_goldilocks_poseidon1_8());

pub type KoalaBearD4Poseidon2SaltedConfig<R> = BuiltinFriConfig<
    StarkConfig<
        SaltedPcs<
            KoalaBear,
            BinomialExtensionField<KoalaBear, 4>,
            Poseidon2KoalaBear<16>,
            R,
            16,
            8,
            8,
        >,
        BinomialExtensionField<KoalaBear, 4>,
        DuplexChallenger<KoalaBear, Poseidon2KoalaBear<16>, 16, 8>,
    >,
>;

pub fn koala_bear_d4_poseidon2_salted<R>(
    descriptor: &FriConfigV1,
    limits: &VerifierLimits,
    input_rng: R,
    commit_rng: R,
    codeword_rng: R,
) -> Result<KoalaBearD4Poseidon2SaltedConfig<R>, BuiltinConfigError>
where
    R: CryptoRng + SeedableRng,
{
    validate_factory_descriptor(descriptor, limits, SuiteIdV1::KoalaBearD4Poseidon2SaltedFri)?;
    let input_perm = default_koalabear_poseidon2_16();
    let input_mmcs: SaltedMmcs<KoalaBear, Poseidon2KoalaBear<16>, R, 16, 8, 8> =
        MerkleTreeHidingMmcs::new(
            PaddingFreeSponge::new(input_perm.clone()),
            TruncatedPermutation::new(input_perm),
            descriptor.input_cap_height() as usize,
            input_rng,
        );
    let commit_perm = default_koalabear_poseidon2_16();
    let commit_mmcs: SaltedMmcs<KoalaBear, Poseidon2KoalaBear<16>, R, 16, 8, 8> =
        MerkleTreeHidingMmcs::new(
            PaddingFreeSponge::new(commit_perm.clone()),
            TruncatedPermutation::new(commit_perm),
            descriptor.commit_cap_height() as usize,
            commit_rng,
        );
    let (fri_params, native, recursive) = checked_parameters(
        descriptor,
        limits,
        SuiteIdV1::KoalaBearD4Poseidon2SaltedFri,
        ExtensionMmcs::new(commit_mmcs),
    )?;
    let pcs = HidingFriPcs::new(
        Radix2DitParallel::default(),
        input_mmcs,
        fri_params,
        descriptor.num_random_codewords() as usize,
        codeword_rng,
    );
    let config = StarkConfig::new(pcs, DuplexChallenger::new(default_koalabear_poseidon2_16()));
    Ok(BuiltinFriConfig::new(
        config,
        *descriptor,
        native,
        recursive,
    ))
}
