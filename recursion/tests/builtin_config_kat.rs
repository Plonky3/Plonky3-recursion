use p3_baby_bear::{
    BabyBear, default_babybear_poseidon1_16, default_babybear_poseidon2_16,
    default_babybear_poseidon2_32,
};
use p3_challenger::{CanObserve, CanSample, DuplexChallenger};
use p3_field::extension::{
    BinomialExtensionField, BinomiallyExtendable, QuinticTrinomialExtensionField,
};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_koala_bear::{
    KoalaBear, default_koalabear_poseidon1_16, default_koalabear_poseidon2_16,
    default_koalabear_poseidon2_32,
};
use p3_recursion::builtin_config::{fixed_goldilocks_poseidon2_8, fixed_goldilocks_poseidon2_16};
use p3_symmetric::{
    CryptographicHasher, CryptographicPermutation, PaddingFreeSponge, Permutation,
    PseudoCompressionFunction, TruncatedPermutation,
};

fn assert_vector<
    F,
    P,
    const WIDTH: usize,
    const RATE: usize,
    const DIGEST: usize,
    const ARITY: usize,
>(
    permutation: P,
    expected_permutation_word: u64,
    expected_digest: [u64; DIGEST],
    expected_compression: [u64; DIGEST],
    expected_sample: u64,
) where
    F: PrimeField64,
    P: CryptographicPermutation<[F; WIDTH]>,
{
    let input = (1..=(RATE + 3)).map(|i| F::from_u64(i as u64));
    let digest: [F; DIGEST] =
        PaddingFreeSponge::<P, WIDTH, RATE, DIGEST>::new(permutation.clone()).hash_iter(input);
    let children: [[F; DIGEST]; ARITY] = core::array::from_fn(|child| {
        core::array::from_fn(|word| F::from_u64((child * DIGEST + word + 1) as u64))
    });
    let compression = TruncatedPermutation::<P, ARITY, DIGEST, WIDTH>::new(permutation.clone())
        .compress(children);
    let mut state = core::array::from_fn(|i| F::from_u64((i + 1) as u64));
    permutation.permute_mut(&mut state);
    let mut challenger = DuplexChallenger::<F, P, WIDTH, RATE>::new(permutation);
    for i in 1..=(RATE + 1) {
        challenger.observe(F::from_u64(i as u64));
    }
    let sample: F = challenger.sample();

    assert_eq!(state[0].as_canonical_u64(), expected_permutation_word);
    assert_eq!(digest.map(|x| x.as_canonical_u64()), expected_digest);
    assert_eq!(
        compression.map(|x| x.as_canonical_u64()),
        expected_compression
    );
    assert_eq!(sample.as_canonical_u64(), expected_sample);
}

#[test]
fn field_moduli_and_extension_bases_are_frozen() {
    assert_eq!(BabyBear::ORDER_U64, 2_013_265_921);
    assert_eq!(KoalaBear::ORDER_U64, 2_130_706_433);
    assert_eq!(Goldilocks::ORDER_U64, 18_446_744_069_414_584_321);

    type BabyD4 = BinomialExtensionField<BabyBear, 4>;
    let baby_x = BabyD4::from_basis_coefficients_slice(&[
        BabyBear::ZERO,
        BabyBear::ONE,
        BabyBear::ZERO,
        BabyBear::ZERO,
    ])
    .unwrap();
    assert_eq!(
        baby_x.exp_u64(4),
        BabyD4::from(<BabyBear as BinomiallyExtendable<4>>::W),
        "BabyBear D4 must use X^4 - W and polynomial coefficient order"
    );

    type KoalaD4 = BinomialExtensionField<KoalaBear, 4>;
    let koala_x = KoalaD4::from_basis_coefficients_slice(&[
        KoalaBear::ZERO,
        KoalaBear::ONE,
        KoalaBear::ZERO,
        KoalaBear::ZERO,
    ])
    .unwrap();
    assert_eq!(
        koala_x.exp_u64(4),
        KoalaD4::from(<KoalaBear as BinomiallyExtendable<4>>::W)
    );

    type GoldilocksD2 = BinomialExtensionField<Goldilocks, 2>;
    let goldilocks_x =
        GoldilocksD2::from_basis_coefficients_slice(&[Goldilocks::ZERO, Goldilocks::ONE]).unwrap();
    assert_eq!(
        goldilocks_x.square(),
        GoldilocksD2::from(<Goldilocks as BinomiallyExtendable<2>>::W)
    );

    type KoalaD5 = QuinticTrinomialExtensionField<KoalaBear>;
    let quintic_x = KoalaD5::from_basis_coefficients_slice(&[
        KoalaBear::ZERO,
        KoalaBear::ONE,
        KoalaBear::ZERO,
        KoalaBear::ZERO,
        KoalaBear::ZERO,
    ])
    .unwrap();
    assert_eq!(
        quintic_x.exp_u64(5) + quintic_x.square() - KoalaD5::ONE,
        KoalaD5::ZERO,
        "KoalaBear D5 must use X^5 + X^2 - 1"
    );
}

#[test]
fn narrow_poseidon_families_match_frozen_hash_compressor_and_challenger_vectors() {
    assert_vector::<BabyBear, _, 16, 8, 8, 2>(
        default_babybear_poseidon2_16(),
        1_673_702_100,
        [
            1_670_998_194,
            97_925_284,
            536_245_453,
            1_689_441_993,
            651_837_075,
            803_422_730,
            762_384_540,
            1_021_844_394,
        ],
        [
            1_673_702_100,
            1_525_859_233,
            120_947_562,
            429_360_967,
            1_845_930_427,
            111_235_020,
            438_992_764,
            1_404_408_233,
        ],
        1_088_010_576,
    );
    assert_vector::<BabyBear, _, 16, 8, 8, 2>(
        default_babybear_poseidon1_16(),
        555_887_718,
        [
            1_390_108_123,
            540_914_276,
            3_163_188,
            266_103_529,
            783_302_415,
            1_657_278_534,
            722_312_893,
            626_722_115,
        ],
        [
            555_887_718,
            709_050_535,
            1_743_933_514,
            141_310_783,
            895_796_432,
            340_821_787,
            481_253_967,
            221_230_164,
        ],
        1_406_343_734,
    );
    assert_vector::<KoalaBear, _, 16, 8, 8, 2>(
        default_koalabear_poseidon2_16(),
        1_371_112_431,
        [
            1_375_499_794,
            1_977_980_754,
            1_599_317_483,
            2_056_148_463,
            876_340_052,
            2_123_569_515,
            415_199_660,
            1_574_153_159,
        ],
        [
            1_371_112_431,
            1_393_558_871,
            1_976_442_961,
            1_730_918_830,
            749_302_612,
            2_033_925_358,
            1_522_282_530,
            1_526_670_208,
        ],
        299_343_847,
    );
    assert_vector::<KoalaBear, _, 16, 8, 8, 2>(
        default_koalabear_poseidon1_16(),
        1_640_793_454,
        [
            248_286_362,
            1_286_780_054,
            550_616_734,
            759_223_028,
            566_381_110,
            205_196_569,
            2_062_389_176,
            2_085_523_882,
        ],
        [
            1_640_793_454,
            919_785_438,
            36_293_252,
            714_860_068,
            862_104_602,
            1_947_344_825,
            2_105_735_133,
            1_507_849_093,
        ],
        945_147_877,
    );
    assert_vector::<Goldilocks, _, 8, 4, 4, 2>(
        fixed_goldilocks_poseidon2_8(),
        8_499_393_048_505_452_504,
        [
            6_208_961_760_703_686_687,
            5_198_351_570_359_416_373,
            9_913_865_526_530_530_233,
            1_092_237_744_162_562_897,
        ],
        [
            8_499_393_048_505_452_504,
            3_160_925_028_565_479_735,
            3_473_856_109_740_611_071,
            3_770_715_856_811_795_404,
        ],
        8_293_877_617_351_384_633,
    );
    assert_vector::<Goldilocks, _, 8, 4, 4, 2>(
        p3_goldilocks::poseidon1::default_goldilocks_poseidon1_8(),
        13_086_765_662_296_183_810,
        [
            13_345_868_005_177_966_266,
            7_918_218_744_923_154_514,
            17_154_122_982_064_044_137,
            6_416_229_712_437_590_355,
        ],
        [
            13_086_765_662_296_183_810,
            3_163_312_297_714_113_098,
            6_296_265_531_618_872_013,
            9_231_900_090_062_921_074,
        ],
        9_552_303_614_428_083_036,
    );
}

#[test]
fn quaternary_poseidon2_mmcs_roles_match_frozen_vectors() {
    assert_vector::<BabyBear, _, 32, 24, 8, 4>(
        default_babybear_poseidon2_32(),
        1_453_584_402,
        [
            1_490_381_129,
            713_583_526,
            335_204_750,
            853_038_267,
            1_959_538_314,
            1_518_523_979,
            13_701_854,
            743_965_893,
        ],
        [
            1_453_584_402,
            1_081_738_344,
            424_541_993,
            1_155_298_465,
            778_753_182,
            988_028_318,
            264_720_021,
            1_927_071_491,
        ],
        1_561_858_874,
    );
    assert_vector::<KoalaBear, _, 32, 24, 8, 4>(
        default_koalabear_poseidon2_32(),
        29_313_719,
        [
            769_159_748,
            77_562_612,
            1_915_887_923,
            1_367_280_288,
            128_985_745,
            1_221_506_753,
            1_690_448_145,
            767_386_373,
        ],
        [
            29_313_719,
            1_797_513_943,
            487_628_555,
            1_235_556_310,
            1_489_069_995,
            308_888_157,
            1_092_367_063,
            652_621_418,
        ],
        332_219_136,
    );
    assert_vector::<Goldilocks, _, 16, 12, 4, 4>(
        fixed_goldilocks_poseidon2_16(),
        3_381_012_219_251_852_427,
        [
            11_203_846_859_751_044_909,
            11_086_434_035_707_915_482,
            9_824_908_919_912_683_536,
            12_208_584_776_377_472_044,
        ],
        [
            3_381_012_219_251_852_427,
            11_598_532_846_335_578_457,
            12_788_497_747_214_433_761,
            3_939_403_822_373_541_086,
        ],
        10_082_559_032_868_911_462,
    );
}

#[cfg(target_pointer_width = "64")]
#[test]
fn fixed_goldilocks_poseidon2_matches_the_historical_small_rng_constructors() {
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    let mut rng = SmallRng::seed_from_u64(1);
    let historical = Poseidon2Goldilocks::<8>::new_from_rng_128(&mut rng);
    let input = core::array::from_fn(|i| Goldilocks::from_u64((i + 1) as u64));
    assert_eq!(
        fixed_goldilocks_poseidon2_8().permute(input),
        historical.permute(input)
    );

    let mut rng = SmallRng::seed_from_u64(1);
    let historical = Poseidon2Goldilocks::<16>::new_from_rng_128(&mut rng);
    let input = core::array::from_fn(|i| Goldilocks::from_u64((i + 1) as u64));
    assert_eq!(
        fixed_goldilocks_poseidon2_16().permute(input),
        historical.permute(input)
    );
}
