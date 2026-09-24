use p3_recursion::VerifierLimits;
use p3_recursion::builtin_config::{
    BuiltinConfigError, FriConfigV1, SuiteIdV1, WhirConfigV1, WhirRateModeV1,
    baby_bear_d4_poseidon1_binary, baby_bear_d4_poseidon1_random_codeword,
    baby_bear_d4_poseidon2_binary, baby_bear_d4_poseidon2_quaternary,
    baby_bear_d4_poseidon2_random_codeword, baby_bear_d4_poseidon2_whir,
    goldilocks_d2_poseidon1_binary, goldilocks_d2_poseidon1_random_codeword,
    goldilocks_d2_poseidon2_binary, goldilocks_d2_poseidon2_quaternary,
    goldilocks_d2_poseidon2_random_codeword, koala_bear_d4_poseidon1_binary,
    koala_bear_d4_poseidon1_random_codeword, koala_bear_d4_poseidon2_binary,
    koala_bear_d4_poseidon2_quaternary, koala_bear_d4_poseidon2_random_codeword,
    koala_bear_d4_poseidon2_salted, koala_bear_d4_poseidon2_whir, koala_bear_d5_poseidon1_binary,
    koala_bear_d5_poseidon2_binary, koala_bear_d5_poseidon2_quaternary,
};
use p3_uni_stark::StarkGenericConfig;
use rand::SeedableRng;
use rand::rngs::StdRng;

const fn descriptor(suite: SuiteIdV1) -> FriConfigV1 {
    let spec = suite.spec();
    FriConfigV1::new(
        suite,
        1,
        0,
        2,
        3,
        4,
        5,
        2,
        1,
        if spec.is_hiding() { 4 } else { 0 },
        spec.salt_elements as u32,
    )
}

#[test]
fn every_ordinary_factory_builds_the_exact_retained_native_parameters() {
    let limits = VerifierLimits::default();
    macro_rules! check {
        ($factory:ident, $suite:expr) => {{
            let descriptor = descriptor($suite);
            let config = $factory(&descriptor, &limits).unwrap();
            assert_eq!(config.descriptor(), &descriptor);
            assert_eq!(config.native_fri_params().log_blowup(), 1);
            assert_eq!(config.native_fri_params().log_final_poly_len(), 0);
            assert_eq!(config.native_fri_params().max_log_arity(), 2);
            assert_eq!(config.native_fri_params().num_queries(), 3);
            assert_eq!(config.native_fri_params().commit_pow_bits(), 4);
            assert_eq!(config.native_fri_params().query_pow_bits(), 5);
            assert_eq!(config.fri_verifier_params().num_queries(), 3);
            assert_eq!(config.is_zk(), 0);
        }};
    }

    check!(
        baby_bear_d4_poseidon2_binary,
        SuiteIdV1::BabyBearD4Poseidon2BinaryFri
    );
    check!(
        baby_bear_d4_poseidon1_binary,
        SuiteIdV1::BabyBearD4Poseidon1BinaryFri
    );
    check!(
        koala_bear_d4_poseidon2_binary,
        SuiteIdV1::KoalaBearD4Poseidon2BinaryFri
    );
    check!(
        koala_bear_d4_poseidon1_binary,
        SuiteIdV1::KoalaBearD4Poseidon1BinaryFri
    );
    check!(
        goldilocks_d2_poseidon2_binary,
        SuiteIdV1::GoldilocksD2Poseidon2BinaryFri
    );
    check!(
        goldilocks_d2_poseidon1_binary,
        SuiteIdV1::GoldilocksD2Poseidon1BinaryFri
    );
    check!(
        koala_bear_d5_poseidon2_binary,
        SuiteIdV1::KoalaBearD5Poseidon2BinaryFri
    );
    check!(
        koala_bear_d5_poseidon1_binary,
        SuiteIdV1::KoalaBearD5Poseidon1BinaryFri
    );
    check!(
        baby_bear_d4_poseidon2_quaternary,
        SuiteIdV1::BabyBearD4Poseidon2QuaternaryFri
    );
    check!(
        koala_bear_d4_poseidon2_quaternary,
        SuiteIdV1::KoalaBearD4Poseidon2QuaternaryFri
    );
    check!(
        goldilocks_d2_poseidon2_quaternary,
        SuiteIdV1::GoldilocksD2Poseidon2QuaternaryFri
    );
    check!(
        koala_bear_d5_poseidon2_quaternary,
        SuiteIdV1::KoalaBearD5Poseidon2QuaternaryFri
    );
}

#[test]
fn a_factory_rejects_a_valid_descriptor_for_another_suite() {
    let descriptor = descriptor(SuiteIdV1::KoalaBearD4Poseidon2BinaryFri);
    assert!(matches!(
        baby_bear_d4_poseidon2_binary(&descriptor, &VerifierLimits::default()),
        Err(BuiltinConfigError::WrongFactorySuite { .. })
    ));
}

#[test]
fn random_codeword_hiding_factories_take_owned_crypto_rngs() {
    let limits = VerifierLimits::default();
    macro_rules! check {
        ($factory:ident, $suite:expr, $seed:expr) => {{
            let descriptor = descriptor($suite);
            let config = $factory(&descriptor, &limits, StdRng::seed_from_u64($seed)).unwrap();
            assert_eq!(config.descriptor(), &descriptor);
            assert_eq!(config.is_zk(), 1);
        }};
    }
    check!(
        baby_bear_d4_poseidon2_random_codeword,
        SuiteIdV1::BabyBearD4Poseidon2RandomCodewordFri,
        1
    );
    check!(
        baby_bear_d4_poseidon1_random_codeword,
        SuiteIdV1::BabyBearD4Poseidon1RandomCodewordFri,
        2
    );
    check!(
        koala_bear_d4_poseidon2_random_codeword,
        SuiteIdV1::KoalaBearD4Poseidon2RandomCodewordFri,
        3
    );
    check!(
        koala_bear_d4_poseidon1_random_codeword,
        SuiteIdV1::KoalaBearD4Poseidon1RandomCodewordFri,
        4
    );
    check!(
        goldilocks_d2_poseidon2_random_codeword,
        SuiteIdV1::GoldilocksD2Poseidon2RandomCodewordFri,
        5
    );
    check!(
        goldilocks_d2_poseidon1_random_codeword,
        SuiteIdV1::GoldilocksD2Poseidon1RandomCodewordFri,
        6
    );
}

#[test]
fn salted_factory_takes_independent_owned_crypto_rngs_for_all_hiding_layers() {
    let descriptor = descriptor(SuiteIdV1::KoalaBearD4Poseidon2SaltedFri);
    let config = koala_bear_d4_poseidon2_salted(
        &descriptor,
        &VerifierLimits::default(),
        StdRng::seed_from_u64(11),
        StdRng::seed_from_u64(12),
        StdRng::seed_from_u64(13),
    )
    .unwrap();
    assert_eq!(config.descriptor(), &descriptor);
    assert_eq!(config.is_zk(), 1);
}

#[test]
fn whir_factories_retain_exact_protocol_modes_and_derive_sealed_verifier_params() {
    let limits = VerifierLimits::default();
    let baby = WhirConfigV1::new(
        SuiteIdV1::BabyBearD4Poseidon2Whir,
        1,
        WhirRateModeV1::Auto,
        4,
        1,
        32,
        0,
        20,
        2,
    );
    let baby_config = baby_bear_d4_poseidon2_whir(&baby, &limits).unwrap();
    assert_eq!(baby_config.descriptor(), &baby);
    assert!(
        baby_config
            .whir_verifier_params()
            .protocol_params()
            .round_log_inv_rates
            .is_empty()
    );
    assert_eq!(baby_config.is_zk(), 0);

    let koala = WhirConfigV1::new(
        SuiteIdV1::KoalaBearD4Poseidon2Whir,
        2,
        WhirRateModeV1::Explicit(vec![1, 2]),
        3,
        1,
        40,
        4,
        18,
        1,
    );
    let koala_config = koala_bear_d4_poseidon2_whir(&koala, &limits).unwrap();
    assert_eq!(koala_config.descriptor(), &koala);
    assert_eq!(
        koala_config
            .whir_verifier_params()
            .protocol_params()
            .round_log_inv_rates,
        [1, 2]
    );
    assert_eq!(koala_config.whir_verifier_params().folding(), 3);
}
