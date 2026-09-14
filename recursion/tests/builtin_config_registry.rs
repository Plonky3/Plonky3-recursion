use alloc::vec;

extern crate alloc;

use p3_recursion::VerifierLimits;
use p3_recursion::builtin_config::{
    BuiltinConfigDescriptorV1, BuiltinConfigError, FriConfigV1, SuiteIdV1, WhirConfigV1,
    WhirRateModeV1, WhirSecurityAssumptionV1,
};

const SUITES: &[(u16, SuiteIdV1)] = &[
    (0x0101, SuiteIdV1::BabyBearD4Poseidon2BinaryFri),
    (0x0102, SuiteIdV1::BabyBearD4Poseidon1BinaryFri),
    (0x0103, SuiteIdV1::KoalaBearD4Poseidon2BinaryFri),
    (0x0104, SuiteIdV1::KoalaBearD4Poseidon1BinaryFri),
    (0x0105, SuiteIdV1::GoldilocksD2Poseidon2BinaryFri),
    (0x0106, SuiteIdV1::GoldilocksD2Poseidon1BinaryFri),
    (0x0107, SuiteIdV1::KoalaBearD5Poseidon2BinaryFri),
    (0x0108, SuiteIdV1::KoalaBearD5Poseidon1BinaryFri),
    (0x0201, SuiteIdV1::BabyBearD4Poseidon2QuaternaryFri),
    (0x0202, SuiteIdV1::KoalaBearD4Poseidon2QuaternaryFri),
    (0x0203, SuiteIdV1::GoldilocksD2Poseidon2QuaternaryFri),
    (0x0204, SuiteIdV1::KoalaBearD5Poseidon2QuaternaryFri),
    (0x0301, SuiteIdV1::BabyBearD4Poseidon2RandomCodewordFri),
    (0x0302, SuiteIdV1::BabyBearD4Poseidon1RandomCodewordFri),
    (0x0303, SuiteIdV1::KoalaBearD4Poseidon2RandomCodewordFri),
    (0x0304, SuiteIdV1::KoalaBearD4Poseidon1RandomCodewordFri),
    (0x0305, SuiteIdV1::GoldilocksD2Poseidon2RandomCodewordFri),
    (0x0306, SuiteIdV1::GoldilocksD2Poseidon1RandomCodewordFri),
    (0x0401, SuiteIdV1::KoalaBearD4Poseidon2SaltedFri),
    (0x0501, SuiteIdV1::BabyBearD4Poseidon2Whir),
    (0x0502, SuiteIdV1::KoalaBearD4Poseidon2Whir),
];

const fn ordinary_fri(suite: SuiteIdV1) -> FriConfigV1 {
    FriConfigV1::new(suite, 1, 0, 2, 2, 0, 0, 3, 3, 0, 0)
}

#[test]
fn suite_ids_are_closed_and_stable() {
    assert_eq!(SuiteIdV1::ALL.len(), SUITES.len());
    for &(raw, suite) in SUITES {
        assert_eq!(suite.as_u16(), raw);
        assert_eq!(SuiteIdV1::from_u16(raw), Ok(suite));
    }
    assert_eq!(
        SuiteIdV1::from_u16(0),
        Err(BuiltinConfigError::UnsupportedSuite(0))
    );
    assert_eq!(
        SuiteIdV1::from_u16(0x0307),
        Err(BuiltinConfigError::UnsupportedSuite(0x0307))
    );
}

#[test]
fn exact_concrete_matrix_does_not_admit_unsupported_products() {
    for &(_, suite) in SUITES {
        let spec = suite.spec();
        if spec.merkle_arity == 4 {
            assert!(spec.is_ordinary_fri());
            assert!(spec.is_poseidon2());
        }
        if spec.extension_degree == 5 {
            assert!(!spec.is_hiding());
        }
        if spec.is_salted() {
            assert_eq!(suite, SuiteIdV1::KoalaBearD4Poseidon2SaltedFri);
            assert_eq!(spec.salt_elements, 4);
        }
    }
}

#[test]
fn fri_descriptor_rejects_family_and_hiding_mismatches() {
    let limits = VerifierLimits::default();
    let whir_as_fri = ordinary_fri(SuiteIdV1::BabyBearD4Poseidon2Whir);
    assert!(matches!(
        BuiltinConfigDescriptorV1::Fri(whir_as_fri).validate(&limits),
        Err(BuiltinConfigError::DescriptorFamilyMismatch { .. })
    ));

    let ordinary_with_randomness = FriConfigV1::new(
        SuiteIdV1::BabyBearD4Poseidon2BinaryFri,
        1,
        0,
        2,
        2,
        0,
        0,
        3,
        3,
        2,
        0,
    );
    assert!(matches!(
        BuiltinConfigDescriptorV1::Fri(ordinary_with_randomness).validate(&limits),
        Err(BuiltinConfigError::InvalidParameter {
            component: "num_random_codewords",
            ..
        })
    ));

    let hiding_without_randomness = FriConfigV1::new(
        SuiteIdV1::BabyBearD4Poseidon2RandomCodewordFri,
        1,
        0,
        2,
        2,
        0,
        0,
        3,
        3,
        0,
        0,
    );
    assert!(matches!(
        BuiltinConfigDescriptorV1::Fri(hiding_without_randomness).validate(&limits),
        Err(BuiltinConfigError::InvalidParameter {
            component: "num_random_codewords",
            ..
        })
    ));
}

#[test]
fn fri_descriptor_rejects_invalid_scalars_before_native_construction() {
    let limits = VerifierLimits::default();
    let zero_queries = FriConfigV1::new(
        SuiteIdV1::GoldilocksD2Poseidon2BinaryFri,
        1,
        0,
        2,
        0,
        0,
        0,
        3,
        3,
        0,
        0,
    );
    assert!(matches!(
        BuiltinConfigDescriptorV1::Fri(zero_queries).validate(&limits),
        Err(BuiltinConfigError::NativeFri(_))
    ));

    let excessive_cap = FriConfigV1::new(
        SuiteIdV1::BabyBearD4Poseidon2QuaternaryFri,
        1,
        0,
        2,
        2,
        0,
        0,
        9,
        3,
        0,
        0,
    );
    let tiny = VerifierLimits {
        max_cap_roots: 1 << 17,
        ..limits
    };
    assert!(matches!(
        BuiltinConfigDescriptorV1::Fri(excessive_cap).validate(&tiny),
        Err(BuiltinConfigError::LimitExceeded {
            component: "input cap roots",
            actual: 262_144,
            limit: 131_072,
        })
    ));
}

#[test]
fn whir_descriptor_distinguishes_auto_and_explicit_rates() {
    let limits = VerifierLimits::default();
    let auto = WhirConfigV1::new(
        SuiteIdV1::BabyBearD4Poseidon2Whir,
        1,
        WhirRateModeV1::Auto,
        4,
        1,
        32,
        0,
        20,
        0,
    );
    let explicit = WhirConfigV1::new(
        SuiteIdV1::BabyBearD4Poseidon2Whir,
        1,
        WhirRateModeV1::Explicit(vec![1, 2]),
        4,
        1,
        32,
        0,
        20,
        0,
    );
    assert_ne!(auto, explicit);
    BuiltinConfigDescriptorV1::Whir(auto)
        .validate(&limits)
        .unwrap();
    BuiltinConfigDescriptorV1::Whir(explicit)
        .validate(&limits)
        .unwrap();

    let empty_explicit = WhirConfigV1::new(
        SuiteIdV1::BabyBearD4Poseidon2Whir,
        1,
        WhirRateModeV1::Explicit(vec![]),
        4,
        1,
        32,
        0,
        20,
        0,
    );
    assert!(matches!(
        BuiltinConfigDescriptorV1::Whir(empty_explicit).validate(&limits),
        Err(BuiltinConfigError::InvalidParameter {
            component: "round_log_inv_rates",
            ..
        })
    ));

    for invalid in [
        WhirConfigV1::new(
            SuiteIdV1::BabyBearD4Poseidon2Whir,
            0,
            WhirRateModeV1::Auto,
            4,
            1,
            32,
            0,
            20,
            0,
        ),
        WhirConfigV1::new(
            SuiteIdV1::BabyBearD4Poseidon2Whir,
            1,
            WhirRateModeV1::Explicit(vec![1, 0]),
            4,
            1,
            32,
            0,
            20,
            0,
        ),
        WhirConfigV1::new(
            SuiteIdV1::BabyBearD4Poseidon2Whir,
            1,
            WhirRateModeV1::Auto,
            4,
            1,
            32,
            31,
            20,
            0,
        ),
    ] {
        assert!(matches!(
            BuiltinConfigDescriptorV1::Whir(invalid).validate(&limits),
            Err(BuiltinConfigError::InvalidParameter { .. })
        ));
    }
}

#[test]
fn whir_security_assumption_ids_are_closed_and_not_normalized() {
    assert_eq!(
        WhirSecurityAssumptionV1::from_u16(1),
        Ok(WhirSecurityAssumptionV1::CapacityBound)
    );
    assert_eq!(
        WhirSecurityAssumptionV1::from_u16(2),
        Ok(WhirSecurityAssumptionV1::UniqueDecoding)
    );
    assert_eq!(
        WhirSecurityAssumptionV1::from_u16(3),
        Err(BuiltinConfigError::UnsupportedSecurityAssumption(3))
    );

    let unique = WhirConfigV1::new(
        SuiteIdV1::BabyBearD4Poseidon2Whir,
        8,
        WhirRateModeV1::Auto,
        8,
        WhirSecurityAssumptionV1::UniqueDecoding.as_u16(),
        124,
        24,
        20,
        0,
    );
    unique.validate(&VerifierLimits::default()).unwrap();
}
