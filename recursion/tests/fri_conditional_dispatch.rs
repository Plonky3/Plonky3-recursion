//! Provider-family priority and table-role controls for custom FRI backends.

#[macro_use]
#[path = "common/builtin_fri_lifecycle.rs"]
mod builtin_fri_lifecycle;

use core::any::TypeId;

use p3_baby_bear::BabyBear;
use p3_circuit::ops::{NpoTypeId, Poseidon1Config, Poseidon2Config};
use p3_circuit::test_utils::FibonacciAir;
use p3_circuit_prover::batch_stark_prover::{
    Poseidon1AirBuilderForConfig, Poseidon2AirBuilder, Poseidon2AirBuilderForConfig,
    RecomposeAirBuilder,
};
use p3_circuit_prover::{
    ConstraintProfile, Poseidon1Preprocessor, Poseidon2Preprocessor, Poseidon2SharedPreprocessor,
};
use p3_goldilocks::Goldilocks;
use p3_recursion::backend::fri::{FriRecursionBackendD5, FriRecursionBackendForExt};
use p3_recursion::builtin_config::*;
use p3_recursion::{ChallengerPermConfig, FriRecursionBackend, PcsRecursionBackend};

#[derive(Clone, Copy)]
struct DualFamily {
    p2: Poseidon2Config,
    p1: Poseidon1Config,
}

impl ChallengerPermConfig for DualFamily {
    fn extension_degree(&self) -> usize {
        self.p2.d()
    }

    fn as_poseidon2(&self) -> Option<&Poseidon2Config> {
        Some(&self.p2)
    }

    fn as_poseidon1(&self) -> Option<&Poseidon1Config> {
        Some(&self.p1)
    }
}

#[derive(Clone, Copy)]
struct NoFamily(usize);

impl ChallengerPermConfig for NoFamily {
    fn extension_degree(&self) -> usize {
        self.0
    }
}

macro_rules! output_ids {
    ($backend:expr, $backend_ty:ty, $config:ty, $degree:literal, $asked:expr) => {
        <$backend_ty as PcsRecursionBackend<$config, FibonacciAir, $degree>>::non_primitive_provers(
            &$backend, $asked,
        )
        .iter()
        .map(|p| p.op_type())
        .collect::<Vec<_>>()
    };
}

macro_rules! input_ids {
    ($backend:expr, $backend_ty:ty, $config:ty, $degree:literal, $asked:expr, $manifest:expr) => {
        <$backend_ty as PcsRecursionBackend<$config, FibonacciAir, $degree>>::non_primitive_input_provers(
            &$backend, $asked, $manifest,
        )
        .iter()
        .map(|p| p.op_type())
        .collect::<Vec<_>>()
    };
}

macro_rules! assert_dual_family {
    ($backend:expr, $backend_ty:ty, $config:ty, $degree:literal, $expected:expr, $prep:ty, $air:ty) => {{
        let backend = $backend;
        let expected = $expected;
        type Backend = $backend_ty;
        let prep = <Backend as PcsRecursionBackend<$config, FibonacciAir, $degree>>::non_primitive_preprocessors(&backend);
        assert_eq!(prep[0].as_ref().type_id(), TypeId::of::<$prep>());
        let output = <Backend as PcsRecursionBackend<$config, FibonacciAir, $degree>>::non_primitive_provers(&backend, $degree);
        assert_eq!(
            output.iter().map(|p| p.op_type()).collect::<Vec<_>>(),
            expected
        );
        let input = <Backend as PcsRecursionBackend<$config, FibonacciAir, $degree>>::non_primitive_input_provers(&backend, $degree, &[]);
        assert_eq!(
            input.iter().map(|p| p.op_type()).collect::<Vec<_>>(),
            expected
        );
        let air = <Backend as PcsRecursionBackend<$config, FibonacciAir, $degree>>::non_primitive_air_builders(&backend);
        assert_eq!(air[0].as_ref().type_id(), TypeId::of::<$air>());
        assert_eq!(air.len(), expected.len());
        assert!(
            air[0]
                .try_build(
                    &expected[0],
                    &[],
                    1,
                    air[0].lanes(),
                    ConstraintProfile::Standard
                )
                .is_some()
        );
    }};
}

#[test]
fn dual_family_uses_poseidon2_at_d2_d4_d5() {
    type D2 = FriRecursionBackendForExt<2, 8, 4, DualFamily>;
    type D4 = FriRecursionBackendForExt<4, 16, 8, DualFamily>;
    type D5 = FriRecursionBackendD5<16, 8, DualFamily>;
    let coefficient = NpoTypeId::recompose_with_coeff_lookups();
    let gold_p2 = Poseidon2Config::GOLDILOCKS_D2_W8;
    assert_dual_family!(
        FriRecursionBackend::<8, 4, _>::new(DualFamily {
            p2: gold_p2,
            p1: Poseidon1Config::GOLDILOCKS_D2_W8,
        })
        .for_extension_degree::<2>(),
        D2,
        GoldilocksD2Poseidon2BinaryConfig,
        2,
        vec![
            NpoTypeId::poseidon2_perm(gold_p2.for_shared_challenger_table()),
            coefficient.clone()
        ],
        Poseidon2SharedPreprocessor,
        Poseidon2AirBuilderForConfig<2>
    );
    let baby_p2 = Poseidon2Config::BABY_BEAR_D4_W16;
    assert_dual_family!(
        FriRecursionBackend::<16, 8, _>::new(DualFamily {
            p2: baby_p2,
            p1: Poseidon1Config::BABY_BEAR_D4_W16,
        })
        .for_extension_degree::<4>(),
        D4,
        BabyBearD4Poseidon2BinaryConfig,
        4,
        vec![
            NpoTypeId::poseidon2_perm(baby_p2.for_shared_challenger_table()),
            coefficient.clone()
        ],
        Poseidon2SharedPreprocessor,
        Poseidon2AirBuilderForConfig<4>
    );
    let koala_p2 = Poseidon2Config::KOALA_BEAR_D1_W16;
    assert_dual_family!(
        FriRecursionBackend::<16, 8, _>::new_d5(DualFamily {
            p2: koala_p2,
            p1: Poseidon1Config::KOALA_BEAR_D1_W16,
        }),
        D5,
        KoalaBearD5Poseidon2BinaryConfig,
        5,
        vec![NpoTypeId::poseidon2_perm(koala_p2), coefficient],
        Poseidon2Preprocessor,
        Poseidon2AirBuilder<5>
    );
}

#[test]
fn marked_poseidon1_uses_distinct_challenger_and_ordinary_roles() {
    type Backend = FriRecursionBackendForExt<2, 8, 4, Poseidon1Config>;
    let ordinary = Poseidon1Config::GOLDILOCKS_D2_W8;
    let marked = ordinary.for_challenger();
    let coefficient = NpoTypeId::recompose_with_coeff_lookups();
    for (backend, expected) in [
        (
            FriRecursionBackend::<8, 4, _>::new(marked).for_extension_degree::<2>(),
            vec![
                NpoTypeId::poseidon1_perm(marked),
                NpoTypeId::poseidon1_perm(ordinary),
                coefficient.clone(),
            ],
        ),
        (
            FriRecursionBackend::<8, 4, _>::new(marked)
                .without_shared_challenger_perm_table()
                .for_extension_degree::<2>(),
            vec![NpoTypeId::poseidon1_perm(marked), coefficient],
        ),
    ] {
        let prep = <Backend as PcsRecursionBackend<
            GoldilocksD2Poseidon1BinaryConfig,
            FibonacciAir,
            2,
        >>::non_primitive_preprocessors(&backend);
        assert_eq!(
            prep[0].as_ref().type_id(),
            TypeId::of::<Poseidon1Preprocessor>()
        );
        let output = <Backend as PcsRecursionBackend<
            GoldilocksD2Poseidon1BinaryConfig,
            FibonacciAir,
            2,
        >>::non_primitive_provers(&backend, 2);
        assert_eq!(
            output.iter().map(|p| p.op_type()).collect::<Vec<_>>(),
            expected
        );
        let input = <Backend as PcsRecursionBackend<
            GoldilocksD2Poseidon1BinaryConfig,
            FibonacciAir,
            2,
        >>::non_primitive_input_provers(&backend, 2, &[]);
        assert_eq!(
            input.iter().map(|p| p.op_type()).collect::<Vec<_>>(),
            expected
        );
        let air = <Backend as PcsRecursionBackend<
            GoldilocksD2Poseidon1BinaryConfig,
            FibonacciAir,
            2,
        >>::non_primitive_air_builders(&backend);
        assert_eq!(
            air[0].as_ref().type_id(),
            TypeId::of::<Poseidon1AirBuilderForConfig<2>>()
        );
        assert_eq!(air.len(), expected.len());
        for (builder, id) in air.iter().zip(expected.iter()).take(expected.len() - 1) {
            assert!(
                builder
                    .try_build(id, &[], 1, builder.lanes(), ConstraintProfile::Standard)
                    .is_some()
            );
        }
    }
}

macro_rules! assert_legacy_and_extra {
    ($common:expr, $backend_ty:ty, $config:ty, $degree:literal, $p2:expr, $extra:expr, $other_degree:expr) => {{
        type Backend = $backend_ty;
        let p2 = $p2;
        let extra = $extra;
        let rec = NpoTypeId::recompose_with_coeff_lookups();
        let shared = NpoTypeId::poseidon2_perm(p2.for_shared_challenger_table());
        let challenger = NpoTypeId::poseidon2_perm(p2.for_challenger());
        let ordinary = NpoTypeId::poseidon2_perm(p2);
        let extra_id = NpoTypeId::poseidon2_perm(extra);
        let common = $common
            .with_extra_poseidon2_table(extra)
            .with_extra_poseidon2_table(extra)
            .with_extra_poseidon2_table(p2)
            .with_extra_poseidon2_table($other_degree);
        for share in [true, false] {
            let selected = if share {
                common.clone()
            } else {
                common.clone().without_shared_challenger_perm_table()
            };
            let backend = selected.clone().for_extension_degree::<$degree>();
            let output = vec![shared.clone(), extra_id.clone(), rec.clone()];
            assert_eq!(
                output_ids!(backend, $backend_ty, $config, $degree, $degree),
                output
            );
            assert_eq!(
                input_ids!(backend, $backend_ty, $config, $degree, $degree, &[]),
                output
            );
            let legacy = vec![challenger.clone(), ordinary.clone()];
            let mut expected_legacy = vec![challenger.clone()];
            if share {
                expected_legacy.push(ordinary.clone());
            }
            expected_legacy.extend([extra_id.clone(), rec.clone()]);
            assert_eq!(
                input_ids!(backend, $backend_ty, $config, $degree, $degree, &legacy),
                expected_legacy
            );
            let omitted = selected
                .without_extra_poseidon2_input_tables()
                .for_extension_degree::<$degree>();
            assert_eq!(
                output_ids!(omitted, $backend_ty, $config, $degree, $degree),
                output
            );
            assert_eq!(
                input_ids!(omitted, $backend_ty, $config, $degree, $degree, &[]),
                vec![shared.clone(), rec.clone()]
            );
            let mut omitted_legacy = vec![challenger.clone()];
            if share {
                omitted_legacy.push(ordinary.clone());
            }
            omitted_legacy.push(rec.clone());
            assert_eq!(
                input_ids!(omitted, $backend_ty, $config, $degree, $degree, &legacy),
                omitted_legacy
            );
            assert!(output_ids!(backend, $backend_ty, $config, $degree, $degree + 1).is_empty());
            assert!(
                input_ids!(backend, $backend_ty, $config, $degree, $degree + 1, &legacy).is_empty()
            );
            let air = <Backend as PcsRecursionBackend<$config, FibonacciAir, $degree>>::non_primitive_air_builders(&backend);
            assert_eq!(air.len(), 3);
            for (builder, accepted, rejected) in
                [(&air[0], &shared, &extra_id), (&air[1], &extra_id, &shared)]
            {
                assert_eq!(
                    builder.as_ref().type_id(),
                    TypeId::of::<Poseidon2AirBuilderForConfig<$degree>>()
                );
                assert!(
                    builder
                        .try_build(
                            accepted,
                            &[],
                            1,
                            builder.lanes(),
                            ConstraintProfile::Standard
                        )
                        .is_some()
                );
                assert!(
                    builder
                        .try_build(
                            rejected,
                            &[],
                            1,
                            builder.lanes(),
                            ConstraintProfile::Standard
                        )
                        .is_none()
                );
            }
        }
    }};
}

#[test]
fn dual_family_legacy_input_and_extra_policy_remain_ordered() {
    type D2 = FriRecursionBackendForExt<2, 8, 4, DualFamily>;
    type D4 = FriRecursionBackendForExt<4, 16, 8, DualFamily>;
    assert_legacy_and_extra!(
        FriRecursionBackend::<8, 4, _>::new(DualFamily {
            p2: Poseidon2Config::GOLDILOCKS_D2_W8,
            p1: Poseidon1Config::GOLDILOCKS_D2_W8,
        }),
        D2,
        GoldilocksD2Poseidon2BinaryConfig,
        2,
        Poseidon2Config::GOLDILOCKS_D2_W8,
        Poseidon2Config::GOLDILOCKS_D2_W16,
        Poseidon2Config::BABY_BEAR_D4_W16
    );
    assert_legacy_and_extra!(
        FriRecursionBackend::<16, 8, _>::new(DualFamily {
            p2: Poseidon2Config::BABY_BEAR_D4_W16,
            p1: Poseidon1Config::BABY_BEAR_D4_W16,
        }),
        D4,
        BabyBearD4Poseidon2BinaryConfig,
        4,
        Poseidon2Config::BABY_BEAR_D4_W16,
        Poseidon2Config::BABY_BEAR_D4_W24,
        Poseidon2Config::BABY_BEAR_D1_W16
    );
}

macro_rules! assert_none_ext {
    ($degree:literal, $width:literal, $rate:literal, $backend_ty:ty, $config:ty, $extra:expr, $wrong:expr, $other_degree:expr) => {{
        type Backend = $backend_ty;
        let backend = FriRecursionBackend::<$width, $rate, _>::new(NoFamily($degree))
            .for_extension_degree::<$degree>();
        let rec = NpoTypeId::recompose_with_coeff_lookups();
        assert_eq!(
            output_ids!(backend, $backend_ty, $config, $degree, $degree),
            vec![rec.clone()]
        );
        assert_eq!(
            input_ids!(backend, $backend_ty, $config, $degree, $degree, &[]),
            vec![rec.clone()]
        );
        let prep = <Backend as PcsRecursionBackend<$config, FibonacciAir, $degree>>::non_primitive_preprocessors(&backend);
        assert_eq!(
            prep[0].as_ref().type_id(),
            TypeId::of::<Poseidon2Preprocessor>()
        );
        let air = <Backend as PcsRecursionBackend<$config, FibonacciAir, $degree>>::non_primitive_air_builders(&backend);
        assert_eq!(air.len(), 1);
        assert_eq!(
            air[0].as_ref().type_id(),
            TypeId::of::<RecomposeAirBuilder<$degree>>()
        );

        let extra = $extra;
        let extra_id = NpoTypeId::poseidon2_perm(extra);
        let enriched = FriRecursionBackend::<$width, $rate, _>::new(NoFamily($degree))
            .with_extra_poseidon2_table(extra)
            .with_extra_poseidon2_table($other_degree)
            .for_extension_degree::<$degree>();
        assert_eq!(
            output_ids!(enriched, $backend_ty, $config, $degree, $degree),
            vec![extra_id.clone(), rec.clone()]
        );
        assert_eq!(
            input_ids!(enriched, $backend_ty, $config, $degree, $degree, &[]),
            vec![extra_id.clone(), rec.clone()]
        );
        let air = <Backend as PcsRecursionBackend<$config, FibonacciAir, $degree>>::non_primitive_air_builders(&enriched);
        assert_eq!(air.len(), 2);
        assert_eq!(
            air[0].as_ref().type_id(),
            TypeId::of::<Poseidon2AirBuilderForConfig<$degree>>()
        );
        assert!(
            air[0]
                .try_build(&extra_id, &[], 1, 1, ConstraintProfile::Standard)
                .is_some()
        );
        assert!(
            air[0]
                .try_build(
                    &NpoTypeId::poseidon2_perm($wrong),
                    &[],
                    1,
                    1,
                    ConstraintProfile::Standard
                )
                .is_none()
        );
        let omitted = FriRecursionBackend::<$width, $rate, _>::new(NoFamily($degree))
            .with_extra_poseidon2_table(extra)
            .with_extra_poseidon2_table($other_degree)
            .without_extra_poseidon2_input_tables()
            .for_extension_degree::<$degree>();
        assert_eq!(
            input_ids!(omitted, $backend_ty, $config, $degree, $degree, &[]),
            vec![rec.clone()]
        );
        assert!(output_ids!(enriched, $backend_ty, $config, $degree, $degree + 1).is_empty());
        assert!(input_ids!(enriched, $backend_ty, $config, $degree, $degree + 1, &[]).is_empty());
    }};
}

#[test]
fn no_family_preserves_distinct_none_fallbacks_and_matching_extras() {
    type D2 = FriRecursionBackendForExt<2, 8, 4, NoFamily>;
    type D4 = FriRecursionBackendForExt<4, 16, 8, NoFamily>;
    type D5 = FriRecursionBackendD5<16, 8, NoFamily>;
    assert_none_ext!(
        2,
        8,
        4,
        D2,
        GoldilocksD2Poseidon2BinaryConfig,
        Poseidon2Config::GOLDILOCKS_D2_W16,
        Poseidon2Config::GOLDILOCKS_D2_W8,
        Poseidon2Config::BABY_BEAR_D4_W16
    );
    assert_none_ext!(
        4,
        16,
        8,
        D4,
        BabyBearD4Poseidon2BinaryConfig,
        Poseidon2Config::BABY_BEAR_D4_W24,
        Poseidon2Config::BABY_BEAR_D4_W16,
        Poseidon2Config::BABY_BEAR_D1_W16
    );
    let rec = NpoTypeId::recompose_with_coeff_lookups();
    let backend = FriRecursionBackend::<16, 8, _>::new_d5(NoFamily(1));
    assert_eq!(
        output_ids!(backend, D5, KoalaBearD5Poseidon2BinaryConfig, 5, 5),
        vec![rec.clone()]
    );
    assert_eq!(
        input_ids!(backend, D5, KoalaBearD5Poseidon2BinaryConfig, 5, 5, &[]),
        vec![rec.clone()]
    );
    let prep = <D5 as PcsRecursionBackend<KoalaBearD5Poseidon2BinaryConfig, FibonacciAir, 5>>::
        non_primitive_preprocessors(&backend);
    assert_eq!(
        prep[0].as_ref().type_id(),
        TypeId::of::<Poseidon2Preprocessor>()
    );
    let air = <D5 as PcsRecursionBackend<KoalaBearD5Poseidon2BinaryConfig, FibonacciAir, 5>>::
        non_primitive_air_builders(&backend);
    assert_eq!(air.len(), 2);
    assert_eq!(
        air[0].as_ref().type_id(),
        TypeId::of::<Poseidon2AirBuilder<5>>()
    );
    let extra = Poseidon2Config::KOALA_BEAR_D1_W16;
    let extra_id = NpoTypeId::poseidon2_perm(extra);
    // The D5 backend is constructed by `new_d5`; keep its special AIR policy visible.
    let enriched = FriRecursionBackend::<16, 8, _>::new_d5(NoFamily(1))
        .with_extra_poseidon2_table(extra)
        .with_extra_poseidon2_table(Poseidon2Config::KOALA_BEAR_D4_W16);
    assert_eq!(
        output_ids!(enriched, D5, KoalaBearD5Poseidon2BinaryConfig, 5, 5),
        vec![extra_id.clone(), rec.clone()]
    );
    assert_eq!(
        input_ids!(enriched, D5, KoalaBearD5Poseidon2BinaryConfig, 5, 5, &[]),
        vec![extra_id.clone(), rec.clone()]
    );
    let air = <D5 as PcsRecursionBackend<KoalaBearD5Poseidon2BinaryConfig, FibonacciAir, 5>>::
        non_primitive_air_builders(&enriched);
    assert_eq!(air.len(), 2);
    assert_eq!(
        air[0].as_ref().type_id(),
        TypeId::of::<Poseidon2AirBuilderForConfig<5>>()
    );
    assert!(
        air[0]
            .try_build(&extra_id, &[], 1, 1, ConstraintProfile::Standard)
            .is_some()
    );
    let omitted = FriRecursionBackend::<16, 8, _>::new_d5(NoFamily(1))
        .with_extra_poseidon2_table(extra)
        .with_extra_poseidon2_table(Poseidon2Config::KOALA_BEAR_D4_W16)
        .without_extra_poseidon2_input_tables();
    assert_eq!(
        input_ids!(omitted, D5, KoalaBearD5Poseidon2BinaryConfig, 5, 5, &[]),
        vec![rec]
    );
    assert!(output_ids!(enriched, D5, KoalaBearD5Poseidon2BinaryConfig, 5, 4).is_empty());
    assert!(input_ids!(enriched, D5, KoalaBearD5Poseidon2BinaryConfig, 5, 4, &[]).is_empty());
}

#[test]
fn poseidon1_marked_d4_plain_d2_and_ordinary_d1_keep_roles() {
    type D2 = FriRecursionBackendForExt<2, 8, 4, Poseidon1Config>;
    type D4 = FriRecursionBackendForExt<4, 16, 8, Poseidon1Config>;
    let rec = NpoTypeId::recompose_with_coeff_lookups();
    let gold = Poseidon1Config::GOLDILOCKS_D2_W8;
    let plain = FriRecursionBackend::<8, 4, _>::new(gold).for_extension_degree::<2>();
    assert_eq!(
        output_ids!(plain, D2, GoldilocksD2Poseidon1BinaryConfig, 2, 2),
        vec![
            NpoTypeId::poseidon1_perm(gold.for_challenger()),
            NpoTypeId::poseidon1_perm(gold),
            rec.clone()
        ]
    );
    let baby = Poseidon1Config::BABY_BEAR_D4_W16;
    for share in [true, false] {
        let base = FriRecursionBackend::<16, 8, _>::new(baby.for_challenger());
        let backend = if share {
            base
        } else {
            base.without_shared_challenger_perm_table()
        }
        .for_extension_degree::<4>();
        let mut expected = vec![NpoTypeId::poseidon1_perm(baby.for_challenger())];
        if share {
            expected.push(NpoTypeId::poseidon1_perm(baby));
        }
        expected.push(rec.clone());
        assert_eq!(
            output_ids!(backend, D4, BabyBearD4Poseidon1BinaryConfig, 4, 4),
            expected
        );
        assert_eq!(
            input_ids!(backend, D4, BabyBearD4Poseidon1BinaryConfig, 4, 4, &[]),
            expected
        );
        let air = <D4 as PcsRecursionBackend<BabyBearD4Poseidon1BinaryConfig, FibonacciAir, 4>>::
            non_primitive_air_builders(&backend);
        assert_eq!(air.len(), expected.len());
        for (builder, accepted) in air.iter().zip(expected.iter()).take(expected.len() - 1) {
            assert_eq!(
                builder.as_ref().type_id(),
                TypeId::of::<Poseidon1AirBuilderForConfig<4>>()
            );
            assert!(
                builder
                    .try_build(accepted, &[], 1, 1, ConstraintProfile::Standard)
                    .is_some()
            );
        }
        if share {
            assert!(
                air[0]
                    .try_build(
                        &NpoTypeId::poseidon1_perm(baby),
                        &[],
                        1,
                        1,
                        ConstraintProfile::Standard
                    )
                    .is_none()
            );
            assert!(
                air[1]
                    .try_build(
                        &NpoTypeId::poseidon1_perm(baby.for_challenger()),
                        &[],
                        1,
                        1,
                        ConstraintProfile::Standard
                    )
                    .is_none()
            );
        }
        assert!(output_ids!(backend, D4, BabyBearD4Poseidon1BinaryConfig, 4, 2).is_empty());
    }
    let ordinary_d1 = Poseidon1Config::KOALA_BEAR_D1_W16;
    let d1 = FriRecursionBackend::<16, 8, _>::new(ordinary_d1).for_extension_degree::<4>();
    type D1Backend = FriRecursionBackendForExt<4, 16, 8, Poseidon1Config>;
    assert_eq!(
        output_ids!(d1, D1Backend, KoalaBearD4Poseidon2BinaryConfig, 4, 4),
        vec![NpoTypeId::poseidon1_perm(ordinary_d1), rec]
    );
}

#[test]
fn poseidon1_with_extra_poseidon2_keeps_existing_air_asymmetry() {
    type Backend = FriRecursionBackendForExt<4, 16, 8, Poseidon1Config>;
    let p1 = Poseidon1Config::BABY_BEAR_D4_W16;
    let extra = Poseidon2Config::BABY_BEAR_D4_W24;
    let backend = FriRecursionBackend::<16, 8, _>::new(p1)
        .with_extra_poseidon2_table(extra)
        .for_extension_degree::<4>();
    let expected = vec![
        NpoTypeId::poseidon1_perm(p1.for_challenger()),
        NpoTypeId::poseidon1_perm(p1),
        NpoTypeId::poseidon2_perm(extra),
        NpoTypeId::recompose_with_coeff_lookups(),
    ];
    assert_eq!(
        output_ids!(backend, Backend, BabyBearD4Poseidon1BinaryConfig, 4, 4),
        expected
    );
    assert_eq!(
        input_ids!(backend, Backend, BabyBearD4Poseidon1BinaryConfig, 4, 4, &[]),
        expected
    );
    let air = <Backend as PcsRecursionBackend<BabyBearD4Poseidon1BinaryConfig, FibonacciAir, 4>>::
        non_primitive_air_builders(&backend);
    assert_eq!(air.len(), 3);
    assert_eq!(
        air[0].as_ref().type_id(),
        TypeId::of::<Poseidon1AirBuilderForConfig<4>>()
    );
    assert_eq!(
        air[1].as_ref().type_id(),
        TypeId::of::<Poseidon1AirBuilderForConfig<4>>()
    );
    assert_eq!(
        air[2].as_ref().type_id(),
        TypeId::of::<RecomposeAirBuilder<4>>()
    );
    let omitted = FriRecursionBackend::<16, 8, _>::new(p1)
        .with_extra_poseidon2_table(extra)
        .without_extra_poseidon2_input_tables()
        .for_extension_degree::<4>();
    assert_eq!(
        input_ids!(omitted, Backend, BabyBearD4Poseidon1BinaryConfig, 4, 4, &[]),
        vec![
            expected[0].clone(),
            expected[1].clone(),
            expected[3].clone()
        ]
    );
}

fri_lifecycle_case!(
    honest_dual_family_baby_p2_d4,
    field: BabyBear,
    wire_bytes: 4,
    config: BabyBearD4Poseidon2BinaryConfig,
    degree: 4,
    suite: SuiteIdV1::BabyBearD4Poseidon2BinaryFri,
    factory: baby_bear_d4_poseidon2_binary,
    backend: FriRecursionBackend::<16, 8, _>::new(DualFamily {
        p2: Poseidon2Config::BABY_BEAR_D4_W16,
        p1: Poseidon1Config::BABY_BEAR_D4_W16,
    }).for_extension_degree::<4>()
);

fri_lifecycle_case!(
    honest_marked_poseidon1_gold_d2,
    field: Goldilocks,
    wire_bytes: 8,
    config: GoldilocksD2Poseidon1BinaryConfig,
    degree: 2,
    suite: SuiteIdV1::GoldilocksD2Poseidon1BinaryFri,
    factory: goldilocks_d2_poseidon1_binary,
    backend: FriRecursionBackend::<8, 4, _>::new(Poseidon1Config::GOLDILOCKS_D2_W8.for_challenger())
        .for_extension_degree::<2>()
);
