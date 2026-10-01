//! Focused provider checks for custom Poseidon1 WHIR recursion backends.

#[path = "common/goldilocks_whir_config.rs"]
mod goldilocks_whir_config;

use core::any::TypeId;

use goldilocks_whir_config::{GoldWhirConfig, gold_whir_config};
use p3_circuit::ops::{NpoTypeId, Poseidon1Config, Poseidon2Config};
use p3_circuit::test_utils::FibonacciAir;
use p3_circuit_prover::batch_stark_prover::{
    Poseidon1AirBuilderForConfig, Poseidon2AirBuilderForConfig,
};
use p3_circuit_prover::{Poseidon1Preprocessor, Poseidon2SharedPreprocessor};
use p3_recursion::backend::whir::{WhirRecursionBackend, WhirRecursionBackendForExt};
use p3_recursion::{ChallengerPermConfig, PcsRecursionBackend};

type GoldP1Backend = WhirRecursionBackendForExt<2, 8, 4, Poseidon1Config>;

#[test]
fn poseidon1_d2_provider_surfaces_use_separate_normalized_tables() {
    let _config = gold_whir_config();
    let backend = WhirRecursionBackend::<8, 4, _>::new(Poseidon1Config::GOLDILOCKS_D2_W8)
        .for_extension_degree::<2>();
    let ordinary = Poseidon1Config::GOLDILOCKS_D2_W8;
    let challenger = ordinary.for_challenger();
    let expected = vec![
        NpoTypeId::poseidon1_perm(challenger),
        NpoTypeId::poseidon1_perm(ordinary),
        NpoTypeId::recompose_with_coeff_lookups(),
    ];
    let preprocessors = <GoldP1Backend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
        non_primitive_preprocessors(&backend);
    assert_eq!(preprocessors.len(), 2);
    assert_eq!(
        preprocessors[0].as_ref().type_id(),
        TypeId::of::<Poseidon1Preprocessor>()
    );
    for config in [ordinary, challenger] {
        let backend = WhirRecursionBackend::<8, 4, _>::new(config).for_extension_degree::<2>();
        let output = <GoldP1Backend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
            non_primitive_provers(&backend, 2);
        assert_eq!(
            output.iter().map(|p| p.op_type()).collect::<Vec<_>>(),
            expected
        );
        let input = <GoldP1Backend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
            non_primitive_input_provers(&backend, 2, &expected);
        assert_eq!(
            input.iter().map(|p| p.op_type()).collect::<Vec<_>>(),
            expected
        );
        let builders = <GoldP1Backend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
            non_primitive_air_builders(&backend);
        assert_eq!(builders.len(), 3);
        assert_eq!(
            builders[0].as_ref().type_id(),
            TypeId::of::<Poseidon1AirBuilderForConfig<2>>()
        );
        assert_eq!(
            builders[1].as_ref().type_id(),
            TypeId::of::<Poseidon1AirBuilderForConfig<2>>()
        );
    }
    assert!(
        <GoldP1Backend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
            non_primitive_provers(&backend, 4).is_empty()
    );
}

#[derive(Clone, Copy)]
struct BothFamilies;

impl ChallengerPermConfig for BothFamilies {
    fn extension_degree(&self) -> usize {
        2
    }

    fn as_poseidon2(&self) -> Option<&Poseidon2Config> {
        Some(&Poseidon2Config::GOLDILOCKS_D2_W8)
    }

    fn as_poseidon1(&self) -> Option<&Poseidon1Config> {
        Some(&Poseidon1Config::GOLDILOCKS_D2_W8)
    }
}

#[test]
fn dual_family_d2_selects_poseidon2_on_all_provider_surfaces() {
    let backend = WhirRecursionBackend::<8, 4, _>::new(BothFamilies).for_extension_degree::<2>();
    type Backend = WhirRecursionBackendForExt<2, 8, 4, BothFamilies>;
    let p2 = Poseidon2Config::GOLDILOCKS_D2_W8;
    let shared = NpoTypeId::poseidon2_perm(p2.for_shared_challenger_table());
    let legacy = [NpoTypeId::poseidon2_perm(p2.for_challenger())];
    let prep = <Backend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
        non_primitive_preprocessors(&backend);
    assert_eq!(
        prep[0].as_ref().type_id(),
        TypeId::of::<Poseidon2SharedPreprocessor>()
    );
    let output =
        <Backend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::non_primitive_provers(
            &backend, 2,
        );
    assert_eq!(
        output.iter().map(|p| p.op_type()).collect::<Vec<_>>(),
        vec![shared, NpoTypeId::recompose_with_coeff_lookups()]
    );
    let input = <Backend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
        non_primitive_input_provers(&backend, 2, &legacy);
    assert_eq!(
        input.iter().map(|p| p.op_type()).collect::<Vec<_>>(),
        vec![
            legacy[0].clone(),
            NpoTypeId::poseidon2_perm(p2),
            NpoTypeId::recompose_with_coeff_lookups()
        ]
    );
    let builders = <Backend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
        non_primitive_air_builders(&backend);
    assert_eq!(builders.len(), 2);
    assert_eq!(
        builders[0].as_ref().type_id(),
        TypeId::of::<Poseidon2AirBuilderForConfig<2>>()
    );
}

#[derive(Clone, Copy)]
struct NoFamily;

impl ChallengerPermConfig for NoFamily {
    fn extension_degree(&self) -> usize {
        2
    }
}

#[test]
fn unknown_d2_family_keeps_provider_panics_and_wrong_degree_empty() {
    use std::panic::{AssertUnwindSafe, catch_unwind};

    type Backend = WhirRecursionBackendForExt<2, 8, 4, NoFamily>;
    let backend = WhirRecursionBackend::<8, 4, _>::new(NoFamily).for_extension_degree::<2>();
    assert!(
        <Backend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::non_primitive_provers(
            &backend, 4
        )
        .is_empty()
    );
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            <Backend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
            non_primitive_preprocessors(&backend)
        }))
        .is_err()
    );
    assert!(catch_unwind(AssertUnwindSafe(|| {
        <Backend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
            non_primitive_provers(&backend, 2)
    })).is_err());
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            <Backend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
            non_primitive_input_provers(&backend, 2, &[])
        }))
        .is_err()
    );
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            <Backend as PcsRecursionBackend<GoldWhirConfig, FibonacciAir, 2>>::
            non_primitive_air_builders(&backend)
        }))
        .is_err()
    );
}
