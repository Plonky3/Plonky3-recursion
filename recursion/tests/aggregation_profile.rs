mod common;

use std::sync::Arc;

use p3_circuit::CircuitError;
use p3_circuit::ops::NpoTypeId;
use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
use p3_circuit_prover::{ConstraintProfile, TablePacking};
use p3_recursion::profile::{
    HashProfile, RecursionLayerProfile, TranscriptKind, prove_aggregation_layer_with_profile,
};
use p3_recursion::{
    BatchOnly, PcsRecursionBackend, Poseidon2Config, build_aggregation_layer_circuit,
};
use p3_test_utils::koala_bear_params::Challenge;

use crate::common::{
    KoalaBearD4Backend, KoalaBearD4RecursionConfig, build_koala_bear_d4_first_layer_input,
};

/// Mirrors `p3_recursion::profile`'s private `bump_table_height` growth rule for a strict
/// `TablePacking` probe; duplicated here since that helper isn't part of the crate's public
/// surface.
fn bump_table_height(packing: TablePacking, table: &str, needed: usize) -> TablePacking {
    match table {
        "ALU" => packing.with_alu_min_height(needed),
        "PUBLIC" => packing.with_public_min_height(needed),
        "CONST" => packing.with_const_min_height(needed),
        other => packing.with_npo_min_height(NpoTypeId::new(other), needed),
    }
}

/// `solve_fixed_point` (`p3_recursion::profile`) only builds a single-input verifier circuit
/// via `build_next_layer_circuit`, so it cannot solve a fixed point for a 2-to-1 aggregation
/// circuit built via `build_aggregation_layer_circuit`. This mirrors its convergence loop
/// against `verification_circuit` directly instead.
fn solve_fixed_point_for_aggregation(
    seed: &RecursionLayerProfile,
    verification_circuit: &p3_circuit::Circuit<Challenge>,
    backend: &KoalaBearD4Backend,
    max_iterations: usize,
) -> RecursionLayerProfile {
    let preprocessors = <KoalaBearD4Backend as PcsRecursionBackend<
        KoalaBearD4RecursionConfig,
        BatchOnly,
        4,
    >>::non_primitive_preprocessors(backend);
    let air_builders = <KoalaBearD4Backend as PcsRecursionBackend<
        KoalaBearD4RecursionConfig,
        BatchOnly,
        4,
    >>::non_primitive_air_builders(backend);

    let mut table_packing = seed.table_packing.clone().with_strict_heights();
    for _ in 0..max_iterations {
        match get_airs_and_degrees_with_prep::<KoalaBearD4RecursionConfig, Challenge, 4>(
            verification_circuit,
            &table_packing,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        ) {
            Ok(_) => {
                return RecursionLayerProfile {
                    table_packing,
                    hash: seed.hash,
                    transcript: seed.transcript,
                    constraint_profile: seed.constraint_profile,
                };
            }
            Err(CircuitError::ProfileOverflow { table, needed, .. }) => {
                table_packing = bump_table_height(table_packing, &table, needed);
            }
            Err(other) => {
                panic!("unexpected error while solving the aggregation fixed point: {other:?}")
            }
        }
    }
    panic!(
        "aggregation fixed point did not converge within {max_iterations} iterations, last packing: {table_packing:?}"
    );
}

fn verify_output(
    output: &p3_recursion::RecursionOutput<KoalaBearD4RecursionConfig>,
    config: &KoalaBearD4RecursionConfig,
    backend: &KoalaBearD4Backend,
    packing: TablePacking,
) {
    let mut verifier =
        p3_circuit_prover::BatchStarkProver::new(config.clone()).with_table_packing(packing);
    for prover in <KoalaBearD4Backend as PcsRecursionBackend<
        KoalaBearD4RecursionConfig,
        BatchOnly,
        4,
    >>::non_primitive_provers(backend, 4)
    {
        verifier.register_table_prover(prover);
    }
    verifier
        .verify_all_tables::<Challenge>(&output.0)
        .expect("the aggregation layer proof must verify");
}

/// `solve_fixed_point` must converge on a real 2-to-1 aggregation verifier circuit (aggregating
/// two KoalaBear D4 base batch-STARK proofs), and `prove_aggregation_layer_with_profile` must
/// actually prove and verify under the resulting profile, with the proof's committed
/// `table_packing` matching the profile it was proven under.
#[test]
fn aggregation_layer_profile_converges_and_proves() {
    let left_fixture = build_koala_bear_d4_first_layer_input();
    let right_fixture = build_koala_bear_d4_first_layer_input();
    let left_input = left_fixture.recursion_input();
    let right_input = right_fixture.recursion_input();

    let config = left_fixture.layer_config.clone();
    let backend = left_fixture.backend.clone();

    let (verification_circuit, (left_result, right_result)) =
        build_aggregation_layer_circuit::<
            KoalaBearD4RecursionConfig,
            BatchOnly,
            BatchOnly,
            KoalaBearD4Backend,
            4,
        >(&left_input, &right_input, &config, &backend)
        .expect("building the 2-to-1 aggregation verifier circuit should succeed");

    // Same undersized seed as `profile_fixed_point.rs`/`solved_koala_bear_d4_profile`: no
    // per-table height overrides, so convergence requires real iteration against this
    // aggregation circuit's actual table shapes.
    let seed = RecursionLayerProfile {
        table_packing: TablePacking::new(1, 3).with_horner_pack_k(4),
        hash: HashProfile::default(),
        transcript: TranscriptKind::default(),
        constraint_profile: ConstraintProfile::default(),
    };

    let profile = solve_fixed_point_for_aggregation(&seed, &verification_circuit, &backend, 8);

    assert!(
        profile.table_packing.is_strict(),
        "the resolved aggregation profile must carry a strict TablePacking"
    );

    let output = prove_aggregation_layer_with_profile::<
        KoalaBearD4RecursionConfig,
        BatchOnly,
        BatchOnly,
        KoalaBearD4Backend,
        4,
    >(
        &profile,
        &left_input,
        &right_input,
        &left_result,
        &right_result,
        &verification_circuit,
        &config,
        &backend,
    )
    .expect("prove_aggregation_layer_with_profile should succeed under its own resolved profile");

    assert_eq!(
        output.0.table_packing, profile.table_packing,
        "the proof's committed table_packing must match the resolved profile"
    );

    verify_output(&output, &config, &backend, profile.table_packing);
}

#[test]
fn backend_output_registration_deduplicates_same_shape_roles() {
    let backend =
        p3_recursion::FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
            .with_extra_poseidon2_table(Poseidon2Config::KOALA_BEAR_D4_W16)
            .with_extra_poseidon2_table(Poseidon2Config::KOALA_BEAR_D4_W16.for_challenger())
            .for_extension_degree::<4>();

    let provers = <KoalaBearD4Backend as PcsRecursionBackend<
        KoalaBearD4RecursionConfig,
        BatchOnly,
        4,
    >>::non_primitive_provers(&backend, 4);
    let same_shape: Vec<_> = provers
        .iter()
        .filter(|prover| {
            prover
                .op_type()
                .as_str()
                .starts_with("poseidon2_perm/koala_bear_d4_w16")
        })
        .collect();
    assert_eq!(same_shape.len(), 1);
    assert_eq!(
        same_shape[0].op_type().as_str(),
        "poseidon2_perm/koala_bear_d4_w16_shared"
    );
}

#[test]
fn backend_input_selector_selects_exact_legacy_or_combined_manifest() {
    let backend =
        p3_recursion::FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
            .for_extension_degree::<4>();
    let combined =
        NpoTypeId::poseidon2_perm(Poseidon2Config::KOALA_BEAR_D4_W16.for_shared_challenger_table());
    let legacy = vec![
        NpoTypeId::poseidon2_perm(Poseidon2Config::KOALA_BEAR_D4_W16.for_challenger()),
        NpoTypeId::poseidon2_perm(Poseidon2Config::KOALA_BEAR_D4_W16),
    ];

    let combined_provers = <KoalaBearD4Backend as PcsRecursionBackend<
        KoalaBearD4RecursionConfig,
        BatchOnly,
        4,
    >>::non_primitive_input_provers(
        &backend, 4, std::slice::from_ref(&combined)
    );
    assert!(combined_provers.iter().any(|p| p.op_type() == combined));

    let legacy_provers = <KoalaBearD4Backend as PcsRecursionBackend<
        KoalaBearD4RecursionConfig,
        BatchOnly,
        4,
    >>::non_primitive_input_provers(&backend, 4, &legacy);
    assert_eq!(
        legacy_provers
            .iter()
            .filter(|p| p
                .op_type()
                .as_str()
                .starts_with("poseidon2_perm/koala_bear_d4_w16"))
            .map(|p| p.op_type())
            .collect::<Vec<_>>(),
        legacy
    );

    let challenger_only_backend =
        p3_recursion::FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
            .without_shared_challenger_perm_table()
            .for_extension_degree::<4>();
    let challenger_only = vec![legacy[0].clone()];
    let challenger_only_provers = <KoalaBearD4Backend as PcsRecursionBackend<
        KoalaBearD4RecursionConfig,
        BatchOnly,
        4,
    >>::non_primitive_input_provers(
        &challenger_only_backend, 4, &challenger_only
    );
    assert_eq!(
        challenger_only_provers
            .iter()
            .filter(|p| p
                .op_type()
                .as_str()
                .starts_with("poseidon2_perm/koala_bear_d4_w16"))
            .map(|p| p.op_type())
            .collect::<Vec<_>>(),
        challenger_only
    );
}

#[test]
fn mixed_arity4_bridge_separates_input_and_output_extra_tables() {
    let backend =
        p3_recursion::FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
            .with_extra_poseidon2_table(Poseidon2Config::KOALA_BEAR_D4_W32)
            .without_extra_poseidon2_input_tables()
            .for_extension_degree::<4>();
    let shared =
        NpoTypeId::poseidon2_perm(Poseidon2Config::KOALA_BEAR_D4_W16.for_shared_challenger_table());
    let wide = NpoTypeId::poseidon2_perm(Poseidon2Config::KOALA_BEAR_D4_W32);
    let recompose = NpoTypeId::recompose_with_coeff_lookups();
    let input_ids = vec![shared.clone(), recompose.clone()];
    let input_provers = <KoalaBearD4Backend as PcsRecursionBackend<
        KoalaBearD4RecursionConfig,
        BatchOnly,
        4,
    >>::non_primitive_input_provers(&backend, 4, &input_ids);
    assert_eq!(
        input_provers
            .iter()
            .map(|prover| prover.op_type())
            .collect::<Vec<_>>(),
        input_ids
    );

    let output_provers = <KoalaBearD4Backend as PcsRecursionBackend<
        KoalaBearD4RecursionConfig,
        BatchOnly,
        4,
    >>::non_primitive_provers(&backend, 4);
    assert_eq!(
        output_provers
            .iter()
            .map(|prover| prover.op_type())
            .collect::<Vec<_>>(),
        vec![shared, wide, recompose]
    );
}

/// `prove_aggregation_layer_with_profile` prepares fresh proving data for each call.
#[test]
fn aggregation_layer_profile_prepares_fresh() {
    let left_fixture = build_koala_bear_d4_first_layer_input();
    let right_fixture = build_koala_bear_d4_first_layer_input();
    let left_input = left_fixture.recursion_input();
    let right_input = right_fixture.recursion_input();

    let config = left_fixture.layer_config.clone();
    let backend = left_fixture.backend.clone();

    let (verification_circuit, (left_result, right_result)) =
        build_aggregation_layer_circuit::<
            KoalaBearD4RecursionConfig,
            BatchOnly,
            BatchOnly,
            KoalaBearD4Backend,
            4,
        >(&left_input, &right_input, &config, &backend)
        .expect("building the 2-to-1 aggregation verifier circuit should succeed");

    let seed = RecursionLayerProfile {
        table_packing: TablePacking::new(1, 3).with_horner_pack_k(4),
        hash: HashProfile::default(),
        transcript: TranscriptKind::default(),
        constraint_profile: ConstraintProfile::default(),
    };
    let profile = solve_fixed_point_for_aggregation(&seed, &verification_circuit, &backend, 8);

    let output = prove_aggregation_layer_with_profile::<
        KoalaBearD4RecursionConfig,
        BatchOnly,
        BatchOnly,
        KoalaBearD4Backend,
        4,
    >(
        &profile,
        &left_input,
        &right_input,
        &left_result,
        &right_result,
        &verification_circuit,
        &config,
        &backend,
    )
    .expect("prove_aggregation_layer_with_profile should prepare fresh and succeed");

    let repeat = prove_aggregation_layer_with_profile::<
        KoalaBearD4RecursionConfig,
        BatchOnly,
        BatchOnly,
        KoalaBearD4Backend,
        4,
    >(
        &profile,
        &left_input,
        &right_input,
        &left_result,
        &right_result,
        &verification_circuit,
        &config,
        &backend,
    )
    .expect("a repeated profile call should prepare independently and succeed");
    assert_ne!(
        Arc::as_ptr(&output.1),
        Arc::as_ptr(&repeat.1),
        "expert free profile calls must not retain detached preparation between calls"
    );

    assert_eq!(
        output.0.table_packing, profile.table_packing,
        "the proof's committed table_packing must match the resolved profile"
    );

    verify_output(&output, &config, &backend, profile.table_packing);
}

/// A profile call prepares proving data and retains the requested output shape.
#[test]
fn aggregation_layer_profile_single_call_preserves_shape() {
    let left_fixture = build_koala_bear_d4_first_layer_input();
    let right_fixture = build_koala_bear_d4_first_layer_input();
    let left_input = left_fixture.recursion_input();
    let right_input = right_fixture.recursion_input();

    let config = left_fixture.layer_config.clone();
    let backend = left_fixture.backend.clone();

    let (verification_circuit, (left_result, right_result)) =
        build_aggregation_layer_circuit::<
            KoalaBearD4RecursionConfig,
            BatchOnly,
            BatchOnly,
            KoalaBearD4Backend,
            4,
        >(&left_input, &right_input, &config, &backend)
        .expect("building the 2-to-1 aggregation verifier circuit should succeed");

    let seed = RecursionLayerProfile {
        table_packing: TablePacking::new(1, 3).with_horner_pack_k(4),
        hash: HashProfile::default(),
        transcript: TranscriptKind::default(),
        constraint_profile: ConstraintProfile::default(),
    };
    let profile = solve_fixed_point_for_aggregation(&seed, &verification_circuit, &backend, 8);

    let output = prove_aggregation_layer_with_profile::<
        KoalaBearD4RecursionConfig,
        BatchOnly,
        BatchOnly,
        KoalaBearD4Backend,
        4,
    >(
        &profile,
        &left_input,
        &right_input,
        &left_result,
        &right_result,
        &verification_circuit,
        &config,
        &backend,
    )
    .expect("prove_aggregation_layer_with_profile should prepare fresh and succeed");

    assert_eq!(
        output.0.table_packing, profile.table_packing,
        "the proof must be committed under the requested profile's table_packing"
    );

    verify_output(&output, &config, &backend, profile.table_packing);
}
