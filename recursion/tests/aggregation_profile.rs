mod common;

use p3_circuit::CircuitError;
use p3_circuit::ops::NpoTypeId;
use p3_circuit_prover::common::get_airs_and_degrees_with_prep;
use p3_circuit_prover::{ConstraintProfile, TablePacking};
use p3_recursion::profile::{
    HashProfile, ProfilePrepCache, RecursionLayerProfile, TranscriptKind,
    prove_aggregation_layer_with_profile,
};
use p3_recursion::{
    BatchOnly, PcsRecursionBackend, ProveNextLayerParams, build_aggregation_layer_circuit,
    build_next_layer_prep,
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
    };

    let profile = solve_fixed_point_for_aggregation(&seed, &verification_circuit, &backend, 8);

    assert!(
        profile.table_packing.is_strict(),
        "the resolved aggregation profile must carry a strict TablePacking"
    );

    let inner =
        build_next_layer_prep::<KoalaBearD4RecursionConfig, BatchOnly, KoalaBearD4Backend, 4>(
            &verification_circuit,
            &config,
            &backend,
            &ProveNextLayerParams {
                table_packing: profile.table_packing.clone(),
                constraint_profile: ConstraintProfile::Standard,
            },
        )
        .expect("resolved profile must not overflow when building prep for the aggregation layer");

    let prep = ProfilePrepCache {
        profile: profile.clone(),
        inner,
    };

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
        Some(&prep),
    )
    .expect("prove_aggregation_layer_with_profile should succeed under its own resolved profile");

    assert_eq!(
        output.0.table_packing, profile.table_packing,
        "the proof's committed table_packing must match the resolved profile"
    );

    prep.inner
        .prover
        .verify_all_tables::<Challenge>(&output.0)
        .expect("the aggregation layer proven under the resolved profile must verify");
}

/// `prove_aggregation_layer_with_profile` must also succeed when no prep cache is supplied at
/// all, exercising the uncached branch (fresh `get_airs_and_degrees_with_prep` +
/// `ProverData::from_airs_and_degrees`) rather than a cached prover.
#[test]
fn aggregation_layer_profile_proves_without_prep_cache() {
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
        None,
    )
    .expect("prove_aggregation_layer_with_profile should succeed with no prep cache supplied");

    assert_eq!(
        output.0.table_packing, profile.table_packing,
        "the proof's committed table_packing must match the resolved profile"
    );

    let verifier =
        build_next_layer_prep::<KoalaBearD4RecursionConfig, BatchOnly, KoalaBearD4Backend, 4>(
            &verification_circuit,
            &config,
            &backend,
            &ProveNextLayerParams {
                table_packing: profile.table_packing,
                constraint_profile: ConstraintProfile::Standard,
            },
        )
        .expect("resolved profile must not overflow when building a verifying prover");

    verifier
        .prover
        .verify_all_tables::<Challenge>(&output.0)
        .expect("the aggregation layer proven with no prep cache must verify");
}

/// A prep cache built under a DIFFERENT (but still non-overflowing) profile than the one being
/// proven under must be ignored: `prove_aggregation_layer_with_profile` must fall back to
/// solving fresh rather than misusing the stale cache's prover/circuit prover data, and the
/// resulting proof must still be committed under -- and verify under -- the requested profile.
#[test]
fn aggregation_layer_profile_ignores_stale_prep_cache() {
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
    };
    let profile = solve_fixed_point_for_aggregation(&seed, &verification_circuit, &backend, 8);

    // Larger than anything this small aggregation circuit needs, so it builds without
    // overflowing, yet still differs from `profile`'s resolved (tight) table_packing.
    let stale_profile = RecursionLayerProfile {
        table_packing: bump_table_height(profile.table_packing.clone(), "ALU", 65536),
        hash: profile.hash,
        transcript: profile.transcript,
    };
    assert_ne!(
        stale_profile, profile,
        "the stale profile must actually differ from the resolved one for this to be a real test"
    );

    let stale_inner =
        build_next_layer_prep::<KoalaBearD4RecursionConfig, BatchOnly, KoalaBearD4Backend, 4>(
            &verification_circuit,
            &config,
            &backend,
            &ProveNextLayerParams {
                table_packing: stale_profile.table_packing.clone(),
                constraint_profile: ConstraintProfile::Standard,
            },
        )
        .expect("the larger stale profile must not overflow either");
    let stale_prep = ProfilePrepCache {
        profile: stale_profile,
        inner: stale_inner,
    };

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
        Some(&stale_prep),
    )
    .expect(
        "prove_aggregation_layer_with_profile should fall back to a fresh solve when the \
         supplied prep cache was built under a different profile",
    );

    assert_eq!(
        output.0.table_packing, profile.table_packing,
        "the proof must be committed under the requested profile's table_packing, not the stale cache's"
    );

    let verifier =
        build_next_layer_prep::<KoalaBearD4RecursionConfig, BatchOnly, KoalaBearD4Backend, 4>(
            &verification_circuit,
            &config,
            &backend,
            &ProveNextLayerParams {
                table_packing: profile.table_packing,
                constraint_profile: ConstraintProfile::Standard,
            },
        )
        .expect("resolved profile must not overflow when building a verifying prover");

    verifier
        .prover
        .verify_all_tables::<Challenge>(&output.0)
        .expect("the aggregation layer proven with a stale prep cache must still verify");
}
