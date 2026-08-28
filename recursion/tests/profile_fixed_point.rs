mod common;

use p3_circuit::ops::NpoTypeId;
use p3_circuit_prover::{ConstraintProfile, TablePacking};
use p3_recursion::profile::{
    HashProfile, RecursionLayerProfile, TranscriptKind, solve_fixed_point,
};
use p3_recursion::{
    BatchOnly, Poseidon2Config, ProveNextLayerParams, build_next_layer_circuit,
    build_next_layer_prep, prove_next_layer,
};
use p3_test_utils::koala_bear_params::Challenge;
use tracing_forest::ForestLayer;
use tracing_forest::util::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

use crate::common::{
    KoalaBearD4Backend, KoalaBearD4RecursionConfig, build_koala_bear_d4_first_layer_input,
};

fn init_logger() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    let _ = Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .try_init();
}

/// `solve_fixed_point` must converge on a real recursion-layer verifier circuit (verifying a
/// KoalaBear D4 base batch-STARK proof), and the profile it returns must be an actual fixed
/// point for that one circuit: independently rebuilding this layer's circuit and
/// proving/verifying it end-to-end under the resolved (strict) packing must not overflow any
/// table -- primitive (ALU/PUBLIC/CONST) or non-primitive (Poseidon2/Recompose), now that
/// strict-mode overflow checks cover NPO tables too.
#[test]
fn fixed_point_converges_on_koala_bear_d4_first_layer_and_the_profile_actually_proves() {
    init_logger();

    let fixture = build_koala_bear_d4_first_layer_input();
    let prev_input = fixture.recursion_input();

    // Deliberately undersized seed: no per-table height overrides and the default global
    // floor of 1, so every primitive table's natural row count (hundreds of ALU/CONST rows
    // verifying a batch-STARK FRI proof) exceeds it. Convergence therefore requires real
    // iteration, not a lucky pass on iteration 0.
    let seed = RecursionLayerProfile {
        table_packing: TablePacking::new(1, 3).with_horner_pack_k(4),
        hash: HashProfile::default(),
        transcript: TranscriptKind::default(),
    };

    // `solve_fixed_point` needs at most (number of tables that overflow) + 1 probes: one bump
    // per overflowing table, plus a final clean re-probe that finds nothing left to bump. Every
    // table with a strict-mode overflow check (primitive or, since NPO tables gained one too,
    // non-primitive) is a candidate to need that one bump, and that set can grow as new
    // strict-mode checks land elsewhere -- so this budget is bounded well above the number of
    // tables expected to need adjustment for this circuit, not tuned to today's exact count or
    // which specific tables can overflow. Confirmed via `RUST_LOG=info` that this circuit
    // converges in well under this budget today (a handful of primitive and NPO bumps, then one
    // converging pass).
    let max_iterations = 8;
    let profile = solve_fixed_point::<_, _, _, 4>(
        seed,
        &prev_input,
        &fixture.layer_config,
        &fixture.backend,
        ConstraintProfile::Standard,
        max_iterations,
    )
    .expect("fixed point should converge within max_iterations");

    assert!(
        profile.table_packing.is_strict(),
        "solve_fixed_point must return a strict TablePacking"
    );

    // Real convergence, not a trivial iteration-0 pass: with a global floor of 1 and no
    // per-table overrides in the seed, all three primitive tables' natural heights (hundreds
    // of ALU/CONST/PUBLIC rows verifying a batch-STARK FRI proof) exceed 1, so all three must
    // have been bumped -- confirmed by `RUST_LOG=info` output showing CONST, PUBLIC, and ALU
    // each bumped once, followed by the NPO tables (below), then a final converging pass with
    // no overflow.
    assert!(
        profile.table_packing.const_min_height().unwrap_or(1) > 1,
        "expected solve_fixed_point to have grown the CONST table's height, got {:?}",
        profile.table_packing
    );
    assert!(
        profile.table_packing.public_min_height().unwrap_or(1) > 1,
        "expected solve_fixed_point to have grown the PUBLIC table's height, got {:?}",
        profile.table_packing
    );
    assert!(
        profile.table_packing.alu_min_height().unwrap_or(1) > 1,
        "expected solve_fixed_point to have grown the ALU table's height, got {:?}",
        profile.table_packing
    );
    // Non-primitive (NPO) tables get the same strict-mode overflow check as primitives, so
    // this layer's Poseidon2 and Recompose tables (natural heights far above the seed's floor
    // of 1) must have been bumped too.
    let poseidon2_op = NpoTypeId::poseidon2_perm(Poseidon2Config::KOALA_BEAR_D4_W16);
    assert!(
        profile
            .table_packing
            .npo_min_height(&poseidon2_op)
            .unwrap_or(1)
            > 1,
        "expected solve_fixed_point to have grown the Poseidon2 NPO table's height, got {:?}",
        profile.table_packing
    );
    // The verifier circuit packs and unpacks every challenger limb through `recompose/coeff`,
    // so that is the recompose table this layer carries rows in.
    let recompose_op = NpoTypeId::recompose_with_coeff_lookups();
    assert!(
        profile
            .table_packing
            .npo_min_height(&recompose_op)
            .unwrap_or(1)
            > 1,
        "expected solve_fixed_point to have grown the recompose/coeff NPO table's height, got {:?}",
        profile.table_packing
    );

    // The actual fixed-point property: an INDEPENDENT rebuild of this layer's verifier circuit
    // -- not reusing anything solve_fixed_point built internally -- must accept the resolved
    // profile without any table overflowing, and the layer must actually prove and verify.
    let (verification_circuit, verifier_result) = build_next_layer_circuit::<_, _, _, 4>(
        &prev_input,
        &fixture.layer_config,
        &fixture.backend,
    )
    .expect("rebuilding the verifier circuit must succeed");

    let params = ProveNextLayerParams {
        table_packing: profile.table_packing,
        constraint_profile: ConstraintProfile::Standard,
    };

    let prep_cache =
        build_next_layer_prep::<KoalaBearD4RecursionConfig, BatchOnly, KoalaBearD4Backend, 4>(
            &verification_circuit,
            &fixture.layer_config,
            &fixture.backend,
            &params,
        )
        .expect("resolved profile must not overflow any table when re-probed independently");

    let output = prove_next_layer::<_, _, _, 4>(
        &prev_input,
        &verification_circuit,
        &verifier_result,
        &fixture.layer_config,
        &fixture.backend,
        &params,
        Some(&prep_cache),
    )
    .expect("resolved profile must actually prove the recursion layer");

    prep_cache
        .prover
        .verify_all_tables::<Challenge>(&output.0)
        .expect("the layer proven under the resolved profile must verify");
}
