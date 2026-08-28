mod common;

use p3_circuit_prover::ConstraintProfile;
use p3_recursion::profile::{
    ProfilePrepCache, build_layer_circuit, prove_layer, solve_fixed_point,
};
use p3_recursion::{
    BatchOnly, ProveNextLayerParams, RecursionOutput, build_next_layer_circuit,
    build_next_layer_prep, prove_next_layer,
};

use crate::common::{KoalaBearD4Backend, KoalaBearD4RecursionConfig, solved_koala_bear_d4_profile};

/// Mirrors the `--profile` examples' per-layer loop: `solved_koala_bear_d4_profile` already
/// solved a `RecursionLayerProfile` against the base proof (this test's "layer 1" input), the
/// same way the examples solve once after their own layer 1 completes. That profile need not
/// yet be a genuine cross-layer fixed point (it was solved against a proof that itself wasn't
/// produced under any profile), so this repeatedly builds/proves one more layer under the
/// current candidate and re-solves against *that* layer's own output -- exactly
/// `solve_fixed_point`'s own documented cross-layer contract -- until a re-solve leaves the
/// profile unchanged, then compares the profile path's output against the plain (non-profile)
/// path byte-for-byte for one more layer under that confirmed-stable profile.
#[test]
fn profile_path_matches_plain_path_once_fixed_point_is_reached() {
    let (config, backend, layer1_prev, layer1_profile) = solved_koala_bear_d4_profile();

    let mut candidate = layer1_profile;
    let mut current_output: Option<RecursionOutput<KoalaBearD4RecursionConfig>> = None;
    let mut stable = false;

    // Bounded bootstrap: each hop proves one more layer under the current candidate (uncached)
    // and re-solves against that layer's own output. `solve_fixed_point` only ever grows a
    // table_packing, never shrinks it, so this strictly progresses towards a fixed point.
    for _ in 0..4 {
        #[allow(clippy::option_if_let_else)]
        let out = match &current_output {
            None => {
                let (circuit, verifier_result) = build_layer_circuit::<
                    KoalaBearD4RecursionConfig,
                    BatchOnly,
                    KoalaBearD4Backend,
                    4,
                >(
                    &candidate, &layer1_prev, &config, &backend
                )
                .expect("building the verifier circuit under the candidate profile should succeed");
                prove_layer::<KoalaBearD4RecursionConfig, BatchOnly, KoalaBearD4Backend, 4>(
                    &candidate,
                    &layer1_prev,
                    &circuit,
                    &verifier_result,
                    &config,
                    &backend,
                    None,
                )
                .expect("proving under the candidate profile should succeed")
            }
            Some(prev_out) => {
                let input = prev_out.into_recursion_input::<BatchOnly>();
                let (circuit, verifier_result) = build_layer_circuit::<
                    KoalaBearD4RecursionConfig,
                    BatchOnly,
                    KoalaBearD4Backend,
                    4,
                >(
                    &candidate, &input, &config, &backend
                )
                .expect("building the verifier circuit under the candidate profile should succeed");
                prove_layer::<KoalaBearD4RecursionConfig, BatchOnly, KoalaBearD4Backend, 4>(
                    &candidate,
                    &input,
                    &circuit,
                    &verifier_result,
                    &config,
                    &backend,
                    None,
                )
                .expect("proving under the candidate profile should succeed")
            }
        };

        let is_stable = {
            let next_input = out.into_recursion_input::<BatchOnly>();
            let resolved =
                solve_fixed_point::<KoalaBearD4RecursionConfig, BatchOnly, KoalaBearD4Backend, 4>(
                    candidate.clone(),
                    &next_input,
                    &config,
                    &backend,
                    ConstraintProfile::Standard,
                    8,
                )
                .expect("re-solving against this layer's own output should converge");
            let is_stable = resolved == candidate;
            candidate = resolved;
            is_stable
        };

        current_output = Some(out);
        if is_stable {
            stable = true;
            break;
        }
    }
    assert!(
        stable,
        "the candidate profile should reach a fixed point within the bootstrap budget, last: {candidate:?}"
    );
    let fixed_profile = candidate;
    let last_output = current_output.expect("at least one bootstrap hop must have run");
    let prev_input = last_output.into_recursion_input::<BatchOnly>();

    // Prove one more layer two ways under the now-confirmed-stable profile and assert
    // byte-identical output: once via the profile path (build_layer_circuit + prove_layer, with
    // a prep cache built from this layer's own circuit), once via the plain path
    // (build_next_layer_circuit + prove_next_layer) using the identical resolved table_packing.
    let (profile_circuit, profile_verifier_result) =
        build_layer_circuit::<KoalaBearD4RecursionConfig, BatchOnly, KoalaBearD4Backend, 4>(
            &fixed_profile,
            &prev_input,
            &config,
            &backend,
        )
        .expect("building the verifier circuit under the fixed profile should succeed");

    let prep_inner =
        build_next_layer_prep::<KoalaBearD4RecursionConfig, BatchOnly, KoalaBearD4Backend, 4>(
            &profile_circuit,
            &config,
            &backend,
            &ProveNextLayerParams {
                table_packing: fixed_profile.table_packing.clone(),
                constraint_profile: ConstraintProfile::Standard,
            },
        )
        .expect("the confirmed-stable profile must not overflow any table");
    let prep = ProfilePrepCache {
        profile: fixed_profile.clone(),
        inner: prep_inner,
    };

    let profile_path_out =
        prove_layer::<KoalaBearD4RecursionConfig, BatchOnly, KoalaBearD4Backend, 4>(
            &fixed_profile,
            &prev_input,
            &profile_circuit,
            &profile_verifier_result,
            &config,
            &backend,
            Some(&prep),
        )
        .expect("prove_layer should succeed under the confirmed-stable profile");

    let plain_params = ProveNextLayerParams {
        table_packing: fixed_profile.table_packing,
        constraint_profile: ConstraintProfile::Standard,
    };
    let (plain_circuit, plain_verifier_result) = build_next_layer_circuit::<
        KoalaBearD4RecursionConfig,
        BatchOnly,
        KoalaBearD4Backend,
        4,
    >(&prev_input, &config, &backend)
    .expect("building the verifier circuit via the plain path should succeed");
    let plain_path_out =
        prove_next_layer::<KoalaBearD4RecursionConfig, BatchOnly, KoalaBearD4Backend, 4>(
            &prev_input,
            &plain_circuit,
            &plain_verifier_result,
            &config,
            &backend,
            &plain_params,
            None,
        )
        .expect("proving via the plain path should succeed");

    let profile_path_bytes =
        postcard::to_allocvec(&profile_path_out.0).expect("serializing the profile-path proof");
    let plain_path_bytes =
        postcard::to_allocvec(&plain_path_out.0).expect("serializing the plain-path proof");

    assert_eq!(
        profile_path_bytes, plain_path_bytes,
        "the profile path (build_layer_circuit/prove_layer under a confirmed-stable profile) \
         must produce byte-identical output to the plain (non-profile) path proving under the \
         same resolved table_packing"
    );
}
