mod common;

use p3_recursion::profile::{RecursionLayerProfile, build_layer_circuit};
use p3_recursion::verifier::VerificationError;

/// A proof built under a DIFFERENT profile (different ALU/public lane packing) must be
/// rejected by `check_proof_shape` before the recursive verifier circuit ever executes on it.
#[test]
fn wrong_table_set_in_proof_is_rejected_as_invalid_shape() {
    let (config, backend, prev_input, profile) = crate::common::solved_koala_bear_d4_profile();
    let (_circuit, _verifier_result) =
        build_layer_circuit::<_, _, _, 4>(&profile, &prev_input, &config, &backend).unwrap();

    let mismatched_profile = RecursionLayerProfile {
        table_packing: profile.table_packing.clone().with_public_alu_lanes(1, 5),
        hash: profile.hash,
        transcript: profile.transcript,
    };
    let (mismatched_output, _prep) =
        crate::common::prove_one_layer(&mismatched_profile, &prev_input, &config, &backend);

    let err = profile.check_proof_shape(&mismatched_output.0).unwrap_err();
    assert!(matches!(err, VerificationError::InvalidProofShape(_)));
}

/// A proof built under the SAME profile it's later checked against must be accepted.
#[test]
fn matching_profile_is_accepted() {
    let (config, backend, prev_input, profile) = crate::common::solved_koala_bear_d4_profile();
    let (output, _prep) = crate::common::prove_one_layer(&profile, &prev_input, &config, &backend);
    assert!(profile.check_proof_shape(&output.0).is_ok());
}
