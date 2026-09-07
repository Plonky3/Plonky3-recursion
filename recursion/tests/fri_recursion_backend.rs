mod common;

use p3_recursion::ProveNextLayerParams;
use p3_recursion::recursion::build_and_prove_next_layer;
use p3_recursion::verifier::VerificationError;

/// A config carrying no permutation config on its FRI verifier params must be refused.
///
/// That setting skips in-circuit MMCS verification for every commitment, so nothing ties a FRI
/// opening to its Merkle root and a prover can open to arbitrary values. It is a legitimate mode
/// for lower-level tests that isolate the FRI arithmetic, but a recursion layer built on it is
/// unsound, and neither the type system nor the circuit's own constraints signal that -- the
/// backend has to. Mirrors
/// `whir_recursion_backend_rejects_an_arithmetic_only_permutation_config` in
/// `whir_recursion_backend.rs`.
#[test]
fn fri_recursion_backend_rejects_an_arithmetic_only_permutation_config() {
    let fixture = crate::common::build_koala_bear_d4_first_layer_input_arithmetic_only();
    let prev_input = fixture.recursion_input();

    let result = build_and_prove_next_layer(
        &prev_input,
        &fixture.layer_config,
        &fixture.backend,
        &ProveNextLayerParams::default(),
    );

    match result {
        Err(VerificationError::InvalidProofShape(message)) => assert!(
            message.contains("permutation_config"),
            "rejected for the permutation config specifically, got: {message}"
        ),
        Err(other) => panic!("expected InvalidProofShape, got {other:?}"),
        Ok(_) => panic!("a permutation-config-less FRI config must not produce a recursion layer"),
    }
}
