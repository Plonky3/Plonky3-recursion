#[path = "../binary_boolean_multi_stark.rs"]
mod binary_boolean_multi_stark;
#[path = "../binary_boolean_native_authority.rs"]
mod binary_boolean_native_authority;
#[path = "../binary_boolean_pcs.rs"]
mod binary_boolean_pcs;
#[path = "../binary_boolean_trace.rs"]
mod binary_boolean_trace;
#[path = "../binary_boolean_trusted_portable.rs"]
mod binary_boolean_trusted_portable;
#[path = "../binary_boolean_whir.rs"]
mod binary_boolean_whir;
#[path = "../binary_boolean_whir_multi_stark.rs"]
mod binary_boolean_whir_multi_stark;
#[path = "../binary_boolean_whir_native_authority.rs"]
mod binary_boolean_whir_native_authority;
#[path = "../binary_boolean_whir_trace.rs"]
mod binary_boolean_whir_trace;
#[path = "../binary_boolean_whir_trusted_portable.rs"]
mod binary_boolean_whir_trusted_portable;
#[path = "../binary_grouped_boolean_multi_stark.rs"]
mod binary_grouped_boolean_multi_stark;
#[path = "../binary_grouped_boolean_native_authority.rs"]
mod binary_grouped_boolean_native_authority;
#[path = "../binary_grouped_boolean_pcs.rs"]
mod binary_grouped_boolean_pcs;
#[path = "../binary_grouped_boolean_trace.rs"]
mod binary_grouped_boolean_trace;
#[path = "../binary_grouped_boolean_trusted_portable.rs"]
mod binary_grouped_boolean_trusted_portable;

// Functional circuit roundtrips do not need the benchmark suite's grinding
// and 100 FRI queries. Keep the same field, hash and expansion factor.
fn proof_config() -> p3_recursion::builtin_config::BabyBearD4Poseidon2BinaryConfig {
    use p3_recursion::builtin_config::{FriConfigV1, SuiteIdV1, baby_bear_d4_poseidon2_binary};
    use p3_recursion::verifier::VerifierLimits;

    baby_bear_d4_poseidon2_binary(
        &FriConfigV1::new(
            SuiteIdV1::BabyBearD4Poseidon2BinaryFri,
            1,
            0,
            2,
            2,
            0,
            0,
            0,
            0,
            0,
            0,
        ),
        &VerifierLimits::default(),
    )
    .unwrap()
}
