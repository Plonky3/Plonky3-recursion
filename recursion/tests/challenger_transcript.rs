//! Transcript compatibility tests for CircuitChallenger vs native DuplexChallenger.
//!
//! These tests verify that the recursive CircuitChallenger produces identical
//! transcript values as the native Plonky3 DuplexChallenger.

mod common;

use p3_baby_bear::{BabyBear, default_babybear_poseidon2_16};
use p3_challenger::{CanObserve, CanSample, DuplexChallenger, FieldChallenger};
use p3_circuit::ops::generate_poseidon2_trace;
use p3_circuit::{CircuitBuilder, Traces};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::challenger::CircuitChallenger;
use p3_recursion::traits::RecursiveChallenger;

type F = BabyBear;
type EF = BinomialExtensionField<F, 4>;
const WIDTH: usize = 16;
const RATE: usize = 8;

fn setup_circuit_with_poseidon2() -> CircuitBuilder<EF> {
    let mut circuit = CircuitBuilder::<EF>::new();
    let perm = default_babybear_poseidon2_16();
    circuit.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<EF, BabyBearD4Width16>,
        perm,
    );
    circuit
}

/// Test basic observe/sample transcript compatibility.
#[test]
fn test_transcript_single_observe_sample() {
    let perm = default_babybear_poseidon2_16();

    // Native challenger
    let mut native = DuplexChallenger::<F, _, WIDTH, RATE>::new(perm);

    // Circuit challenger
    let mut circuit = setup_circuit_with_poseidon2();
    let mut circuit_challenger = CircuitChallenger::<WIDTH, RATE>::new_babybear();

    // Observe a single value
    let val = F::from_u64(42);
    native.observe(val);
    let val_target = circuit.define_const(EF::from(val));
    RecursiveChallenger::<F, EF>::observe(&mut circuit_challenger, &mut circuit, val_target);

    // Fill to RATE to trigger duplexing
    for i in 1..RATE {
        let v = F::from_u64(i as u64);
        native.observe(v);
        let v_t = circuit.define_const(EF::from(v));
        RecursiveChallenger::<F, EF>::observe(&mut circuit_challenger, &mut circuit, v_t);
    }

    // Sample and compare
    let native_sample: F = native.sample();
    let circuit_sample =
        RecursiveChallenger::<F, EF>::sample(&mut circuit_challenger, &mut circuit);

    // Connect circuit sample to expected native value
    let expected = circuit.define_const(EF::from(native_sample));
    circuit.connect(circuit_sample, expected);

    // Build and run - if values match, no WitnessConflict
    let compiled = circuit.build().expect("Circuit should build");
    let runner = compiled.runner();
    let traces: Traces<EF> = runner
        .run()
        .expect("Single observe/sample should match native");

    assert!(
        traces.witness_trace.num_rows() > 0,
        "Should produce witness trace"
    );
}

/// Test observe_ext matches native observe_base_as_algebra_element.
#[test]
fn test_transcript_observe_ext_compatibility() {
    let perm = default_babybear_poseidon2_16();

    let mut native = DuplexChallenger::<F, _, WIDTH, RATE>::new(perm);
    let mut circuit = setup_circuit_with_poseidon2();
    let mut circuit_challenger = CircuitChallenger::<WIDTH, RATE>::new_babybear();

    // Observe a base value as algebra element (like batch-STARK does)
    let base_val = F::from_usize(123);
    native.observe_base_as_algebra_element::<EF>(base_val);
    let val_target = circuit.define_const(EF::from(base_val));
    RecursiveChallenger::<F, EF>::observe_ext(&mut circuit_challenger, &mut circuit, val_target);

    // Observe another value
    let base_val2 = F::from_usize(456);
    native.observe_base_as_algebra_element::<EF>(base_val2);
    let val_target2 = circuit.define_const(EF::from(base_val2));
    RecursiveChallenger::<F, EF>::observe_ext(&mut circuit_challenger, &mut circuit, val_target2);

    // Sample extension element
    let native_ext: EF = native.sample_algebra_element();
    let circuit_ext =
        RecursiveChallenger::<F, EF>::sample_ext(&mut circuit_challenger, &mut circuit);

    let expected = circuit.define_const(native_ext);
    circuit.connect(circuit_ext, expected);

    let compiled = circuit.build().expect("Circuit should build");
    let traces: Traces<EF> = compiled
        .runner()
        .run()
        .expect("observe_ext should match native observe_base_as_algebra_element");

    assert!(traces.witness_trace.num_rows() > 0);
}

/// Test multiple duplexing rounds maintain transcript compatibility.
#[test]
fn test_transcript_multiple_duplexing_rounds() {
    let perm = default_babybear_poseidon2_16();

    let mut native = DuplexChallenger::<F, _, WIDTH, RATE>::new(perm);
    let mut circuit = setup_circuit_with_poseidon2();
    let mut circuit_challenger = CircuitChallenger::<WIDTH, RATE>::new_babybear();

    // First round: observe RATE elements
    for i in 0..RATE {
        let val = F::from_u64(i as u64 + 100);
        native.observe(val);
        let t = circuit.define_const(EF::from(val));
        RecursiveChallenger::<F, EF>::observe(&mut circuit_challenger, &mut circuit, t);
    }

    // Sample after first round
    let native_s1: F = native.sample();
    let circuit_s1 = RecursiveChallenger::<F, EF>::sample(&mut circuit_challenger, &mut circuit);
    let expected_s1 = circuit.define_const(EF::from(native_s1));
    circuit.connect(circuit_s1, expected_s1);

    // Second round: observe more elements
    for i in 0..RATE {
        let val = F::from_u64(i as u64 + 200);
        native.observe(val);
        let t = circuit.define_const(EF::from(val));
        RecursiveChallenger::<F, EF>::observe(&mut circuit_challenger, &mut circuit, t);
    }

    // Sample after second round
    let native_s2: F = native.sample();
    let circuit_s2 = RecursiveChallenger::<F, EF>::sample(&mut circuit_challenger, &mut circuit);
    let expected_s2 = circuit.define_const(EF::from(native_s2));
    circuit.connect(circuit_s2, expected_s2);

    // Third round with extension samples
    for i in 0..4 {
        let val = F::from_u64(i as u64 + 300);
        native.observe_base_as_algebra_element::<EF>(val);
        let t = circuit.define_const(EF::from(val));
        RecursiveChallenger::<F, EF>::observe_ext(&mut circuit_challenger, &mut circuit, t);
    }

    let native_ext: EF = native.sample_algebra_element();
    let circuit_ext =
        RecursiveChallenger::<F, EF>::sample_ext(&mut circuit_challenger, &mut circuit);
    let expected_ext = circuit.define_const(native_ext);
    circuit.connect(circuit_ext, expected_ext);

    let compiled = circuit.build().expect("Circuit should build");
    let traces: Traces<EF> = compiled
        .runner()
        .run()
        .expect("Multiple duplexing rounds should match native");

    assert!(traces.witness_trace.num_rows() > 0);
}

/// Test partial absorption (less than RATE) then sample.
#[test]
fn test_transcript_partial_absorption() {
    let perm = default_babybear_poseidon2_16();

    let mut native = DuplexChallenger::<F, _, WIDTH, RATE>::new(perm);
    let mut circuit = setup_circuit_with_poseidon2();
    let mut circuit_challenger = CircuitChallenger::<WIDTH, RATE>::new_babybear();

    // Observe only 3 elements (less than RATE=8)
    for i in 0..3 {
        let val = F::from_u64(i as u64 + 50);
        native.observe(val);
        let t = circuit.define_const(EF::from(val));
        RecursiveChallenger::<F, EF>::observe(&mut circuit_challenger, &mut circuit, t);
    }

    // Sample triggers duplexing with partial input
    let native_sample: F = native.sample();
    let circuit_sample =
        RecursiveChallenger::<F, EF>::sample(&mut circuit_challenger, &mut circuit);

    let expected = circuit.define_const(EF::from(native_sample));
    circuit.connect(circuit_sample, expected);

    let compiled = circuit.build().expect("Circuit should build");
    let traces: Traces<EF> = compiled
        .runner()
        .run()
        .expect("Partial absorption should match native");

    assert!(traces.witness_trace.num_rows() > 0);
}

/// Test extension field element observation (observe_algebra_element equivalent).
#[test]
fn test_transcript_observe_extension_element() {
    let perm = default_babybear_poseidon2_16();

    let mut native = DuplexChallenger::<F, _, WIDTH, RATE>::new(perm);
    let mut circuit = setup_circuit_with_poseidon2();
    let mut circuit_challenger = CircuitChallenger::<WIDTH, RATE>::new_babybear();

    // Create extension field elements
    let ext_val = EF::from_basis_coefficients_slice(&[
        F::from_u64(10),
        F::from_u64(20),
        F::from_u64(30),
        F::from_u64(40),
    ])
    .unwrap();

    // Native: observe_algebra_element decomposes to D coefficients
    native.observe_algebra_element(ext_val);
    // Circuit: observe_ext does the same decomposition
    let ext_target = circuit.define_const(ext_val);
    RecursiveChallenger::<F, EF>::observe_ext(&mut circuit_challenger, &mut circuit, ext_target);

    // Observe more to trigger duplexing
    let ext_val2 = EF::from_basis_coefficients_slice(&[
        F::from_u64(11),
        F::from_u64(21),
        F::from_u64(31),
        F::from_u64(41),
    ])
    .unwrap();
    native.observe_algebra_element(ext_val2);
    let ext_target2 = circuit.define_const(ext_val2);
    RecursiveChallenger::<F, EF>::observe_ext(&mut circuit_challenger, &mut circuit, ext_target2);

    // Sample and compare
    let native_ext: EF = native.sample_algebra_element();
    let circuit_ext =
        RecursiveChallenger::<F, EF>::sample_ext(&mut circuit_challenger, &mut circuit);

    let expected = circuit.define_const(native_ext);
    circuit.connect(circuit_ext, expected);

    let compiled = circuit.build().expect("Circuit should build");
    let traces: Traces<EF> = compiled
        .runner()
        .run()
        .expect("Extension element observation should match native");

    assert!(traces.witness_trace.num_rows() > 0);
}

/// Test mixed observation types (base and extension).
#[test]
fn test_transcript_mixed_observations() {
    let perm = default_babybear_poseidon2_16();

    let mut native = DuplexChallenger::<F, _, WIDTH, RATE>::new(perm);
    let mut circuit = setup_circuit_with_poseidon2();
    let mut circuit_challenger = CircuitChallenger::<WIDTH, RATE>::new_babybear();

    // Mix of base field observations
    for i in 0..3 {
        let val = F::from_u64(i as u64);
        native.observe(val);
        let t = circuit.define_const(EF::from(val));
        RecursiveChallenger::<F, EF>::observe(&mut circuit_challenger, &mut circuit, t);
    }

    // Extension field observation
    let base_as_ext = F::from_usize(999);
    native.observe_base_as_algebra_element::<EF>(base_as_ext);
    let t = circuit.define_const(EF::from(base_as_ext));
    RecursiveChallenger::<F, EF>::observe_ext(&mut circuit_challenger, &mut circuit, t);

    // More base observations
    for i in 0..2 {
        let val = F::from_u64(i as u64 + 100);
        native.observe(val);
        let t = circuit.define_const(EF::from(val));
        RecursiveChallenger::<F, EF>::observe(&mut circuit_challenger, &mut circuit, t);
    }

    // Sample base field element
    let native_base: F = native.sample();
    let circuit_base = RecursiveChallenger::<F, EF>::sample(&mut circuit_challenger, &mut circuit);
    let expected_base = circuit.define_const(EF::from(native_base));
    circuit.connect(circuit_base, expected_base);

    // Sample extension field element
    let native_ext: EF = native.sample_algebra_element();
    let circuit_ext =
        RecursiveChallenger::<F, EF>::sample_ext(&mut circuit_challenger, &mut circuit);
    let expected_ext = circuit.define_const(native_ext);
    circuit.connect(circuit_ext, expected_ext);

    let compiled = circuit.build().expect("Circuit should build");
    let traces: Traces<EF> = compiled
        .runner()
        .run()
        .expect("Mixed observations should match native");

    assert!(traces.witness_trace.num_rows() > 0);
}

/// Test circuit challenger clear functionality.
/// Native DuplexChallenger doesn't have clear, so we verify circuit clear
/// produces consistent state (fresh zero state).
#[test]
fn test_transcript_clear_produces_fresh_state() {
    let perm = default_babybear_poseidon2_16();

    // Create a fresh native challenger (simulating what clear does)
    let mut native = DuplexChallenger::<F, _, WIDTH, RATE>::new(perm);

    let mut circuit = setup_circuit_with_poseidon2();
    let mut circuit_challenger = CircuitChallenger::<WIDTH, RATE>::new_babybear();

    // First, do some observations to dirty the state
    for i in 0..5 {
        let val = F::from_u64(i as u64);
        let t = circuit.define_const(EF::from(val));
        RecursiveChallenger::<F, EF>::observe(&mut circuit_challenger, &mut circuit, t);
    }

    // Clear circuit challenger (resets to fresh zero state)
    RecursiveChallenger::<F, EF>::clear(&mut circuit_challenger, &mut circuit);

    // Now both should be in equivalent fresh states
    // Observe same values in both
    for i in 0..RATE {
        let val = F::from_u64(i as u64 + 1000);
        native.observe(val);
        let t = circuit.define_const(EF::from(val));
        RecursiveChallenger::<F, EF>::observe(&mut circuit_challenger, &mut circuit, t);
    }

    // Sample should match
    let native_sample: F = native.sample();
    let circuit_sample =
        RecursiveChallenger::<F, EF>::sample(&mut circuit_challenger, &mut circuit);

    let expected = circuit.define_const(EF::from(native_sample));
    circuit.connect(circuit_sample, expected);

    let compiled = circuit.build().expect("Circuit should build");
    let traces: Traces<EF> = compiled
        .runner()
        .run()
        .expect("Clear should produce fresh state matching new challenger");

    assert!(traces.witness_trace.num_rows() > 0);
}

/// Test multiple consecutive samples without intermediate observations.
#[test]
fn test_transcript_consecutive_samples() {
    let perm = default_babybear_poseidon2_16();

    let mut native = DuplexChallenger::<F, _, WIDTH, RATE>::new(perm);
    let mut circuit = setup_circuit_with_poseidon2();
    let mut circuit_challenger = CircuitChallenger::<WIDTH, RATE>::new_babybear();

    // Initial observations
    for i in 0..RATE {
        let val = F::from_u64(i as u64 + 77);
        native.observe(val);
        let t = circuit.define_const(EF::from(val));
        RecursiveChallenger::<F, EF>::observe(&mut circuit_challenger, &mut circuit, t);
    }

    // Multiple consecutive samples
    for _ in 0..5 {
        let native_s: F = native.sample();
        let circuit_s = RecursiveChallenger::<F, EF>::sample(&mut circuit_challenger, &mut circuit);
        let expected = circuit.define_const(EF::from(native_s));
        circuit.connect(circuit_s, expected);
    }

    let compiled = circuit.build().expect("Circuit should build");
    let traces: Traces<EF> = compiled
        .runner()
        .run()
        .expect("Consecutive samples should match native");

    assert!(traces.witness_trace.num_rows() > 0);
}

// ============================================================================
// Edge Case Tests
// ============================================================================

/// Edge case: Exactly RATE observations triggers duplexing, then sample.
/// Tests the boundary condition when input buffer is exactly full.
#[test]
fn test_edge_case_exactly_rate_observations() {
    let perm = default_babybear_poseidon2_16();

    let mut native = DuplexChallenger::<F, _, WIDTH, RATE>::new(perm);
    let mut circuit = setup_circuit_with_poseidon2();
    let mut circuit_challenger = CircuitChallenger::<WIDTH, RATE>::new_babybear();

    // Observe exactly RATE elements (should trigger duplexing on last observe)
    for i in 0..RATE {
        let val = F::from_u64(i as u64 + 500);
        native.observe(val);
        let t = circuit.define_const(EF::from(val));
        RecursiveChallenger::<F, EF>::observe(&mut circuit_challenger, &mut circuit, t);
    }

    // At this point, input buffer should be empty (duplexing occurred)
    // and output buffer should be full

    // Sample should come from output buffer without triggering new duplexing
    let native_s1: F = native.sample();
    let circuit_s1 = RecursiveChallenger::<F, EF>::sample(&mut circuit_challenger, &mut circuit);
    let expected_s1 = circuit.define_const(EF::from(native_s1));
    circuit.connect(circuit_s1, expected_s1);

    // Sample again to verify output buffer state
    let native_s2: F = native.sample();
    let circuit_s2 = RecursiveChallenger::<F, EF>::sample(&mut circuit_challenger, &mut circuit);
    let expected_s2 = circuit.define_const(EF::from(native_s2));
    circuit.connect(circuit_s2, expected_s2);

    let compiled = circuit.build().expect("Circuit should build");
    let traces: Traces<EF> = compiled
        .runner()
        .run()
        .expect("Exactly RATE observations should match native");

    assert!(traces.witness_trace.num_rows() > 0);
}

/// Edge case: Drain entire output buffer (RATE samples) then sample again.
/// This triggers a new duplexing when output buffer is empty.
#[test]
fn test_edge_case_drain_output_buffer_completely() {
    let perm = default_babybear_poseidon2_16();

    let mut native = DuplexChallenger::<F, _, WIDTH, RATE>::new(perm);
    let mut circuit = setup_circuit_with_poseidon2();
    let mut circuit_challenger = CircuitChallenger::<WIDTH, RATE>::new_babybear();

    // Observe RATE elements to trigger duplexing
    for i in 0..RATE {
        let val = F::from_u64(i as u64 + 600);
        native.observe(val);
        let t = circuit.define_const(EF::from(val));
        RecursiveChallenger::<F, EF>::observe(&mut circuit_challenger, &mut circuit, t);
    }

    // Drain entire output buffer (RATE samples)
    for j in 0..RATE {
        let native_s: F = native.sample();
        let circuit_s = RecursiveChallenger::<F, EF>::sample(&mut circuit_challenger, &mut circuit);
        let expected = circuit.define_const(EF::from(native_s));
        circuit.connect(circuit_s, expected);

        // Verify we got a valid sample at each step
        if j == RATE - 1 {
            // Last sample from output buffer
        }
    }

    // Now output buffer is empty - this sample should trigger new duplexing
    let native_extra: F = native.sample();
    let circuit_extra = RecursiveChallenger::<F, EF>::sample(&mut circuit_challenger, &mut circuit);
    let expected_extra = circuit.define_const(EF::from(native_extra));
    circuit.connect(circuit_extra, expected_extra);

    let compiled = circuit.build().expect("Circuit should build");
    let traces: Traces<EF> = compiled
        .runner()
        .run()
        .expect("Draining output buffer then sampling should match native");

    assert!(traces.witness_trace.num_rows() > 0);
}

/// Edge case: Interleaved observe/sample pattern.
/// Tests complex state transitions with alternating operations.
#[test]
fn test_edge_case_interleaved_observe_sample() {
    let perm = default_babybear_poseidon2_16();

    let mut native = DuplexChallenger::<F, _, WIDTH, RATE>::new(perm);
    let mut circuit = setup_circuit_with_poseidon2();
    let mut circuit_challenger = CircuitChallenger::<WIDTH, RATE>::new_babybear();

    // Pattern: observe a few, sample, observe more, sample, etc.
    // This tests output buffer invalidation on observe

    // Observe 3
    for i in 0..3 {
        let val = F::from_u64(i as u64 + 700);
        native.observe(val);
        let t = circuit.define_const(EF::from(val));
        RecursiveChallenger::<F, EF>::observe(&mut circuit_challenger, &mut circuit, t);
    }

    // Sample (triggers duplexing with 3 inputs)
    let native_s1: F = native.sample();
    let circuit_s1 = RecursiveChallenger::<F, EF>::sample(&mut circuit_challenger, &mut circuit);
    let expected_s1 = circuit.define_const(EF::from(native_s1));
    circuit.connect(circuit_s1, expected_s1);

    // Observe 2 more (invalidates output buffer)
    for i in 0..2 {
        let val = F::from_u64(i as u64 + 800);
        native.observe(val);
        let t = circuit.define_const(EF::from(val));
        RecursiveChallenger::<F, EF>::observe(&mut circuit_challenger, &mut circuit, t);
    }

    // Sample (triggers new duplexing with 2 inputs)
    let native_s2: F = native.sample();
    let circuit_s2 = RecursiveChallenger::<F, EF>::sample(&mut circuit_challenger, &mut circuit);
    let expected_s2 = circuit.define_const(EF::from(native_s2));
    circuit.connect(circuit_s2, expected_s2);

    // Sample again (from output buffer)
    let native_s3: F = native.sample();
    let circuit_s3 = RecursiveChallenger::<F, EF>::sample(&mut circuit_challenger, &mut circuit);
    let expected_s3 = circuit.define_const(EF::from(native_s3));
    circuit.connect(circuit_s3, expected_s3);

    // Observe 1 more
    let val = F::from_u64(900);
    native.observe(val);
    let t = circuit.define_const(EF::from(val));
    RecursiveChallenger::<F, EF>::observe(&mut circuit_challenger, &mut circuit, t);

    // Final sample
    let native_s4: F = native.sample();
    let circuit_s4 = RecursiveChallenger::<F, EF>::sample(&mut circuit_challenger, &mut circuit);
    let expected_s4 = circuit.define_const(EF::from(native_s4));
    circuit.connect(circuit_s4, expected_s4);

    let compiled = circuit.build().expect("Circuit should build");
    let traces: Traces<EF> = compiled
        .runner()
        .run()
        .expect("Interleaved observe/sample should match native");

    assert!(traces.witness_trace.num_rows() > 0);
}

/// Edge case: Sample immediately without any observations.
/// Tests initial state sampling behavior.
#[test]
fn test_edge_case_sample_without_observations() {
    let perm = default_babybear_poseidon2_16();

    let mut native = DuplexChallenger::<F, _, WIDTH, RATE>::new(perm);
    let mut circuit = setup_circuit_with_poseidon2();
    let mut circuit_challenger = CircuitChallenger::<WIDTH, RATE>::new_babybear();

    // Sample immediately (duplexing with zero-initialized state)
    let native_s1: F = native.sample();
    let circuit_s1 = RecursiveChallenger::<F, EF>::sample(&mut circuit_challenger, &mut circuit);
    let expected_s1 = circuit.define_const(EF::from(native_s1));
    circuit.connect(circuit_s1, expected_s1);

    // Sample again
    let native_s2: F = native.sample();
    let circuit_s2 = RecursiveChallenger::<F, EF>::sample(&mut circuit_challenger, &mut circuit);
    let expected_s2 = circuit.define_const(EF::from(native_s2));
    circuit.connect(circuit_s2, expected_s2);

    let compiled = circuit.build().expect("Circuit should build");
    let traces: Traces<EF> = compiled
        .runner()
        .run()
        .expect("Sample without observations should match native");

    assert!(traces.witness_trace.num_rows() > 0);
}

/// Edge case: Observe single element then sample multiple times.
/// Tests output buffer usage after minimal input.
#[test]
fn test_edge_case_single_observe_multiple_samples() {
    let perm = default_babybear_poseidon2_16();

    let mut native = DuplexChallenger::<F, _, WIDTH, RATE>::new(perm);
    let mut circuit = setup_circuit_with_poseidon2();
    let mut circuit_challenger = CircuitChallenger::<WIDTH, RATE>::new_babybear();

    // Single observation
    let val = F::from_u64(12345);
    native.observe(val);
    let t = circuit.define_const(EF::from(val));
    RecursiveChallenger::<F, EF>::observe(&mut circuit_challenger, &mut circuit, t);

    // Multiple samples (first triggers duplexing, rest from buffer)
    for _ in 0..RATE {
        let native_s: F = native.sample();
        let circuit_s = RecursiveChallenger::<F, EF>::sample(&mut circuit_challenger, &mut circuit);
        let expected = circuit.define_const(EF::from(native_s));
        circuit.connect(circuit_s, expected);
    }

    let compiled = circuit.build().expect("Circuit should build");
    let traces: Traces<EF> = compiled
        .runner()
        .run()
        .expect("Single observe then multiple samples should match native");

    assert!(traces.witness_trace.num_rows() > 0);
}

/// Edge case: Extension field samples draining output buffer.
/// Each sample_ext consumes D base elements from output.
#[test]
fn test_edge_case_extension_samples_drain_buffer() {
    let perm = default_babybear_poseidon2_16();

    let mut native = DuplexChallenger::<F, _, WIDTH, RATE>::new(perm);
    let mut circuit = setup_circuit_with_poseidon2();
    let mut circuit_challenger = CircuitChallenger::<WIDTH, RATE>::new_babybear();

    // Observe RATE elements
    for i in 0..RATE {
        let val = F::from_u64(i as u64 + 1000);
        native.observe(val);
        let t = circuit.define_const(EF::from(val));
        RecursiveChallenger::<F, EF>::observe(&mut circuit_challenger, &mut circuit, t);
    }

    // Sample extension elements (each consumes 4 base elements from RATE=8 buffer)
    // After 2 ext samples, buffer is empty
    let native_ext1: EF = native.sample_algebra_element();
    let circuit_ext1 =
        RecursiveChallenger::<F, EF>::sample_ext(&mut circuit_challenger, &mut circuit);
    let expected_ext1 = circuit.define_const(native_ext1);
    circuit.connect(circuit_ext1, expected_ext1);

    let native_ext2: EF = native.sample_algebra_element();
    let circuit_ext2 =
        RecursiveChallenger::<F, EF>::sample_ext(&mut circuit_challenger, &mut circuit);
    let expected_ext2 = circuit.define_const(native_ext2);
    circuit.connect(circuit_ext2, expected_ext2);

    // Third ext sample should trigger new duplexing
    let native_ext3: EF = native.sample_algebra_element();
    let circuit_ext3 =
        RecursiveChallenger::<F, EF>::sample_ext(&mut circuit_challenger, &mut circuit);
    let expected_ext3 = circuit.define_const(native_ext3);
    circuit.connect(circuit_ext3, expected_ext3);

    let compiled = circuit.build().expect("Circuit should build");
    let traces: Traces<EF> = compiled
        .runner()
        .run()
        .expect("Extension samples draining buffer should match native");

    assert!(traces.witness_trace.num_rows() > 0);
}
