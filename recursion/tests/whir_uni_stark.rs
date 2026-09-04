mod common;

use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_field::PrimeCharacteristicRing;
use p3_uni_stark::{prove, verify};

use crate::common::whir_config::{BbF, bb_whir_config};

/// The value [`generate_trace_rows::<BbF>(0, 1, n)`]'s last row claims as its
/// output, i.e. `F(n)` for the sequence started at `F(0) = 0`, `F(1) = 1`.
fn fibonacci_output(n: usize) -> BbF {
    let (mut a, mut b) = (BbF::ZERO, BbF::ONE);
    for _ in 1..n {
        let next = a + b;
        a = b;
        b = next;
    }
    b
}

/// A uni-STARK proved and verified with WHIR as its polynomial commitment scheme.
#[test]
fn fibonacci_uni_stark_over_whir_round_trips() {
    // Large enough that the committed polynomial's stacked arity needs the
    // intermediate WHIR round `bb_whir_config` below schedules (`folding = 4`
    // needs a stacked arity of at least 11 to avoid folding straight to the
    // direct-send threshold in one round).
    let n = 1 << 10;
    let x = fibonacci_output(n);
    let trace = generate_trace_rows::<BbF>(0, 1, n);
    let pis = vec![BbF::ZERO, BbF::ONE, x];
    let air = FibonacciAir {};

    // One intermediate WHIR round.
    let config = bb_whir_config(vec![4]);
    let proof = prove(&config, &air, trace, &pis);
    verify(&config, &air, &proof, &pis).expect("WHIR-backed uni-STARK verifies");
}

/// Corrupting a public input must make verification fail, proving the proof is
/// actually bound to the statement rather than trivially accepted.
#[test]
fn fibonacci_uni_stark_over_whir_rejects_a_wrong_public_input() {
    let n = 1 << 10;
    let x = fibonacci_output(n);
    let trace = generate_trace_rows::<BbF>(0, 1, n);
    let pis = vec![BbF::ZERO, BbF::ONE, x];
    let air = FibonacciAir {};

    let config = bb_whir_config(vec![4]);
    let proof = prove(&config, &air, trace, &pis);

    let wrong = vec![BbF::ZERO, BbF::ONE, x + BbF::ONE];
    assert!(verify(&config, &air, &proof, &wrong).is_err());
}
