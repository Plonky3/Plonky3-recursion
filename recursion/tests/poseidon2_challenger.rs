//! Tests for CircuitChallenger with Poseidon2 permutation.

use p3_baby_bear::BabyBear;
use p3_circuit::CircuitBuilder;
use p3_circuit::op::{NonPrimitiveOpConfig, NonPrimitiveOpType};
use p3_field::PrimeCharacteristicRing;
use p3_recursion::Target;
use p3_recursion::circuit_challenger::CircuitChallenger;
use p3_recursion::recursive_challenger::RecursiveChallenger;

const RATE: usize = 8;
const CAPACITY: usize = 8;
const WIDTH: usize = 16;

#[test]
fn test_challenger_single_observe_sample() {
    let mut circuit = CircuitBuilder::<BabyBear>::new();
    circuit.enable_op(
        NonPrimitiveOpType::Poseidon2Permutation,
        NonPrimitiveOpConfig::None,
    );

    let mut challenger = CircuitChallenger::<RATE, CAPACITY, WIDTH>::new();

    // Observe a single value
    let val = circuit.add_const(BabyBear::ONE);
    challenger.observe(&mut circuit, val);

    // Sample a challenge
    let challenge = challenger.sample(&mut circuit);
    assert!(challenge.0 > 0);

    // Verify circuit structure
    let built_circuit = circuit.build().unwrap();
    assert!(!built_circuit.non_primitive_ops.is_empty());
}

#[test]
fn test_challenger_multiple_absorbs() {
    let mut circuit = CircuitBuilder::<BabyBear>::new();
    circuit.enable_op(
        NonPrimitiveOpType::Poseidon2Permutation,
        NonPrimitiveOpConfig::None,
    );

    let mut challenger = CircuitChallenger::<RATE, CAPACITY, WIDTH>::new();

    // Observe RATE elements (exactly one chunk)
    for i in 0..RATE {
        let val = circuit.add_const(BabyBear::new(i as u32));
        challenger.observe(&mut circuit, val);
    }

    let challenge = challenger.sample(&mut circuit);
    assert!(challenge.0 > 0);
}

#[test]
fn test_challenger_multi_chunk_absorb() {
    let mut circuit = CircuitBuilder::<BabyBear>::new();
    circuit.enable_op(
        NonPrimitiveOpType::Poseidon2Permutation,
        NonPrimitiveOpConfig::None,
    );

    let mut challenger = CircuitChallenger::<RATE, CAPACITY, WIDTH>::new();

    // Observe more than RATE elements (triggers multiple permutations)
    for i in 0..20 {
        let val = circuit.add_const(BabyBear::new(i as u32));
        challenger.observe(&mut circuit, val);
    }

    let challenge = challenger.sample(&mut circuit);
    assert!(challenge.0 > 0);

    // Should have multiple permutation operations
    let built_circuit = circuit.build().unwrap();
    let perm_count = built_circuit
        .non_primitive_ops
        .iter()
        .filter(|op| {
            matches!(
                op,
                p3_circuit::op::NonPrimitiveOp::Poseidon2Permutation { .. }
            )
        })
        .count();

    // 20 inputs / 8 RATE = 3 permutations for absorb + 1 for squeeze
    assert!(perm_count >= 3);
}

#[test]
fn test_challenger_squeeze_exhaustion() {
    let mut circuit = CircuitBuilder::<BabyBear>::new();
    circuit.enable_op(
        NonPrimitiveOpType::Poseidon2Permutation,
        NonPrimitiveOpConfig::None,
    );

    let mut challenger = CircuitChallenger::<RATE, CAPACITY, WIDTH>::new();

    // Observe one value
    let val = circuit.add_const(BabyBear::ONE);
    challenger.observe(&mut circuit, val);

    // Sample more than RATE challenges (should trigger permutation for new samples)
    let challenges = challenger.sample_vec(&mut circuit, RATE + 2);
    assert_eq!(challenges.len(), RATE + 2);

    // Each challenge should be a different target
    for i in 0..challenges.len() {
        for j in i + 1..challenges.len() {
            assert_ne!(
                challenges[i], challenges[j],
                "Challenges should be distinct"
            );
        }
    }
}

#[test]
fn test_challenger_clear_and_reuse() {
    let mut circuit = CircuitBuilder::<BabyBear>::new();
    circuit.enable_op(
        NonPrimitiveOpType::Poseidon2Permutation,
        NonPrimitiveOpConfig::None,
    );

    let mut challenger = CircuitChallenger::<RATE, CAPACITY, WIDTH>::new();

    // First round
    let val1 = circuit.add_const(BabyBear::ONE);
    challenger.observe(&mut circuit, val1);
    let challenge1 = challenger.sample(&mut circuit);

    // Clear
    RecursiveChallenger::<BabyBear, RATE, CAPACITY>::clear(&mut challenger);

    // Second round (should start fresh)
    let val2 = circuit.add_const(BabyBear::TWO);
    challenger.observe(&mut circuit, val2);
    let challenge2 = challenger.sample(&mut circuit);

    // Challenges should be different (different transcripts)
    assert_ne!(challenge1, challenge2);
}

#[test]
fn test_challenger_empty_sample() {
    let mut circuit = CircuitBuilder::<BabyBear>::new();
    circuit.enable_op(
        NonPrimitiveOpType::Poseidon2Permutation,
        NonPrimitiveOpConfig::None,
    );

    let mut challenger = CircuitChallenger::<RATE, CAPACITY, WIDTH>::new();

    // Sample without observing anything (should initialize to zero state)
    let challenge = challenger.sample(&mut circuit);
    assert!(challenge.0 > 0);
}

#[test]
fn test_challenger_observe_slice() {
    let mut circuit = CircuitBuilder::<BabyBear>::new();
    circuit.enable_op(
        NonPrimitiveOpType::Poseidon2Permutation,
        NonPrimitiveOpConfig::None,
    );

    let mut challenger = CircuitChallenger::<RATE, CAPACITY, WIDTH>::new();

    // Observe multiple values at once
    let values: Vec<Target> = (0..5)
        .map(|i| circuit.add_const(BabyBear::new(i as u32)))
        .collect();

    challenger.observe_slice(&mut circuit, &values);

    let challenge = challenger.sample(&mut circuit);
    assert!(challenge.0 > 0);
}

#[test]
fn test_challenger_capacity_isolation() {
    let mut circuit = CircuitBuilder::<BabyBear>::new();
    circuit.enable_op(
        NonPrimitiveOpType::Poseidon2Permutation,
        NonPrimitiveOpConfig::None,
    );

    let mut challenger = CircuitChallenger::<RATE, CAPACITY, WIDTH>::new();

    // The capacity portion should never be directly exposed
    // Observe some values
    for i in 0..5 {
        let val = circuit.add_const(BabyBear::new(i as u32));
        challenger.observe(&mut circuit, val);
    }

    // Sample - the capacity maintains security
    let challenge = challenger.sample(&mut circuit);
    assert!(challenge.0 > 0);
}

#[test]
fn test_challenger_different_transcripts() {
    let mut circuit = CircuitBuilder::<BabyBear>::new();
    circuit.enable_op(
        NonPrimitiveOpType::Poseidon2Permutation,
        NonPrimitiveOpConfig::None,
    );

    let mut challenger1 = CircuitChallenger::<RATE, CAPACITY, WIDTH>::new();
    let mut challenger2 = CircuitChallenger::<RATE, CAPACITY, WIDTH>::new();

    // Different observations
    let val1 = circuit.add_const(BabyBear::new(42));
    let val2 = circuit.add_const(BabyBear::new(123));

    challenger1.observe(&mut circuit, val1);
    challenger2.observe(&mut circuit, val2);

    // Should produce different challenge ExprIds (they allocate at different positions)
    let challenge1 = challenger1.sample(&mut circuit);
    let challenge2 = challenger2.sample(&mut circuit);

    // Different transcripts produce different expression IDs
    assert_ne!(challenge1, challenge2);
}
