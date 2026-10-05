//! Raw coordinates must not pass through integer ring embeddings.

use p3_binary_field::{BinaryField8, BinaryField128, Ghash128, Poly64};
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::{CircuitBuilder, CircuitBuilderError};
use p3_field::PrimeCharacteristicRing;

fn roundtrip<F: BinaryCoordinateField>(raw: u128) {
    let value = F::from_raw_coordinates(raw).unwrap();
    assert_eq!(value.to_raw_coordinates(), raw);
    let mut builder = CircuitBuilder::<F>::new();
    let input = builder.public_input();
    let expected_bits: Vec<_> = (0..F::COORDINATE_BITS)
        .map(|_| builder.public_input())
        .collect();
    let bits = builder
        .binary_decompose_coordinates(input, F::COORDINATE_BITS)
        .unwrap();
    for (&actual, &expected) in bits.iter().zip(&expected_bits) {
        builder.connect(actual, expected);
    }
    let reconstructed = builder.binary_recompose_coordinates(&bits).unwrap();
    builder.connect(reconstructed, input);
    let circuit = builder.build().unwrap();
    let public: Vec<_> = core::iter::once(value)
        .chain((0..F::COORDINATE_BITS).map(|i| F::from_bool(raw >> i & 1 != 0)))
        .collect();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    runner.run().unwrap();
    let mut changed = public;
    changed[F::COORDINATE_BITS] += F::ONE;
    let mut runner = circuit.runner();
    assert!(
        runner
            .set_public_inputs(&changed)
            .and_then(|()| runner.run())
            .is_err()
    );
}

#[test]
fn dense_tower_polynomial_and_ghash_coordinates_roundtrip() {
    roundtrip::<BinaryField8>(0xfa);
    roundtrip::<BinaryField128>(0xfedc_ba98_7654_3210_8123_4567_89ab_cdef);
    roundtrip::<Ghash128>(0x8000_0000_0000_0000_0000_0000_0000_0002);
    roundtrip::<Poly64>(0xdead_beef_abcd_1234);
    assert_ne!(
        BinaryField128::from_raw_coordinates(2).unwrap(),
        BinaryField128::from_u8(2)
    );
}

#[test]
fn partial_decomposition_enforces_the_coordinate_span() {
    let mut builder = CircuitBuilder::<BinaryField128>::new();
    let byte = builder.public_input();
    builder.binary_decompose_coordinates(byte, 8).unwrap();
    let circuit = builder.build().unwrap();
    for raw in [0, 0xff] {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&[BinaryField128::from_raw_coordinates(raw).unwrap()])
            .unwrap();
        runner.run().unwrap();
    }
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[BinaryField128::from_raw_coordinates(1 << 8).unwrap()])
        .unwrap();
    assert!(runner.run().is_err());

    let mut builder = CircuitBuilder::<Poly64>::new();
    let input = builder.public_input();
    assert!(
        builder
            .binary_decompose_coordinates(input, 0)
            .unwrap()
            .is_empty()
    );
    let circuit = builder.build().unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&[Poly64::ZERO]).unwrap();
    runner.run().unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&[Poly64::ONE]).unwrap();
    assert!(runner.run().is_err());
}

#[test]
fn oversized_coordinates_and_bit_counts_are_rejected_without_truncation() {
    assert!(BinaryField8::from_raw_coordinates(1 << 8).is_none());
    assert!(Poly64::from_raw_coordinates(1 << 64).is_none());
    assert_eq!(
        BinaryField128::from_raw_coordinates(u128::MAX)
            .unwrap()
            .to_raw_coordinates(),
        u128::MAX
    );
    let mut builder = CircuitBuilder::<Poly64>::new();
    let input = builder.public_input();
    assert!(matches!(
        builder.binary_decompose_coordinates(input, 65),
        Err(CircuitBuilderError::BinaryDecompositionTooManyBits { .. })
    ));
    assert!(matches!(
        builder.binary_recompose_coordinates(&[input; 65]),
        Err(CircuitBuilderError::BinaryDecompositionTooManyBits { .. })
    ));
    let empty = builder.binary_recompose_coordinates(&[]).unwrap();
    let zero = builder.define_const(Poly64::ZERO);
    builder.connect(empty, zero);
    let circuit = builder.build().unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&[Poly64::ONE]).unwrap();
    runner.run().unwrap();
}

#[test]
fn repeated_and_recomposed_coordinates_reuse_their_checked_bits() {
    let mut builder = CircuitBuilder::<BinaryField128>::new();
    let input = builder.public_input();
    let bits = builder.binary_decompose_coordinates(input, 16).unwrap();
    assert_eq!(
        builder.binary_decompose_coordinates(input, 16).unwrap(),
        bits
    );
    let low = builder.binary_recompose_coordinates(&bits[..8]).unwrap();
    assert_eq!(
        builder.binary_decompose_coordinates(low, 8).unwrap(),
        bits[..8]
    );
    let widened = builder.binary_decompose_coordinates(low, 16).unwrap();
    assert_eq!(widened[..8], bits[..8]);
    assert!(
        widened[8..]
            .iter()
            .all(|&bit| bit == p3_circuit::ExprId::ZERO)
    );
    // A narrower request must still enforce the tighter span after a cache hit.
    assert_eq!(
        builder.binary_decompose_coordinates(input, 8).unwrap(),
        bits[..8]
    );
    let circuit = builder.build().unwrap();
    for (raw, accepted) in [(0xa5, true), (0x1a5, false)] {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&[BinaryField128::from_raw_coordinates(raw).unwrap()])
            .unwrap();
        assert_eq!(runner.run().is_ok(), accepted);
    }
}

#[test]
fn constant_coordinates_fold_without_hints_and_reject_high_bits() {
    let mut builder = CircuitBuilder::<Poly64>::new();
    let byte = builder.define_const(Poly64::new(0xa5));
    let bits = builder.binary_decompose_coordinates(byte, 8).unwrap();
    for (i, &bit) in bits.iter().enumerate() {
        let expected = builder.define_const(Poly64::from_bool(0xa5 >> i & 1 != 0));
        builder.connect(bit, expected);
    }
    assert!(builder.binary_decompose_coordinates(byte, 7).is_err());
    assert!(builder.binary_decompose_coordinates(byte, 0).is_err());
    let full = builder.define_const(Poly64::new(u64::MAX));
    assert_eq!(
        builder
            .binary_decompose_coordinates(full, 64)
            .unwrap()
            .len(),
        64
    );
    let zero = builder.define_const(Poly64::ZERO);
    assert!(
        builder
            .binary_decompose_coordinates(zero, 0)
            .unwrap()
            .is_empty()
    );
    let circuit = builder.build().unwrap();
    assert!(
        circuit
            .ops
            .iter()
            .all(|op| !matches!(op, p3_circuit::ops::Op::Hint { .. }))
    );
    let mut builder = CircuitBuilder::<BinaryField128>::new();
    let full = builder.define_const(BinaryField128::from_raw_coordinates(u128::MAX).unwrap());
    assert_eq!(
        builder
            .binary_decompose_coordinates(full, 128)
            .unwrap()
            .len(),
        128
    );
    assert!(builder.binary_decompose_coordinates(full, 127).is_err());
}
