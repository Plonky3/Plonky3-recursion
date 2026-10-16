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

fn sparse_coordinates<F: BinaryCoordinateField>() {
    use p3_circuit::ops::binary_native::BinaryCoordinateExtractor;
    let mut b = CircuitBuilder::<F>::new();
    let input = b.public_input();
    for column in 0..F::COORDINATE_BITS {
        let extractor = BinaryCoordinateExtractor::<F>::new(column).unwrap();
        let bit = extractor.extract(&mut b, input).unwrap();
        let expected = b.public_input();
        b.connect(bit, expected);
    }
    let circuit = b.build().unwrap();
    let mask = u128::MAX >> (128 - F::COORDINATE_BITS);
    let cases: Vec<u128> = if F::COORDINATE_BITS <= 4 {
        (0..=mask).collect()
    } else {
        [0, mask, 0xfedc_ba98_7654_3210_8123_4567_89ab_cdef & mask]
            .into_iter()
            .chain((0..F::COORDINATE_BITS).map(|i| 1u128 << i))
            .collect()
    };
    for raw in cases {
        let mut public = vec![F::from_raw_coordinates(raw).unwrap()];
        public.extend((0..F::COORDINATE_BITS).map(|i| F::from_bool(raw >> i & 1 != 0)));
        let accepts = |public: &[F]| {
            let mut runner = circuit.runner();
            runner
                .set_public_inputs(public)
                .and_then(|()| runner.run())
                .is_ok()
        };
        assert!(accepts(&public), "{raw:x}");
        public[1 + raw as usize % F::COORDINATE_BITS] += F::ONE;
        assert!(!accepts(&public));
    }
    assert!(BinaryCoordinateExtractor::<F>::new(F::COORDINATE_BITS).is_err());
    assert!(BinaryCoordinateExtractor::<F>::new(usize::MAX).is_err());
}

#[test]
fn sparse_coordinates_bind_each_sealed_field_basis() {
    use p3_binary_field::{
        BinaryField2, BinaryField4, BinaryField16, BinaryField32, BinaryField64, Gf2,
    };
    sparse_coordinates::<Gf2>();
    sparse_coordinates::<BinaryField2>();
    sparse_coordinates::<BinaryField4>();
    sparse_coordinates::<BinaryField8>();
    sparse_coordinates::<BinaryField16>();
    sparse_coordinates::<BinaryField32>();
    sparse_coordinates::<BinaryField64>();
    sparse_coordinates::<BinaryField128>();
    sparse_coordinates::<Ghash128>();
    sparse_coordinates::<Poly64>();
}

#[test]
fn sparse_coordinates_reuse_constants_and_checked_prefixes_without_claiming_other_bits() {
    use p3_circuit::ops::binary_native::BinaryCoordinateExtractor;
    use p3_circuit::{ExprId, Op};
    let extractor = BinaryCoordinateExtractor::<Poly64>::new(3).unwrap();
    let mut b = CircuitBuilder::<Poly64>::new();
    let constant = b.define_const(Poly64::new(0xa5));
    assert_eq!(extractor.extract(&mut b, constant).unwrap(), ExprId::ZERO);
    let input = b.public_input();
    let bits = b.binary_decompose_coordinates(input, 4).unwrap();
    let calls = b.construction_usage().unwrap().non_primitive_calls;
    assert_eq!(extractor.extract(&mut b, input).unwrap(), bits[3]);
    assert_eq!(
        BinaryCoordinateExtractor::<Poly64>::new(7)
            .unwrap()
            .extract(&mut b, input)
            .unwrap(),
        ExprId::ZERO
    );
    assert_eq!(b.construction_usage().unwrap().non_primitive_calls, calls);
    let circuit = b.build().unwrap();
    assert_eq!(
        circuit
            .ops
            .iter()
            .filter(|op| matches!(op, Op::Hint { .. }))
            .count(),
        1
    );
    for (raw, accepted) in [(0xf, true), (0x8f, false)] {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[Poly64::new(raw)]).unwrap();
        assert_eq!(runner.run().is_ok(), accepted);
    }

    // Reading one coordinate must leave the other coordinates unconstrained.
    // A later full decomposition must still supply and check all of them.
    let mut b = CircuitBuilder::<Poly64>::new();
    let input = b.public_input();
    let sparse = extractor.extract(&mut b, input).unwrap();
    let bits = b.binary_decompose_coordinates(input, 64).unwrap();
    b.connect(sparse, bits[3]);
    let expected = b.public_input();
    b.connect(bits[63], expected);
    let circuit = b.build().unwrap();
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[Poly64::new(0x8000_0000_0000_0008), Poly64::ONE])
        .unwrap();
    runner.run().unwrap();
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[Poly64::new(0x8000_0000_0000_0008), Poly64::ZERO])
        .unwrap();
    assert!(runner.run().is_err());
}

#[test]
fn sparse_coordinates_enforce_construction_limits() {
    use p3_circuit::CircuitConstructionLimits;
    use p3_circuit::ops::binary_native::BinaryCoordinateExtractor;
    let limits = CircuitConstructionLimits {
        max_expression_nodes: usize::MAX,
        max_pending_connects: usize::MAX,
        max_non_primitive_calls: 0,
        max_non_primitive_slots: usize::MAX,
    };
    let mut b = CircuitBuilder::<Poly64>::with_construction_limits(limits).unwrap();
    let input = b.public_input();
    assert!(matches!(
        BinaryCoordinateExtractor::<Poly64>::new(3)
            .unwrap()
            .extract(&mut b, input),
        Err(CircuitBuilderError::ConstructionLimitExceeded {
            component: "non-primitive calls",
            ..
        })
    ));
}

/// The hinted zero test answers zero and nonzero scalars, a run claiming the
/// wrong answer fails, and constant inputs fold. Forged inverses are covered
/// by the unit tests beside `binary_is_zero`.
fn zero_test<F: BinaryCoordinateField>(nonzero: u128) {
    let mut builder = CircuitBuilder::<F>::new();
    let input = builder.public_input();
    let claimed = builder.public_input();
    let zero = builder.binary_is_zero(input).unwrap();
    builder.connect(zero, claimed);
    let constant = builder.define_const(F::from_raw_coordinates(nonzero).unwrap());
    assert_eq!(
        builder.binary_is_zero(constant).unwrap(),
        p3_circuit::ExprId::ZERO
    );
    let circuit = builder.build().unwrap();
    let value = F::from_raw_coordinates(nonzero).unwrap();
    for (input, claimed, accepted) in [
        (F::ZERO, F::ONE, true),
        (F::ZERO, F::ZERO, false),
        (value, F::ZERO, true),
        (value, F::ONE, false),
        (F::ONE, F::ZERO, true),
    ] {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[input, claimed]).unwrap();
        assert_eq!(runner.run().is_ok(), accepted);
    }
}

#[test]
fn zero_tests_bind_zero_and_nonzero_scalars() {
    zero_test::<BinaryField128>(0x8000_0000_0000_0000_0000_0000_0001_0000);
    zero_test::<Poly64>(0x8000_0000_0001_0000);
}
