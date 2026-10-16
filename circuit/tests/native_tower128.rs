//! Native tower arithmetic keeps scalar products in the exact Wiedemann field.

use p3_binary_field::{BinaryField128, TowerLevel};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_field::{Field, PrimeCharacteristicRing};

type F = BinaryField128;

#[test]
fn scalar_arithmetic_and_checked_word_bits_match_the_native_field() {
    let mut b = CircuitBuilder::<F>::new();
    let inputs = b.alloc_public_input_array::<3>("a b inverse");
    let expected = b.alloc_public_input_array::<3>("sum product square");
    let words = b.alloc_public_input_array::<8>("raw words");
    let a = b.native_tower128_from_expr(inputs[0]);
    let c = b.native_tower128_from_expr(inputs[1]);
    let inverse = b.native_tower128_from_expr(inputs[2]);
    let sum = b.native_tower128_add(&a, &c);
    let product = b.native_tower128_mul(&a, &c);
    let square = b.native_tower128_square(&a);
    for (actual, expected) in [sum, product, square].iter().zip(expected) {
        b.connect(actual.as_expr(), expected);
    }
    b.assert_native_tower128_inverse(&a, &inverse);
    let actual_words = b.native_tower128_to_words(&a).unwrap();
    for i in 0..8 {
        b.connect(actual_words[i], words[i]);
    }
    let decoded = b.native_tower128_from_words(words).unwrap();
    b.connect(decoded.as_expr(), a.as_expr());
    let bits = b.native_tower128_to_bits(&c).unwrap();
    let decoded = b.native_tower128_from_bits(bits).unwrap();
    b.connect(decoded.as_expr(), c.as_expr());
    let constant = b.native_tower128_constant(0x8123456789abcdef0123456789abcdef);
    let constant_expected = b.public_input();
    b.connect(constant.as_expr(), constant_expected);
    let circuit = b.build().unwrap();
    for (a, c) in [
        (1, 0),
        (
            0x8912_3456_789a_bcde_f012_3456_789a_bcde,
            0xfedcba9876543210123456789abcdef0,
        ),
        (u128::MAX, 1 << 127),
    ] {
        let a = F::from_repr(a);
        let c = F::from_repr(c);
        let mut public = vec![a, c, a.inverse(), a + c, a * c, a * a];
        public.extend(
            (0..8).map(|i| {
                F::from_raw_coordinates((a.to_repr() >> (16 * i)) as u16 as u128).unwrap()
            }),
        );
        public.push(F::from_repr(0x8123456789abcdef0123456789abcdef));
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public).unwrap();
        runner.run().unwrap();
        for changed in [2, 3, 4, 5, 13, 14] {
            let mut wrong = public.clone();
            wrong[changed] += F::ONE;
            let mut runner = circuit.runner();
            assert!(
                runner
                    .set_public_inputs(&wrong)
                    .and_then(|()| runner.run())
                    .is_err()
            );
        }
    }
}

#[test]
fn zero_has_no_native_scalar_inverse() {
    let mut b = CircuitBuilder::<F>::new();
    let a = b.public_input();
    let inverse = b.public_input();
    let a = b.native_tower128_from_expr(a);
    let inverse = b.native_tower128_from_expr(inverse);
    b.assert_native_tower128_inverse(&a, &inverse);
    let circuit = b.build().unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&[F::ZERO, F::ONE]).unwrap();
    assert!(runner.run().is_err());
}

/// Sixteen bytes pack into the scalar whose raw coordinates are their bits in
/// order. A byte with an eighth coordinate is rejected even when its
/// neighbour compensates, which leaves the packed scalar unchanged.
#[test]
fn bytes_pack_into_their_raw_coordinates_and_reject_wide_bytes() {
    for k in 1..16 {
        for i in 0..8 {
            assert_eq!(
                F::from_repr(1 << i) * F::from_repr(1 << (8 * k)),
                F::from_repr(1 << (8 * k + i))
            );
        }
    }
    let value = 0x8912_3456_789a_bcde_f012_3456_789a_bcdeu128;
    let mut b = CircuitBuilder::<F>::new();
    let bytes = b.alloc_public_input_array::<16>("bytes");
    let expected = b.public_input();
    let packed = b.native_tower128_from_bytes(bytes).unwrap();
    b.connect(packed.as_expr(), expected);
    let circuit = b.build().unwrap();
    let runs = |public: &[F]| {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(public)
            .and_then(|()| runner.run())
            .is_ok()
    };
    let mut public: Vec<F> = value
        .to_le_bytes()
        .map(|byte| F::from_repr(byte.into()))
        .to_vec();
    public.push(F::from_repr(value));
    assert!(runs(&public));
    let mut wrong = public.clone();
    wrong[16] += F::from_repr(1 << 77);
    assert!(!runs(&wrong), "changed packed scalar");
    let mut wide = public;
    wide[2] += F::from_repr(1 << 8);
    wide[3] += F::ONE;
    assert_eq!(
        (0..16)
            .map(|k| wide[k] * F::from_repr(1 << (8 * k)))
            .sum::<F>(),
        wide[16]
    );
    assert!(!runs(&wide), "byte with coordinate 8");
}

/// A packed scalar keeps its bytes' coordinates, so a later decomposition adds
/// nothing, and bytes that are already checked cost one `mul_add` each.
#[test]
fn packed_bytes_record_their_coordinates() {
    let mut b = CircuitBuilder::<F>::new();
    let bytes = b.alloc_public_input_array::<16>("bytes");
    let packed = b.native_tower128_from_bytes(bytes).unwrap();
    let before = b.construction_usage().unwrap();
    let bits = b.native_tower128_to_bits(&packed).unwrap();
    for (k, &byte) in bytes.iter().enumerate() {
        let byte_bits = b.binary_decompose_coordinates(byte, 8).unwrap();
        assert_eq!(bits[8 * k..8 * k + 8], byte_bits[..]);
    }
    assert_eq!(b.construction_usage().unwrap(), before);
    let checked: [_; 16] = bits
        .as_chunks::<8>()
        .0
        .iter()
        .map(|byte| b.binary_recompose_coordinates(byte).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let before = b.construction_usage().unwrap().expression_nodes;
    b.native_tower128_from_bytes(checked).unwrap();
    assert_eq!(
        b.construction_usage().unwrap().expression_nodes - before,
        15
    );
}

#[test]
fn unchecked_words_split_and_bind_the_low_coordinates() {
    let value = 0x8912_3456_789a_bcde_f012_3456_789a_bcdeu128;
    for count in 0..=8 {
        let mut b = CircuitBuilder::<F>::new();
        let input = b.public_input();
        let expected = (0..count).map(|_| b.public_input()).collect::<Vec<_>>();
        let scalar = b.native_tower128_from_expr(input);
        let words = b.native_tower128_unchecked_words(&scalar, count).unwrap();
        assert_eq!(words.len(), count);
        for (&word, &expected) in words.iter().zip(&expected) {
            b.connect(word, expected);
        }
        let circuit = b.build().unwrap();
        let runs = |public: &[F]| {
            let mut runner = circuit.runner();
            runner
                .set_public_inputs(public)
                .and_then(|()| runner.run())
                .is_ok()
        };
        let low = if count == 8 {
            value
        } else {
            value & ((1 << (16 * count)) - 1)
        };
        let mut public = vec![F::from_repr(low)];
        public.extend((0..count).map(|j| F::from_repr(low >> (16 * j) & 0xffff)));
        assert!(runs(&public), "{count} words");
        if count > 0 {
            let mut wrong = public.clone();
            wrong[count] += F::ONE;
            assert!(!runs(&wrong), "changed top word of {count}");
        }
        if count < 8 {
            let mut high = public.clone();
            high[0] += F::from_repr(1 << (16 * count));
            assert!(!runs(&high), "coordinate above {count} words");
        }
    }
    let mut b = CircuitBuilder::<F>::new();
    let input = b.public_input();
    let scalar = b.native_tower128_from_expr(input);
    let before = b.construction_usage().unwrap();
    assert!(b.native_tower128_unchecked_words(&scalar, 9).is_err());
    assert_eq!(b.construction_usage().unwrap(), before);
}

/// Unchecked words pack into the scalar of their raw coordinates in order, with seven
/// `mul_add`s and no decomposition hint. The packing alone does not range-check: a word with a
/// sixteenth coordinate, compensated by its neighbour, packs to the same scalar, so callers
/// take the words from a range-checked source such as a native Keccak-f output.
#[test]
fn unchecked_words_pack_into_their_raw_coordinates() {
    for j in 1..8 {
        for i in 0..16 {
            assert_eq!(
                F::from_repr(1 << i) * F::from_repr(1 << (16 * j)),
                F::from_repr(1 << (16 * j + i))
            );
        }
    }
    let value = 0x8912_3456_789a_bcde_f012_3456_789a_bcdeu128;
    let mut b = CircuitBuilder::<F>::new();
    let words = b.alloc_public_input_array::<8>("words");
    let expected = b.public_input();
    let before = b.construction_usage().unwrap();
    let packed = b.native_tower128_from_unchecked_words(words).unwrap();
    let after = b.construction_usage().unwrap();
    assert!(after.expression_nodes - before.expression_nodes <= 14);
    assert_eq!(after.non_primitive_calls, before.non_primitive_calls);
    b.connect(packed.as_expr(), expected);
    let circuit = b.build().unwrap();
    let runs = |public: &[F]| {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(public)
            .and_then(|()| runner.run())
            .is_ok()
    };
    let mut public: Vec<F> = (0..8)
        .map(|j| F::from_repr(value >> (16 * j) & 0xffff))
        .collect();
    public.push(F::from_repr(value));
    assert!(runs(&public));
    let mut wrong = public.clone();
    wrong[8] += F::from_repr(1 << 77);
    assert!(!runs(&wrong), "changed packed scalar");
    let mut wide = public;
    wide[2] += F::from_repr(1 << 16);
    wide[3] += F::ONE;
    assert!(runs(&wide), "an unchecked word may carry coordinate 16");
}

#[test]
fn unchecked_word_splits_reuse_provenance_and_keep_narrowing_constraints() {
    let mut b = CircuitBuilder::<F>::new();
    let input = b.public_input();
    let scalar = b.native_tower128_from_expr(input);
    let words = b.native_tower128_unchecked_words(&scalar, 8).unwrap();
    assert_eq!(
        b.native_tower128_unchecked_words(&scalar, 8).unwrap(),
        words
    );
    for &word in &words {
        b.binary_decompose_coordinates(word, 16).unwrap();
    }
    let packed = b
        .native_tower128_from_unchecked_words(words.clone().try_into().unwrap())
        .unwrap();
    assert_eq!(
        b.native_tower128_unchecked_words(&packed, 8).unwrap(),
        words
    );
    assert_eq!(
        b.native_tower128_unchecked_words(&scalar, 1).unwrap(),
        words[..1]
    );
    let circuit = b.build().unwrap();
    for (value, accepted) in [(0xa5, true), (0x1a5, true), (1 << 16, false)] {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[F::from_repr(value)]).unwrap();
        assert_eq!(runner.run_witness().is_ok(), accepted);
    }
}

#[test]
fn constant_word_splits_fold_and_reject_out_of_span_values() {
    let mut b = CircuitBuilder::<F>::new();
    let value = b.native_tower128_constant(0x1234abcd);
    let words = b.native_tower128_unchecked_words(&value, 2).unwrap();
    let expected = [
        b.define_const(F::from_repr(0xabcd)),
        b.define_const(F::from_repr(0x1234)),
    ];
    assert_eq!(words, expected);
    assert!(b.native_tower128_unchecked_words(&value, 1).is_err());
    let circuit = b.build().unwrap();
    assert!(
        circuit
            .ops
            .iter()
            .all(|op| !matches!(op, p3_circuit::ops::Op::Hint { .. }))
    );
}
