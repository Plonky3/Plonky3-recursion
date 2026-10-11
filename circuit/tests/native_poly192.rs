//! Native Poly64 coefficients retain the full Poly192 challenge field.

use p3_binary_field::{Poly64, Poly192};
use p3_circuit::CircuitBuilder;
use p3_field::{Field, PrimeCharacteristicRing};

#[test]
fn native_cubic_coordinates_bind_all_three_coefficients() {
    let mut builder = CircuitBuilder::<Poly64>::new();
    let coefficients = builder.alloc_public_input_array::<3>("coefficients");
    let expected = builder.alloc_public_input_array::<192>("coordinates");
    let value = builder.native_poly192_from_coefficients(coefficients);
    let bits = builder.native_poly192_to_bits(&value).unwrap();
    for (&actual, &expected) in bits.iter().zip(&expected) {
        builder.connect(actual, expected);
    }
    let recomposed = builder.native_poly192_from_bits(expected).unwrap();
    for (&actual, &expected) in recomposed.coefficients().iter().zip(&coefficients) {
        builder.connect(actual, expected);
    }
    let circuit = builder.build().unwrap();
    for raw in [
        [0, 0, 1 << 63],
        [u64::MAX, 0x8123456789abcdef, 0xfedcba9876543210],
    ] {
        let public: Vec<_> = raw
            .into_iter()
            .map(Poly64::new)
            .chain(
                raw.into_iter()
                    .flat_map(|word| (0..64).map(move |i| Poly64::from_bool(word >> i & 1 != 0))),
            )
            .collect();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public).unwrap();
        runner.run().unwrap();
        for index in [0, 1, 2, 3 + 64, 3 + 191] {
            let mut wrong = public.clone();
            wrong[index] += Poly64::ONE;
            let mut runner = circuit.runner();
            assert!(
                runner
                    .set_public_inputs(&wrong)
                    .and_then(|()| runner.run())
                    .is_err()
            );
        }
        let mut non_boolean = public;
        non_boolean[3] = Poly64::new(2);
        let mut runner = circuit.runner();
        assert!(
            runner
                .set_public_inputs(&non_boolean)
                .and_then(|()| runner.run())
                .is_err()
        );
    }
}

#[test]
fn native_cubic_arithmetic_matches_the_released_field() {
    let mut builder = CircuitBuilder::<Poly64>::new();
    let a = builder.alloc_public_input_array("a");
    let b = builder.alloc_public_input_array("b");
    let product = builder.alloc_public_input_array::<3>("product");
    let square = builder.alloc_public_input_array::<3>("square");
    let sum = builder.alloc_public_input_array::<3>("sum");
    let a = builder.native_poly192_from_coefficients(a);
    let b = builder.native_poly192_from_coefficients(b);
    let actual_product = builder.native_poly192_mul(&a, &b);
    let actual_square = builder.native_poly192_square(&a);
    let actual_sum = builder.native_poly192_add(&a, &b);
    for i in 0..3 {
        builder.connect(actual_product.coefficients()[i], product[i]);
        builder.connect(actual_square.coefficients()[i], square[i]);
        builder.connect(actual_sum.coefficients()[i], sum[i]);
    }
    let circuit = builder.build().unwrap();
    let values = [
        ([0, 0, 0], [1, 0, 0]),
        ([0, 0, 1 << 63], [0, 1 << 63, 0]),
        (
            [u64::MAX, 0x1234_5678_9abc_def0, 0xdead_beef],
            [0xfedc_ba98_7654_3210, u64::MAX, 0x8123_4567_89ab_cdef],
        ),
    ];
    for (a, b) in values {
        let a = Poly192::new(a.map(Poly64::new));
        let b = Poly192::new(b.map(Poly64::new));
        let public: Vec<_> = [a, b, a * b, a.square(), a + b]
            .into_iter()
            .flat_map(|x| x.coefficients())
            .collect();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public).unwrap();
        runner.run().unwrap();
        let mut wrong = public;
        wrong[8] += Poly64::ONE;
        let mut runner = circuit.runner();
        assert!(
            runner
                .set_public_inputs(&wrong)
                .and_then(|()| runner.run())
                .is_err()
        );
    }
}

#[test]
fn native_cubic_product_fits_ten_alu_operations() {
    let mut builder = CircuitBuilder::<Poly64>::new();
    let a = builder.alloc_public_input_array::<3>("a");
    let b = builder.alloc_public_input_array::<3>("b");
    let expected = builder.alloc_public_input_array::<3>("product");
    let a = builder.native_poly192_from_coefficients(a);
    let b = builder.native_poly192_from_coefficients(b);
    let product = builder.native_poly192_mul(&a, &b);
    for (&actual, &expected) in product.coefficients().iter().zip(&expected) {
        builder.connect(actual, expected);
    }
    let circuit = builder.build().unwrap();
    let alu_count = circuit
        .ops
        .iter()
        .filter(|op| matches!(op, p3_circuit::Op::Alu { .. }))
        .count();
    assert!(
        alu_count <= 10,
        "cubic product uses {alu_count} ALU operations"
    );
    // y^4 = y^2 + y exercises both reductions of the high product.
    let public = [0, 0, 1, 0, 0, 1, 0, 1, 1].map(Poly64::new);
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    runner.run().unwrap();
    for index in 6..9 {
        let mut wrong = public;
        wrong[index] += Poly64::ONE;
        let mut runner = circuit.runner();
        assert!(
            runner
                .set_public_inputs(&wrong)
                .and_then(|()| runner.run())
                .is_err()
        );
    }
}

#[test]
fn native_inverse_candidate_and_raw_constants_are_constrained() {
    let mut builder = CircuitBuilder::<Poly64>::new();
    let value = builder.alloc_public_input_array("value");
    let inverse = builder.alloc_public_input_array("inverse");
    let expected_constant = builder.alloc_public_input_array::<3>("raw constant");
    let value = builder.native_poly192_from_coefficients(value);
    let inverse = builder.native_poly192_from_coefficients(inverse);
    builder.assert_native_poly192_inverse(&value, &inverse);
    let constant = builder.native_poly192_constant([0xdead_beef, 0xfedc_ba98_7654_3210, 1 << 63]);
    for (&coefficient, &expected) in constant.coefficients().iter().zip(&expected_constant) {
        builder.connect(coefficient, expected);
    }
    let circuit = builder.build().unwrap();
    let value = Poly192::new([0xdead_beef, 0xfedc_ba98_7654_3210, 1 << 63].map(Poly64::new));
    let public: Vec<_> = [value, value.inverse(), value]
        .into_iter()
        .flat_map(|x| x.coefficients())
        .collect();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    runner.run().unwrap();
    let mut wrong = public;
    wrong[5] += Poly64::ONE;
    let mut runner = circuit.runner();
    assert!(
        runner
            .set_public_inputs(&wrong)
            .and_then(|()| runner.run())
            .is_err()
    );
    let mut swapped = wrong;
    swapped[5] += Poly64::ONE;
    swapped.swap(7, 8);
    let mut runner = circuit.runner();
    assert!(
        runner
            .set_public_inputs(&swapped)
            .and_then(|()| runner.run())
            .is_err()
    );
    let mut runner = circuit.runner();
    let mut zero = vec![Poly64::ZERO; 6];
    zero.extend(value.coefficients());
    runner.set_public_inputs(&zero).unwrap();
    assert!(runner.run().is_err());
}

/// `x^i * x^shift = x^(i + shift)` below degree 64: multiplying a cell of at
/// most `width` coefficients by `x^shift` only shifts them.
fn assert_shifts_without_reduction(width: usize, shifts: impl IntoIterator<Item = usize>) {
    for shift in shifts {
        for i in 0..width {
            assert_eq!(
                Poly64::new(1 << i) * Poly64::new(1 << shift),
                Poly64::new(1 << (i + shift))
            );
        }
    }
}

#[test]
fn unchecked_poly64_words_split_and_bind_the_low_coefficients() {
    assert_shifts_without_reduction(16, [16, 32, 48]);
    let value = 0x8912_3456_789a_bcdeu64;
    for count in 0..=4 {
        let mut b = CircuitBuilder::<Poly64>::new();
        let input = b.public_input();
        let expected = (0..count).map(|_| b.public_input()).collect::<Vec<_>>();
        let words = b.native_poly64_unchecked_words(input, count).unwrap();
        assert_eq!(words.len(), count);
        for (&word, &expected) in words.iter().zip(&expected) {
            b.connect(word, expected);
        }
        let circuit = b.build().unwrap();
        let runs = |public: &[Poly64]| {
            let mut runner = circuit.runner();
            runner
                .set_public_inputs(public)
                .and_then(|()| runner.run())
                .is_ok()
        };
        let low = if count == 4 {
            value
        } else {
            value & ((1 << (16 * count)) - 1)
        };
        let mut public = vec![Poly64::new(low)];
        public.extend((0..count).map(|j| Poly64::new(low >> (16 * j) & 0xffff)));
        assert!(runs(&public), "{count} words");
        if count > 0 {
            let mut wrong = public.clone();
            wrong[count] += Poly64::ONE;
            assert!(!runs(&wrong), "changed top word of {count}");
        }
        if count < 4 {
            let mut high = public.clone();
            high[0] += Poly64::new(1 << (16 * count));
            assert!(!runs(&high), "coefficient above {count} words");
        }
    }
    let mut b = CircuitBuilder::<Poly64>::new();
    let input = b.public_input();
    let before = b.construction_usage().unwrap();
    assert!(b.native_poly64_unchecked_words(input, 5).is_err());
    assert_eq!(b.construction_usage().unwrap(), before);
}

/// Eight bytes pack into `Poly64::from_le_bytes`, whose coefficients are
/// their bits in order. A byte with an eighth coefficient is rejected even
/// when its neighbour compensates, which leaves the packed cell unchanged.
#[test]
fn poly64_bytes_pack_into_their_coefficients_and_reject_wide_bytes() {
    assert_shifts_without_reduction(8, (1..8).map(|k| 8 * k));
    let value = 0x8912_3456_789a_bcdeu64;
    let mut b = CircuitBuilder::<Poly64>::new();
    let bytes = b.alloc_public_input_array::<8>("bytes");
    let expected = b.public_input();
    let packed = b.native_poly64_from_bytes(bytes).unwrap();
    b.connect(packed, expected);
    let circuit = b.build().unwrap();
    let runs = |public: &[Poly64]| {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(public)
            .and_then(|()| runner.run())
            .is_ok()
    };
    let mut public: Vec<Poly64> = value
        .to_le_bytes()
        .map(|byte| Poly64::new(byte.into()))
        .to_vec();
    public.push(Poly64::from_le_bytes(value.to_le_bytes()));
    assert!(runs(&public));
    let mut wrong = public.clone();
    wrong[8] += Poly64::new(1 << 37);
    assert!(!runs(&wrong), "changed packed cell");
    let mut wide = public;
    wide[2] += Poly64::new(1 << 8);
    wide[3] += Poly64::ONE;
    assert_eq!(
        (0..8)
            .map(|k| wide[k] * Poly64::new(1 << (8 * k)))
            .sum::<Poly64>(),
        wide[8]
    );
    assert!(!runs(&wide), "byte with coefficient 8");
}

/// A packed cell keeps its bytes' coordinates, so a later decomposition adds
/// nothing, and bytes that are already checked cost one `mul_add` each.
#[test]
fn packed_poly64_bytes_record_their_coordinates() {
    let mut b = CircuitBuilder::<Poly64>::new();
    let bytes = b.alloc_public_input_array::<8>("bytes");
    let packed = b.native_poly64_from_bytes(bytes).unwrap();
    let before = b.construction_usage().unwrap();
    let bits = b.binary_decompose_coordinates(packed, 64).unwrap();
    for (k, &byte) in bytes.iter().enumerate() {
        let byte_bits = b.binary_decompose_coordinates(byte, 8).unwrap();
        assert_eq!(bits[8 * k..8 * k + 8], byte_bits[..]);
    }
    assert_eq!(b.construction_usage().unwrap(), before);
    let checked: [_; 8] = bits
        .as_chunks::<8>()
        .0
        .iter()
        .map(|byte| b.binary_recompose_coordinates(byte).unwrap())
        .collect::<Vec<_>>()
        .try_into()
        .unwrap();
    let before = b.construction_usage().unwrap().expression_nodes;
    b.native_poly64_from_bytes(checked).unwrap();
    assert_eq!(b.construction_usage().unwrap().expression_nodes - before, 7);
}

/// Unchecked words pack into the cell of their coefficients in order, which is
/// `Poly64::from_le_bytes` of their little-endian bytes, with three `mul_add`s and no
/// decomposition hint. The packing alone does not range-check: a word with a sixteenth
/// coefficient, compensated by its neighbour, packs to the same cell.
#[test]
fn unchecked_poly64_words_pack_into_their_coefficients() {
    assert_shifts_without_reduction(16, (1..4).map(|j| 16 * j));
    let value = 0x8912_3456_789a_bcdeu64;
    let mut b = CircuitBuilder::<Poly64>::new();
    let words = b.alloc_public_input_array::<4>("words");
    let expected = b.public_input();
    let before = b.construction_usage().unwrap();
    let packed = b.native_poly64_from_unchecked_words(words).unwrap();
    let after = b.construction_usage().unwrap();
    assert!(after.expression_nodes - before.expression_nodes <= 6);
    assert_eq!(after.non_primitive_calls, before.non_primitive_calls);
    b.connect(packed, expected);
    let circuit = b.build().unwrap();
    let runs = |public: &[Poly64]| {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(public)
            .and_then(|()| runner.run())
            .is_ok()
    };
    let mut public: Vec<Poly64> = (0..4)
        .map(|j| Poly64::new(value >> (16 * j) & 0xffff))
        .collect();
    public.push(Poly64::from_le_bytes(value.to_le_bytes()));
    assert!(runs(&public));
    let mut wrong = public.clone();
    wrong[4] += Poly64::new(1 << 37);
    assert!(!runs(&wrong), "changed packed cell");
    let mut wide = public;
    wide[1] += Poly64::new(1 << 16);
    wide[2] += Poly64::ONE;
    assert!(runs(&wide), "an unchecked word may carry coefficient 16");
}
