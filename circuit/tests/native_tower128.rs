//! Native tower arithmetic keeps scalar products in the exact Wiedemann field.

use p3_binary_field::{BinaryField128, TowerLevel};
use p3_circuit::{CircuitBuilder, ops::binary_native::BinaryCoordinateField};
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
