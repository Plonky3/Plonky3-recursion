//! Native Poly64 coefficients retain the full Poly192 challenge field.

use p3_binary_field::{Poly64, Poly192};
use p3_circuit::CircuitBuilder;
use p3_field::{Field, PrimeCharacteristicRing};

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
fn native_inverse_candidate_and_raw_constants_are_constrained() {
    let mut builder = CircuitBuilder::<Poly64>::new();
    let value = builder.alloc_public_input_array("value");
    let inverse = builder.alloc_public_input_array("inverse");
    let expected_constant = builder.alloc_public_input_array::<3>("raw constant");
    let value = builder.native_poly192_from_coefficients(value);
    let inverse = builder.native_poly192_from_coefficients(inverse);
    builder.assert_native_poly192_inverse(&value, &inverse);
    let constant = builder.native_poly192_constant([0xdead_beef, 0xfedc_ba98_7654_3210, 1 << 63]);
    for i in 0..3 {
        builder.connect(constant.coefficients()[i], expected_constant[i]);
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
