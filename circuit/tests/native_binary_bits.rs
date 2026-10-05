//! Coordinate arithmetic targets must work inside characteristic-two circuits.

use p3_binary_field::{BinaryField128, Gf2, Poly64, Poly192, TowerLevel};
use p3_circuit::CircuitBuilder;
use p3_field::PrimeCharacteristicRing;

fn bits(raw: u128, count: usize) -> impl Iterator<Item = Gf2> {
    (0..count).map(move |i| {
        if raw >> i & 1 == 0 {
            Gf2::ZERO
        } else {
            Gf2::ONE
        }
    })
}

#[test]
fn tower_coordinates_multiply_and_square_in_a_binary_circuit() {
    let mut builder = CircuitBuilder::<Gf2>::new();
    let a_bits = builder.alloc_public_input_array("a");
    let b_bits = builder.alloc_public_input_array("b");
    let expected_product = builder.alloc_public_input_array::<128>("product");
    let expected_square = builder.alloc_public_input_array::<128>("square");
    let a = builder.binary128_from_bits(a_bits).unwrap();
    let b = builder.binary128_from_bits(b_bits).unwrap();
    let product = builder.binary128_mul(&a, &b);
    let square = builder.binary128_square(&a);
    for i in 0..128 {
        builder.connect(product.bits()[i], expected_product[i]);
        builder.connect(square.bits()[i], expected_square[i]);
    }
    let constant = builder.binary128_constant(1 << 127).unwrap();
    let one = builder.define_const(Gf2::ONE);
    builder.connect(constant.bits()[127], one);
    let circuit = builder.build().unwrap();
    for (a, b) in [
        (0, 1),
        (1 << 127, 1 << 63),
        (u128::MAX, 0xfedc_ba98_7654_3210),
    ] {
        let a = BinaryField128::from_repr(a);
        let b = BinaryField128::from_repr(b);
        let public: Vec<_> = [
            a.to_repr(),
            b.to_repr(),
            (a * b).to_repr(),
            a.square().to_repr(),
        ]
        .into_iter()
        .flat_map(|raw| bits(raw, 128))
        .collect();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public).unwrap();
        runner.run().unwrap();
        let mut changed = public;
        changed[256] += Gf2::ONE;
        let mut runner = circuit.runner();
        assert!(
            runner
                .set_public_inputs(&changed)
                .and_then(|()| runner.run())
                .is_err()
        );
    }
}

#[test]
fn polynomial_coordinates_preserve_all_three_challenge_coefficients() {
    let raw = [0xfedc_ba98_7654_3210, 0xdead_beef_abcd_1234, 1 << 63];
    let mut builder = CircuitBuilder::<Gf2>::new();
    let value = builder.binary_poly192_constant(raw).unwrap();
    let square = builder.binary_poly192_square(&value);
    let expected = builder.alloc_public_input_array::<192>("expected square");
    for (coefficient, target) in square.coefficients().iter().enumerate() {
        for bit in 0..64 {
            builder.connect(target.bits()[bit], expected[64 * coefficient + bit]);
        }
    }
    let inputs = builder.alloc_public_input_array::<64>("poly64 bits");
    let input = builder.binary_poly64_from_bits(inputs).unwrap();
    let one = builder.binary_poly64_constant(1).unwrap();
    let product = builder.binary_poly64_mul(&input, &one);
    for (actual, expected) in product.bits().iter().zip(inputs) {
        builder.connect(*actual, expected);
    }
    let circuit = builder.build().unwrap();
    let square = Poly192::new(raw.map(Poly64::new)).square();
    let public: Vec<_> = square
        .coefficients()
        .iter()
        .flat_map(|value| bits(value.to_bits() as u128, 64))
        .chain(bits(raw[0] as u128, 64))
        .collect();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    runner.run().unwrap();
    let mut changed = public;
    changed[191] += Gf2::ONE;
    let mut runner = circuit.runner();
    assert!(
        runner
            .set_public_inputs(&changed)
            .and_then(|()| runner.run())
            .is_err()
    );
}
