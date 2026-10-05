//! Exactly one is stronger than an odd selector count in characteristic two.

use p3_binary_field::{BinaryField128, TowerLevel};
use p3_circuit::CircuitBuilder;
use p3_field::PrimeCharacteristicRing;

#[test]
fn exactly_one_rejects_zero_two_and_three_selectors() {
    type F = BinaryField128;
    let mut builder = CircuitBuilder::<F>::new();
    let selectors = builder.alloc_public_input_array::<3>("selector");
    builder.assert_exactly_one(&selectors).unwrap();
    let circuit = builder.build().unwrap();
    for pattern in 0u8..8 {
        let public = core::array::from_fn::<_, 3, _>(|i| F::from_bool(pattern >> i & 1 != 0));
        let mut runner = circuit.runner();
        let accepted = runner
            .set_public_inputs(&public)
            .and_then(|()| runner.run())
            .is_ok();
        assert_eq!(accepted, pattern.count_ones() == 1, "pattern={pattern:03b}");
    }
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[F::from_repr(2), F::ONE, F::ZERO])
        .unwrap();
    assert!(runner.run().is_err());
}

#[test]
fn empty_selector_list_is_rejected_before_builder_mutation() {
    let mut builder = CircuitBuilder::<BinaryField128>::new();
    assert!(builder.assert_exactly_one(&[]).is_err());
    let input = builder.public_input();
    builder.assert_exactly_one(&[input]).unwrap();
    let circuit = builder.build().unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&[BinaryField128::ONE]).unwrap();
    runner.run().unwrap();
}
