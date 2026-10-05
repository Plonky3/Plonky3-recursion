//! The protocol's byte/limb shape is independent of its circuit carrier.

use core::hash::Hash;
use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField8, BinaryField128, Poly64};
use p3_circuit::{
    CircuitBuilder,
    ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding, PrimeBinaryEncoding},
};
use p3_field::{Field, extension::BinomialExtensionField};

fn roundtrip<F: Field + Eq + Hash, E: BinaryCircuitEncoding<F>>() {
    let mut builder = CircuitBuilder::<F>::new();
    let input = builder.public_input();
    let expected = builder.alloc_public_input_array::<16>("word bits");
    let bits = E::decompose_word(&mut builder, input, 16).unwrap();
    for i in 0..16 {
        builder.connect(bits[i], expected[i]);
    }
    let packed = E::recompose_word(&mut builder, &bits).unwrap();
    builder.connect(packed, input);
    assert!(E::decompose_word(&mut builder, input, 17).is_err());
    assert!(E::recompose_word(&mut builder, &[input; 17]).is_err());
    let circuit = builder.build().unwrap();
    let value: F = E::encode_u16(0xabcd).unwrap();
    let public: Vec<_> = core::iter::once(value)
        .chain((0..16).map(|i| F::from_bool(0xabcdu16 >> i & 1 != 0)))
        .collect();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    runner.run().unwrap();
    let mut wrong = public;
    wrong[16] += F::ONE;
    let mut runner = circuit.runner();
    assert!(
        runner
            .set_public_inputs(&wrong)
            .and_then(|()| runner.run())
            .is_err()
    );
}

#[test]
fn explicit_encodings_preserve_words_in_prime_extension_and_binary_carriers() {
    roundtrip::<BabyBear, PrimeBinaryEncoding<BabyBear>>();
    roundtrip::<BinomialExtensionField<BabyBear, 4>, PrimeBinaryEncoding<BabyBear>>();
    roundtrip::<BinaryField128, NativeBinaryEncoding>();
    roundtrip::<Poly64, NativeBinaryEncoding>();
}

#[test]
fn zero_bit_words_bind_zero_in_both_encodings() {
    fn check<F: Field + Eq + Hash, E: BinaryCircuitEncoding<F>>() {
        let mut builder = CircuitBuilder::<F>::new();
        let input = builder.public_input();
        assert!(
            E::decompose_word(&mut builder, input, 0)
                .unwrap()
                .is_empty()
        );
        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[F::ZERO]).unwrap();
        runner.run().unwrap();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[F::ONE]).unwrap();
        assert!(runner.run().is_err());
    }
    check::<BabyBear, PrimeBinaryEncoding<BabyBear>>();
    check::<BinaryField128, NativeBinaryEncoding>();
}

#[test]
fn invalid_widths_and_carriers_leave_fresh_builders_unchanged() {
    fn check<F: Field + Eq + Hash, E: BinaryCircuitEncoding<F>>(width: usize) {
        let mut rejected = CircuitBuilder::<F>::new();
        let input = rejected.public_input();
        assert!(E::decompose_word(&mut rejected, input, width).is_err());
        assert!(E::recompose_word(&mut rejected, &vec![input; width]).is_err());
        let rejected = rejected.build().unwrap();
        let mut control = CircuitBuilder::<F>::new();
        control.public_input();
        let control = control.build().unwrap();
        assert_eq!(rejected.witness_count, control.witness_count);
        assert_eq!(rejected.expr_to_widx, control.expr_to_widx);
        assert_eq!(rejected.public_rows, control.public_rows);
        assert_eq!(rejected.private_input_rows, control.private_input_rows);
        assert_eq!(format!("{:?}", rejected.ops), format!("{:?}", control.ops));
    }
    check::<BabyBear, PrimeBinaryEncoding<BabyBear>>(17);
    check::<BinaryField128, NativeBinaryEncoding>(17);
    check::<BinaryField8, NativeBinaryEncoding>(16);
    assert!(<NativeBinaryEncoding as BinaryCircuitEncoding<BinaryField8>>::encode_u16(1).is_err());
}
