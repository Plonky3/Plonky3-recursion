//! Product GKR over native Poly64 cells and three-coefficient Poly192 targets.

use p3_binary_field::{BinaryChallenger, Poly64, Poly192};
use p3_bus::{ProductGkrProof, ProductGkrRootShape, ProductGkrShape};
use p3_challenger::FieldChallenger;
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::{ByteHash, NativePoly192Target};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::Keccak256Hash;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::verifier::BinaryPolyProductGkrVerifier;

type H = NativeBinaryEncoding;
fn scalar(b: &mut CircuitBuilder<Poly64>) -> NativePoly192Target {
    let coefficients = core::array::from_fn(|_| b.public_input());
    b.native_poly192_from_coefficients(coefficients)
}
fn equal(b: &mut CircuitBuilder<Poly64>, a: &NativePoly192Target, c: &NativePoly192Target) {
    for (&a, &c) in a.coefficients().iter().zip(c.coefficients()) {
        let difference = b.sub(a, c);
        b.assert_zero(difference);
    }
}
fn run(circuit: &Circuit<Poly64>, public: &[Poly64], private: &[Poly64]) -> bool {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public)
        .and_then(|()| runner.set_private_inputs(private))
        .and_then(|()| runner.run())
        .is_ok()
}

#[test]
fn native_poly_product_matches_roots_points_leaves_and_next_draw() {
    for height in 0..=4 {
        for sharing in [
            ProductGkrRootShape::Distinct,
            ProductGkrRootShape::FirstTwoShared,
        ] {
            let verifier = BinaryPolyProductGkrVerifier::new(height, 3, sharing).unwrap();
            let shape = verifier.input_shape();
            let native_shape = ProductGkrShape::new(height, 3, sharing).unwrap();
            let make = || BinaryChallenger::<Poly64, _>::from_hasher(vec![9, 17, 3], Keccak256Hash);
            let dense = |n: usize| {
                Poly192::new([
                    Poly64::new(0x80123456789abcdeu64.wrapping_mul(n as u64 + 11)),
                    Poly64::new(0xfedcba9876543210u64.wrapping_mul(n as u64 + 7)),
                    Poly64::new(0x9000000000000001u64.wrapping_mul(n as u64 + 3)),
                ])
            };
            let mut first: Vec<_> = (0..1 << height).map(dense).collect();
            first[0] = Poly192::ZERO;
            let mut second = first.clone();
            second.reverse();
            if sharing == ProductGkrRootShape::Distinct {
                second[0] += Poly192::ONE;
            }
            let third: Vec<_> = (0..(1usize << height) - 1).map(dense).collect();
            let mut native_ch = make();
            let (proof, native) = ProductGkrProof::prove::<Poly64, _>(
                &[&first, &second, &third],
                native_shape,
                &mut native_ch,
            );
            let mut imported_ch = make();
            let imported = verifier.import_native(&proof, &mut imported_ch).unwrap();
            let next = native_ch.sample_algebra_element::<Poly192>();
            assert_eq!(next, imported_ch.sample_algebra_element::<Poly192>());
            let mut b = CircuitBuilder::<Poly64>::new();
            b.enable_native_keccak_f1600().unwrap();
            let targets = shape.allocate_native_targets(&mut b).unwrap();
            let initial = [9, 17, 3].map(|byte| b.define_const(H::encode_u16(byte).unwrap()));
            let ch = BinaryTower128Challenger::with_initial_bytes_with_host::<H, Poly64>(
                &mut b,
                ByteHash::Keccak256,
                &initial,
            )
            .unwrap();
            let mut output = verifier
                .verify_reduction_native(&mut b, ch, &targets)
                .unwrap();
            for value in output
                .roots
                .iter()
                .chain(&output.point)
                .chain(&output.values)
            {
                let expected = scalar(&mut b);
                equal(&mut b, value, &expected);
            }
            let bits = output
                .challenger
                .sample_poly192_with_host::<H, Poly64>(&mut b)
                .unwrap();
            let actual = b
                .native_poly192_from_bits(core::array::from_fn(|i| {
                    bits.coefficients()[i / 64].bits()[i % 64]
                }))
                .unwrap();
            let expected = scalar(&mut b);
            equal(&mut b, &actual, &expected);
            let circuit = b.build().unwrap();
            let private = imported.private_native_values(&shape).unwrap();
            let public: Vec<_> = native
                .roots
                .iter()
                .chain(&native.point)
                .chain(&native.values)
                .copied()
                .chain([next])
                .flat_map(|value| value.coefficients())
                .collect();
            assert!(run(&circuit, &public, &private));
            for index in [0, 1, 2, public.len() - 1] {
                let mut wrong = public.clone();
                wrong[index] += Poly64::ONE;
                assert!(!run(&circuit, &wrong, &private));
            }
            for index in 0..3 {
                let mut wrong = private.clone();
                wrong[index] += Poly64::ONE;
                assert!(!run(&circuit, &public, &wrong));
            }
            let other = BinaryPolyProductGkrVerifier::new(height + 1, 3, sharing).unwrap();
            assert!(
                imported
                    .private_native_values(&other.input_shape())
                    .is_err()
            );
        }
    }
}
