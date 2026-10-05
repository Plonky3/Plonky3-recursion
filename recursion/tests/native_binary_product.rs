//! Native scalar product-GKR reductions and their exact transcript completion.

use p3_binary_field::{BinaryChallenger, BinaryField128, TowerLevel};
use p3_bus::{ProductGkrProof, ProductGkrRootShape, ProductGkrShape};
use p3_challenger::FieldChallenger;
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::{ByteHash, NativeTower128Target};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::Keccak256Hash;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::verifier::BinaryProductGkrVerifier;

type F = BinaryField128;
type H = NativeBinaryEncoding;
fn scalar(b: &mut CircuitBuilder<F>) -> NativeTower128Target {
    let expression = b.public_input();
    b.native_tower128_from_expr(expression)
}
fn run(circuit: &Circuit<F>, public: &[F], private: &[F]) -> bool {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public)
        .and_then(|()| runner.set_private_inputs(private))
        .and_then(|()| runner.run())
        .is_ok()
}

#[test]
fn scalar_product_layers_match_native_roots_points_leaves_and_next_draw() {
    for height in 0..=3 {
        for sharing in [
            ProductGkrRootShape::Distinct,
            ProductGkrRootShape::FirstTwoShared,
        ] {
            let verifier = BinaryProductGkrVerifier::<F, F>::new(height, 3, sharing).unwrap();
            let shape = verifier.input_shape();
            let native_shape = ProductGkrShape::new(height, 3, sharing).unwrap();
            let make = || BinaryChallenger::<F, _>::from_hasher(vec![9, 17, 3], Keccak256Hash);
            let dense = |n: usize| {
                F::from_repr(0x2317fcbed892457aca078927af723881u128.wrapping_mul(n as u128 + 11))
            };
            let mut first: Vec<_> = (0..1 << height).map(dense).collect();
            first[0] = F::ZERO;
            let mut second = first.clone();
            second.reverse();
            if sharing == ProductGkrRootShape::Distinct {
                second[0] += F::ONE;
            }
            let third: Vec<_> = (0..(1usize << height) - 1).map(dense).collect();
            let mut native_ch = make();
            let (proof, native) = ProductGkrProof::prove::<F, _>(
                &[&first, &second, &third],
                native_shape,
                &mut native_ch,
            );
            let mut imported_ch = make();
            let imported = verifier.import_native(&proof, &mut imported_ch).unwrap();
            let next = native_ch.sample_algebra_element::<F>();
            assert_eq!(next, imported_ch.sample_algebra_element::<F>());
            let mut b = CircuitBuilder::<F>::new();
            b.enable_native_keccak_f1600().unwrap();
            let targets = shape.allocate_native_targets(&mut b).unwrap();
            let initial = [9, 17, 3].map(|byte| b.define_const(H::encode_u16(byte).unwrap()));
            let ch = BinaryTower128Challenger::with_initial_bytes_with_host::<H, F>(
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
                let difference = b.sub(value.as_expr(), expected.as_expr());
                b.assert_zero(difference);
            }
            let bits = output.challenger.sample_with_host::<H, F>(&mut b).unwrap();
            let actual = b.native_tower128_from_bits(*bits.bits()).unwrap();
            let expected = scalar(&mut b);
            let difference = b.sub(actual.as_expr(), expected.as_expr());
            b.assert_zero(difference);
            let circuit = b.build().unwrap();
            let private = imported.private_native_values(&shape).unwrap();
            let public: Vec<_> = native
                .roots
                .iter()
                .chain(&native.point)
                .chain(&native.values)
                .copied()
                .chain([next])
                .collect();
            assert!(run(&circuit, &public, &private));
            for index in [0, public.len() - 1] {
                let mut wrong = public.clone();
                wrong[index] += F::ONE;
                assert!(!run(&circuit, &wrong, &private));
            }
            let mut wrong = private;
            wrong[0] += F::ONE;
            assert!(!run(&circuit, &public, &wrong));
        }
    }
}
