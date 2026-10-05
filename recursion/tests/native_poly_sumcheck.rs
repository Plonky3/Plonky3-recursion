//! Poly192 sumcheck messages in native Poly64 cells and exact continuations.

use p3_binary_field::{BinaryChallenger, Poly64, Poly192};
use p3_challenger::FieldChallenger;
use p3_circuit::{
    Circuit, CircuitBuilder,
    ops::{
        ByteHash, NativePoly192Target,
        binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding},
    },
};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::Keccak256Hash;
use p3_recursion::{
    BinaryTower128Challenger,
    pcs::binary::{BinaryPolyGenericSumcheckVerifier, BinaryPolyNonzeroChallengePlan},
};
use p3_sumcheck::generic_degree::{GenericDegreeProof, GenericDegreeShape, ProverTranscript};

type F = Poly64;
type E = Poly192;
type H = NativeBinaryEncoding;
fn scalar(b: &mut CircuitBuilder<F>) -> NativePoly192Target {
    let coefficients = core::array::from_fn(|_| b.public_input());
    b.native_poly192_from_coefficients(coefficients)
}
fn bind(b: &mut CircuitBuilder<F>, value: &NativePoly192Target) {
    let expected = scalar(b);
    for (&value, &expected) in value.coefficients().iter().zip(expected.coefficients()) {
        let difference = b.sub(value, expected);
        b.assert_zero(difference);
    }
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
fn native_poly_sumcheck_matches_claims_grinding_and_resumed_draws() {
    for (rounds, degree, pow) in [(0, 1, 0), (1, 4, 0), (2, 4, 2)] {
        for after_queries in [false, true] {
            let verifier = BinaryPolyGenericSumcheckVerifier::new(rounds, degree, pow).unwrap();
            let shape = verifier.input_shape();
            let prefix = BinaryPolyNonzeroChallengePlan::new(1, 4).unwrap();
            let make = || BinaryChallenger::<F, _>::from_hasher(vec![129, 9, 251], Keccak256Hash);
            let value = |i: usize| {
                E::new([
                    F::new(0x80123456789abcdeu64.wrapping_mul(i as u64 + 11)),
                    F::new(0xfedcba9876543210u64.wrapping_mul(i as u64 + 7)),
                    F::new(0x9000000000000001u64.wrapping_mul(i as u64 + 3)),
                ])
            };
            let claimed_sum = value(1);
            let round_polys: Vec<Vec<_>> = (0..rounds)
                .map(|r| (0..degree).map(|i| value(11 + r * 29 + i)).collect())
                .collect();
            let mut native_ch = make();
            if after_queries {
                prefix.sample_native(&mut native_ch).unwrap();
            }
            let mut transcript = ProverTranscript::<_, F, E>::new(
                &mut native_ch,
                GenericDegreeShape::new(rounds, degree, pow),
                claimed_sum,
            );
            let mut pow_witnesses = vec![];
            for poly in &round_polys {
                let (_, witness) = transcript.round(poly);
                pow_witnesses.extend(witness);
            }
            transcript.finish();
            let native = GenericDegreeProof {
                claimed_sum,
                round_polys,
                pow_witnesses,
            };
            let mut replay = make();
            if after_queries {
                prefix.sample_native(&mut replay).unwrap();
            }
            let (point, claim) = native.verify(&mut replay, rounds, degree, pow).unwrap();
            let next = replay.sample_algebra_element::<E>();
            assert_eq!(next, native_ch.sample_algebra_element::<E>());
            let mut import_ch = make();
            if after_queries {
                prefix.sample_native(&mut import_ch).unwrap();
            }
            let imported = verifier.import_native(&native, &mut import_ch).unwrap();
            assert_eq!(next, import_ch.sample_algebra_element::<E>());
            let mut b = CircuitBuilder::<F>::new();
            b.enable_native_keccak_f1600().unwrap();
            let expected_sum = scalar(&mut b);
            let proof = shape.allocate_native_targets(&mut b).unwrap();
            let initial = [129, 9, 251].map(|byte| b.define_const(H::encode_u16(byte).unwrap()));
            let ch = BinaryTower128Challenger::with_initial_bytes_with_host::<H, F>(
                &mut b,
                ByteHash::Keccak256,
                &initial,
            )
            .unwrap();
            let mut output = if after_queries {
                let prefix = prefix.sample_native_targets(&mut b, ch).unwrap();
                verifier
                    .verify_reduction_after_queries_native(
                        &mut b,
                        prefix.continuation,
                        &expected_sum,
                        &proof,
                    )
                    .unwrap()
            } else {
                verifier
                    .verify_reduction_native(&mut b, ch, &expected_sum, &proof)
                    .unwrap()
            };
            for coordinate in &output.point {
                bind(&mut b, coordinate);
            }
            bind(&mut b, &output.claim);
            let bits = output
                .challenger
                .sample_poly192_with_host::<H, F>(&mut b)
                .unwrap();
            let actual = b
                .native_poly192_from_bits(core::array::from_fn(|i| {
                    bits.coefficients()[i / 64].bits()[i % 64]
                }))
                .unwrap();
            bind(&mut b, &actual);
            let circuit = b.build().unwrap();
            let private = imported.private_native_values(&shape).unwrap();
            let public: Vec<_> = [claimed_sum]
                .into_iter()
                .chain(point.iter().copied())
                .chain([claim, next])
                .flat_map(|value| value.coefficients())
                .collect();
            assert!(run(&circuit, &public, &private));
            for index in [
                0,
                1,
                2,
                public.len() - 3,
                public.len() - 2,
                public.len() - 1,
            ] {
                let mut wrong = public.clone();
                wrong[index] += F::ONE;
                assert!(!run(&circuit, &wrong, &private));
            }
            let mut wrong = private.clone();
            wrong[0] += F::ONE;
            assert!(!run(&circuit, &public, &wrong));
            if rounds > 0 {
                let mut wrong = private.clone();
                wrong[3] += F::ONE;
                assert!(!run(&circuit, &public, &wrong));
            }
            if pow > 0 {
                let mut rejected = 0;
                for raw in 1..=16 {
                    let mut wrong = private.clone();
                    wrong[3 * (1 + rounds * degree)] += F::new(raw);
                    rejected += usize::from(!run(&circuit, &public, &wrong));
                }
                assert!(rejected > 0);
            }
            let foreign = BinaryPolyGenericSumcheckVerifier::new(rounds, degree + 1, pow).unwrap();
            assert!(
                imported
                    .private_native_values(&foreign.input_shape())
                    .is_err()
            );
        }
    }
}
