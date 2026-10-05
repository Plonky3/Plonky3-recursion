//! Native scalar sumcheck messages, grinding and transcript continuation.

use p3_binary_field::{BinaryChallenger, BinaryField128, TowerLevel};
use p3_challenger::FieldChallenger;
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::{ByteHash, NativeTower128Target};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::Keccak256Hash;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{BinaryGenericSumcheckVerifier, BinaryNonzeroChallengePlan};
use p3_sumcheck::generic_degree::{GenericDegreeProof, GenericDegreeShape, ProverTranscript};

type F = BinaryField128;
type H = NativeBinaryEncoding;
fn scalar(b: &mut CircuitBuilder<F>) -> NativeTower128Target {
    let expression = b.public_input();
    b.native_tower128_from_expr(expression)
}
fn bind(b: &mut CircuitBuilder<F>, value: &NativeTower128Target) {
    let expected = scalar(b);
    let difference = b.sub(value.as_expr(), expected.as_expr());
    b.assert_zero(difference);
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
fn scalar_sumcheck_matches_native_claims_grinding_and_resumed_draws() {
    for (rounds, degree, pow) in [(0, 1, 0), (1, 4, 0), (2, 4, 2)] {
        for after_queries in [false, true] {
            let verifier = BinaryGenericSumcheckVerifier::<F, F>::new(rounds, degree, pow).unwrap();
            let shape = verifier.input_shape();
            let prefix = BinaryNonzeroChallengePlan::<F>::new(1, 4).unwrap();
            let make = || BinaryChallenger::<F, _>::from_hasher(vec![129, 9, 251], Keccak256Hash);
            let value = |i: usize| {
                F::from_repr(0x2317fcbed892457aca078927af723881u128.wrapping_mul(i as u128 + 11))
            };
            let claimed_sum = value(1);
            let round_polys: Vec<Vec<_>> = (0..rounds)
                .map(|r| (0..degree).map(|i| value(11 + r * 29 + i)).collect())
                .collect();
            let mut native_ch = make();
            if after_queries {
                prefix.sample_native::<F, _>(&mut native_ch).unwrap();
            }
            let mut transcript = ProverTranscript::<_, F, F>::new(
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
                prefix.sample_native::<F, _>(&mut replay).unwrap();
            }
            let (point, claim) = native.verify(&mut replay, rounds, degree, pow).unwrap();
            let next = replay.sample_algebra_element::<F>();
            assert_eq!(next, native_ch.sample_algebra_element::<F>());
            let mut import_ch = make();
            if after_queries {
                prefix.sample_native::<F, _>(&mut import_ch).unwrap();
            }
            let imported = verifier.import_native(&native, &mut import_ch).unwrap();
            assert_eq!(next, import_ch.sample_algebra_element::<F>());
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
                let prefix = prefix.sample_with_host::<H, F>(&mut b, ch).unwrap();
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
            let bits = output.challenger.sample_with_host::<H, F>(&mut b).unwrap();
            let actual = b.native_tower128_from_bits(*bits.bits()).unwrap();
            bind(&mut b, &actual);
            let circuit = b.build().unwrap();
            let private = imported.private_native_values(&shape).unwrap();
            let public: Vec<_> = [claimed_sum]
                .into_iter()
                .chain(point.iter().copied())
                .chain([claim, next])
                .collect();
            assert!(run(&circuit, &public, &private));
            for index in [0, public.len() - 2, public.len() - 1] {
                let mut wrong = public.clone();
                wrong[index] += F::ONE;
                assert!(!run(&circuit, &wrong, &private));
            }
            let mut wrong = private.clone();
            wrong[0] += F::ONE;
            assert!(!run(&circuit, &public, &wrong));
            if rounds > 0 {
                let mut wrong = private.clone();
                wrong[1] += F::ONE;
                assert!(!run(&circuit, &public, &wrong));
            }
            if pow > 0 {
                let mut rejected = 0;
                for raw in 1..=16 {
                    let mut wrong = private.clone();
                    wrong[1 + rounds * degree] += F::from_repr(raw);
                    rejected += usize::from(!run(&circuit, &public, &wrong));
                }
                assert!(rejected > 0);
            }
            let foreign =
                BinaryGenericSumcheckVerifier::<F, F>::new(rounds, degree + 1, pow).unwrap();
            assert!(
                imported
                    .private_native_values(&foreign.input_shape())
                    .is_err()
            );
        }
    }
}
