//! Native Poly64 Fraction GKR with independently authenticated leaf closure.

use p3_binary_field::{BinaryChallenger, Poly64, Poly192};
use p3_challenger::FieldChallenger;
use p3_circuit::ops::{
    ByteHash, NativePoly192Target,
    binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding},
};
use p3_keccak::Keccak256Hash;
type H = NativeBinaryEncoding;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_multi_stark::fractional_gkr::{
    Fraction, LeafNumerator, prove_fractional_gkr, verify_fractional_gkr,
};
use p3_multilinear_util::poly::{Poly, PolyMaybePacked};
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::BinaryPolyNonzeroChallengePlan;
use p3_recursion::verifier::BinaryPolyFractionGkrVerifier;

fn input(b: &mut CircuitBuilder<Poly64>) -> NativePoly192Target {
    let coefficients = b.alloc_private_input_array::<3>("native fraction comparison");
    b.native_poly192_from_coefficients(coefficients)
}
fn equal(b: &mut CircuitBuilder<Poly64>, a: &NativePoly192Target, e: &NativePoly192Target) {
    for (&a, &e) in a.coefficients().iter().zip(e.coefficients()) {
        let difference = b.sub(a, e);
        b.assert_zero(difference);
    }
}
fn evaluate_fixed(
    b: &mut CircuitBuilder<Poly64>,
    leaves: &[NativePoly192Target],
    point: &[NativePoly192Target],
) -> NativePoly192Target {
    let one = b.native_poly192_constant([1, 0, 0]);
    let mut sum = b.native_poly192_constant([0; 3]);
    for (index, value) in leaves.iter().enumerate() {
        let mut weight = one.clone();
        for (bit, r) in point.iter().enumerate() {
            let factor = if index >> (point.len() - 1 - bit) & 1 == 1 {
                r.clone()
            } else {
                b.native_poly192_add(&one, r)
            };
            weight = b.native_poly192_mul(&weight, &factor);
        }
        let term = b.native_poly192_mul(&weight, value);
        sum = b.native_poly192_add(&sum, &term);
    }
    sum
}

fn run(circuit: &Circuit<Poly64>, values: &[Poly64]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(values).is_ok() && runner.run().is_ok()
}

fn exercise<Ch>(
    hash: ByteHash,
    make: impl Fn(u8) -> Ch,
    height: usize,
    high_root: bool,
) -> (Circuit<Poly64>, Vec<Poly64>)
where
    Ch: FieldChallenger<Poly64> + Clone,
{
    let verifier = BinaryPolyFractionGkrVerifier::new(height, 4).unwrap();
    let shape = verifier.input_shape();
    let prefix = BinaryPolyNonzeroChallengePlan::new(1, 4).unwrap();
    let value = |i: usize| {
        let raw = 0x5317fcbed892457aca078927af723881u128.wrapping_mul(i as u128 + 2);
        Poly192::new([
            Poly64::new(raw as u64),
            Poly64::new((raw >> 64) as u64),
            Poly64::new((raw as u64).rotate_left(13) ^ 0xfedcba9876543210),
        ])
    };
    let count = 1usize << height;
    let denom: Vec<_> = if high_root {
        assert_eq!(height, 1);
        vec![
            Poly192::ONE,
            Poly192::new([Poly64::ZERO, Poly64::ZERO, Poly64::ONE]),
        ]
    } else {
        (0..count).map(|i| value(i + 17)).collect()
    };
    let mut quotients: Vec<_> = (0..count - 1).map(value).collect();
    quotients.push(quotients.iter().copied().sum());
    let numer: Vec<_> = quotients.iter().zip(&denom).map(|(&q, &d)| q * d).collect();
    let native_numer = PolyMaybePacked::<Poly64, Poly192>::Scalar(Poly::new(numer.clone()));
    let native_denom = PolyMaybePacked::<Poly64, Poly192>::Scalar(Poly::new(denom.clone()));
    let mut b = CircuitBuilder::<Poly64>::new();
    assert_eq!(hash, ByteHash::Keccak256);
    b.enable_native_keccak_f1600().unwrap();
    let targets = shape.allocate_native_targets(&mut b).unwrap();
    let initial = b.alloc_private_input_array::<3>("fraction initial transcript");
    let ch =
        BinaryTower128Challenger::with_initial_bytes_with_host::<H, Poly64>(&mut b, hash, &initial)
            .unwrap();
    let output = if height == 3 {
        let prefix = prefix.sample_native_targets(&mut b, ch).unwrap();
        verifier
            .verify_reduction_after_queries_native(&mut b, prefix.continuation, &targets)
            .unwrap()
    } else {
        verifier
            .verify_reduction_native(&mut b, ch, &targets)
            .unwrap()
    };
    // Close both returned claims against independent, fixed input polynomials.
    for (leaves, actual) in [(&numer, &output.numerator), (&denom, &output.denominator)] {
        let leaves = leaves
            .iter()
            .map(|&value| b.native_poly192_constant(value.coefficients().map(|c| c.to_bits())))
            .collect::<Vec<_>>();
        let expected = evaluate_fixed(&mut b, &leaves, &output.point);
        equal(&mut b, actual, &expected);
    }
    for value in output
        .point
        .iter()
        .chain([&output.numerator, &output.denominator])
    {
        let expected = input(&mut b);
        equal(&mut b, value, &expected);
    }
    let observation = Poly64::new(0x9137_acde_0123_4567)
        .to_bits()
        .to_le_bytes()
        .map(|v| b.define_const(H::encode_u16(u16::from(v)).unwrap()));
    let mut ch = output
        .continuation
        .resume_with_observation_with_host::<H, Poly64>(&mut b, &observation)
        .unwrap();
    for _ in 0..2 {
        let bits = ch.sample_poly192_with_host::<H, Poly64>(&mut b).unwrap();
        let actual = b
            .native_poly192_from_bits(core::array::from_fn(|i| {
                bits.coefficients()[i / 64].bits()[i % 64]
            }))
            .unwrap();
        let expected = input(&mut b);
        equal(&mut b, &actual, &expected);
    }
    let circuit = b.build().unwrap();
    let mut last = Vec::new();
    for seed in [2u8, 19] {
        let begin = || {
            let mut ch = make(seed);
            if height == 3 {
                prefix.sample_native(&mut ch).unwrap();
            }
            ch
        };
        let (proof, proved) = prove_fractional_gkr::<Poly64, Poly192, _>(
            Fraction {
                n: LeafNumerator::Ext(&native_numer),
                d: &native_denom,
            },
            &mut begin(),
        );
        let mut verified_ch = begin();
        let verified =
            verify_fractional_gkr::<Poly64, Poly192, _>(&proof, height, &mut verified_ch).unwrap();
        assert_eq!(proved, verified);
        let evaluate = |leaves: &[Poly192]| {
            (0..1usize << height)
                .map(|index| {
                    leaves[index]
                        * verified.point.iter().enumerate().fold(
                            Poly192::ONE,
                            |weight, (bit, &r)| {
                                weight
                                    * if index >> (height - 1 - bit) & 1 == 1 {
                                        r
                                    } else {
                                        Poly192::ONE + r
                                    }
                            },
                        )
                })
                .sum::<Poly192>()
        };
        assert_eq!(evaluate(&numer), verified.numerator);
        assert_eq!(evaluate(&denom), verified.denominator);
        let mut imported_ch = begin();
        let imported = verifier.import_native(&proof, &mut imported_ch).unwrap();
        let observed = Poly64::new(0x9137_acde_0123_4567);
        verified_ch.observe(observed);
        imported_ch.observe(observed);
        let nexts: Vec<_> = (0..2)
            .map(|_| {
                let next = verified_ch.sample_algebra_element::<Poly192>();
                assert_eq!(imported_ch.sample_algebra_element::<Poly192>(), next);
                next
            })
            .collect();
        let mut values = imported.private_native_values(&shape).unwrap();
        let initial_values: [Poly64; 3] =
            [seed, 17, 3].map(|byte| H::encode_u16(u16::from(byte)).unwrap());
        values.extend(initial_values);
        for value in verified
            .point
            .iter()
            .chain([&verified.numerator, &verified.denominator])
            .chain(&nexts)
        {
            values.extend(value.coefficients());
        }
        assert!(run(&circuit, &values));
        if !last.is_empty() {
            assert_ne!(last, values);
        }
        for index in [0, 1, 2, 3, values.len() - 1] {
            let mut wrong = values.clone();
            wrong[index] += Poly64::ONE;
            assert!(!run(&circuit, &wrong));
        }
        let unchanged = |bad| {
            let mut ch = begin();
            assert!(verifier.import_native(&bad, &mut ch).is_err());
            assert_eq!(
                ch.sample_algebra_element::<Poly192>(),
                begin().sample_algebra_element::<Poly192>()
            );
        };
        let mut bad = proof.clone();
        bad.layers.pop();
        unchanged(bad);
        let mut bad = proof.clone();
        bad.layers[0].round_polys.push([Poly192::ZERO; 3]);
        unchanged(bad);
        let mut bad = proof.clone();
        bad.root_denominator = Poly192::ZERO;
        unchanged(bad);
        let mut bad = proof.clone();
        bad.layers[0].claims.n0 += Poly192::ONE;
        unchanged(bad);
        if height > 1 {
            let mut bad = proof.clone();
            bad.layers[1].round_polys[0][0] += Poly192::ONE;
            unchanged(bad);
        }
        let foreign = BinaryPolyFractionGkrVerifier::new(height, 5).unwrap();
        assert!(
            imported
                .private_native_values(&foreign.input_shape())
                .is_err()
        );
        let mut malformed_targets = targets.clone();
        malformed_targets.layers.pop();
        let mut other_builder = CircuitBuilder::<Poly64>::new();
        assert!(
            verifier
                .verify_reduction_native(
                    &mut other_builder,
                    BinaryTower128Challenger::new(hash),
                    &malformed_targets
                )
                .is_err()
        );
        last = values;
    }
    (circuit, last)
}

#[test]
fn native_poly_fraction_authenticates_leaf_claims_and_continuations() {
    for height in [1, 2, 3] {
        exercise(
            ByteHash::Keccak256,
            |seed| BinaryChallenger::<Poly64, _>::from_hasher(vec![seed, 17, 3], Keccak256Hash),
            height,
            false,
        );
    }
}
#[test]
fn native_poly_fraction_accepts_a_coefficient_two_only_root() {
    exercise(
        ByteHash::Keccak256,
        |seed| BinaryChallenger::<Poly64, _>::from_hasher(vec![seed, 17, 3], Keccak256Hash),
        1,
        true,
    );
}
