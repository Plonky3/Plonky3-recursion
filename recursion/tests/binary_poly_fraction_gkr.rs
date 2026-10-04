//! Released fractional reductions, bounded replay, and authenticated leaf closure.

use p3_baby_bear::BabyBear;
use p3_binary_field::{Poly64, Poly192};
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger};
use p3_circuit::ops::{BinaryPoly192Target, ByteHash};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_multi_stark::fractional_gkr::{
    Fraction, FractionGkrLayerProof, FractionGkrProof, LeafNumerator, SplitFraction,
    prove_fractional_gkr, verify_fractional_gkr,
};
use p3_multilinear_util::poly::{Poly, PolyMaybePacked};
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::BinaryPolyNonzeroChallengePlan;
use p3_recursion::verifier::{BinaryPolyFractionGkrVerifier, VerifierLimits};
use p3_test_utils::binary_field_params::{blake3, keccak};

fn input(b: &mut CircuitBuilder<BabyBear>) -> BinaryPoly192Target {
    let limbs = b.alloc_private_input_array::<12>("fraction GKR comparison");
    b.binary_poly192_from_limbs::<BabyBear>(limbs).unwrap()
}
fn equal(b: &mut CircuitBuilder<BabyBear>, a: &BinaryPoly192Target, e: &BinaryPoly192Target) {
    for (&a, &e) in a
        .coefficients()
        .iter()
        .flat_map(|c| c.bits())
        .zip(e.coefficients().iter().flat_map(|c| c.bits()))
    {
        let difference = b.sub(a, e);
        b.assert_zero(difference);
    }
}
fn evaluate_fixed(
    b: &mut CircuitBuilder<BabyBear>,
    leaves: &[BinaryPoly192Target],
    point: &[BinaryPoly192Target],
) -> BinaryPoly192Target {
    let one = b.binary_poly192_constant([1, 0, 0]).unwrap();
    let mut sum = b.binary_poly192_constant([0; 3]).unwrap();
    for (index, value) in leaves.iter().enumerate() {
        let mut weight = one.clone();
        for (bit, r) in point.iter().enumerate() {
            let factor = if index >> (point.len() - 1 - bit) & 1 == 1 {
                r.clone()
            } else {
                b.binary_poly192_add(&one, r)
            };
            weight = b.binary_poly192_mul(&weight, &factor);
        }
        let term = b.binary_poly192_mul(&weight, value);
        sum = b.binary_poly192_add(&sum, &term);
    }
    sum
}

fn run(circuit: &Circuit<BabyBear>, values: &[BabyBear]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(values).is_ok() && runner.run().is_ok()
}

fn exercise<Ch>(
    hash: ByteHash,
    make: impl Fn(u8) -> Ch,
    height: usize,
    high_root: bool,
) -> (Circuit<BabyBear>, Vec<BabyBear>)
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
    let mut b = CircuitBuilder::<BabyBear>::new();
    match hash {
        ByteHash::Keccak256 => b.enable_keccak_f1600::<BabyBear>(),
        ByteHash::Blake3 => b.enable_blake3_compress::<BabyBear>(),
    }
    let targets = shape
        .allocate_targets::<BabyBear, BabyBear>(&mut b)
        .unwrap();
    let initial = b.alloc_private_input_array::<3>("fraction initial transcript");
    let ch =
        BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(&mut b, hash, &initial)
            .unwrap();
    let output = if height == 3 {
        let prefix = prefix.sample::<BabyBear, BabyBear>(&mut b, ch).unwrap();
        verifier
            .verify_reduction_after_queries::<BabyBear, BabyBear>(
                &mut b,
                prefix.continuation,
                &targets,
            )
            .unwrap()
    } else {
        verifier
            .verify_reduction::<BabyBear, BabyBear>(&mut b, ch, &targets)
            .unwrap()
    };
    // Close both returned claims against independent, fixed input polynomials.
    for (leaves, actual) in [(&numer, &output.numerator), (&denom, &output.denominator)] {
        let leaves = leaves
            .iter()
            .map(|&value| {
                b.binary_poly192_constant(value.coefficients().map(|c| c.to_bits()))
                    .unwrap()
            })
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
        .map(|v| b.define_const(BabyBear::from_u8(v)));
    let mut ch = output
        .continuation
        .resume_with_observation::<BabyBear, BabyBear>(&mut b, &observation)
        .unwrap();
    for _ in 0..2 {
        let actual = ch.sample_poly192::<BabyBear, BabyBear>(&mut b).unwrap();
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
        let mut values = imported.private_values::<BabyBear>(&shape).unwrap();
        values.extend([seed, 17, 3].map(BabyBear::from_u8));
        for value in verified
            .point
            .iter()
            .chain([&verified.numerator, &verified.denominator])
            .chain(&nexts)
        {
            for coefficient in value.coefficients() {
                let raw = coefficient.to_bits();
                values.extend((0..4).map(|i| BabyBear::from_u16((raw >> (16 * i)) as u16)));
            }
        }
        assert!(run(&circuit, &values));
        if !last.is_empty() {
            assert_ne!(last, values);
        }
        for index in [0, 8, 12, values.len() - 4] {
            let mut wrong = values.clone();
            wrong[index] += BabyBear::ONE;
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
                .private_values::<BabyBear>(&foreign.input_shape())
                .is_err()
        );
        let mut malformed_targets = targets.clone();
        malformed_targets.layers.pop();
        let mut other_builder = CircuitBuilder::<BabyBear>::new();
        assert!(
            verifier
                .verify_reduction::<BabyBear, BabyBear>(
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
fn full_poly192_fraction_layers_match_native_for_both_hashes() {
    for height in [1, 2, 3] {
        exercise(
            ByteHash::Keccak256,
            |seed| keccak::LevelChallenger::from_hasher(vec![seed, 17, 3], keccak::byte_hash()),
            height,
            false,
        );
        exercise(
            ByteHash::Blake3,
            |seed| blake3::LevelChallenger::from_hasher(vec![seed, 17, 3], blake3::byte_hash()),
            height,
            false,
        );
    }
}

#[test]
fn a_coefficient_two_only_root_denominator_is_nonzero() {
    exercise(
        ByteHash::Blake3,
        |seed| blake3::LevelChallenger::from_hasher(vec![seed, 17, 3], blake3::byte_hash()),
        1,
        true,
    );
}

#[test]
fn fraction_geometry_and_aggregate_limits_are_checked_before_allocation() {
    assert!(BinaryPolyFractionGkrVerifier::new(0, 4).is_err());
    assert!(BinaryPolyFractionGkrVerifier::new(usize::MAX, 4).is_err());
    assert!(BinaryPolyFractionGkrVerifier::new(1, 0).is_err());
    let usage = BinaryPolyFractionGkrVerifier::new(3, 4)
        .unwrap()
        .input_resource_usage();
    assert_eq!(usage.scalar_elements, 22 * 12);
    assert_eq!(usage.rounds, 9);
    assert_eq!(usage.queries, 27);
    for limits in [
        VerifierLimits {
            max_rounds: usage.rounds - 1,
            ..VerifierLimits::default()
        },
        VerifierLimits {
            max_queries_per_round: 4,
            ..VerifierLimits::default()
        },
        VerifierLimits {
            max_total_scalar_elements: usage.scalar_elements - 1,
            ..VerifierLimits::default()
        },
        VerifierLimits {
            max_metadata_entries: usage.metadata_entries - 1,
            ..VerifierLimits::default()
        },
    ] {
        assert!(BinaryPolyFractionGkrVerifier::with_limits(3, 4, &limits).is_err());
    }
    assert!(
        BinaryPolyFractionGkrVerifier::with_limits(
            3,
            4,
            &VerifierLimits {
                max_metadata_entries: usage.metadata_entries,
                ..VerifierLimits::default()
            }
        )
        .is_ok()
    );
}

#[derive(Clone)]
struct ZeroChallenger {
    draws: usize,
}
impl CanObserve<Poly64> for ZeroChallenger {
    fn observe(&mut self, _: Poly64) {}
}
impl CanSample<Poly64> for ZeroChallenger {
    fn sample(&mut self) -> Poly64 {
        self.draws += 1;
        Poly64::ZERO
    }
}
impl CanSampleBits<usize> for ZeroChallenger {
    fn sample_bits(&mut self, _: usize) -> usize {
        panic!("fraction GKR has no bit samples")
    }
}
impl FieldChallenger<Poly64> for ZeroChallenger {}

#[test]
fn native_fraction_rejection_is_finite_and_leaves_the_caller_unchanged() {
    let verifier = BinaryPolyFractionGkrVerifier::with_limits(
        1,
        2,
        &VerifierLimits {
            max_rounds: 2,
            max_queries_per_round: 2,
            ..VerifierLimits::default()
        },
    )
    .unwrap();
    assert!(
        BinaryPolyFractionGkrVerifier::with_limits(
            1,
            2,
            &VerifierLimits {
                max_rounds: 1,
                ..VerifierLimits::default()
            }
        )
        .is_err()
    );
    let proof = FractionGkrProof {
        root_denominator: Poly192::ONE,
        layers: vec![FractionGkrLayerProof {
            round_polys: vec![],
            claims: SplitFraction {
                n0: Poly192::ONE,
                n1: Poly192::ONE,
                d0: Poly192::ONE,
                d1: Poly192::ONE,
            },
        }],
    };
    let mut ch = ZeroChallenger { draws: 0 };
    assert!(verifier.import_native(&proof, &mut ch).is_err());
    assert_eq!(ch.draws, 0);
}

#[test]
fn a_closed_fraction_reduction_proves_in_a_prime_field_circuit() {
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, Blake3CompressAirBuilder, Blake3CompressPreprocessor,
        Blake3CompressProver,
    };
    use p3_circuit_prover::{ConstraintProfile, config};
    let (circuit, values) = exercise(
        ByteHash::Blake3,
        |seed| blake3::LevelChallenger::from_hasher(vec![seed, 17, 3], blake3::byte_hash()),
        2,
        false,
    );
    let mut prover = BatchStarkProver::new(config::baby_bear());
    prover.register_table_prover(Box::new(Blake3CompressProver::<1>));
    let prepared = prover
        .prepare_circuit::<BabyBear, 1>(
            &circuit,
            &[Box::new(Blake3CompressPreprocessor)],
            &[Box::new(Blake3CompressAirBuilder::<1>)],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let mut runner = circuit.runner();
    runner.set_private_inputs(&values).unwrap();
    let proof = prepared.prove(&runner.run().unwrap()).unwrap();
    prepared.verifier().verify(&proof, &[]).unwrap();
}
