//! Released fractional reductions, bounded replay, and authenticated leaf closure.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField8, BinaryField64, BinaryField128};
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger};
use p3_circuit::ops::{BinaryTower128Target, ByteHash};
use p3_circuit::{Circuit, CircuitBuilder, ExprId};
use p3_field::{ExtensionField, PrimeCharacteristicRing};
use p3_multi_stark::fractional_gkr::{
    Fraction, FractionGkrLayerProof, FractionGkrProof, LeafNumerator, SplitFraction,
    prove_fractional_gkr, verify_fractional_gkr,
};
use p3_multilinear_util::poly::{Poly, PolyMaybePacked};
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{
    BinaryNonzeroChallengePlan, RecursiveBinaryChallengeField, RecursiveBinaryTowerField,
    binary128_eval_multilinear,
};
use p3_recursion::verifier::{BinaryFractionGkrVerifier, VerifierLimits};
use p3_test_utils::binary_field_params::{blake3, keccak};

fn input(b: &mut CircuitBuilder<BabyBear>) -> BinaryTower128Target {
    let limbs = b.alloc_private_input_array::<8>("fraction GKR comparison");
    b.binary128_from_limbs::<BabyBear>(limbs).unwrap()
}
fn equal(b: &mut CircuitBuilder<BabyBear>, a: &BinaryTower128Target, e: &BinaryTower128Target) {
    for (&a, &e) in a.bits().iter().zip(e.bits()) {
        let difference = b.sub(a, e);
        b.assert_zero(difference);
    }
}
fn run(circuit: &Circuit<BabyBear>, values: &[BabyBear]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(values).is_ok() && runner.run().is_ok()
}

fn exercise<F, E, Ch>(
    hash: ByteHash,
    make: impl Fn(u8) -> Ch,
    height: usize,
) -> (Circuit<BabyBear>, Vec<BabyBear>)
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
    Ch: FieldChallenger<F> + Clone,
{
    let verifier = BinaryFractionGkrVerifier::<F, E>::new(height, 4).unwrap();
    let shape = verifier.input_shape();
    let prefix = BinaryNonzeroChallengePlan::<E>::new(1, 4).unwrap();
    let value = |i: usize| {
        E::from_le_byte_iter(
            0x5317fcbed892457aca078927af723881u128
                .wrapping_mul(i as u128 + 2)
                .to_le_bytes()
                .into_iter(),
        )
    };
    let numer: Vec<_> = (0..1usize << height).map(|i| value(i / 2)).collect();
    let denom: Vec<_> = (0..1usize << height).map(|i| value(i / 2 + 17)).collect();
    let native_numer = PolyMaybePacked::<F, E>::Scalar(Poly::new(numer.clone()));
    let native_denom = PolyMaybePacked::<F, E>::Scalar(Poly::new(denom.clone()));
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
    let output = if height == 3 || F::RAW_BITS == 128 {
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
            .map(|&value| b.binary128_constant(value.raw_coordinates()).unwrap())
            .collect::<Vec<_>>();
        let expected = binary128_eval_multilinear(&mut b, &leaves, &output.point).unwrap();
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
    let observation = (0..F::RAW_BITS / 8)
        .map(|i| b.define_const(BabyBear::from_u8(if i == 0 { 9 } else { 0 })))
        .collect::<Vec<_>>();
    let mut ch = output
        .continuation
        .resume_with_observation::<BabyBear, BabyBear>(&mut b, &observation)
        .unwrap();
    let bytes = ch
        .sample_bytes::<BabyBear, BabyBear>(&mut b, E::RAW_BITS / 8)
        .unwrap();
    let mut bits = [ExprId::ZERO; 128];
    for (i, byte) in bytes.into_iter().enumerate() {
        bits[8 * i..8 * i + 8].copy_from_slice(&b.decompose_to_bits::<BabyBear>(byte, 8).unwrap());
    }
    let actual = b.binary128_from_bits(bits).unwrap();
    let expected = input(&mut b);
    equal(&mut b, &actual, &expected);
    let circuit = b.build().unwrap();
    let mut last = Vec::new();
    for seed in [2u8, 19] {
        let begin = || {
            let mut ch = make(seed);
            if height == 3 || F::RAW_BITS == 128 {
                prefix.sample_native::<F, _>(&mut ch).unwrap();
            }
            ch
        };
        let (proof, proved) = prove_fractional_gkr::<F, E, _>(
            Fraction {
                n: LeafNumerator::Ext(&native_numer),
                d: &native_denom,
            },
            &mut begin(),
        );
        let mut verified_ch = begin();
        let verified = verify_fractional_gkr::<F, E, _>(&proof, height, &mut verified_ch).unwrap();
        assert_eq!(proved, verified);
        let evaluate = |leaves: &[E]| {
            (0..1usize << height)
                .map(|index| {
                    leaves[index]
                        * verified
                            .point
                            .iter()
                            .enumerate()
                            .fold(E::ONE, |weight, (bit, &r)| {
                                weight
                                    * if index >> (height - 1 - bit) & 1 == 1 {
                                        r
                                    } else {
                                        E::ONE + r
                                    }
                            })
                })
                .sum::<E>()
        };
        assert_eq!(evaluate(&numer), verified.numerator);
        assert_eq!(evaluate(&denom), verified.denominator);
        let mut imported_ch = begin();
        let imported = verifier.import_native(&proof, &mut imported_ch).unwrap();
        verified_ch.observe(F::from_le_byte_iter(
            (0..F::RAW_BITS / 8).map(|i| if i == 0 { 9 } else { 0 }),
        ));
        imported_ch.observe(F::from_le_byte_iter(
            (0..F::RAW_BITS / 8).map(|i| if i == 0 { 9 } else { 0 }),
        ));
        let next = verified_ch.sample_algebra_element::<E>();
        assert_eq!(imported_ch.sample_algebra_element::<E>(), next);
        let mut values = imported.private_values::<BabyBear>(&shape).unwrap();
        values.extend([seed, 17, 3].map(BabyBear::from_u8));
        for value in
            verified
                .point
                .iter()
                .chain([&verified.numerator, &verified.denominator, &next])
        {
            let raw = value.raw_coordinates();
            values.extend((0..8).map(|i| BabyBear::from_u16((raw >> (16 * i)) as u16)));
        }
        assert!(run(&circuit, &values));
        if !last.is_empty() {
            assert_ne!(last, values);
        }
        for index in [0, 8, values.len() - 8] {
            let mut wrong = values.clone();
            wrong[index] += BabyBear::ONE;
            assert!(!run(&circuit, &wrong));
        }
        if E::RAW_BITS == 64 {
            let mut wrong = values.clone();
            wrong[4] = BabyBear::ONE;
            assert!(!run(&circuit, &wrong));
        }
        let unchanged = |bad| {
            let mut ch = begin();
            assert!(verifier.import_native(&bad, &mut ch).is_err());
            assert_eq!(
                ch.sample_algebra_element::<E>(),
                begin().sample_algebra_element::<E>()
            );
        };
        let mut bad = proof.clone();
        bad.layers.pop();
        unchanged(bad);
        let mut bad = proof.clone();
        bad.layers[0].round_polys.push([E::ZERO; 3]);
        unchanged(bad);
        let mut bad = proof.clone();
        bad.root_denominator = E::ZERO;
        unchanged(bad);
        let mut bad = proof.clone();
        bad.layers[0].claims.n0 += E::ONE;
        unchanged(bad);
        if height > 1 {
            let mut bad = proof.clone();
            bad.layers[1].round_polys[0][0] += E::ONE;
            unchanged(bad);
        }
        let foreign = BinaryFractionGkrVerifier::<F, E>::new(height, 5).unwrap();
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
fn fraction_layers_match_native_reductions_for_both_hashes_and_widths() {
    for height in [1, 2, 3] {
        exercise::<BinaryField8, BinaryField64, _>(
            ByteHash::Keccak256,
            |seed| keccak::LevelChallenger::from_hasher(vec![seed, 17, 3], keccak::byte_hash()),
            height,
        );
        exercise::<BinaryField8, BinaryField128, _>(
            ByteHash::Blake3,
            |seed| blake3::LevelChallenger::from_hasher(vec![seed, 17, 3], blake3::byte_hash()),
            height,
        );
        exercise::<BinaryField8, BinaryField128, _>(
            ByteHash::Keccak256,
            |seed| keccak::LevelChallenger::from_hasher(vec![seed, 17, 3], keccak::byte_hash()),
            height,
        );
        exercise::<BinaryField8, BinaryField64, _>(
            ByteHash::Blake3,
            |seed| blake3::LevelChallenger::from_hasher(vec![seed, 17, 3], blake3::byte_hash()),
            height,
        );
    }
    exercise::<BinaryField128, BinaryField128, _>(
        ByteHash::Keccak256,
        |seed| keccak::LevelChallenger::from_hasher(vec![seed, 17, 3], keccak::byte_hash()),
        1,
    );
}

#[test]
fn fraction_geometry_and_aggregate_limits_are_checked_before_allocation() {
    assert!(BinaryFractionGkrVerifier::<BinaryField128>::new(0, 4).is_err());
    assert!(BinaryFractionGkrVerifier::<BinaryField128>::new(usize::MAX, 4).is_err());
    assert!(BinaryFractionGkrVerifier::<BinaryField128>::new(1, 0).is_err());
    let usage = BinaryFractionGkrVerifier::<BinaryField128>::new(3, 4)
        .unwrap()
        .input_resource_usage();
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
        assert!(BinaryFractionGkrVerifier::<BinaryField128>::with_limits(3, 4, &limits).is_err());
    }
    assert!(
        BinaryFractionGkrVerifier::<BinaryField128>::with_limits(
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
impl CanObserve<BinaryField128> for ZeroChallenger {
    fn observe(&mut self, _: BinaryField128) {}
}
impl CanSample<BinaryField128> for ZeroChallenger {
    fn sample(&mut self) -> BinaryField128 {
        self.draws += 1;
        BinaryField128::ZERO
    }
}
impl CanSampleBits<usize> for ZeroChallenger {
    fn sample_bits(&mut self, _: usize) -> usize {
        panic!("fraction GKR has no bit samples")
    }
}
impl FieldChallenger<BinaryField128> for ZeroChallenger {}

#[test]
fn native_fraction_rejection_is_finite_and_leaves_the_caller_unchanged() {
    let verifier = BinaryFractionGkrVerifier::<BinaryField128>::with_limits(
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
        BinaryFractionGkrVerifier::<BinaryField128>::with_limits(
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
        root_denominator: BinaryField128::ONE,
        layers: vec![FractionGkrLayerProof {
            round_polys: vec![],
            claims: SplitFraction {
                n0: BinaryField128::ONE,
                n1: BinaryField128::ONE,
                d0: BinaryField128::ONE,
                d1: BinaryField128::ONE,
            },
        }],
    };
    let mut ch = ZeroChallenger { draws: 0 };
    assert!(verifier.import_native(&proof, &mut ch).is_err());
    assert_eq!(ch.draws, 0);
}

#[test]
fn a_closed_fraction_reduction_proves_in_a_prime_field_circuit() {
    use p3_circuit_prover::ConstraintProfile;
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, Blake3CompressAirBuilder, Blake3CompressPreprocessor,
        Blake3CompressProver,
    };
    let (circuit, values) = exercise::<BinaryField8, BinaryField64, _>(
        ByteHash::Blake3,
        |seed| blake3::LevelChallenger::from_hasher(vec![seed, 17, 3], blake3::byte_hash()),
        2,
    );
    let mut prover = BatchStarkProver::new(crate::proof_config());
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
