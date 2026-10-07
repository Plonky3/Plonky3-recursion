//! Released product-tree reductions inside prime-field circuits.

use p3_baby_bear::BabyBear;
use p3_binary_field::{Poly64, Poly192};
use p3_bus::{ProductGkrProof, ProductGkrRootShape, ProductGkrShape};
use p3_challenger::FieldChallenger;
use p3_circuit::ops::{BinaryPoly192Target, ByteHash};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::verifier::{BinaryPolyProductGkrVerifier, VerifierLimits};
use p3_test_utils::binary_field_params::{blake3, keccak};

fn input(b: &mut CircuitBuilder<BabyBear>) -> BinaryPoly192Target {
    let limbs = b.alloc_private_input_array::<12>("product GKR comparison");
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

fn run(circuit: &Circuit<BabyBear>, values: &[BabyBear]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(values).is_ok() && runner.run().is_ok()
}

fn exercise<Ch>(
    hash: ByteHash,
    make: impl Fn() -> Ch,
    height: usize,
    root_shape: ProductGkrRootShape,
) -> (Circuit<BabyBear>, Vec<BabyBear>)
where
    Ch: FieldChallenger<Poly64> + Clone,
{
    let verifier = BinaryPolyProductGkrVerifier::new(height, 3, root_shape).unwrap();
    let shape = verifier.input_shape();
    let native_shape = ProductGkrShape::new(height, 3, root_shape).unwrap();
    let mut b = CircuitBuilder::<BabyBear>::new();
    match hash {
        ByteHash::Keccak256 => b.enable_keccak_f1600::<BabyBear>(),
        ByteHash::Blake3 => b.enable_blake3_compress::<BabyBear>(),
    }
    let proof = shape
        .allocate_targets::<BabyBear, BabyBear>(&mut b)
        .unwrap();
    let initial: Vec<_> = [9, 17, 3]
        .into_iter()
        .map(|v| b.define_const(BabyBear::from_u8(v)))
        .collect();
    let ch =
        BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(&mut b, hash, &initial)
            .unwrap();
    let mut output = verifier
        .verify_reduction::<BabyBear, BabyBear>(&mut b, ch, &proof)
        .unwrap();
    for value in output
        .roots
        .iter()
        .chain(&output.point)
        .chain(&output.values)
    {
        let expected = input(&mut b);
        equal(&mut b, value, &expected);
    }
    let continuation = output
        .challenger
        .sample_poly192::<BabyBear, BabyBear>(&mut b)
        .unwrap();
    let expected = input(&mut b);
    equal(&mut b, &continuation, &expected);
    let circuit = b.build().unwrap();
    let mut last = Vec::new();
    for seed in [2u128, 19] {
        let value = |i: usize| {
            let raw = 0x2317fcbed892457aca078927af723881u128.wrapping_mul(seed + i as u128);
            Poly192::new([
                Poly64::new(raw as u64),
                Poly64::new((raw >> 64) as u64),
                Poly64::new((raw as u64).rotate_left(17) ^ 0xfedcba9876543210),
            ])
        };
        let mut first: Vec<_> = (0..1usize << height).map(value).collect();
        // Zero roots are valid, including structurally shared zero roots.
        first[0] = Poly192::ZERO;
        let mut second = first.clone();
        second.reverse();
        if root_shape == ProductGkrRootShape::Distinct {
            second[0] += Poly192::ONE;
        }
        // A short arbitrary prefix exercises native identity padding.
        let third: Vec<_> = (0..(1usize << height).saturating_sub(1))
            .map(value)
            .collect();
        let mut prover_ch = make();
        let (native, native_output) = ProductGkrProof::prove::<Poly64, _>(
            &[&first, &second, &third],
            native_shape,
            &mut prover_ch,
        );
        for (leaves, &expected) in [&first, &second, &third]
            .into_iter()
            .zip(&native_output.values)
        {
            let actual = (0..1usize << height)
                .map(|index| {
                    let weight = native_output.point.iter().enumerate().fold(
                        Poly192::ONE,
                        |weight, (bit, &r)| {
                            weight
                                * if index >> (height - 1 - bit) & 1 == 1 {
                                    r
                                } else {
                                    Poly192::ONE + r
                                }
                        },
                    );
                    weight * leaves.get(index).copied().unwrap_or(Poly192::ONE)
                })
                .sum::<Poly192>();
            assert_eq!(actual, expected);
        }
        let mut imported_ch = make();
        let imported = verifier.import_native(&native, &mut imported_ch).unwrap();
        let next = prover_ch.sample_algebra_element::<Poly192>();
        assert_eq!(imported_ch.sample_algebra_element::<Poly192>(), next);
        let mut values = imported.private_values::<BabyBear>(&shape).unwrap();
        for value in native_output
            .roots
            .iter()
            .chain(&native_output.point)
            .chain(&native_output.values)
            .chain(core::slice::from_ref(&next))
        {
            for coefficient in value.coefficients() {
                let raw = coefficient.to_bits();
                values.extend((0..4).map(|i| BabyBear::from_u16((raw >> (16 * i)) as u16)));
            }
        }
        assert!(run(&circuit, &values));
        if !last.is_empty() && height > 0 {
            assert_ne!(last, values);
        }
        let mut wrong = values.clone();
        wrong[0] += BabyBear::ONE;
        assert!(!run(&circuit, &wrong));
        let mut high = values.clone();
        high[8] += BabyBear::ONE;
        assert!(!run(&circuit, &high));
        let mut malformed = native.clone();
        malformed.roots.push(Poly192::ONE);
        let mut failed_ch = make();
        assert!(verifier.import_native(&malformed, &mut failed_ch).is_err());
        assert_eq!(
            failed_ch.sample_algebra_element::<Poly192>(),
            make().sample_algebra_element::<Poly192>()
        );
        if height > 0 {
            let mut inconsistent = native.clone();
            inconsistent.roots[0] += Poly192::ONE;
            let mut failed_ch = make();
            assert!(
                verifier
                    .import_native(&inconsistent, &mut failed_ch)
                    .is_err()
            );
            assert_eq!(
                failed_ch.sample_algebra_element::<Poly192>(),
                make().sample_algebra_element::<Poly192>()
            );
        }
        let different = BinaryPolyProductGkrVerifier::new(height + 1, 3, root_shape).unwrap();
        assert!(
            imported
                .private_values::<BabyBear>(&different.input_shape())
                .is_err()
        );
        last = values;
    }
    (circuit, last)
}

#[test]
fn odd_and_even_product_layers_match_both_native_hashes() {
    for height in [0, 1, 3, 4] {
        for roots in [
            ProductGkrRootShape::Distinct,
            ProductGkrRootShape::FirstTwoShared,
        ] {
            exercise(
                ByteHash::Keccak256,
                || keccak::LevelChallenger::from_hasher(vec![9, 17, 3], keccak::byte_hash()),
                height,
                roots,
            );
            exercise(
                ByteHash::Blake3,
                || blake3::LevelChallenger::from_hasher(vec![9, 17, 3], blake3::byte_hash()),
                height,
                roots,
            );
        }
    }
}

#[test]
fn product_geometry_and_aggregate_budgets_are_checked() {
    let roots = ProductGkrRootShape::FirstTwoShared;
    let usage = BinaryPolyProductGkrVerifier::new(4, 3, roots)
        .unwrap()
        .input_resource_usage();
    // Two transmitted roots, twelve first-layer children, ten sumcheck
    // values and twelve final-layer children, each with all twelve limbs.
    assert_eq!(usage.scalar_elements, 36 * 12);
    let exact = VerifierLimits {
        max_total_scalar_elements: usage.scalar_elements,
        max_metadata_entries: usage.metadata_entries,
        max_rounds: usage.rounds,
        max_instances: usage.instances,
        ..VerifierLimits::default()
    };
    assert_eq!(
        BinaryPolyProductGkrVerifier::with_limits(4, 3, roots, &exact)
            .unwrap()
            .input_resource_usage(),
        usage
    );
    for limits in [
        VerifierLimits {
            max_total_scalar_elements: usage.scalar_elements - 1,
            ..exact
        },
        VerifierLimits {
            max_metadata_entries: usage.metadata_entries - 1,
            ..exact
        },
        VerifierLimits {
            max_rounds: usage.rounds - 1,
            ..exact
        },
    ] {
        assert!(BinaryPolyProductGkrVerifier::with_limits(4, 3, roots, &limits).is_err());
    }
    assert!(
        BinaryPolyProductGkrVerifier::new(usize::BITS as usize, 2, ProductGkrRootShape::Distinct)
            .is_err()
    );
    assert!(BinaryPolyProductGkrVerifier::new(1, 0, ProductGkrRootShape::Distinct).is_err());
    assert!(BinaryPolyProductGkrVerifier::new(1, 1, ProductGkrRootShape::FirstTwoShared).is_err());
    let limits = VerifierLimits {
        max_rounds: 1,
        ..VerifierLimits::default()
    };
    assert!(
        BinaryPolyProductGkrVerifier::with_limits(4, 2, ProductGkrRootShape::Distinct, &limits)
            .is_err()
    );
    let limits = VerifierLimits {
        max_total_scalar_elements: 100,
        ..VerifierLimits::default()
    };
    assert!(
        BinaryPolyProductGkrVerifier::with_limits(
            3,
            2,
            ProductGkrRootShape::FirstTwoShared,
            &limits
        )
        .is_err()
    );
}

#[test]
fn a_poly192_product_reduction_proves_in_a_prime_field_circuit() {
    use p3_circuit_prover::ConstraintProfile;
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, Blake3CompressAirBuilder, Blake3CompressPreprocessor,
        Blake3CompressProver,
    };
    let (circuit, values) = exercise(
        ByteHash::Blake3,
        || blake3::LevelChallenger::from_hasher(vec![9, 17, 3], blake3::byte_hash()),
        3,
        ProductGkrRootShape::FirstTwoShared,
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
