//! Released product-tree reductions inside prime-field circuits.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField8, BinaryField64, BinaryField128};
use p3_bus::{ProductGkrProof, ProductGkrRootShape, ProductGkrShape};
use p3_challenger::FieldChallenger;
use p3_circuit::ops::{BinaryTower128Target, ByteHash};
use p3_circuit::{Circuit, CircuitBuilder, ExprId};
use p3_field::{ExtensionField, PrimeCharacteristicRing};
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{RecursiveBinaryChallengeField, RecursiveBinaryTowerField};
use p3_recursion::verifier::{BinaryProductGkrVerifier, VerifierLimits};
use p3_test_utils::binary_field_params::{blake3, keccak};

fn input(b: &mut CircuitBuilder<BabyBear>) -> BinaryTower128Target {
    let limbs = b.alloc_private_input_array::<8>("product GKR comparison");
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
    make: impl Fn() -> Ch,
    height: usize,
    root_shape: ProductGkrRootShape,
) -> (Circuit<BabyBear>, Vec<BabyBear>)
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
    Ch: FieldChallenger<F> + Clone,
{
    let verifier = BinaryProductGkrVerifier::<F, E>::new(height, 3, root_shape).unwrap();
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
    let bytes = output
        .challenger
        .sample_bytes::<BabyBear, BabyBear>(&mut b, E::RAW_BITS / 8)
        .unwrap();
    let mut bits = [ExprId::ZERO; 128];
    for (i, byte) in bytes.into_iter().enumerate() {
        let byte = b.decompose_to_bits::<BabyBear>(byte, 8).unwrap();
        bits[8 * i..8 * i + 8].copy_from_slice(&byte);
    }
    let continuation = b.binary128_from_bits(bits).unwrap();
    let expected = input(&mut b);
    equal(&mut b, &continuation, &expected);
    let circuit = b.build().unwrap();
    let mut last = Vec::new();
    for seed in [2u128, 19] {
        let value = |i: usize| {
            E::from_le_byte_iter(
                0x2317fcbed892457aca078927af723881u128
                    .wrapping_mul(seed + i as u128)
                    .to_le_bytes()
                    .into_iter(),
            )
        };
        let mut first: Vec<_> = (0..1usize << height).map(value).collect();
        // Zero roots are valid, including structurally shared zero roots.
        first[0] = E::ZERO;
        let mut second = first.clone();
        second.reverse();
        if root_shape == ProductGkrRootShape::Distinct {
            second[0] += E::ONE;
        }
        // A short arbitrary prefix exercises native identity padding.
        let third: Vec<_> = (0..(1usize << height).saturating_sub(1))
            .map(value)
            .collect();
        let mut prover_ch = make();
        let (native, native_output) = ProductGkrProof::prove::<F, _>(
            &[&first, &second, &third],
            native_shape,
            &mut prover_ch,
        );
        for (leaves, &expected) in [&first, &second, &third]
            .into_iter()
            .zip(&native_output.values)
        {
            let actual =
                (0..1usize << height)
                    .map(|index| {
                        let weight = native_output.point.iter().enumerate().fold(
                            E::ONE,
                            |weight, (bit, &r)| {
                                weight
                                    * if index >> (height - 1 - bit) & 1 == 1 {
                                        r
                                    } else {
                                        E::ONE + r
                                    }
                            },
                        );
                        weight * leaves.get(index).copied().unwrap_or(E::ONE)
                    })
                    .sum::<E>();
            assert_eq!(actual, expected);
        }
        let mut imported_ch = make();
        let imported = verifier.import_native(&native, &mut imported_ch).unwrap();
        let next = prover_ch.sample_algebra_element::<E>();
        assert_eq!(imported_ch.sample_algebra_element::<E>(), next);
        let mut values = imported.private_values::<BabyBear>(&shape).unwrap();
        for value in native_output
            .roots
            .iter()
            .chain(&native_output.point)
            .chain(&native_output.values)
            .chain(core::slice::from_ref(&next))
        {
            let raw = value.raw_coordinates();
            values.extend((0..8).map(|i| BabyBear::from_u16((raw >> (16 * i)) as u16)));
        }
        assert!(run(&circuit, &values));
        if !last.is_empty() && height > 0 {
            assert_ne!(last, values);
        }
        let mut wrong = values.clone();
        wrong[0] += BabyBear::ONE;
        assert!(!run(&circuit, &wrong));
        if E::RAW_BITS == 64 {
            let mut wide = values.clone();
            wide[4] = BabyBear::ONE;
            assert!(!run(&circuit, &wide));
        }
        let mut malformed = native.clone();
        malformed.roots.push(E::ONE);
        let mut failed_ch = make();
        assert!(verifier.import_native(&malformed, &mut failed_ch).is_err());
        assert_eq!(
            failed_ch.sample_algebra_element::<E>(),
            make().sample_algebra_element::<E>()
        );
        if height > 0 {
            let mut inconsistent = native.clone();
            inconsistent.roots[0] += E::ONE;
            let mut failed_ch = make();
            assert!(
                verifier
                    .import_native(&inconsistent, &mut failed_ch)
                    .is_err()
            );
            assert_eq!(
                failed_ch.sample_algebra_element::<E>(),
                make().sample_algebra_element::<E>()
            );
        }
        let different = BinaryProductGkrVerifier::<F, E>::new(height + 1, 3, root_shape).unwrap();
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
            exercise::<BinaryField128, BinaryField128, _>(
                ByteHash::Keccak256,
                || keccak::LevelChallenger::from_hasher(vec![9, 17, 3], keccak::byte_hash()),
                height,
                roots,
            );
            exercise::<BinaryField8, BinaryField64, _>(
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
    assert!(
        BinaryProductGkrVerifier::<BinaryField128>::new(
            usize::BITS as usize,
            2,
            ProductGkrRootShape::Distinct
        )
        .is_err()
    );
    assert!(
        BinaryProductGkrVerifier::<BinaryField128>::new(1, 0, ProductGkrRootShape::Distinct)
            .is_err()
    );
    assert!(
        BinaryProductGkrVerifier::<BinaryField128>::new(1, 1, ProductGkrRootShape::FirstTwoShared)
            .is_err()
    );
    let limits = VerifierLimits {
        max_rounds: 1,
        ..VerifierLimits::default()
    };
    assert!(
        BinaryProductGkrVerifier::<BinaryField128>::with_limits(
            4,
            2,
            ProductGkrRootShape::Distinct,
            &limits
        )
        .is_err()
    );
    let limits = VerifierLimits {
        max_total_scalar_elements: 100,
        ..VerifierLimits::default()
    };
    assert!(
        BinaryProductGkrVerifier::<BinaryField128>::with_limits(
            3,
            2,
            ProductGkrRootShape::FirstTwoShared,
            &limits
        )
        .is_err()
    );
}

#[test]
fn a_binary_product_reduction_proves_in_a_prime_field_circuit() {
    use p3_circuit_prover::ConstraintProfile;
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, Blake3CompressAirBuilder, Blake3CompressPreprocessor,
        Blake3CompressProver,
    };
    let (circuit, values) = exercise::<BinaryField8, BinaryField64, _>(
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
