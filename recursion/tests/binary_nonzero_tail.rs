//! Rejection-sampled challenges followed by unrestricted transcript words.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryChallenger, BinaryField8, BinaryField64, BinaryField128, TowerLevel};
use p3_challenger::{CanObserve, CanSample, FieldChallenger, HashChallenger};
use p3_circuit::ops::ByteHash;
use p3_circuit::{Circuit, CircuitBuilder, ExprId};
use p3_field::PrimeCharacteristicRing;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{
    BinaryNonzeroChallengePlan, BinaryNonzeroChallengeTailPlan, RecursiveBinaryTowerField,
};
use p3_recursion::verifier::VerifierLimits;
use p3_test_utils::binary_field_params::{blake3, keccak};

macro_rules! differential {
    ($f:ty, $e:ty, $params:ident, $hash:expr, $skip:expr, $tail:expr) => {{
        type F = $f;
        type E = $e;
        let plan = BinaryNonzeroChallengeTailPlan::<E>::new(2, 5, $tail).unwrap();
        let mut inner = HashChallenger::new(vec![7; 3], $params::byte_hash());
        let skip = $skip;
        for _ in 0..skip {
            let _: u8 = inner.sample();
        }
        let mut native = BinaryChallenger::<F, _>::new(inner);
        let (expected, following) = plan.sample_native::<F, _>(&mut native).unwrap();
        native.observe(F::from_le_byte_iter(
            (0..F::RAW_BITS / 8).map(|i| if i == 0 { 9 } else { 0 }),
        ));
        let next = native.sample_algebra_element::<E>();

        let mut b = CircuitBuilder::<BabyBear>::new();
        match $hash {
            ByteHash::Keccak256 => b.enable_keccak_f1600::<BabyBear>(),
            ByteHash::Blake3 => b.enable_blake3_compress::<BabyBear>(),
        }
        let initial = b.alloc_private_input_array::<3>("initial transcript bytes");
        let mut ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
            &mut b, $hash, &initial,
        )
        .unwrap();
        if $skip != 0 {
            ch.sample_bytes::<BabyBear, BabyBear>(&mut b, $skip).unwrap();
        }
        let output = plan.sample::<BabyBear, BabyBear>(&mut b, ch).unwrap();
        assert_eq!(output.following.len(), $tail);
        let observation = (0..F::RAW_BITS / 8)
            .map(|i| b.define_const(BabyBear::from_u8(if i == 0 { 9 } else { 0 })))
            .collect::<Vec<_>>();
        let mut ch = output
            .continuation
            .resume_with_observation::<BabyBear, BabyBear>(&mut b, &observation)
            .unwrap();
        let bytes = ch.sample_bytes::<BabyBear, BabyBear>(&mut b, E::RAW_BITS / 8).unwrap();
        let mut bits = [ExprId::ZERO; 128];
        for (i, byte) in bytes.into_iter().enumerate() {
            bits[8 * i..8 * i + 8].copy_from_slice(&b.decompose_to_bits::<BabyBear>(byte, 8).unwrap());
        }
        let next_target = b.binary128_from_bits(bits).unwrap();
        let mut values = vec![BabyBear::from_u8(7); 3];
        for (actual, expected) in output.values.iter().chain(&output.following).chain([&next_target])
            .zip(expected.into_iter().chain(following).chain([next]))
        {
            let limbs = b.alloc_private_input_array::<8>("native nonzero and tail comparison");
            let expected_target = b.binary128_from_limbs::<BabyBear>(limbs).unwrap();
            for (&a, &e) in actual.bits().iter().zip(expected_target.bits()) {
                let diff = b.sub(a, e);
                b.assert_zero(diff);
            }
            let raw = expected.raw_coordinates();
            values.extend((0..8).map(|i| BabyBear::from_u16((raw >> (16 * i)) as u16)));
        }
        let circuit = b.build().unwrap();
        assert!(run(&circuit, &values));
        for index in [0, 3, 19, values.len() - 8] {
            let mut wrong = values.clone();
            wrong[index] += BabyBear::ONE;
            assert!(!run(&circuit, &wrong));
        }
        if E::RAW_BITS == 64 {
            let mut wrong = values.clone();
            wrong[23] = BabyBear::ONE;
            assert!(!run(&circuit, &wrong));
        }
        (circuit, values)
    }};
}

fn run(circuit: &Circuit<BabyBear>, values: &[BabyBear]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(values).unwrap();
    runner.run().is_ok()
}

#[test]
fn both_hashes_and_extension_widths_preserve_unrestricted_following_words() {
    differential!(
        BinaryField128,
        BinaryField128,
        keccak,
        ByteHash::Keccak256,
        0,
        1
    );
    differential!(
        BinaryField8,
        BinaryField64,
        keccak,
        ByteHash::Keccak256,
        3,
        4
    );
    differential!(
        BinaryField128,
        BinaryField128,
        blake3,
        ByteHash::Blake3,
        3,
        2
    );
    differential!(BinaryField8, BinaryField64, blake3, ByteHash::Blake3, 0, 1);
}

#[test]
fn tail_resources_are_trusted_and_zero_tail_preserves_legacy_accounting() {
    let plain = BinaryNonzeroChallengePlan::<BinaryField128>::new(2, 5).unwrap();
    let zero_tail = BinaryNonzeroChallengeTailPlan::<BinaryField128>::new(2, 5, 0).unwrap();
    assert_eq!(
        plain.input_resource_usage(),
        zero_tail.input_resource_usage()
    );
    let plan = BinaryNonzeroChallengeTailPlan::<BinaryField128>::new(2, 5, 1).unwrap();
    let usage = plan.input_resource_usage();
    assert_eq!(usage.rounds, 3);
    assert_eq!(usage.queries, 6);
    assert_eq!(
        usage.metadata_entries,
        plain.input_resource_usage().metadata_entries + 288 + 129 * 5
    );
    for limits in [
        VerifierLimits {
            max_rounds: 2,
            ..VerifierLimits::default()
        },
        VerifierLimits {
            max_queries_per_round: 5,
            ..VerifierLimits::default()
        },
        VerifierLimits {
            max_metadata_entries: usage.metadata_entries - 1,
            ..VerifierLimits::default()
        },
    ] {
        assert!(
            BinaryNonzeroChallengeTailPlan::<BinaryField128>::with_limits(2, 5, 1, &limits)
                .is_err()
        );
    }
    assert!(
        BinaryNonzeroChallengeTailPlan::<BinaryField128>::with_limits(
            2,
            5,
            1,
            &VerifierLimits {
                max_metadata_entries: usage.metadata_entries,
                ..VerifierLimits::default()
            }
        )
        .is_ok()
    );
    assert!(BinaryNonzeroChallengeTailPlan::<BinaryField128>::new(1, 1, usize::MAX).is_err());
    assert!(BinaryNonzeroChallengeTailPlan::<BinaryField128>::new(0, 1, 1).is_err());
    assert!(BinaryNonzeroChallengeTailPlan::<BinaryField128>::new(2, 1, 1).is_err());
    differential!(BinaryField8, BinaryField64, blake3, ByteHash::Blake3, 3, 0);
}

#[test]
fn the_selected_tail_and_continuation_prove_in_a_prime_field_circuit() {
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, Blake3CompressAirBuilder, Blake3CompressPreprocessor,
        Blake3CompressProver,
    };
    use p3_circuit_prover::{ConstraintProfile, config};
    let (circuit, values) =
        differential!(BinaryField8, BinaryField64, blake3, ByteHash::Blake3, 3, 1);
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
