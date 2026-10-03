//! Nonzero rejection sampling and exact observed native continuations.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField8, BinaryField64, BinaryField128, TowerLevel};
use p3_challenger::{CanObserve, FieldChallenger};
use p3_circuit::ops::ByteHash;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{BinaryNonzeroChallengePlan, RecursiveBinaryTowerField};
use p3_recursion::verifier::{VerificationError, VerifierLimits};
use p3_test_utils::binary_field_params::{blake3, keccak};

macro_rules! differential {
    ($f:ty, $e:ty, $params:ident, $hash:expr) => {{
        type F = $f;
        type E = $e;
        let plan = BinaryNonzeroChallengePlan::<E>::new(3, 7).unwrap();
        let mut native = $params::LevelChallenger::<F>::from_hasher(vec![7; 3], $params::byte_hash());
        let expected = plan.sample_native::<F, _>(&mut native).unwrap();
        let observation = F::from_le_byte_iter(
            (0..F::RAW_BITS / 8).map(|i| if i == 0 { 9 } else { 0 }),
        );
        native.observe(observation);
        let next = native.sample_algebra_element::<E>();

        let mut b = CircuitBuilder::<BabyBear>::new();
        match $hash {
            ByteHash::Keccak256 => b.enable_keccak_f1600::<BabyBear>(),
            ByteHash::Blake3 => b.enable_blake3_compress::<BabyBear>(),
        }
        let initial = (0..3)
            .map(|_| b.define_const(BabyBear::from_u8(7)))
            .collect::<Vec<_>>();
        let ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
            &mut b, $hash, &initial,
        )
        .unwrap();
        let output = plan.sample::<BabyBear, BabyBear>(&mut b, ch).unwrap();
        let observation = (0..F::RAW_BITS / 8)
            .map(|i| b.define_const(BabyBear::from_u8(if i == 0 { 9 } else { 0 })))
            .collect::<Vec<_>>();
        let mut ch = output
            .continuation
            .resume_with_observation::<BabyBear, BabyBear>(&mut b, &observation)
            .unwrap();
        let next_bytes = ch
            .sample_bytes::<BabyBear, BabyBear>(&mut b, E::RAW_BITS / 8)
            .unwrap();
        let mut next_bits = [p3_circuit::ExprId::ZERO; 128];
        for (i, byte) in next_bytes.into_iter().enumerate() {
            let bits = b.decompose_to_bits::<BabyBear>(byte, 8).unwrap();
            next_bits[8 * i..8 * i + 8].copy_from_slice(&bits);
        }
        let mut actual = output.values;
        actual.push(b.binary128_from_bits(next_bits).unwrap());
        let mut values = Vec::new();
        for (actual, expected) in actual.iter().zip(expected.into_iter().chain([next])) {
            let limbs = b.alloc_private_input_array::<8>("native nonzero comparison");
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
        let mut wrong = values.clone();
        wrong[0] += BabyBear::ONE;
        assert!(!run(&circuit, &wrong));
        let mut wrong = values.clone();
        wrong[24] += BabyBear::ONE;
        assert!(!run(&circuit, &wrong));
        if E::RAW_BITS == 64 {
            let mut wrong = values.clone();
            wrong[4] = BabyBear::ONE;
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
fn both_tower_widths_and_hashes_keep_the_native_completion() {
    differential!(BinaryField128, BinaryField128, keccak, ByteHash::Keccak256);
    differential!(BinaryField8, BinaryField64, keccak, ByteHash::Keccak256);
    differential!(BinaryField128, BinaryField128, blake3, ByteHash::Blake3);
    differential!(BinaryField8, BinaryField64, blake3, ByteHash::Blake3);
}

#[test]
fn the_sampled_point_and_continuation_prove_in_a_prime_field_circuit() {
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover,
    };
    use p3_circuit_prover::{ConstraintProfile, config};
    let (circuit, values) = differential!(BinaryField8, BinaryField64, keccak, ByteHash::Keccak256);
    let mut prover = BatchStarkProver::new(config::baby_bear());
    prover.register_table_prover(Box::new(KeccakF1600Prover::<1>));
    let prepared = prover
        .prepare_circuit::<BabyBear, 1>(
            &circuit,
            &[Box::new(KeccakF1600Preprocessor)],
            &[Box::new(KeccakF1600AirBuilder::<1>)],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let mut runner = circuit.runner();
    runner.set_private_inputs(&values).unwrap();
    let proof = prepared.prove(&runner.run().unwrap()).unwrap();
    prepared.verifier().verify(&proof, &[]).unwrap();
}

#[test]
fn trusted_nonzero_counts_and_work_budgets_are_checked_before_sampling() {
    assert!(BinaryNonzeroChallengePlan::<BinaryField128>::new(0, 1).is_err());
    assert!(BinaryNonzeroChallengePlan::<BinaryField128>::new(2, 1).is_err());
    assert!(BinaryNonzeroChallengePlan::<BinaryField128>::new(65, 65).is_err());
    assert!(BinaryNonzeroChallengePlan::<BinaryField128>::new(1, 4097).is_err());
    assert!(BinaryNonzeroChallengePlan::<BinaryField128>::new(1, usize::MAX).is_err());
    let limits = VerifierLimits {
        max_metadata_entries: 160,
        ..VerifierLimits::default()
    };
    assert!(matches!(
        BinaryNonzeroChallengePlan::<BinaryField128>::with_limits(1, 1, &limits),
        Err(VerificationError::ResourceLimitExceeded {
            component: "metadata entries",
            ..
        })
    ));
    let limits = VerifierLimits {
        max_metadata_entries: 161,
        ..limits
    };
    assert!(BinaryNonzeroChallengePlan::<BinaryField128>::with_limits(1, 1, &limits).is_ok());
}
