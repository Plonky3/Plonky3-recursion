//! Continuous full-width polynomial nonzero prefixes and unrestricted tails.
use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryChallenger, Poly64, Poly192};
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, HashChallenger};
use p3_circuit::ops::ByteHash;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{
    BinaryPolyNonzeroChallengePlan, BinaryPolyNonzeroChallengeTailPlan,
};
use p3_recursion::verifier::VerifierLimits;
use p3_test_utils::binary_field_params::{blake3, keccak};

macro_rules! differential {
    ($params:ident, $hash:expr, $skip:expr, $tail:expr) => {{
        type F = Poly64;
        type E = Poly192;
        let plan = BinaryPolyNonzeroChallengeTailPlan::new(2, 5, $tail).unwrap();
        let mut inner = HashChallenger::new(vec![7; 3], $params::byte_hash());
        let skip = $skip;
        for _ in 0..skip {
            let _: u8 = inner.sample();
        }
        let mut native = BinaryChallenger::<F, _>::new(inner);
        let (expected, following) = plan.sample_native(&mut native).unwrap();
        native.observe(F::new(9));
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
            ch.sample_bytes::<BabyBear, BabyBear>(&mut b, $skip)
                .unwrap();
        }
        let output = plan.sample::<BabyBear, BabyBear>(&mut b, ch).unwrap();
        assert_eq!(output.following.len(), $tail);
        let observation = (0..8)
            .map(|i| b.define_const(BabyBear::from_u8(if i == 0 { 9 } else { 0 })))
            .collect::<Vec<_>>();
        let mut ch = output
            .continuation
            .resume_with_observation::<BabyBear, BabyBear>(&mut b, &observation)
            .unwrap();
        let next_target = ch.sample_poly192::<BabyBear, BabyBear>(&mut b).unwrap();
        let mut values = vec![BabyBear::from_u8(7); 3];
        for (actual, expected) in output
            .values
            .iter()
            .chain(&output.following)
            .chain([&next_target])
            .zip(expected.into_iter().chain(following).chain([next]))
        {
            let limbs = b.alloc_private_input_array::<12>("native nonzero and tail comparison");
            let expected_target = b.binary_poly192_from_limbs::<BabyBear>(limbs).unwrap();
            for (a, e) in actual
                .coefficients()
                .iter()
                .zip(expected_target.coefficients())
            {
                for (&a, &e) in a.bits().iter().zip(e.bits()) {
                    let diff = b.sub(a, e);
                    b.assert_zero(diff);
                }
            }
            for coefficient in expected.coefficients() {
                let raw = coefficient.to_bits();
                values.extend((0..4).map(|i| BabyBear::from_u16((raw >> (16 * i)) as u16)));
            }
        }
        let circuit = b.build().unwrap();
        assert!(run(&circuit, &values));
        for index in [0, 3, 19, 35, values.len() - 12] {
            let mut wrong = values.clone();
            wrong[index] += BabyBear::ONE;
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
fn both_hashes_preserve_full_width_tail_and_partial_byte_continuations() {
    differential!(keccak, ByteHash::Keccak256, 0, 1);
    differential!(keccak, ByteHash::Keccak256, 3, 4);
    differential!(blake3, ByteHash::Blake3, 3, 2);
    differential!(blake3, ByteHash::Blake3, 0, 1);
}

#[test]
fn tail_resources_are_trusted_and_zero_tail_preserves_legacy_accounting() {
    let plain = BinaryPolyNonzeroChallengePlan::new(2, 5).unwrap();
    let zero_tail = BinaryPolyNonzeroChallengeTailPlan::new(2, 5, 0).unwrap();
    assert_eq!(
        plain.input_resource_usage(),
        zero_tail.input_resource_usage()
    );
    let plan = BinaryPolyNonzeroChallengeTailPlan::new(2, 5, 1).unwrap();
    let usage = plan.input_resource_usage();
    assert_eq!(usage.rounds, 3);
    assert_eq!(usage.queries, 6);
    assert_eq!(
        usage.metadata_entries,
        plain.input_resource_usage().metadata_entries + 416 + 193 * 5
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
        assert!(BinaryPolyNonzeroChallengeTailPlan::with_limits(2, 5, 1, &limits).is_err());
    }
    assert!(
        BinaryPolyNonzeroChallengeTailPlan::with_limits(
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
    assert!(BinaryPolyNonzeroChallengeTailPlan::new(1, 1, usize::MAX).is_err());
    assert!(BinaryPolyNonzeroChallengeTailPlan::new(0, 1, 1).is_err());
    assert!(BinaryPolyNonzeroChallengeTailPlan::new(2, 1, 1).is_err());
    differential!(blake3, ByteHash::Blake3, 3, 0);
}

#[test]
fn the_selected_tail_and_continuation_prove_in_a_prime_field_circuit() {
    use p3_circuit_prover::ConstraintProfile;
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, Blake3CompressAirBuilder, Blake3CompressPreprocessor,
        Blake3CompressProver,
    };
    let (circuit, values) = differential!(blake3, ByteHash::Blake3, 3, 1);
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

#[derive(Clone)]
struct Scripted {
    words: Vec<Poly64>,
    position: usize,
}
impl CanObserve<Poly64> for Scripted {
    fn observe(&mut self, _: Poly64) {}
}
impl CanSample<Poly64> for Scripted {
    fn sample(&mut self) -> Poly64 {
        let value = self.words[self.position];
        self.position += 1;
        value
    }
}
impl CanSampleBits<usize> for Scripted {
    fn sample_bits(&mut self, _: usize) -> usize {
        panic!("field sampling must not draw uniform bits")
    }
}
impl FieldChallenger<Poly64> for Scripted {}

#[test]
fn native_tail_accepts_a_high_only_prefix_then_unrestricted_zero_without_observation() {
    let plan = BinaryPolyNonzeroChallengeTailPlan::new(1, 3, 2).unwrap();
    let mut ch = Scripted {
        words: [0, 0, 0, 0, 0, 1, 0, 0, 0, 17, 19, 23]
            .map(Poly64::new)
            .to_vec(),
        position: 0,
    };
    let (prefix, following) = plan.sample_native(&mut ch).unwrap();
    assert_eq!(
        prefix,
        [Poly192::new([Poly64::ZERO, Poly64::ZERO, Poly64::ONE])]
    );
    assert_eq!(
        following,
        [
            Poly192::ZERO,
            Poly192::new([Poly64::new(17), Poly64::new(19), Poly64::new(23)])
        ]
    );
    assert_eq!(ch.position, 12);
    ch = Scripted {
        words: vec![Poly64::ZERO; 15],
        position: 0,
    };
    assert!(plan.sample_native(&mut ch).is_err());
    assert_eq!(ch.position, 0);
}
