//! Full-width polynomial rejection sampling and exact resumed transcripts.

use p3_baby_bear::BabyBear;
use p3_binary_field::{Poly64, Poly192};
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{BinaryPoly192Target, ByteHash};
use p3_field::PrimeCharacteristicRing;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{
    BinaryPolyGenericSumcheckVerifier, BinaryPolyNonzeroChallengePlan,
};
use p3_recursion::verifier::{VerificationError, VerifierLimits};
use p3_sumcheck::generic_degree::{GenericDegreeProof, GenericDegreeShape, ProverTranscript};
use p3_test_utils::binary_field_params::{blake3, keccak};

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
fn native_poly192_sampler_skips_zero_and_preserves_exhausted_state() {
    let plan = BinaryPolyNonzeroChallengePlan::new(2, 3).unwrap();
    let mut ch = Scripted {
        words: vec![Poly64::ZERO; 9],
        position: 0,
    };
    assert!(plan.sample_native(&mut ch).is_err());
    assert_eq!(ch.position, 0);
    ch.words = [0, 0, 0, 0, 0, 1, 11, 13, 17].map(Poly64::new).to_vec();
    assert_eq!(
        plan.sample_native(&mut ch).unwrap(),
        [
            Poly192::new([Poly64::ZERO, Poly64::ZERO, Poly64::ONE]),
            Poly192::new([Poly64::new(11), Poly64::new(13), Poly64::new(17)]),
        ]
    );
    assert_eq!(ch.position, 9);
}

fn input(b: &mut CircuitBuilder<BabyBear>) -> BinaryPoly192Target {
    let limbs = b.alloc_private_input_array::<12>("expected polynomial challenge");
    b.binary_poly192_from_limbs::<BabyBear>(limbs).unwrap()
}
fn equal(b: &mut CircuitBuilder<BabyBear>, a: &BinaryPoly192Target, e: &BinaryPoly192Target) {
    for (a, e) in a.coefficients().iter().zip(e.coefficients()) {
        for (&a, &e) in a.bits().iter().zip(e.bits()) {
            let difference = b.sub(a, e);
            b.assert_zero(difference);
        }
    }
}
fn pack(value: Poly192) -> impl Iterator<Item = BabyBear> {
    value
        .coefficients()
        .into_iter()
        .flat_map(|c| (0..4).map(move |i| BabyBear::from_u16((c.to_bits() >> (16 * i)) as u16)))
}

macro_rules! check {
    ($params:ident, $hash:expr) => {{
        type Ch = $params::LevelChallenger<Poly64>;
        let make = || Ch::from_hasher(vec![7, 19, 13], $params::byte_hash());
        let plan = BinaryPolyNonzeroChallengePlan::new(3, 8).unwrap();
        let sumcheck = BinaryPolyGenericSumcheckVerifier::new(2, 4, 0).unwrap();
        let shape = sumcheck.input_shape();
        let mut b = CircuitBuilder::<BabyBear>::new();
        match $hash {
            ByteHash::Keccak256 => b.enable_keccak_f1600::<BabyBear>(),
            ByteHash::Blake3 => b.enable_blake3_compress::<BabyBear>(),
        }
        let targets = shape
            .allocate_targets::<BabyBear, BabyBear>(&mut b)
            .unwrap();
        let initial = [7u8, 19, 13].map(|v| b.define_const(BabyBear::from_u8(v)));
        let ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
            &mut b, $hash, &initial,
        )
        .unwrap();
        let output = plan.sample::<BabyBear, BabyBear>(&mut b, ch).unwrap();
        for value in &output.values {
            let e = input(&mut b);
            equal(&mut b, value, &e);
        }
        let zero = b.binary_poly192_constant([0; 3]).unwrap();
        let reduction = sumcheck
            .verify_reduction_after_queries::<BabyBear, BabyBear>(
                &mut b,
                output.continuation,
                &zero,
                &targets,
            )
            .unwrap();
        for value in &reduction.point {
            let e = input(&mut b);
            equal(&mut b, value, &e);
        }
        let e = input(&mut b);
        equal(&mut b, &reduction.claim, &e);
        let mut ch = reduction.challenger;
        for _ in 0..2 {
            let value = ch.sample_poly192::<BabyBear, BabyBear>(&mut b).unwrap();
            let e = input(&mut b);
            equal(&mut b, &value, &e);
        }
        let circuit = b.build().unwrap();
        let mut prover_ch = make();
        let values = plan.sample_native(&mut prover_ch).unwrap();
        let polys = (0..2)
            .map(|r| {
                (0..4)
                    .map(|i| {
                        Poly192::new(core::array::from_fn(|j| {
                            Poly64::new(
                                0x8123_abcd_7654_321fu64
                                    .wrapping_mul(1 + i + 7 * r + 29 * j as u64),
                            )
                        }))
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut transcript = ProverTranscript::<_, Poly64, Poly192>::new(
            &mut prover_ch,
            GenericDegreeShape::new(2, 4, 0),
            Poly192::ZERO,
        );
        for polynomial in &polys {
            let _ = transcript.round(polynomial);
        }
        transcript.finish();
        let proof = GenericDegreeProof {
            claimed_sum: Poly192::ZERO,
            round_polys: polys,
            pow_witnesses: vec![],
        };
        let mut native_ch = make();
        assert_eq!(values, plan.sample_native(&mut native_ch).unwrap());
        let (point, claim) = proof.verify(&mut native_ch, 2, 4, 0).unwrap();
        let mut import_ch = make();
        assert_eq!(values, plan.sample_native(&mut import_ch).unwrap());
        let imported = sumcheck.import_native(&proof, &mut import_ch).unwrap();
        let mut private = imported.private_values::<BabyBear>(&shape).unwrap();
        let first_selected = private.len();
        private.extend(values.into_iter().flat_map(pack));
        private.extend(point.into_iter().flat_map(pack));
        private.extend(pack(claim));
        for _ in 0..2 {
            let next = native_ch.sample_algebra_element::<Poly192>();
            assert_eq!(next, import_ch.sample_algebra_element::<Poly192>());
            private.extend(pack(next));
        }
        let run = |private: &[BabyBear]| {
            let mut runner = circuit.runner();
            runner.set_private_inputs(private).unwrap();
            runner.run().is_ok()
        };
        let mut runner = circuit.runner();
        runner.set_private_inputs(&private).unwrap();
        runner.run().unwrap();
        for at in [
            first_selected + 8,
            first_selected + 36 + 24 + 8,
            private.len() - 4,
        ] {
            let mut wrong = private.clone();
            wrong[at] += BabyBear::ONE;
            assert!(!run(&wrong));
        }
    }};
}

#[test]
fn full_poly192_nonzero_samples_resume_the_sumcheck_transcript_for_both_hashes() {
    check!(blake3, ByteHash::Blake3);
    check!(keccak, ByteHash::Keccak256);
}

#[test]
fn invalid_poly_nonzero_counts_and_budgets_are_rejected() {
    assert!(BinaryPolyNonzeroChallengePlan::new(0, 1).is_err());
    assert!(BinaryPolyNonzeroChallengePlan::new(2, 1).is_err());
    assert!(BinaryPolyNonzeroChallengePlan::new(usize::MAX, usize::MAX).is_err());
    let limits = VerifierLimits {
        max_metadata_entries: 224,
        ..VerifierLimits::default()
    };
    assert!(matches!(
        BinaryPolyNonzeroChallengePlan::with_limits(1, 1, &limits),
        Err(VerificationError::ResourceLimitExceeded {
            component: "metadata entries",
            ..
        })
    ));
    let limits = VerifierLimits {
        max_metadata_entries: 225,
        ..limits
    };
    assert!(BinaryPolyNonzeroChallengePlan::with_limits(1, 1, &limits).is_ok());
}
