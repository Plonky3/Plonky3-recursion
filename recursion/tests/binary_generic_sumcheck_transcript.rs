//! Released generic-degree binary sumcheck transcript and witness contracts.

use p3_baby_bear::BabyBear;
use p3_binary_field::{
    BinaryField8, BinaryField16, BinaryField32, BinaryField64, BinaryField128, TowerLevel,
};
use p3_challenger::{CanSampleUniformBits, FieldChallenger};
use p3_circuit::ops::{BinaryTower128Target, ByteHash};
use p3_circuit::{Circuit, CircuitBuilder, ExprId};
use p3_field::PrimeCharacteristicRing;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{
    BinaryGenericSumcheckVerifier, RecursiveBinaryTowerField,
    verify_binary_query_indices_with_continuation,
};
use p3_sumcheck::generic_degree::{GenericDegreeProof, GenericDegreeShape, ProverTranscript};
use p3_test_utils::binary_field_params::{blake3, keccak};

fn input(b: &mut CircuitBuilder<BabyBear>) -> BinaryTower128Target {
    let limbs = b.alloc_private_input_array::<8>("sumcheck comparison");
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
    runner.set_private_inputs(values).unwrap();
    runner.run().is_ok()
}

macro_rules! check {
    ($f:ty, $params:ident, $hash:expr, $rounds:expr, $degree:expr, $pow:expr) => {{
        check!(
            $f,
            BinaryField128,
            $params,
            $hash,
            $rounds,
            $degree,
            $pow,
            false
        )
    }};
    ($f:ty, $params:ident, $hash:expr, $rounds:expr, $degree:expr, $pow:expr, $after_queries:expr) => {{
        check!(
            $f,
            BinaryField128,
            $params,
            $hash,
            $rounds,
            $degree,
            $pow,
            $after_queries
        )
    }};
    ($f:ty, $e:ty, $params:ident, $hash:expr, $rounds:expr, $degree:expr, $pow:expr, $after_queries:expr) => {{
        type F = $f;
        type E = $e;
        type Ch = $params::LevelChallenger<F>;
        let verifier = BinaryGenericSumcheckVerifier::<F, E>::new($rounds, $degree, $pow).unwrap();
        let shape = verifier.input_shape();
        let mut b = CircuitBuilder::<BabyBear>::new();
        match $hash {
            ByteHash::Keccak256 => b.enable_keccak_f1600::<BabyBear>(),
            ByteHash::Blake3 => b.enable_blake3_compress::<BabyBear>(),
        }
        let expected_claim = input(&mut b);
        let proof = shape
            .allocate_targets::<BabyBear, BabyBear>(&mut b)
            .unwrap();
        let query_targets = if $after_queries {
            (0..2)
                .map(|_| {
                    (0..3)
                        .map(|_| b.alloc_private_input("preceding query bit"))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        } else {
            vec![]
        };
        let initial = (0..3)
            .map(|_| b.define_const(BabyBear::from_u8(9)))
            .collect::<Vec<_>>();
        let ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
            &mut b, $hash, &initial,
        )
        .unwrap();
        let output = if $after_queries {
            let token = verify_binary_query_indices_with_continuation::<BabyBear, BabyBear>(
                &mut b,
                ch,
                3,
                &query_targets,
                32,
            )
            .unwrap();
            verifier
                .verify_reduction_after_queries::<BabyBear, BabyBear>(
                    &mut b,
                    token,
                    &expected_claim,
                    &proof,
                )
                .unwrap()
        } else {
            verifier
                .verify_reduction::<BabyBear, BabyBear>(&mut b, ch, &expected_claim, &proof)
                .unwrap()
        };
        for r in &output.point {
            let e = input(&mut b);
            equal(&mut b, r, &e);
        }
        let e = input(&mut b);
        equal(&mut b, &output.claim, &e);
        let mut ch = output.challenger;
        let bytes = ch
            .sample_bytes::<BabyBear, BabyBear>(&mut b, E::RAW_BITS / 8)
            .unwrap();
        let mut bits = [ExprId::ZERO; 128];
        for (i, byte) in bytes.into_iter().enumerate() {
            let byte_bits = b.decompose_to_bits::<BabyBear>(byte, 8).unwrap();
            bits[8 * i..8 * i + 8].copy_from_slice(&byte_bits);
        }
        let continuation = b.binary128_from_bits(bits).unwrap();
        let e = input(&mut b);
        equal(&mut b, &continuation, &e);
        let circuit = b.build().unwrap();
        let make = || Ch::from_hasher(vec![9; 3], $params::byte_hash());
        let queries = |ch: &mut Ch| {
            let mut indices = vec![];
            if $after_queries {
                while indices.len() < 2 {
                    let index = ch.sample_uniform_bits::<true>(3).unwrap();
                    if !indices.contains(&index) {
                        indices.push(index);
                    }
                }
                indices.sort_unstable();
            }
            indices
        };
        let mut last = vec![];
        for seed in [2u128, 19] {
            let value = |i| {
                E::from_le_byte_iter(
                    0x2317fcbed892457aca078927af723881u128
                        .wrapping_mul(seed + i)
                        .to_le_bytes()
                        .into_iter(),
                )
            };
            let claimed_sum = value(1);
            let polys = (0..$rounds)
                .map(|r| {
                    (0..$degree)
                        .map(|i| value(11 + r as u128 * 29 + i as u128))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let mut prover_ch = make();
            let indices = queries(&mut prover_ch);
            let mut transcript = ProverTranscript::<_, F, E>::new(
                &mut prover_ch,
                GenericDegreeShape::new($rounds, $degree, $pow),
                claimed_sum,
            );
            let mut pow_witnesses = vec![];
            for polynomial in &polys {
                let (_, witness) = transcript.round(polynomial);
                pow_witnesses.extend(witness);
            }
            transcript.finish();
            let native = GenericDegreeProof {
                claimed_sum,
                round_polys: polys,
                pow_witnesses,
            };
            let mut native_ch = make();
            assert_eq!(queries(&mut native_ch), indices);
            let (point, claim) = native
                .verify(&mut native_ch, $rounds, $degree, $pow)
                .unwrap();
            let continuation = native_ch.sample_algebra_element::<E>();
            let mut imported_ch = make();
            assert_eq!(queries(&mut imported_ch), indices);
            let imported = verifier.import_native(&native, &mut imported_ch).unwrap();
            assert_eq!(imported_ch.sample_algebra_element::<E>(), continuation);
            let foreign =
                BinaryGenericSumcheckVerifier::<F, E>::new($rounds, $degree + 1, $pow).unwrap();
            assert!(
                imported
                    .private_values::<BabyBear>(&foreign.input_shape())
                    .is_err()
            );
            let pack = |v: E| {
                (0..8).map(move |i| BabyBear::from_u16(((v.to_repr() as u128) >> (16 * i)) as u16))
            };
            let mut values = pack(claimed_sum).collect::<Vec<_>>();
            values.extend(imported.private_values::<BabyBear>(&shape).unwrap());
            values.extend(
                indices.iter().flat_map(|&index| {
                    (0..3).map(move |j| BabyBear::from_bool(index >> j & 1 != 0))
                }),
            );
            values.extend(point.iter().copied().flat_map(pack));
            values.extend(pack(claim));
            values.extend(pack(continuation));
            assert!(run(&circuit, &values));
            for at in [0, 8, values.len() - 16, values.len() - 8] {
                let mut wrong = values.clone();
                wrong[at] += BabyBear::ONE;
                assert!(!run(&circuit, &wrong));
            }
            if $rounds > 0 {
                let mut wrong = values.clone();
                wrong[16] += BabyBear::ONE;
                assert!(!run(&circuit, &wrong));
            }
            if E::RAW_BITS == 64 {
                let mut wrong = values.clone();
                wrong[8 + 4] = BabyBear::ONE;
                assert!(!run(&circuit, &wrong));
                if $rounds > 0 {
                    let mut wrong = values.clone();
                    wrong[16 + 4] = BabyBear::ONE;
                    assert!(!run(&circuit, &wrong));
                }
            }
            if F::RAW_BITS < 128 && $pow > 0 {
                let mut wrong = values.clone();
                wrong[8 + 8 * (1 + $rounds * $degree) + F::RAW_BITS.div_ceil(16)] = BabyBear::ONE;
                assert!(!run(&circuit, &wrong));
            }
            let mut malformed = native.clone();
            if let Some(poly) = malformed.round_polys.first_mut() {
                poly.pop();
            } else {
                malformed.round_polys.push(vec![E::ZERO; $degree]);
            }
            let mut unchanged = make();
            assert!(verifier.import_native(&malformed, &mut unchanged).is_err());
            assert_eq!(
                unchanged.sample_algebra_element::<E>(),
                make().sample_algebra_element::<E>()
            );
            let mut malformed = native.clone();
            if malformed.pow_witnesses.is_empty() {
                malformed.pow_witnesses.push(F::ZERO);
            } else {
                malformed.pow_witnesses.pop();
            }
            let mut unchanged = make();
            assert!(verifier.import_native(&malformed, &mut unchanged).is_err());
            assert_eq!(
                unchanged.sample_algebra_element::<E>(),
                make().sample_algebra_element::<E>()
            );
            last = values;
        }
        (circuit, last)
    }};
}

#[test]
fn quartic_binary_zerocheck_rounds_match_the_native_transcript() {
    check!(BinaryField128, keccak, ByteHash::Keccak256, 2, 4, 0);
}

#[test]
fn narrow_positive_pow_and_zero_rounds_preserve_native_continuations() {
    check!(BinaryField32, blake3, ByteHash::Blake3, 2, 3, 3);
    check!(BinaryField128, blake3, ByteHash::Blake3, 0, 7, 0);
}

#[test]
fn a_bounded_rejection_phase_resumes_the_native_sumcheck_seed_once() {
    check!(BinaryField128, keccak, ByteHash::Keccak256, 1, 4, 0, true);
    check!(BinaryField32, blake3, ByteHash::Blake3, 0, 3, 0, true);
}

#[test]
fn native_quartic_reduction_transcripts_prove_in_prime_field_circuits() {
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover,
    };
    use p3_circuit_prover::{ConstraintProfile, config};
    for (circuit, values) in [
        check!(BinaryField128, keccak, ByteHash::Keccak256, 1, 4, 0),
        check!(
            BinaryField8,
            BinaryField64,
            keccak,
            ByteHash::Keccak256,
            1,
            4,
            0,
            false
        ),
    ] {
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
}

#[test]
fn trusted_sumcheck_rounds_grinding_and_aggregate_limbs_are_bounded() {
    use p3_recursion::verifier::{VerificationError, VerifierLimits};
    assert!(BinaryGenericSumcheckVerifier::<BinaryField128>::new(65, 4, 0).is_err());
    assert!(BinaryGenericSumcheckVerifier::<BinaryField128>::new(1, 4, 65).is_err());
    assert!(BinaryGenericSumcheckVerifier::<BinaryField128>::new(1, 4, 64).is_err());
    assert!(BinaryGenericSumcheckVerifier::<BinaryField128>::new(1, 4, 56).is_ok());
    assert!(BinaryGenericSumcheckVerifier::<BinaryField128>::new(1, 4, 57).is_err());
    assert!(BinaryGenericSumcheckVerifier::<BinaryField32>::new(1, 4, 24).is_ok());
    assert!(BinaryGenericSumcheckVerifier::<BinaryField32>::new(1, 4, 25).is_err());
    let limits = VerifierLimits {
        max_total_scalar_elements: 87,
        ..VerifierLimits::default()
    };
    assert!(matches!(
        BinaryGenericSumcheckVerifier::<BinaryField128>::with_limits(2, 4, 3, &limits),
        Err(VerificationError::ResourceLimitExceeded {
            component: "scalar elements",
            ..
        })
    ));
}

#[test]
fn tower64_challenges_match_native_for_narrow_base_seeds_and_pow_witnesses() {
    check!(
        BinaryField8,
        BinaryField64,
        keccak,
        ByteHash::Keccak256,
        3,
        4,
        0,
        true
    );
    check!(
        BinaryField16,
        BinaryField64,
        blake3,
        ByteHash::Blake3,
        2,
        3,
        3,
        false
    );
    check!(
        BinaryField64,
        BinaryField64,
        blake3,
        ByteHash::Blake3,
        0,
        7,
        0,
        true
    );
}
