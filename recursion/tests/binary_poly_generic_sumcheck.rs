//! Released generic-degree reductions with mixed Poly64/Poly192 witness widths.

use p3_baby_bear::BabyBear;
use p3_binary_field::{Poly64, Poly192};
use p3_challenger::{CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_circuit::ops::{BinaryPoly192Target, ByteHash};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{
    BinaryPolyGenericSumcheckVerifier, verify_binary_query_indices_with_continuation,
};
use p3_sumcheck::generic_degree::{GenericDegreeProof, GenericDegreeShape, ProverTranscript};
use p3_test_utils::binary_field_params::{blake3, keccak};

fn input(b: &mut CircuitBuilder<BabyBear>) -> BinaryPoly192Target {
    let limbs = b.alloc_private_input_array::<12>("Poly192 sumcheck comparison");
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
fn pack(v: Poly192) -> impl Iterator<Item = BabyBear> {
    v.coefficients().into_iter().flat_map(|coefficient| {
        (0..4).map(move |i| BabyBear::from_u16((coefficient.to_bits() >> (16 * i)) as u16))
    })
}
fn dense(seed: u64) -> Poly192 {
    Poly192::new(core::array::from_fn(|k| {
        Poly64::new(0x2317_fcbe_d892_457au64.wrapping_mul(seed + 91 * k as u64))
    }))
}
fn run(circuit: &Circuit<BabyBear>, values: &[BabyBear]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(values).unwrap();
    runner.run().is_ok()
}

fn check<Ch>(
    hash: ByteHash,
    rounds: usize,
    degree: usize,
    pow: usize,
    after_queries: bool,
    make: impl Fn() -> Ch,
) where
    Ch: FieldChallenger<Poly64>
        + GrindingChallenger<Witness = Poly64>
        + CanSampleUniformBits<Poly64>
        + Clone,
{
    let verifier = BinaryPolyGenericSumcheckVerifier::new(rounds, degree, pow).unwrap();
    let shape = verifier.input_shape();
    let mut b = CircuitBuilder::<BabyBear>::new();
    match hash {
        ByteHash::Keccak256 => b.enable_keccak_f1600::<BabyBear>(),
        ByteHash::Blake3 => b.enable_blake3_compress::<BabyBear>(),
    }
    let expected_sum = input(&mut b);
    let targets = shape
        .allocate_targets::<BabyBear, BabyBear>(&mut b)
        .unwrap();
    let query_targets = if after_queries {
        (0..2)
            .map(|_| {
                (0..3)
                    .map(|_| b.alloc_private_input("preceding Poly query bit"))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    } else {
        vec![]
    };
    let initial = [9u8; 3].map(|v| b.define_const(BabyBear::from_u8(v)));
    let ch =
        BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(&mut b, hash, &initial)
            .unwrap();
    let output = if after_queries {
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
                &expected_sum,
                &targets,
            )
            .unwrap()
    } else {
        verifier
            .verify_reduction::<BabyBear, BabyBear>(&mut b, ch, &expected_sum, &targets)
            .unwrap()
    };
    for actual in &output.point {
        let expected = input(&mut b);
        equal(&mut b, actual, &expected);
    }
    let expected = input(&mut b);
    equal(&mut b, &output.claim, &expected);
    let mut ch = output.challenger;
    for _ in 0..2 {
        let actual = ch.sample_poly192::<BabyBear, BabyBear>(&mut b).unwrap();
        let expected = input(&mut b);
        equal(&mut b, &actual, &expected);
    }
    let observed = Poly64::new(0x91fe_dcba_0123_4567);
    let target = b.binary_poly64_constant(observed.to_bits()).unwrap();
    ch.observe_poly64::<BabyBear, BabyBear>(&mut b, &target)
        .unwrap();
    let actual = ch.sample_poly192::<BabyBear, BabyBear>(&mut b).unwrap();
    let expected = input(&mut b);
    equal(&mut b, &actual, &expected);
    let circuit = b.build().unwrap();
    let queries = |ch: &mut Ch| {
        let mut indices = vec![];
        if after_queries {
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
    for seed in [2u64, 19] {
        let claimed_sum = dense(seed);
        let polys = (0..rounds)
            .map(|r| {
                (0..degree)
                    .map(|i| dense(seed + 11 + 29 * r as u64 + i as u64))
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let mut prover_ch = make();
        let indices = queries(&mut prover_ch);
        let mut transcript = ProverTranscript::<_, Poly64, Poly192>::new(
            &mut prover_ch,
            GenericDegreeShape::new(rounds, degree, pow),
            claimed_sum,
        );
        let mut pow_witnesses = vec![];
        for polynomial in &polys {
            let (_, witness) = transcript.round(polynomial);
            pow_witnesses.extend(witness);
        }
        transcript.finish();
        let proof = GenericDegreeProof {
            claimed_sum,
            round_polys: polys,
            pow_witnesses,
        };
        let mut native_ch = make();
        assert_eq!(queries(&mut native_ch), indices);
        let (point, claim) = proof.verify(&mut native_ch, rounds, degree, pow).unwrap();
        let mut import_ch = make();
        assert_eq!(queries(&mut import_ch), indices);
        let imported = verifier.import_native(&proof, &mut import_ch).unwrap();
        let mut values = pack(claimed_sum).collect::<Vec<_>>();
        let private = imported.private_values::<BabyBear>(&shape).unwrap();
        assert_eq!(
            private.len(),
            12 * (1 + rounds * degree) + if pow > 0 { 4 * rounds } else { 0 }
        );
        values.extend(private);
        values.extend(
            indices
                .iter()
                .flat_map(|&index| (0..3).map(move |i| BabyBear::from_bool(index >> i & 1 != 0))),
        );
        values.extend(point.iter().copied().flat_map(pack));
        values.extend(pack(claim));
        for _ in 0..2 {
            let next = native_ch.sample_algebra_element::<Poly192>();
            assert_eq!(next, import_ch.sample_algebra_element::<Poly192>());
            values.extend(pack(next));
        }
        native_ch.observe(observed);
        import_ch.observe(observed);
        let next = native_ch.sample_algebra_element::<Poly192>();
        assert_eq!(next, import_ch.sample_algebra_element::<Poly192>());
        values.extend(pack(next));
        assert!(run(&circuit, &values));
        for at in [0, 12, 32, values.len() - 4] {
            let mut wrong = values.clone();
            wrong[at] += BabyBear::ONE;
            assert!(!run(&circuit, &wrong));
        }
        let foreign = BinaryPolyGenericSumcheckVerifier::new(rounds, degree + 1, pow).unwrap();
        assert!(
            imported
                .private_values::<BabyBear>(&foreign.input_shape())
                .is_err()
        );
        let mut malformed = proof.clone();
        if rounds > 0 {
            malformed.round_polys[0].pop();
        } else {
            malformed.round_polys.push(vec![Poly192::ZERO; degree]);
        }
        let mut unchanged = make();
        assert!(verifier.import_native(&malformed, &mut unchanged).is_err());
        assert_eq!(
            unchanged.sample_algebra_element::<Poly192>(),
            make().sample_algebra_element::<Poly192>()
        );
        if pow > 0 {
            let malformed = (0..64)
                .find_map(|raw| {
                    let mut bad = proof.clone();
                    bad.pow_witnesses[0] = Poly64::new(raw);
                    bad.verify(&mut make(), rounds, degree, pow)
                        .is_err()
                        .then_some(bad)
                })
                .expect("fixture must include a native-rejected grinding witness");
            let mut unchanged = make();
            assert!(verifier.import_native(&malformed, &mut unchanged).is_err());
            assert_eq!(
                unchanged.sample_algebra_element::<Poly192>(),
                make().sample_algebra_element::<Poly192>()
            );
        }
        let mut malformed = proof.clone();
        malformed.pow_witnesses.push(Poly64::ZERO);
        let mut unchanged = make();
        assert!(verifier.import_native(&malformed, &mut unchanged).is_err());
        assert_eq!(
            unchanged.sample_algebra_element::<Poly192>(),
            make().sample_algebra_element::<Poly192>()
        );
    }
}

#[test]
fn native_poly192_messages_interpolation_and_continuations_match_both_hashes() {
    check(ByteHash::Keccak256, 3, 4, 0, false, || {
        keccak::LevelChallenger::<Poly64>::from_hasher(vec![9; 3], keccak::byte_hash())
    });
    check(ByteHash::Blake3, 3, 4, 0, false, || {
        blake3::LevelChallenger::<Poly64>::from_hasher(vec![9; 3], blake3::byte_hash())
    });
}

#[test]
fn poly64_pow_witnesses_have_four_limbs_and_preserve_the_native_transcript() {
    check(ByteHash::Blake3, 2, 3, 3, false, || {
        blake3::LevelChallenger::<Poly64>::from_hasher(vec![9; 3], blake3::byte_hash())
    });
}

#[test]
fn zero_rounds_and_query_continuations_absorb_the_poly_sumcheck_seed_once() {
    check(ByteHash::Blake3, 0, 3, 0, false, || {
        blake3::LevelChallenger::<Poly64>::from_hasher(vec![9; 3], blake3::byte_hash())
    });
    check(ByteHash::Blake3, 2, 4, 0, true, || {
        blake3::LevelChallenger::<Poly64>::from_hasher(vec![9; 3], blake3::byte_hash())
    });
    check(ByteHash::Keccak256, 2, 4, 0, true, || {
        keccak::LevelChallenger::<Poly64>::from_hasher(vec![9; 3], keccak::byte_hash())
    });
}
