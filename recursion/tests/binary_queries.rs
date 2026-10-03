//! Fixed-shape verification of native binary PCS duplicate-rejection sampling.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryChallenger, BinaryField128, TowerLevel};
use p3_challenger::{CanObserve, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_circuit::ops::ByteHash;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::BinomialExtensionField;
use p3_keccak::Keccak256Hash;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{
    verify_binary_pcs_query_indices, verify_binary_query_indices,
    verify_binary_query_indices_with_continuation,
};

type EF = BinomialExtensionField<BabyBear, 4>;

fn native(seed: &[u8], bits: usize, count: usize) -> (Vec<usize>, usize) {
    let mut challenger =
        BinaryChallenger::<BinaryField128, _>::from_hasher(seed.to_vec(), Keccak256Hash);
    let mut queries = Vec::new();
    let mut draws = 0;
    while queries.len() < count {
        let candidate = challenger.sample_bits(bits);
        draws += 1;
        if !queries.contains(&candidate) {
            queries.push(candidate);
        }
    }
    queries.sort_unstable();
    (queries, draws)
}

fn circuit(bits: usize, count: usize, max_draws: usize) -> Circuit<EF> {
    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_keccak_f1600::<BabyBear>();
    let initial: Vec<_> = (0..7).map(|_| builder.public_input()).collect();
    let queries: Vec<Vec<_>> = (0..count)
        .map(|_| (0..bits).map(|_| builder.public_input()).collect())
        .collect();
    let challenger = BinaryTower128Challenger::with_initial_bytes::<BabyBear, EF>(
        &mut builder,
        ByteHash::Keccak256,
        &initial,
    )
    .unwrap();
    verify_binary_query_indices::<BabyBear, EF>(
        &mut builder,
        challenger,
        bits,
        &queries,
        max_draws,
    )
    .unwrap();
    builder.build().unwrap()
}

fn continuing_circuit(bits: usize, count: usize, max_draws: usize) -> Circuit<EF> {
    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_keccak_f1600::<BabyBear>();
    let initial = (0..7).map(|_| builder.public_input()).collect::<Vec<_>>();
    let queries = (0..count)
        .map(|_| {
            (0..bits)
                .map(|_| builder.public_input())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let expected = builder.alloc_public_input_array::<8>("resumed challenge");
    let expected = builder.binary128_from_limbs::<BabyBear>(expected).unwrap();
    let ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, EF>(
        &mut builder,
        ByteHash::Keccak256,
        &initial,
    )
    .unwrap();
    let continuation = verify_binary_query_indices_with_continuation::<BabyBear, EF>(
        &mut builder,
        ch,
        bits,
        &queries,
        max_draws,
    )
    .unwrap();
    let observation = 13u128
        .to_le_bytes()
        .map(|b| builder.define_const(EF::from_u8(b)));
    let mut ch = continuation
        .resume_with_observation::<BabyBear, EF>(&mut builder, &observation)
        .unwrap();
    let actual = ch.sample::<BabyBear, EF>(&mut builder).unwrap();
    for (&a, &b) in actual.bits().iter().zip(expected.bits()) {
        let difference = builder.sub(a, b);
        builder.assert_zero(difference);
    }
    builder.build().unwrap()
}

fn inputs(seed: &[u8], bits: usize, queries: &[usize]) -> Vec<EF> {
    seed.iter()
        .copied()
        .map(EF::from_u8)
        .chain(
            queries
                .iter()
                .flat_map(|&index| (0..bits).map(move |bit| EF::from_bool(index >> bit & 1 == 1))),
        )
        .collect()
}

fn runs(circuit: &Circuit<EF>, values: &[EF]) -> bool {
    let mut runner = circuit.runner();
    runner.set_public_inputs(values).is_ok() && runner.run().is_ok()
}

#[test]
fn one_circuit_accepts_different_native_duplicate_patterns() {
    let circuit = circuit(3, 5, 48);
    let mut draw_counts = Vec::new();
    for value in 0..12 {
        let seed = [value; 7];
        let (queries, draws) = native(&seed, 3, 5);
        assert!(draws <= 48);
        draw_counts.push(draws);
        assert!(runs(&circuit, &inputs(&seed, 3, &queries)));

        let mut wrong = queries.clone();
        wrong.swap(0, 1);
        assert!(!runs(&circuit, &inputs(&seed, 3, &wrong)));
        wrong[1] = wrong[0];
        assert!(!runs(&circuit, &inputs(&seed, 3, &wrong)));
    }
    draw_counts.sort_unstable();
    draw_counts.dedup();
    assert!(draw_counts.len() > 1);
}

#[test]
fn exact_draw_budget_accepts_and_one_fewer_rejects() {
    let seed = [17; 7];
    let (queries, draws) = native(&seed, 3, 6);
    assert!(draws > queries.len());
    let values = inputs(&seed, 3, &queries);
    assert!(runs(&circuit(3, 6, draws), &values));
    assert!(!runs(&circuit(3, 6, draws - 1), &values));
}

#[test]
fn zero_bit_query_and_indices_wider_than_the_host_field() {
    let seed = [251; 7];
    assert!(runs(&circuit(0, 1, 1), &inputs(&seed, 0, &[0])));
    let width = (usize::BITS as usize - 1).min(40);
    let (queries, _) = native(&seed, width, 3);
    let circuit = circuit(width, 3, 3);
    assert!(runs(&circuit, &inputs(&seed, width, &queries)));
    let mut wrong = queries;
    wrong[0] += 2_013_265_921; // BabyBear's modulus must not alias a query index.
    wrong.sort_unstable();
    assert!(!runs(&circuit, &inputs(&seed, width, &wrong)));
}

#[test]
fn native_pcs_config_fixes_query_width_and_count() {
    use p3_binary_pcs::transcript::BinaryPcsShape;
    use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsParams};

    let config = BinaryPcsConfig::try_new::<BinaryField128, BinaryField128>(
        1,
        BinaryPcsParams {
            log_inv_rate: 2,
            pow_bits: 0,
            security_level: 40,
        },
    )
    .unwrap();
    let shape = BinaryPcsShape::new(&config);
    let seed = [7; 7];
    let (queries, _) = native(&seed, shape.pair_bits, shape.num_pairs);
    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_keccak_f1600::<BabyBear>();
    let initial: Vec<_> = seed.iter().map(|_| builder.public_input()).collect();
    let targets: Vec<Vec<_>> = queries
        .iter()
        .map(|_| {
            (0..shape.pair_bits)
                .map(|_| builder.public_input())
                .collect()
        })
        .collect();
    let challenger = BinaryTower128Challenger::with_initial_bytes::<BabyBear, EF>(
        &mut builder,
        ByteHash::Keccak256,
        &initial,
    )
    .unwrap();
    assert!(
        verify_binary_pcs_query_indices::<BabyBear, EF>(
            &mut builder,
            challenger.clone(),
            &config,
            &targets[..targets.len() - 1],
            64,
        )
        .is_err()
    );
    verify_binary_pcs_query_indices::<BabyBear, EF>(
        &mut builder,
        challenger,
        &config,
        &targets,
        64,
    )
    .unwrap();
    assert!(runs(
        &builder.build().unwrap(),
        &inputs(&seed, shape.pair_bits, &queries)
    ));
}

#[test]
fn malformed_query_shape_reports_the_offending_count() {
    for (count, budget, expected) in [(0, 16, 0), (9, 16, 9), (5, 4, 4)] {
        let mut builder = CircuitBuilder::<EF>::new();
        let indices: Vec<Vec<_>> = (0..count)
            .map(|_| (0..3).map(|_| builder.public_input()).collect())
            .collect();
        let error = verify_binary_query_indices::<BabyBear, EF>(
            &mut builder,
            BinaryTower128Challenger::new(ByteHash::Keccak256),
            3,
            &indices,
            budget,
        )
        .unwrap_err();
        assert!(matches!(error,
            p3_circuit::CircuitBuilderError::NonPrimitiveOpArity { got, .. }
                if got == expected
        ));
    }
}

#[test]
fn a_bounded_query_relation_proves() {
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover,
    };
    use p3_circuit_prover::{ConstraintProfile, config};

    let seed = [17; 7];
    let (queries, draws) = native(&seed, 3, 5);
    // Include one ignored draw after native completion in the real proof.
    let circuit = continuing_circuit(3, 5, draws + 1);
    let mut prover = BatchStarkProver::new(config::baby_bear());
    prover.register_table_prover(Box::new(KeccakF1600Prover::<4>));
    let prepared = prover
        .prepare_circuit::<EF, 4>(
            &circuit,
            &[Box::new(KeccakF1600Preprocessor)],
            &[Box::new(KeccakF1600AirBuilder::<4>)],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let mut runner = circuit.runner();
    let mut native =
        BinaryChallenger::<BinaryField128, _>::from_hasher(seed.to_vec(), Keccak256Hash);
    for _ in 0..draws {
        let _ = native.sample_bits(3);
    }
    native.observe(BinaryField128::from_repr(13));
    let expected = native.sample_algebra_element::<BinaryField128>().to_repr();
    let mut public = inputs(&seed, 3, &queries);
    public.extend((0..8).map(|i| EF::from_u16((expected >> (16 * i)) as u16)));
    runner.set_public_inputs(&public).unwrap();
    let proof = prepared.prove(&runner.run().unwrap()).unwrap();
    prepared.verifier().verify(&proof, &[]).unwrap();
}

#[test]
fn bounded_queries_resume_at_the_exact_native_completion_digest() {
    use p3_blake3::Blake3;

    macro_rules! check {
        ($hash:expr, $native_hash:expr, $bits:expr, $count:expr, $pre_samples:expr, $pow:expr) => {{
            let bits = $bits;
            let count = $count;
            let pow_bits = $pow;
            let mut builder = CircuitBuilder::<EF>::new();
            match $hash {
                ByteHash::Keccak256 => builder.enable_keccak_f1600::<BabyBear>(),
                ByteHash::Blake3 => builder.enable_blake3_compress::<BabyBear>(),
            }
            let initial = (0..7).map(|_| builder.public_input()).collect::<Vec<_>>();
            let pow = builder.alloc_public_input_array::<8>("query continuation field");
            let pow = builder.binary128_from_limbs::<BabyBear>(pow).unwrap();
            let queries = (0..count)
                .map(|_| {
                    (0..bits)
                        .map(|_| builder.public_input())
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let expected = builder.alloc_public_input_array::<8>("query continuation field");
            let expected = builder.binary128_from_limbs::<BabyBear>(expected).unwrap();
            let mut ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, EF>(
                &mut builder,
                $hash,
                &initial,
            )
            .unwrap();
            for _ in 0..$pre_samples {
                let _ = ch.sample::<BabyBear, EF>(&mut builder).unwrap();
            }
            ch.check_witness::<BabyBear, EF>(&mut builder, pow_bits, &pow)
                .unwrap();
            let continuation = verify_binary_query_indices_with_continuation::<BabyBear, EF>(
                &mut builder,
                ch,
                bits,
                &queries,
                48,
            )
            .unwrap();
            let observation = 0x230efdd683b217d840591086ffbad9c1u128;
            let bytes = observation
                .to_le_bytes()
                .map(|b| builder.define_const(EF::from_u8(b)));
            let mut resumed = continuation
                .resume_with_observation::<BabyBear, EF>(&mut builder, &bytes)
                .unwrap();
            let actual = resumed.sample::<BabyBear, EF>(&mut builder).unwrap();
            for (&a, &b) in actual.bits().iter().zip(expected.bits()) {
                let difference = builder.sub(a, b);
                builder.assert_zero(difference);
            }
            let circuit = builder.build().unwrap();
            let mut draw_counts = Vec::new();
            for seed in 0..10u8 {
                let mut ch =
                    BinaryChallenger::<BinaryField128, _>::from_hasher(vec![seed; 7], $native_hash);
                for _ in 0..$pre_samples {
                    let _ = ch.sample_algebra_element::<BinaryField128>();
                }
                let pow = if pow_bits == 0 {
                    BinaryField128::ZERO
                } else {
                    ch.clone().grind(pow_bits)
                };
                assert!(ch.check_witness(pow_bits, pow));
                let mut queries = Vec::new();
                let mut draws = 0;
                while queries.len() < count {
                    let candidate = ch.sample_bits(bits);
                    draws += 1;
                    if !queries.contains(&candidate) {
                        queries.push(candidate);
                    }
                }
                assert!(draws <= 48);
                draw_counts.push(draws);
                queries.sort_unstable();
                ch.observe(BinaryField128::from_repr(observation));
                let expected = ch.sample_algebra_element::<BinaryField128>().to_repr();
                let mut values = vec![EF::from_u8(seed); 7];
                values.extend((0..8).map(|i| EF::from_u16((pow.to_repr() >> (16 * i)) as u16)));
                values.extend(
                    queries
                        .iter()
                        .flat_map(|&q| (0..bits).map(move |b| EF::from_bool(q >> b & 1 == 1))),
                );
                values.extend((0..8).map(|i| EF::from_u16((expected >> (16 * i)) as u16)));
                assert!(runs(&circuit, &values));
                let last = values.len() - 8;
                values[last] += EF::ONE;
                assert!(!runs(&circuit, &values));
            }
            draw_counts
        }};
    }
    let counts = check!(ByteHash::Keccak256, Keccak256Hash, 3, 5, 0, 0);
    assert!(counts.iter().any(|&n| n <= 4) || counts.iter().any(|&n| n <= 8));
    assert!(counts.iter().any(|&n| n > 8));
    check!(ByteHash::Blake3, Blake3, 3, 5, 1, 0);
    check!(ByteHash::Keccak256, Keccak256Hash, 0, 1, 1, 1);
    check!(ByteHash::Blake3, Blake3, 1, 2, 0, 0);
}

#[test]
fn query_continuation_rejects_an_empty_resume_observation() {
    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_keccak_f1600::<BabyBear>();
    let continuation = verify_binary_query_indices_with_continuation::<BabyBear, EF>(
        &mut builder,
        BinaryTower128Challenger::new(ByteHash::Keccak256),
        0,
        &[vec![]],
        1,
    )
    .unwrap();
    let error = continuation
        .resume_with_observation::<BabyBear, EF>(&mut builder, &[])
        .unwrap_err();
    assert!(matches!(
        error,
        p3_circuit::CircuitBuilderError::NonPrimitiveOpArity { got: 0, .. }
    ));
}
