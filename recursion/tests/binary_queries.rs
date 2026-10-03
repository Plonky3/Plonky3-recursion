//! Fixed-shape verification of native binary PCS duplicate-rejection sampling.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryChallenger, BinaryField128};
use p3_challenger::CanSampleBits;
use p3_circuit::ops::ByteHash;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::BinomialExtensionField;
use p3_keccak::Keccak256Hash;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{verify_binary_pcs_query_indices, verify_binary_query_indices};

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
    let circuit = circuit(3, 5, draws + 1);
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
    runner
        .set_public_inputs(&inputs(&seed, 3, &queries))
        .unwrap();
    let proof = prepared.prove(&runner.run().unwrap()).unwrap();
    prepared.verifier().verify(&proof, &[]).unwrap();
}
