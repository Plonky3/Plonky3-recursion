//! Native arbitrary-degree interpolation at binary sumcheck nodes.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_circuit::ops::BinaryTower128Target;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_recursion::pcs::binary::Binary128SumcheckInterpolator;
use p3_sumcheck::generic_degree::RoundPolyInterpolator;

fn input(b: &mut CircuitBuilder<BabyBear>) -> BinaryTower128Target {
    let limbs = b.alloc_private_input_array::<8>("generic sumcheck field");
    b.binary128_from_limbs::<BabyBear>(limbs).unwrap()
}

fn run(circuit: &Circuit<BabyBear>, values: &[BinaryField128]) -> bool {
    let values = values
        .iter()
        .flat_map(|v| (0..8).map(move |i| BabyBear::from_u16((v.to_repr() >> (16 * i)) as u16)))
        .collect::<Vec<_>>();
    let mut runner = circuit.runner();
    runner.set_private_inputs(&values).unwrap();
    runner.run().is_ok()
}

fn fixture(degree: usize) -> (Circuit<BabyBear>, Vec<BinaryField128>) {
    let recursive = Binary128SumcheckInterpolator::new(degree).unwrap();
    let native = RoundPolyInterpolator::<BinaryField128>::new(degree);
    let mut b = CircuitBuilder::<BabyBear>::new();
    let claim = input(&mut b);
    let messages = (0..degree).map(|_| input(&mut b)).collect::<Vec<_>>();
    let challenge = input(&mut b);
    let expected = input(&mut b);
    let actual = recursive
        .reduce_claim(&mut b, &claim, &messages, &challenge)
        .unwrap();
    for (&a, &e) in actual.bits().iter().zip(expected.bits()) {
        let difference = b.sub(a, e);
        b.assert_zero(difference);
    }
    let circuit = b.build().unwrap();
    let dense = |i: usize| {
        BinaryField128::from_repr(
            0x892f364ca7bc5139228945fab023d947u128.wrapping_mul(i as u128 + 11),
        )
    };
    let claim = dense(0);
    let messages = (0..degree).map(|i| dense(i + 1)).collect::<Vec<_>>();
    let mut last = vec![];
    for challenge in (0..=degree)
        .map(BinaryField128::interpolation_node)
        .chain([dense(30)])
    {
        let expected = native.eval(&messages, claim, challenge);
        let mut values = vec![claim];
        values.extend_from_slice(&messages);
        values.extend([challenge, expected]);
        assert!(run(&circuit, &values));
        let mut wrong = values.clone();
        *wrong.last_mut().unwrap() += BinaryField128::ONE;
        assert!(!run(&circuit, &wrong));
        last = values;
    }
    (circuit, last)
}

#[test]
fn arbitrary_degree_reductions_match_native_at_nodes_and_dense_challenges() {
    for degree in [1, 2, 3, 4, 7] {
        fixture(degree);
    }
}

#[test]
fn quartic_binary_reduction_proves_in_a_prime_field_circuit() {
    use p3_circuit_prover::batch_stark_prover::BatchStarkProver;
    use p3_circuit_prover::{ConstraintProfile, config};
    let (circuit, values) = fixture(4);
    let prover = BatchStarkProver::new(config::baby_bear());
    let prepared = prover
        .prepare_circuit::<BabyBear, 1>(&circuit, &[], &[], ConstraintProfile::Standard)
        .unwrap();
    let values = values
        .iter()
        .flat_map(|v| (0..8).map(move |i| BabyBear::from_u16((v.to_repr() >> (16 * i)) as u16)))
        .collect::<Vec<_>>();
    let mut runner = circuit.runner();
    runner.set_private_inputs(&values).unwrap();
    let proof = prepared.prove(&runner.run().unwrap()).unwrap();
    prepared.verifier().verify(&proof, &[]).unwrap();
}

#[test]
fn trusted_interpolation_degree_and_coefficient_limits_are_checked() {
    use p3_recursion::verifier::{VerificationError, VerifierLimits};
    assert!(Binary128SumcheckInterpolator::new(0).is_err());
    assert!(Binary128SumcheckInterpolator::new(33).is_err());
    let limits = VerifierLimits {
        max_metadata_entries: 24,
        ..VerifierLimits::default()
    };
    assert!(matches!(
        Binary128SumcheckInterpolator::with_limits(4, &limits),
        Err(VerificationError::ResourceLimitExceeded {
            component: "metadata entries",
            ..
        })
    ));
    let interpolator = Binary128SumcheckInterpolator::new(4).unwrap();
    let mut b = CircuitBuilder::<BabyBear>::new();
    let zero = b.binary128_constant(0).unwrap();
    assert!(
        interpolator
            .reduce_claim(&mut b, &zero, &vec![zero.clone(); 3], &zero)
            .is_err()
    );
}
