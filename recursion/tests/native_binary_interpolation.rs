//! Native scalar interpolation uses the released binary sumcheck nodes.

use p3_binary_field::{BinaryField128, TowerLevel};
use p3_circuit::{CircuitBuilder, ops::NativeTower128Target};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_recursion::pcs::binary::Binary128SumcheckInterpolator;
use p3_sumcheck::generic_degree::RoundPolyInterpolator;

type F = BinaryField128;
fn scalar(b: &mut CircuitBuilder<F>) -> NativeTower128Target {
    let expression = b.public_input();
    b.native_tower128_from_expr(expression)
}

#[test]
fn scalar_interpolation_matches_native_at_nodes_and_dense_challenges() {
    for degree in [1, 2, 3, 4, 5, 7] {
        let recursive = Binary128SumcheckInterpolator::new(degree).unwrap();
        let native = RoundPolyInterpolator::<F>::new(degree);
        let mut b = CircuitBuilder::<F>::new();
        let claim = scalar(&mut b);
        let evaluations: Vec<_> = (0..degree).map(|_| scalar(&mut b)).collect();
        let challenge = scalar(&mut b);
        let expected = scalar(&mut b);
        assert!(
            recursive
                .reduce_claim_native(&mut b, &claim, &evaluations[..degree - 1], &challenge)
                .is_err()
        );
        let actual = recursive
            .reduce_claim_native(&mut b, &claim, &evaluations, &challenge)
            .unwrap();
        let difference = b.sub(actual.as_expr(), expected.as_expr());
        b.assert_zero(difference);
        let circuit = b.build().unwrap();
        let dense = |n: u128| F::from_repr(0x892f364ca7bc5139228945fab023d947u128.wrapping_mul(n));
        let claim = dense(11);
        let evaluations: Vec<_> = (0..degree).map(|i| dense(i as u128 + 12)).collect();
        let run = |public: &[F]| {
            let mut runner = circuit.runner();
            runner
                .set_public_inputs(public)
                .and_then(|()| runner.run())
                .is_ok()
        };
        for challenge in (0..=degree).map(F::interpolation_node).chain([dense(53)]) {
            let expected = native.eval(&evaluations, claim, challenge);
            let mut public = vec![claim];
            public.extend_from_slice(&evaluations);
            public.extend([challenge, expected]);
            assert!(run(&public));
            *public.last_mut().unwrap() += F::ONE;
            assert!(!run(&public));
        }
    }
}
