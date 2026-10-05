//! Native scalar AIR folding agrees with the native multilinear folder.

use std::borrow::Cow;

use p3_air::boundary::{BoundaryEnd, BoundaryPublic};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::{BinaryField32, BinaryField128, TowerLevel};
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsParams};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{ByteHash, NativeTower128Target};
use p3_circuit_prover::native_bus::NativeBusCircuit;
use p3_field::PrimeCharacteristicRing;
use p3_multi_stark::folder::MultilinearFolder;
use p3_multi_stark::selectors::BoundaryEvals;
use p3_recursion::artifact::{
    BinaryNativeAuthority, BinaryNativePcsParameters, BinaryNativeVerifierSpec,
};
use p3_recursion::verifier::{BinaryAirConstraintPlan, VerifierLimits};

type F = BinaryField128;

struct NarrowAir;
impl BaseAir<BinaryField32> for NarrowAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}
impl<AB: AirBuilder<F = BinaryField32>> Air<AB> for NarrowAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let value = main.current_slice()[0];
        let public = b.public_values()[0];
        b.when_first_row().assert_eq(value * value, public);
    }
}

#[test]
fn tower32_air_uses_native_challenges_and_rejects_high_base_coordinates() {
    let plan = BinaryAirConstraintPlan::<BinaryField32, F>::from_air(&NarrowAir, 1).unwrap();
    let mut b = CircuitBuilder::<F>::new();
    let current = [scalar(&mut b)];
    let public = [scalar(&mut b)];
    let point = [scalar(&mut b)];
    let alpha = scalar(&mut b);
    let folded = plan
        .evaluate_native(&mut b, &point, &current, &[], &public, &alpha)
        .unwrap();
    let expected = scalar(&mut b);
    let difference = b.sub(folded.as_expr(), expected.as_expr());
    b.assert_zero(difference);
    let circuit = b.build().unwrap();
    let current = F::from_repr(0xfedcba98765432108123456789abcdef);
    let public = F::from_repr(0x8912);
    let point = F::from_repr(0x8123456789abcdeffedcba9876543210);
    let alpha = F::from_repr(0x9876543210abcdef0123456789abcdef);
    let expected = (F::ONE + point) * (current * current + public);
    let values = [current, public, point, alpha, expected];
    let mut runner = circuit.runner();
    runner.set_public_inputs(&values).unwrap();
    runner.run().unwrap();
    for high in [1u128 << 32, 1u128 << 127] {
        let mut wrong = values;
        wrong[1] += F::from_repr(high);
        // Keep the folded equation satisfied so only base-field membership
        // rejects the assignment.
        wrong[4] = (F::ONE + point) * (current * current + wrong[1]);
        let mut runner = circuit.runner();
        assert!(
            runner
                .set_public_inputs(&wrong)
                .and_then(|()| runner.run())
                .is_err()
        );
    }
    let mut b = CircuitBuilder::<F>::new();
    let zero = b.native_tower128_constant(0);
    let invalid = b.native_tower128_constant(1u128 << 32);
    assert!(
        plan.evaluate_native(&mut b, &[zero], &[zero], &[], &[invalid], &zero)
            .is_err()
    );
}

struct DenseAir {
    periods: Vec<Vec<F>>,
    constant: F,
}
impl BaseAir<F> for DenseAir {
    fn width(&self) -> usize {
        3
    }
    fn preprocessed_width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        2
    }
    fn num_periodic_columns(&self) -> usize {
        self.periods.len()
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<F>]> {
        Cow::Borrowed(&self.periods)
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![2, 0]
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![1]
    }
    fn public_boundary_io(&self) -> &[BoundaryPublic] {
        const PINS: [BoundaryPublic; 2] = [
            BoundaryPublic::new(0, BoundaryEnd::First, 0),
            BoundaryPublic::new(2, BoundaryEnd::Last, 1),
        ];
        &PINS
    }
}
impl<AB: AirBuilder<F = F>> Air<AB> for DenseAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let pp = b.preprocessed();
        let [a, c, d] = core::array::from_fn::<_, 3, _>(|i| main.current_slice()[i]);
        let [next2, next0] = [main.next_slice()[2], main.next_slice()[0]];
        let [pp0, pp1, pp_next1] = [
            pp.current_slice()[0],
            pp.current_slice()[1],
            pp.next_slice()[1],
        ];
        let [period0, period1, period2]: [AB::Expr; 3] =
            core::array::from_fn(|i| b.periodic_values()[i].into());
        let public: AB::Expr = b.public_values()[0].into();
        b.assert_eq(a, pp0 * c + period0 + self.constant);
        b.when_transition().assert_eq(next2, c + pp_next1);
        b.assert_eq(next0, period2 + public);
        b.assert_eq(pp1, period1 * d);
    }
}

fn mle(values: &[F], point: &[F]) -> F {
    let mut layer = values.to_vec();
    let count = values.len().ilog2() as usize;
    for &r in point[point.len() - count..].iter().rev() {
        layer = layer
            .as_chunks::<2>()
            .0
            .iter()
            .map(|p| p[0] + r * (p[0] + p[1]))
            .collect();
    }
    layer[0]
}

fn scalar(b: &mut CircuitBuilder<F>) -> NativeTower128Target {
    let expression = b.public_input();
    b.native_tower128_from_expr(expression)
}

#[test]
fn scalar_air_preserves_dense_constants_periods_and_successor_order() {
    let dense = |n: u128| F::from_repr(0x8123456789abcdeffedcba9876543210u128.wrapping_mul(n));
    let air = DenseAir {
        constant: dense(17),
        periods: vec![
            vec![dense(19)],
            vec![dense(23), dense(29)],
            vec![dense(31), dense(37), dense(41), dense(43)],
        ],
    };
    let plan = BinaryAirConstraintPlan::<F, F>::from_air(&air, 2).unwrap();
    let mut b = CircuitBuilder::<F>::new();
    let current = [scalar(&mut b), scalar(&mut b), scalar(&mut b)];
    let next = [scalar(&mut b), scalar(&mut b)];
    let pp = [scalar(&mut b), scalar(&mut b)];
    let pp_next = [scalar(&mut b)];
    let public = [scalar(&mut b), scalar(&mut b)];
    let point = [scalar(&mut b), scalar(&mut b)];
    let alpha = scalar(&mut b);
    let actual = plan
        .evaluate_native_with_auxiliary(
            &mut b, &point, &current, &next, &pp, &pp_next, &public, &alpha,
        )
        .unwrap();
    let expected = scalar(&mut b);
    let difference = b.sub(actual.as_expr(), expected.as_expr());
    b.assert_zero(difference);
    let circuit = b.build().unwrap();
    let prepared = NativeBusCircuit::new(&circuit, "native-air").unwrap();
    let parameters = |n| BinaryNativePcsParameters {
        config: BinaryPcsConfig::try_new::<F, F>(
            n,
            BinaryPcsParams {
                log_inv_rate: 2,
                pow_bits: 0,
                security_level: 8,
            },
        )
        .unwrap(),
        hash: ByteHash::Keccak256,
        cap_height: 0,
        max_query_draws: 128,
    };
    let spec = BinaryNativeVerifierSpec {
        main: parameters(prepared.main_variables()),
        preprocessed: prepared.preprocessed_variables().map(parameters),
        transcript_hash: ByteHash::Keccak256,
        initial_bytes: b"native-scalar-air-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 32,
        security_bits: 4,
    };
    let (prover, authority) = BinaryNativeAuthority::<F, F, _>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec,
        &VerifierLimits::default(),
    )
    .unwrap();
    for seed in [2, 47] {
        let current = [dense(seed), dense(seed + 1), dense(seed + 2)];
        let next = [dense(seed + 3), dense(seed + 4), dense(seed + 5)];
        let pp = [dense(seed + 6), dense(seed + 7)];
        let pp_next = [dense(seed + 8), dense(seed + 9)];
        let public = [dense(seed + 10), dense(seed + 11)];
        let point = [dense(seed + 12), dense(seed + 13)];
        let alpha = dense(seed + 14);
        let periods: Vec<_> = air.periods.iter().map(|v| mle(v, &point)).collect();
        let expected =
            MultilinearFolder::new(&current, &next, BoundaryEvals::at(&point), &public, alpha)
                .with_preprocessed(&pp, &pp_next)
                .with_periodic(&periods)
                .eval_air(&air);
        let mut statement = current.to_vec();
        statement.extend([next[2], next[0]]);
        statement.extend(pp);
        statement.push(pp_next[1]);
        statement.extend(public);
        statement.extend(point);
        statement.extend([alpha, expected]);
        let mut runner = circuit.runner();
        runner.set_public_inputs(&statement).unwrap();
        let traces = prepared
            .traces(&runner.run().unwrap().witness_trace)
            .unwrap();
        let public = prepared.public_values(&statement).unwrap();
        let proof = prover.prove(&public, traces).unwrap();
        authority.verify_native(&proof, &public).unwrap();
        *statement.last_mut().unwrap() += F::ONE;
        let wrong = prepared.public_values(&statement).unwrap();
        assert!(authority.verify_native(&proof, &wrong).is_err());
        let mut runner = circuit.runner();
        assert!(
            runner
                .set_public_inputs(&statement)
                .and_then(|()| runner.run())
                .is_err()
        );
    }
}
