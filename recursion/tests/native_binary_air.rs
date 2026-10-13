//! Native scalar AIR folding agrees with the native multilinear folder.

use std::borrow::Cow;

use p3_air::boundary::{BoundaryEnd, BoundaryPublic};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::{BinaryField32, BinaryField128, TowerLevel};
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsParams};
use p3_blake3_air::Blake3BinaryAir;
use p3_bus::BusSymbolicBuilder;
use p3_circuit::ops::{ByteHash, NativeTower128Target};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_circuit_prover::native_bus::NativeBusCircuit;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionSymbolicBuilder;
use p3_multi_stark::folder::MultilinearFolder;
use p3_multi_stark::selectors::BoundaryEvals;
use p3_recursion::artifact::{
    BinaryNativeAuthority, BinaryNativePcsParameters, BinaryNativeVerifierSpec,
};
use p3_recursion::verifier::{BinaryAirConstraintPlan, VerifierLimits};

use crate::sum_shapes_air::{CarryAir, SUM_SHAPE_COLUMNS, SumShapesAir};

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

/// Columns of [`ZeroColumnsAir`].
const COLUMNS: usize = 4;

/// Asserts its first `asserted` columns zero, in column order, so its fold is the Horner sum of
/// those openings.
struct ZeroColumnsAir {
    asserted: usize,
}
impl BaseAir<F> for ZeroColumnsAir {
    fn width(&self) -> usize {
        COLUMNS
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}
impl<AB: AirBuilder<F = F>> Air<AB> for ZeroColumnsAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        for &value in &main.current_slice()[..self.asserted] {
            b.assert_zero(value);
        }
    }
}

/// The native fold weights the assertions by descending powers of alpha, the first under the
/// highest, as the native folder does. The ascending order and the sum weighted by alpha alone
/// are refused.
#[test]
fn native_fold_weights_assertions_by_descending_alpha_powers() {
    let air = ZeroColumnsAir { asserted: COLUMNS };
    let plan = BinaryAirConstraintPlan::<F, F>::from_air(&air, 1).unwrap();
    let mut b = CircuitBuilder::<F>::new();
    let current: [_; COLUMNS] = core::array::from_fn(|_| scalar(&mut b));
    let point = [scalar(&mut b)];
    let alpha = scalar(&mut b);
    let folded = plan
        .evaluate_native(&mut b, &point, &current, &[], &[], &alpha)
        .unwrap();
    let expected = scalar(&mut b);
    let difference = b.sub(folded.as_expr(), expected.as_expr());
    b.assert_zero(difference);
    let circuit = b.build().unwrap();
    let dense = |n: u128| F::from_repr(0x8123456789abcdeffedcba9876543210u128.wrapping_mul(n));
    let current: [F; COLUMNS] = core::array::from_fn(|i| dense(i as u128 + 3));
    let point = dense(53);
    let alpha = dense(59);
    let runs = |expected: F| {
        let mut statement = current.to_vec();
        statement.extend([point, alpha, expected]);
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&statement)
            .and_then(|()| runner.run())
            .is_ok()
    };
    let descending = current.iter().fold(F::ZERO, |sum, &c| sum * alpha + c);
    let folder = MultilinearFolder::new(
        &current,
        &[F::ZERO; COLUMNS],
        BoundaryEvals::at(&[point]),
        &[],
        alpha,
    )
    .eval_air(&air);
    assert_eq!(descending, folder);
    assert!(runs(descending));
    let ascending = current
        .iter()
        .rev()
        .fold(F::ZERO, |sum, &c| sum * alpha + c);
    let flat = alpha * current.iter().copied().sum::<F>();
    for wrong in [ascending, flat] {
        assert_ne!(wrong, descending);
        assert!(!runs(wrong));
    }
}

/// Each assertion after the first adds one expression node to the native fold: a multiply-add of
/// the running sum, alpha and the assertion, with no separately constrained product.
#[test]
fn native_fold_adds_one_node_per_further_assertion() {
    let nodes = |asserted| {
        let plan =
            BinaryAirConstraintPlan::<F, F>::from_air(&ZeroColumnsAir { asserted }, 1).unwrap();
        let mut b = CircuitBuilder::<F>::new();
        let current: [_; COLUMNS] = core::array::from_fn(|_| scalar(&mut b));
        let point = [scalar(&mut b)];
        let alpha = scalar(&mut b);
        let before = b.construction_usage().unwrap().expression_nodes;
        plan.evaluate_native(&mut b, &point, &current, &[], &[], &alpha)
            .unwrap();
        b.construction_usage().unwrap().expression_nodes - before
    };
    assert_eq!(nodes(COLUMNS) - nodes(1), COLUMNS - 1);
}

/// Binds the native fold of `air` at one point to a public expected value. Public inputs: the
/// openings, the point, alpha, then the expected fold.
fn native_fold_circuit<A>(air: &A) -> (BinaryAirConstraintPlan<F, F>, Circuit<F>)
where
    A: Air<InteractionSymbolicBuilder<F, F>> + Air<BusSymbolicBuilder<F, F>>,
{
    let limits = VerifierLimits {
        max_metadata_entries: 1 << 20,
        ..VerifierLimits::default()
    };
    let plan = BinaryAirConstraintPlan::<F, F>::with_limits(air, 1, &limits).unwrap();
    let mut b = CircuitBuilder::<F>::new();
    let current: Vec<_> = (0..plan.main_width()).map(|_| scalar(&mut b)).collect();
    let point = [scalar(&mut b)];
    let alpha = scalar(&mut b);
    let folded = plan
        .evaluate_native(&mut b, &point, &current, &[], &[], &alpha)
        .unwrap();
    let expected = scalar(&mut b);
    let difference = b.sub(folded.as_expr(), expected.as_expr());
    b.assert_zero(difference);
    (plan, b.build().unwrap())
}

/// Openings, point and alpha drawn from `seed`, then the AIR polynomial's fold there.
fn dense_fold<A>(air: &A, width: usize, seed: u128) -> (Vec<F>, F, F, F)
where
    A: for<'a> Air<MultilinearFolder<'a, F, F, F>>,
{
    let dense =
        |n: u128| F::from_repr(0x8123456789abcdeffedcba9876543210u128.wrapping_mul(seed + 2 * n));
    let current: Vec<F> = (0..width as u128).map(dense).collect();
    let point = dense(width as u128);
    let alpha = dense(width as u128 + 1);
    let fold = MultilinearFolder::new(
        &current,
        &vec![F::ZERO; width],
        BoundaryEvals::at(&[point]),
        &[],
        alpha,
    )
    .eval_air(air);
    (current, point, alpha, fold)
}

/// Whether `circuit` from [`native_fold_circuit`] accepts `expected` as the fold.
fn accepts_fold(circuit: &Circuit<F>, current: &[F], point: F, alpha: F, expected: F) -> bool {
    let mut statement = current.to_vec();
    statement.extend([point, alpha, expected]);
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&statement)
        .and_then(|()| runner.run())
        .is_ok()
}

/// The native fold of every sum shape is the AIR polynomial's fold, as the native folder
/// computes it, and its circuit binds that fold: the fold plus one is refused.
#[test]
fn native_fold_of_every_sum_shape_is_the_air_polynomial() {
    let (_, circuit) = native_fold_circuit(&SumShapesAir);
    for seed in [5, 89] {
        let (current, point, alpha, fold) = dense_fold(&SumShapesAir, SUM_SHAPE_COLUMNS, seed);
        assert!(accepts_fold(&circuit, &current, point, alpha, fold));
        assert!(!accepts_fold(
            &circuit,
            &current,
            point,
            alpha,
            fold + F::ONE
        ));
    }
}

/// The native fold of the BLAKE3 compression AIR is its AIR polynomial's fold. 10,304 of its
/// constraints are a majority plus a carry.
#[test]
fn native_fold_of_the_blake3_air_is_the_air_polynomial() {
    let air = Blake3BinaryAir::default();
    let (plan, circuit) = native_fold_circuit(&air);
    let width = plan.main_width();
    for seed in [7, 61] {
        let (current, point, alpha, fold) = dense_fold(&air, width, seed);
        assert!(accepts_fold(&circuit, &current, point, alpha, fold));
        assert!(!accepts_fold(
            &circuit,
            &current,
            point,
            alpha,
            fold + F::ONE
        ));
    }
}

/// Each further bit of the BLAKE3 carry chain adds five expression nodes to the native fold,
/// with the majority's product either operand of its sum: two additions for its carry
/// `sum + x + y`, and three for the previous bit's majority plus that carry. These are the sum
/// `x + carry`, one multiply-add of it with the factor `y + carry` and the addend `carry`, and
/// one Horner step that folds the multiply-add and the new carry into the running fold. The
/// factor `y + carry` is the carry's own partial sum `sum + x`, which takes no node.
#[test]
fn native_carry_chain_adds_five_nodes_per_bit() {
    let nodes = |bits, addend_first| {
        let air = CarryAir { bits, addend_first };
        let plan = BinaryAirConstraintPlan::<F, F>::from_air(&air, 1).unwrap();
        let mut b = CircuitBuilder::<F>::new();
        let current: Vec<_> = (0..3 * bits).map(|_| scalar(&mut b)).collect();
        let point = [scalar(&mut b)];
        let alpha = scalar(&mut b);
        let before = b.construction_usage().unwrap().expression_nodes;
        plan.evaluate_native(&mut b, &point, &current, &[], &[], &alpha)
            .unwrap();
        b.construction_usage().unwrap().expression_nodes - before
    };
    for addend_first in [false, true] {
        assert_eq!(
            nodes(9, addend_first) - nodes(8, addend_first),
            5,
            "addend first: {addend_first}"
        );
    }
}

/// A sum of a product and an addend, `c0 * c1 + c2`, stated once and read by `readers`
/// constraints, each the product of the sum and a column of its own.
struct SharedSumAir {
    readers: usize,
}
impl<F> BaseAir<F> for SharedSumAir {
    fn width(&self) -> usize {
        3 + self.readers
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}
impl<AB: AirBuilder> Air<AB> for SharedSumAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let columns: Vec<AB::Expr> = main.current_slice().iter().map(|&c| c.into()).collect();
        let sum = columns[0].clone() * columns[1].clone() + columns[2].clone();
        for column in &columns[3..] {
            b.assert_zero(sum.clone() * column.clone());
        }
    }
}

/// A sum of a product and an addend that several constraints read is one multiply-add. Each
/// reader's copy of the sum is a node of its own in the program, and equal nodes evaluate to one
/// shared expression, so the product is read once. A second reader adds two nodes, its own
/// product and its fold step.
#[test]
fn native_fold_evaluates_a_shared_sum_as_one_multiply_add() {
    let nodes = |readers| {
        let plan = BinaryAirConstraintPlan::<F, F>::from_air(&SharedSumAir { readers }, 1).unwrap();
        let mut b = CircuitBuilder::<F>::new();
        let current: Vec<_> = (0..3 + readers).map(|_| scalar(&mut b)).collect();
        let point = [scalar(&mut b)];
        let alpha = scalar(&mut b);
        let before = b.construction_usage().unwrap().expression_nodes;
        plan.evaluate_native(&mut b, &point, &current, &[], &[], &alpha)
            .unwrap();
        b.construction_usage().unwrap().expression_nodes - before
    };
    assert_eq!(nodes(2) - nodes(1), 2);
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
