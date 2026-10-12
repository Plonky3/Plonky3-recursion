//! Poly64 AIR folding with three native cells per Poly192 challenge.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::{Poly64, Poly192};
use p3_blake3_air::Blake3BinaryAir;
use p3_bus::BusSymbolicBuilder;
use p3_circuit::ops::NativePoly192Target;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::InteractionSymbolicBuilder;
use p3_multi_stark::folder::MultilinearFolder;
use p3_multi_stark::selectors::BoundaryEvals;
use p3_recursion::verifier::{BinaryPolyAirConstraintPlan, VerifierLimits};

use crate::sum_shapes_air::{CarryAir, SUM_SHAPE_COLUMNS, SumShapesAir};

struct DenseAir;
impl BaseAir<Poly64> for DenseAir {
    fn width(&self) -> usize {
        2
    }
    fn preprocessed_width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![1]
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}
impl<AB: AirBuilder<F = Poly64>> Air<AB> for DenseAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let pp = b.preprocessed();
        let [a, c] = [main.current_slice()[0], main.current_slice()[1]];
        let next = main.next_slice()[1];
        let public = b.public_values()[0];
        let constant = Poly64::new(0xfedcba9876543210);
        b.assert_eq(a * c, pp.current_slice()[0] + constant);
        b.when_transition().assert_eq(next, a + c);
        b.when_first_row().assert_eq(a, public);
    }
}

/// Columns of [`ZeroColumnsAir`].
const COLUMNS: usize = 4;

/// Asserts its first `asserted` columns zero, in column order, so its fold is the Horner sum of
/// those openings.
struct ZeroColumnsAir {
    asserted: usize,
}
impl BaseAir<Poly64> for ZeroColumnsAir {
    fn width(&self) -> usize {
        COLUMNS
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}
impl<AB: AirBuilder<F = Poly64>> Air<AB> for ZeroColumnsAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        for &value in &main.current_slice()[..self.asserted] {
            b.assert_zero(value);
        }
    }
}

fn scalar(b: &mut CircuitBuilder<Poly64>) -> NativePoly192Target {
    let coefficients = b.alloc_public_input_array::<3>("native Poly192 value");
    b.native_poly192_from_coefficients(coefficients)
}
fn dense(i: u64) -> Poly192 {
    Poly192::new(core::array::from_fn(|k| {
        Poly64::new(0x8123456789abcdefu64.wrapping_mul(i + 17 * k as u64))
    }))
}

#[test]
fn native_poly_air_matches_the_full_extension_folder() {
    let plan = BinaryPolyAirConstraintPlan::from_air(&DenseAir, 1).unwrap();
    let mut b = CircuitBuilder::<Poly64>::new();
    let current = [scalar(&mut b), scalar(&mut b)];
    let next = [scalar(&mut b)];
    let pp = [scalar(&mut b)];
    let public = [b.public_input()];
    let point = [scalar(&mut b)];
    let alpha = scalar(&mut b);
    let actual = plan
        .evaluate_native_with_auxiliary(&mut b, &point, &current, &next, &pp, &[], &public, &alpha)
        .unwrap();
    let expected = scalar(&mut b);
    for (&actual, &expected) in actual.coefficients().iter().zip(expected.coefficients()) {
        let difference = b.sub(actual, expected);
        b.assert_zero(difference);
    }
    let circuit = b.build().unwrap();
    for seed in [13, 49] {
        let current = [dense(seed), dense(seed + 1)];
        let next = [Poly192::ZERO, dense(seed + 2)];
        let pp = [dense(seed + 3)];
        let public = [Poly64::new(0xfedcba9876543210)];
        let point = [dense(seed + 4)];
        let alpha = dense(seed + 5);
        let expected =
            MultilinearFolder::new(&current, &next, BoundaryEvals::at(&point), &public, alpha)
                .with_preprocessed(&pp, &[Poly192::ZERO])
                .eval_air(&DenseAir);
        let mut values: Vec<_> = current
            .into_iter()
            .chain([next[1]])
            .chain(pp)
            .flat_map(|value| value.coefficients())
            .collect();
        values.extend(public);
        values.extend(
            point
                .into_iter()
                .chain([alpha, expected])
                .flat_map(|value| value.coefficients()),
        );
        let run = |values: &[Poly64]| {
            let mut runner = circuit.runner();
            runner
                .set_public_inputs(values)
                .and_then(|()| runner.run())
                .is_ok()
        };
        assert!(run(&values));
        for coefficient in 0..3 {
            let mut wrong = values.clone();
            let index = wrong.len() - 3 + coefficient;
            wrong[index] += Poly64::ONE;
            assert!(!run(&wrong));
        }
    }
}

/// The native fold weights the assertions by descending powers of alpha, the first under the
/// highest, as the native folder does. The ascending order and the sum weighted by alpha alone
/// are refused.
#[test]
fn native_fold_weights_assertions_by_descending_alpha_powers() {
    let air = ZeroColumnsAir { asserted: COLUMNS };
    let plan = BinaryPolyAirConstraintPlan::from_air(&air, 1).unwrap();
    let mut b = CircuitBuilder::<Poly64>::new();
    let current: [_; COLUMNS] = core::array::from_fn(|_| scalar(&mut b));
    let point = [scalar(&mut b)];
    let alpha = scalar(&mut b);
    let folded = plan
        .evaluate_native(&mut b, &point, &current, &[], &[], &alpha)
        .unwrap();
    let expected = scalar(&mut b);
    for (&folded, &expected) in folded.coefficients().iter().zip(expected.coefficients()) {
        let difference = b.sub(folded, expected);
        b.assert_zero(difference);
    }
    let circuit = b.build().unwrap();
    let current: [Poly192; COLUMNS] = core::array::from_fn(|i| dense(i as u64 + 3));
    let point = dense(53);
    let alpha = dense(59);
    let runs = |expected: Poly192| {
        let statement: Vec<_> = current
            .into_iter()
            .chain([point, alpha, expected])
            .flat_map(|value| value.coefficients())
            .collect();
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&statement)
            .and_then(|()| runner.run())
            .is_ok()
    };
    let descending = current
        .iter()
        .fold(Poly192::ZERO, |sum, &c| sum * alpha + c);
    let folder = MultilinearFolder::new(
        &current,
        &[Poly192::ZERO; COLUMNS],
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
        .fold(Poly192::ZERO, |sum, &c| sum * alpha + c);
    let flat = alpha * current.iter().copied().sum::<Poly192>();
    for wrong in [ascending, flat] {
        assert_ne!(wrong, descending);
        assert!(!runs(wrong));
    }
}

/// Each assertion after the first adds nine expression nodes to the native fold: one Poly192
/// multiply-add of the running sum, alpha and the assertion, where a product and a sum take
/// thirteen.
#[test]
fn native_fold_adds_one_multiply_add_per_further_assertion() {
    let nodes = |asserted| {
        let plan = BinaryPolyAirConstraintPlan::from_air(&ZeroColumnsAir { asserted }, 1).unwrap();
        let mut b = CircuitBuilder::<Poly64>::new();
        let current: [_; COLUMNS] = core::array::from_fn(|_| scalar(&mut b));
        let point = [scalar(&mut b)];
        let alpha = scalar(&mut b);
        let before = b.construction_usage().unwrap().expression_nodes;
        plan.evaluate_native(&mut b, &point, &current, &[], &[], &alpha)
            .unwrap();
        b.construction_usage().unwrap().expression_nodes - before
    };
    assert_eq!(nodes(COLUMNS) - nodes(1), 9 * (COLUMNS - 1));
}

/// Binds the native fold of `air` at one point to three public expected coefficients. Public
/// inputs: the openings' coefficients, the point's, alpha's, then the expected fold's.
fn native_fold_circuit<A>(air: &A) -> (BinaryPolyAirConstraintPlan, Circuit<Poly64>)
where
    A: Air<InteractionSymbolicBuilder<Poly64, Poly192>> + Air<BusSymbolicBuilder<Poly64, Poly192>>,
{
    let limits = VerifierLimits {
        max_metadata_entries: 1 << 20,
        ..VerifierLimits::default()
    };
    let plan = BinaryPolyAirConstraintPlan::with_limits(air, 1, &limits).unwrap();
    let mut b = CircuitBuilder::<Poly64>::new();
    let current: Vec<_> = (0..plan.main_width()).map(|_| scalar(&mut b)).collect();
    let point = [scalar(&mut b)];
    let alpha = scalar(&mut b);
    let folded = plan
        .evaluate_native(&mut b, &point, &current, &[], &[], &alpha)
        .unwrap();
    let expected = scalar(&mut b);
    for (&folded, &expected) in folded.coefficients().iter().zip(expected.coefficients()) {
        let difference = b.sub(folded, expected);
        b.assert_zero(difference);
    }
    (plan, b.build().unwrap())
}

/// Openings, point and alpha drawn from `seed`, then the AIR polynomial's fold there.
fn dense_fold<A>(air: &A, width: usize, seed: u64) -> (Vec<Poly192>, Poly192, Poly192, Poly192)
where
    A: for<'a> Air<MultilinearFolder<'a, Poly64, Poly192, Poly192>>,
{
    let current: Vec<Poly192> = (0..width as u64).map(|i| dense(seed + 3 * i)).collect();
    let point = dense(seed + 3 * width as u64);
    let alpha = dense(seed + 3 * width as u64 + 1);
    let fold = MultilinearFolder::new(
        &current,
        &vec![Poly192::ZERO; width],
        BoundaryEvals::at(&[point]),
        &[],
        alpha,
    )
    .eval_air(air);
    (current, point, alpha, fold)
}

/// Whether `circuit` from [`native_fold_circuit`] accepts `expected` as the fold.
fn accepts_fold(
    circuit: &Circuit<Poly64>,
    current: &[Poly192],
    point: Poly192,
    alpha: Poly192,
    expected: Poly192,
) -> bool {
    let statement: Vec<_> = current
        .iter()
        .copied()
        .chain([point, alpha, expected])
        .flat_map(|value| value.coefficients())
        .collect();
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&statement)
        .and_then(|()| runner.run())
        .is_ok()
}

/// The native fold of every sum shape is the AIR polynomial's fold, as the full extension folder
/// computes it. Its first constraint, the majority plus a carry `p * q + r + s` with
/// `p = c0 + c2`, `q = c1 + c2`, `r = c2` and `s = c3`, is bound with its operands in place:
/// the fold with that constraint taken as `p * r + q + s`, `r * q + p + s` or `p * q + r` is
/// refused, as is the fold off by one in any coefficient.
#[test]
fn native_fold_of_every_sum_shape_is_the_air_polynomial() {
    let (plan, circuit) = native_fold_circuit(&SumShapesAir);
    let weight = |alpha: Poly192| alpha.exp_u64(plan.constraint_count() as u64 - 1);
    for seed in [5, 89] {
        let (current, point, alpha, fold) = dense_fold(&SumShapesAir, SUM_SHAPE_COLUMNS, seed);
        assert!(accepts_fold(&circuit, &current, point, alpha, fold));
        for coefficient in 0..3 {
            let mut unit = [Poly64::ZERO; 3];
            unit[coefficient] = Poly64::ONE;
            let wrong = fold + Poly192::new(unit);
            assert!(!accepts_fold(&circuit, &current, point, alpha, wrong));
        }
        let [p, q, r, s] = [
            current[0] + current[2],
            current[1] + current[2],
            current[2],
            current[3],
        ];
        for wrong in [p * r + q + s, r * q + p + s, p * q + r] {
            let wrong = fold + weight(alpha) * (wrong + p * q + r + s);
            assert_ne!(wrong, fold);
            assert!(!accepts_fold(&circuit, &current, point, alpha, wrong));
        }
    }
}

/// The native fold of the BLAKE3 compression AIR in Poly192 is its AIR polynomial's fold.
/// 10,304 of its constraints are a majority plus a carry.
#[test]
fn native_fold_of_the_blake3_air_is_the_air_polynomial() {
    let air = Blake3BinaryAir::default();
    let (plan, circuit) = native_fold_circuit(&air);
    let width = plan.main_width();
    for seed in [7, 61] {
        let (current, point, alpha, fold) = dense_fold(&air, width, seed);
        assert!(accepts_fold(&circuit, &current, point, alpha, fold));
        let wrong = fold + Poly192::new([Poly64::ZERO, Poly64::ONE, Poly64::ZERO]);
        assert!(!accepts_fold(&circuit, &current, point, alpha, wrong));
    }
}

/// Each further bit of the BLAKE3 carry chain adds 28 expression nodes to the native fold: six
/// additions for its carry `sum + x + y`, and 22 for the previous bit's majority plus that
/// carry. These are three for the sum `x + carry`, nine for the Poly192 multiply-add of it with
/// the factor `y + carry` and the addend `carry`, and ten for the step that folds the
/// multiply-add and the new carry into the running fold. The factor `y + carry` is the carry's
/// own partial sum `sum + x`, which takes no node.
#[test]
fn native_carry_chain_adds_28_nodes_per_bit() {
    let nodes = |bits| {
        let plan = BinaryPolyAirConstraintPlan::from_air(&CarryAir { bits }, 1).unwrap();
        let mut b = CircuitBuilder::<Poly64>::new();
        let current: Vec<_> = (0..3 * bits).map(|_| scalar(&mut b)).collect();
        let point = [scalar(&mut b)];
        let alpha = scalar(&mut b);
        let before = b.construction_usage().unwrap().expression_nodes;
        plan.evaluate_native(&mut b, &point, &current, &[], &[], &alpha)
            .unwrap();
        b.construction_usage().unwrap().expression_nodes - before
    };
    assert_eq!(nodes(9) - nodes(8), 28);
}
