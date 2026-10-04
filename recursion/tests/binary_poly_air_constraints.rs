//! Polynomial-basis AIR folding with full Poly192 challenges and Poly64 statements.

use p3_air::boundary::{BoundaryEnd, BoundaryPublic};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::{Poly64, Poly192};
use p3_bus::{BusActivation, BusDirection, BusInteractionBuilder, BusName, BusSymbolicBuilder};
use p3_circuit::ops::{BinaryPoly64Target, BinaryPoly192Target};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_lookup::{IndexedLookupBuilder, InteractionSymbolicBuilder};
use p3_multi_stark::folder::MultilinearFolder;
use p3_multi_stark::selectors::BoundaryEvals;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_recursion::verifier::{BinaryPolyAirConstraintPlan, VerificationError};

struct RecurrenceAir;
impl BaseAir<Poly64> for RecurrenceAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        3
    }
}
impl<AB: AirBuilder<F = Poly64>> Air<AB> for RecurrenceAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let current = main.current_slice();
        let next = main.next_slice();
        let public = b.public_values().to_vec();
        b.when_first_row().assert_eq(current[0], public[0]);
        b.when_first_row().assert_eq(current[1], public[1]);
        b.when_transition().assert_eq(next[0], current[1]);
        b.when_transition()
            .assert_eq(next[1], current[0] * current[1] + current[0]);
        b.when_last_row().assert_eq(current[1], public[2]);
    }
}

struct BooleanAir;
impl BaseAir<Poly64> for BooleanAir {
    fn width(&self) -> usize {
        1
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}
impl<AB: AirBuilder<F = Poly64>> Air<AB> for BooleanAir {
    fn eval(&self, b: &mut AB) {
        b.assert_bool(b.main().current_slice()[0]);
    }
}

fn base_input(b: &mut CircuitBuilder<BabyBear>) -> BinaryPoly64Target {
    let limbs = b.alloc_private_input_array::<4>("Poly64 AIR statement");
    b.binary_poly64_from_limbs::<BabyBear>(limbs).unwrap()
}
fn extension_input(b: &mut CircuitBuilder<BabyBear>) -> BinaryPoly192Target {
    let limbs = b.alloc_private_input_array::<12>("Poly192 AIR comparison");
    b.binary_poly192_from_limbs::<BabyBear>(limbs).unwrap()
}
fn base_limbs(v: Poly64) -> impl Iterator<Item = BabyBear> {
    (0..4).map(move |i| BabyBear::from_u16((v.to_bits() >> (16 * i)) as u16))
}
fn extension_limbs(v: Poly192) -> impl Iterator<Item = BabyBear> {
    v.coefficients().into_iter().flat_map(base_limbs)
}
fn run(circuit: &Circuit<BabyBear>, values: &[BabyBear]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(values).unwrap();
    runner.run().is_ok()
}
fn dense(i: u64) -> Poly192 {
    Poly192::new(core::array::from_fn(|k| {
        Poly64::new(0x693a_cef7_3315_31cdu64.wrapping_mul(i + 91 * k as u64))
    }))
}

fn compare<A>(
    air: A,
    height: usize,
    current: Vec<Poly192>,
    next: Vec<Poly192>,
    public: Vec<Poly64>,
    point: Vec<Poly192>,
    alpha: Poly192,
) -> (
    BinaryPolyAirConstraintPlan,
    Circuit<BabyBear>,
    Vec<BabyBear>,
)
where
    A: Air<InteractionSymbolicBuilder<Poly64, Poly192>>
        + Air<BusSymbolicBuilder<Poly64, Poly192>>
        + for<'a> Air<MultilinearFolder<'a, Poly64, Poly192, Poly192>>,
{
    let plan = BinaryPolyAirConstraintPlan::from_air(&air, height).unwrap();
    let native = MultilinearFolder::new(&current, &next, BoundaryEvals::at(&point), &public, alpha)
        .eval_air(&air);
    let mut b = CircuitBuilder::<BabyBear>::new();
    let current_targets = (0..current.len())
        .map(|_| extension_input(&mut b))
        .collect::<Vec<_>>();
    let next_targets = (0..plan.next_columns().len())
        .map(|_| extension_input(&mut b))
        .collect::<Vec<_>>();
    let public_targets = (0..public.len())
        .map(|_| base_input(&mut b))
        .collect::<Vec<_>>();
    let point_targets = (0..point.len())
        .map(|_| extension_input(&mut b))
        .collect::<Vec<_>>();
    let alpha_target = extension_input(&mut b);
    let actual = plan
        .evaluate(
            &mut b,
            &point_targets,
            &current_targets,
            &next_targets,
            &public_targets,
            &alpha_target,
        )
        .unwrap();
    let expected = extension_input(&mut b);
    for (a, e) in actual.coefficients().iter().zip(expected.coefficients()) {
        for (&a, &e) in a.bits().iter().zip(e.bits()) {
            let difference = b.sub(a, e);
            b.assert_zero(difference);
        }
    }
    let circuit = b.build().unwrap();
    let mut values = current
        .iter()
        .copied()
        .flat_map(extension_limbs)
        .collect::<Vec<_>>();
    for &column in plan.next_columns() {
        values.extend(extension_limbs(next[column]));
    }
    values.extend(public.iter().copied().flat_map(base_limbs));
    values.extend(point.iter().copied().flat_map(extension_limbs));
    values.extend(extension_limbs(alpha));
    values.extend(extension_limbs(native));
    assert!(run(&circuit, &values));
    let mut wrong = values.clone();
    let third_coefficient = wrong.len() - 4;
    wrong[third_coefficient] += BabyBear::ONE;
    assert!(!run(&circuit, &wrong));
    (plan, circuit, values)
}

#[test]
fn recurrence_fold_matches_native_with_all_three_challenge_coefficients() {
    let (plan, circuit, values) = compare(
        RecurrenceAir,
        2,
        vec![dense(3), dense(7)],
        vec![dense(11), dense(19)],
        vec![
            Poly64::new(0x9012_3456_789a_bcde),
            Poly64::new(0x57a9_83b1_de02_1365),
            Poly64::new(0xfefd_fcfb_faf9_f8f7),
        ],
        vec![dense(53), dense(61)],
        dense(71),
    );
    assert_eq!(plan.constraint_degree(), 3);
    assert_eq!(plan.constraint_count(), 5);
    assert_eq!(plan.next_columns(), [0, 1]);
    let mut wrong = values.clone();
    wrong[48] += BabyBear::ONE;
    assert!(!run(&circuit, &wrong));
    let mut wrong = values;
    wrong[48] = BabyBear::from_u32(1 << 16);
    assert!(!run(&circuit, &wrong));
}

#[test]
fn ordinary_boolean_assertions_remain_polynomial_constraints() {
    let (plan, _, _) = compare(
        BooleanAir,
        1,
        vec![dense(11)],
        vec![dense(13)],
        vec![],
        vec![dense(17)],
        dense(19),
    );
    assert_eq!(plan.constraint_degree(), 2);
    assert_eq!(plan.constraint_count(), 1);
}

struct AuxiliaryAir {
    period: Vec<Poly64>,
}
impl BaseAir<Poly64> for AuxiliaryAir {
    fn width(&self) -> usize {
        3
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![2, 0]
    }
    fn preprocessed_width(&self) -> usize {
        2
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![1]
    }
    fn num_public_values(&self) -> usize {
        2
    }
    fn num_periodic_columns(&self) -> usize {
        1
    }
    fn periodic_columns(&self) -> std::borrow::Cow<'_, [Vec<Poly64>]> {
        std::borrow::Cow::Owned(vec![self.period.clone()])
    }
    fn public_boundary_io(&self) -> &[BoundaryPublic] {
        const PINS: [BoundaryPublic; 2] = [
            BoundaryPublic::new(2, BoundaryEnd::Last, 0),
            BoundaryPublic::new(0, BoundaryEnd::First, 1),
        ];
        &PINS
    }
}
impl<AB: AirBuilder<F = Poly64>> Air<AB> for AuxiliaryAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let current = main.current_slice();
        let next = main.next_slice();
        let pp = b.preprocessed();
        let (p0, p1, pn1) = (
            pp.current_slice()[0],
            pp.current_slice()[1],
            pp.next_slice()[1],
        );
        let periodic: AB::Expr = b.periodic_values()[0].into();
        b.assert_eq(next[2], current[0]);
        b.assert_eq(next[0], current[1]);
        b.assert_eq(current[2], p1.into() * periodic);
        b.assert_eq(pn1, p0);
    }
}

#[test]
fn periodic_suffix_preprocessing_sparse_successors_and_pins_match_native() {
    let air = AuxiliaryAir {
        period: (11..15)
            .map(|i| Poly64::new(0x8539_437b_215d_1351 ^ i))
            .collect(),
    };
    let point = [dense(401), dense(503), dense(601)];
    let current = [dense(3), dense(5), dense(7)];
    let next = [dense(11), dense(13), dense(17)];
    let pp = [dense(37), dense(71)];
    let pp_next = [dense(167), dense(233)];
    let public = [
        Poly64::new(0x9012_3456_789a_bcde),
        Poly64::new(0x57a9_83b1_de02_1365),
    ];
    let alpha = dense(733);
    let periods = [Poly::new(air.period.clone()).eval_base(&Point::new(point[1..].to_vec()))];
    let expected =
        MultilinearFolder::new(&current, &next, BoundaryEvals::at(&point), &public, alpha)
            .with_preprocessed(&pp, &pp_next)
            .with_periodic(&periods)
            .eval_air(&air);
    let plan = BinaryPolyAirConstraintPlan::from_air(&air, 3).unwrap();
    assert_eq!(plan.next_columns(), [2, 0]);
    assert_eq!(plan.preprocessed_next_columns(), [1]);
    assert_eq!(plan.constraint_count(), 6);
    let mut b = CircuitBuilder::<BabyBear>::new();
    let current_targets = (0..3).map(|_| extension_input(&mut b)).collect::<Vec<_>>();
    let next_targets = (0..2).map(|_| extension_input(&mut b)).collect::<Vec<_>>();
    let pp_targets = (0..2).map(|_| extension_input(&mut b)).collect::<Vec<_>>();
    let pp_next_targets = [extension_input(&mut b)];
    let public_targets = (0..2).map(|_| base_input(&mut b)).collect::<Vec<_>>();
    let point_targets = (0..3).map(|_| extension_input(&mut b)).collect::<Vec<_>>();
    let alpha_target = extension_input(&mut b);
    assert!(
        plan.evaluate(
            &mut b,
            &point_targets,
            &current_targets,
            &next_targets,
            &public_targets,
            &alpha_target
        )
        .is_err()
    );
    let actual = plan
        .evaluate_with_auxiliary(
            &mut b,
            &point_targets,
            &current_targets,
            &next_targets,
            &pp_targets,
            &pp_next_targets,
            &public_targets,
            &alpha_target,
        )
        .unwrap();
    let expected_target = extension_input(&mut b);
    for (a, e) in actual
        .coefficients()
        .iter()
        .zip(expected_target.coefficients())
    {
        for (&a, &e) in a.bits().iter().zip(e.bits()) {
            let difference = b.sub(a, e);
            b.assert_zero(difference);
        }
    }
    let circuit = b.build().unwrap();
    let mut values = current
        .into_iter()
        .chain([next[2], next[0]])
        .chain(pp)
        .chain([pp_next[1]])
        .flat_map(extension_limbs)
        .collect::<Vec<_>>();
    values.extend(public.into_iter().flat_map(base_limbs));
    values.extend(
        point
            .into_iter()
            .chain([alpha, expected])
            .flat_map(extension_limbs),
    );
    assert!(run(&circuit, &values));
    for index in [72, 92, 96, values.len() - 4] {
        let mut wrong = values.clone();
        wrong[index] += BabyBear::ONE;
        assert!(!run(&circuit, &wrong));
    }
    let mut changed = air;
    changed.period[1] += Poly64::ONE;
    assert_ne!(
        plan,
        BinaryPolyAirConstraintPlan::from_air(&changed, 3).unwrap()
    );
}

struct UnsupportedAir(u8);
impl BaseAir<Poly64> for UnsupportedAir {
    fn width(&self) -> usize {
        1
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn assumes_boolean_trace(&self) -> bool {
        self.0 == 2
    }
}
impl<AB> Air<AB> for UnsupportedAir
where
    AB: AirBuilder<F = Poly64> + BusInteractionBuilder + IndexedLookupBuilder,
{
    fn eval(&self, b: &mut AB) {
        let value = b.main().current_slice()[0];
        b.assert_zero(value);
        match self.0 {
            0 => b.push_bus_interaction(
                BusName::new("poly-bus"),
                BusDirection::Push,
                [value],
                BusActivation::Always,
            ),
            1 => b.push_indexed_read("poly-table", 0, [0]),
            _ => {}
        }
    }
}

#[test]
fn unsupported_reductions_are_rejected_during_trusted_poly_air_compilation() {
    for kind in 0..3 {
        assert!(matches!(
            BinaryPolyAirConstraintPlan::from_air(&UnsupportedAir(kind), 1),
            Err(VerificationError::InvalidProofShape(_))
        ));
    }
}
