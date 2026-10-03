//! Native binary AIR folding, boundary pins, successor order and admission.

use std::borrow::Cow;

use p3_air::boundary::{BoundaryEnd, BoundaryPublic};
use p3_air::{Air, AirBuilder, BaseAir, ExtensionBuilder, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField8, BinaryField64, BinaryField128, TowerLevel};
use p3_bus::{BusActivation, BusDirection, BusInteractionBuilder, BusName};
use p3_circuit::ops::BinaryTower128Target;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, IndexedLookupBuilder, InteractionBuilder, TraceWindow};
use p3_multi_stark::folder::MultilinearFolder;
use p3_multi_stark::selectors::BoundaryEvals;
use p3_recursion::verifier::{BinaryAirConstraintPlan, VerificationError, VerifierLimits};

#[derive(Clone)]
struct RecurrenceAir;
impl<F> BaseAir<F> for RecurrenceAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        3
    }
}
impl<AB: AirBuilder> Air<AB> for RecurrenceAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let current = main.current_slice();
        let next = main.next_slice();
        let public = b.public_values();
        let (a, c, output) = (public[0], public[1], public[2]);
        b.when_first_row().assert_eq(current[0], a);
        b.when_first_row().assert_eq(current[1], c);
        b.when_transition().assert_eq(next[0], current[1]);
        b.when_transition()
            .assert_eq(next[1], current[0] * current[1] + current[0]);
        b.when_last_row().assert_eq(current[1], output);
    }
}

fn input(b: &mut CircuitBuilder<BabyBear>) -> BinaryTower128Target {
    let limbs = b.alloc_private_input_array::<8>("binary AIR comparison");
    let value = b.binary128_from_limbs::<BabyBear>(limbs).unwrap();
    let derived_limbs = b.binary128_to_limbs::<BabyBear>(&value).unwrap();
    b.binary128_from_limbs::<BabyBear>(derived_limbs).unwrap()
}
fn raw_inputs(raw: u128) -> impl Iterator<Item = BabyBear> {
    (0..8).map(move |i| BabyBear::from_u16((raw >> (16 * i)) as u16))
}
fn run(circuit: &Circuit<BabyBear>, values: &[BabyBear]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(values).unwrap();
    runner.run().is_ok()
}

macro_rules! compare {
    ($air:expr, $f:ty, $e:ty, $height:expr, $current:expr, $next:expr, $public:expr, $point:expr, $alpha:expr) => {{
        type NativeAirBase = $f;
        type NativeAirChallenge = $e;
        let air = $air;
        let current: Vec<NativeAirChallenge> = $current;
        let next: Vec<NativeAirChallenge> = $next;
        let public: Vec<NativeAirBase> = $public;
        let point: Vec<NativeAirChallenge> = $point;
        let alpha: NativeAirChallenge = $alpha;
        let plan = BinaryAirConstraintPlan::<NativeAirBase, NativeAirChallenge>::from_air(&air, $height).unwrap();
        let native = MultilinearFolder::new(
            &current, &next, BoundaryEvals::at(&point), &public, alpha,
        ).eval_air(&air);
        let mut b = CircuitBuilder::<BabyBear>::new();
        let current_targets = (0..current.len()).map(|_| input(&mut b)).collect::<Vec<_>>();
        let next_targets = (0..plan.next_columns().len()).map(|_| input(&mut b)).collect::<Vec<_>>();
        let public_targets = (0..public.len()).map(|_| input(&mut b)).collect::<Vec<_>>();
        let point_targets = (0..point.len()).map(|_| input(&mut b)).collect::<Vec<_>>();
        let alpha_target = input(&mut b);
        let output = plan.evaluate(
            &mut b, &point_targets, &current_targets, &next_targets, &public_targets, &alpha_target,
        ).unwrap();
        let expected = input(&mut b);
        for (&a, &e) in output.bits().iter().zip(expected.bits()) {
            let diff = b.sub(a, e);
            b.assert_zero(diff);
        }
        let circuit = b.build().unwrap();
        let mut values = Vec::new();
        for &v in &current { values.extend(raw_inputs(v.to_repr() as u128)); }
        for &column in plan.next_columns() { values.extend(raw_inputs(next[column].to_repr() as u128)); }
        for &v in &public { values.extend(raw_inputs(v.to_repr() as u128)); }
        for &v in &point { values.extend(raw_inputs(v.to_repr() as u128)); }
        values.extend(raw_inputs(alpha.to_repr() as u128));
        values.extend(raw_inputs(native.to_repr() as u128));
        let mut runner = circuit.runner();
        runner.set_private_inputs(&values).unwrap();
        runner.run().expect("native binary AIR evaluation must match");
        let mut wrong = values.clone();
        let last = wrong.len() - 8;
        wrong[last] += BabyBear::ONE;
        assert!(!run(&circuit, &wrong));
        (plan, circuit, values)
    }};
}

#[test]
fn recurrence_constraints_match_native_at_dense_tower_points() {
    type E = BinaryField128;
    let dense = |i: u128| E::from_repr(0x1917_a591_b613_85e7_4371_49af_310d_ace3 ^ i);
    let (plan, _, _) = compare!(
        RecurrenceAir,
        E,
        E,
        2,
        vec![dense(3), dense(7)],
        vec![dense(11), dense(19)],
        vec![dense(29), dense(37), dense(47)],
        vec![dense(53), dense(61)],
        dense(71)
    );
    assert_eq!(plan.constraint_degree(), 3);
    assert_eq!(plan.constraint_count(), 5);
    assert_eq!(plan.next_columns(), [0, 1]);
    let (circuit, values) = narrow_recurrence();
    let mut wrong = values.clone();
    wrong[4] = BabyBear::ONE; // An E64 opening cannot carry an upper coordinate.
    assert!(!run(&circuit, &wrong));
    let mut wrong = values;
    wrong[32] = BabyBear::from_u16(256); // First public value must remain F8.
    assert!(!run(&circuit, &wrong));
}

fn narrow_recurrence() -> (Circuit<BabyBear>, Vec<BabyBear>) {
    let (_, circuit, values) = compare!(
        RecurrenceAir,
        BinaryField8,
        BinaryField64,
        1,
        vec![
            BinaryField64::from_repr(0xc751_41bd_973b_6951),
            BinaryField64::from_repr(0x91bd_8355_1539_ab73)
        ],
        vec![
            BinaryField64::from_repr(0x593d_b73d_9139_4521),
            BinaryField64::from_repr(0x237b_7739_4955_9133)
        ],
        vec![
            BinaryField8::from_repr(11),
            BinaryField8::from_repr(19),
            BinaryField8::from_repr(37)
        ],
        vec![BinaryField64::from_repr(0x794b_d551_353d_c379)],
        BinaryField64::from_repr(0x8539_437b_215d_1351)
    );
    (circuit, values)
}

struct PinnedSparseAir;
impl<F> BaseAir<F> for PinnedSparseAir {
    fn width(&self) -> usize {
        3
    }
    fn num_public_values(&self) -> usize {
        2
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![2, 0]
    }
    fn public_boundary_io(&self) -> &[BoundaryPublic] {
        const PINS: [BoundaryPublic; 2] = [
            BoundaryPublic::new(2, BoundaryEnd::Last, 0),
            BoundaryPublic::new(0, BoundaryEnd::First, 1),
        ];
        &PINS
    }
}
impl<AB: AirBuilder> Air<AB> for PinnedSparseAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        b.assert_eq(main.next_slice()[2], main.current_slice()[0]);
        b.assert_eq(main.next_slice()[0], main.current_slice()[1]);
    }
}

#[test]
fn public_pins_follow_assertions_and_sparse_next_columns_keep_their_order() {
    type E = BinaryField128;
    let v = |i: u128| E::from_repr(0xf39b_238d_5517_8721_4d79_39b5_59d7_154b ^ i);
    let (plan, _, _) = compare!(
        PinnedSparseAir,
        E,
        E,
        2,
        vec![v(3), v(5), v(7)],
        vec![v(11), v(13), v(17)],
        vec![v(19), v(23)],
        vec![v(29), v(31)],
        v(37)
    );
    assert_eq!(plan.constraint_count(), 4);
    assert_eq!(plan.constraint_degree(), 2);
    assert_eq!(plan.next_columns(), [2, 0]);
}

struct SharedAir;
impl<F> BaseAir<F> for SharedAir {
    fn width(&self) -> usize {
        1
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}
impl<AB: AirBuilder> Air<AB> for SharedAir {
    fn eval(&self, b: &mut AB) {
        let mut shared: AB::Expr = b.main().current_slice()[0].into();
        for _ in 0..24 {
            shared = shared.clone() + shared;
        }
        b.assert_zero(shared);
    }
}

struct PinOnlyAir;
impl<F> BaseAir<F> for PinOnlyAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        Some(usize::MAX)
    }
    fn public_boundary_io(&self) -> &[BoundaryPublic] {
        const PINS: [BoundaryPublic; 1] = [BoundaryPublic::new(0, BoundaryEnd::First, 0)];
        &PINS
    }
}
impl<AB: AirBuilder> Air<AB> for PinOnlyAir {
    fn eval(&self, _: &mut AB) {}
}

#[test]
fn shared_subexpressions_stay_bounded_and_pin_only_hints_match_native() {
    let limits = VerifierLimits {
        max_metadata_entries: 128,
        ..VerifierLimits::default()
    };
    let shared =
        BinaryAirConstraintPlan::<BinaryField128>::with_limits(&SharedAir, 1, &limits).unwrap();
    assert!(shared.input_resource_usage().metadata_entries < 128);
    assert_eq!(shared.constraint_degree(), 1);
    type E = BinaryField128;
    let v = |i: u128| E::from_repr(0xa731_3dc5_b573_d917_5b49_593d_559b_c737 ^ i);
    compare!(
        SharedAir,
        E,
        E,
        1,
        vec![v(3)],
        vec![E::ZERO],
        vec![],
        vec![v(5)],
        v(7)
    );
    let (plan, _, _) = compare!(
        PinOnlyAir,
        E,
        E,
        0,
        vec![v(11)],
        vec![E::ZERO],
        vec![v(13)],
        vec![],
        v(17)
    );
    assert_eq!(plan.constraint_degree(), 2);
    assert_eq!(plan.constraint_count(), 1);
}

#[test]
fn compiled_constraints_prove_over_a_prime_field() {
    use p3_circuit_prover::batch_stark_prover::BatchStarkProver;
    use p3_circuit_prover::{ConstraintProfile, config};
    type E = BinaryField128;
    let v = |i: u128| E::from_repr(0x1da7_9bc5_5d47_3bc5_a179_79ad_39b1_4917 ^ i);
    let (_, circuit, values) = compare!(
        RecurrenceAir,
        E,
        E,
        1,
        vec![v(3), v(5)],
        vec![v(7), v(11)],
        vec![v(13), v(17), v(19)],
        vec![v(23)],
        v(29)
    );
    for (circuit, values) in [(circuit, values), narrow_recurrence()] {
        let prover = BatchStarkProver::new(config::baby_bear());
        let prepared = prover
            .prepare_circuit::<BabyBear, 1>(&circuit, &[], &[], ConstraintProfile::Standard)
            .unwrap();
        let mut runner = circuit.runner();
        runner.set_private_inputs(&values).unwrap();
        let proof = prepared.prove(&runner.run().unwrap()).unwrap();
        prepared.verifier().verify(&proof, &[]).unwrap();
    }
}

#[derive(Clone, Copy)]
enum Unsupported {
    MissingNext,
    DuplicateNext,
    OutOfRangeNext,
    Preprocessed,
    Periodic,
    Boolean,
    BadPin,
    Empty,
    Constant,
}
struct UnsupportedAir(Unsupported);
impl<F: Field> BaseAir<F> for UnsupportedAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn preprocessed_width(&self) -> usize {
        usize::from(matches!(self.0, Unsupported::Preprocessed))
    }
    fn num_periodic_columns(&self) -> usize {
        usize::from(matches!(self.0, Unsupported::Periodic))
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<F>]> {
        if matches!(self.0, Unsupported::Periodic) {
            Cow::Owned(vec![vec![F::ONE]])
        } else {
            Cow::Borrowed(&[])
        }
    }
    fn assumes_boolean_trace(&self) -> bool {
        matches!(self.0, Unsupported::Boolean)
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        match self.0 {
            Unsupported::MissingNext => vec![1],
            Unsupported::DuplicateNext => vec![0, 0],
            Unsupported::OutOfRangeNext => vec![2],
            _ => vec![0, 1],
        }
    }
    fn public_boundary_io(&self) -> &[BoundaryPublic] {
        const BAD: [BoundaryPublic; 1] = [BoundaryPublic::new(2, BoundaryEnd::First, 0)];
        if matches!(self.0, Unsupported::BadPin) {
            &BAD
        } else {
            &[]
        }
    }
}
impl<AB: AirBuilder> Air<AB> for UnsupportedAir
where
    AB::F: Field,
{
    fn eval(&self, b: &mut AB) {
        if matches!(self.0, Unsupported::Empty) {
            return;
        }
        if matches!(self.0, Unsupported::Constant) {
            b.assert_zero(AB::F::ONE);
            return;
        }
        let main = b.main();
        b.assert_eq(main.next_slice()[0], main.current_slice()[1]);
    }
}

struct BusAir;
impl<F> BaseAir<F> for BusAir {
    fn width(&self) -> usize {
        1
    }
}
impl<AB: BusInteractionBuilder> Air<AB> for BusAir {
    fn eval(&self, b: &mut AB) {
        let v = b.main().current_slice()[0];
        b.assert_zero(v);
        b.push_bus_interaction(
            BusName::new("native-bus"),
            BusDirection::Push,
            [v],
            BusActivation::Always,
        );
    }
}
struct LookupAir;
impl<F> BaseAir<F> for LookupAir {
    fn width(&self) -> usize {
        1
    }
}

struct LocalLookupAir;
impl<F> BaseAir<F> for LocalLookupAir {
    fn width(&self) -> usize {
        1
    }
}
impl<AB: InteractionBuilder> Air<AB> for LocalLookupAir {
    fn eval(&self, b: &mut AB) {
        let v = b.main().current_slice()[0];
        b.assert_zero(v);
        b.push_local_interaction([(vec![v.into()], Count::from(1))]);
    }
}
struct ExclusiveLookupAir;
impl<F> BaseAir<F> for ExclusiveLookupAir {
    fn width(&self) -> usize {
        1
    }
}
impl<AB: InteractionBuilder> Air<AB> for ExclusiveLookupAir {
    fn eval(&self, b: &mut AB) {
        let v = b.main().current_slice()[0];
        b.assert_zero(v);
        b.push_exclusive_interaction("lookup", [(v.into(), Count::from(1), vec![v.into()])]);
    }
}
struct IndexedAir(bool);
impl<F> BaseAir<F> for IndexedAir {
    fn width(&self) -> usize {
        1
    }
}
impl<AB: IndexedLookupBuilder> Air<AB> for IndexedAir {
    fn eval(&self, b: &mut AB) {
        let v = b.main().current_slice()[0];
        b.assert_zero(v);
        if self.0 {
            b.push_indexed_read("table", 0, [0]);
        } else {
            b.push_indexed_table("table", TraceWindow::Main, [0]);
        }
    }
}
impl<AB: InteractionBuilder> Air<AB> for LookupAir {
    fn eval(&self, b: &mut AB) {
        let v = b.main().current_slice()[0];
        b.assert_zero(v);
        b.push_interaction("lookup", [v], Count::from(1));
    }
}
struct ExtensionAir;
impl<F> BaseAir<F> for ExtensionAir {
    fn width(&self) -> usize {
        1
    }
}
impl<AB: ExtensionBuilder> Air<AB> for ExtensionAir {
    fn eval(&self, b: &mut AB) {
        let v = b.main().current_slice()[0];
        b.assert_zero(v);
        b.assert_zero_ext(AB::EF::ONE);
    }
}

#[test]
fn unsupported_obligations_and_invalid_declarations_are_rejected() {
    for kind in [
        Unsupported::MissingNext,
        Unsupported::DuplicateNext,
        Unsupported::OutOfRangeNext,
        Unsupported::Boolean,
        Unsupported::BadPin,
        Unsupported::Empty,
        Unsupported::Constant,
    ] {
        assert!(
            BinaryAirConstraintPlan::<BinaryField128>::from_air(&UnsupportedAir(kind), 1).is_err()
        );
    }
    for kind in [Unsupported::Preprocessed, Unsupported::Periodic] {
        assert!(
            BinaryAirConstraintPlan::<BinaryField128>::from_air(&UnsupportedAir(kind), 1).is_ok()
        );
    }
    assert!(BinaryAirConstraintPlan::<BinaryField128>::from_air(&BusAir, 1).is_err());
    assert!(BinaryAirConstraintPlan::<BinaryField128>::from_air(&LookupAir, 1).is_err());
    assert!(BinaryAirConstraintPlan::<BinaryField128>::from_air(&LocalLookupAir, 1).is_err());
    assert!(BinaryAirConstraintPlan::<BinaryField128>::from_air(&ExclusiveLookupAir, 1).is_err());
    assert!(BinaryAirConstraintPlan::<BinaryField128>::from_air(&IndexedAir(true), 1).is_err());
    assert!(BinaryAirConstraintPlan::<BinaryField128>::from_air(&IndexedAir(false), 1).is_err());
    assert!(BinaryAirConstraintPlan::<BinaryField128>::from_air(&ExtensionAir, 1).is_err());
}

#[test]
fn trusted_geometry_metadata_and_degree_are_bounded() {
    assert!(BinaryAirConstraintPlan::<BinaryField128>::from_air(&RecurrenceAir, 33).is_err());
    let limits = VerifierLimits {
        max_matrix_width: 1,
        ..VerifierLimits::default()
    };
    assert!(
        BinaryAirConstraintPlan::<BinaryField128>::with_limits(&RecurrenceAir, 1, &limits).is_err()
    );
    let limits = VerifierLimits {
        max_metadata_entries: 6,
        ..VerifierLimits::default()
    };
    assert!(matches!(
        BinaryAirConstraintPlan::<BinaryField128>::with_limits(&RecurrenceAir, 1, &limits),
        Err(VerificationError::ResourceLimitExceeded {
            component: "metadata entries",
            ..
        })
    ));
    let limits = VerifierLimits {
        max_log_domain_or_degree: 2,
        ..VerifierLimits::default()
    };
    assert!(
        BinaryAirConstraintPlan::<BinaryField128>::with_limits(&RecurrenceAir, 1, &limits).is_err()
    );
}
