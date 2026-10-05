//! Trusted auxiliary columns in the released binary multilinear AIR folder.

use std::borrow::Cow;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField8, BinaryField64, BinaryField128, TowerLevel};
use p3_circuit::ops::BinaryTower128Target;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing};
use p3_multi_stark::folder::MultilinearFolder;
use p3_multi_stark::selectors::BoundaryEvals;
use p3_recursion::pcs::binary::RecursiveBinaryTowerField;
use p3_recursion::verifier::{BinaryAirConstraintPlan, VerifierLimits};

struct AuxiliaryAir<F> {
    periods: Vec<Vec<F>>,
    next: Vec<usize>,
}
impl<F: Clone + Sync> BaseAir<F> for AuxiliaryAir<F> {
    fn width(&self) -> usize {
        1
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn preprocessed_width(&self) -> usize {
        3
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        self.next.clone()
    }
    fn num_periodic_columns(&self) -> usize {
        3
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<F>]> {
        Cow::Borrowed(&self.periods)
    }
}
impl<AB: AirBuilder> Air<AB> for AuxiliaryAir<AB::F> {
    fn eval(&self, b: &mut AB) {
        let main = b.main().current_slice()[0];
        let preprocessing = b.preprocessed();
        let current = preprocessing.current_slice();
        let next = preprocessing.next_slice();
        let periods = b.periodic_values();
        let (pre0, pre2, next0, next2) = (current[0], current[2], next[0], next[2]);
        let product: AB::Expr = periods[0].into() * periods[1].into();
        let periodic_last: AB::Expr = periods[2].into();
        let periodic_next: AB::Expr = periods[1].into();
        b.assert_eq(main, pre0.into() + product + periodic_last);
        b.when_transition().assert_eq(next2, pre0);
        b.when_transition()
            .assert_eq(next0, pre2.into() + periodic_next);
    }
}

#[test]
fn trusted_auxiliary_columns_are_accepted_by_the_binary_air_program() {
    type F = BinaryField128;
    let air = AuxiliaryAir {
        periods: vec![
            vec![F::from_repr(19)],
            vec![F::from_repr(37), F::from_repr(71)],
            vec![
                F::from_repr(11),
                F::from_repr(17),
                F::from_repr(23),
                F::from_repr(29),
            ],
        ],
        next: vec![2, 0],
    };
    let plan = BinaryAirConstraintPlan::<F>::from_air(&air, 3).unwrap();
    assert_eq!(plan.constraint_degree(), 2);
    assert_eq!(plan.constraint_count(), 3);
}

fn periods<F: RecursiveBinaryTowerField>() -> Vec<Vec<F>> {
    [vec![19u128], vec![37, 71], vec![11, 17, 23, 29]]
        .into_iter()
        .map(|values| {
            values
                .into_iter()
                .map(|raw| {
                    F::from_le_byte_iter(raw.to_le_bytes().into_iter().take(F::RAW_BITS / 8))
                })
                .collect()
        })
        .collect()
}

fn periodic_mle<F: Field, E: ExtensionField<F>>(values: &[F], point: &[E]) -> E {
    let arity = values.len().ilog2() as usize;
    let mut values: Vec<_> = values.iter().copied().map(E::from).collect();
    for &coordinate in point[point.len() - arity..].iter().rev() {
        values = values
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| pair[0] + coordinate * (pair[1] - pair[0]))
            .collect();
    }
    values[0]
}

fn input(b: &mut CircuitBuilder<BabyBear>) -> BinaryTower128Target {
    let limbs = b.alloc_private_input_array::<8>("binary auxiliary AIR comparison");
    let target = b.binary128_from_limbs::<BabyBear>(limbs).unwrap();
    let derived = b.binary128_to_limbs::<BabyBear>(&target).unwrap();
    b.binary128_from_limbs::<BabyBear>(derived).unwrap()
}

fn run(circuit: &Circuit<BabyBear>, values: &[BabyBear]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(values).unwrap();
    runner.run().is_ok()
}

macro_rules! compare {
    ($f:ty, $e:ty) => {{
        type F = $f;
        type E = $e;
        let air = AuxiliaryAir { periods: periods::<F>(), next: vec![2, 0] };
        let dense = |seed: u128| E::from_le_byte_iter(
            (0x8539_437b_215d_1351_5791_5317_4179_9133u128 ^ seed)
                .to_le_bytes().into_iter().take(E::RAW_BITS / 8),
        );
        let current = [dense(11)];
        let preprocessed = [dense(37), dense(71), dense(109)];
        let next = [dense(167), dense(233), dense(307)];
        let point = [dense(401), dense(503), dense(601)];
        let alpha = dense(733);
        let periodic_values: Vec<E> = air.periods.iter()
            .map(|period| periodic_mle::<F, E>(period, &point)).collect();
        let expected = MultilinearFolder::new(&current, &current, BoundaryEvals::at(&point), &[], alpha)
            .with_preprocessed(&preprocessed, &next)
            .with_periodic(&periodic_values).eval_air(&air);
        let plan = BinaryAirConstraintPlan::<F, E>::from_air(&air, 3).unwrap();
        assert_eq!(plan.preprocessed_width(), 3);
        assert_eq!(plan.preprocessed_next_columns(), [2, 0]);
        let mut changed_air = AuxiliaryAir { periods: periods::<F>(), next: vec![2, 0] };
        changed_air.periods[2][1] += F::ONE;
        assert_ne!(plan, BinaryAirConstraintPlan::<F, E>::from_air(&changed_air, 3).unwrap());
        let mut b = CircuitBuilder::<BabyBear>::new();
        let current_targets = [input(&mut b)];
        let preprocessed_targets: Vec<_> = (0..3).map(|_| input(&mut b)).collect();
        let next_targets: Vec<_> = (0..2).map(|_| input(&mut b)).collect();
        let point_targets: Vec<_> = (0..3).map(|_| input(&mut b)).collect();
        let alpha_target = input(&mut b);
        assert!(plan.evaluate(&mut b, &point_targets, &current_targets, &[], &[], &alpha_target).is_err());
        let output = plan.evaluate_with_auxiliary(
            &mut b, &point_targets, &current_targets, &[], &preprocessed_targets,
            &next_targets, &[], &alpha_target,
        ).unwrap();
        let expected_target = input(&mut b);
        for (&a, &e) in output.bits().iter().zip(expected_target.bits()) {
            let difference = b.sub(a, e);
            b.assert_zero(difference);
        }
        let circuit = b.build().unwrap();
        let values: Vec<_> = current.into_iter().chain(preprocessed)
            .chain([next[2], next[0]]).chain(point).chain([alpha, expected])
            .flat_map(|value| {
                let raw = value.raw_coordinates();
                (0..8).map(move |i| BabyBear::from_u16((raw >> (16 * i)) as u16))
            }).collect();
        let mut runner = circuit.runner();
        runner.set_private_inputs(&values).unwrap();
        runner.run().expect("native auxiliary AIR fold must match");
        for index in [8, 32, values.len() - 8] {
            let mut wrong = values.clone();
            wrong[index] += BabyBear::ONE;
            assert!(!run(&circuit, &wrong));
        }
        if E::RAW_BITS == 64 {
            let mut wrong = values.clone();
            wrong[12] = BabyBear::ONE;
            assert!(!run(&circuit, &wrong));
        }
        (circuit, values)
    }};
}

#[test]
fn periodic_suffixes_and_sparse_preprocessed_successors_match_native() {
    compare!(BinaryField128, BinaryField128);
    compare!(BinaryField8, BinaryField64);
}

#[test]
fn auxiliary_constants_and_declarations_are_bounded_before_compilation() {
    type F = BinaryField128;
    for bad in [vec![], vec![F::ONE; 3], vec![F::ONE; 16]] {
        let mut air = AuxiliaryAir {
            periods: periods::<F>(),
            next: vec![2, 0],
        };
        air.periods[0] = bad;
        assert!(BinaryAirConstraintPlan::<F>::from_air(&air, 3).is_err());
    }
    let mut air = AuxiliaryAir {
        periods: periods::<F>(),
        next: vec![2, 0],
    };
    air.periods.pop();
    assert!(BinaryAirConstraintPlan::<F>::from_air(&air, 3).is_err());
    for next in [vec![2, 2], vec![3], vec![0]] {
        let air = AuxiliaryAir {
            periods: periods::<F>(),
            next,
        };
        assert!(BinaryAirConstraintPlan::<F>::from_air(&air, 3).is_err());
    }
    let air = AuxiliaryAir {
        periods: periods::<F>(),
        next: vec![2, 0],
    };
    for limits in [
        VerifierLimits {
            max_matrix_width: 2,
            ..VerifierLimits::default()
        },
        VerifierLimits {
            max_metadata_entries: 20,
            ..VerifierLimits::default()
        },
    ] {
        assert!(BinaryAirConstraintPlan::<F>::with_limits(&air, 3, &limits).is_err());
    }
}

#[test]
fn auxiliary_air_arithmetic_proves_in_a_prime_field_circuit() {
    use p3_circuit_prover::batch_stark_prover::BatchStarkProver;
    use p3_circuit_prover::{ConstraintProfile, config};
    let (circuit, values) = compare!(BinaryField8, BinaryField64);
    let prover = BatchStarkProver::new(config::baby_bear());
    let prepared = prover
        .prepare_circuit::<BabyBear, 1>(&circuit, &[], &[], ConstraintProfile::Standard)
        .unwrap();
    let mut runner = circuit.runner();
    runner.set_private_inputs(&values).unwrap();
    let proof = prepared.prove(&runner.run().unwrap()).unwrap();
    prepared.verifier().verify(&proof, &[]).unwrap();
}
