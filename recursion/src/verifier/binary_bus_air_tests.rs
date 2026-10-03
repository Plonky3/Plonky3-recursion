use super::*;
use alloc::borrow::Cow;
use alloc::vec;
use p3_air::{AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::TowerLevel;
use p3_bus::{BusActivation, BusDirection, BusInteractionBuilder, BusName, BusPlan, BusPlanInput};
use p3_field::PrimeCharacteristicRing;

#[derive(Clone, Copy)]
struct BusAir;
impl<F> BaseAir<F> for BusAir {
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
        Vec::new()
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        Vec::new()
    }
}
impl<AB: AirBuilder + BusInteractionBuilder> Air<AB> for BusAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let [x, selected] = [main.current_slice()[0], main.current_slice()[1]];
        let pre: AB::Expr = b.preprocessed().current_slice()[0].into();
        let public: AB::Expr = b.public_values()[0].into();
        b.when_first_row().assert_eq(x, public.clone());
        for direction in BusDirection::ALL {
            b.push_bus_interaction(
                BusName::new("events"),
                direction,
                [x * x, pre.clone() + public.clone()],
                BusActivation::Boolean(selected.into()),
            );
        }
    }
}

#[test]
fn bus_payloads_share_the_air_program_without_repeating_boolean_constraints() {
    type F = BinaryField128;
    let limits = VerifierLimits::default();
    assert!(BinaryAirConstraintPlan::<F>::from_air(&BusAir, 2).is_err());
    let (plan, interactions) =
        BinaryAirConstraintPlan::<F>::with_bus_limits(&BusAir, 2, &limits).unwrap();
    assert_eq!(plan.constraint_count(), 3);
    assert_eq!(plan.bus_declarations().len(), 2);
    assert_eq!(plan.bus_declarations()[0].factor_degree, 3);
    let native_plan = BusPlan::build(&[BusPlanInput {
        log_height: 2,
        interactions: &interactions,
    }])
    .unwrap()
    .unwrap();
    assert_eq!(native_plan.fingerprint_width(), 4);
    let mut b = CircuitBuilder::<BabyBear>::new();
    let mut field = || {
        let limbs = b.alloc_private_input_array::<8>("bus AIR comparison");
        b.binary128_from_limbs::<BabyBear>(limbs).unwrap()
    };
    let point = vec![field(), field()];
    let current = vec![field(), field()];
    let preprocessed = vec![field()];
    let public = vec![field()];
    let alpha = field();
    let result = plan
        .evaluate_with_bus(
            &mut b,
            &point,
            &current,
            &[],
            &preprocessed,
            &[],
            &public,
            &alpha,
        )
        .unwrap();
    for value in core::iter::once(&result.folded)
        .chain(result.bus_fields.iter().flatten())
        .chain(result.bus_activations.iter().flatten())
    {
        let limbs = b.alloc_private_input_array::<8>("expected bus AIR value");
        let expected = b.binary128_from_limbs::<BabyBear>(limbs).unwrap();
        for (&actual, &expected) in value.bits().iter().zip(expected.bits()) {
            let difference = b.sub(actual, expected);
            b.assert_zero(difference);
        }
    }
    let circuit = b.build().unwrap();
    let dense = |n| F::from_repr(0x783920571fd326a958c94327af63de81u128.wrapping_mul(n));
    for seed in [2u128, 19] {
        let input: Vec<_> = (seed..seed + 7).map(dense).collect();
        let [r0, r1, x, selected, pre, public, alpha]: [F; 7] = input.clone().try_into().unwrap();
        let boolean = selected * (selected + F::ONE);
        let first = (F::ONE + r0) * (F::ONE + r1) * (x + public);
        let folded = (first * alpha + boolean) * alpha + boolean;
        let mut values = input;
        values.extend([
            folded,
            x * x,
            pre + public,
            x * x,
            pre + public,
            selected,
            selected,
        ]);
        let limbs: Vec<_> = values
            .iter()
            .flat_map(|value| {
                let raw = value.to_repr();
                (0..8).map(move |i| BabyBear::from_u16((raw >> (16 * i)) as u16))
            })
            .collect();
        let mut runner = circuit.runner();
        runner.set_private_inputs(&limbs).unwrap();
        runner.run().unwrap();
        let mut wrong = limbs;
        wrong[7 * 8] += BabyBear::ONE;
        let mut runner = circuit.runner();
        runner.set_private_inputs(&wrong).unwrap();
        assert!(runner.run().is_err());
    }
}

#[derive(Clone, Copy)]
struct PeriodicBusAir;
impl<F: PrimeCharacteristicRing> BaseAir<F> for PeriodicBusAir {
    fn width(&self) -> usize {
        1
    }
    fn num_periodic_columns(&self) -> usize {
        1
    }
    fn periodic_columns(&self) -> Cow<'_, [Vec<F>]> {
        Cow::Owned(vec![vec![F::ONE]])
    }
}
impl<AB: AirBuilder + BusInteractionBuilder> Air<AB> for PeriodicBusAir {
    fn eval(&self, b: &mut AB) {
        let periodic = b.periodic_values()[0].clone();
        // Compile this root first as an ordinary constraint, then reuse it in
        // the declaration: pointer memoization must not bypass access checks.
        b.assert_zero(periodic.clone());
        b.push_bus_interaction(
            BusName::new("events"),
            BusDirection::Push,
            [periodic],
            BusActivation::Boolean(b.main().current_slice()[0].into()),
        );
    }
}

#[test]
fn unsupported_bus_accesses_and_retained_metadata_are_bounded() {
    assert!(
        BinaryAirConstraintPlan::<BinaryField128>::with_bus_limits(
            &PeriodicBusAir,
            2,
            &VerifierLimits::default()
        )
        .is_err()
    );
    let limits = VerifierLimits {
        max_metadata_string_bytes: 5,
        ..VerifierLimits::default()
    };
    assert!(
        BinaryAirConstraintPlan::<BinaryField128>::with_bus_limits(&BusAir, 2, &limits).is_err()
    );
}
