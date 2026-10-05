//! Poly64 AIR folding with three native cells per Poly192 challenge.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::{Poly64, Poly192};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::NativePoly192Target;
use p3_field::PrimeCharacteristicRing;
use p3_multi_stark::folder::MultilinearFolder;
use p3_multi_stark::selectors::BoundaryEvals;
use p3_recursion::verifier::BinaryPolyAirConstraintPlan;

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
