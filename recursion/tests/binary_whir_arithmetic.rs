//! Released additive WHIR selectors, row folds and coefficient evaluations.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField32, BinaryField128, TowerLevel};
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::BinaryTower128Target;
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_recursion::pcs::binary::{
    binary_whir_query_point, binary128_eval_coefficients, binary128_eval_multilinear,
    binary128_select_eval,
};
use p3_sumcheck::constraints::statement::SelectStatement;
use p3_whir::{WhirDomain, WhirQueryPoint};

fn value(i: usize) -> BinaryField128 {
    BinaryField128::from_repr(0x598741ee35171f49a3781264456ba331u128.wrapping_mul(i as u128 + 1))
}

fn input(
    b: &mut CircuitBuilder<BabyBear>,
    values: &mut Vec<BabyBear>,
    v: BinaryField128,
) -> BinaryTower128Target {
    let limbs = b.alloc_private_input_array::<8>("binary WHIR value");
    values.extend((0..8).map(|i| BabyBear::from_u16((v.to_repr() >> (16 * i)) as u16)));
    b.binary128_from_limbs::<BabyBear>(limbs).unwrap()
}

fn bind(
    b: &mut CircuitBuilder<BabyBear>,
    values: &mut Vec<BabyBear>,
    actual: &BinaryTower128Target,
    v: BinaryField128,
) {
    let expected = input(b, values, v);
    for (&a, &e) in actual.bits().iter().zip(expected.bits()) {
        let difference = b.sub(a, e);
        b.assert_zero(difference);
    }
}

fn check(b: CircuitBuilder<BabyBear>, mut values: Vec<BabyBear>) {
    let circuit = b.build().unwrap();
    let mut runner = circuit.runner();
    runner.set_private_inputs(&values).unwrap();
    runner.run().unwrap();
    *values.last_mut().unwrap() += BabyBear::ONE;
    let mut runner = circuit.runner();
    runner.set_private_inputs(&values).unwrap();
    assert!(runner.run().is_err());
}

#[test]
fn direct_selector_and_coefficient_evaluation_match_native_statements() {
    for n in 0..=4 {
        let point = Point::new((0..n).map(value).collect());
        let row = Point::new((0..n).map(|i| value(13 + i)).collect());
        let coeffs = (0..1 << n).map(|i| value(29 + i)).collect::<Vec<_>>();
        let expected = coeffs
            .iter()
            .enumerate()
            .map(|(index, &c)| {
                let monomial: BinaryField128 = point
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| (index >> (n - 1 - i)) & 1 != 0)
                    .map(|(_, &r)| r)
                    .product();
                c * monomial
            })
            .sum();
        let mut statement = SelectStatement::<BinaryField128, BinaryField128>::initialize(n);
        statement.add_point_constraint(point.clone(), expected);
        assert!(statement.verify(&Poly::new(coeffs.clone())));
        let weight = statement.weights_at(&row).next().unwrap();
        let mut b = CircuitBuilder::<BabyBear>::new();
        let mut values = Vec::new();
        let p = point
            .iter()
            .map(|&v| input(&mut b, &mut values, v))
            .collect::<Vec<_>>();
        let r = row
            .iter()
            .map(|&v| input(&mut b, &mut values, v))
            .collect::<Vec<_>>();
        let c = coeffs
            .iter()
            .map(|&v| input(&mut b, &mut values, v))
            .collect::<Vec<_>>();
        let actual = binary128_select_eval(&mut b, &p, &r).unwrap();
        bind(&mut b, &mut values, &actual, weight);
        let actual = binary128_eval_coefficients(&mut b, &c, &p).unwrap();
        bind(&mut b, &mut values, &actual, expected);
        let actual = binary128_eval_multilinear(&mut b, &c, &p).unwrap();
        bind(
            &mut b,
            &mut values,
            &actual,
            Poly::new(coeffs).eval_ext::<BinaryField128>(&point),
        );
        check(b, values);
    }
}

macro_rules! query_points {
    ($f:ty, $width:expr) => {{
        type F = $f;
        let width = $width;
        let domain = BinaryWhirDomain::<F>::default();
        for index in [0usize, 1, 2, 7, (1usize << width) - 13] {
            for n in [0, 1, 4, width] {
                let WhirQueryPoint::Multilinear(point) =
                    <BinaryWhirDomain<F> as WhirDomain<F, BinaryField128>>::query_point(
                        &domain, width, n, index,
                    )
                else {
                    panic!("binary domain must return direct coordinates");
                };
                let mut b = CircuitBuilder::<BabyBear>::new();
                let mut values = Vec::new();
                let bits = (0..width)
                    .map(|i| {
                        values.push(BabyBear::from_bool((index >> i) & 1 != 0));
                        b.alloc_private_input("binary WHIR query bit")
                    })
                    .collect::<Vec<_>>();
                let actual = binary_whir_query_point::<F, BabyBear>(&mut b, &bits, n).unwrap();
                assert_eq!(actual.len(), n);
                for (a, &e) in actual.iter().zip(point.iter()) {
                    bind(
                        &mut b,
                        &mut values,
                        a,
                        BinaryField128::from_repr(e.to_repr() as u128),
                    );
                }
                if n == 0 {
                    let circuit = b.build().unwrap();
                    let mut runner = circuit.runner();
                    runner.set_private_inputs(&values).unwrap();
                    runner.run().unwrap();
                } else {
                    check(b, values);
                }
            }
        }
    }};
}

#[test]
fn shifted_cantor_coordinates_match_both_released_tower_domains() {
    query_points!(BinaryField128, 40);
    query_points!(BinaryField32, 31);
}

#[test]
fn malformed_evaluation_geometry_is_rejected() {
    let mut b = CircuitBuilder::<BabyBear>::new();
    let zero = b.binary128_constant(0).unwrap();
    assert!(binary128_eval_multilinear(&mut b, &[], &[]).is_err());
    assert!(
        binary128_eval_coefficients(&mut b, &vec![zero.clone(); 3], std::slice::from_ref(&zero))
            .is_err()
    );
    assert!(binary128_select_eval(&mut b, &[zero], &[]).is_err());
    assert!(
        binary_whir_query_point::<BinaryField32, BabyBear>(
            &mut b,
            &[p3_circuit::ExprId::ZERO; 33],
            1
        )
        .is_err()
    );
}

#[test]
fn empty_coordinate_points_enforce_boolean_ingress_in_the_proof() {
    use p3_circuit_prover::batch_stark_prover::BatchStarkProver;
    use p3_circuit_prover::{ConstraintProfile, config};
    let mut b = CircuitBuilder::<BabyBear>::new();
    let bit = b.alloc_private_input("query bit");
    binary_whir_query_point::<BinaryField128, BabyBear>(&mut b, &[bit], 0).unwrap();
    let circuit = b.build().unwrap();
    let prover = BatchStarkProver::new(config::baby_bear());
    let prepared = prover
        .prepare_circuit::<BabyBear, 1>(&circuit, &[], &[], ConstraintProfile::Standard)
        .unwrap();
    for (value, accepted) in [(BabyBear::ONE, true), (BabyBear::TWO, false)] {
        let mut runner = circuit.runner();
        runner.set_private_inputs(&[value]).unwrap();
        // BoolCheck is enforced by AIR; the runner only records its input.
        let proof = prepared.prove(&runner.run().unwrap()).unwrap();
        assert_eq!(prepared.verifier().verify(&proof, &[]).is_ok(), accepted);
    }
}
