//! Native differentials for binary multilinear weights, sumcheck, and folds.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryChallenger, BinaryField8, BinaryField128, TowerLevel};
use p3_binary_pcs::fold_pair;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::BinaryTower128Target;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_keccak::Keccak256Hash;
use p3_multilinear_util::point::Point;
use p3_recursion::pcs::binary::{
    binary128_eq_eval, binary128_fold_pair, binary128_next_eval, binary128_reduce_sumcheck_claim,
};
use p3_sumcheck::SumcheckData;
use p3_sumcheck::strategy::Basis;

const DENSE: u128 = 0x21bade026a6ae768f2ed66ffdcc99396;

fn value(seed: u128) -> BinaryField128 {
    BinaryField128::from_repr(DENSE.wrapping_mul(seed + 1))
}

fn input(
    builder: &mut CircuitBuilder<BabyBear>,
    values: &mut Vec<BabyBear>,
    value: BinaryField128,
) -> BinaryTower128Target {
    let limbs = builder.alloc_private_input_array::<8>("binary field coordinates");
    values.extend((0..8).map(|i| BabyBear::from_u16((value.to_repr() >> (16 * i)) as u16)));
    builder.binary128_from_limbs::<BabyBear>(limbs).unwrap()
}

fn check_output(
    mut builder: CircuitBuilder<BabyBear>,
    mut values: Vec<BabyBear>,
    actual: &BinaryTower128Target,
    expected: BinaryField128,
) {
    let independent = input(&mut builder, &mut values, expected);
    for (&actual, &expected) in actual.bits().iter().zip(independent.bits()) {
        let difference = builder.sub(actual, expected);
        builder.assert_zero(difference);
    }
    let circuit = builder.build().unwrap();
    let mut runner = circuit.runner();
    runner.set_private_inputs(&values).unwrap();
    runner.run().unwrap();
    let last = values.last_mut().unwrap();
    *last = BabyBear::from_u64(last.as_canonical_u64() ^ 1);
    let mut runner = circuit.runner();
    runner.set_private_inputs(&values).unwrap();
    assert!(runner.run().is_err());
}

#[test]
fn equality_and_repeat_last_successor_weights_match_native() {
    for n in 0..=4 {
        for successor in [false, true] {
            let point: Vec<_> = (0..n).map(|i| value(i as u128)).collect();
            let row: Vec<_> = (0..n).map(|i| value(17 + i as u128)).collect();
            let mut builder = CircuitBuilder::<BabyBear>::new();
            let mut values = Vec::new();
            let point_targets: Vec<_> = point
                .iter()
                .map(|&x| input(&mut builder, &mut values, x))
                .collect();
            let row_targets: Vec<_> = row
                .iter()
                .map(|&x| input(&mut builder, &mut values, x))
                .collect();
            let (actual, expected) = if successor {
                let (_, done, omega) = Point::eval_next(&point, &row);
                (
                    binary128_next_eval(&mut builder, &point_targets, &row_targets).unwrap(),
                    done + omega,
                )
            } else {
                (
                    binary128_eq_eval(&mut builder, &point_targets, &row_targets).unwrap(),
                    Point::eval_eq(&point, &row),
                )
            };
            check_output(builder, values, &actual, expected);
        }
    }
}

#[test]
fn compact_quadratic_claim_reduction_matches_native_rounds() {
    let mut challenger =
        BinaryChallenger::<BinaryField128, _>::from_hasher(vec![3, 1, 4, 1, 5], Keccak256Hash);
    let mut native_claim = value(21);
    for round in 0..3 {
        let before = native_claim;
        let h0 = value(3 * round);
        let hinf = value(3 * round + 1);
        let data = SumcheckData::<BinaryField128, BinaryField128> {
            polynomial_evaluations: vec![[h0, hinf]],
            pow_witnesses: Vec::new(),
        };
        let beta = data
            .verify_rounds(&mut challenger, &mut native_claim, 1, 0, Basis::Evaluation)
            .unwrap()
            .as_slice()[0];
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let mut values = Vec::new();
        let claim = input(&mut builder, &mut values, before);
        let h0 = input(&mut builder, &mut values, h0);
        let hinf = input(&mut builder, &mut values, hinf);
        let beta = input(&mut builder, &mut values, beta);
        let actual =
            binary128_reduce_sumcheck_claim(&mut builder, &claim, &h0, &hinf, &beta).unwrap();
        check_output(builder, values, &actual, native_claim);
    }
}

#[test]
fn cantor_pair_folds_match_native_with_variable_indices() {
    let width = (usize::BITS as usize - 1).min(40);
    for index in [0, 1, 2, 17, 127, (1usize << width) - 3] {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let mut values = Vec::new();
        let beta = value(3);
        let lo = value(11);
        let hi = value(19);
        let beta_target = input(&mut builder, &mut values, beta);
        let lo_target = input(&mut builder, &mut values, lo);
        let hi_target = input(&mut builder, &mut values, hi);
        let bits: Vec<_> = (0..width)
            .map(|bit| {
                values.push(BabyBear::from_bool(index >> bit & 1 == 1));
                builder.alloc_private_input("query index bit")
            })
            .collect();
        let actual =
            binary128_fold_pair(&mut builder, &bits, &beta_target, &lo_target, &hi_target).unwrap();
        check_output(builder, values, &actual, fold_pair(index, beta, lo, hi));
    }
}

#[test]
fn narrow_alphabet_fold_widens_in_the_native_tower_basis() {
    let lo = BinaryField8::from_repr(0x93);
    let hi = BinaryField8::from_repr(0xe7);
    let beta = value(29);
    let index = 17;
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let mut values = Vec::new();
    let lo_target = input(
        &mut builder,
        &mut values,
        BinaryField128::from_repr(lo.to_repr() as u128),
    );
    let hi_target = input(
        &mut builder,
        &mut values,
        BinaryField128::from_repr(hi.to_repr() as u128),
    );
    let beta_target = input(&mut builder, &mut values, beta);
    let bits: Vec<_> = (0..6)
        .map(|bit| {
            values.push(BabyBear::from_bool(index >> bit & 1 == 1));
            builder.alloc_private_input("query index bit")
        })
        .collect();
    let actual =
        binary128_fold_pair(&mut builder, &bits, &beta_target, &lo_target, &hi_target).unwrap();
    check_output(builder, values, &actual, fold_pair(index, beta, lo, hi));
}
