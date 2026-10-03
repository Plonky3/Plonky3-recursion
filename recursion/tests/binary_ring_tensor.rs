//! Native tensor differentials for Boolean ring-switch arithmetic.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField64, BinaryField128, TowerLevel};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::BinaryTower128Target;
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::poly::Poly;
use p3_recursion::pcs::binary::{
    BinaryTowerTensorTarget, RecursiveBinaryChallengeField, binary_tensor_closing_weight,
};
use p3_sumcheck::ring_switch::bits::BitTensor;

fn input<E: RecursiveBinaryChallengeField>(
    builder: &mut CircuitBuilder<BabyBear>,
    values: &mut Vec<BabyBear>,
    value: E,
) -> BinaryTower128Target {
    let limbs = builder.alloc_private_input_array::<8>("tensor coordinates");
    values.extend((0..8).map(|i| BabyBear::from_u16((value.raw_coordinates() >> (16 * i)) as u16)));
    builder.binary128_from_limbs::<BabyBear>(limbs).unwrap()
}

fn check<E: RecursiveBinaryChallengeField>(
    mut builder: CircuitBuilder<BabyBear>,
    mut values: Vec<BabyBear>,
    actual: &BinaryTower128Target,
    expected: E,
    narrow_fields: &[usize],
) {
    let expected = input(&mut builder, &mut values, expected);
    for (&a, &b) in actual.bits().iter().zip(expected.bits()) {
        let difference = builder.sub(a, b);
        builder.assert_zero(difference);
    }
    let circuit = builder.build().unwrap();
    let mut runner = circuit.runner();
    runner.set_private_inputs(&values).unwrap();
    runner.run().unwrap();
    if E::RAW_BITS == 64 {
        for &field in narrow_fields {
            let mut wide = values.clone();
            wide[8 * field + 4] += BabyBear::ONE;
            let mut runner = circuit.runner();
            runner.set_private_inputs(&wide).unwrap();
            assert!(
                runner.run().is_err(),
                "upper native coordinates must be zero"
            );
        }
    }
    let last_field = values.len() - 8;
    values[last_field] += BabyBear::ONE;
    let mut runner = circuit.runner();
    runner.set_private_inputs(&values).unwrap();
    assert!(runner.run().is_err());
}

fn readings<E: RecursiveBinaryChallengeField>(rows: Vec<E>, low: Vec<E>) {
    let native = BitTensor::<E>::try_from(rows.clone()).unwrap();
    let weights = Poly::new_from_point(&low, E::ONE);
    let expected = native
        .columns()
        .iter()
        .zip(weights.as_slice())
        .map(|(&a, &b)| a * b)
        .sum::<E>();
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let mut values = Vec::new();
    let rows = rows
        .into_iter()
        .map(|x| input(&mut builder, &mut values, x))
        .collect();
    let tensor = BinaryTowerTensorTarget::<E>::from_rows(&mut builder, rows).unwrap();
    let point = low
        .into_iter()
        .map(|x| input(&mut builder, &mut values, x))
        .collect::<Vec<_>>();
    let actual = tensor
        .transpose(&mut builder)
        .unwrap()
        .evaluate_rows(&mut builder, &point)
        .unwrap();
    check(builder, values, &actual, expected, &[0, E::RAW_BITS]);
}

fn closing<E: RecursiveBinaryChallengeField>(
    high: Vec<E>,
    other: Vec<E>,
    batch: Vec<E>,
    successor: Option<(usize, E)>,
) {
    let mut narrow_fields = vec![0, high.len(), high.len() + other.len()];
    if successor.is_some() {
        narrow_fields.push(high.len() + other.len() + batch.len());
    }
    let mut tensor = BitTensor::<E>::one();
    for (&a, &b) in high.iter().zip(&other) {
        tensor.mul_equality_factor(a, b);
    }
    if let Some((kept, alpha)) = successor {
        let selector = high.len() - kept;
        let mut carry = BitTensor::successor_element(&high[selector..], &other[selector..]);
        let mut last = BitTensor::exterior_product(
            high[selector..].iter().copied().product(),
            other[selector..].iter().copied().product(),
        );
        for (&a, &b) in high[..selector].iter().zip(&other[..selector]) {
            carry.mul_equality_factor(a, b);
            last.mul_equality_factor(a, b);
        }
        carry.scale_rows(alpha);
        last.scale_rows(alpha * alpha);
        tensor += carry;
        tensor += last;
    }
    let weights = Poly::new_from_point(&batch, E::ONE);
    let expected = tensor
        .rows()
        .iter()
        .zip(weights.as_slice())
        .map(|(&a, &b)| a * b)
        .sum::<E>();
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let mut values = Vec::new();
    let high = high
        .into_iter()
        .map(|x| input(&mut builder, &mut values, x))
        .collect::<Vec<_>>();
    let other = other
        .into_iter()
        .map(|x| input(&mut builder, &mut values, x))
        .collect::<Vec<_>>();
    let batch = batch
        .into_iter()
        .map(|x| input(&mut builder, &mut values, x))
        .collect::<Vec<_>>();
    let alpha = successor.map(|(kept, alpha)| (kept, input(&mut builder, &mut values, alpha)));
    let actual = binary_tensor_closing_weight::<E, BabyBear>(
        &mut builder,
        &high,
        &other,
        &batch,
        alpha.as_ref().map(|(kept, alpha)| (*kept, alpha)),
    )
    .unwrap();
    check(builder, values, &actual, expected, &narrow_fields);
}

#[test]
fn row_reading_and_bit_transpose_match_native_at_both_challenge_widths() {
    readings(
        (0..128)
            .map(|i| {
                BinaryField128::from_repr(
                    0x21bade026a6ae768f2ed66ffdcc99396u128.wrapping_mul(i + 1),
                )
            })
            .collect(),
        (0..7)
            .map(|i| BinaryField128::from_repr(0xab93u128.wrapping_mul(i + 1)))
            .collect(),
    );
    readings(
        (0..64)
            .map(|i| BinaryField64::from_repr(0x2de9c38277314a15u64.wrapping_mul(i + 1)))
            .collect(),
        (0..6)
            .map(|i| BinaryField64::from_repr(0xdef1u64.wrapping_mul(i + 1)))
            .collect(),
    );
}

#[test]
fn tensor_closing_matches_native_equality_and_wide_successor_weights() {
    let val = |i: u128| {
        BinaryField128::from_repr(0x21bade026a6ae768f2ed66ffdcc99396u128.wrapping_mul(i + 1))
    };
    let batch = (30..37).map(val).collect::<Vec<_>>();
    closing::<BinaryField128>(vec![], vec![], batch.clone(), None);
    for (high, other, kept) in [
        (vec![val(1)], vec![val(8)], 1),
        (vec![val(1), val(2)], vec![val(8), val(9)], 2),
        (
            vec![BinaryField128::ONE, val(1), val(2)],
            vec![val(7), val(8), val(9)],
            2,
        ),
        (
            vec![BinaryField128::ZERO, BinaryField128::ONE, val(2)],
            vec![BinaryField128::ZERO, BinaryField128::ONE, val(9)],
            1,
        ),
    ] {
        closing(high.clone(), other.clone(), batch.clone(), None);
        closing(high, other, batch.clone(), Some((kept, val(42))));
    }
    let val = |i: u64| BinaryField64::from_repr(0x2de9c38277314a15u64.wrapping_mul(i + 1));
    closing(
        vec![val(1), val(2)],
        vec![val(8), val(9)],
        (30..36).map(val).collect(),
        Some((1, val(42))),
    );
}

#[test]
fn malformed_tensor_and_point_shapes_return_errors() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    assert!(BinaryTowerTensorTarget::<BinaryField128>::from_rows(&mut builder, vec![]).is_err());
    let zero = builder.binary128_constant(0).unwrap();
    let tensor =
        BinaryTowerTensorTarget::<BinaryField64>::from_rows(&mut builder, vec![zero.clone(); 64])
            .unwrap();
    assert!(tensor.evaluate_rows(&mut builder, &[]).is_err());
    assert!(
        binary_tensor_closing_weight::<BinaryField128, BabyBear>(
            &mut builder,
            &[zero.clone()],
            &[],
            &vec![zero.clone(); 7],
            None
        )
        .is_err()
    );
    assert!(
        binary_tensor_closing_weight::<BinaryField128, BabyBear>(
            &mut builder,
            &[zero.clone()],
            &[zero.clone()],
            &vec![zero.clone(); 7],
            Some((2, &zero))
        )
        .is_err()
    );
}
