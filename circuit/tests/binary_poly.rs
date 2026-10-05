//! Polynomial-basis binary arithmetic against released native fields.

use core::hash::Hash;

use p3_baby_bear::BabyBear;
use p3_binary_field::{Gf2, Poly64, Poly192};
use p3_circuit::CircuitBuilder;
use p3_field::extension::BinomialExtensionField;
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;

fn limbs<F: PrimeCharacteristicRing>(raw: u64) -> [F; 4] {
    core::array::from_fn(|i| F::from_u16((raw >> (16 * i)) as u16))
}
fn raw(value: Poly192) -> [u64; 3] {
    value.coefficients().map(Poly64::to_bits)
}
fn reference_mul(a: u64, b: u64) -> u64 {
    let mut product = 0u128;
    for i in 0..64 {
        if b >> i & 1 != 0 {
            product ^= (a as u128) << i;
        }
    }
    for i in (64..=126).rev() {
        if product >> i & 1 != 0 {
            product ^= (1u128 << i) | (0x1bu128 << (i - 64));
        }
    }
    product as u64
}

fn poly64<BF, F>()
where
    BF: PrimeField64,
    F: ExtensionField<BF> + Eq + Hash,
{
    let mut b = CircuitBuilder::<F>::new();
    let a = b.alloc_public_input_array::<4>("poly64 a");
    let second = b.alloc_public_input_array::<4>("poly64 b");
    let expected =
        core::array::from_fn::<_, 3, _>(|_| b.alloc_public_input_array::<4>("poly64 result"));
    let a = b.binary_poly64_from_limbs::<BF>(a).unwrap();
    let second = b.binary_poly64_from_limbs::<BF>(second).unwrap();
    let sum = b.binary_poly64_add(&a, &second);
    let product = b.binary_poly64_mul(&a, &second);
    let square = b.binary_poly64_square(&a);
    for (value, expected) in [sum, product, square].iter().zip(expected) {
        let actual = b.binary_poly64_to_limbs::<BF>(value).unwrap();
        for (actual, expected) in actual.into_iter().zip(expected) {
            let difference = b.sub(actual, expected);
            b.assert_zero(difference);
        }
    }
    let circuit = b.build().unwrap();
    let mut pairs = vec![
        (0, 0),
        (0, u64::MAX),
        (1, u64::MAX),
        (u64::MAX, u64::MAX),
        (1 << 63, 2),
        (0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210),
    ];
    pairs.extend((0..64).map(|i| (1u64 << i, 1u64 << ((i + 37) % 64))));
    let mut seed = 0x91e1_0da5_c79e_7b1du64;
    for _ in 0..16 {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 43;
        let a = seed;
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 43;
        pairs.push((a, seed));
    }
    for (a, second) in pairs {
        let native = Poly64::new(a) * Poly64::new(second);
        assert_eq!(native.to_bits(), reference_mul(a, second));
        let inputs: Vec<_> = [
            a,
            second,
            a ^ second,
            native.to_bits(),
            Poly64::new(a).square().to_bits(),
        ]
        .into_iter()
        .flat_map(limbs::<F>)
        .collect();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&inputs).unwrap();
        runner.run().unwrap();
        for offset in [8, 12, 15, 16, 19] {
            let mut wrong = inputs.clone();
            wrong[offset] += F::ONE;
            let mut runner = circuit.runner();
            runner.set_public_inputs(&wrong).unwrap();
            assert!(runner.run().is_err());
        }
    }
}

fn poly192<BF, F>()
where
    BF: PrimeField64,
    F: ExtensionField<BF> + Eq + Hash,
{
    let mut b = CircuitBuilder::<F>::new();
    let a = b.alloc_public_input_array::<12>("poly192 a");
    let second = b.alloc_public_input_array::<12>("poly192 b");
    let expected =
        core::array::from_fn::<_, 5, _>(|_| b.alloc_public_input_array::<12>("poly192 result"));
    let a = b.binary_poly192_from_limbs::<BF>(a).unwrap();
    let second = b.binary_poly192_from_limbs::<BF>(second).unwrap();
    let sum = b.binary_poly192_add(&a, &second);
    let product = b.binary_poly192_mul(&a, &second);
    let square = b.binary_poly192_square(&a);
    let scaled = b.binary_poly192_scale(&a, &a.coefficients()[0]);
    let times_y = b.binary_poly192_mul_y(&a);
    for (value, expected) in [sum, product, square, scaled, times_y].iter().zip(expected) {
        let actual = b.binary_poly192_to_limbs::<BF>(value).unwrap();
        for (actual, expected) in actual.into_iter().zip(expected) {
            let difference = b.sub(actual, expected);
            b.assert_zero(difference);
        }
    }
    let circuit = b.build().unwrap();
    let mut pairs = vec![
        ([0; 3], [0; 3]),
        ([u64::MAX; 3], [u64::MAX; 3]),
        ([0, 1, 0], [0, 0, 1]),
        ([1, 0, 0], [u64::MAX; 3]),
        (
            [
                0x0123_4567_89ab_cdef,
                0xfedc_ba98_7654_3210,
                0x1357_2468_9abc_def0,
            ],
            [0xdead_beef, 0x9231_8765, 1 << 63],
        ),
    ];
    for i in 0..192 {
        let mut a = [0; 3];
        a[i / 64] = 1 << (i % 64);
        let mut second = [0; 3];
        let j = (i + 79) % 192;
        second[j / 64] = 1 << (j % 64);
        pairs.push((a, second));
    }
    let y = Poly192::new([Poly64::ZERO, Poly64::ONE, Poly64::ZERO]);
    for (a, second) in pairs {
        let native_a = Poly192::new(a.map(Poly64::new));
        let native_b = Poly192::new(second.map(Poly64::new));
        let words = [
            a,
            second,
            raw(native_a + native_b),
            raw(native_a * native_b),
            raw(native_a.square()),
            raw(native_a * native_a.coefficients()[0]),
            raw(native_a * y),
        ];
        let inputs: Vec<_> = words.into_iter().flatten().flat_map(limbs::<F>).collect();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&inputs).unwrap();
        runner.run().unwrap();
        for offset in [24, 36, 47, 48, 59, 60, 71, 72, 83] {
            let mut wrong = inputs.clone();
            wrong[offset] += F::ONE;
            let mut runner = circuit.runner();
            runner.set_public_inputs(&wrong).unwrap();
            assert!(runner.run().is_err());
        }
    }
}

#[test]
fn polynomial_arithmetic_matches_native_over_baby_bear() {
    poly64::<BabyBear, BabyBear>();
    poly192::<BabyBear, BabyBear>();
}
#[test]
fn polynomial_arithmetic_matches_native_over_prime_extensions() {
    poly64::<BabyBear, BinomialExtensionField<BabyBear, 4>>();
    poly192::<BabyBear, BinomialExtensionField<BabyBear, 4>>();
    poly64::<Goldilocks, BinomialExtensionField<Goldilocks, 2>>();
    poly192::<Goldilocks, BinomialExtensionField<Goldilocks, 2>>();
}

#[test]
fn inverse_candidates_are_unique_and_zero_has_none() {
    let mut b = CircuitBuilder::<BabyBear>::new();
    let value = b.alloc_public_input_array::<12>("poly inverse value");
    let inverse = b.alloc_public_input_array::<12>("poly inverse candidate");
    let value = b.binary_poly192_from_limbs::<BabyBear>(value).unwrap();
    let inverse = b.binary_poly192_from_limbs::<BabyBear>(inverse).unwrap();
    b.assert_binary_poly192_inverse(&value, &inverse);
    let circuit = b.build().unwrap();
    for a in [[0, 1, 0], [1 << 63, u64::MAX, 0x1234_5678], [0, 0, 1]] {
        let inverse = raw(Poly192::new(a.map(Poly64::new)).try_inverse().unwrap());
        let values: Vec<_> = a
            .into_iter()
            .chain(inverse)
            .flat_map(limbs::<BabyBear>)
            .collect();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&values).unwrap();
        runner.run().unwrap();
        let mut wrong = values;
        wrong[23] += BabyBear::ONE;
        let mut runner = circuit.runner();
        runner.set_public_inputs(&wrong).unwrap();
        assert!(runner.run().is_err());
    }
    let mut runner = circuit.runner();
    runner.set_public_inputs(&[BabyBear::ZERO; 24]).unwrap();
    assert!(runner.run().is_err());
}

#[test]
fn polynomial_constants_preserve_raw_coordinates_in_characteristic_two() {
    let mut b = CircuitBuilder::<Gf2>::new();
    let value = b.binary_poly64_constant(2).unwrap();
    b.tag(value.bits()[1], "poly64 bit one").unwrap();
    b.tag(value.bits()[0], "poly64 bit zero").unwrap();
    let value = b.binary_poly192_constant([1, 2, 3]).unwrap();
    b.tag(value.coefficients()[2].bits()[1], "coefficient two bit one")
        .unwrap();
    let circuit = b.build().unwrap();
    let traces = circuit.runner().run().unwrap();
    assert_eq!(traces.probe("poly64 bit one"), Some(&Gf2::ONE));
    assert_eq!(traces.probe("poly64 bit zero"), Some(&Gf2::ZERO));
    assert_eq!(traces.probe("coefficient two bit one"), Some(&Gf2::ONE));
}
