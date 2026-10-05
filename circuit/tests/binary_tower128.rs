//! Direct and native-differential checks for the Wiedemann GF(2^128) circuit gadget.

use core::hash::Hash;

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField128, Ghash128, TowerLevel};
use p3_circuit::{CircuitBuilder, CircuitError, ExprId, Traces};
use p3_field::extension::BinomialExtensionField;
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;

type BabyBearQuartic = BinomialExtensionField<BabyBear, 4>;
type GoldilocksQuadratic = BinomialExtensionField<Goldilocks, 2>;

#[derive(Clone, Copy)]
struct Fixture {
    a: u128,
    b: u128,
    product: u128,
    square: u128,
    inverse: u128,
    polynomial_a: u128,
    polynomial_b: u128,
    polynomial_product: u128,
}

// Generated independently by polynomial arithmetic modulo x^128 + x^7 + x^2 + x + 1,
// then converted through the seven tower-root images. These are raw tower coordinates.
const FIXTURES: [Fixture; 4] = [
    Fixture {
        a: 0x21bade026a6ae768f2ed66ffdcc99396,
        b: 0x6102dd7063e8540e9dd8904f07489671,
        product: 0xe979023873d074c503a03109a53de616,
        square: 0xdd9d695d6ba4065cd8ae51fbb43689e5,
        inverse: 0x0f244f8ffaba6994734a7f4eeedeea9c,
        polynomial_a: 0xf384262129e38bc1f89153aac3890087,
        polynomial_b: 0x13b51464dd678997a83073c38ec36aff,
        polynomial_product: 0x423bc46468a8265e794c160479489fa4,
    },
    Fixture {
        a: 0x83faac572f564652466de486522c4f8d,
        b: 0x781b9a43d04ce50b0620f0877e5fe381,
        product: 0xa67d71dcb60e3b54ce1c34e0e36dc1c2,
        square: 0x7b7caaf0f0c1958568dd26df711df745,
        inverse: 0x6218a936a3fc9ae09827379be863d108,
        polynomial_a: 0x2d8ea4f1c4005d849f698355c5e24796,
        polynomial_b: 0xaf9c20f22a3b2f99e9fe8dad2601dbe7,
        polynomial_product: 0xf80cb3c0de85c65b62b765d3cb406b80,
    },
    Fixture {
        a: 0xc35d7d3b92e4016e27e47ffc284a2d4f,
        b: 0x06e7df8e1eb1c66e79f74d60ac03031e,
        product: 0x7f0d3f8552772bd0ff4fffdd83bff1c5,
        square: 0x663895fb2904bc7f032e3f8325ae3256,
        inverse: 0x580d6a28c932e32c1de069b9544c4987,
        polynomial_a: 0x5efe186621148b1a105a9d49d73859ca,
        polynomial_b: 0xae532e4bb318ef2db7949463aa8c4a1f,
        polynomial_product: 0x06ae786de2d1cdd739c2470a69450cf6,
    },
    Fixture {
        a: 0x2e09e4b8245edebc817af708207473b7,
        b: 0xb7c039842be38ecc1f07a223563ebc38,
        product: 0x88b09d4e93c31775be082cb43a091df5,
        square: 0x722531e7f98fa19cfe84a329c4b90477,
        inverse: 0x9eb09b0326786868fe7f7e65ab3593db,
        polynomial_a: 0x2a78e2f5eab2746a37c976c81401125b,
        polynomial_b: 0x9395f21cf86debfa5b7ebc48d946c5c9,
        polynomial_product: 0x7134d0710363896f4d632964e371a893,
    },
];

fn bit_values<F: PrimeCharacteristicRing>(raw: u128) -> [F; 128] {
    core::array::from_fn(|i| if (raw >> i) & 1 == 0 { F::ZERO } else { F::ONE })
}

fn limb_values<F: PrimeCharacteristicRing>(raw: u128) -> [F; 8] {
    core::array::from_fn(|i| F::from_u16(((raw >> (16 * i)) & 0xffff) as u16))
}

fn read_bits<F: Field + PartialEq>(traces: &Traces<F>, prefix: &str) -> u128 {
    let mut raw = 0u128;
    for i in 0..128 {
        let tag = format!("{prefix}_{i}");
        let bit = *traces
            .probe(&tag)
            .unwrap_or_else(|| panic!("missing {tag}"));
        assert!(bit == F::ZERO || bit == F::ONE, "non-bit at {tag}");
        if bit == F::ONE {
            raw |= 1u128 << i;
        }
    }
    raw
}

fn sample_pairs(all_basis: bool) -> Vec<(u128, u128)> {
    let mut pairs = vec![
        (0, 0),
        (0, u128::MAX),
        (1, u128::MAX),
        (u128::MAX, u128::MAX),
        (
            0x0123456789abcdeffedcba9876543210,
            0x6dcb09a1478523fe13579bdf02468ace,
        ),
        (1 << 15, 1 << 16),
        (1 << 31, 1 << 32),
        (1 << 63, 1 << 64),
        (1 << 127, 1 << 127),
    ];
    pairs.extend(FIXTURES.iter().map(|fixture| (fixture.a, fixture.b)));

    let positions: Vec<usize> = if all_basis {
        (0..128).collect()
    } else {
        vec![0, 1, 7, 8, 15, 16, 31, 32, 63, 64, 95, 96, 126, 127]
    };
    pairs.extend(
        positions
            .into_iter()
            .map(|i| (1u128 << i, 1u128 << ((i + 37) % 128))),
    );

    let mut seed = 0x91e10da5c79e7b1d4f2c8160ab3d9507u128;
    for _ in 0..12 {
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 43;
        let a = seed;
        seed ^= seed << 13;
        seed ^= seed >> 17;
        seed ^= seed << 43;
        pairs.push((a, seed));
    }
    pairs
}

#[test]
fn fixed_tower_vectors_match_native_and_polynomial_basis() {
    for fixture in FIXTURES {
        let a = BinaryField128::from_repr(fixture.a);
        let b = BinaryField128::from_repr(fixture.b);
        assert_eq!((a * b).to_repr(), fixture.product);
        assert_eq!(a.square().to_repr(), fixture.square);
        assert_eq!(a.try_inverse().unwrap().to_repr(), fixture.inverse);
        assert_eq!(Ghash128::from(a).to_repr(), fixture.polynomial_a);
        assert_eq!(Ghash128::from(b).to_repr(), fixture.polynomial_b);
        assert_eq!(Ghash128::from(a * b).to_repr(), fixture.polynomial_product);
    }
}

fn arithmetic_matches_native<BF, F>(all_basis: bool)
where
    BF: PrimeField64,
    F: ExtensionField<BF> + Eq + Hash,
{
    let mut builder = CircuitBuilder::<F>::new();
    let a_bits: [ExprId; 128] = builder.alloc_public_input_array("a bit");
    let b_bits: [ExprId; 128] = builder.alloc_public_input_array("b bit");
    let expected_sum: [ExprId; 128] = builder.alloc_public_input_array("sum bit");
    let expected_product: [ExprId; 128] = builder.alloc_public_input_array("product bit");
    let expected_square: [ExprId; 128] = builder.alloc_public_input_array("square bit");
    let a = builder.binary128_from_bits(a_bits).unwrap();
    let b = builder.binary128_from_bits(b_bits).unwrap();
    let sum = builder.binary128_add(&a, &b);
    let product = builder.binary128_mul(&a, &b);
    let square = builder.binary128_square(&a);
    for (prefix, actual, expected) in [
        ("sum", sum.bits(), &expected_sum),
        ("product", product.bits(), &expected_product),
        ("square", square.bits(), &expected_square),
    ] {
        for (i, (&actual_bit, &expected_bit)) in actual.iter().zip(expected.iter()).enumerate() {
            builder.tag(actual_bit, format!("{prefix}_{i}")).unwrap();
            let difference = builder.sub(actual_bit, expected_bit);
            builder.assert_zero(difference);
        }
    }
    let circuit = builder.build().unwrap();

    for (a_raw, b_raw) in sample_pairs(all_basis) {
        let a_native = BinaryField128::from_repr(a_raw);
        let b_native = BinaryField128::from_repr(b_raw);
        let sum_raw = (a_native + b_native).to_repr();
        let product_raw = (a_native * b_native).to_repr();
        let square_raw = a_native.square().to_repr();
        assert_eq!(sum_raw, a_raw ^ b_raw);
        assert_eq!(product_raw, a_native.reference_mul(b_native).to_repr());
        assert_eq!(square_raw, (a_native * a_native).to_repr());
        let values: Vec<F> = [a_raw, b_raw, sum_raw, product_raw, square_raw]
            .into_iter()
            .flat_map(bit_values::<F>)
            .collect();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&values).unwrap();
        let traces = runner.run().unwrap_or_else(|error| {
            panic!("honest a={a_raw:032x}, b={b_raw:032x} rejected: {error:?}")
        });
        assert_eq!(
            read_bits(&traces, "sum"),
            sum_raw,
            "a={a_raw:032x}, b={b_raw:032x}"
        );
        assert_eq!(
            read_bits(&traces, "product"),
            product_raw,
            "a={a_raw:032x}, b={b_raw:032x}"
        );
        assert_eq!(read_bits(&traces, "square"), square_raw, "a={a_raw:032x}");
        if let Some(fixture) = FIXTURES
            .iter()
            .find(|fixture| fixture.a == a_raw && fixture.b == b_raw)
        {
            assert_eq!(read_bits(&traces, "product"), fixture.product);
            assert_eq!(read_bits(&traces, "square"), fixture.square);
        }
    }

    let a_raw = FIXTURES[0].a;
    let b_raw = FIXTURES[0].b;
    let a = BinaryField128::from_repr(a_raw);
    let b = BinaryField128::from_repr(b_raw);
    let honest = [
        a_raw,
        b_raw,
        (a + b).to_repr(),
        (a * b).to_repr(),
        a.square().to_repr(),
    ];
    for (word, bit) in [(2, 0), (2, 127), (3, 0), (3, 96), (4, 0), (4, 127)] {
        let mut wrong = honest;
        wrong[word] ^= 1u128 << bit;
        let values: Vec<F> = wrong.into_iter().flat_map(bit_values::<F>).collect();
        let mut runner = circuit.runner();
        let result = runner
            .set_public_inputs(&values)
            .and_then(|()| runner.run().map(drop));
        assert!(
            matches!(result.as_ref(), Err(CircuitError::WitnessConflict { .. })),
            "wrong word {word} bit {bit}: {result:?}"
        );
    }
}

#[test]
fn arithmetic_matches_native_over_baby_bear() {
    arithmetic_matches_native::<BabyBear, BabyBear>(true);
}

#[test]
fn arithmetic_matches_native_over_baby_bear_quartic() {
    arithmetic_matches_native::<BabyBear, BabyBearQuartic>(false);
}

#[test]
fn arithmetic_matches_native_over_goldilocks_quadratic() {
    arithmetic_matches_native::<Goldilocks, GoldilocksQuadratic>(false);
}

fn limb_roundtrips<BF, F>()
where
    BF: PrimeField64,
    F: ExtensionField<BF> + Eq + Hash,
{
    let mut builder = CircuitBuilder::<F>::new();
    let input_limbs: [ExprId; 8] = builder.alloc_public_input_array("tower limb");
    let target = builder.binary128_from_limbs::<BF>(input_limbs).unwrap();
    let output_limbs = builder.binary128_to_limbs::<BF>(&target).unwrap();
    for (i, &limb) in output_limbs.iter().enumerate() {
        builder.tag(limb, format!("limb_{i}")).unwrap();
    }
    for (i, &bit) in target.bits().iter().enumerate() {
        builder.tag(bit, format!("bits_{i}")).unwrap();
    }
    let circuit = builder.build().unwrap();

    let mut cases = vec![
        0,
        1,
        0xffff,
        0x1_0000,
        u128::MAX,
        0x0123456789abcdeffedcba9876543210,
    ];
    cases.extend((0..128).map(|i| 1u128 << i));
    for raw in cases {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&limb_values::<F>(raw)).unwrap();
        let traces = runner
            .run()
            .unwrap_or_else(|error| panic!("raw={raw:032x}: {error:?}"));
        assert_eq!(read_bits(&traces, "bits"), raw);
        for i in 0..8 {
            let expected = F::from_u16(((raw >> (16 * i)) & 0xffff) as u16);
            assert_eq!(
                *traces.probe(&format!("limb_{i}")).unwrap(),
                expected,
                "raw={raw:032x}, limb {i}"
            );
        }
    }

    let mut bad_limbs = [F::ZERO; 8];
    bad_limbs[0] = F::from_u32(1 << 16);
    let mut runner = circuit.runner();
    let result = runner
        .set_public_inputs(&bad_limbs)
        .and_then(|()| runner.run().map(drop));
    assert!(
        matches!(result.as_ref(), Err(CircuitError::WitnessConflict { .. })),
        "a 65536 limb was accepted: {result:?}"
    );
}

#[test]
fn little_endian_limbs_roundtrip_over_baby_bear() {
    limb_roundtrips::<BabyBear, BabyBear>();
}

#[test]
fn little_endian_limbs_roundtrip_over_baby_bear_quartic() {
    limb_roundtrips::<BabyBear, BabyBearQuartic>();
}

#[test]
fn little_endian_limbs_roundtrip_over_goldilocks_quadratic() {
    limb_roundtrips::<Goldilocks, GoldilocksQuadratic>();
}

#[test]
fn constants_use_raw_tower_coordinates_and_root_reductions() {
    const ROOT_SQUARES: [(u128, u128); 7] = [
        (0x2, 0x3),
        (0x4, 0x9),
        (0x10, 0x41),
        (0x100, 0x1001),
        (0x10000, 0x1000001),
        (0x100000000, 0x1000000000001),
        (0x10000000000000000, 0x1000000000000000000000001),
    ];
    let mut cases = ROOT_SQUARES.to_vec();
    cases.extend(FIXTURES.iter().map(|fixture| (fixture.a, fixture.square)));
    cases.extend(
        [0, 1, u128::MAX, 1u128 << 127]
            .map(|raw| (raw, BinaryField128::from_repr(raw).square().to_repr())),
    );
    for (raw, squared) in cases {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let value = builder.binary128_constant(raw).unwrap();
        let square = builder.binary128_square(&value);
        for (i, (&input_bit, &square_bit)) in
            value.bits().iter().zip(square.bits().iter()).enumerate()
        {
            builder.tag(input_bit, format!("input_{i}")).unwrap();
            builder.tag(square_bit, format!("square_{i}")).unwrap();
        }
        let circuit = builder.build().unwrap();
        let traces = circuit.runner().run().unwrap();
        assert_eq!(read_bits(&traces, "input"), raw);
        assert_eq!(read_bits(&traces, "square"), squared);
        assert_eq!(BinaryField128::from_repr(raw).square().to_repr(), squared);
    }
}

#[test]
fn inverse_check_accepts_native_inverses_and_rejects_wrong_or_zero_candidates() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let a_bits: [ExprId; 128] = builder.alloc_public_input_array("element bit");
    let inverse_bits: [ExprId; 128] = builder.alloc_public_input_array("inverse bit");
    let a = builder.binary128_from_bits(a_bits).unwrap();
    let inverse = builder.binary128_from_bits(inverse_bits).unwrap();
    builder.assert_binary128_inverse(&a, &inverse);
    let circuit = builder.build().unwrap();

    let mut nonzero = vec![1, u128::MAX, 0x0123456789abcdeffedcba9876543210];
    nonzero.extend(FIXTURES.iter().map(|fixture| fixture.a));
    nonzero.extend([
        1u128 << 0,
        1u128 << 15,
        1u128 << 63,
        1u128 << 64,
        1u128 << 127,
    ]);
    for raw in nonzero {
        let native_inverse = BinaryField128::from_repr(raw)
            .try_inverse()
            .unwrap()
            .to_repr();
        if let Some(fixture) = FIXTURES.iter().find(|fixture| fixture.a == raw) {
            assert_eq!(native_inverse, fixture.inverse);
        }
        let values: Vec<BabyBear> = [raw, native_inverse]
            .into_iter()
            .flat_map(bit_values)
            .collect();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&values).unwrap();
        runner
            .run()
            .unwrap_or_else(|error| panic!("inverse of {raw:032x} rejected: {error:?}"));
    }

    let a = FIXTURES[0].a;
    for candidate in [
        FIXTURES[0].inverse ^ 1,
        FIXTURES[0].inverse ^ (1u128 << 127),
    ] {
        let values: Vec<BabyBear> = [a, candidate].into_iter().flat_map(bit_values).collect();
        let mut runner = circuit.runner();
        let result = runner
            .set_public_inputs(&values)
            .and_then(|()| runner.run().map(drop));
        assert!(
            matches!(result.as_ref(), Err(CircuitError::WitnessConflict { .. })),
            "bad inverse accepted: {result:?}"
        );
    }
    for candidate in [0, 1, u128::MAX] {
        let values: Vec<BabyBear> = [0, candidate].into_iter().flat_map(bit_values).collect();
        let mut runner = circuit.runner();
        let result = runner
            .set_public_inputs(&values)
            .and_then(|()| runner.run().map(drop));
        assert!(
            matches!(result.as_ref(), Err(CircuitError::WitnessConflict { .. })),
            "zero inverse accepted: {result:?}"
        );
    }
}

#[test]
fn raw_bit_constructor_accepts_characteristic_two() {
    let mut builder = CircuitBuilder::<BinaryField128>::new();
    let bits = builder.alloc_public_input_array::<128>("bit");
    let target = builder.binary128_from_bits(bits).unwrap();
    assert_eq!(target.bits(), &bits);
    assert_eq!(builder.public_input_count(), 128);
    let constant = builder.binary128_constant(1 << 127).unwrap();
    builder
        .tag(constant.bits()[127], "high constant bit")
        .unwrap();
    builder.tag(constant.bits()[0], "low constant bit").unwrap();
    let circuit = builder.build().unwrap();
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&[BinaryField128::ONE; 128])
        .unwrap();
    let traces = runner.run().unwrap();
    assert_eq!(
        traces.probe("high constant bit"),
        Some(&BinaryField128::ONE)
    );
    assert_eq!(
        traces.probe("low constant bit"),
        Some(&BinaryField128::ZERO)
    );
}
