//! Binary carriers preserve the native byte transcript, including refill boundaries.

use p3_binary_field::{
    BinaryChallenger, BinaryField8, BinaryField128, Poly64, Poly192, TowerLevel,
};
use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger, HashChallenger,
};
use p3_circuit::ops::ByteHash;
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_keccak::Keccak256Hash;
use p3_recursion::BinaryTower128Challenger;
use p3_symmetric::Hash;

type E = NativeBinaryEncoding;

fn bind_bits<F: BinaryCoordinateField>(b: &mut CircuitBuilder<F>, bits: &[ExprId], raw: u128) {
    for (i, &bit) in bits.iter().enumerate() {
        let expected = b.define_const(F::from_bool(raw >> i & 1 != 0));
        b.connect(bit, expected);
    }
}

fn bytes_and_tower<F: BinaryCoordinateField>() {
    let initial = [3u8, 251, 7, 129, 11, 17, 193];
    let mut native =
        BinaryChallenger::<BinaryField8, _>::from_hasher(initial.to_vec(), Keccak256Hash);
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let input = b.alloc_public_input_array::<7>("initial bytes");
    let mut ch = BinaryTower128Challenger::with_initial_bytes_with_host::<E, F>(
        &mut b,
        ByteHash::Keccak256,
        &input,
    )
    .unwrap();
    for count in [1, 16, 7, 24, 17, 0] {
        let bytes = ch.sample_bytes_with_host::<E, F>(&mut b, count).unwrap();
        for byte in bytes {
            let expected: BinaryField8 = native.sample();
            let expected = b.define_const(E::encode_u16(u16::from(expected.to_repr())).unwrap());
            b.connect(byte, expected);
        }
        for width in [0, 23] {
            let expected = native.sample_bits(width);
            let bits = ch.sample_bits_with_host::<E, F>(&mut b, width).unwrap();
            bind_bits(&mut b, &bits, expected as u128);
        }
    }
    for bytes in [&[][..], &input[..3], &input[..1]] {
        for &byte in &initial[..bytes.len()] {
            native.observe(BinaryField8::from_repr(byte));
        }
        ch.observe_bytes_with_host::<E, F>(&mut b, bytes).unwrap();
        let expected: BinaryField128 = native.sample();
        let actual = ch.sample_with_host::<E, F>(&mut b).unwrap();
        bind_bits(&mut b, actual.bits(), expected.to_repr());
    }
    let circuit = b.build().unwrap();
    let public: Vec<_> = initial
        .map(|byte| E::encode_u16(u16::from(byte)).unwrap())
        .to_vec();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    runner.run().unwrap();
    let mut wrong = public;
    wrong[6] = F::from_raw_coordinates(256).unwrap();
    let mut runner = circuit.runner();
    assert!(
        runner
            .set_public_inputs(&wrong)
            .and_then(|()| runner.run())
            .is_err()
    );
}

#[test]
fn native_tower_and_polynomial_carriers_match_byte_and_tower_draws() {
    bytes_and_tower::<BinaryField128>();
    bytes_and_tower::<Poly64>();
}

#[test]
fn native_poly192_draws_preserve_coefficients_and_partial_refills() {
    let mut native = BinaryChallenger::<Poly64, HashChallenger<u8, _, 32>>::from_hasher(
        vec![129, 3, 251],
        Keccak256Hash,
    );
    let mut b = CircuitBuilder::<Poly64>::new();
    b.enable_native_keccak_f1600().unwrap();
    let initial = [129u16, 3, 251].map(|word| b.define_const(E::encode_u16(word).unwrap()));
    let mut ch = BinaryTower128Challenger::with_initial_bytes_with_host::<E, Poly64>(
        &mut b,
        ByteHash::Keccak256,
        &initial,
    )
    .unwrap();
    let observed = Poly192::new([
        Poly64::new(0x80123456789abcde),
        Poly64::new(0x57a983b1de021365),
        Poly64::new(0xfefdfcfbfaf9f8f7),
    ]);
    for _ in 0..4 {
        let expected = native.sample_algebra_element::<Poly192>();
        let actual = ch.sample_poly192_with_host::<E, Poly64>(&mut b).unwrap();
        for (coefficient, raw) in actual.coefficients().iter().zip(expected.coefficients()) {
            bind_bits(&mut b, coefficient.bits(), raw.to_bits() as u128);
        }
        for coefficient in observed.coefficients() {
            native.observe(coefficient);
        }
        let target = b
            .binary_poly192_constant(observed.coefficients().map(Poly64::to_bits))
            .unwrap();
        ch.observe_poly192_with_host::<E, Poly64>(&mut b, &target)
            .unwrap();
    }
    b.build().unwrap().runner().run().unwrap();
}

#[test]
fn failed_refill_can_be_retried_and_zero_work_preserves_state() {
    let mut b = CircuitBuilder::<BinaryField128>::new();
    let mut ch = BinaryTower128Challenger::new(ByteHash::Keccak256);
    assert!(ch.sample_with_host::<E, BinaryField128>(&mut b).is_err());
    assert!(
        ch.sample_bytes_with_host::<E, BinaryField128>(&mut b, 0)
            .unwrap()
            .is_empty()
    );
    let witness = b.binary128_constant(0).unwrap();
    ch.check_witness_with_host::<E, BinaryField128>(&mut b, 0, &witness)
        .unwrap();
    b.enable_native_keccak_f1600().unwrap();
    let actual = ch.sample_with_host::<E, BinaryField128>(&mut b).unwrap();
    let mut native = BinaryChallenger::<BinaryField128, _>::from_hasher(vec![], Keccak256Hash);
    let expected: BinaryField128 = native.sample();
    bind_bits(&mut b, actual.bits(), expected.to_repr());
    assert!(
        BinaryTower128Challenger::with_initial_bytes_with_host::<E, BinaryField128>(
            &mut b,
            ByteHash::Blake3,
            &[]
        )
        .is_err()
    );
    b.build().unwrap().runner().run().unwrap();
}

#[test]
fn native_limbs_digest_and_grinding_keep_the_next_draw_bound() {
    type F = BinaryField128;
    let initial = [0xabcdu16, 0x9812];
    let digest: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(129));
    let mut native = BinaryChallenger::<F, _>::from_hasher(
        initial.into_iter().flat_map(u16::to_le_bytes).collect(),
        Keccak256Hash,
    );
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let input = b.alloc_public_input_array::<2>("initial words");
    let mut ch = BinaryTower128Challenger::with_initial_limbs_with_host::<E, F>(
        &mut b,
        ByteHash::Keccak256,
        &input,
    )
    .unwrap();
    let raw = 0x9123456789abcdef0123456789abcdef;
    let observed = b.binary128_constant(raw).unwrap();
    native.observe(F::from_repr(raw));
    ch.observe_slice_with_host::<E, F>(&mut b, &[observed])
        .unwrap();
    let expected: F = native.sample();
    let actual = ch.sample_with_host::<E, F>(&mut b).unwrap();
    bind_bits(&mut b, actual.bits(), expected.to_repr());
    let words = b.alloc_public_input_array::<16>("digest words");
    ch.observe_digest_with_host::<E, F>(&mut b, &words).unwrap();
    native.observe(Hash::<F, u8, 32>::from(digest));
    let before_pow = native.clone();
    let witness = native.grind(3);
    let bad = (0..100u128)
        .find(|&raw| !before_pow.clone().check_witness(3, F::from_repr(raw)))
        .unwrap();
    let witness_words = b.alloc_public_input_array::<8>("grinding words");
    let mut bits = Vec::new();
    for word in witness_words {
        bits.extend(E::decompose_word(&mut b, word, 16).unwrap());
    }
    let witness_target = b.binary128_from_bits(bits.try_into().unwrap()).unwrap();
    ch.check_witness_with_host::<E, F>(&mut b, 3, &witness_target)
        .unwrap();
    let expected: F = native.sample();
    let actual = ch.sample_with_host::<E, F>(&mut b).unwrap();
    bind_bits(&mut b, actual.bits(), expected.to_repr());
    let circuit = b.build().unwrap();
    let mut public: Vec<F> = initial
        .into_iter()
        .map(|word| E::encode_u16(word).unwrap())
        .collect();
    public.extend(
        digest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| -> F { E::encode_u16(u16::from_le_bytes(*pair)).unwrap() }),
    );
    public.extend(
        (0..8).map(|i| -> F { E::encode_u16((witness.to_repr() >> (16 * i)) as u16).unwrap() }),
    );
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    runner.run().unwrap();
    for i in 0..8 {
        public[18 + i] = E::encode_u16((bad >> (16 * i)) as u16).unwrap();
    }
    let mut runner = circuit.runner();
    assert!(
        runner
            .set_public_inputs(&public)
            .and_then(|()| runner.run())
            .is_err()
    );
}
