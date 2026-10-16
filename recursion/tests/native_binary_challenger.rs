//! Binary carriers preserve the native byte transcript, including refill boundaries.

use p3_binary_field::{
    BinaryChallenger, BinaryField8, BinaryField128, Poly64, Poly192, TowerLevel,
};
use p3_blake3::Blake3;
use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger, HashChallenger,
};
use p3_circuit::ops::ByteHash;
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, ExprId, NpoTypeId};
use p3_keccak::Keccak256Hash;
use p3_recursion::BinaryTower128Challenger;
use p3_symmetric::{CryptographicHasher, Hash};

type E = NativeBinaryEncoding;

/// A byte hash with its native hasher, so a script runs under either.
trait NativeHash: CryptographicHasher<u8, [u8; 32]> + Clone + Send + Sync + 'static {
    const HASH: ByteHash;
}

impl NativeHash for Keccak256Hash {
    const HASH: ByteHash = ByteHash::Keccak256;
}

impl NativeHash for Blake3 {
    const HASH: ByteHash = ByteHash::Blake3;
}

fn enable_hash<F: BinaryCoordinateField, H: NativeHash>(b: &mut CircuitBuilder<F>) {
    match H::HASH {
        ByteHash::Keccak256 => b.enable_native_keccak_f1600().unwrap(),
        ByteHash::Blake3 => b.enable_native_blake3_compress().unwrap(),
    }
}

fn bind_bits<F: BinaryCoordinateField>(b: &mut CircuitBuilder<F>, bits: &[ExprId], raw: u128) {
    for (i, &bit) in bits.iter().enumerate() {
        let expected = b.define_const(F::from_bool(raw >> i & 1 != 0));
        b.connect(bit, expected);
    }
}

fn bytes_and_tower<F: BinaryCoordinateField, H: NativeHash>(hasher: H) {
    let initial = [3u8, 251, 7, 129, 11, 17, 193];
    let mut native = BinaryChallenger::<BinaryField8, _>::from_hasher(initial.to_vec(), hasher);
    let mut b = CircuitBuilder::<F>::new();
    enable_hash::<F, H>(&mut b);
    let input = b.alloc_public_input_array::<7>("initial bytes");
    let mut ch =
        BinaryTower128Challenger::with_initial_bytes_with_host::<E, F>(&mut b, H::HASH, &input)
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
    bytes_and_tower::<BinaryField128, _>(Keccak256Hash);
    bytes_and_tower::<Poly64, _>(Keccak256Hash);
}

#[test]
fn native_blake3_tower_and_polynomial_carriers_match_byte_and_tower_draws() {
    bytes_and_tower::<BinaryField128, _>(Blake3);
    bytes_and_tower::<Poly64, _>(Blake3);
}

fn poly192_draws<H: NativeHash>(hasher: H) {
    type F = Poly64;
    let mut native = BinaryChallenger::<Poly64, HashChallenger<u8, _, 32>>::from_hasher(
        vec![129, 3, 251],
        hasher,
    );
    let mut b = CircuitBuilder::<Poly64>::new();
    enable_hash::<F, H>(&mut b);
    let initial = [129u16, 3, 251].map(|word| b.define_const(E::encode_u16(word).unwrap()));
    let mut ch = BinaryTower128Challenger::with_initial_bytes_with_host::<E, Poly64>(
        &mut b,
        H::HASH,
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
fn native_poly192_draws_preserve_coefficients_and_partial_refills() {
    poly192_draws(Keccak256Hash);
}

#[test]
fn native_blake3_poly192_draws_preserve_coefficients_and_partial_refills() {
    poly192_draws(Blake3);
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
    // A Blake3 refill without the native Blake3 compression is not allowed and
    // leaves the challenger to draw the transcript's first value once it is.
    let mut blake3 = BinaryTower128Challenger::with_initial_bytes_with_host::<E, BinaryField128>(
        &mut b,
        ByteHash::Blake3,
        &[],
    )
    .unwrap();
    let error = blake3
        .sample_with_host::<E, BinaryField128>(&mut b)
        .unwrap_err();
    assert!(
        matches!(
            &error,
            CircuitBuilderError::OpNotAllowed { op } if *op == NpoTypeId::native_blake3_compress()
        ),
        "{error}"
    );
    b.enable_native_blake3_compress().unwrap();
    let actual = blake3
        .sample_with_host::<E, BinaryField128>(&mut b)
        .unwrap();
    let mut native = BinaryChallenger::<BinaryField128, _>::from_hasher(vec![], Blake3);
    let expected: BinaryField128 = native.sample();
    bind_bits(&mut b, actual.bits(), expected.to_repr());
    b.build().unwrap().runner().run().unwrap();
}

fn limbs_digest_and_grinding<H: NativeHash>(hasher: H) {
    type F = BinaryField128;
    let initial = [0xabcdu16, 0x9812];
    let digest: [u8; 32] = core::array::from_fn(|i| (i as u8).wrapping_mul(37).wrapping_add(129));
    let mut native = BinaryChallenger::<F, _>::from_hasher(
        initial.into_iter().flat_map(u16::to_le_bytes).collect(),
        hasher,
    );
    let mut b = CircuitBuilder::<F>::new();
    enable_hash::<F, H>(&mut b);
    let input = b.alloc_public_input_array::<2>("initial words");
    let mut ch =
        BinaryTower128Challenger::with_initial_limbs_with_host::<E, F>(&mut b, H::HASH, &input)
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

#[test]
fn native_limbs_digest_and_grinding_keep_the_next_draw_bound() {
    limbs_digest_and_grinding(Keccak256Hash);
}

#[test]
fn native_blake3_limbs_digest_and_grinding_keep_the_next_draw_bound() {
    limbs_digest_and_grinding(Blake3);
}

/// Words observed whole sample exactly like the same values observed as
/// checked bytes, and like the native transcript: in an odd-length input, a
/// word-aligned input, words at odd offsets and a two-block input.
fn word_observations<H: NativeHash>(hasher: H) {
    type F = BinaryField128;
    const BYTE: u8 = 201;
    let initial = [3u8, 251, 7];
    let values: [u128; 12] = core::array::from_fn(|i| {
        0x8123_4567_89ab_cdef_0fed_cba9_8765_4321u128.rotate_left(11 * i as u32) ^ i as u128
    });
    let mut native = BinaryChallenger::<BinaryField8, _>::from_hasher(initial.to_vec(), hasher);
    let mut b = CircuitBuilder::<F>::new();
    enable_hash::<F, H>(&mut b);
    let input = b.alloc_public_input_array::<3>("initial bytes");
    let observed = b.alloc_public_input_array::<12>("observed values");
    // The byte challenger reads its own copy of the values, so a change to
    // `observed` reaches the samples only through the word challenger.
    let copies = b.alloc_public_input_array::<12>("checked copies");
    let mut words =
        BinaryTower128Challenger::with_initial_bytes_with_host::<E, F>(&mut b, H::HASH, &input)
            .unwrap();
    let mut bytes = words.clone();
    let byte = [b.define_const(E::encode_u16(u16::from(BYTE)).unwrap())];
    // Values observed before each draw; the third phase brackets them with a
    // byte, so its words sit at odd offsets.
    for (range, bracket) in [(0..2, false), (2..3, false), (3..4, true), (4..12, false)] {
        for _ in 0..usize::from(bracket) {
            native.observe(BinaryField8::from_repr(BYTE));
            words
                .observe_bytes_with_host::<E, F>(&mut b, &byte)
                .unwrap();
            bytes
                .observe_bytes_with_host::<E, F>(&mut b, &byte)
                .unwrap();
        }
        for i in range {
            for byte in values[i].to_le_bytes() {
                native.observe(BinaryField8::from_repr(byte));
            }
            let value = b.native_tower128_from_expr(observed[i]);
            let split = b.native_tower128_unchecked_words(&value, 8).unwrap();
            words
                .observe_words_with_host::<E, F>(&mut b, &split)
                .unwrap();
            let copy = b.native_tower128_from_expr(copies[i]);
            let checked: Vec<_> = b
                .native_tower128_to_bits(&copy)
                .unwrap()
                .as_chunks::<8>()
                .0
                .iter()
                .map(|bits| E::recompose_word(&mut b, bits).unwrap())
                .collect();
            bytes
                .observe_bytes_with_host::<E, F>(&mut b, &checked)
                .unwrap();
        }
        for _ in 0..usize::from(bracket) {
            native.observe(BinaryField8::from_repr(BYTE));
            words
                .observe_bytes_with_host::<E, F>(&mut b, &byte)
                .unwrap();
            bytes
                .observe_bytes_with_host::<E, F>(&mut b, &byte)
                .unwrap();
        }
        let expected: BinaryField128 = native.sample();
        for ch in [&mut words, &mut bytes] {
            let actual = ch.sample_with_host::<E, F>(&mut b).unwrap();
            bind_bits(&mut b, actual.bits(), expected.to_repr());
        }
        let expected = native.sample_bits(13);
        for ch in [&mut words, &mut bytes] {
            let actual = ch.sample_bits_with_host::<E, F>(&mut b, 13).unwrap();
            bind_bits(&mut b, &actual, expected as u128);
        }
    }
    let circuit = b.build().unwrap();
    let mut public: Vec<F> = initial
        .iter()
        .map(|&byte| E::encode_u16(u16::from(byte)).unwrap())
        .collect();
    public.extend(values.map(F::from_repr));
    public.extend(values.map(F::from_repr));
    let runs = |public: &[F]| {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(public)
            .and_then(|()| runner.run())
            .is_ok()
    };
    assert!(runs(&public));
    for value in [0, 2, 3, 11] {
        let mut wrong = public.clone();
        wrong[3 + value] += F::from_repr(1 << 77);
        assert!(!runs(&wrong), "changed word-observed value {value}");
    }
}

#[test]
fn native_word_observations_sample_like_byte_observations() {
    word_observations(Keccak256Hash);
}

#[test]
fn native_blake3_word_observations_sample_like_byte_observations() {
    word_observations(Blake3);
}

/// A public word observed whole is range-checked by every refill path:
/// absorbed as a lane at an even offset, split at an odd offset, and split
/// in an odd-length input. A seventeenth coordinate is rejected, although
/// the low sixteen coordinates hash and sample honestly.
fn out_of_range_observed_words<F: BinaryCoordinateField, H: NativeHash>(hasher: &H) {
    const WORD: u16 = 0xb7e5;
    // Bytes before and after the word: even offset, odd offset, odd length.
    for (before, after) in [(&[3u8, 251][..], &[][..]), (&[3], &[7]), (&[3, 251], &[7])] {
        let mut native =
            BinaryChallenger::<BinaryField8, _>::from_hasher(before.to_vec(), hasher.clone());
        for &byte in WORD.to_le_bytes().iter().chain(after) {
            native.observe(BinaryField8::from_repr(byte));
        }
        let expected: BinaryField128 = native.sample();
        let mut b = CircuitBuilder::<F>::new();
        enable_hash::<F, H>(&mut b);
        let initial: Vec<_> = before
            .iter()
            .map(|&byte| b.define_const(E::encode_u16(u16::from(byte)).unwrap()))
            .collect();
        let trailing: Vec<_> = after
            .iter()
            .map(|&byte| b.define_const(E::encode_u16(u16::from(byte)).unwrap()))
            .collect();
        let word = b.public_input();
        let mut ch = BinaryTower128Challenger::with_initial_bytes_with_host::<E, F>(
            &mut b,
            H::HASH,
            &initial,
        )
        .unwrap();
        ch.observe_words_with_host::<E, F>(&mut b, &[word]).unwrap();
        ch.observe_bytes_with_host::<E, F>(&mut b, &trailing)
            .unwrap();
        let actual = ch.sample_with_host::<E, F>(&mut b).unwrap();
        bind_bits(&mut b, actual.bits(), expected.to_repr());
        let circuit = b.build().unwrap();
        let runs = |word: u128| {
            let mut runner = circuit.runner();
            runner
                .set_public_inputs(&[F::from_raw_coordinates(word).unwrap()])
                .and_then(|()| runner.run())
                .is_ok()
        };
        let case = (before.len(), after.len());
        assert!(
            runs(u128::from(WORD)),
            "honest word, bytes around it {case:?}"
        );
        assert!(
            !runs(u128::from(WORD) | (1 << 16)),
            "word with coordinate 16, bytes around it {case:?}"
        );
    }
}

#[test]
fn native_out_of_range_observed_words_are_rejected_on_every_absorb_path() {
    out_of_range_observed_words::<BinaryField128, _>(&Keccak256Hash);
    out_of_range_observed_words::<Poly64, _>(&Keccak256Hash);
}

#[test]
fn native_blake3_out_of_range_observed_words_are_rejected_on_every_absorb_path() {
    out_of_range_observed_words::<BinaryField128, _>(&Blake3);
    out_of_range_observed_words::<Poly64, _>(&Blake3);
}

/// Observations longer than a kibibyte, of odd lengths and mixed bytes and
/// words, refill like the native transcript, and the draws bind every
/// observed value. Under BLAKE3 the first refill hashes several chunks.
fn long_observations<F: BinaryCoordinateField, H: NativeHash>(hasher: H) {
    const INITIAL: usize = 5;
    // (bytes observed, words observed) before each draw.
    const PHASES: [(usize, usize); 5] = [(1100, 0), (33, 0), (0, 700), (1, 513), (7, 1)];
    let byte = |i: usize| (i * 73 + 11) as u8;
    let word = |i: usize| (i * 40503 + 7) as u16;
    let mut native =
        BinaryChallenger::<BinaryField8, _>::from_hasher((0..INITIAL).map(byte).collect(), hasher);
    let mut b = CircuitBuilder::<F>::new();
    enable_hash::<F, H>(&mut b);
    let initial = b.alloc_public_input_array::<INITIAL>("initial bytes");
    let mut ch =
        BinaryTower128Challenger::with_initial_bytes_with_host::<E, F>(&mut b, H::HASH, &initial)
            .unwrap();
    let encode = |limb: u16| -> F { E::encode_u16(limb).unwrap() };
    let mut public: Vec<F> = (0..INITIAL).map(|i| encode(u16::from(byte(i)))).collect();
    for (bytes, words) in PHASES {
        let observed = b.alloc_public_inputs(bytes, "observed bytes");
        public.extend((0..bytes).map(|i| encode(u16::from(byte(i)))));
        for i in 0..bytes {
            native.observe(BinaryField8::from_repr(byte(i)));
        }
        ch.observe_bytes_with_host::<E, F>(&mut b, &observed)
            .unwrap();
        let observed = b.alloc_public_inputs(words, "observed words");
        public.extend((0..words).map(|i| encode(word(i))));
        for i in 0..words {
            for byte in word(i).to_le_bytes() {
                native.observe(BinaryField8::from_repr(byte));
            }
        }
        ch.observe_words_with_host::<E, F>(&mut b, &observed)
            .unwrap();
        let expected: BinaryField128 = native.sample();
        let actual = ch.sample_with_host::<E, F>(&mut b).unwrap();
        bind_bits(&mut b, actual.bits(), expected.to_repr());
        let expected = native.sample_bits(21);
        let bits = ch.sample_bits_with_host::<E, F>(&mut b, 21).unwrap();
        bind_bits(&mut b, &bits, expected as u128);
    }
    let circuit = b.build().unwrap();
    let runs = |public: &[F]| {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(public)
            .and_then(|()| runner.run())
            .is_ok()
    };
    assert!(runs(&public));
    for index in [
        0,
        INITIAL + 1099,
        INITIAL + 1100 + 33 + 699,
        public.len() - 1,
    ] {
        let mut wrong = public.clone();
        wrong[index] += F::ONE;
        assert!(!runs(&wrong), "changed observed value {index}");
    }
}

#[test]
fn native_long_observations_refill_like_the_native_transcript() {
    long_observations::<BinaryField128, _>(Keccak256Hash);
    long_observations::<Poly64, _>(Keccak256Hash);
}

#[test]
fn native_blake3_long_observations_refill_like_the_native_transcript() {
    long_observations::<BinaryField128, _>(Blake3);
    long_observations::<Poly64, _>(Blake3);
}
