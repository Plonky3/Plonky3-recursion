//! Hash boundaries preserve natural bytes and low-first digest words.

use core::hash::Hash;

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField128, Poly64};
use p3_blake3::Blake3;
use p3_circuit::ops::ByteHash;
use p3_circuit::ops::binary_encoding::{
    BinaryCircuitEncoding, NativeBinaryEncoding, PrimeBinaryEncoding,
};
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::{CircuitBuilder, ExprId, NpoTypeId, Op};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_keccak::Keccak256Hash;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher, PseudoCompressionFunction};

/// The p3 digest of `bytes` under `hash`.
fn digest_of(hash: ByteHash, bytes: impl IntoIterator<Item = u8>) -> [u8; 32] {
    match hash {
        ByteHash::Keccak256 => Keccak256Hash.hash_iter(bytes),
        ByteHash::Blake3 => Blake3.hash_iter(bytes),
    }
}

fn check<F: Field + Eq + Hash, H: BinaryCircuitHost<F>>(mut b: CircuitBuilder<F>, hash: ByteHash) {
    let input = b.alloc_public_input_array::<32>("two digests");
    let expected = b.alloc_public_input_array::<16>("compressed digest");
    let actual = H::compress(&mut b, hash, &input[..16], &input[16..]).unwrap();
    let hashed = H::hash_words(&mut b, hash, &input).unwrap();
    for i in 0..16 {
        b.connect(actual[i], expected[i]);
        b.connect(hashed[i], expected[i]);
    }
    let odd = b.alloc_public_input_array::<3>("odd bytes");
    let words = H::words_from_bytes(&mut b, &odd).unwrap();
    assert_eq!(words.len(), 2);
    let padded = H::bytes_from_words(&mut b, &words).unwrap();
    for i in 0..3 {
        b.connect(padded[i], odd[i]);
    }
    b.connect(padded[3], ExprId::ZERO);
    assert!(H::compress(&mut b, hash, &input[..15], &input[16..]).is_err());
    let circuit = b.build().unwrap();
    let input: [u16; 32] =
        core::array::from_fn(|i| 0x9123u16.wrapping_add((i as u16).wrapping_mul(1703)));
    let digest = digest_of(hash, input.into_iter().flat_map(u16::to_le_bytes));
    let mut public: Vec<F> = input
        .into_iter()
        .map(|word| H::encode_u16(word).unwrap())
        .collect();
    public.extend(
        digest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| H::encode_u16(u16::from_le_bytes(*pair)).unwrap()),
    );
    public.extend([0xd3, 0x92, 0xf7].map(|word| H::encode_u16(word).unwrap()));
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    runner.run().unwrap();
    public[47] += F::ONE;
    let mut runner = circuit.runner();
    assert!(
        runner
            .set_public_inputs(&public)
            .and_then(|()| runner.run())
            .is_err()
    );
}

/// A four-digest node is Keccak-256 of the 128 concatenated digest bytes and a
/// two-digest node is the pairwise compression.
fn check_compress_n<F: Field + Eq + Hash, H: BinaryCircuitHost<F>>(
    mut b: CircuitBuilder<F>,
    hash: ByteHash,
) {
    let input = b.alloc_public_input_array::<64>("four digests");
    let expected = b.alloc_public_input_array::<16>("compressed digest");
    let digests: Vec<&[ExprId]> = input.chunks(16).collect();
    let actual = H::compress_n(&mut b, hash, &digests).unwrap();
    let pair = H::compress_n(&mut b, hash, &digests[..2]).unwrap();
    let compressed = H::compress(&mut b, hash, digests[0], digests[1]).unwrap();
    for i in 0..16 {
        b.connect(actual[i], expected[i]);
        b.connect(pair[i], compressed[i]);
    }
    for malformed in [
        &[digests[0]; 5][..],
        &digests[..1],
        &[digests[0], &input[..15]],
    ] {
        assert!(H::compress_n(&mut b, hash, malformed).is_err());
    }
    let circuit = b.build().unwrap();
    let input: [u16; 64] =
        core::array::from_fn(|i| 0x4c1du16.wrapping_add((i as u16).wrapping_mul(2741)));
    let digest = digest_of(hash, input.into_iter().flat_map(u16::to_le_bytes));
    let mut public: Vec<F> = input
        .into_iter()
        .map(|word| H::encode_u16(word).unwrap())
        .collect();
    public.extend(
        digest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| H::encode_u16(u16::from_le_bytes(*pair)).unwrap()),
    );
    let runs = |public: &[F]| {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(public)
            .and_then(|()| runner.run())
            .is_ok()
    };
    assert!(runs(&public));
    // The last digest is bound as much as the first.
    for changed in [0, 63, 64] {
        let mut wrong = public.clone();
        wrong[changed] += F::ONE;
        assert!(!runs(&wrong), "changed input {changed}");
    }
}

/// The Keccak-f calls, operations of type `keccak`, of a circuit that
/// compresses `arity` digests into one node.
fn node_keccak_calls<F: Field + Eq + Hash, H: BinaryCircuitHost<F>>(
    mut b: CircuitBuilder<F>,
    keccak: &NpoTypeId,
    arity: usize,
) -> usize {
    let input = b.alloc_public_input_array::<64>("four digests");
    let expected = b.alloc_public_input_array::<16>("compressed digest");
    let digests: Vec<&[ExprId]> = input.chunks(16).take(arity).collect();
    let node = H::compress_n(&mut b, ByteHash::Keccak256, &digests).unwrap();
    for (&computed, &expected) in node.iter().zip(&expected) {
        b.connect(computed, expected);
    }
    b.build()
        .unwrap()
        .ops
        .iter()
        .filter(|op| {
            matches!(op, Op::NonPrimitiveOpWithExecutor { executor, .. }
                if executor.op_type() == keccak)
        })
        .count()
}

/// A four-digest node is a single Keccak-f call on the native and prime
/// hosts, as a pairwise node is, which is what halves the hashing of an
/// arity-4 authentication path.
#[test]
fn native_and_prime_hosts_compress_four_digests_in_one_keccak_block() {
    let native = || {
        let mut b = CircuitBuilder::<BinaryField128>::new();
        b.enable_native_keccak_f1600().unwrap();
        b
    };
    check_compress_n::<BinaryField128, NativeBinaryEncoding>(native(), ByteHash::Keccak256);
    let keccak = NpoTypeId::native_keccak_f1600();
    for arity in [2, 4] {
        assert_eq!(
            node_keccak_calls::<BinaryField128, NativeBinaryEncoding>(native(), &keccak, arity),
            1
        );
    }
    let native = || {
        let mut b = CircuitBuilder::<Poly64>::new();
        b.enable_native_keccak_f1600().unwrap();
        b
    };
    check_compress_n::<Poly64, NativeBinaryEncoding>(native(), ByteHash::Keccak256);
    for arity in [2, 4] {
        assert_eq!(
            node_keccak_calls::<Poly64, NativeBinaryEncoding>(native(), &keccak, arity),
            1
        );
    }
    let prime = || {
        let mut b = CircuitBuilder::<BabyBear>::new();
        b.enable_keccak_f1600::<BabyBear>();
        b
    };
    check_compress_n::<BabyBear, PrimeBinaryEncoding<BabyBear>>(prime(), ByteHash::Keccak256);
    let keccak = NpoTypeId::keccak_f1600();
    for arity in [2, 4] {
        assert_eq!(
            node_keccak_calls::<BabyBear, PrimeBinaryEncoding<BabyBear>>(prime(), &keccak, arity),
            1
        );
    }
}

#[test]
fn native_and_prime_hosts_match_digest_compression_and_odd_byte_packing() {
    let mut b = CircuitBuilder::<BinaryField128>::new();
    b.enable_native_keccak_f1600().unwrap();
    check::<BinaryField128, NativeBinaryEncoding>(b, ByteHash::Keccak256);
    let mut b = CircuitBuilder::<Poly64>::new();
    b.enable_native_keccak_f1600().unwrap();
    check::<Poly64, NativeBinaryEncoding>(b, ByteHash::Keccak256);
    let mut b = CircuitBuilder::<BabyBear>::new();
    b.enable_keccak_f1600::<BabyBear>();
    check::<BabyBear, PrimeBinaryEncoding<BabyBear>>(b, ByteHash::Keccak256);
}

/// Under Blake3 the native host is plain Blake3 of the concatenated digests,
/// which is p3's `CompressionFunctionFromHasher<Blake3, N, 32>`, and hashing
/// words and bytes matches p3.
#[test]
fn native_blake3_host_matches_p3_compression_and_hashing() {
    let tower = || {
        let mut b = CircuitBuilder::<BinaryField128>::new();
        b.enable_native_blake3_compress().unwrap();
        b
    };
    check::<BinaryField128, NativeBinaryEncoding>(tower(), ByteHash::Blake3);
    check_compress_n::<BinaryField128, NativeBinaryEncoding>(tower(), ByteHash::Blake3);
    let poly = || {
        let mut b = CircuitBuilder::<Poly64>::new();
        b.enable_native_blake3_compress().unwrap();
        b
    };
    check::<Poly64, NativeBinaryEncoding>(poly(), ByteHash::Blake3);
    check_compress_n::<Poly64, NativeBinaryEncoding>(poly(), ByteHash::Blake3);

    let digests: [[u8; 32]; 4] =
        core::array::from_fn(|d| core::array::from_fn(|i| (d * 41 + i * 7 + 3) as u8));
    assert_eq!(
        CompressionFunctionFromHasher::<Blake3, 2, 32>::new(Blake3)
            .compress([digests[0], digests[1]]),
        digest_of(ByteHash::Blake3, digests[..2].concat())
    );
    assert_eq!(
        CompressionFunctionFromHasher::<Blake3, 3, 32>::new(Blake3)
            .compress([digests[0], digests[1], digests[2]]),
        digest_of(ByteHash::Blake3, digests[..3].concat())
    );
    assert_eq!(
        CompressionFunctionFromHasher::<Blake3, 4, 32>::new(Blake3).compress(digests),
        digest_of(ByteHash::Blake3, digests.concat())
    );
}

/// A three-digest node is the Blake3 of 96 bytes.
#[test]
fn native_blake3_host_compresses_three_digests() {
    type Host = NativeBinaryEncoding;
    type F = BinaryField128;
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_blake3_compress().unwrap();
    let input = b.alloc_public_input_array::<48>("three digests");
    let expected = b.alloc_public_input_array::<16>("compressed digest");
    let digests: Vec<&[ExprId]> = input.chunks(16).collect();
    let node =
        <Host as BinaryCircuitHost<F>>::compress_n(&mut b, ByteHash::Blake3, &digests).unwrap();
    for (&computed, &expected) in node.iter().zip(&expected) {
        b.connect(computed, expected);
    }
    let circuit = b.build().unwrap();
    let words: [u16; 48] =
        core::array::from_fn(|i| 0x2b47u16.wrapping_add((i as u16).wrapping_mul(977)));
    let digest = digest_of(
        ByteHash::Blake3,
        words.into_iter().flat_map(u16::to_le_bytes),
    );
    let mut public: Vec<F> = words
        .into_iter()
        .map(|word| <Host as BinaryCircuitEncoding<F>>::encode_u16(word).unwrap())
        .collect();
    public.extend(digest.as_chunks::<2>().0.iter().map(|pair| {
        <Host as BinaryCircuitEncoding<F>>::encode_u16(u16::from_le_bytes(*pair)).unwrap()
    }));
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    runner.run().unwrap();
    public[47] += F::ONE;
    let mut runner = circuit.runner();
    assert!(
        runner
            .set_public_inputs(&public)
            .and_then(|()| runner.run())
            .is_err()
    );
}

/// The host returns swapped digest limbs under Blake3 as under Keccak-256,
/// each the byte swap of its digest limb, without splitting the digest.
#[test]
fn native_blake3_host_returns_swapped_digest_limbs() {
    type Host = NativeBinaryEncoding;
    type F = BinaryField128;
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_blake3_compress().unwrap();
    let words = b.alloc_public_input_array::<20>("words");
    let bytes = b.alloc_public_input_array::<37>("bytes");
    let from_words =
        <Host as BinaryCircuitHost<F>>::hash_words_to_limbs(&mut b, ByteHash::Blake3, &words)
            .unwrap()
            .expect("Blake3 returns digest limbs");
    let from_bytes =
        <Host as BinaryCircuitHost<F>>::hash_bytes_to_limbs(&mut b, ByteHash::Blake3, &bytes)
            .unwrap()
            .expect("Blake3 returns digest limbs");
    let out = b.alloc_public_input_array::<64>("digest limbs");
    for i in 0..16 {
        b.connect(from_words.limbs[i], out[i]);
        b.connect(from_words.swapped[i], out[16 + i]);
        b.connect(from_bytes.limbs[i], out[32 + i]);
        b.connect(from_bytes.swapped[i], out[48 + i]);
    }
    let circuit = b.build().unwrap();

    let word_values: [u16; 20] =
        core::array::from_fn(|i| 0x71c3u16.wrapping_add((i as u16).wrapping_mul(1297)));
    let byte_values: [u8; 37] = core::array::from_fn(|i| (i * 29 + 5) as u8);
    let limbs_of = |digest: [u8; 32]| -> [u16; 16] {
        core::array::from_fn(|i| u16::from_le_bytes([digest[2 * i], digest[2 * i + 1]]))
    };
    let word_digest = limbs_of(digest_of(
        ByteHash::Blake3,
        word_values.into_iter().flat_map(u16::to_le_bytes),
    ));
    let byte_digest = limbs_of(digest_of(ByteHash::Blake3, byte_values));
    let encode = |value: u16| <Host as BinaryCircuitEncoding<F>>::encode_u16(value).unwrap();
    let mut public: Vec<F> = word_values.into_iter().map(encode).collect();
    public.extend(byte_values.into_iter().map(|byte| encode(byte.into())));
    for limbs in [word_digest, byte_digest] {
        public.extend(limbs.iter().map(|&limb| encode(limb)));
        public.extend(limbs.iter().map(|&limb| encode(limb.swap_bytes())));
    }
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    runner.run().unwrap();
    let last = public.len() - 1;
    public[last] += F::ONE;
    let mut runner = circuit.runner();
    assert!(
        runner
            .set_public_inputs(&public)
            .and_then(|()| runner.run())
            .is_err()
    );
}
