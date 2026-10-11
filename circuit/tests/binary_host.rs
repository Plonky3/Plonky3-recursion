//! Hash boundaries preserve natural bytes and low-first digest words.

use core::hash::Hash;

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField128, Poly64};
use p3_circuit::ops::ByteHash;
use p3_circuit::ops::binary_encoding::{NativeBinaryEncoding, PrimeBinaryEncoding};
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::{CircuitBuilder, ExprId};
use p3_field::Field;
use p3_keccak::Keccak256Hash;
use p3_symmetric::CryptographicHasher;

fn check<F: Field + Eq + Hash, H: BinaryCircuitHost<F>>(mut b: CircuitBuilder<F>) {
    let input = b.alloc_public_input_array::<32>("two digests");
    let expected = b.alloc_public_input_array::<16>("compressed digest");
    let actual = H::compress(&mut b, ByteHash::Keccak256, &input[..16], &input[16..]).unwrap();
    let hashed = H::hash_words(&mut b, ByteHash::Keccak256, &input).unwrap();
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
    assert!(H::compress(&mut b, ByteHash::Keccak256, &input[..15], &input[16..]).is_err());
    let circuit = b.build().unwrap();
    let input: [u16; 32] =
        core::array::from_fn(|i| 0x9123u16.wrapping_add((i as u16).wrapping_mul(1703)));
    let digest = Keccak256Hash.hash_iter(input.into_iter().flat_map(u16::to_le_bytes));
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
/// two-digest node is the pairwise compression. Returns the non-primitive calls
/// the four-digest node adds.
fn check_compress_n<F: Field + Eq + Hash, H: BinaryCircuitHost<F>>(
    mut b: CircuitBuilder<F>,
) -> usize {
    let input = b.alloc_public_input_array::<64>("four digests");
    let expected = b.alloc_public_input_array::<16>("compressed digest");
    let digests: Vec<&[ExprId]> = input.chunks(16).collect();
    let calls = b.construction_usage().unwrap().non_primitive_calls;
    let actual = H::compress_n(&mut b, ByteHash::Keccak256, &digests).unwrap();
    let node_calls = b.construction_usage().unwrap().non_primitive_calls - calls;
    let pair = H::compress_n(&mut b, ByteHash::Keccak256, &digests[..2]).unwrap();
    let compressed = H::compress(&mut b, ByteHash::Keccak256, digests[0], digests[1]).unwrap();
    for i in 0..16 {
        b.connect(actual[i], expected[i]);
        b.connect(pair[i], compressed[i]);
    }
    for malformed in [
        &[digests[0]; 5][..],
        &digests[..1],
        &[digests[0], &input[..15]],
    ] {
        assert!(H::compress_n(&mut b, ByteHash::Keccak256, malformed).is_err());
    }
    let circuit = b.build().unwrap();
    let input: [u16; 64] =
        core::array::from_fn(|i| 0x4c1du16.wrapping_add((i as u16).wrapping_mul(2741)));
    let digest = Keccak256Hash.hash_iter(input.into_iter().flat_map(u16::to_le_bytes));
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
    node_calls
}

/// A native four-digest node is a single Keccak-f call, as a pairwise node is,
/// which is what halves the hashing of an arity-4 authentication path.
#[test]
fn native_and_prime_hosts_compress_four_digests_in_one_keccak_block() {
    let mut b = CircuitBuilder::<BinaryField128>::new();
    b.enable_native_keccak_f1600().unwrap();
    assert_eq!(
        check_compress_n::<BinaryField128, NativeBinaryEncoding>(b),
        1
    );
    let mut b = CircuitBuilder::<Poly64>::new();
    b.enable_native_keccak_f1600().unwrap();
    assert_eq!(check_compress_n::<Poly64, NativeBinaryEncoding>(b), 1);
    let mut b = CircuitBuilder::<BabyBear>::new();
    b.enable_keccak_f1600::<BabyBear>();
    check_compress_n::<BabyBear, PrimeBinaryEncoding<BabyBear>>(b);
}

#[test]
fn native_and_prime_hosts_match_digest_compression_and_odd_byte_packing() {
    let mut b = CircuitBuilder::<BinaryField128>::new();
    b.enable_native_keccak_f1600().unwrap();
    check::<BinaryField128, NativeBinaryEncoding>(b);
    let mut b = CircuitBuilder::<Poly64>::new();
    b.enable_native_keccak_f1600().unwrap();
    check::<Poly64, NativeBinaryEncoding>(b);
    let mut b = CircuitBuilder::<BabyBear>::new();
    b.enable_keccak_f1600::<BabyBear>();
    check::<BabyBear, PrimeBinaryEncoding<BabyBear>>(b);
}
