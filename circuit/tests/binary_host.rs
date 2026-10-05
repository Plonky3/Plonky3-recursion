//! Hash boundaries preserve natural bytes and low-first digest words.

use core::hash::Hash;
use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField128, Poly64};
use p3_circuit::{
    CircuitBuilder, ExprId,
    ops::{
        ByteHash,
        binary_encoding::{NativeBinaryEncoding, PrimeBinaryEncoding},
        binary_host::BinaryCircuitHost,
    },
};
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
            .chunks_exact(2)
            .map(|pair| H::encode_u16(u16::from_le_bytes(pair.try_into().unwrap())).unwrap()),
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
