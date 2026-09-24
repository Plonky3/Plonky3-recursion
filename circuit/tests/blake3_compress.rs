//! The BLAKE3 compression non-primitive operation executes exactly the native compression.

use p3_baby_bear::BabyBear;
use p3_blake3::Blake3;
use p3_circuit::ops::{
    BLAKE3_INPUT_LIMBS, BLAKE3_INPUT_WORDS, BLAKE3_IV, BLAKE3_OUTPUT_LIMBS, blake3_compress,
    blake3_flags, limbs_to_words, words_to_limbs,
};
use p3_circuit::{CircuitBuilder, CircuitBuilderError, CircuitError, ExprId};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, ExtensionField, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_symmetric::CryptographicHasher;

type EF4 = BinomialExtensionField<BabyBear, 4>;
type EF2 = BinomialExtensionField<Goldilocks, 2>;

/// The compression input that hashes a message of at most 64 bytes: one chunk, one block, root.
fn single_block_input(message: &[u8]) -> [u32; BLAKE3_INPUT_WORDS] {
    assert!(message.len() <= 64);
    let mut block = [0u8; 64];
    block[..message.len()].copy_from_slice(message);
    let mut input = [0u32; BLAKE3_INPUT_WORDS];
    for (word, bytes) in input.iter_mut().zip(block.chunks_exact(4)) {
        *word = u32::from_le_bytes(bytes.try_into().unwrap());
    }
    input[16..24].copy_from_slice(&BLAKE3_IV);
    input[26] = message.len() as u32;
    input[27] = blake3_flags::CHUNK_START | blake3_flags::CHUNK_END | blake3_flags::ROOT;
    input
}

#[test]
fn native_compression_hashes_single_block_messages_like_blake3() {
    for len in [0usize, 1, 31, 32, 63, 64] {
        let message: Vec<u8> = (0..len).map(|i| (i * 13 + 5) as u8).collect();
        let output = blake3_compress(&single_block_input(&message));
        let digest: Vec<u8> = output[..8].iter().flat_map(|w| w.to_le_bytes()).collect();
        assert_eq!(
            digest,
            Blake3.hash_iter(message.iter().copied()),
            "message of {len} bytes"
        );
    }
}

fn compressions_match_native<BF, F>()
where
    BF: PrimeField64,
    F: ExtensionField<BF> + Eq + core::hash::Hash,
{
    let first = single_block_input(b"plonky3 recursion");
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_blake3_compress::<BF>();
    let inputs: Vec<ExprId> = (0..BLAKE3_INPUT_LIMBS)
        .map(|_| builder.public_input())
        .collect();
    let out = builder.add_blake3_compress(&inputs).unwrap();
    for (i, &limb) in out.iter().enumerate() {
        builder.tag(limb, format!("out_{i}")).unwrap();
    }
    let circuit = builder.build().unwrap();

    let mut runner = circuit.runner();
    let public: Vec<F> = words_to_limbs(&first)
        .into_iter()
        .map(F::from_u16)
        .collect();
    runner.set_public_inputs(&public).unwrap();
    let traces = runner.run().unwrap();

    let limbs: Vec<u16> = (0..BLAKE3_OUTPUT_LIMBS)
        .map(|i| {
            let value = traces.probe(&format!("out_{i}")).unwrap();
            let coeffs = <F as BasedVectorSpace<BF>>::as_basis_coefficients_slice(value);
            u16::try_from(coeffs[0].as_canonical_u64()).unwrap()
        })
        .collect();
    assert_eq!(limbs_to_words(&limbs), blake3_compress(&first));
}

#[test]
fn compressions_match_native_over_baby_bear_quartic() {
    compressions_match_native::<BabyBear, EF4>();
}

#[test]
fn compressions_match_native_over_goldilocks_quadratic() {
    compressions_match_native::<Goldilocks, EF2>();
}

#[test]
fn a_limb_of_sixteen_bits_or_more_is_rejected() {
    let mut builder = CircuitBuilder::<EF4>::new();
    builder.enable_blake3_compress::<BabyBear>();
    let inputs: Vec<ExprId> = (0..BLAKE3_INPUT_LIMBS)
        .map(|_| builder.public_input())
        .collect();
    builder.add_blake3_compress(&inputs).unwrap();
    let circuit = builder.build().unwrap();

    let mut values: Vec<EF4> = words_to_limbs(&single_block_input(b""))
        .into_iter()
        .map(EF4::from_u16)
        .collect();
    values[3] = EF4::from_u32(1 << 16);
    let mut runner = circuit.runner();
    runner.set_public_inputs(&values).unwrap();
    assert!(matches!(
        runner.run(),
        Err(CircuitError::InvalidNonPrimitiveOpInput { .. })
    ));
}

#[test]
fn the_operation_must_be_enabled_and_take_a_full_input() {
    let mut builder = CircuitBuilder::<EF4>::new();
    let inputs: Vec<ExprId> = (0..BLAKE3_INPUT_LIMBS)
        .map(|_| builder.public_input())
        .collect();
    assert!(matches!(
        builder.add_blake3_compress(&inputs),
        Err(CircuitBuilderError::OpNotAllowed { .. })
    ));
    builder.enable_blake3_compress::<BabyBear>();
    assert!(matches!(
        builder.add_blake3_compress(&inputs[1..]),
        Err(CircuitBuilderError::NonPrimitiveOpArity { .. })
    ));
}
