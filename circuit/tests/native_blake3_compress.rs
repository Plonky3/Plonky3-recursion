//! The native BLAKE3 compression operation executes exactly the reference compression
//! over raw 16-bit binary-coordinate limbs.

use p3_binary_field::{BinaryField8, BinaryField128, Poly64};
use p3_blake3::Blake3;
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::{
    BLAKE3_INPUT_LIMBS, BLAKE3_INPUT_WORDS, BLAKE3_IV, NpoTypeId, blake3_compress, blake3_flags,
    words_to_limbs,
};
use p3_circuit::{CircuitBuilder, CircuitBuilderError, CircuitError, ExprId};
use p3_symmetric::CryptographicHasher;

fn raw<F: BinaryCoordinateField>(limbs: &[u16]) -> Vec<F> {
    limbs
        .iter()
        .map(|&limb| F::from_raw_coordinates(limb.into()).unwrap())
        .collect()
}

/// Builds a circuit with the compression's inputs and expected outputs as public inputs,
/// and connects the outputs to the expected values.
fn compression_circuit<F: BinaryCoordinateField>() -> p3_circuit::Circuit<F> {
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_blake3_compress().unwrap();
    let inputs: Vec<ExprId> = (0..BLAKE3_INPUT_LIMBS)
        .map(|_| builder.public_input())
        .collect();
    let expected = builder.alloc_public_input_array::<16>("chaining value");
    let output = builder.add_native_blake3_compress(&inputs).unwrap();
    for (actual, expected) in output.into_iter().zip(expected) {
        builder.connect(actual, expected);
    }
    builder.build().unwrap()
}

fn run<F: BinaryCoordinateField>(
    circuit: &p3_circuit::Circuit<F>,
    public: &[F],
) -> Result<(), CircuitError> {
    let mut runner = circuit.runner();
    runner.set_public_inputs(public)?;
    runner.run().map(|_| ())
}

fn pseudo_random_input(seed: u32) -> [u32; BLAKE3_INPUT_WORDS] {
    core::array::from_fn(|i| {
        (i as u32 + 1)
            .wrapping_mul(0x9E37_79B1)
            .rotate_left(seed % 31)
            ^ seed.wrapping_mul(0x85EB_CA6B)
    })
}

fn matches_reference<F: BinaryCoordinateField>() {
    let circuit = compression_circuit::<F>();
    for seed in 0..8 {
        let input = pseudo_random_input(seed);
        let output = blake3_compress(&input);
        let public: Vec<F> = raw(&words_to_limbs(&input))
            .into_iter()
            .chain(raw(&words_to_limbs(&output[..8])))
            .collect();
        run(&circuit, &public).unwrap();
        let mut wrong = public;
        *wrong.last_mut().unwrap() += F::ONE;
        assert!(run(&circuit, &wrong).is_err());
    }
}

#[test]
fn chaining_value_matches_the_reference_compression_in_both_bases() {
    matches_reference::<BinaryField128>();
    matches_reference::<Poly64>();
}

fn single_block_input(message: &[u8]) -> [u32; BLAKE3_INPUT_WORDS] {
    let mut block = [0u8; 64];
    block[..message.len()].copy_from_slice(message);
    let mut input = [0u32; BLAKE3_INPUT_WORDS];
    for (word, bytes) in input.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_le_bytes(*bytes);
    }
    input[16..24].copy_from_slice(&BLAKE3_IV);
    input[26] = message.len() as u32;
    input[27] = blake3_flags::CHUNK_START | blake3_flags::CHUNK_END | blake3_flags::ROOT;
    input
}

fn hashes_single_block_messages<F: BinaryCoordinateField>() {
    let circuit = compression_circuit::<F>();
    for len in 0..=64usize {
        let message: Vec<u8> = (0..len).map(|i| (i * 29 + 3) as u8).collect();
        let digest = Blake3.hash_iter(message.iter().copied());
        let digest_limbs: Vec<u16> = digest
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes(*pair))
            .collect();
        let public: Vec<F> = raw(&words_to_limbs(&single_block_input(&message)))
            .into_iter()
            .chain(raw(&digest_limbs))
            .collect();
        run(&circuit, &public).unwrap_or_else(|e| panic!("{len} bytes: {e:?}"));
    }
}

#[test]
fn single_block_outputs_are_the_blake3_digest() {
    hashes_single_block_messages::<BinaryField128>();
    hashes_single_block_messages::<Poly64>();
}

#[test]
fn a_limb_wider_than_sixteen_coordinates_is_rejected() {
    let circuit = compression_circuit::<BinaryField128>();
    let mut public: Vec<BinaryField128> = raw(&[0u16; BLAKE3_INPUT_LIMBS + 16]);
    public[5] = BinaryField128::from_raw_coordinates(0x1_0000).unwrap();
    let err = run(&circuit, &public).unwrap_err();
    assert!(
        matches!(err, CircuitError::InvalidNonPrimitiveOpInput { .. }),
        "{err:?}"
    );
}

#[test]
fn wrong_arity_is_rejected_before_any_state_changes() {
    let mut builder = CircuitBuilder::<BinaryField128>::new();
    builder.enable_native_blake3_compress().unwrap();
    let inputs: Vec<ExprId> = (0..BLAKE3_INPUT_LIMBS + 1)
        .map(|_| builder.public_input())
        .collect();
    let before = builder.construction_usage().unwrap();
    for len in [BLAKE3_INPUT_LIMBS - 1, BLAKE3_INPUT_LIMBS + 1] {
        let err = builder
            .add_native_blake3_compress(&inputs[..len])
            .unwrap_err();
        assert!(matches!(
            err,
            CircuitBuilderError::NonPrimitiveOpArity { .. }
        ));
    }
    let after = builder.construction_usage().unwrap();
    assert_eq!(after.non_primitive_calls, before.non_primitive_calls);
    assert_eq!(after.non_primitive_slots, before.non_primitive_slots);
}

#[test]
fn a_carrier_narrower_than_a_limb_is_rejected() {
    let mut builder = CircuitBuilder::<BinaryField8>::new();
    let err = builder.enable_native_blake3_compress().unwrap_err();
    assert!(
        matches!(
            err,
            CircuitBuilderError::InvalidDimension {
                expected: 16,
                actual: 8
            }
        ),
        "{err:?}"
    );
    let inputs: Vec<ExprId> = (0..BLAKE3_INPUT_LIMBS)
        .map(|_| builder.public_input())
        .collect();
    assert!(matches!(
        builder.add_native_blake3_compress(&inputs).unwrap_err(),
        CircuitBuilderError::InvalidDimension { .. }
    ));
}

#[test]
fn the_operation_must_be_enabled() {
    let mut builder = CircuitBuilder::<BinaryField128>::new();
    let inputs: Vec<ExprId> = (0..BLAKE3_INPUT_LIMBS)
        .map(|_| builder.public_input())
        .collect();
    let err = builder.add_native_blake3_compress(&inputs).unwrap_err();
    assert!(
        matches!(err, CircuitBuilderError::OpNotAllowed { ref op } if *op == NpoTypeId::native_blake3_compress()),
        "{err:?}"
    );
}
