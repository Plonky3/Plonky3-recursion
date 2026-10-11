//! Native BLAKE3 hashing of bytes and words equals the reference hash, and only
//! compressions whose chaining value and block are not constants below the limb
//! width become native calls.

use p3_binary_field::{BinaryField128, Poly64};
use p3_blake3::Blake3;
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::{NpoTypeId, bytes_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder, CircuitBuilderError, CircuitError, ExprId, Op};
use p3_symmetric::CryptographicHasher;

fn raw<F: BinaryCoordinateField>(unit: u16) -> F {
    F::from_raw_coordinates(unit.into()).unwrap()
}

fn blake3_calls<F: BinaryCoordinateField>(circuit: &Circuit<F>) -> usize {
    circuit
        .ops
        .iter()
        .filter(|op| {
            matches!(op, Op::NonPrimitiveOpWithExecutor { executor, .. }
                if executor.op_type() == &NpoTypeId::native_blake3_compress())
        })
        .count()
}

fn run<F: BinaryCoordinateField>(circuit: &Circuit<F>, public: &[F]) -> Result<(), CircuitError> {
    let mut runner = circuit.runner();
    runner.set_public_inputs(public)?;
    runner.run().map(|_| ())
}

/// Hashes `message`, whose units at `is_constant` positions are circuit
/// constants and the rest public inputs, and binds the digest units to public
/// inputs. The circuit must accept the reference `digest` and reject a changed
/// digest unit or a changed public message unit.
fn hash_circuit<F: BinaryCoordinateField>(
    message: &[u16],
    is_constant: impl Fn(usize) -> bool,
    digest: &[u16],
    hash: impl Fn(&mut CircuitBuilder<F>, &[ExprId]) -> Vec<ExprId>,
) -> Circuit<F> {
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_blake3_compress().unwrap();
    let units: Vec<_> = message
        .iter()
        .enumerate()
        .map(|(i, &unit)| {
            if is_constant(i) {
                builder.define_const(raw(unit))
            } else {
                builder.public_input()
            }
        })
        .collect();
    let actual = hash(&mut builder, &units);
    assert_eq!(actual.len(), digest.len());
    for actual in actual {
        let expected = builder.public_input();
        builder.connect(actual, expected);
    }
    let circuit = builder.build().unwrap();
    let public = |message: &[u16], digest: &[u16]| -> Vec<F> {
        message
            .iter()
            .enumerate()
            .filter(|&(i, _)| !is_constant(i))
            .map(|(_, &unit)| unit)
            .chain(digest.iter().copied())
            .map(raw)
            .collect()
    };
    run(&circuit, &public(message, digest))
        .unwrap_or_else(|e| panic!("{} units: {e:?}", message.len()));
    let mut wrong = digest.to_vec();
    *wrong.last_mut().unwrap() ^= 1;
    assert!(run(&circuit, &public(message, &wrong)).is_err());
    if let Some(first) = (0..message.len()).find(|&i| !is_constant(i)) {
        let mut wrong = message.to_vec();
        wrong[first] ^= 1;
        assert!(run(&circuit, &public(&wrong, digest)).is_err());
    }
    circuit
}

fn bytes_message(len: usize) -> Vec<u8> {
    (0..len).map(|i| (i * 89 + 13) as u8).collect()
}

/// Builds the byte hash of `message` with `is_constant` bytes as constants and
/// returns its native call count.
fn byte_hash_calls<F: BinaryCoordinateField>(
    message: &[u8],
    is_constant: impl Fn(usize) -> bool,
) -> usize {
    let digest = Blake3.hash_slice(message);
    let circuit = hash_circuit::<F>(
        &message
            .iter()
            .map(|&byte| u16::from(byte))
            .collect::<Vec<_>>(),
        is_constant,
        &digest.map(u16::from),
        |builder, bytes| builder.native_blake3_bytes(bytes).unwrap().to_vec(),
    );
    blake3_calls(&circuit)
}

/// Lengths on both sides of the block and chunk boundaries, odd lengths with
/// a zero-paired last byte, and trees of two to five chunks, the last of
/// which is partial.
fn byte_hashes<F: BinaryCoordinateField>() {
    for len in [
        0, 1, 2, 31, 32, 33, 63, 64, 65, 127, 128, 255, 256, 1023, 1024, 1025, 2047, 2048, 2049,
        3073, 4096, 5000,
    ] {
        byte_hash_calls::<F>(&bytes_message(len), |_| false);
    }
}

#[test]
fn byte_hashes_match_blake3_in_both_bases() {
    byte_hashes::<BinaryField128>();
    byte_hashes::<Poly64>();
}

/// Words are serialized as little-endian byte pairs: 32 words are one Merkle
/// node of two digests, and 512 words are one full chunk.
fn word_hashes<F: BinaryCoordinateField>() {
    for len in [0, 1, 32, 128, 512, 513, 2500] {
        let message: Vec<u16> = (0..len).map(|i| (i * 3127 + 179) as u16).collect();
        let digest = Blake3.hash_iter(message.iter().flat_map(|word| word.to_le_bytes()));
        hash_circuit::<F>(
            &message,
            |_| false,
            &bytes_to_limbs(&digest),
            |b, words| b.native_blake3_words(words).unwrap().to_vec(),
        );
    }
}

#[test]
fn word_hashes_match_blake3_of_little_endian_pairs_in_both_bases() {
    word_hashes::<BinaryField128>();
    word_hashes::<Poly64>();
}

/// Each compression whose chaining value and block are known while building
/// is computed natively, so it costs no call; the digest still equals BLAKE3
/// of the whole message.
fn constant_folding<F: BinaryCoordinateField>() {
    // 3073 bytes are four chunks: three full chunks of 16 blocks and a
    // 1-byte chunk of 1 block. The tree is parent(parent(0, 1), parent(2, 3)),
    // so 16 + 16 + 16 + 1 blocks and 3 parents make 52 calls.
    let message = bytes_message(3073);
    assert_eq!(byte_hash_calls::<F>(&message, |_| false), 52);
    // Constant chunk 1 is known: its 16 blocks are folded, but its parent with
    // the wired chunk 0 stays a call. 52 - 16 = 36.
    let chunk_1 = |i: usize| (1024..2048).contains(&i);
    assert_eq!(byte_hash_calls::<F>(&message, chunk_1), 36);
    // Constant chunk 2, the last full chunk: likewise 52 - 16 = 36.
    let chunk_2 = |i: usize| (2048..3072).contains(&i);
    assert_eq!(byte_hash_calls::<F>(&message, chunk_2), 36);
    // Constant chunks 0 and 1 fold their 32 blocks and their known parent,
    // which enters the wired root as a constant block half. 52 - 33 = 19.
    assert_eq!(byte_hash_calls::<F>(&message, |i| i < 2048), 19);
    // All constant: every block and parent is folded, and the digest is a
    // constant.
    assert_eq!(byte_hash_calls::<F>(&message, |_| true), 0);
    // A single 1024-byte chunk of 16 blocks whose first 15 blocks and next 40
    // bytes are constant: the 15 leading blocks fold, and block 15 mixes
    // constant and public bytes, so 16 - 15 = 1 call. With 1001 constant
    // bytes, byte 1000 pairs a constant with a public byte.
    let message = bytes_message(1024);
    for constant in [1000, 1001] {
        assert_eq!(byte_hash_calls::<F>(&message, |i| i < constant), 1);
    }
    // Words: 1100 words are a full chunk of 16 blocks, a full chunk and a
    // 76-word chunk of 3 blocks, under parent(parent(0, 1), 2): 35 blocks and
    // 2 parents. A constant first chunk folds its 16 blocks: 37 - 16 = 21.
    let words: Vec<u16> = (0..1100).map(|i| (i * 3127 + 179) as u16).collect();
    let digest = Blake3.hash_iter(words.iter().flat_map(|word| word.to_le_bytes()));
    let circuit = hash_circuit::<F>(
        &words,
        |i| i < 512,
        &bytes_to_limbs(&digest),
        |b, w| b.native_blake3_words(w).unwrap().to_vec(),
    );
    assert_eq!(blake3_calls(&circuit), 21);
}

#[test]
fn known_chaining_values_are_folded_while_building() {
    constant_folding::<BinaryField128>();
    constant_folding::<Poly64>();
}

/// A fully constant message needs no call, and its digest units are the very
/// constants of the reference digest. Hashing it adds no node but those digest
/// constants: no folded block, chaining value or byte pair is left behind as
/// an unread constant.
fn constant_digests<F: BinaryCoordinateField>() {
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_blake3_compress().unwrap();
    let message = bytes_message(3073);
    let bytes: Vec<_> = message
        .iter()
        .map(|&byte| builder.define_const(raw(byte.into())))
        .collect();
    let nodes =
        |builder: &CircuitBuilder<F>| builder.construction_usage().unwrap().expression_nodes;
    let before = nodes(&builder);
    let digest = builder.native_blake3_bytes(&bytes).unwrap();
    assert!(nodes(&builder) - before <= 32);
    for (actual, expected) in digest.into_iter().zip(Blake3.hash_slice(&message)) {
        assert_eq!(actual, builder.define_const(raw(expected.into())));
    }
    let words: Vec<u16> = (0..600).map(|i| (i * 3127 + 179) as u16).collect();
    let constant: Vec<_> = words
        .iter()
        .map(|&word| builder.define_const(raw(word)))
        .collect();
    let before = nodes(&builder);
    let digest = builder.native_blake3_words(&constant).unwrap();
    assert!(nodes(&builder) - before <= 16);
    let expected = Blake3.hash_iter(words.iter().flat_map(|word| word.to_le_bytes()));
    for (actual, expected) in digest.into_iter().zip(bytes_to_limbs(&expected)) {
        assert_eq!(actual, builder.define_const(raw(expected)));
    }
    let circuit = builder.build().unwrap();
    assert_eq!(blake3_calls(&circuit), 0);
    run(&circuit, &[]).unwrap();
}

#[test]
fn constant_messages_have_constant_digests() {
    constant_digests::<BinaryField128>();
    constant_digests::<Poly64>();
}

/// A constant word wider than sixteen coordinates in an otherwise constant
/// message is never folded: its block stays a native call, which rejects it.
fn wide_constant_word<F: BinaryCoordinateField>() {
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_blake3_compress().unwrap();
    let mut words: Vec<_> = (0..64u16)
        .map(|i| builder.define_const(raw(i * 977 + 5)))
        .collect();
    words[40] = builder.define_const(F::from_raw_coordinates(0x1_0000).unwrap());
    builder.native_blake3_words(&words).unwrap();
    let circuit = builder.build().unwrap();
    // Block 0 is folded; block 1 holds the wide word and is the only call.
    assert_eq!(blake3_calls(&circuit), 1);
    let err = run(&circuit, &[]).unwrap_err();
    assert!(
        matches!(err, CircuitError::InvalidNonPrimitiveOpInput { .. }),
        "{err:?}"
    );
}

#[test]
fn wide_constant_words_stay_in_native_calls() {
    wide_constant_word::<BinaryField128>();
    wide_constant_word::<Poly64>();
}

/// Bytes [0x00, 0x01] and [0x100, 0x00] pack to the same limb, so a byte
/// witness of 0x100 must be rejected by its eight-coordinate range check even
/// with the digest of the honest message, and a constant byte of 0x100 must
/// not become a constant limb.
fn byte_range_check<F: BinaryCoordinateField>() {
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_blake3_compress().unwrap();
    let bytes = [builder.public_input(), builder.public_input()];
    let digest = builder.native_blake3_bytes(&bytes).unwrap();
    for actual in digest {
        let expected = builder.public_input();
        builder.connect(actual, expected);
    }
    let circuit = builder.build().unwrap();
    let digest = Blake3.hash_slice(&[0x00, 0x01]).map(u16::from);
    let public =
        |message: [u16; 2]| -> Vec<F> { message.into_iter().chain(digest).map(raw).collect() };
    run(&circuit, &public([0x00, 0x01])).unwrap();
    assert!(run(&circuit, &public([0x100, 0x00])).is_err());

    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_blake3_compress().unwrap();
    let bytes = [builder.define_const(raw(0x100)), ExprId::ZERO];
    let err = builder.native_blake3_bytes(&bytes).unwrap_err();
    assert!(
        matches!(
            err,
            CircuitBuilderError::InvalidDimension { expected: 8, .. }
        ),
        "{err:?}"
    );
}

#[test]
fn byte_witnesses_wider_than_eight_coordinates_are_rejected() {
    byte_range_check::<BinaryField128>();
    byte_range_check::<Poly64>();
}

#[test]
fn hashing_requires_the_enabled_operation() {
    let mut builder = CircuitBuilder::<BinaryField128>::new();
    let before = builder.construction_usage().unwrap();
    let not_allowed = |err: CircuitBuilderError| matches!(err, CircuitBuilderError::OpNotAllowed { ref op } if *op == NpoTypeId::native_blake3_compress());
    for message in [&[][..], &[ExprId::ZERO][..]] {
        assert!(not_allowed(
            builder.native_blake3_words(message).unwrap_err()
        ));
        assert!(not_allowed(
            builder.native_blake3_bytes(message).unwrap_err()
        ));
    }
    assert_eq!(
        builder.construction_usage().unwrap().expression_nodes,
        before.expression_nodes
    );
}
