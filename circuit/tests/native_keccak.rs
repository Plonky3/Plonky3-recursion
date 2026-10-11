//! Native hash inputs and outputs use raw byte/limb coordinates.

use p3_binary_field::{BinaryField8, BinaryField128, Poly64};
use p3_circuit::ops::binary_encoding::NativeBinaryEncoding;
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::{ByteHash, NpoTypeId, bytes_to_limbs, keccak_state_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder, CircuitConstructionLimits, ExprId, Op};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_symmetric::{CryptographicHasher, Permutation};

fn permutation<F: BinaryCoordinateField>() {
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_keccak_f1600().unwrap();
    let input = builder.alloc_public_input_array::<100>("state");
    let expected = builder.alloc_public_input_array::<100>("permuted state");
    let output = builder.add_native_keccak_f1600(&input).unwrap();
    for i in 0..100 {
        builder.connect(output[i], expected[i]);
    }
    let circuit = builder.build().unwrap();
    let input: [u64; 25] = core::array::from_fn(|i| 0xdead_beef_9876_5432u64.rotate_left(i as u32));
    let output = KeccakF.permute(input);
    let public: Vec<_> = [input, output]
        .into_iter()
        .flat_map(|state| keccak_state_to_limbs(&state))
        .map(|raw| F::from_raw_coordinates(raw as u128).unwrap())
        .collect();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    runner.run().unwrap();
    let mut wrong = public;
    wrong[199] += F::ONE;
    let mut runner = circuit.runner();
    assert!(
        runner
            .set_public_inputs(&wrong)
            .and_then(|()| runner.run())
            .is_err()
    );
}

#[test]
fn native_permutation_preserves_dense_coordinates_in_both_bases() {
    permutation::<BinaryField128>();
    permutation::<Poly64>();
}

#[test]
fn native_keccak256_handles_odd_lengths_padding_and_multiple_blocks() {
    for length in [0, 3, 135, 136, 137, 273] {
        let message: Vec<_> = (0..length).map(|i| (i * 31 + 7) as u8).collect();
        let digest = Keccak256Hash.hash_iter(message.iter().copied());
        let mut builder = CircuitBuilder::<BinaryField128>::new();
        builder.enable_native_keccak_f1600().unwrap();
        let bytes: Vec<_> = (0..length).map(|_| builder.public_input()).collect();
        let expected = builder.alloc_public_input_array::<32>("digest");
        let actual = builder.native_keccak256_bytes(&bytes).unwrap();
        for i in 0..32 {
            builder.connect(actual[i], expected[i]);
        }
        let circuit = builder.build().unwrap();
        let public: Vec<_> = message
            .iter()
            .chain(&digest)
            .map(|&byte| BinaryField128::from_raw_coordinates(byte as u128).unwrap())
            .collect();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public).unwrap();
        runner.run().unwrap();
        let mut wrong = public;
        *wrong.last_mut().unwrap() += BinaryField128::ONE;
        let mut runner = circuit.runner();
        assert!(
            runner
                .set_public_inputs(&wrong)
                .and_then(|()| runner.run())
                .is_err()
        );
    }
}

#[test]
fn native_hash_rejects_undersized_fields_and_noncanonical_limbs() {
    let mut small = CircuitBuilder::<BinaryField8>::new();
    assert!(small.enable_native_keccak_f1600().is_err());
    let mut builder = CircuitBuilder::<BinaryField128>::new();
    assert!(builder.add_native_keccak_f1600(&[]).is_err());
    let before = builder.construction_usage().unwrap();
    assert!(builder.native_keccak256_words(&[]).is_err());
    assert_eq!(
        builder.construction_usage().unwrap().expression_nodes,
        before.expression_nodes
    );
    builder.enable_native_keccak_f1600().unwrap();
    let input = builder.alloc_public_input_array::<100>("state");
    assert!(builder.add_native_keccak_f1600(&input[..99]).is_err());
    let _output = builder.add_native_keccak_f1600(&input).unwrap();
    let circuit = builder.build().unwrap();
    let mut public = vec![BinaryField128::ZERO; 100];
    public[3] = BinaryField128::from_raw_coordinates(1 << 16).unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    assert!(runner.run().is_err());
}

fn word_hash<F: BinaryCoordinateField>() {
    for length in [0, 1, 32, 67, 68, 69, 136, 137] {
        let message: Vec<_> = (0..length).map(|i| (i * 3127 + 179) as u16).collect();
        let digest = Keccak256Hash.hash_iter(message.iter().flat_map(|word| word.to_le_bytes()));
        let mut builder =
            CircuitBuilder::<F>::with_construction_limits(CircuitConstructionLimits {
                max_expression_nodes: 1024,
                max_pending_connects: 1024,
                max_non_primitive_calls: 3,
                max_non_primitive_slots: 2048,
            })
            .unwrap();
        builder.enable_native_keccak_f1600().unwrap();
        let words: Vec<_> = (0..length).map(|_| builder.public_input()).collect();
        let expected = builder.alloc_public_input_array::<16>("word digest");
        let actual = <NativeBinaryEncoding as BinaryCircuitHost<F>>::hash_words(
            &mut builder,
            ByteHash::Keccak256,
            &words,
        )
        .expect("word hashing must fit the bounded graph without byte conversions");
        for (actual, expected) in actual.into_iter().zip(expected) {
            builder.connect(actual, expected);
        }
        let circuit = builder.build().unwrap();
        let mut public: Vec<_> = message
            .iter()
            .copied()
            .chain(bytes_to_limbs(&digest))
            .map(|word| F::from_raw_coordinates(u128::from(word)).unwrap())
            .collect();
        let run = |public: &[F]| {
            let mut runner = circuit.runner();
            runner
                .set_public_inputs(public)
                .and_then(|()| runner.run())
                .is_ok()
        };
        assert!(run(&public), "word length {length}");
        let last = public.len() - 1;
        public[last] += F::ONE;
        assert!(!run(&public), "wrong digest at word length {length}");
        public[last] += F::ONE;
        if length != 0 {
            public[0] += F::from_raw_coordinates(1 << 16).unwrap();
            assert!(
                !run(&public),
                "high input coordinates at word length {length}"
            );
        }
    }
}

#[test]
fn native_word_hashes_fit_small_graphs_and_match_byte_serialization() {
    word_hash::<BinaryField128>();
    word_hash::<Poly64>();
}

fn keccak_calls<F: BinaryCoordinateField>(circuit: &Circuit<F>) -> usize {
    circuit
        .ops
        .iter()
        .filter(|op| {
            matches!(op, Op::NonPrimitiveOpWithExecutor { executor, .. }
                if executor.op_type() == &NpoTypeId::native_keccak_f1600())
        })
        .count()
}

/// Builds `message`, whose first `constant` units are circuit constants and
/// the rest public inputs, hashes it with `hash`, and binds the digest units
/// to public inputs. The circuit must accept the true digest and reject a
/// changed digest or a changed public unit.
fn prefix_sponge<F: BinaryCoordinateField>(
    message: &[u16],
    constant: usize,
    digest: &[u16],
    hash: impl Fn(&mut CircuitBuilder<F>, &[ExprId]) -> Vec<ExprId>,
) -> Circuit<F> {
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_keccak_f1600().unwrap();
    let units: Vec<_> = message
        .iter()
        .enumerate()
        .map(|(i, &unit)| {
            if i < constant {
                builder.define_const(F::from_raw_coordinates(u128::from(unit)).unwrap())
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
    let encode = |units: &[u16]| -> Vec<F> {
        units
            .iter()
            .map(|&unit| F::from_raw_coordinates(u128::from(unit)).unwrap())
            .collect()
    };
    let run = |message: &[u16], digest: &[u16]| {
        let mut public = encode(&message[constant..]);
        public.extend(encode(digest));
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&public)
            .and_then(|()| runner.run())
            .is_ok()
    };
    assert!(run(message, digest));
    let mut wrong = digest.to_vec();
    wrong[digest.len() - 1] ^= 1;
    assert!(!run(message, &wrong));
    if constant < message.len() {
        let mut wrong = message.to_vec();
        wrong[constant] ^= 1;
        assert!(!run(&wrong, digest));
    }
    circuit
}

/// A message whose leading full rate blocks are circuit constants absorbs
/// them out of circuit: only blocks from the first public unit on, padding
/// included, are native Keccak-f calls, and a fully constant message needs
/// none. The digest equals Keccak-256 of the whole message, which binds every
/// lane of the precomputed state, for constant prefixes on both sides of each
/// block boundary, with byte and word absorption, in both carriers.
fn constant_prefix_sponges<F: BinaryCoordinateField>() {
    const RATE: usize = 136;
    for constant in [0, 1, 135, 136, 137, 271, 272, 273, 408, 409] {
        for public in [0, 1, 2, 134, 135, 136, 137] {
            let message: Vec<u8> = (0..constant + public)
                .map(|i| (i * 89 + 13) as u8)
                .collect();
            let digest = Keccak256Hash.hash_iter(message.iter().copied());
            let circuit = prefix_sponge::<F>(
                &message
                    .iter()
                    .map(|&byte| u16::from(byte))
                    .collect::<Vec<_>>(),
                constant,
                &digest.map(u16::from),
                |builder, bytes| builder.native_keccak256_bytes(bytes).unwrap().to_vec(),
            );
            let blocks = message.len() / RATE + 1;
            let calls = if public == 0 {
                0
            } else {
                blocks - constant / RATE
            };
            assert_eq!(keccak_calls(&circuit), calls, "{constant} + {public} bytes");
        }
    }
    for constant in [0, 1, 67, 68, 69, 135, 136, 137, 204] {
        for public in [0, 1, 66, 67, 68, 69] {
            let message: Vec<u16> = (0..constant + public)
                .map(|i| (i * 3127 + 179) as u16)
                .collect();
            let digest =
                Keccak256Hash.hash_iter(message.iter().flat_map(|word| word.to_le_bytes()));
            let circuit = prefix_sponge::<F>(
                &message,
                constant,
                &bytes_to_limbs(&digest),
                |builder, words| {
                    <NativeBinaryEncoding as BinaryCircuitHost<F>>::hash_words(
                        builder,
                        ByteHash::Keccak256,
                        words,
                    )
                    .unwrap()
                },
            );
            let blocks = 2 * message.len() / RATE + 1;
            let calls = if public == 0 {
                0
            } else {
                blocks - 2 * constant / RATE
            };
            assert_eq!(keccak_calls(&circuit), calls, "{constant} + {public} words");
        }
    }
}

#[test]
fn native_sponges_absorb_constant_leading_blocks_out_of_circuit() {
    constant_prefix_sponges::<BinaryField128>();
    constant_prefix_sponges::<Poly64>();
}

/// A constant word wider than sixteen coordinates in an otherwise constant
/// leading block is not absorbed out of circuit, so the native Keccak-f
/// check on its lane still rejects the message.
#[test]
fn native_word_sponge_keeps_wide_constant_words_in_circuit() {
    let mut builder = CircuitBuilder::<BinaryField128>::new();
    builder.enable_native_keccak_f1600().unwrap();
    let mut words: Vec<_> = (0..68)
        .map(|i| builder.define_const(BinaryField128::from_raw_coordinates(i * 977 + 5).unwrap()))
        .collect();
    words[7] = builder.define_const(BinaryField128::from_raw_coordinates(1 << 16).unwrap());
    words.push(builder.public_input());
    builder.native_keccak256_words(&words).unwrap();
    let circuit = builder.build().unwrap();
    assert_eq!(keccak_calls(&circuit), 2);
    let mut runner = circuit.runner();
    runner.set_public_inputs(&[BinaryField128::ONE]).unwrap();
    assert!(runner.run().is_err());
}

/// Native Keccak-f calls whose outputs include the swapped digest limbs.
fn swapped_digest_calls<F: BinaryCoordinateField>(circuit: &Circuit<F>) -> usize {
    circuit
        .ops
        .iter()
        .filter(|op| {
            matches!(op, Op::NonPrimitiveOpWithExecutor { outputs, .. }
                if outputs[0].len() == 116)
        })
        .count()
}

/// The digest limbs followed by the little-endian words of the digest bytes
/// read from the end: the word drawn `k`-th is bytes `31 - 2k` and `30 - 2k`,
/// which is digest limb `15 - k` with its two bytes swapped.
fn limbs_and_swapped(digest: &[u8; 32]) -> Vec<u16> {
    let mut units = bytes_to_limbs(digest).to_vec();
    let mut swapped: Vec<u16> = digest
        .iter()
        .rev()
        .copied()
        .collect::<Vec<_>>()
        .chunks(2)
        .map(|pair| u16::from_le_bytes([pair[0], pair[1]]))
        .collect();
    swapped.reverse();
    units.extend(swapped);
    units
}

/// The swapped-digest sponges hash like the plain ones and also return each
/// digest limb with its bytes swapped. Only the final Keccak-f call exposes
/// them; a fully constant message has constant swapped limbs and no call.
fn swapped_digest_sponges<F: BinaryCoordinateField>() {
    const RATE: usize = 136;
    for constant in [0, 136, 137] {
        for public in [0, 1, 135] {
            let message: Vec<u8> = (0..constant + public)
                .map(|i| (i * 53 + 29) as u8)
                .collect();
            let digest = Keccak256Hash.hash_iter(message.iter().copied());
            let circuit = prefix_sponge::<F>(
                &message
                    .iter()
                    .map(|&byte| u16::from(byte))
                    .collect::<Vec<_>>(),
                constant,
                &limbs_and_swapped(&digest),
                |builder, bytes| {
                    let (limbs, swapped) = builder
                        .native_keccak256_bytes_with_swapped_digest(bytes)
                        .unwrap();
                    [limbs, swapped].concat()
                },
            );
            let calls = if public == 0 {
                0
            } else {
                message.len() / RATE + 1 - constant / RATE
            };
            assert_eq!(keccak_calls(&circuit), calls, "{constant} + {public} bytes");
            assert_eq!(swapped_digest_calls(&circuit), calls.min(1));
        }
    }
    for constant in [0, 68, 69] {
        for public in [0, 1, 67] {
            let message: Vec<u16> = (0..constant + public)
                .map(|i| (i * 2909 + 61) as u16)
                .collect();
            let digest =
                Keccak256Hash.hash_iter(message.iter().flat_map(|word| word.to_le_bytes()));
            let circuit = prefix_sponge::<F>(
                &message,
                constant,
                &limbs_and_swapped(&digest),
                |builder, words| {
                    let (limbs, swapped) = builder
                        .native_keccak256_words_with_swapped_digest(words)
                        .unwrap();
                    [limbs, swapped].concat()
                },
            );
            let calls = if public == 0 {
                0
            } else {
                2 * message.len() / RATE + 1 - 2 * constant / RATE
            };
            assert_eq!(keccak_calls(&circuit), calls, "{constant} + {public} words");
            assert_eq!(swapped_digest_calls(&circuit), calls.min(1));
        }
    }
}

#[test]
fn native_sponges_return_the_byte_swapped_digest_limbs() {
    swapped_digest_sponges::<BinaryField128>();
    swapped_digest_sponges::<Poly64>();
}
