//! Native hash inputs and outputs use raw byte/limb coordinates.

use p3_binary_field::{BinaryField8, BinaryField128, Poly64};
use p3_circuit::ops::binary_encoding::NativeBinaryEncoding;
use p3_circuit::ops::binary_host::BinaryCircuitHost;
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::{ByteHash, bytes_to_limbs, keccak_state_to_limbs};
use p3_circuit::{CircuitBuilder, CircuitConstructionLimits};
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
