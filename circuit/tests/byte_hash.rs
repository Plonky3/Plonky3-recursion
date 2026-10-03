//! Byte-exact hash inputs, including partial limbs, blocks, and BLAKE3 chunks.

use p3_baby_bear::BabyBear;
use p3_blake3::Blake3;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{ByteHash, bytes_to_limbs};
use p3_commit::Mmcs;
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::BinomialExtensionField;
use p3_keccak::Keccak256Hash;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_symmetric::CryptographicHasher;
use p3_test_utils::binary_field_params::{BinaryField8, TowerLevel, blake3, keccak};

type EF = BinomialExtensionField<BabyBear, 4>;

fn circuit(hash: ByteHash, message: &[u8]) -> p3_circuit::Circuit<EF> {
    let mut builder = CircuitBuilder::<EF>::new();
    match hash {
        ByteHash::Keccak256 => builder.enable_keccak_f1600::<BabyBear>(),
        ByteHash::Blake3 => builder.enable_blake3_compress::<BabyBear>(),
    }
    let bytes: Vec<_> = message.iter().map(|_| builder.public_input()).collect();
    let digest = builder.byte_hash_bytes::<BabyBear>(hash, &bytes).unwrap();
    let expected = match hash {
        ByteHash::Keccak256 => Keccak256Hash.hash_iter(message.iter().copied()),
        ByteHash::Blake3 => Blake3.hash_iter(message.iter().copied()),
    };
    for (actual, limb) in digest.into_iter().zip(bytes_to_limbs(&expected)) {
        let expected = builder.define_const(EF::from_u16(limb));
        builder.connect(actual, expected);
    }
    builder.build().unwrap()
}

#[test]
fn byte_inputs_match_native_at_padding_and_tree_boundaries() {
    for hash in [ByteHash::Keccak256, ByteHash::Blake3] {
        for length in [
            0, 1, 2, 3, 31, 32, 63, 64, 65, 135, 136, 137, 271, 272, 273, 1023, 1024, 1025, 2047,
            2048, 2049, 3073,
        ] {
            let message: Vec<_> = (0..length).map(|i| (i * 137 + 251) as u8).collect();
            let circuit = circuit(hash, &message);
            let values: Vec<_> = message.iter().copied().map(EF::from_u8).collect();
            let mut runner = circuit.runner();
            runner.set_public_inputs(&values).unwrap();
            runner
                .run()
                .unwrap_or_else(|e| panic!("{hash:?}, {length} bytes: {e:?}"));
        }
    }
}

#[test]
fn bytes_are_checked_and_odd_tail_is_bound() {
    for hash in [ByteHash::Keccak256, ByteHash::Blake3] {
        let circuit = circuit(hash, &[5, 7, 251]);
        for changed in [250, 256] {
            let mut runner = circuit.runner();
            runner
                .set_public_inputs(&[EF::from_u8(5), EF::from_u8(7), EF::from_u16(changed)])
                .unwrap();
            assert!(runner.run().is_err(), "{hash:?}, tail {changed}");
        }
    }
}

#[test]
fn odd_width_binary_byte_leaves_match_native_mmcs() {
    for hash in [ByteHash::Keccak256, ByteHash::Blake3] {
        for cap_height in [0, 1] {
            for index in 0..4 {
                macro_rules! opening {
                    ($params:ident) => {{
                        let mmcs = $params::LevelMmcs::<BinaryField8>::new(
                            $params::FieldHash::new($params::byte_hash()),
                            $params::Compress::new($params::byte_hash()),
                            cap_height,
                        );
                        let matrices = vec![
                            RowMajorMatrix::new(
                                (0..12).map(|i| BinaryField8::from_repr(i * 19)).collect(),
                                3,
                            ),
                            RowMajorMatrix::new(vec![BinaryField8::from_repr(251); 2], 1),
                        ];
                        let dims: Vec<_> = matrices.iter().map(Matrix::dimensions).collect();
                        let (commitment, data) = mmcs.commit(matrices);
                        let opening = mmcs.open_batch(index, &data);
                        mmcs.verify_batch(&commitment, &dims, index, (&opening).into())
                            .unwrap();
                        let mut values: Vec<_> = opening
                            .opened_values
                            .iter()
                            .flatten()
                            .map(|x| EF::from_u8(x.to_repr()))
                            .collect();
                        values.extend((0..2).map(|bit| EF::from_bool(index >> bit & 1 == 1)));
                        for digest in opening.opening_proof.iter().chain(commitment.roots()) {
                            values.extend(bytes_to_limbs(digest).into_iter().map(EF::from_u16));
                        }
                        values
                    }};
                }
                let mut builder = CircuitBuilder::<EF>::new();
                match hash {
                    ByteHash::Keccak256 => builder.enable_keccak_f1600::<BabyBear>(),
                    ByteHash::Blake3 => builder.enable_blake3_compress::<BabyBear>(),
                }
                let mut inputs = |count| (0..count).map(|_| builder.public_input()).collect();
                let rows = vec![inputs(3), inputs(1)];
                let bits = inputs(2);
                let siblings: Vec<_> = (0..2 - cap_height).map(|_| inputs(16)).collect();
                let cap: Vec<_> = (0..1 << cap_height).map(|_| inputs(16)).collect();
                builder
                    .verify_byte_hash_mmcs_opening_bytes::<BabyBear>(
                        hash,
                        &rows,
                        &[4, 2],
                        &bits,
                        &siblings,
                        &cap,
                    )
                    .unwrap();
                let circuit = builder.build().unwrap();
                let values = match hash {
                    ByteHash::Keccak256 => opening!(keccak),
                    ByteHash::Blake3 => opening!(blake3),
                };
                let mut runner = circuit.runner();
                runner.set_public_inputs(&values).unwrap();
                runner.run().unwrap();

                let mut wrong = values;
                wrong[3] += EF::ONE;
                let mut runner = circuit.runner();
                runner.set_public_inputs(&wrong).unwrap();
                assert!(runner.run().is_err());
            }
        }
    }
}
