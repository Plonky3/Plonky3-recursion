//! In-circuit openings of Keccak-256 and BLAKE3 `MerkleTreeMmcs` batch commitments: several
//! matrices of different heights (powers of two or not), and caps with more than one root.

use p3_baby_bear::BabyBear;
use p3_circuit::ops::{ByteHash, DIGEST_LIMBS, bytes_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder, ExprId};
use p3_circuit_prover::batch_stark_prover::{
    BatchStarkProver, Blake3CompressAirBuilder, Blake3CompressPreprocessor, Blake3CompressProver,
    KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover,
};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::{ConstraintProfile, config};
use p3_commit::Mmcs;
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::BinomialExtensionField;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_test_utils::binary_field_params::{BinaryField128, TowerLevel, blake3, keccak};

type EF = BinomialExtensionField<BabyBear, 4>;
const D: usize = 4;

/// Matrix heights and widths, in commitment order: two tallest, one injected at each lower
/// level.
type Shape = &'static [(usize, usize)];
const POWERS_OF_TWO: Shape = &[(8, 3), (8, 2), (4, 4), (2, 1)];
/// Heights `ceil(6 / 2^k)`: the tree pads odd layers, as natively.
const NOT_POWERS_OF_TWO: Shape = &[(6, 3), (6, 2), (3, 4), (2, 1)];

fn max_height(shape: Shape) -> usize {
    shape.iter().map(|&(h, _)| h).max().unwrap()
}

fn log_max(shape: Shape) -> usize {
    p3_util::log2_ceil_usize(max_height(shape))
}

fn matrices(shape: Shape) -> Vec<RowMajorMatrix<BabyBear>> {
    shape
        .iter()
        .enumerate()
        .map(|(m, &(height, width))| {
            let values = (0..(width * height) as u32)
                .map(|i| BabyBear::from_u32((i + 1).wrapping_mul(2_654_435_761 ^ m as u32) >> 4))
                .collect();
            RowMajorMatrix::new(values, width)
        })
        .collect()
}

/// A native opening: the rows, the siblings and the cap.
struct NativeOpening {
    rows: Vec<Vec<BabyBear>>,
    siblings: Vec<[u8; 32]>,
    cap: Vec<[u8; 32]>,
}

macro_rules! native_opening {
    ($params:ident, $shape:expr, $cap_height:expr, $index:expr) => {{
        let mmcs = $params::LevelMmcs::<BabyBear>::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            $cap_height,
        );
        let matrices = matrices($shape);
        let dims: Vec<_> = matrices.iter().map(Matrix::dimensions).collect();
        let (commitment, data) = mmcs.commit(matrices);
        let opening = mmcs.open_batch($index, &data);
        mmcs.verify_batch(&commitment, &dims, $index, (&opening).into())
            .expect("the native opening verifies");
        NativeOpening {
            rows: opening.opened_values.clone(),
            siblings: opening.opening_proof.clone(),
            cap: commitment.roots().to_vec(),
        }
    }};
}

fn opening(hash: ByteHash, shape: Shape, cap_height: usize, index: usize) -> NativeOpening {
    match hash {
        ByteHash::Keccak256 => native_opening!(keccak, shape, cap_height, index),
        ByteHash::Blake3 => native_opening!(blake3, shape, cap_height, index),
    }
}

fn circuit(hash: ByteHash, shape: Shape, cap_height: usize) -> Circuit<EF> {
    let log_max = log_max(shape);
    let mut builder = CircuitBuilder::<EF>::new();
    match hash {
        ByteHash::Keccak256 => builder.enable_keccak_f1600::<BabyBear>(),
        ByteHash::Blake3 => builder.enable_blake3_compress::<BabyBear>(),
    }
    let mut inputs = |n: usize| -> Vec<ExprId> { (0..n).map(|_| builder.public_input()).collect() };
    let rows: Vec<Vec<ExprId>> = shape.iter().map(|&(_, width)| inputs(width)).collect();
    let bits = inputs(log_max);
    let siblings: Vec<Vec<ExprId>> = (0..log_max - cap_height)
        .map(|_| inputs(DIGEST_LIMBS))
        .collect();
    let cap: Vec<Vec<ExprId>> = (0..1 << cap_height).map(|_| inputs(DIGEST_LIMBS)).collect();
    let heights: Vec<usize> = shape.iter().map(|&(h, _)| h).collect();
    builder
        .verify_byte_hash_mmcs_opening::<BabyBear>(hash, &rows, &heights, &bits, &siblings, &cap)
        .unwrap();
    builder.build().unwrap()
}

fn public(opening: &NativeOpening, log_max: usize, index: usize) -> Vec<EF> {
    let digest = |d: &[u8; 32]| bytes_to_limbs(d).into_iter().map(EF::from_u16);
    opening
        .rows
        .iter()
        .flatten()
        .map(|&x| EF::from(x))
        .chain((0..log_max).map(|i| EF::from_bool(index >> i & 1 == 1)))
        .chain(opening.siblings.iter().flat_map(digest))
        .chain(opening.cap.iter().flat_map(digest))
        .collect()
}

fn runs(circuit: &Circuit<EF>, values: &[EF]) -> bool {
    let mut runner = circuit.runner();
    runner.set_public_inputs(values).is_ok() && runner.run().is_ok()
}

fn every_index_runs_and_tampering_does_not(hash: ByteHash) {
    for shape in [POWERS_OF_TWO, NOT_POWERS_OF_TWO] {
        let log_max = log_max(shape);
        let last = shape.len() - 1;
        for cap_height in [0, 1] {
            let circuit = circuit(hash, shape, cap_height);
            for index in 0..max_height(shape) {
                let honest = opening(hash, shape, cap_height, index);
                assert!(
                    runs(&circuit, &public(&honest, log_max, index)),
                    "index {index}"
                );

                // A value in the shortest matrix, the selected cap root, and the index.
                let mut wrong_row = opening(hash, shape, cap_height, index);
                wrong_row.rows[last][0] += BabyBear::ONE;
                assert!(!runs(&circuit, &public(&wrong_row, log_max, index)));

                if cap_height == 1 {
                    let mut wrong_cap = opening(hash, shape, cap_height, index);
                    wrong_cap.cap[index >> (log_max - 1)][5] ^= 1;
                    assert!(!runs(&circuit, &public(&wrong_cap, log_max, index)));
                }
                assert!(!runs(&circuit, &public(&honest, log_max, index ^ 0b100)));
            }
            // Past the tallest matrix: the index bound rejects it, whatever the path.
            if !max_height(shape).is_power_of_two() {
                let honest = opening(hash, shape, cap_height, max_height(shape) - 1);
                assert!(!runs(
                    &circuit,
                    &public(&honest, log_max, max_height(shape))
                ));
            }
        }
    }
}

#[test]
fn keccak_mixed_height_openings_match_native() {
    every_index_runs_and_tampering_does_not(ByteHash::Keccak256);
}

#[test]
fn blake3_mixed_height_openings_match_native() {
    every_index_runs_and_tampering_does_not(ByteHash::Blake3);
}

/// Heights that the native tree could not have committed are rejected when building.
#[test]
fn unreachable_heights_are_rejected() {
    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_blake3_compress::<BabyBear>();
    let mut inputs = |n: usize| -> Vec<ExprId> { (0..n).map(|_| builder.public_input()).collect() };
    let rows = vec![inputs(1), inputs(1)];
    let bits = inputs(3);
    let siblings: Vec<Vec<ExprId>> = (0..3).map(|_| inputs(DIGEST_LIMBS)).collect();
    let cap = vec![inputs(DIGEST_LIMBS)];
    // ceil(6 / 2) is 3, not 4; and 6 needs three index bits, not two.
    for (heights, bits) in [(&[6, 4][..], &bits[..]), (&[6, 3][..], &bits[..2])] {
        assert!(
            builder
                .verify_byte_hash_mmcs_opening::<BabyBear>(
                    ByteHash::Blake3,
                    &rows,
                    heights,
                    bits,
                    &siblings[..bits.len()],
                    &cap,
                )
                .is_err()
        );
    }
}

fn prove(hash: ByteHash) {
    let shape = NOT_POWERS_OF_TWO;
    let circuit = circuit(hash, shape, 1);
    let values = public(&opening(hash, shape, 1, 5), log_max(shape), 5);
    prove_opening(hash, &circuit, &values);
}

fn prove_opening(hash: ByteHash, circuit: &Circuit<EF>, values: &[EF]) {
    let mut preprocessors: Vec<Box<dyn NpoPreprocessor<BabyBear>>> = Vec::new();
    let mut air_builders: Vec<Box<dyn NpoAirBuilder<config::BabyBearConfig, D>>> = Vec::new();
    match hash {
        ByteHash::Keccak256 => {
            preprocessors.push(Box::new(KeccakF1600Preprocessor));
            air_builders.push(Box::new(KeccakF1600AirBuilder::<D>));
        }
        ByteHash::Blake3 => {
            preprocessors.push(Box::new(Blake3CompressPreprocessor));
            air_builders.push(Box::new(Blake3CompressAirBuilder::<D>));
        }
    }
    let mut prover = BatchStarkProver::new(config::baby_bear());
    match hash {
        ByteHash::Keccak256 => prover.register_table_prover(Box::new(KeccakF1600Prover::<D>)),
        ByteHash::Blake3 => prover.register_table_prover(Box::new(Blake3CompressProver::<D>)),
    }
    let prepared = prover
        .prepare_circuit::<EF, D>(
            circuit,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(values).unwrap();
    let traces = runner.run().unwrap();
    let proof = prepared.prove(&traces).unwrap();
    prepared.verifier().verify(&proof, &[]).unwrap();
}

#[test]
fn a_keccak_mixed_height_opening_proves() {
    prove(ByteHash::Keccak256);
}

#[test]
fn a_blake3_mixed_height_opening_proves() {
    prove(ByteHash::Blake3);
}

/// The leaves carry binary coordinates, so serializing each limb as a host field element
/// would hash a different byte string than the native binary commitment.
fn binary_opening_values(hash: ByteHash, shape: Shape, cap_height: usize, index: usize) -> Vec<EF> {
    macro_rules! open {
        ($params:ident) => {{
            let mmcs = $params::LevelMmcs::<BinaryField128>::new(
                $params::FieldHash::new($params::byte_hash()),
                $params::Compress::new($params::byte_hash()),
                cap_height,
            );
            let matrices: Vec<_> = shape
                .iter()
                .enumerate()
                .map(|(matrix, &(height, width))| {
                    RowMajorMatrix::new(
                        (0..height * width)
                            .map(|cell| {
                                BinaryField128::from_repr(
                                    0x21bade026a6ae768f2ed66ffdcc99396u128
                                        .wrapping_mul((cell + 1) as u128)
                                        ^ ((matrix as u128) << 96),
                                )
                            })
                            .collect(),
                        width,
                    )
                })
                .collect();
            let dims: Vec<_> = matrices.iter().map(Matrix::dimensions).collect();
            let (commitment, data) = mmcs.commit(matrices);
            let opening = mmcs.open_batch(index, &data);
            mmcs.verify_batch(&commitment, &dims, index, (&opening).into())
                .unwrap();
            let digest = |d: &[u8; 32]| bytes_to_limbs(d).into_iter().map(EF::from_u16);
            opening
                .opened_values
                .iter()
                .flatten()
                .flat_map(|value| {
                    let raw = value.to_repr();
                    (0..8).map(move |limb| EF::from_u16((raw >> (16 * limb)) as u16))
                })
                .chain((0..log_max(shape)).map(|bit| EF::from_bool(index >> bit & 1 == 1)))
                .chain(opening.opening_proof.iter().flat_map(digest))
                .chain(commitment.roots().iter().flat_map(digest))
                .collect::<Vec<_>>()
        }};
    }
    match hash {
        ByteHash::Keccak256 => open!(keccak),
        ByteHash::Blake3 => open!(blake3),
    }
}

fn binary_circuit(hash: ByteHash, shape: Shape, cap_height: usize) -> Circuit<EF> {
    binary_circuit_repeated(hash, shape, cap_height, 1)
}

fn binary_circuit_repeated(
    hash: ByteHash,
    shape: Shape,
    cap_height: usize,
    repetitions: usize,
) -> Circuit<EF> {
    let mut builder = CircuitBuilder::<EF>::new();
    match hash {
        ByteHash::Keccak256 => builder.enable_keccak_f1600::<BabyBear>(),
        ByteHash::Blake3 => builder.enable_blake3_compress::<BabyBear>(),
    }
    let mut inputs = |n: usize| -> Vec<ExprId> { (0..n).map(|_| builder.public_input()).collect() };
    let rows: Vec<_> = shape.iter().map(|&(_, width)| inputs(8 * width)).collect();
    let bits = inputs(log_max(shape));
    let siblings: Vec<_> = (0..log_max(shape) - cap_height)
        .map(|_| inputs(DIGEST_LIMBS))
        .collect();
    let cap: Vec<_> = (0..1 << cap_height).map(|_| inputs(DIGEST_LIMBS)).collect();
    let heights: Vec<_> = shape.iter().map(|&(height, _)| height).collect();
    for _ in 0..repetitions {
        builder
            .verify_byte_hash_mmcs_opening_limbs::<BabyBear>(
                hash, &rows, &heights, &bits, &siblings, &cap,
            )
            .unwrap();
    }
    builder.build().unwrap()
}

#[test]
fn binary_tower_mixed_height_openings_match_native() {
    for hash in [ByteHash::Keccak256, ByteHash::Blake3] {
        for shape in [POWERS_OF_TWO, NOT_POWERS_OF_TWO] {
            for cap_height in [0, 1] {
                let circuit = binary_circuit(hash, shape, cap_height);
                for index in 0..max_height(shape) {
                    let values = binary_opening_values(hash, shape, cap_height, index);
                    assert!(runs(&circuit, &values), "{hash:?}, index {index}");

                    let mut wrong_row = values.clone();
                    wrong_row[0] += EF::ONE;
                    assert!(!runs(&circuit, &wrong_row));

                    let mut wrong_root = values.clone();
                    let selected_root = index >> (log_max(shape) - cap_height);
                    let root_start = values.len() - (1 << cap_height) * DIGEST_LIMBS;
                    wrong_root[root_start + selected_root * DIGEST_LIMBS] += EF::ONE;
                    assert!(!runs(&circuit, &wrong_root));
                }
            }
        }
    }
}

#[test]
fn binary_opening_limbs_are_range_checked() {
    for hash in [ByteHash::Keccak256, ByteHash::Blake3] {
        let circuit = binary_circuit(hash, NOT_POWERS_OF_TWO, 1);
        let mut values = binary_opening_values(hash, NOT_POWERS_OF_TWO, 1, 5);
        values[0] = EF::from_u32(1 << 16);
        assert!(!runs(&circuit, &values));
    }
}

#[test]
fn binary_tower_openings_prove() {
    for hash in [ByteHash::Keccak256, ByteHash::Blake3] {
        let circuit = binary_circuit(hash, NOT_POWERS_OF_TWO, 1);
        let values = binary_opening_values(hash, NOT_POWERS_OF_TWO, 1, 5);
        prove_opening(hash, &circuit, &values);
    }
}

#[test]
fn repeated_binary_openings_keep_one_hash_output_creator() {
    let shape: Shape = &[(2, 1)];
    for hash in [ByteHash::Keccak256, ByteHash::Blake3] {
        for cap_height in [0, 1] {
            let circuit = binary_circuit_repeated(hash, shape, cap_height, 2);
            let values = binary_opening_values(hash, shape, cap_height, 0);
            assert!(runs(&circuit, &values));
            prove_opening(hash, &circuit, &values);
        }
    }
}
