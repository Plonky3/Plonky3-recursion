//! In-circuit openings of Keccak-256 and BLAKE3 `MerkleTreeMmcs` batch commitments: several
//! matrices of different heights, and caps with more than one root.

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
use p3_test_utils::binary_field_params::{blake3, keccak};

type EF = BinomialExtensionField<BabyBear, 4>;
const D: usize = 4;

/// Matrix log-heights and widths, in commitment order: two tallest, one injected at each lower
/// level.
const SHAPES: [(usize, usize); 4] = [(3, 3), (3, 2), (2, 4), (1, 1)];
const LOG_MAX: usize = 3;

fn matrices() -> Vec<RowMajorMatrix<BabyBear>> {
    SHAPES
        .iter()
        .enumerate()
        .map(|(m, &(log_height, width))| {
            let values = (0..(width << log_height) as u32)
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
    ($params:ident, $cap_height:expr, $index:expr) => {{
        let mmcs = $params::LevelMmcs::<BabyBear>::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            $cap_height,
        );
        let matrices = matrices();
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

fn opening(hash: ByteHash, cap_height: usize, index: usize) -> NativeOpening {
    match hash {
        ByteHash::Keccak256 => native_opening!(keccak, cap_height, index),
        ByteHash::Blake3 => native_opening!(blake3, cap_height, index),
    }
}

fn circuit(hash: ByteHash, cap_height: usize) -> Circuit<EF> {
    let mut builder = CircuitBuilder::<EF>::new();
    match hash {
        ByteHash::Keccak256 => builder.enable_keccak_f1600::<BabyBear>(),
        ByteHash::Blake3 => builder.enable_blake3_compress::<BabyBear>(),
    }
    let mut inputs = |n: usize| -> Vec<ExprId> { (0..n).map(|_| builder.public_input()).collect() };
    let rows: Vec<Vec<ExprId>> = SHAPES.iter().map(|&(_, width)| inputs(width)).collect();
    let bits = inputs(LOG_MAX);
    let siblings: Vec<Vec<ExprId>> = (0..LOG_MAX - cap_height)
        .map(|_| inputs(DIGEST_LIMBS))
        .collect();
    let cap: Vec<Vec<ExprId>> = (0..1 << cap_height).map(|_| inputs(DIGEST_LIMBS)).collect();
    let log_heights: Vec<usize> = SHAPES.iter().map(|&(h, _)| h).collect();
    builder
        .verify_byte_hash_mmcs_opening::<BabyBear>(
            hash,
            &rows,
            &log_heights,
            &bits,
            &siblings,
            &cap,
        )
        .unwrap();
    builder.build().unwrap()
}

fn public(opening: &NativeOpening, index: usize) -> Vec<EF> {
    let digest = |d: &[u8; 32]| bytes_to_limbs(d).into_iter().map(EF::from_u16);
    opening
        .rows
        .iter()
        .flatten()
        .map(|&x| EF::from(x))
        .chain((0..LOG_MAX).map(|i| EF::from_bool(index >> i & 1 == 1)))
        .chain(opening.siblings.iter().flat_map(digest))
        .chain(opening.cap.iter().flat_map(digest))
        .collect()
}

fn runs(circuit: &Circuit<EF>, values: &[EF]) -> bool {
    let mut runner = circuit.runner();
    runner.set_public_inputs(values).is_ok() && runner.run().is_ok()
}

fn every_index_runs_and_tampering_does_not(hash: ByteHash) {
    for cap_height in [0, 1] {
        let circuit = circuit(hash, cap_height);
        for index in 0..1 << LOG_MAX {
            let honest = opening(hash, cap_height, index);
            assert!(runs(&circuit, &public(&honest, index)), "index {index}");

            // A value in the injected (shortest) matrix, the second cap root, and the index.
            let mut wrong_row = opening(hash, cap_height, index);
            wrong_row.rows[3][0] += BabyBear::ONE;
            assert!(!runs(&circuit, &public(&wrong_row, index)));

            if cap_height == 1 {
                let mut wrong_cap = opening(hash, cap_height, index);
                wrong_cap.cap[index >> (LOG_MAX - 1)][5] ^= 1;
                assert!(!runs(&circuit, &public(&wrong_cap, index)));
            }
            assert!(!runs(&circuit, &public(&honest, index ^ 0b100)));
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

fn prove(hash: ByteHash) {
    let circuit = circuit(hash, 1);
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
            &circuit,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .unwrap();
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&public(&opening(hash, 1, 5), 5))
        .unwrap();
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
