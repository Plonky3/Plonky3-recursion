//! End-to-end proofs of circuits that call the BLAKE3 compression.

use std::panic::{AssertUnwindSafe, catch_unwind};

use p3_blake3::Blake3;
use p3_circuit::ops::{
    BLAKE3_INPUT_LIMBS, BLAKE3_INPUT_WORDS, BLAKE3_IV, Blake3CompressTrace, NpoTypeId,
    blake3_compress, blake3_flags, words_to_limbs,
};
use p3_circuit::tables::Traces;
use p3_circuit::{Circuit, CircuitBuilder, ExprId};
use p3_circuit_prover::batch_stark_prover::{
    BatchStarkProver, Blake3CompressAirBuilder, Blake3CompressPreprocessor, Blake3CompressProver,
};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::{ConstraintProfile, config};
use p3_field::PrimeCharacteristicRing;
use p3_symmetric::CryptographicHasher;
use p3_test_utils::baby_bear_params::{BabyBear, BinomialExtensionField};

type EF = BinomialExtensionField<BabyBear, 4>;
const D: usize = 4;

fn words(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes(c.try_into().unwrap()))
        .collect()
}

/// The compression input for block `block` of a single-chunk message.
fn chunk_block_input(
    cv: [u32; 8],
    block: &[u8; 64],
    block_len: u32,
    flags: u32,
) -> [u32; BLAKE3_INPUT_WORDS] {
    let mut input = [0u32; BLAKE3_INPUT_WORDS];
    input[..16].copy_from_slice(&words(block));
    input[16..24].copy_from_slice(&cv);
    input[26] = block_len;
    input[27] = flags;
    input
}

/// BLAKE3 of a 128-byte message: two chained compressions in one chunk, the second the root.
/// The circuit takes both blocks as public limbs, carries the chaining value between the two
/// calls in-circuit, and connects the digest to public limbs.
fn two_block_hash_circuit() -> Circuit<EF> {
    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_blake3_compress::<BabyBear>();
    let mut inputs = |n: usize| -> Vec<ExprId> { (0..n).map(|_| builder.public_input()).collect() };
    let first = inputs(BLAKE3_INPUT_LIMBS);
    let second_block = inputs(32);
    let second_tail = inputs(8); // counter lo/hi, block length, flags
    let digest = inputs(16);

    let first_out = builder.add_blake3_compress(&first).unwrap();
    let mut second = second_block;
    second.extend_from_slice(&first_out[..16]);
    second.extend_from_slice(&second_tail);
    let out = builder.add_blake3_compress(&second).unwrap();
    for (&got, &want) in out[..16].iter().zip(&digest) {
        builder.connect(got, want);
    }
    builder.build().unwrap()
}

fn two_block_public(message: &[u8; 128]) -> Vec<EF> {
    let first_block: &[u8; 64] = message[..64].try_into().unwrap();
    let second_block: &[u8; 64] = message[64..].try_into().unwrap();
    let first = chunk_block_input(BLAKE3_IV, first_block, 64, blake3_flags::CHUNK_START);
    let cv: [u32; 8] = blake3_compress(&first)[..8].try_into().unwrap();
    let second = chunk_block_input(
        cv,
        second_block,
        64,
        blake3_flags::CHUNK_END | blake3_flags::ROOT,
    );
    let digest = words(&Blake3.hash_iter(message.iter().copied()));
    assert_eq!(&blake3_compress(&second)[..8], digest.as_slice());

    words_to_limbs(&first)
        .into_iter()
        .chain(words_to_limbs(&second[..16]))
        .chain(words_to_limbs(&second[24..]))
        .chain(words_to_limbs(&digest))
        .map(EF::from_u16)
        .collect()
}

fn prove_and_verify(
    circuit: &Circuit<EF>,
    public: &[EF],
    edit: impl FnOnce(&mut Traces<EF>),
) -> Result<(), String> {
    let preprocessors: Vec<Box<dyn NpoPreprocessor<BabyBear>>> =
        vec![Box::new(Blake3CompressPreprocessor)];
    let air_builders: Vec<Box<dyn NpoAirBuilder<config::BabyBearConfig, D>>> =
        vec![Box::new(Blake3CompressAirBuilder::<D>)];
    let mut prover = BatchStarkProver::new(config::baby_bear());
    prover.register_table_prover(Box::new(Blake3CompressProver::<D>));
    let prepared = prover
        .prepare_circuit::<EF, D>(
            circuit,
            &preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .map_err(|e| format!("prepare: {e:?}"))?;
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public)
        .map_err(|e| format!("inputs: {e:?}"))?;
    let mut traces = runner.run().map_err(|e| format!("run: {e:?}"))?;
    edit(&mut traces);
    let proof = prepared
        .prove(&traces)
        .map_err(|e| format!("prove: {e:?}"))?;
    prepared
        .verifier()
        .verify(&proof, &[])
        .map_err(|e| format!("verify: {e:?}"))
}

fn message() -> [u8; 128] {
    core::array::from_fn(|i| (i as u8).wrapping_mul(29).wrapping_add(7))
}

#[test]
fn a_two_block_blake3_hash_proves_and_verifies() {
    let circuit = two_block_hash_circuit();
    prove_and_verify(&circuit, &two_block_public(&message()), |_| {})
        .expect("an honest BLAKE3 circuit proves and verifies");
}

/// A BLAKE3 table whose first call compresses a different block than the witness table holds
/// cannot balance the witness bus.
#[test]
fn a_blake3_trace_that_disagrees_with_the_witnesses_is_rejected() {
    let circuit = two_block_hash_circuit();
    let result = catch_unwind(AssertUnwindSafe(|| {
        prove_and_verify(&circuit, &two_block_public(&message()), |traces| {
            let op_type = NpoTypeId::blake3_compress();
            let mut forged = traces
                .non_primitive_trace::<Blake3CompressTrace>(&op_type)
                .expect("the run records a BLAKE3 trace")
                .clone();
            forged.operations[0].input[0] ^= 1;
            traces
                .non_primitive_traces
                .insert(op_type, Box::new(forged));
        })
    }));
    match result {
        Ok(Ok(())) => panic!("a forged BLAKE3 trace must not verify"),
        Ok(Err(stage)) => assert!(
            stage.starts_with("prove:") || stage.starts_with("verify:"),
            "rejected before proving: {stage}"
        ),
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .cloned()
                .or_else(|| payload.downcast_ref::<&str>().map(|s| (*s).to_string()))
                .unwrap_or_default();
            assert!(
                message.contains("Lookup mismatch") && message.contains("WitnessChecks"),
                "unexpected panic: {message}"
            );
        }
    }
}

/// A native BLAKE3 MMCS opening verifies in-circuit and proves; tampering fails.
#[test]
fn a_native_blake3_merkle_opening_proves_in_circuit() {
    use p3_circuit::ops::{DIGEST_LIMBS, bytes_to_limbs};
    use p3_commit::Mmcs;
    use p3_matrix::Matrix;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_test_utils::binary_field_params::blake3;

    const LOG_HEIGHT: usize = 3;
    const WIDTH: usize = 6;
    let mmcs = blake3::level_mmcs::<BabyBear>();
    let values = (0..(WIDTH << LOG_HEIGHT) as u32)
        .map(|i| BabyBear::from_u32(i.wrapping_mul(2_246_822_519) >> 3))
        .collect();
    let matrix = RowMajorMatrix::new(values, WIDTH);
    let dims = [matrix.dimensions()];
    let (commitment, data) = mmcs.commit_matrix(matrix);

    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_blake3_compress::<BabyBear>();
    let mut inputs = |n: usize| -> Vec<ExprId> { (0..n).map(|_| builder.public_input()).collect() };
    let leaf = inputs(WIDTH);
    let bits = inputs(LOG_HEIGHT);
    let siblings: Vec<Vec<ExprId>> = (0..LOG_HEIGHT).map(|_| inputs(DIGEST_LIMBS)).collect();
    let root = inputs(DIGEST_LIMBS);
    builder
        .verify_blake3_merkle_path::<BabyBear>(&leaf, &bits, &siblings, &root)
        .unwrap();
    let circuit = builder.build().unwrap();

    let public = |row: &[BabyBear], index: usize, siblings: &[[u8; 32]]| -> Vec<EF> {
        let digest = |d: &[u8; 32]| bytes_to_limbs(d).into_iter().map(EF::from_u16);
        row.iter()
            .map(|&x| EF::from(x))
            .chain((0..LOG_HEIGHT).map(|i| EF::from_bool(index >> i & 1 == 1)))
            .chain(siblings.iter().flat_map(digest))
            .chain(digest(&commitment.roots()[0]))
            .collect()
    };
    let runs = |values: &[EF]| {
        let mut runner = circuit.runner();
        runner.set_public_inputs(values).is_ok() && runner.run().is_ok()
    };

    for index in 0..1 << LOG_HEIGHT {
        let opening = mmcs.open_batch(index, &data);
        mmcs.verify_batch(&commitment, &dims, index, (&opening).into())
            .expect("the native opening verifies");
        let row = &opening.opened_values[0];
        assert!(runs(&public(row, index, &opening.opening_proof)));
        let mut wrong = opening.opening_proof.clone();
        wrong[0][31] ^= 0x80;
        assert!(!runs(&public(row, index, &wrong)));
        assert!(!runs(&public(row, index ^ 2, &opening.opening_proof)));
    }

    let opening = mmcs.open_batch(6, &data);
    prove_and_verify(
        &circuit,
        &public(&opening.opened_values[0], 6, &opening.opening_proof),
        |_| {},
    )
    .expect("a native BLAKE3 opening proves and verifies");
}
