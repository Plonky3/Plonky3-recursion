mod common;

use std::time::Instant;

use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    Blake3PrivateData, NpoPrivateData, generate_blake3_trace, generate_poseidon2_trace,
    generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::batch_stark_prover::{
    blake3_air_builders_d1, blake3_table_provers, poseidon2_air_builders, recompose_air_builders,
    recompose_table_provers,
};
use p3_circuit_prover::common::{NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{
    BatchStarkProver, Blake3Preprocessor, CircuitProverData, ConstraintProfile,
    Poseidon2Preprocessor, Poseidon2Prover, RecomposePreprocessor, TablePacking, TableProver,
};
use p3_field::PrimeCharacteristicRing;
use p3_fri::FriParameters;
use p3_lookup::logup::LogUpGadget;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::Poseidon2Config;
use p3_recursion::pcs::fri::{FriVerifierParams, InputProofTargets, MerkleCapTargets, RecValMmcs};
use p3_recursion::pcs::set_fri_mmcs_private_data;
use p3_recursion::verifier::verify_p3_batch_proof_circuit;
use p3_test_utils::baby_bear_params::*;
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};
use tracing_forest::ForestLayer;
use tracing_forest::util::LevelFilter;
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, Registry};

use crate::common::InnerFriGeneric;

type InnerFri = InnerFriGeneric<MyConfig, MyHash, MyCompress, DIGEST_ELEMS>;

const BLAKE3_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const BLAKE3_MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

fn g(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(mx);
    s[d] = (s[d] ^ s[a]).rotate_right(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(12);
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(my);
    s[d] = (s[d] ^ s[a]).rotate_right(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(7);
}

fn blake3_mixing_round(s: &mut [u32; 16], m: &[u32; 16]) {
    g(s, 0, 4, 8, 12, m[0], m[1]);
    g(s, 1, 5, 9, 13, m[2], m[3]);
    g(s, 2, 6, 10, 14, m[4], m[5]);
    g(s, 3, 7, 11, 15, m[6], m[7]);
    g(s, 0, 5, 10, 15, m[8], m[9]);
    g(s, 1, 6, 11, 12, m[10], m[11]);
    g(s, 2, 7, 8, 13, m[12], m[13]);
    g(s, 3, 4, 9, 14, m[14], m[15]);
}

fn permute_msg(msg: &mut [u32; 16]) {
    let orig = *msg;
    for (i, slot) in msg.iter_mut().enumerate() {
        *slot = orig[BLAKE3_MSG_PERMUTATION[i]];
    }
}

/// Standard Blake3 parent-node compression (msg_0 = full message).
///
/// The AIR trace recomputation uses `msg_0 = full_msg` (not the executor's
/// incremental partial-buffer approach), because the AIR constrains
/// `permute^8(msg_0) == buffer_final` and the Blake3 permutation has order 8.
/// Native root computation must match the trace, so we parse the full 64-byte
/// message into 16 u32 words upfront.
fn blake3_compress(cv_in: &[u32; 8], full_msg_bytes: &[u8; 64]) -> [u32; 8] {
    let mut msg = [0u32; 16];
    for i in 0..16 {
        msg[i] = u32::from_le_bytes(full_msg_bytes[4 * i..4 * i + 4].try_into().unwrap());
    }

    let mut state: [u32; 16] = [
        cv_in[0],
        cv_in[1],
        cv_in[2],
        cv_in[3],
        cv_in[4],
        cv_in[5],
        cv_in[6],
        cv_in[7],
        BLAKE3_IV[0],
        BLAKE3_IV[1],
        BLAKE3_IV[2],
        BLAKE3_IV[3],
        0,
        0,
        64,
        0x04,
    ];

    for _ in 0..7 {
        blake3_mixing_round(&mut state, &msg);
        permute_msg(&mut msg);
    }

    let mut cv_out = [0u32; 8];
    for i in 0..8 {
        cv_out[i] = state[i] ^ state[i + 8];
    }
    cv_out
}

fn words_to_bytes(words: &[u32; 8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (i, &w) in words.iter().enumerate() {
        out[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn root_to_limbs(root: &[u32; 8]) -> [F; 16] {
    let mut limbs = [F::ZERO; 16];
    for (i, &w) in root.iter().enumerate() {
        limbs[2 * i] = F::from_u32(w & 0xFFFF);
        limbs[2 * i + 1] = F::from_u32(w >> 16);
    }
    limbs
}

/// Build the internal levels of a depth-`depth` Blake3 Merkle tree from `data`,
/// where `data` contains `2^depth` 64-byte leaves laid out contiguously.
///
/// Each leaf is hashed alone with the IV (one compression per leaf) to produce
/// a 32-byte digest; those digests are then paired up the tree as usual.
///
/// Returns `(levels, root)` with `depth + 1` levels: `levels[0]` are the
/// per-leaf digests, `levels[k]` for `k >= 1` are the digests at height `k`.
fn merkle_levels(data: &[u8], depth: usize) -> (Vec<Vec<[u32; 8]>>, [u32; 8]) {
    let num_leaves = 1usize << depth;
    assert_eq!(data.len(), num_leaves * 64);

    let mut levels: Vec<Vec<[u32; 8]>> = Vec::new();

    let mut leaf_digests = Vec::with_capacity(num_leaves);
    for i in 0..num_leaves {
        let mut msg = [0u8; 64];
        msg.copy_from_slice(&data[i * 64..(i + 1) * 64]);
        leaf_digests.push(blake3_compress(&BLAKE3_IV, &msg));
    }
    levels.push(leaf_digests);

    while levels.last().unwrap().len() > 1 {
        let prev = levels.last().unwrap();
        let mut next_level = Vec::with_capacity(prev.len() / 2);
        for pair in prev.chunks(2) {
            let mut msg = [0u8; 64];
            msg[..32].copy_from_slice(&words_to_bytes(&pair[0]));
            msg[32..].copy_from_slice(&words_to_bytes(&pair[1]));
            next_level.push(blake3_compress(&BLAKE3_IV, &msg));
        }
        levels.push(next_level);
    }

    let root = levels.last().unwrap()[0];
    (levels, root)
}

/// Compute the `depth + 1` 64-byte compression messages along the Merkle path
/// that authenticates leaf `leaf_idx` against the root produced by
/// `merkle_levels`. The first message is the 64-byte leaf itself (the input to
/// the leaf-hash compression); the next `depth` messages are the sibling-pair
/// inputs, one per tree level.
fn merkle_path_messages(
    data: &[u8],
    levels: &[Vec<[u32; 8]>],
    depth: usize,
    leaf_idx: usize,
) -> Vec<[u8; 64]> {
    let num_leaves = 1usize << depth;
    assert!(leaf_idx < num_leaves);

    let mut messages = Vec::with_capacity(depth + 1);

    let mut leaf_msg = [0u8; 64];
    leaf_msg.copy_from_slice(&data[leaf_idx * 64..(leaf_idx + 1) * 64]);
    messages.push(leaf_msg);

    let mut idx = leaf_idx;
    for level in 0..depth {
        let sibling_idx = idx ^ 1;
        let left_idx = idx.min(sibling_idx);
        let right_idx = idx.max(sibling_idx);

        let mut msg = [0u8; 64];
        msg[..32].copy_from_slice(&words_to_bytes(&levels[level][left_idx]));
        msg[32..].copy_from_slice(&words_to_bytes(&levels[level][right_idx]));
        messages.push(msg);
        idx /= 2;
    }
    messages
}

fn init_logger() {
    let env_filter = EnvFilter::builder()
        .with_default_directive(LevelFilter::INFO.into())
        .from_env_lossy();

    Registry::default()
        .with(env_filter)
        .with(ForestLayer::default())
        .init();
}

/// Build a `MyConfig` whose PCS uses the FRI parameters for `layer`.
///
/// `layer` indexes the per-layer parameter sets at the bottom of this file:
/// 0 → first_layer, 1 → second_layer, 2 → third_layer. The verifier circuit
/// for layer N must be built against the *same* FRI parameters used to prove
/// layer N — see `fri_params_for_layer` and the call sites in `test_blake3_bench`.
fn make_test_config(layer: usize) -> MyConfig {
    let perm = default_babybear_poseidon2_16();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = MyMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = fri_params_for_layer(layer, challenge_mmcs);
    let pcs = MyPcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::new(perm);
    MyConfig::new(pcs, challenger)
}

fn fri_params_for_layer<Mmcs>(layer: usize, mmcs: Mmcs) -> FriParameters<Mmcs> {
    match layer {
        0 => create_benchmark_fri_params_first_layer(mmcs),
        1 => create_benchmark_fri_params_second_layer(mmcs),
        2 => create_benchmark_fri_params_third_layer(mmcs),
        _ => panic!("unsupported layer index: {layer}"),
    }
}

fn proof_size<SC: p3_batch_stark::StarkGenericConfig>(
    proof: &p3_circuit_prover::batch_stark_prover::BatchStarkProof<SC>,
) -> usize
where
    p3_circuit_prover::batch_stark_prover::BatchStarkProof<SC>: serde::Serialize,
{
    postcard::to_allocvec(proof).unwrap().len()
}

#[test]
fn test_blake3_bench() {
    init_logger();

    // Number of rows in the full weights matrix (a power of two — that's the
    // number of leaves in the matrix Merkle tree).
    const N: usize = 2048;
    // Number of 16-bit field limbs per row / per vector entry. With 32 limbs
    // each row (and the vector) is exactly 64 bytes, i.e. one Blake3 leaf
    // (one full Blake3 compression block).
    const WEIGHT_WIDTH: usize = 32;
    // Number of rows we open against the matrix commitment.
    const WEIGHT_HEIGHT: usize = 1024;
    // 64-byte leaves: 32 limbs × 2 bytes/limb.
    const LEAF_BYTES: usize = WEIGHT_WIDTH * 2;
    // Tree depth = log2(N). Each opening uses `DEPTH_WEIGHTS + 1` Blake3
    // compressions: one to hash the 64-byte leaf alone, then DEPTH_WEIGHTS
    // pair-hash levels going up to the root.
    const DEPTH_WEIGHTS: usize = 11;
    const _: () = assert!(1 << DEPTH_WEIGHTS == N);
    // Vector tree: the vector fits in a single 64-byte leaf; pair it with a
    // (zero) sibling so the depth-1 path (2 compressions) can authenticate it.
    const DEPTH_VECTOR: usize = 1;

    // -----------------------------------------------------------------------
    // 1. Random data: weights matrix and vector
    // -----------------------------------------------------------------------
    let mut rng = SmallRng::seed_from_u64(0);
    let mut weights_data = vec![0u8; N * LEAF_BYTES];
    rng.fill(&mut weights_data[..]);

    let mut vector_leaf = [0u8; LEAF_BYTES];
    rng.fill(&mut vector_leaf[..]);
    // depth=1 needs 2 leaves; pad with zeros (the "virtual sibling").
    let mut vector_data = vec![0u8; 2 * LEAF_BYTES];
    vector_data[..LEAF_BYTES].copy_from_slice(&vector_leaf);

    // -----------------------------------------------------------------------
    // 2. Native Blake3 commitments (must match what the circuit recomputes)
    // -----------------------------------------------------------------------
    let (weights_levels, weights_root) = merkle_levels(&weights_data, DEPTH_WEIGHTS);
    let (vector_levels, vector_root) = merkle_levels(&vector_data, DEPTH_VECTOR);

    let weights_root_limbs = root_to_limbs(&weights_root);
    let vector_root_limbs = root_to_limbs(&vector_root);

    // -----------------------------------------------------------------------
    // 3. Build the circuit: WEIGHT_HEIGHT openings into the matrix tree, plus
    //    a single opening of the vector against its commitment.
    // -----------------------------------------------------------------------
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_blake3(generate_blake3_trace::<F>);

    let weights: [ExprId; WEIGHT_HEIGHT * WEIGHT_WIDTH] =
        builder.alloc_public_input_array("weights");
    let token: [ExprId; WEIGHT_WIDTH] = builder.alloc_public_input_array("token");

    let weights_root_expr: Vec<ExprId> = weights_root_limbs
        .iter()
        .map(|&v| builder.alloc_const(v, "weights_root_limb"))
        .collect();
    let vector_root_expr: Vec<ExprId> = vector_root_limbs
        .iter()
        .map(|&v| builder.alloc_const(v, "vector_root_limb"))
        .collect();

    let mut weight_op_ids: Vec<Vec<_>> = Vec::with_capacity(WEIGHT_HEIGHT);
    for _ in 0..WEIGHT_HEIGHT {
        let ids = builder
            .add_blake3_merkle_verify(DEPTH_WEIGHTS + 1, &weights_root_expr)
            .unwrap();
        assert_eq!(ids.len(), (DEPTH_WEIGHTS + 1) * 8);
        weight_op_ids.push(ids);
    }
    let vector_op_ids = builder
        .add_blake3_merkle_verify(DEPTH_VECTOR + 1, &vector_root_expr)
        .unwrap();
    assert_eq!(vector_op_ids.len(), (DEPTH_VECTOR + 1) * 8);

    for i in 0..WEIGHT_HEIGHT {
        let mut cumsum = builder.alloc_const(F::ZERO, "zero");
        for j in 0..WEIGHT_WIDTH {
            let mul = builder.mul(weights[i * WEIGHT_WIDTH + j], token[j]);
            cumsum = builder.add(cumsum, mul);
        }
    }

    let circuit = builder.build().unwrap();

    // -----------------------------------------------------------------------
    // 4. Run the circuit: feed each compression's 64-byte message in 8x8-byte
    //    chunks via private data.
    // -----------------------------------------------------------------------
    let mut runner = circuit.runner();
    let public_inputs = &weights_data[..WEIGHT_HEIGHT * WEIGHT_WIDTH]
        .iter()
        .chain(&vector_data[..WEIGHT_WIDTH])
        .map(|&v| F::from_u16(v as u16))
        .collect::<Vec<_>>();
    runner.set_public_inputs(&public_inputs).unwrap();

    // Open leaves 0..WEIGHT_HEIGHT of the weights tree.
    for (leaf_idx, ids) in weight_op_ids.iter().enumerate() {
        let messages =
            merkle_path_messages(&weights_data, &weights_levels, DEPTH_WEIGHTS, leaf_idx);
        for (compression, msg) in messages.iter().enumerate() {
            for round in 0..8 {
                let mut chunk = [0u8; 8];
                chunk.copy_from_slice(&msg[round * 8..(round + 1) * 8]);
                runner
                    .set_private_data(
                        ids[compression * 8 + round],
                        NpoPrivateData::new(Blake3PrivateData { uint8_data: chunk }),
                    )
                    .unwrap();
            }
        }
    }

    // Open the vector against its (depth-1) tree: one leaf-hash compression
    // plus one pair-hash compression with the zero sibling.
    let vector_messages = merkle_path_messages(&vector_data, &vector_levels, DEPTH_VECTOR, 0);
    for (compression, msg) in vector_messages.iter().enumerate() {
        for round in 0..8 {
            let mut chunk = [0u8; 8];
            chunk.copy_from_slice(&msg[round * 8..(round + 1) * 8]);
            runner
                .set_private_data(
                    vector_op_ids[compression * 8 + round],
                    NpoPrivateData::new(Blake3PrivateData { uint8_data: chunk }),
                )
                .unwrap();
        }
    }

    let tv = Instant::now();
    let traces = runner.run().unwrap();
    println!("Execution time: {:.2?}", tv.elapsed());

    // -----------------------------------------------------------------------
    // 5. Layer 0: prove the base circuit
    // -----------------------------------------------------------------------
    let table_packing = TablePacking::new(1, 2);
    let config0 = make_test_config(0);

    let npo_prep: Vec<Box<dyn NpoPreprocessor<F>>> = vec![Box::new(Blake3Preprocessor)];
    let air_builders = blake3_air_builders_d1::<MyConfig>();
    let (airs_degrees, prim_cols, npo_cols) = get_airs_and_degrees_with_prep::<MyConfig, _, 1>(
        &circuit,
        &table_packing,
        &npo_prep,
        &air_builders,
        ConstraintProfile::Standard,
    )
    .unwrap();

    let (mut airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

    let prover_data = ProverData::from_airs_and_degrees(&config0, &mut airs, &degrees);
    let circuit_prover_data = CircuitProverData::new(prover_data, prim_cols, npo_cols);

    let mut prover0 = BatchStarkProver::new(config0).with_table_packing(table_packing);
    prover0.register_blake3_table();

    let proof0 = prover0
        .prove_all_tables(&traces, &circuit_prover_data)
        .unwrap();
    let layer0_size = proof_size(&proof0);

    match prover0.verify_all_tables(&proof0) {
        Ok(()) => println!("Layer 0 native verify: OK"),
        Err(e) => println!("Layer 0 native verify FAILED: {:?}", e),
    }

    println!("=== Layer 0 (base circuit) ===");
    println!(
        "  Proof size   : {} bytes ({:.1} KiB)",
        layer0_size,
        layer0_size as f64 / 1024.0
    );

    // -----------------------------------------------------------------------
    // 6. Recursion layers
    // -----------------------------------------------------------------------
    let lookup_gadget = LogUpGadget::new();

    // Layer 1: recursively verify the base proof (TRACE_D = 1, has Blake3 tables).
    let proof1 = {
        let common0 = &proof0.stark_common;

        // Primitive tables (CONST, PUBLIC, ALU) have zero public values.
        // Non-primitive tables (Blake3) expose their own public values.
        let mut pis0: Vec<Vec<F>> = vec![vec![]; 3];
        for entry in &proof0.non_primitives {
            pis0.push(entry.public_values.clone());
        }

        prove_recursion_layer(
            &proof0,
            common0,
            &pis0,
            1,
            true,
            &lookup_gadget,
            "Layer 1 (recursion)",
            false,
            1,
            0,
        )
    };

    // Layer 2: recursively verify the layer-1 proof (TRACE_D = 4, no Blake3 tables).
    {
        let common1 = &proof1.stark_common;
        let num_tables1 = common1
            .preprocessed
            .as_ref()
            .map(|g| g.instances.len())
            .unwrap_or(0);
        let pis1: Vec<Vec<F>> = vec![vec![]; num_tables1];

        prove_recursion_layer(
            &proof1,
            common1,
            &pis1,
            4,
            false,
            &lookup_gadget,
            "Layer 2 (recursion)",
            true,
            2,
            1,
        );
    }

    println!("\nBlake3 benchmark completed successfully!");
}

/// Creates a set of `FriParameters` suitable for benchmarking.
/// These parameters represent typical settings used in production-like scenarios.
///
/// `log_final_poly_len` is capped by the smallest committed trace's
/// `log_height`. The base proof's `CONST` table has 33 rows → pads to `2^6`,
/// so 5 is the largest legal value here.
const fn create_benchmark_fri_params_first_layer<Mmcs>(mmcs: Mmcs) -> FriParameters<Mmcs> {
    FriParameters {
        log_blowup: 2,
        log_final_poly_len: 5,
        max_log_arity: 2,
        // Conjectured soundness: log_blowup * num_queries + query_pow_bits
        // = 2 * 51 + 18 = 120 bits.
        num_queries: 51,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 18,
        mmcs,
    }
}

/// Creates a set of `FriParameters` suitable for benchmarking.
/// These parameters represent typical settings used in production-like scenarios.
///
/// `log_final_poly_len` must be strictly less than the smallest committed
/// trace's `log_height`. The recursion circuit's primitive tables (notably
/// `CONST`) are small — for this test the smallest table pads to `2^7` rows —
/// so we use 6 here rather than 7.
const fn create_benchmark_fri_params_second_layer<Mmcs>(mmcs: Mmcs) -> FriParameters<Mmcs> {
    FriParameters {
        log_blowup: 4,
        log_final_poly_len: 6,
        max_log_arity: 3,
        // Conjectured soundness: log_blowup * num_queries + query_pow_bits
        // = 4 * 26 + 18 = 122 bits.
        num_queries: 26,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 18,
        mmcs,
    }
}

/// Creates a set of `FriParameters` suitable for benchmarking.
/// These parameters represent typical settings used in production-like scenarios.
///
/// See the note on `create_benchmark_fri_params_second_layer` about the
/// `log_final_poly_len` upper bound from the smallest committed trace.
/// Layer 2's smallest table (`PUBLIC`) pads to `2^8` here, so 7 is legal.
const fn create_benchmark_fri_params_third_layer<Mmcs>(mmcs: Mmcs) -> FriParameters<Mmcs> {
    FriParameters {
        log_blowup: 7,
        log_final_poly_len: 7,
        max_log_arity: 3,
        num_queries: 14,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 22,
        mmcs,
    }
}

/// Build a recursive verification circuit around `inner_proof`, prove it, and
/// optionally verify. Returns the new proof.
///
/// `layer_number` is the layer being proved here (e.g. `1` for "Layer 1
/// recursion"); the outer prover uses that layer's FRI parameters. `inner_layer`
/// is the layer of `inner_proof` and dictates the FRI parameters wired into
/// the verifier circuit — it must match what produced `inner_proof`, otherwise
/// the verifier rejects the shape with `InvalidProofShape`.
fn prove_recursion_layer(
    inner_proof: &p3_circuit_prover::batch_stark_prover::BatchStarkProof<MyConfig>,
    inner_common: &p3_batch_stark::CommonData<MyConfig>,
    inner_pis: &[Vec<F>],
    trace_d: usize,
    has_blake3_tables: bool,
    lookup_gadget: &LogUpGadget,
    label: &str,
    do_verify: bool,
    layer_number: usize,
    inner_layer: usize,
) -> p3_circuit_prover::batch_stark_prover::BatchStarkProof<MyConfig> {
    let config_layer = make_test_config(inner_layer);
    let fri_params_layer = {
        let perm = default_babybear_poseidon2_16();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm);
        let val_mmcs = MyMmcs::new(hash, compress, 0);
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs);
        fri_params_for_layer(inner_layer, challenge_mmcs)
    };

    let fri_verifier_params = FriVerifierParams::with_mmcs(
        fri_params_layer.log_blowup,
        fri_params_layer.log_final_poly_len,
        fri_params_layer.commit_proof_of_work_bits,
        fri_params_layer.query_proof_of_work_bits,
        Poseidon2Config::BabyBearD4Width16,
    );

    let mut circuit_builder = CircuitBuilder::new();
    let poseidon2_perm = default_babybear_poseidon2_16();
    circuit_builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, BabyBearD4Width16>,
        poseidon2_perm,
    );
    circuit_builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    let table_provers_for_verify: Vec<Box<dyn TableProver<MyConfig>>> = {
        let mut tp: Vec<Box<dyn TableProver<MyConfig>>> = vec![Box::new(Poseidon2Prover::new(
            Poseidon2Config::BabyBearD4Width16,
            ConstraintProfile::Standard,
        ))];
        tp.extend(recompose_table_provers::<_, 4>(1, false));
        if has_blake3_tables {
            tp.extend(blake3_table_provers::<MyConfig>());
        }
        tp
    };

    let (verifier_inputs, mmcs_op_ids) = match trace_d {
        1 => verify_p3_batch_proof_circuit::<
            MyConfig,
            MerkleCapTargets<F, DIGEST_ELEMS>,
            InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
            InnerFri,
            LogUpGadget,
            _,
            WIDTH,
            RATE,
            1,
        >(
            &config_layer,
            &mut circuit_builder,
            inner_proof,
            &fri_verifier_params,
            inner_common,
            lookup_gadget,
            Poseidon2Config::BabyBearD4Width16,
            &table_provers_for_verify,
        )
        .unwrap(),
        4 => verify_p3_batch_proof_circuit::<
            MyConfig,
            MerkleCapTargets<F, DIGEST_ELEMS>,
            InputProofTargets<F, Challenge, RecValMmcs<F, DIGEST_ELEMS, MyHash, MyCompress>>,
            InnerFri,
            LogUpGadget,
            _,
            WIDTH,
            RATE,
            4,
        >(
            &config_layer,
            &mut circuit_builder,
            inner_proof,
            &fri_verifier_params,
            inner_common,
            lookup_gadget,
            Poseidon2Config::BabyBearD4Width16,
            &table_provers_for_verify,
        )
        .unwrap(),
        _ => panic!("Unexpected TRACE_D: {trace_d}"),
    };

    let verification_circuit = circuit_builder.build().unwrap();
    let expected_pub_len = verification_circuit.public_flat_len;

    let (pub_vals, priv_vals) =
        verifier_inputs.pack_values(inner_pis, &inner_proof.proof, inner_common);
    assert_eq!(pub_vals.len(), expected_pub_len);

    let verification_table_packing = TablePacking::new(1, 8);
    let poseidon2_config = Poseidon2Config::BabyBearD4Width16;
    let npo_prep: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
        Box::new(Poseidon2Preprocessor),
        Box::new(RecomposePreprocessor::default()),
    ];
    let mut air_builders = poseidon2_air_builders::<_, 4>();
    air_builders.extend(recompose_air_builders::<MyConfig, 4>(1, false));
    let (ver_airs_degrees, ver_prim, ver_npo) = get_airs_and_degrees_with_prep::<MyConfig, _, 4>(
        &verification_circuit,
        &verification_table_packing,
        &npo_prep,
        &air_builders,
        ConstraintProfile::RecursionOptimized,
    )
    .unwrap();
    let (mut ver_airs, ver_degrees): (Vec<_>, Vec<usize>) = ver_airs_degrees.into_iter().unzip();

    let mut ver_runner = verification_circuit.runner();
    ver_runner.set_public_inputs(&pub_vals).unwrap();
    ver_runner.set_private_inputs(&priv_vals).unwrap();
    set_fri_mmcs_private_data::<
        F,
        Challenge,
        ChallengeMmcs,
        MyMmcs,
        MyHash,
        MyCompress,
        DIGEST_ELEMS,
    >(
        &mut ver_runner,
        &mmcs_op_ids,
        &inner_proof.proof.opening_proof,
    )
    .unwrap();

    let ver_traces = ver_runner.run().unwrap();

    let config_prove = make_test_config(layer_number);
    let ver_prover_data =
        ProverData::from_airs_and_degrees(&config_prove, &mut ver_airs, &ver_degrees);
    let ver_cpd = CircuitProverData::new(ver_prover_data, ver_prim, ver_npo);

    let mut ver_prover =
        BatchStarkProver::new(config_prove).with_table_packing(verification_table_packing);
    ver_prover.register_poseidon2_table::<4>(poseidon2_config);
    ver_prover.register_recompose_table::<4>(false);

    let ver_proof = ver_prover
        .prove_all_tables(&ver_traces, &ver_cpd)
        .expect("Failed to prove verification circuit");
    let layer_size = proof_size(&ver_proof);

    println!("=== {} ===", label);
    println!(
        "  Proof size   : {} bytes ({:.1} KiB)",
        layer_size,
        layer_size as f64 / 1024.0
    );

    if do_verify {
        let tv = Instant::now();
        ver_prover
            .verify_all_tables(&ver_proof)
            .expect("Final verification failed");
        let verify_time = tv.elapsed();
        println!("verify time {:?}", verify_time);
    }

    ver_proof
}
