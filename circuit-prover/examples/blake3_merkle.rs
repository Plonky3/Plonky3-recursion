//! Test 1: Blake3 Merkle proof, end-to-end prove+verify.
//!
//! Builds a depth-2 Merkle tree using a native equivalent of the Blake3
//! executor's incremental-message compression, verifies the same membership
//! proof in a circuit, and runs end-to-end prove+verify.

use std::error::Error;

use p3_baby_bear::BabyBear;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{Blake3PrivateData, NpoPrivateData, NpoTypeId, generate_blake3_trace};
use p3_circuit::{CircuitBuilder, ExprId};
use p3_circuit_prover::batch_stark_prover::blake3_air_builders_d1;
use p3_circuit_prover::common::{NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::config::BabyBearConfig;
use p3_circuit_prover::{
    BatchStarkProver, Blake3Preprocessor, CircuitProverData, ConstraintProfile, TablePacking,
    config,
};
use p3_field::PrimeCharacteristicRing;

type F = BabyBear;

// ---------------------------------------------------------------------------
// Native executor-equivalent Blake3 compression
// ---------------------------------------------------------------------------
// Mirrors the executor's incremental message loading and mixing.

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

fn shift_and_load_buffer(buf: &mut [u32; 16], data: &[u8; 8]) {
    buf.copy_within(2.., 0);
    buf[14] = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    buf[15] = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
}

/// State that persists across compressions, mirroring the executor.
struct NativeBlake3State {
    msg_buffer: [u32; 16],
}

impl NativeBlake3State {
    fn new() -> Self {
        Self {
            msg_buffer: [0u32; 16],
        }
    }

    /// Compute a single Blake3 compression using IV as cv_in.
    /// The msg_buffer carries over from the previous compression.
    fn compress(&mut self, full_msg: &[u8; 64]) -> [u32; 8] {
        let cv_in = BLAKE3_IV;
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
            0x04, // counter_lo, counter_hi, block_len, flags (PARENT)
        ];

        let mut msg = [0u32; 16];

        for round in 0..8 {
            let chunk: [u8; 8] = full_msg[round * 8..round * 8 + 8].try_into().unwrap();
            shift_and_load_buffer(&mut self.msg_buffer, &chunk);

            if round == 0 {
                msg = self.msg_buffer;
            } else {
                permute_msg(&mut msg);
            }

            if round < 7 {
                blake3_mixing_round(&mut state, &msg);
            } else {
                for i in 0..8 {
                    state[i] ^= state[i + 8];
                    state[i + 8] ^= cv_in[i];
                }
            }
        }

        [
            state[0], state[1], state[2], state[3], state[4], state[5], state[6], state[7],
        ]
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    // Build a depth-2 Merkle tree natively.
    //
    //         root
    //        /    \
    //     h01      sibling1
    //    /    \
    // leaf0   leaf1

    let leaf0: [u8; 32] = core::array::from_fn(|i| (i + 1) as u8);
    let leaf1: [u8; 32] = core::array::from_fn(|i| (i + 33) as u8);
    let sibling1: [u8; 32] = core::array::from_fn(|i| (i + 65) as u8);

    // Level 0: compress(leaf0 || leaf1)
    let mut msg0 = [0u8; 64];
    msg0[..32].copy_from_slice(&leaf0);
    msg0[32..].copy_from_slice(&leaf1);

    let mut native_state = NativeBlake3State::new();
    let h01 = native_state.compress(&msg0);

    // Level 1: compress(h01_bytes || sibling1)
    let mut h01_bytes = [0u8; 32];
    for (i, &w) in h01.iter().enumerate() {
        h01_bytes[4 * i..4 * i + 4].copy_from_slice(&w.to_le_bytes());
    }
    let mut msg1 = [0u8; 64];
    msg1[..32].copy_from_slice(&h01_bytes);
    msg1[32..].copy_from_slice(&sibling1);
    let root = native_state.compress(&msg1);

    // Convert root to 16 field limbs (8 u32 words × 2 16-bit limbs).
    let root_limbs: [F; 16] = {
        let mut limbs = [F::ZERO; 16];
        for (i, &w) in root.iter().enumerate() {
            limbs[2 * i] = F::from_u32(w & 0xFFFF);
            limbs[2 * i + 1] = F::from_u32(w >> 16);
        }
        limbs
    };

    // Build the circuit.
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_blake3(generate_blake3_trace::<F>);

    // Root as const expressions.
    let root_pub: Vec<ExprId> = root_limbs
        .iter()
        .map(|&v| builder.alloc_const(v, "root_limb"))
        .collect();

    // Verify Merkle membership: depth=2 → 16 round ops.
    let op_ids = builder.add_blake3_merkle_verify(2, &root_pub)?;
    assert_eq!(op_ids.len(), 16);

    let circuit = builder.build()?;

    let mut runner = circuit.runner();
    runner.set_public_inputs(&[])?;

    for round in 0..8 {
        let mut data = [0u8; 8];
        data.copy_from_slice(&msg0[round * 8..round * 8 + 8]);
        runner.set_private_data(
            op_ids[round],
            NpoPrivateData::new(Blake3PrivateData { uint8_data: data }),
        )?;
    }

    for round in 0..8 {
        let mut data = [0u8; 8];
        data.copy_from_slice(&msg1[round * 8..round * 8 + 8]);
        runner.set_private_data(
            op_ids[8 + round],
            NpoPrivateData::new(Blake3PrivateData { uint8_data: data }),
        )?;
    }

    let traces = runner.run()?;

    // Verify trace was created.
    let blake3_trace = traces
        .non_primitive_trace::<p3_circuit::ops::Blake3Trace>(&NpoTypeId::blake3())
        .expect("blake3 trace missing");
    assert_eq!(blake3_trace.total_rows(), 16);

    // Set up prover infrastructure.
    let table_packing = TablePacking::new(4, 4);
    let stark_config = config::baby_bear().build();

    let npo_prep: Vec<Box<dyn NpoPreprocessor<F>>> = vec![Box::new(Blake3Preprocessor)];
    let air_builders = blake3_air_builders_d1::<BabyBearConfig>();
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<BabyBearConfig, _, 1>(
            &circuit,
            &table_packing,
            &npo_prep,
            &air_builders,
            ConstraintProfile::Standard,
        )?;
    let (mut airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

    let prover_data = ProverData::from_airs_and_degrees(&stark_config, &mut airs, &degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);

    let mut prover = BatchStarkProver::new(stark_config).with_table_packing(table_packing);
    prover.register_blake3_table();

    let proof = prover.prove_all_tables(&traces, &circuit_prover_data)?;
    prover.verify_all_tables(&proof)?;

    println!("Blake3 Merkle proof test PASSED!");
    println!("Root: {:?}", root);
    Ok(())
}
