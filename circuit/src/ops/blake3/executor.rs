//! Blake3 membership proof executor.
//!
//! Each invocation of [`Blake3Executor::execute`] corresponds to one STARK row
//! (one Blake3 round). A full compression takes 8 invocations: 7 mixing rounds
//! plus 1 finalization row.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use p3_field::Field;

use crate::CircuitError;
use crate::ops::blake3::state::{Blake3ExecutionState, Blake3PrivateData};
use crate::ops::blake3::trace::Blake3CircuitRow;
use crate::ops::{ExecutionContext, NonPrimitiveExecutor, NpoTypeId, PreprocessedWriter};
use crate::types::WitnessId;

/// Number of 16-bit limbs in the chaining value (8 u32 words × 2 limbs).
const CV_LIMBS: usize = 16;
/// Number of rounds per Blake3 compression.
const ROUNDS_PER_COMPRESSION: usize = 8;
/// Number of G mixing rounds (rounds 1-7).
const MIXING_ROUNDS: usize = 7;

const BLAKE3_IV: [u32; 8] = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
];

const BLAKE3_MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// Default tweak for Merkle parent-node compression.
const DEFAULT_COUNTER_LO: u32 = 0;
const DEFAULT_COUNTER_HI: u32 = 0;
const DEFAULT_BLOCK_LEN: u32 = 64;
const DEFAULT_FLAGS: u32 = 0x04; // PARENT

#[inline(always)]
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

fn shift_and_load_buffer(buf: &mut [u32; 16], uint8_data: &[u8; 8]) {
    buf.copy_within(2.., 0);
    buf[14] = u32::from_le_bytes([uint8_data[0], uint8_data[1], uint8_data[2], uint8_data[3]]);
    buf[15] = u32::from_le_bytes([uint8_data[4], uint8_data[5], uint8_data[6], uint8_data[7]]);
}

/// Runtime executor for a single Blake3 round.
///
/// Each invocation handles one of the 8 rows of a compression.
/// The executor operates entirely in u32 arithmetic and only converts
/// to field elements when writing cv_out to witnesses.
#[derive(Debug, Clone)]
pub(crate) struct Blake3Executor {
    op_type: NpoTypeId,
    /// When true, this row starts a fresh chain (cv_in = IV).
    pub(crate) new_start: bool,
    /// When true, this row starts a new compression (round 1).
    pub(crate) is_new_blake: bool,
    /// When true, cv_out is exposed on the WitnessChecks bus (only valid on round 8).
    pub(crate) is_hash_output: bool,
}

impl Blake3Executor {
    pub const fn new(
        op_type: NpoTypeId,
        new_start: bool,
        is_new_blake: bool,
        is_hash_output: bool,
    ) -> Self {
        Self {
            op_type,
            new_start,
            is_new_blake,
            is_hash_output,
        }
    }
}

impl<F: Field + Send + Sync + 'static> NonPrimitiveExecutor<F> for Blake3Executor {
    fn execute(
        &self,
        _inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        let uint8_data = ctx
            .get_private_data()
            .ok()
            .and_then(|pd| pd.downcast_ref::<Blake3PrivateData>())
            .map(|d| d.uint8_data)
            .unwrap_or([0u8; 8]);

        let round_idx;
        let cv_in;
        let blake3_msg;

        if self.is_new_blake {
            cv_in = if self.new_start {
                BLAKE3_IV
            } else {
                ctx.get_op_state::<Blake3ExecutionState>(&self.op_type)
                    .and_then(|s| s.last_cv_out)
                    .ok_or_else(|| CircuitError::Poseidon2ChainMissingPreviousState {
                        operation_index: ctx.operation_id(),
                    })?
            };

            let es = ctx.get_op_state_mut::<Blake3ExecutionState>(&self.op_type);
            es.cv_in = cv_in;
            es.state = [
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
                DEFAULT_COUNTER_LO,
                DEFAULT_COUNTER_HI,
                DEFAULT_BLOCK_LEN,
                DEFAULT_FLAGS,
            ];
            shift_and_load_buffer(&mut es.msg_buffer, &uint8_data);
            es.msg = es.msg_buffer;
            es.round_idx = 1;

            round_idx = 1;
            blake3_msg = es.msg;
        } else {
            let es = ctx.get_op_state_mut::<Blake3ExecutionState>(&self.op_type);
            shift_and_load_buffer(&mut es.msg_buffer, &uint8_data);
            permute_msg(&mut es.msg);
            es.round_idx += 1;

            round_idx = es.round_idx;
            cv_in = es.cv_in;
            blake3_msg = es.msg;
        }

        let es = ctx.get_op_state_mut::<Blake3ExecutionState>(&self.op_type);
        let state_before = es.state;
        let is_last_round = round_idx == ROUNDS_PER_COMPRESSION;

        if round_idx <= MIXING_ROUNDS {
            blake3_mixing_round(&mut es.state, &blake3_msg);
        }

        let mut cv_out_val = None;
        if is_last_round {
            // Recompute cv_out using standard Blake3 compression with the
            // fully-loaded message buffer, matching the AIR constraint
            // `permute^8(msg_0) == buffer_final` which implies `msg_0 == full_msg`.
            // The accumulated `es.state` was evolved with a partial-buffer msg
            // schedule and is therefore incorrect; we recompute from scratch.
            let full_msg = es.msg_buffer;
            let mut correct_state: [u32; 16] = [
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
                DEFAULT_COUNTER_LO,
                DEFAULT_COUNTER_HI,
                DEFAULT_BLOCK_LEN,
                DEFAULT_FLAGS,
            ];
            let mut msg = full_msg;
            for _ in 0..MIXING_ROUNDS {
                blake3_mixing_round(&mut correct_state, &msg);
                permute_msg(&mut msg);
            }
            for i in 0..8 {
                correct_state[i] ^= correct_state[i + 8];
                correct_state[i + 8] ^= cv_in[i];
            }
            let cv = [
                correct_state[0],
                correct_state[1],
                correct_state[2],
                correct_state[3],
                correct_state[4],
                correct_state[5],
                correct_state[6],
                correct_state[7],
            ];
            es.last_cv_out = Some(cv);
            cv_out_val = Some(cv);
            es.state = correct_state;
        }

        let state_after = es.state;
        let msg_buffer = es.msg_buffer;

        // Write cv_out to witnesses as 16-bit limbs.
        if self.is_hash_output {
            if let Some(cv) = cv_out_val {
                for (i, &word) in cv.iter().enumerate() {
                    let lo = F::from_u32(word & 0xFFFF);
                    let hi = F::from_u32(word >> 16);
                    let lo_idx = i * 2;
                    let hi_idx = i * 2 + 1;
                    if let Some(out_slot) = outputs.get(lo_idx) {
                        if let [wid] = out_slot.as_slice() {
                            ctx.set_witness(*wid, lo)?;
                        }
                    }
                    if let Some(out_slot) = outputs.get(hi_idx) {
                        if let [wid] = out_slot.as_slice() {
                            ctx.set_witness(*wid, hi)?;
                        }
                    }
                }
            }
        }

        // Build trace row.
        let mut output_indices = vec![0u32; CV_LIMBS];
        let mut out_ctl = vec![false; CV_LIMBS];
        if self.is_hash_output && cv_out_val.is_some() {
            for (i, out_slot) in outputs.iter().enumerate().take(CV_LIMBS) {
                if let [wid] = out_slot.as_slice() {
                    out_ctl[i] = true;
                    output_indices[i] = wid.0;
                }
            }
        }

        let row = Blake3CircuitRow {
            round_idx,
            is_new_blake: self.is_new_blake,
            is_last_round,
            is_hash_output: self.is_hash_output,
            new_start: self.new_start,
            is_msg_mat: true,
            is_msg_aux_data: false,
            is_msg_cv: false,
            is_msg_jackpot: false,
            is_use_job_key: false,
            is_use_commitment_hash: false,
            uint8_data,
            msg_buffer,
            cv_in,
            blake3_msg,
            state_before,
            state_after,
            cv_out: cv_out_val,
            output_indices,
            out_ctl,
        };

        let es = ctx.get_op_state_mut::<Blake3ExecutionState>(&self.op_type);
        es.rows.push(row);

        Ok(())
    }

    fn op_type(&self) -> &NpoTypeId {
        &self.op_type
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn num_exposed_outputs(&self) -> Option<usize> {
        if self.is_hash_output {
            Some(CV_LIMBS)
        } else {
            Some(0)
        }
    }

    fn preprocess(
        &self,
        _inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        preprocessed: &mut dyn PreprocessedWriter<F>,
    ) -> Result<(), CircuitError> {
        if self.is_hash_output && outputs.len() >= CV_LIMBS {
            // Register each output limb's index, then 16 CTL flags.
            for limb_outputs in outputs.iter().take(CV_LIMBS) {
                if !limb_outputs.is_empty() {
                    // preprocessed
                    //     .register_non_primitive_output_index(&self.op_type, &[limb_outputs[0]]);
                    preprocessed
                        .register_non_primitive_output_index(&self.op_type, &[limb_outputs[0]]);
                } else {
                    preprocessed
                        .register_non_primitive_preprocessed_no_read(&self.op_type, &[F::ZERO]);
                }
            }
            for limb_outputs in outputs.iter().take(CV_LIMBS) {
                let enabled = !limb_outputs.is_empty();
                preprocessed.register_non_primitive_preprocessed_no_read(
                    &self.op_type,
                    &[F::from_bool(enabled)],
                );
            }
        } else {
            // Non-output row: 16 zero indices + 16 zero flags.
            let zeros = [F::ZERO; CV_LIMBS];
            preprocessed.register_non_primitive_preprocessed_no_read(&self.op_type, &zeros);
            preprocessed.register_non_primitive_preprocessed_no_read(&self.op_type, &zeros);
        }
        Ok(())
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}
