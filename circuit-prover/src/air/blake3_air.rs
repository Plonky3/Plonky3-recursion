//! [`Blake3Air`] defines the AIR for the Blake3 membership-proof NPO table.
//!
//! The table carries out three Merkle membership proofs using Blake3
//! compression: one for A, one for B, and one for Jackpot.
//!
//! # Hash outputs
//!
//! Rows where `is_hash_output` is set expose `cv_out` via a Receive
//! interaction on the WitnessChecks bus, analogous to the output limb
//! lookups in [`Poseidon2CircuitAir`].
//!
//! # Siblings and roots
//!
//! Siblings behave exactly like the siblings in Merkle paths for the
//! Poseidon2 permutation AIR — they are public inputs supplied via the
//! Public table. Merkle roots are *not* stored in this table; the
//! circuit-level verification checks that the computed root (the final
//! `cv_out` of each membership proof) matches the expected constant
//! public value.
//!
//! # Column layout
//!
//! See [`Blake3Columns`](super::blake3_columns::Blake3Columns) for the
//! full main-trace column layout (selectors, message buffering, cv,
//! blake3 round columns, output, etc.).
//!
//! # Preprocessed columns
//!
//! Per row: `[out_idx[0..16], out_mult[0..16]]` — 16 witness index /
//! multiplicity pairs, one per cv_out limb. Active only on `is_hash_output`
//! rows; zero on all other rows.
//!
//! # CTL lookups
//!
//! `16/D` Receive lookups per row on the WitnessChecks bus:
//! key = `[out_idx[k], cv_out[k*D..(k+1)*D]]`, multiplicity = `out_mult[k]`.

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;
use core::ops::Range;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::lookup_traits::{Direction, Kind, Lookup};
use p3_lookup::{LookupAir, LookupInput};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::SymbolicExpression;

use super::blake3_columns::{BLAKE3_COL_MAP, BLAKE3_PREP_COL_MAP, BLAKE3_PREP_WIDTH, NUM_COLUMNS};
use super::utils::create_symbolic_variables;
use crate::air::blake3_columns::{BLAKE3_CV_LEN, Blake3Columns, Blake3State};
use crate::air::blake3_compress::{BLAKE3_IV, blake3_permute_msg};

const HASH_LEN: usize = 16;
const JOB_KEY: usize = 16;
const COMMITMENT_HASH: usize = JOB_KEY + HASH_LEN;
const HASH_A: usize = COMMITMENT_HASH + HASH_LEN;
const HASH_B: usize = HASH_A + HASH_LEN;
const HASH_JACKPOT: usize = HASH_B + HASH_LEN;

/// AIR for the Blake3 membership-proof table.
///
/// Zero local constraints for now — blake3 round correctness and
/// chaining constraints will be added in a follow-up. Correctness of
/// hash outputs is enforced via the CTL Receive interaction on the
/// WitnessChecks bus.
#[derive(Debug, Clone)]
pub struct Blake3Air<F, const D: usize> {
    pub(crate) num_lookup_columns: usize,
    pub(crate) min_height: usize,
    /// Flat preprocessed trace data in row-major order.
    pub(crate) preprocessed: Vec<F>,
    _phantom: PhantomData<F>,
}

impl<F: Field + PrimeCharacteristicRing, const D: usize> Blake3Air<F, D> {
    /// Main trace width: one full Blake3 column row.
    pub const fn main_width() -> usize {
        NUM_COLUMNS
    }

    /// Preprocessed width per row.
    pub const fn preprocessed_width() -> usize {
        BLAKE3_PREP_WIDTH
    }

    /// Create a new Blake3Air with no preprocessed data.
    pub const fn new() -> Self {
        Self {
            num_lookup_columns: 0,
            min_height: 1,
            preprocessed: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// Create a new Blake3Air with pre-populated preprocessed trace data.
    pub fn new_with_preprocessed(preprocessed: Vec<F>, min_height: usize) -> Self {
        Self {
            num_lookup_columns: 0,
            min_height: min_height.next_power_of_two().max(1),
            preprocessed,
            _phantom: PhantomData,
        }
    }

    /// Set the minimum trace height for FRI compatibility.
    pub fn with_min_height(mut self, min_height: usize) -> Self {
        self.min_height = min_height.next_power_of_two().max(1);
        self
    }

    /// Convert Blake3 circuit rows into a main-trace `RowMajorMatrix`.
    ///
    /// Each `Blake3CircuitRow` stores computation data in `u32` form. This
    /// method decomposes those values into the 16-bit limb pairs and 32-bit
    /// boolean decompositions that `Blake3Columns` expects, re-computing the
    /// 4 per-row intermediate states from `state_before`.
    pub fn generate_trace_rows(
        rows: &[p3_circuit::ops::Blake3CircuitRow],
        min_height: usize,
    ) -> RowMajorMatrix<F> {
        use alloc::vec;
        let padded_height = rows
            .len()
            .next_power_of_two()
            .max(min_height.next_power_of_two());
        let width = NUM_COLUMNS;
        let mut values = vec![F::ZERO; padded_height * width];

        // Pre-process: for each compression (group of 8 rows starting with
        // is_new_blake), compute the final buffer and derive the correct msg
        // schedule and states.  The executor's blake3_msg/state_before are
        // computed with a partial buffer; we need the full buffer.
        let correct = recompute_compressions(rows);

        for (row_idx, row) in rows.iter().enumerate() {
            let offset = row_idx * width;
            let cols = &mut values[offset..offset + width];

            // --- Selectors ---
            cols[BLAKE3_COL_MAP.is_use_job_key] = bool_to_f(row.is_use_job_key);
            cols[BLAKE3_COL_MAP.is_use_commitment_hash] = bool_to_f(row.is_use_commitment_hash);
            cols[BLAKE3_COL_MAP.is_hash_output] = bool_to_f(row.is_hash_output);
            cols[BLAKE3_COL_MAP.is_cv_in] = F::ZERO;
            cols[BLAKE3_COL_MAP.is_new_blake] = bool_to_f(row.is_new_blake);
            cols[BLAKE3_COL_MAP.is_last_round] = bool_to_f(row.is_last_round);
            cols[BLAKE3_COL_MAP.is_msg_mat] = bool_to_f(row.is_msg_mat);
            cols[BLAKE3_COL_MAP.is_msg_jackpot] = bool_to_f(row.is_msg_jackpot);
            cols[BLAKE3_COL_MAP.is_msg_aux_data] = bool_to_f(row.is_msg_aux_data);
            cols[BLAKE3_COL_MAP.is_msg_cv] = bool_to_f(row.is_msg_cv);

            // --- uint8_data: 8 byte values ---
            for (i, &b) in row.uint8_data.iter().enumerate() {
                cols[BLAKE3_COL_MAP.uint8_data[i]] = F::from_u32(b as u32);
            }

            // --- blake3_msg_buffer: prefer the recomputed buffer when
            // available (covers both real compressions and chained padding).
            let msg_buffer = if row_idx < correct.len() {
                correct[row_idx].msg_buffer
            } else {
                row.msg_buffer
            };
            for (w, &word) in msg_buffer.iter().enumerate() {
                let (lo, hi) = u32_to_limb_pair(word);
                cols[BLAKE3_COL_MAP.blake3_msg_buffer[2 * w]] = F::from_u32(lo);
                cols[BLAKE3_COL_MAP.blake3_msg_buffer[2 * w + 1]] = F::from_u32(hi);
            }

            // --- cv_or_tweak_prep ---
            if row.is_new_blake {
                let tweak_packed = pack_tweak(
                    DEFAULT_COUNTER_LO,
                    DEFAULT_COUNTER_HI,
                    DEFAULT_FLAGS,
                    DEFAULT_BLOCK_LEN,
                );
                cols[BLAKE3_COL_MAP.cv_or_tweak_prep] = F::from_u64(tweak_packed);
            }

            // --- cv_in: 8 u32 words → 16 (lo,hi) limbs ---
            for (w, &word) in row.cv_in.iter().enumerate() {
                let (lo, hi) = u32_to_limb_pair(word);
                cols[BLAKE3_COL_MAP.cv_in[2 * w]] = F::from_u32(lo);
                cols[BLAKE3_COL_MAP.cv_in[2 * w + 1]] = F::from_u32(hi);
            }

            // Use the re-computed msg and state for real rows.
            let (msg, state_before, is_last) = if row_idx < correct.len() {
                let c = &correct[row_idx];
                (c.msg, c.state_before, c.is_last_round)
            } else {
                (row.blake3_msg, row.state_before, row.is_last_round)
            };

            // NEXT row's STATE0 and is_new_blake flag — needed by
            // `compute_intermediate_states` to chain the unconditional
            // add3/add2 constraints across the row boundary and to pick the
            // right is_last_round layout. Constraints are evaluated cyclically
            // so the last row's "next" wraps around to row 0.
            let next_idx = (row_idx + 1) % rows.len();
            let next_state_before = if next_idx < correct.len() {
                correct[next_idx].state_before
            } else {
                rows[next_idx].state_before
            };
            let next_is_new_blake = rows[next_idx].is_new_blake;

            // --- blake3_msg ---
            for (w, &word) in msg.iter().enumerate() {
                let (lo, hi) = u32_to_limb_pair(word);
                cols[BLAKE3_COL_MAP.blake3_msg[2 * w]] = F::from_u32(lo);
                cols[BLAKE3_COL_MAP.blake3_msg[2 * w + 1]] = F::from_u32(hi);
            }

            // --- blake3_round[0..4]: intermediate states ---
            let _ = is_last; // selector flag is written elsewhere
            let intermediates = compute_intermediate_states(
                &state_before,
                &msg,
                &next_state_before,
                next_is_new_blake,
            );
            for (s_idx, state16) in intermediates.iter().enumerate() {
                write_blake3_state(&mut cols[..], s_idx, state16);
            }

            // --- cv_out: derived from states via XOR ---
            for i in 0..4 {
                let xor_word = intermediates[1][4 + i] ^ intermediates[1][12 + i];
                let (lo, hi) = u32_to_limb_pair(xor_word);
                cols[BLAKE3_COL_MAP.cv_out[2 * i]] = F::from_u32(lo);
                cols[BLAKE3_COL_MAP.cv_out[2 * i + 1]] = F::from_u32(hi);
            }
            for i in 0..4 {
                let xor_word = intermediates[0][4 + i] ^ intermediates[0][12 + i];
                let (lo, hi) = u32_to_limb_pair(xor_word);
                cols[BLAKE3_COL_MAP.cv_out[8 + 2 * i]] = F::from_u32(lo);
                cols[BLAKE3_COL_MAP.cv_out[8 + 2 * i + 1]] = F::from_u32(hi);
            }

            // --- cv_out_freq ---
            cols[BLAKE3_COL_MAP.cv_out_freq] = bool_to_f(row.is_hash_output);

            // --- stark_row_idx ---
            cols[BLAKE3_COL_MAP.stark_row_idx] = F::from_u32(row_idx as u32);
        }

        RowMajorMatrix::new(values, width)
    }
}

/// Extract flat preprocessed trace data from Blake3 circuit rows.
///
/// Returns a flat vector of `[out_idx[0..16], out_mult[0..16]]` per row,
/// suitable for [`Blake3Air::new_with_preprocessed`].
pub fn extract_blake3_preprocessed<F: Field>(
    rows: &[p3_circuit::ops::Blake3CircuitRow],
    witness_ctl_scale: u32,
) -> Vec<F> {
    let prep_width = BLAKE3_PREP_WIDTH;
    let mut data = vec![F::ZERO; rows.len() * prep_width];
    for (i, row) in rows.iter().enumerate() {
        let base = i * prep_width;
        if row.is_hash_output && !row.output_indices.is_empty() {
            for limb in 0..BLAKE3_CV_LEN.min(row.output_indices.len()) {
                data[base + limb] = F::from_u32(row.output_indices[limb]);
                let ctl = row.out_ctl.get(limb).copied().unwrap_or(false);
                if ctl {
                    data[base + BLAKE3_CV_LEN + limb] = F::from_u32(witness_ctl_scale);
                }
            }
        }
    }
    data
}

// ---------------------------------------------------------------------------
// Trace-generation helpers
// ---------------------------------------------------------------------------

const DEFAULT_COUNTER_LO: u32 = 0;
const DEFAULT_COUNTER_HI: u32 = 0;
const DEFAULT_BLOCK_LEN: u32 = 64;
const DEFAULT_FLAGS: u32 = 0x04;
const ROUNDS_PER_COMPRESSION: usize = 8;

struct CorrectRow {
    msg: [u32; 16],
    state_before: [u32; 16],
    is_last_round: bool,
    msg_buffer: [u32; 16],
}

/// Re-compute per-row msg, state_before, state_after for each compression.
///
/// The AIR constrains `permute^8(msg_0) == buffer_final`, so `msg_0` must
/// equal the fully-loaded buffer.  The executor sets `msg_0 = partial_buffer`
/// (after one load), so we recompute here with the correct message schedule.
fn recompute_compressions(
    rows: &[p3_circuit::ops::Blake3CircuitRow],
) -> alloc::vec::Vec<CorrectRow> {
    use alloc::vec::Vec;
    let mut result: Vec<CorrectRow> = Vec::with_capacity(rows.len());

    // Buffer persists across compressions, matching the executor's
    // `es.msg_buffer` which is never reset between compressions.
    let mut buf = [0u32; 16];

    let mut i = 0;
    while i < rows.len() {
        if !rows[i].is_new_blake && i > 0 {
            let prev = &result[i - 1];

            let mut new_msg = prev.msg;
            permute_msg_u32(&mut new_msg);

            let mut new_state = prev.state_before;
            blake3_mixing_round_u32(&mut new_state, &prev.msg);

            shift_and_load_buffer_u32(&mut buf, &[0u8; 8]);

            result.push(CorrectRow {
                msg: new_msg,
                state_before: new_state,
                is_last_round: false,
                msg_buffer: buf,
            });
            i += 1;
            continue;
        }

        // Find the 8 rows of this compression.
        let comp_start = i;
        let comp_end = (comp_start + ROUNDS_PER_COMPRESSION).min(rows.len());
        let comp_rows = &rows[comp_start..comp_end];
        let mut per_round_buf: [[u32; 16]; ROUNDS_PER_COMPRESSION] =
            [[0u32; 16]; ROUNDS_PER_COMPRESSION];
        for (k, cr) in comp_rows.iter().enumerate() {
            shift_and_load_buffer_u32(&mut buf, &cr.uint8_data);
            per_round_buf[k] = buf;
        }
        let full_msg = buf; // = the final buffer after all 8 loads

        // Compute correct msg schedule: msg_0 = full_msg, msg_k = permute^k(full_msg)
        let mut msg = full_msg;
        let cv_in = comp_rows[0].cv_in;
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
            DEFAULT_COUNTER_LO,
            DEFAULT_COUNTER_HI,
            DEFAULT_BLOCK_LEN,
            DEFAULT_FLAGS,
        ];

        for (round, _cr) in comp_rows.iter().enumerate() {
            let is_last = round == ROUNDS_PER_COMPRESSION - 1;
            let state_before = state;

            if round > 0 {
                permute_msg_u32(&mut msg);
            }

            if !is_last {
                blake3_mixing_round_u32(&mut state, &msg);
            }

            result.push(CorrectRow {
                msg,
                state_before,
                is_last_round: is_last,
                msg_buffer: per_round_buf[round],
            });
        }

        i = comp_end;
    }

    result
}

fn shift_and_load_buffer_u32(buf: &mut [u32; 16], data: &[u8; 8]) {
    buf.copy_within(2.., 0);
    buf[14] = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    buf[15] = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
}

/// Extend `padded_ops` to length `padded_rows` by appending all-zero
/// `Blake3CircuitRow`s. `recompute_compressions` then chains the blake3
/// message-permutation and round computations through them so the AIR
/// constraints stay satisfied without an explicit `is_not_padding` flag.
pub fn pad_blake3_padding_rows(
    padded_ops: &mut alloc::vec::Vec<p3_circuit::ops::Blake3CircuitRow>,
    padded_rows: usize,
) {
    use alloc::vec;
    padded_ops.resize_with(padded_rows, || p3_circuit::ops::Blake3CircuitRow {
        round_idx: 0,
        is_new_blake: false,
        is_last_round: false,
        is_hash_output: false,
        new_start: false,
        is_msg_mat: false,
        is_msg_aux_data: false,
        is_msg_cv: false,
        is_msg_jackpot: false,
        is_use_job_key: false,
        is_use_commitment_hash: false,
        uint8_data: [0; 8],
        msg_buffer: [0; 16],
        cv_in: [0; 8],
        blake3_msg: [0; 16],
        state_before: [0; 16],
        state_after: [0; 16],
        cv_out: None,
        output_indices: vec![0; 16],
        out_ctl: vec![false; 16],
    });
}

fn permute_msg_u32(msg: &mut [u32; 16]) {
    let orig = *msg;
    const PERM: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
    for (i, slot) in msg.iter_mut().enumerate() {
        *slot = orig[PERM[i]];
    }
}

#[inline(always)]
fn g_u32(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(mx);
    s[d] = (s[d] ^ s[a]).rotate_right(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(12);
    s[a] = s[a].wrapping_add(s[b]).wrapping_add(my);
    s[d] = (s[d] ^ s[a]).rotate_right(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_right(7);
}

fn blake3_mixing_round_u32(s: &mut [u32; 16], m: &[u32; 16]) {
    g_u32(s, 0, 4, 8, 12, m[0], m[1]);
    g_u32(s, 1, 5, 9, 13, m[2], m[3]);
    g_u32(s, 2, 6, 10, 14, m[4], m[5]);
    g_u32(s, 3, 7, 11, 15, m[6], m[7]);
    g_u32(s, 0, 5, 10, 15, m[8], m[9]);
    g_u32(s, 1, 6, 11, 12, m[10], m[11]);
    g_u32(s, 2, 7, 8, 13, m[12], m[13]);
    g_u32(s, 3, 4, 9, 14, m[14], m[15]);
}

fn bool_to_f<F: Field>(b: bool) -> F {
    if b { F::ONE } else { F::ZERO }
}

#[inline]
fn u32_to_limb_pair(word: u32) -> (u32, u32) {
    (word & 0xFFFF, word >> 16)
}

#[inline]
fn u32_to_bits<F: Field>(word: u32) -> [F; 32] {
    core::array::from_fn(|i| {
        if (word >> i) & 1 == 1 {
            F::ONE
        } else {
            F::ZERO
        }
    })
}

/// Pack tweak fields into a single u64 for `cv_or_tweak_prep`.
/// Layout: counter_low(32) | counter_high(16) | flags(8) | block_len(7)
fn pack_tweak(counter_low: u32, counter_high: u32, flags: u32, block_len: u32) -> u64 {
    let mut val = counter_low as u64;
    val |= ((counter_high & 0xFFFF) as u64) << 32;
    val |= ((flags & 0xFF) as u64) << 48;
    val |= ((block_len & 0x7F) as u64) << 56;
    val
}

/// Native half-G step on u32 values.
///
/// When `flag` is false, rotations are (16, 12); when true, (8, 7).
#[inline]
fn half_g_u32(a: u32, b: u32, c: u32, d: u32, m: u32, flag: bool) -> (u32, u32, u32, u32) {
    let (rot_d, rot_b) = if flag { (8, 7) } else { (16, 12) };
    let a = a.wrapping_add(b).wrapping_add(m);
    let d = (d ^ a).rotate_right(rot_d);
    let c = c.wrapping_add(d);
    let b = (b ^ c).rotate_right(rot_b);
    (a, b, c, d)
}

/// Compute the 4 intermediate Blake3 states for one trace row.
///
/// For mixing rounds (1-7): runs 4 half-G transitions
/// (column first-half, column second-half, diagonal first-half, diagonal second-half).
///
/// For the finalization round (8): the layout depends on what comes next.
/// * `next_is_new_blake = true` (typical inter-compression): use the bit-decomp
///   layout so `finalize_blake` (gated by `next.is_new_blake`) recovers the
///   real hash; the unconditional `add3_unchecked`/`add2_unchecked` chain is
///   patched up via the next row's STATE0 fields. The XOR check is gated off
///   in this case so it doesn't constrain the layout.
/// * `next_is_new_blake = false` (e.g. padding follows): run a real blake3
///   round so the XOR check (now active) is satisfied by round semantics.
///   `finalize_blake` is gated off in this case, so cv_out at this row no
///   longer recovers the real hash — that's intentional.
fn compute_intermediate_states(
    state_before: &[u32; 16],
    msg: &[u32; 16],
    next_state: &[u32; 16],
    next_is_new_blake: bool,
) -> [[u32; 16]; 4] {
    let mut states = [[0u32; 16]; 4];
    states[0] = *state_before;

    // Bit-decomp layout is needed whenever the next row will activate
    // `finalize_blake` (gated by `next.is_new_blake`). That's the normal
    // is_last_round → next_compression boundary, but it's also the wrap from
    // a padding tail back to row 0 of the first compression. The XOR check
    // is gated off in this case, so the layout is allowed to violate it.
    if next_is_new_blake {
        // a-words / b-words / c-words from state_before (d-words not used directly).
        let r1: [u32; 4] = state_before[0..4].try_into().unwrap();
        let r2: [u32; 4] = state_before[4..8].try_into().unwrap();
        let r3: [u32; 4] = state_before[8..12].try_into().unwrap();

        // NEXT row's STATE0 fields used to derive STATE3.
        let nr1: [u32; 4] = next_state[0..4].try_into().unwrap();
        let nr3: [u32; 4] = next_state[8..12].try_into().unwrap();
        let nr4: [u32; 4] = next_state[12..16].try_into().unwrap();

        // STATE1: row2 = bits(r1) (a-words at b-positions), row4 = bits(r3)
        // (c-words at d-positions) for finalize_blake. row1 satisfies phase-1
        // add3 (a + b_packed + m), row3 satisfies phase-1 add2 (c + d_packed = 2*r3).
        let s1r1: [u32; 4] =
            core::array::from_fn(|i| r1[i].wrapping_add(r2[i]).wrapping_add(msg[2 * i]));
        let s1r3: [u32; 4] = core::array::from_fn(|i| r3[i].wrapping_add(r3[i]));

        let mut s1 = [0u32; 16];
        s1[0..4].copy_from_slice(&s1r1);
        s1[4..8].copy_from_slice(&r1);
        s1[8..12].copy_from_slice(&s1r3);
        s1[12..16].copy_from_slice(&r3);
        states[1] = s1;

        // STATE2: row2/row4 = 0 bits. row1 satisfies phase-2 add3
        // (s1.row1 + s1.row2_packed + msg[2i+1] = s1r1 + r1 + msg[2i+1]),
        // row3 = s1r3 satisfies phase-2 add2 with d_packed = 0.
        let s2r1: [u32; 4] =
            core::array::from_fn(|i| s1r1[i].wrapping_add(r1[i]).wrapping_add(msg[2 * i + 1]));
        let mut s2 = [0u32; 16];
        s2[0..4].copy_from_slice(&s2r1);
        s2[8..12].copy_from_slice(&s1r3);
        states[2] = s2;

        // STATE3: row1 satisfies phase-3 add3 with b_packed=0 (s2r1 + msg[8+2i]).
        // row2[b]/row3[c]/row4[d] are derived backwards from NEXT.STATE0 to
        // satisfy phase-3 add2 and phase-4 add3/add2.
        let s3r1: [u32; 4] = core::array::from_fn(|i| s2r1[i].wrapping_add(msg[8 + 2 * i]));
        let mut s3r2 = [0u32; 4];
        let mut s3r3 = [0u32; 4];
        let mut s3r4 = [0u32; 4];
        for i in 0..4 {
            let bi = (i + 1) % 4;
            let ci = (i + 2) % 4;
            let di = (i + 3) % 4;
            // phase-3 add2: s3r3[ci] + nr4[di] == nr3[ci]  (NEXT.row3 add chain)
            s3r3[ci] = nr3[ci].wrapping_sub(nr4[di]);
            // phase-3 add2 closure: s1r3[ci] + s3r4_packed[di] == s3r3[ci]
            s3r4[di] = s3r3[ci].wrapping_sub(s1r3[ci]);
            // phase-4 add3: s3r1[i] + s3r2_packed[bi] + msg[8+2i+1] == nr1[i]
            s3r2[bi] = nr1[i]
                .wrapping_sub(s3r1[i])
                .wrapping_sub(msg[8 + 2 * i + 1]);
        }
        let mut s3 = [0u32; 16];
        s3[0..4].copy_from_slice(&s3r1);
        s3[4..8].copy_from_slice(&s3r2);
        s3[8..12].copy_from_slice(&s3r3);
        s3[12..16].copy_from_slice(&s3r4);
        states[3] = s3;

        return states;
    }

    // Step 0→1: column half_g, flag=false, msg words [0,2,4,6]
    let mut s = *state_before;
    for i in 0..4 {
        let (a, b, c, d) = half_g_u32(s[i], s[4 + i], s[8 + i], s[12 + i], msg[2 * i], false);
        s[i] = a;
        s[4 + i] = b;
        s[8 + i] = c;
        s[12 + i] = d;
    }
    states[1] = s;

    // Step 1→2: column half_g, flag=true, msg words [1,3,5,7]
    for i in 0..4 {
        let (a, b, c, d) = half_g_u32(s[i], s[4 + i], s[8 + i], s[12 + i], msg[2 * i + 1], true);
        s[i] = a;
        s[4 + i] = b;
        s[8 + i] = c;
        s[12 + i] = d;
    }
    states[2] = s;

    // Step 2→3: diagonal half_g, flag=false, msg words [8,10,12,14]
    for i in 0..4 {
        let bi = (i + 1) % 4;
        let ci = (i + 2) % 4;
        let di = (i + 3) % 4;
        let (a, b, c, d) = half_g_u32(
            s[i],
            s[4 + bi],
            s[8 + ci],
            s[12 + di],
            msg[8 + 2 * i],
            false,
        );
        s[i] = a;
        s[4 + bi] = b;
        s[8 + ci] = c;
        s[12 + di] = d;
    }
    states[3] = s;

    states
}

/// Write a 16-word u32 state into `Blake3State` columns.
///
/// Layout: words 0-3 → row1 (limb pairs), words 4-7 → row2 (32-bit booleans),
///         words 8-11 → row3 (limb pairs), words 12-15 → row4 (32-bit booleans).
fn write_blake3_state<F: Field>(cols: &mut [F], state_idx: usize, state: &[u32; 16]) {
    // row1: a-words as (lo, hi) limb pairs
    for i in 0..4 {
        let (lo, hi) = u32_to_limb_pair(state[i]);
        cols[BLAKE3_COL_MAP.blake3_round[state_idx].row1[2 * i]] = F::from_u32(lo);
        cols[BLAKE3_COL_MAP.blake3_round[state_idx].row1[2 * i + 1]] = F::from_u32(hi);
    }
    // row2: b-words as 32-bit boolean decompositions
    for i in 0..4 {
        let bits = u32_to_bits::<F>(state[4 + i]);
        for (j, &bit) in bits.iter().enumerate() {
            cols[BLAKE3_COL_MAP.blake3_round[state_idx].row2[i][j]] = bit;
        }
    }
    // row3: c-words as (lo, hi) limb pairs
    for i in 0..4 {
        let (lo, hi) = u32_to_limb_pair(state[8 + i]);
        cols[BLAKE3_COL_MAP.blake3_round[state_idx].row3[2 * i]] = F::from_u32(lo);
        cols[BLAKE3_COL_MAP.blake3_round[state_idx].row3[2 * i + 1]] = F::from_u32(hi);
    }
    // row4: d-words as 32-bit boolean decompositions
    for i in 0..4 {
        let bits = u32_to_bits::<F>(state[12 + i]);
        for (j, &bit) in bits.iter().enumerate() {
            cols[BLAKE3_COL_MAP.blake3_round[state_idx].row4[i][j]] = bit;
        }
    }
}

/// Number of public values the Blake3 AIR expects:
/// 16 (hash output) + 16 (job_key) + 16 (commitment_hash) + 16 (hash_a) + 16 (hash_b) + 16 (hash_jackpot).
pub const BLAKE3_NUM_PUBLIC_VALUES: usize = HASH_JACKPOT + HASH_LEN;

impl<F: Field, const D: usize> BaseAir<F> for Blake3Air<F, D> {
    fn width(&self) -> usize {
        Self::main_width()
    }

    fn num_public_values(&self) -> usize {
        BLAKE3_NUM_PUBLIC_VALUES
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let width = Self::preprocessed_width();
        let mut mat = RowMajorMatrix::from_flat_padded(self.preprocessed.to_vec(), width, F::ZERO);
        mat.pad_to_min_power_of_two_height(self.min_height, F::ZERO);
        Some(mat)
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        let m = &BLAKE3_COL_MAP;
        let mut cols = Vec::new();
        // verify_buffer_advancement: next.blake3_msg_buffer[0..28]
        for i in 0..28 {
            cols.push(m.blake3_msg_buffer[i]);
        }
        // verify_msg_constraints: next.blake3_msg[0..32]
        for i in 0..32 {
            cols.push(m.blake3_msg[i]);
        }
        // blake3_eval_transition_constraints: next.is_new_blake
        cols.push(m.is_new_blake);
        // blake3_eval_transition_constraints/verify_round: next.blake3_round[0] (full state)
        let s0 = &m.blake3_round[0];
        cols.extend_from_slice(&s0.row1);
        for word in &s0.row2 {
            cols.extend_from_slice(word);
        }
        cols.extend_from_slice(&s0.row3);
        for word in &s0.row4 {
            cols.extend_from_slice(word);
        }
        cols.sort_unstable();
        cols.dedup();
        cols
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}

pub const BYTES_PER_BABY_BEAR: usize = 2;
pub fn polyval<AB: AirBuilder>(coeffs: &[AB::Expr], x: &AB::Expr) -> AB::Expr {
    if coeffs.is_empty() {
        return AB::Expr::ZERO.into();
    }

    let mut res = coeffs.last().unwrap().clone();
    for c in coeffs.iter().rev().skip(1) {
        res = res * x.clone() + c.clone();
    }
    res
}

pub fn to_expr<AB: AirBuilder>(values: &[AB::Var]) -> Vec<AB::Expr> {
    values.iter().map(|&v| v.into()).collect()
}

pub fn inner_product<AB: AirBuilder>(a: &[AB::Expr], b: &[AB::Expr]) -> AB::Expr {
    assert_eq!(a.len(), b.len());
    a.iter()
        .zip(b.iter())
        .fold(AB::Expr::ZERO.into(), |acc, (x, y)| {
            acc + x.clone() * y.clone()
        })
}

/// `(a XOR b)` for boolean expressions: `a + b - 2ab`.
pub fn xor_bit<AB: AirBuilder>(a: AB::Expr, b: AB::Expr) -> AB::Expr {
    a.clone() + b.clone() - AB::Expr::TWO * a * b
}

/// Pack 32 bits as an unsigned u32, optionally rotated right by `right_shift`
/// bits. Bits are little-endian (bit 0 = LSB).
pub fn bits_to_u32<AB: AirBuilder>(bits: &[AB::Expr], right_shift: u32) -> AB::Expr {
    debug_assert_eq!(bits.len(), 32);
    let two: AB::Expr = AB::Expr::TWO;
    let r = (right_shift as usize) % 32;
    let mut rotated = Vec::with_capacity(32);
    rotated.extend_from_slice(&bits[r..]);
    rotated.extend_from_slice(&bits[..r]);
    polyval::<AB>(&rotated, &two)
}

/// Pack 32 bits as a signed i32 (interpreting bit 31 as the sign bit).
pub fn bits_to_i32<AB: AirBuilder>(bits: &[AB::Expr]) -> AB::Expr {
    debug_assert_eq!(bits.len(), 32);
    let two: AB::Expr = AB::Expr::TWO;
    let low_31 = polyval::<AB>(&bits[..31], &two);
    let high_bit = bits[31].clone() * AB::Expr::from_u64(1u64 << 31);
    low_31 - high_bit
}

/// Map `idx` (0-based) to its `(i, j)` representation under the lexicographic
/// ordering of pairs with `i <= j`. Mirrors the encoding used by
/// `degree_2_indicators`. Used by trace-fill code that needs to reconstruct
/// which (i, j) pair to set when emitting a `JACKPOT_IDX` packed value.
pub fn index_to_pair(mut idx: usize) -> (usize, usize) {
    for j in 0.. {
        if idx > j {
            idx -= j + 1;
            continue;
        }
        return (idx, j);
    }
    unreachable!()
}

/// Degree-2 indicators over `range`.
///
/// `muxer_bits` must have exactly two of its entries equal to 1 (others 0);
/// the encoded index is the lexicographic position of the resulting `(i, j)`
/// pair (with `i <= j`). For each index `r` in `range`, returns an expression
/// that equals 1 if `muxer_bits` encodes `r`, else 0.
pub fn degree_2_indicators<AB: AirBuilder>(
    muxer_bits: &[AB::Var],
    range: Range<usize>,
) -> Vec<AB::Expr> {
    let mut res = Vec::with_capacity(range.len());
    if range.is_empty() {
        return res;
    }

    let sum_muxer_bits: AB::Expr = muxer_bits
        .iter()
        .fold(AB::Expr::ZERO, |acc, &b| acc + AB::Expr::from(b));

    let two = AB::Expr::TWO;

    let (mut i, mut j) = index_to_pair(range.start);
    for _ in range {
        if i == j {
            // Diagonal: indicator = bits[i] * (2 * bits[i] - sum_muxer_bits).
            // When sum = 2 and bits[i] = 1: bits[i] * (2 - 2) = 0 if any other
            // bit is set; bits[i] * (2 - 1 - 1) = ... actually the encoding
            // ensures both indicators equal `bits[i]` so this fires only when
            // both bits are at position i, i.e. (i, i).
            let is_active: AB::Expr = AB::Expr::from(muxer_bits[i]);
            let is_participant = is_active.clone() * two.clone() - sum_muxer_bits.clone();
            res.push(is_participant * is_active);
            i = 0;
            j += 1;
        } else {
            res.push(AB::Expr::from(muxer_bits[i]) * AB::Expr::from(muxer_bits[j]));
            i += 1;
        }
    }
    res
}

fn verify_buffer_advancement<AB: AirBuilder>(
    builder: &mut AB,
    blake3_msg_buffer: &[AB::Var],
    next_blake3_msg_buffer: &[AB::Var],
    buffer_len: usize,
    uint8_data: &[AB::Var],
    cv_in: &[AB::Expr],
    is_msg_mat: AB::Var,
    is_msg_aux_data: AB::Var,
    is_msg_cv: AB::Var,
    next_is_same_blake: AB::Expr,
) {
    let shift_len = 4;

    let last_start_position = buffer_len - shift_len;

    // Buffer transition: next_buffer[0..28] = buffer[4..32].
    // Only valid between consecutive rounds of the same compression.
    for i in 0..(buffer_len - shift_len) {
        let constraint = next_is_same_blake.clone()
            * (next_blake3_msg_buffer[i] - blake3_msg_buffer[i + shift_len]);
        builder.assert_zero(constraint);
    }

    let c256 = AB::Expr::from_u64(256);
    let uint8_data_packed: [AB::Expr; 4] = core::array::from_fn(|i| {
        polyval::<AB>(
            &to_expr::<AB>(&uint8_data[i * BYTES_PER_BABY_BEAR..(i + 1) * BYTES_PER_BABY_BEAR]),
            &c256,
        )
    });

    let is_load_uint8 = is_msg_mat + is_msg_aux_data;
    for i in 0..shift_len {
        let constraint = is_load_uint8.clone()
            * (blake3_msg_buffer[last_start_position + i] - uint8_data_packed[i].clone());
        builder.assert_zero(constraint);
    }

    for i in 0..cv_in.len() {
        let constraint = is_msg_cv.clone() * (blake3_msg_buffer[16 + i] - cv_in[i].clone());
        builder.assert_zero(constraint);
    }
}

fn verify_msg_constraints<AB: AirBuilder>(
    builder: &mut AB,
    blake3_msg: &[AB::Var],
    blake3_msg_buffer: &[AB::Var],
    next_trace: &Blake3Columns<AB::Var>,
    is_last_round: AB::Var,
) {
    let next_blake3_msg = &next_trace.blake3_msg;
    let next_is_new_blake = next_trace.is_new_blake;

    let next_is_same_blake = AB::Expr::ONE - next_is_new_blake.clone();
    let mut permuted_msg: [AB::Var; 32] = blake3_msg.try_into().unwrap();
    blake3_permute_msg(&mut permuted_msg);
    for i in 0..32 {
        let constraint =
            next_is_same_blake.clone() * (permuted_msg[i] - next_blake3_msg[i].clone());
        builder.assert_zero(constraint);
    }

    for i in 0..32 {
        let constraint = is_last_round.clone() * (permuted_msg[i] - blake3_msg_buffer[i].clone());
        builder.assert_zero(constraint);
    }
}

fn blake3_eval_transition_constraints<'a, AB: AirBuilder<F: Field>>(
    builder: &mut AB,
    local: &Blake3Columns<AB::Var>,
    msg: &[AB::Var],
    next: &Blake3Columns<AB::Var>,
    next_is_new_blake: AB::Var,
) -> [AB::Expr; BLAKE3_CV_LEN] {
    let init_state = local.blake3_round[0].clone();
    let next_init_state = next.blake3_round[0].clone();
    let states = [
        init_state,
        local.blake3_round[1].clone(),
        local.blake3_round[2].clone(),
        local.blake3_round[3].clone(),
        next_init_state,
    ];

    let next_is_same_blake: AB::Expr = AB::Expr::ONE - next_is_new_blake.into();
    verify_round(builder, &states, msg, next_is_same_blake);

    let blake3_output = finalize_blake(builder, &states, next_is_new_blake.into());

    blake3_output
}

/// Compute XOR bits from two 32-bit decompositions, with optional rotation on b.
fn xor_bits_shifted<AB: AirBuilder>(a: &[AB::Var], b: &[AB::Var], shift: usize) -> Vec<AB::Expr> {
    debug_assert_eq!(a.len(), 32);
    debug_assert_eq!(b.len(), 32);
    (0..32)
        .map(|i| {
            let a_bit: AB::Expr = a[i].into();
            let b_bit: AB::Expr = b[(i + 32 - shift) % 32].into();
            a_bit.clone() + b_bit.clone() - AB::Expr::TWO * a_bit * b_bit
        })
        .collect()
}

/// Pack 16 bits into a 16-bit limb expression (fits in BabyBear, max 2^16-1).
fn polyval_half<AB: AirBuilder>(bits: &[AB::Expr]) -> AB::Expr {
    debug_assert!(bits.len() <= 16);
    let two = AB::Expr::TWO;
    polyval::<AB>(bits, &two)
}

/// Constrain `diff` to be in {0, c, 2c} (degree-3).
fn assert_multiple_of_3<AB: AirBuilder>(builder: &mut AB, diff: AB::Expr, c: AB::Expr) {
    let two_c = c.clone() + c.clone();
    builder.assert_zero(diff.clone() * (diff.clone() - c) * (diff - two_c));
}

/// Constrain `diff` to be in {0, c} (degree-2).
fn assert_multiple_of_2<AB: AirBuilder>(builder: &mut AB, diff: AB::Expr, c: AB::Expr) {
    builder.assert_zero(diff.clone() * (diff - c));
}

/// Unchecked 3-input mod-2^32 addition on 16-bit limb pairs.
/// All intermediate values stay below ~200k, well within BabyBear.
/// Requires AB::F: Field for computing (2^16)^{-1}.
#[allow(clippy::too_many_arguments)]
fn add3_unchecked<AB: AirBuilder<F: Field>>(
    builder: &mut AB,
    res_lo: AB::Expr,
    res_hi: AB::Expr,
    a_lo: AB::Expr,
    a_hi: AB::Expr,
    b_lo: AB::Expr,
    b_hi: AB::Expr,
    c_lo: AB::Expr,
    c_hi: AB::Expr,
) {
    let c2_16 = AB::Expr::from_u64(1u64 << 16);
    let inv_2_16 = AB::Expr::from(AB::F::from_u64(1u64 << 16).inverse());

    let diff_lo = a_lo + b_lo + c_lo - res_lo;
    assert_multiple_of_3(builder, diff_lo.clone(), c2_16.clone());

    let carry = diff_lo * inv_2_16;
    let diff_hi = a_hi + b_hi + c_hi + carry - res_hi;
    assert_multiple_of_3(builder, diff_hi, c2_16);
}

/// Unchecked 2-input mod-2^32 addition on 16-bit limb pairs.
/// Requires AB::F: Field for computing (2^16)^{-1}.
fn add2_unchecked<AB: AirBuilder<F: Field>>(
    builder: &mut AB,
    res_lo: AB::Expr,
    res_hi: AB::Expr,
    a_lo: AB::Expr,
    a_hi: AB::Expr,
    b_lo: AB::Expr,
    b_hi: AB::Expr,
) {
    let c2_16 = AB::Expr::from_u64(1u64 << 16);
    let inv_2_16 = AB::Expr::from(AB::F::from_u64(1u64 << 16).inverse());

    let diff_lo = a_lo + b_lo - res_lo;
    assert_multiple_of_2(builder, diff_lo.clone(), c2_16.clone());

    let carry = diff_lo * inv_2_16;
    let diff_hi = a_hi + b_hi + carry - res_hi;
    assert_multiple_of_2(builder, diff_hi, c2_16);
}

/// Verify res = (a XOR (b >>> shift)) and that b's bits are boolean.
/// res is a 16-bit limb pair; comparison is per-limb (no overflow).
/// The constraint on res is conditional on is_activated; boolean checks are unconditional.
fn xor_32_shift_if<AB: AirBuilder>(
    builder: &mut AB,
    res_lo: AB::Expr,
    res_hi: AB::Expr,
    a: &[AB::Var],
    b: &[AB::Var],
    is_activated: AB::Expr,
    shift: usize,
) {
    debug_assert!(shift < 32);
    debug_assert_eq!(a.len(), 32);
    debug_assert_eq!(b.len(), 32);

    for &bit in b.iter() {
        let bit_expr: AB::Expr = bit.into();
        builder.assert_zero(bit_expr.clone() * (bit_expr - AB::Expr::ONE));
    }

    let xor_bits = xor_bits_shifted::<AB>(a, b, shift);
    let xor_lo = polyval_half::<AB>(&xor_bits[..16]);
    let xor_hi = polyval_half::<AB>(&xor_bits[16..]);
    builder.assert_zero(is_activated.clone() * (res_lo - xor_lo));
    builder.assert_zero(is_activated * (res_hi - xor_hi));
}

/// Compute a XOR b from bit decompositions, returning (lo_16, hi_16) limb pair.
fn xor_32_limbs<AB: AirBuilder>(a: &[AB::Var], b: &[AB::Var]) -> (AB::Expr, AB::Expr) {
    let xor_bits = xor_bits_shifted::<AB>(a, b, 0);
    (
        polyval_half::<AB>(&xor_bits[..16]),
        polyval_half::<AB>(&xor_bits[16..]),
    )
}

/// Verify a half-round (quarter-round pair) of the Blake3 G function.
/// All word values are passed as (lo, hi) 16-bit limb pairs to avoid field overflow.
#[allow(clippy::too_many_arguments)]
fn half_g<AB: AirBuilder<F: Field>>(
    builder: &mut AB,
    a_lo: AB::Var,
    a_hi: AB::Var,
    b: &[AB::Var],
    c_lo: AB::Var,
    c_hi: AB::Var,
    d: &[AB::Var],
    m_lo: AB::Var,
    m_hi: AB::Var,
    flag: bool,
    expected_a_lo: AB::Var,
    expected_a_hi: AB::Var,
    expected_b: &[AB::Var],
    expected_c_lo: AB::Var,
    expected_c_hi: AB::Var,
    expected_d: &[AB::Var],
    is_activated: AB::Expr,
) {
    debug_assert_eq!(b.len(), 32);
    debug_assert_eq!(d.len(), 32);
    debug_assert_eq!(expected_b.len(), 32);
    debug_assert_eq!(expected_d.len(), 32);
    let (rot_1, rot_2) = if flag { (8, 7) } else { (16, 12) };

    let two = AB::Expr::TWO;
    let b_lo = polyval::<AB>(&to_expr::<AB>(&b[..16]), &two);
    let b_hi = polyval::<AB>(&to_expr::<AB>(&b[16..]), &two);
    add3_unchecked(
        builder,
        expected_a_lo.into(),
        expected_a_hi.into(),
        a_lo.into(),
        a_hi.into(),
        b_lo,
        b_hi,
        m_lo.into(),
        m_hi.into(),
    );
    xor_32_shift_if(
        builder,
        expected_a_lo.into(),
        expected_a_hi.into(),
        d,
        expected_d,
        is_activated.clone(),
        rot_1,
    );

    let expected_d_lo = polyval::<AB>(&to_expr::<AB>(&expected_d[..16]), &two);
    let expected_d_hi = polyval::<AB>(&to_expr::<AB>(&expected_d[16..]), &two);
    add2_unchecked(
        builder,
        expected_c_lo.into(),
        expected_c_hi.into(),
        c_lo.into(),
        c_hi.into(),
        expected_d_lo,
        expected_d_hi,
    );
    xor_32_shift_if(
        builder,
        expected_c_lo.into(),
        expected_c_hi.into(),
        b,
        expected_b,
        is_activated,
        rot_2,
    );
}

/// Verify a full round of the Blake3 permutation (4 column + 4 diagonal quarter-rounds).
/// Word values from row1/row3 are passed as limb pairs; msg words likewise.
fn verify_round<AB: AirBuilder<F: Field>>(
    builder: &mut AB,
    states: &[Blake3State<AB::Var>; 5],
    msg: &[AB::Var],
    is_activated: AB::Expr,
) {
    // row1/row3 word `w` has limbs at [2w] and [2w+1].
    // msg word `j` has limbs at [2j] and [2j+1].
    (0..4).for_each(|i| {
        half_g(
            builder,
            states[0].row1[2 * i],
            states[0].row1[2 * i + 1],
            &states[0].row2[i],
            states[0].row3[2 * i],
            states[0].row3[2 * i + 1],
            &states[0].row4[i],
            msg[2 * (2 * i)],
            msg[2 * (2 * i) + 1],
            false,
            states[1].row1[2 * i],
            states[1].row1[2 * i + 1],
            &states[1].row2[i],
            states[1].row3[2 * i],
            states[1].row3[2 * i + 1],
            &states[1].row4[i],
            is_activated.clone(),
        );
    });
    (0..4).for_each(|i| {
        half_g(
            builder,
            states[1].row1[2 * i],
            states[1].row1[2 * i + 1],
            &states[1].row2[i],
            states[1].row3[2 * i],
            states[1].row3[2 * i + 1],
            &states[1].row4[i],
            msg[2 * (2 * i + 1)],
            msg[2 * (2 * i + 1) + 1],
            true,
            states[2].row1[2 * i],
            states[2].row1[2 * i + 1],
            &states[2].row2[i],
            states[2].row3[2 * i],
            states[2].row3[2 * i + 1],
            &states[2].row4[i],
            is_activated.clone(),
        );
    });
    (0..4).for_each(|i| {
        let bi = (i + 1) % 4;
        let ci = (i + 2) % 4;
        let di = (i + 3) % 4;
        half_g(
            builder,
            states[2].row1[2 * i],
            states[2].row1[2 * i + 1],
            &states[2].row2[bi],
            states[2].row3[2 * ci],
            states[2].row3[2 * ci + 1],
            &states[2].row4[di],
            msg[2 * (8 + 2 * i)],
            msg[2 * (8 + 2 * i) + 1],
            false,
            states[3].row1[2 * i],
            states[3].row1[2 * i + 1],
            &states[3].row2[bi],
            states[3].row3[2 * ci],
            states[3].row3[2 * ci + 1],
            &states[3].row4[di],
            is_activated.clone(),
        );
    });
    (0..4).for_each(|i| {
        let bi = (i + 1) % 4;
        let ci = (i + 2) % 4;
        let di = (i + 3) % 4;
        half_g(
            builder,
            states[3].row1[2 * i],
            states[3].row1[2 * i + 1],
            &states[3].row2[bi],
            states[3].row3[2 * ci],
            states[3].row3[2 * ci + 1],
            &states[3].row4[di],
            msg[2 * (8 + 2 * i + 1)],
            msg[2 * (8 + 2 * i + 1) + 1],
            true,
            states[4].row1[2 * i],
            states[4].row1[2 * i + 1],
            &states[4].row2[bi],
            states[4].row3[2 * ci],
            states[4].row3[2 * ci + 1],
            &states[4].row4[di],
            is_activated.clone(),
        );
    });
}

/// Finalize Blake3 compression: XOR first half of state with second half.
/// Output is cv_out = [row1 ^ row3, row2 ^ row4] as 16-bit limb pairs.
/// Equality checks are per-limb (no field overflow).
fn finalize_blake<AB: AirBuilder>(
    builder: &mut AB,
    states: &[Blake3State<AB::Var>; 5],
    is_activated: AB::Expr,
) -> [AB::Expr; BLAKE3_CV_LEN] {
    let two = AB::Expr::TWO;
    // states[1].row2 is the bit decomposition of states[0].row1.
    // Check per-limb: lo 16 bits and hi 16 bits separately (each ≤ 2^16-1 < p).
    for i in 0..4 {
        let bits = states[1].row2[i];
        let bits_lo = polyval::<AB>(&to_expr::<AB>(&bits[..16]), &two);
        let bits_hi = polyval::<AB>(&to_expr::<AB>(&bits[16..]), &two);
        builder
            .assert_zero(is_activated.clone() * (AB::Expr::from(states[0].row1[2 * i]) - bits_lo));
        builder.assert_zero(
            is_activated.clone() * (AB::Expr::from(states[0].row1[2 * i + 1]) - bits_hi),
        );
    }
    // states[1].row4 is the bit decomposition of states[0].row3.
    for i in 0..4 {
        let bits = states[1].row4[i];
        let bits_lo = polyval::<AB>(&to_expr::<AB>(&bits[..16]), &two);
        let bits_hi = polyval::<AB>(&to_expr::<AB>(&bits[16..]), &two);
        builder
            .assert_zero(is_activated.clone() * (AB::Expr::from(states[0].row3[2 * i]) - bits_lo));
        builder.assert_zero(
            is_activated.clone() * (AB::Expr::from(states[0].row3[2 * i + 1]) - bits_hi),
        );
    }
    // cv_out[0..8]  = row1 XOR row3 (via bit decompositions in states[1].row2 and states[1].row4)
    // cv_out[8..16] = row2 XOR row4 (via bit decompositions in states[0].row2 and states[0].row4)
    // states[1].row2/row4 bits are boolean-checked in verify_round, so output is u32 range-checked.
    let mut output = [AB::Expr::ZERO; BLAKE3_CV_LEN];
    for i in 0..4 {
        let (lo, hi) = xor_32_limbs::<AB>(&states[1].row2[i], &states[1].row4[i]);
        output[2 * i] = lo;
        output[2 * i + 1] = hi;
    }
    for i in 0..4 {
        let (lo, hi) = xor_32_limbs::<AB>(&states[0].row2[i], &states[0].row4[i]);
        output[8 + 2 * i] = lo;
        output[8 + 2 * i + 1] = hi;
    }
    output
}

/// Verify init state when is_new_blake is true.
fn verify_init_state<AB: AirBuilder>(
    builder: &mut AB,
    init_state: &Blake3State<AB::Var>,
    is_new_blake: AB::Var,
    cv: &[AB::Expr],
    blake3_tweak: AB::Var,
) {
    let gate = AB::Expr::from(is_new_blake);
    // row1 holds a-words (cv[0..4]) as (lo,hi) limb pairs.
    // row3 holds c-words (IV[0..4]) as (lo,hi) limb pairs.
    for i in 0..4 {
        let constr: AB::Expr = gate.clone() * (init_state.row1[2 * i].into() - cv[2 * i].clone());
        builder.assert_zero(constr);
        let constr: AB::Expr =
            gate.clone() * (init_state.row1[2 * i + 1].into() - cv[2 * i + 1].clone());
        builder.assert_zero(constr);

        let constr =
            gate.clone() * (init_state.row3[2 * i] - AB::Expr::from_u32(BLAKE3_IV[i] & 0xFFFF));
        builder.assert_zero(constr);
        let constr =
            gate.clone() * (init_state.row3[2 * i + 1] - AB::Expr::from_u32(BLAKE3_IV[i] >> 16));
        builder.assert_zero(constr);
    }

    // row2 holds b-words (cv[4..8]) as 32-bit boolean decompositions.
    // Compare lo/hi 16-bit halves against the corresponding cv_in limbs.
    for i in 0..4 {
        let bits_lo = polyval_half::<AB>(&to_expr::<AB>(&init_state.row2[i][..16]));
        let bits_hi = polyval_half::<AB>(&to_expr::<AB>(&init_state.row2[i][16..]));
        let constr = gate.clone() * (bits_lo - cv[8 + 2 * i].clone());
        builder.assert_zero(constr);
        let constr = gate.clone() * (bits_hi - cv[8 + 2 * i + 1].clone());
        builder.assert_zero(constr);
    }

    // row4 encodes blake3 tweak: counter_low(32) | counter_high(16) | flags(8) | block_len(7)
    let active_bits = [
        &init_state.row4[0],
        &init_state.row4[1][0..16],
        &init_state.row4[3][0..8],
        &init_state.row4[2][0..7],
    ]
    .concat();
    let packed = polyval::<AB>(&to_expr::<AB>(&active_bits), &AB::Expr::TWO);
    let constr = gate.clone() * (packed - blake3_tweak);
    builder.assert_zero(constr);

    let zero_bits = [
        &init_state.row4[1][16..],
        &init_state.row4[2][7..],
        &init_state.row4[3][8..],
    ]
    .concat();
    for bit in zero_bits {
        builder.assert_zero(gate.clone() * bit);
    }
}

impl<AB: AirBuilder, const D: usize> Air<AB> for Blake3Air<AB::F, D>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.current_slice();
        let next = main.next_slice();

        unsafe {
            debug_assert_eq!(local.len(), NUM_COLUMNS);
            debug_assert_eq!(next.len(), NUM_COLUMNS);
            let local: &Blake3Columns<AB::Var> = &*local.as_ptr().cast();
            let next: &Blake3Columns<AB::Var> = &*next.as_ptr().cast();

            // TODO: add constraints
            let blake3_msg = &local.blake3_msg;
            let blake3_msg_buffer = &local.blake3_msg_buffer;
            let next_blake3_msg_buffer = &next.blake3_msg_buffer;
            let uint8_data = &local.uint8_data;
            let cv_in: &[AB::Expr] = &local.cv_in.iter().map(|&v| v.into()).collect::<Vec<_>>();
            let is_msg_mat = local.is_msg_mat;
            let is_msg_aux_data = local.is_msg_aux_data;
            let is_msg_cv = local.is_msg_cv;
            let is_last_round = local.is_last_round;
            let is_new_blake = local.is_new_blake;
            let blake3_tweak = local.cv_or_tweak_prep;
            let is_active: AB::Expr = is_msg_mat.into();
            let next_is_new_blake = next.is_new_blake;
            let next_is_same_blake: AB::Expr =
                is_active.clone() * (AB::Expr::ONE - next_is_new_blake.into());
            verify_buffer_advancement(
                builder,
                blake3_msg_buffer,
                next_blake3_msg_buffer,
                local.blake3_msg_buffer.len(),
                uint8_data,
                cv_in,
                is_msg_mat,
                is_msg_aux_data,
                is_msg_cv,
                next_is_same_blake.clone(),
            );

            verify_msg_constraints(builder, blake3_msg, blake3_msg_buffer, &next, is_last_round);

            let public_values = builder.public_values().to_vec();

            let is_use_job_key = local.is_use_job_key;
            let is_use_commitment_hash = local.is_use_commitment_hash;
            let job_key: [AB::Expr; HASH_LEN] =
                core::array::from_fn(|i| public_values[JOB_KEY + i].into());
            let commitment_hash: [AB::Expr; HASH_LEN] =
                core::array::from_fn(|i| public_values[COMMITMENT_HASH + i].into());
            let use_cv_in = AB::Expr::ONE - is_use_job_key.clone() - is_use_commitment_hash.clone();
            let cv_selectors = [
                use_cv_in.clone(),
                is_use_job_key.into().clone(),
                is_use_commitment_hash.into().clone(),
            ];
            let mut expected_cvs = [AB::Expr::ZERO; BLAKE3_CV_LEN];
            for i in 0..BLAKE3_CV_LEN {
                let cv_sources = [
                    cv_in[i].clone(),
                    job_key[i].clone(),
                    commitment_hash[i].clone(),
                ];
                let expected_cv = inner_product::<AB>(&cv_selectors, &cv_sources);
                expected_cvs[i] = expected_cv;
            }

            /////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // Read BLAKE3_ROUND and check constraints
            let blake3_output = blake3_eval_transition_constraints(
                builder,
                &local,
                blake3_msg,
                &next,
                next_is_new_blake,
            );

            let init_state = local.blake3_round[0].clone();
            // Verify blake3 init state when this row starts a new blake3 (is_new_blake).
            verify_init_state(
                builder,
                &init_state,
                is_new_blake,
                &expected_cvs,
                blake3_tweak,
            );

            /////////////////////////////////////////////////////////////////////////////////////////////////////////////
            // Read CV_OUT
            let cv_out = &local.cv_out;
            for i in 0..cv_out.len() {
                builder.assert_zero(cv_out[i] - blake3_output[i].clone());
            }
        }
    }
}

impl<F: Field, const D: usize> LookupAir<F> for Blake3Air<F, D> {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let new_idx = self.num_lookup_columns;
        self.num_lookup_columns += 1;
        vec![new_idx]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        let mut lookups = Vec::new();
        self.num_lookup_columns = 0;

        let total_main_width = Self::main_width();
        let total_prep_width = Self::preprocessed_width();

        let (symbolic_main, symbolic_preprocessed) =
            create_symbolic_variables::<F>(total_prep_width, total_main_width, 0, 0);

        // Output hash lookups: one per output wire on the WitnessChecks bus.
        //
        // For D=1: 16 lookups, each with key [out_idx[k], cv_out[k]].
        // For D>1: BLAKE3_CV_LEN/D lookups, each with key [out_idx[k], cv_out[k*D..(k+1)*D]].
        let num_lookups = BLAKE3_CV_LEN / D;
        for k in 0..num_lookups {
            let out_idx =
                SymbolicExpression::from(symbolic_preprocessed[BLAKE3_PREP_COL_MAP.out_idx[k]]);
            let out_mult =
                SymbolicExpression::from(symbolic_preprocessed[BLAKE3_PREP_COL_MAP.out_mult[k]]);

            let cv_out_col = BLAKE3_COL_MAP.cv_out[k * D];
            let mut values = vec![out_idx];
            for j in 0..D {
                values.push(SymbolicExpression::from(symbolic_main[cv_out_col + j]));
            }

            let inp: LookupInput<F> = (values, out_mult, Direction::Receive);
            lookups.push(LookupAir::register_lookup(
                self,
                Kind::Global("WitnessChecks".to_string()),
                &[inp],
            ));
        }

        lookups
    }
}
