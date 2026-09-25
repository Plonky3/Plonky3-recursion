//! [`Blake3CompressAir`] proves the circuit's BLAKE3 compressions.
//!
//! The main trace is `p3-blake3-air`'s [`Blake3Air`] trace, one compression per row, followed by
//! one column per exchanged limb. The compression constraints are that AIR's own, evaluated on
//! the leading columns. This wrapper fills the trace with each call's real counter, block length
//! and flags (the upstream generator fixes them for benchmarking), and adds the witness-bus
//! lookups that tie each call's limbs to the circuit's witness table.
//!
//! # Limb columns
//!
//! After the `Blake3Cols` block: 56 input limbs, then 32 output limbs, each constrained to the
//! little-endian packing of 16 of `Blake3Air`'s boolean columns. The lookups read these single
//! columns rather than the 16-term packings: symbolic lookup analysis resolves every main-column
//! leaf of a lookup against a copy of the whole main window, so one leaf per limb instead of
//! sixteen makes that analysis sixteen times cheaper.
//!
//! # Preprocessed columns
//!
//! Per row: `active`, `in_idx_0 … in_idx_55`, `out_idx_0 … out_idx_31`, `out_mult_0 … out_mult_31`.
//! Padding rows are zero, which disables every lookup; their main rows compress zero inputs.
//!
//! # Lookups (per row, on the `WitnessChecks` bus)
//!
//! - **Send** `[in_idx_j, input limb j, 0, …]` with multiplicity `-active`. Each input limb
//!   equals a packing of 16 boolean columns, so it is below `2^16`.
//! - **Receive** `[out_idx_j, output limb j, 0, …]` with multiplicity `out_mult_j`.

use alloc::vec;
use alloc::vec::Vec;
use core::array;
use core::borrow::{Borrow, BorrowMut};
use core::marker::PhantomData;

use p3_air::utils::{pack_bits_le, u32_to_bits_le};
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_blake3_air::{Blake3Air, Blake3Cols, Blake3State, FullRound, NUM_BLAKE3_COLS};
use p3_circuit::ops::{
    BLAKE3_INPUT_LIMBS, BLAKE3_INPUT_WORDS, BLAKE3_IV, BLAKE3_OUTPUT_LIMBS,
    Blake3CompressCircuitRow, blake3_compress, words_to_limbs,
};
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use p3_uni_stark::SubAirBuilder;

/// Preprocessed values the circuit emits per call: `[active, in_idx × 56, (out_idx, out_mult) × 32]`.
pub const BLAKE3_PREP_OP_WIDTH: usize = 1 + BLAKE3_INPUT_LIMBS + 2 * BLAKE3_OUTPUT_LIMBS;
/// Preprocessed columns per row: `[active, in_idx × 56, out_idx × 32, out_mult × 32]`.
pub const BLAKE3_PREP_ROW_WIDTH: usize = BLAKE3_PREP_OP_WIDTH;
/// Limb columns appended after the `Blake3Cols` block.
pub const BLAKE3_LIMB_COLS: usize = BLAKE3_INPUT_LIMBS + BLAKE3_OUTPUT_LIMBS;
/// Main trace width.
pub const BLAKE3_COMPRESS_WIDTH: usize = NUM_BLAKE3_COLS + BLAKE3_LIMB_COLS;

const MSG_PERMUTATION: [usize; 16] = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];

/// AIR for the BLAKE3 compression table.
#[derive(Debug, Clone)]
pub struct Blake3CompressAir<F, const D: usize> {
    /// Per-call preprocessed values, [`BLAKE3_PREP_OP_WIDTH`] per call.
    pub(crate) preprocessed: Vec<F>,
    pub(crate) min_height: usize,
    _phantom: PhantomData<F>,
}

impl<F: PrimeField64, const D: usize> Blake3CompressAir<F, D> {
    /// An AIR over the given per-call preprocessed values.
    pub const fn new_with_preprocessed(preprocessed: Vec<F>, min_height: usize) -> Self {
        Self {
            preprocessed,
            min_height,
            _phantom: PhantomData,
        }
    }

    /// Calls described by the preprocessed values.
    pub const fn num_ops(&self) -> usize {
        self.preprocessed.len() / BLAKE3_PREP_OP_WIDTH
    }

    /// Trace height: a power of two holding every call, at least `min_height`.
    pub fn height_for(num_ops: usize, min_height: usize) -> usize {
        num_ops
            .max(1)
            .next_power_of_two()
            .max(min_height.next_power_of_two())
    }

    /// Main trace for the given calls at exactly `height` rows; padding rows compress zeros.
    pub fn trace_to_matrix(ops: &[Blake3CompressCircuitRow], height: usize) -> RowMajorMatrix<F> {
        assert!(height.is_power_of_two() && height >= ops.len());
        let mut values = F::zero_vec(height * BLAKE3_COMPRESS_WIDTH);
        values
            .par_chunks_exact_mut(BLAKE3_COMPRESS_WIDTH)
            .enumerate()
            .for_each(|(i, row)| {
                let input = ops.get(i).map_or([0; BLAKE3_INPUT_WORDS], |op| op.input);
                let (cols, limbs) = row.split_at_mut(NUM_BLAKE3_COLS);
                fill_row(cols.borrow_mut(), &input);
                let mut words = input.to_vec();
                words.extend_from_slice(&blake3_compress(&input));
                for (limb, value) in limbs.iter_mut().zip(words_to_limbs(&words)) {
                    *limb = F::from_u16(value);
                }
            });
        RowMajorMatrix::new(values, BLAKE3_COMPRESS_WIDTH)
    }
}

/// One half of a BLAKE3 quarter round, as `Blake3Air` checks it: `flag` selects the second half.
const fn half_round(
    mut a: u32,
    mut b: u32,
    mut c: u32,
    mut d: u32,
    m: u32,
    flag: bool,
) -> (u32, u32, u32, u32) {
    let (rot_1, rot_2) = if flag { (8, 7) } else { (16, 12) };
    a = a.wrapping_add(b).wrapping_add(m);
    d = (d ^ a).rotate_right(rot_1);
    c = c.wrapping_add(d);
    b = (b ^ c).rotate_right(rot_2);
    (a, b, c, d)
}

fn save_state<F: PrimeCharacteristicRing>(trace: &mut Blake3State<F>, state: &[[u32; 4]; 4]) {
    let limbs = |w: u32| [F::from_u16(w as u16), F::from_u16((w >> 16) as u16)];
    trace.row0 = array::from_fn(|i| limbs(state[0][i]));
    trace.row1 = array::from_fn(|i| u32_to_bits_le(state[1][i]));
    trace.row2 = array::from_fn(|i| limbs(state[2][i]));
    trace.row3 = array::from_fn(|i| u32_to_bits_le(state[3][i]));
}

fn fill_round<F: PrimeCharacteristicRing>(
    round: &mut FullRound<F>,
    state: &mut [[u32; 4]; 4],
    m: &[u32; 16],
) {
    for i in 0..4 {
        (state[0][i], state[1][i], state[2][i], state[3][i]) = half_round(
            state[0][i],
            state[1][i],
            state[2][i],
            state[3][i],
            m[2 * i],
            false,
        );
    }
    save_state(&mut round.state_prime, state);
    for i in 0..4 {
        (state[0][i], state[1][i], state[2][i], state[3][i]) = half_round(
            state[0][i],
            state[1][i],
            state[2][i],
            state[3][i],
            m[2 * i + 1],
            true,
        );
    }
    save_state(&mut round.state_middle, state);
    for flag in [false, true] {
        for i in 0..4 {
            let (b, c, d) = ((i + 1) % 4, (i + 2) % 4, (i + 3) % 4);
            (state[0][i], state[1][b], state[2][c], state[3][d]) = half_round(
                state[0][i],
                state[1][b],
                state[2][c],
                state[3][d],
                m[8 + 2 * i + usize::from(flag)],
                flag,
            );
        }
        if flag {
            save_state(&mut round.state_output, state);
        } else {
            save_state(&mut round.state_middle_prime, state);
        }
    }
}

/// Fills one `Blake3Air` row for a compression of `input` (block, chaining value, counter words,
/// block length, flags).
fn fill_row<F: PrimeCharacteristicRing>(
    row: &mut Blake3Cols<F>,
    input: &[u32; BLAKE3_INPUT_WORDS],
) {
    let cv: [u32; 8] = array::from_fn(|i| input[16 + i]);
    let mut m: [u32; 16] = array::from_fn(|i| input[i]);

    row.inputs = array::from_fn(|i| u32_to_bits_le(input[i]));
    row.chaining_values = array::from_fn(|i| array::from_fn(|j| u32_to_bits_le(cv[4 * i + j])));
    row.counter_low = u32_to_bits_le(input[24]);
    row.counter_hi = u32_to_bits_le(input[25]);
    row.block_len = u32_to_bits_le(input[26]);
    row.flags = u32_to_bits_le(input[27]);
    row.initial_row0 =
        array::from_fn(|i| [F::from_u16(cv[i] as u16), F::from_u16((cv[i] >> 16) as u16)]);
    row.initial_row2 = array::from_fn(|i| {
        [
            F::from_u16(BLAKE3_IV[i] as u16),
            F::from_u16((BLAKE3_IV[i] >> 16) as u16),
        ]
    });

    let mut state = [
        [cv[0], cv[1], cv[2], cv[3]],
        [cv[4], cv[5], cv[6], cv[7]],
        [BLAKE3_IV[0], BLAKE3_IV[1], BLAKE3_IV[2], BLAKE3_IV[3]],
        [input[24], input[25], input[26], input[27]],
    ];
    for (r, round) in row.full_rounds.iter_mut().enumerate() {
        fill_round(round, &mut state, &m);
        if r < 6 {
            m = array::from_fn(|i| m[MSG_PERMUTATION[i]]);
        }
    }

    row.final_round_helpers = array::from_fn(|i| u32_to_bits_le(state[2][i]));
    row.outputs[0] = array::from_fn(|i| u32_to_bits_le(state[0][i] ^ state[2][i]));
    row.outputs[1] = array::from_fn(|i| u32_to_bits_le(state[1][i] ^ state[3][i]));
    row.outputs[2] = array::from_fn(|i| u32_to_bits_le(state[2][i] ^ cv[i]));
    row.outputs[3] = array::from_fn(|i| u32_to_bits_le(state[3][i] ^ cv[4 + i]));
}

impl<F: PrimeField64, const D: usize> BaseAir<F> for Blake3CompressAir<F, D> {
    fn width(&self) -> usize {
        BLAKE3_COMPRESS_WIDTH
    }

    fn preprocessed_width(&self) -> usize {
        BLAKE3_PREP_ROW_WIDTH
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let height = Self::height_for(self.num_ops(), self.min_height);
        let mut values = F::zero_vec(height * BLAKE3_PREP_ROW_WIDTH);
        for (row, prep) in values
            .chunks_exact_mut(BLAKE3_PREP_ROW_WIDTH)
            .zip(self.preprocessed.chunks_exact(BLAKE3_PREP_OP_WIDTH))
        {
            row[..1 + BLAKE3_INPUT_LIMBS].copy_from_slice(&prep[..1 + BLAKE3_INPUT_LIMBS]);
            let outputs = &prep[1 + BLAKE3_INPUT_LIMBS..];
            for (j, pair) in outputs.chunks_exact(2).enumerate() {
                row[1 + BLAKE3_INPUT_LIMBS + j] = pair[0];
                row[1 + BLAKE3_INPUT_LIMBS + BLAKE3_OUTPUT_LIMBS + j] = pair[1];
            }
        }
        Some(RowMajorMatrix::new(values, BLAKE3_PREP_ROW_WIDTH))
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn max_constraint_degree(&self) -> Option<usize> {
        Some(3)
    }
}

impl<AB, const D: usize> Air<AB> for Blake3CompressAir<AB::F, D>
where
    AB: AirBuilder + InteractionBuilder,
    AB::F: PrimeField64,
{
    fn eval(&self, builder: &mut AB) {
        let mut sub = SubAirBuilder::<AB, Blake3Air, AB::Var>::new(builder, 0..NUM_BLAKE3_COLS);
        Blake3Air {}.eval(&mut sub);

        let main = builder.main();
        let row = main.current_slice();
        let local: &Blake3Cols<AB::Var> = row[..NUM_BLAKE3_COLS].borrow();
        let limbs = &row[NUM_BLAKE3_COLS..];
        let prep = builder.preprocessed().clone();
        let prep_local = prep.current_slice();

        // Input words in the circuit's order (block, chaining value, counter lo/hi, length,
        // flags), then the output words; each limb column packs 16 boolean columns.
        let words = local
            .inputs
            .iter()
            .chain(local.chaining_values.iter().flatten())
            .chain([
                &local.counter_low,
                &local.counter_hi,
                &local.block_len,
                &local.flags,
            ])
            .chain(local.outputs.iter().flatten());
        for (bits, pair) in words.zip(limbs.chunks_exact(2)) {
            let lo: AB::Expr = pack_bits_le(bits[..16].iter().copied());
            let hi: AB::Expr = pack_bits_le(bits[16..].iter().copied());
            builder.assert_eq(pair[0], lo);
            builder.assert_eq(pair[1], hi);
        }

        let tuple = |idx: AB::Expr, limb: AB::Var| {
            let mut values: Vec<AB::Expr> = Vec::with_capacity(1 + D);
            values.push(idx);
            values.push(limb.into());
            values.resize(1 + D, AB::Expr::ZERO);
            values
        };
        let active: AB::Expr = prep_local[0].into();
        for (j, &limb) in limbs[..BLAKE3_INPUT_LIMBS].iter().enumerate() {
            builder.push_interaction(
                "WitnessChecks",
                tuple(prep_local[1 + j].into(), limb),
                Count::bounded(-active.clone(), 1),
            );
        }
        for (j, &limb) in limbs[BLAKE3_INPUT_LIMBS..].iter().enumerate() {
            let idx = prep_local[1 + BLAKE3_INPUT_LIMBS + j].into();
            let mult: AB::Expr =
                prep_local[1 + BLAKE3_INPUT_LIMBS + BLAKE3_OUTPUT_LIMBS + j].into();
            builder.push_interaction("WitnessChecks", tuple(idx, limb), Count::bounded(mult, 1));
        }
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use alloc::vec;
    use core::borrow::BorrowMut;

    use p3_air::check_constraints;
    use p3_baby_bear::BabyBear;
    use p3_circuit::ops::{blake3_flags, limbs_to_words};

    use super::*;

    /// The `Blake3Cols` block of each row, the part `Blake3Air` constrains.
    fn blake3_block(trace: &RowMajorMatrix<BabyBear>) -> RowMajorMatrix<BabyBear> {
        let values = trace
            .values
            .chunks_exact(BLAKE3_COMPRESS_WIDTH)
            .flat_map(|row| row[..NUM_BLAKE3_COLS].iter().copied())
            .collect();
        RowMajorMatrix::new(values, NUM_BLAKE3_COLS)
    }

    fn row_input(seed: u32, counter: u64, block_len: u32, flags: u32) -> [u32; BLAKE3_INPUT_WORDS] {
        let mut input: [u32; BLAKE3_INPUT_WORDS] =
            array::from_fn(|i| seed.wrapping_mul(0x9e37_79b9).rotate_left(i as u32));
        input[24] = counter as u32;
        input[25] = (counter >> 32) as u32;
        input[26] = block_len;
        input[27] = flags;
        input
    }

    /// Rows filled with real counters, lengths and flags satisfy `Blake3Air`, and their output
    /// columns hold the native compression.
    #[test]
    fn filled_rows_satisfy_blake3_air_and_match_native_compression() {
        let inputs = [
            row_input(1, 0, 64, blake3_flags::CHUNK_START),
            row_input(
                2,
                (1 << 32) + 5,
                17,
                blake3_flags::CHUNK_END | blake3_flags::ROOT,
            ),
            row_input(3, 7, 64, blake3_flags::PARENT),
        ];
        let ops: Vec<Blake3CompressCircuitRow> = inputs
            .iter()
            .map(|&input| Blake3CompressCircuitRow {
                input_wids: vec![],
                output_wids: vec![],
                input,
            })
            .collect();
        let trace = Blake3CompressAir::<BabyBear, 4>::trace_to_matrix(&ops, 4);
        check_constraints(&Blake3Air {}, &blake3_block(&trace), &[]);

        for (row, input) in trace
            .values
            .chunks_exact(BLAKE3_COMPRESS_WIDTH)
            .zip(&inputs)
        {
            let cols: &Blake3Cols<BabyBear> = row[..NUM_BLAKE3_COLS].borrow();
            let limbs: Vec<u16> = cols
                .outputs
                .iter()
                .flatten()
                .flat_map(|bits| {
                    [0, 16].map(|start| {
                        bits[start..start + 16]
                            .iter()
                            .rev()
                            .fold(0u16, |acc, b| (acc << 1) | b.as_canonical_u64() as u16)
                    })
                })
                .collect();
            assert_eq!(limbs_to_words(&limbs), blake3_compress(input));
            let limb_cols: Vec<u16> = row[NUM_BLAKE3_COLS..]
                .iter()
                .map(|v| v.as_canonical_u64() as u16)
                .collect();
            let mut words = input.to_vec();
            words.extend_from_slice(&blake3_compress(input));
            assert_eq!(limb_cols, words_to_limbs(&words));
        }
    }

    /// A flags bit that disagrees with the rounds it fed is caught by `Blake3Air`.
    #[test]
    fn a_row_whose_flags_disagree_with_its_rounds_is_rejected() {
        let ops = vec![Blake3CompressCircuitRow {
            input_wids: vec![],
            output_wids: vec![],
            input: row_input(4, 0, 64, blake3_flags::ROOT),
        }];
        let mut trace = blake3_block(&Blake3CompressAir::<BabyBear, 4>::trace_to_matrix(&ops, 2));
        let cols: &mut Blake3Cols<BabyBear> = trace.values[..NUM_BLAKE3_COLS].borrow_mut();
        cols.flags[3] = BabyBear::ZERO;
        let result = std::panic::catch_unwind(|| check_constraints(&Blake3Air {}, &trace, &[]));
        assert!(result.is_err());
    }
}
