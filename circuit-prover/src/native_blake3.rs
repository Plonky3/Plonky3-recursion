//! The native BLAKE3 table of the native bus circuit: one compression per row.
//!
//! A row holds the bits of one compression in the upstream binary BLAKE3 AIR. Every input and
//! output limb of a call, and its output limbs with their two bytes swapped when the call outputs
//! them, is a weighted sum of sixteen of those bits, and the row pushes it onto the witness bus
//! under its preprocessed witness label. Output bits are sums of the last round's cells, so every
//! pushed limb has degree one. The bits are Boolean by the AIR, or by a commitment that stores
//! bits, so every pushed limb spans sixteen coordinates. A row may push a slot of limbs as one
//! carrier element instead, see [`ElementSlots`].

use alloc::vec::Vec;
use core::array;
use core::borrow::Borrow;

use p3_air::{Air, AirBuilder};
use p3_blake3_air::{
    Blake3BinaryAir, Blake3BinaryCols, Blake3BinaryGCols, Blake3CompressionInput,
    generate_binary_trace_packed, generate_binary_trace_rows,
};
use p3_bus::{BusActivation, BusDirection, BusInteractionBuilder, BusName};
use p3_circuit::Circuit;
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::native_blake3::NATIVE_BLAKE3_OUTPUT_LIMBS;
use p3_circuit::ops::{BLAKE3_INPUT_LIMBS, NpoTypeId, Op, limbs_to_words};
use p3_circuit::tables::WitnessTrace;
use p3_circuit::types::WitnessId;
use p3_field::{Algebra, Field};
use p3_matrix::dense::RowMajorMatrix;

use crate::indexed::cells;
use crate::native_bus::NativeBusCircuitError;

/// Limbs a row pushes: the call's input limbs, its output limbs, then its output limbs with
/// their two bytes swapped.
const PUSHED_LIMBS: usize = BLAKE3_INPUT_LIMBS + 2 * NATIVE_BLAKE3_OUTPUT_LIMBS;
/// Pushed limbs under the call activation; the swapped output limbs follow.
const CALL_LIMBS: usize = BLAKE3_INPUT_LIMBS + NATIVE_BLAKE3_OUTPUT_LIMBS;
/// Input limbs of a call's block: its first sixteen input words.
const BLOCK_LIMBS: usize = 32;
/// Preprocessed columns: the call activation, a witness label per pushed limb, and the
/// swapped-digest activation. A table that binds elements adds an activation per slot.
const BLAKE3_PP: usize = PUSHED_LIMBS + 2;
const ACTIVE: usize = 0;
const LABELS: usize = 1;
const SWAPPED_ACTIVE: usize = LABELS + PUSHED_LIMBS;
const BOUND: usize = BLAKE3_PP;

/// Runs of pushed limbs that a row can push as one carrier element of `words` sixteen-bit
/// words: the block's aligned runs of `words` limbs, then the swapped output limbs `words` at a
/// time in the order a draw reads them, from the back. A bound slot pushes
/// `sum_j shift_j * limb_j` over its words `limb_j`, with `shift_j` the element of raw
/// coordinate `16 * j`, under the label of its word 0 in place of its limbs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ElementSlots {
    words: usize,
}

impl ElementSlots {
    /// The slots of a carrier of `F::COORDINATE_BITS / 16` words, when that is more than one.
    pub(crate) const fn of<F: BinaryCoordinateField>() -> Option<Self> {
        let words = F::COORDINATE_BITS / 16;
        if words > 1 {
            Some(Self { words })
        } else {
            None
        }
    }

    /// Slots per row: the block's, then the swapped output limbs'.
    pub(crate) const fn count(self) -> usize {
        (BLOCK_LIMBS + NATIVE_BLAKE3_OUTPUT_LIMBS) / self.words
    }

    /// The pushed limbs of slot `slot`'s words, word 0 first.
    pub(crate) fn limbs(self, slot: usize) -> impl Iterator<Item = usize> {
        let block = BLOCK_LIMBS / self.words;
        (0..self.words).map(move |j| {
            if slot < block {
                self.words * slot + j
            } else {
                PUSHED_LIMBS - 1 - self.words * (slot - block) - j
            }
        })
    }

    /// `shift_j` for each word `j` of a slot.
    pub(crate) fn shifts<F: BinaryCoordinateField>(self) -> Vec<F> {
        (0..self.words)
            .map(|j| F::from_raw_coordinates(1 << (16 * j)).expect("a slot spans the carrier"))
            .collect()
    }
}

/// Preprocessed columns of a table that binds elements to `slots`, when it binds any.
pub(crate) fn blake3_preprocessed_width(slots: Option<ElementSlots>) -> usize {
    BLAKE3_PP + slots.map_or(0, ElementSlots::count)
}

/// The `a`, `b`, `c`, `d` word indices of each G step of a round: four column steps, then four
/// diagonal steps.
const G_SCHEDULE: [[usize; 4]; 8] = [
    [0, 0, 0, 0],
    [1, 1, 1, 1],
    [2, 2, 2, 2],
    [3, 3, 3, 3],
    [0, 1, 2, 3],
    [1, 2, 3, 0],
    [2, 3, 0, 1],
    [3, 0, 1, 2],
];

#[derive(Clone, Debug)]
pub(crate) struct Blake3Call {
    pub(crate) input: [usize; BLAKE3_INPUT_LIMBS],
    pub(crate) output: [usize; NATIVE_BLAKE3_OUTPUT_LIMBS],
    /// Outputs holding the output limbs with their two bytes swapped.
    pub(crate) swapped: Option<[usize; NATIVE_BLAKE3_OUTPUT_LIMBS]>,
    /// The element each slot of the table's [`ElementSlots`] pushes, by slot; empty when the
    /// row binds none.
    pub(crate) bound: Vec<Option<usize>>,
}

impl Blake3Call {
    /// The witness ID of pushed limb `limb`, in label order, unless it is a swapped output limb
    /// of a call that outputs none.
    pub(crate) fn limb(&self, limb: usize) -> Option<usize> {
        match limb {
            0..BLAKE3_INPUT_LIMBS => Some(self.input[limb]),
            BLAKE3_INPUT_LIMBS..CALL_LIMBS => Some(self.output[limb - BLAKE3_INPUT_LIMBS]),
            _ => self.swapped.map(|swapped| swapped[limb - CALL_LIMBS]),
        }
    }

    /// The witness ID each label column of the call's row labels, by pushed limb: the limb's own,
    /// except that a slot bound under `slots` labels its word 0's column with its element and
    /// leaves its other columns unlabelled. The row pushes exactly the labelled columns.
    pub(crate) fn labels(&self, slots: Option<ElementSlots>) -> [Option<usize>; PUSHED_LIMBS] {
        let mut labels = array::from_fn(|limb| self.limb(limb));
        for (slot, &element) in self.bound.iter().enumerate() {
            if let (Some(element), Some(slots)) = (element, slots) {
                for (j, limb) in slots.limbs(slot).enumerate() {
                    labels[limb] = (j == 0).then_some(element);
                }
            }
        }
        labels
    }
}

/// Called only after the primitive plan has validated operation identities and IDs.
pub(crate) fn blake3_calls<F: Field>(
    circuit: &Circuit<F>,
) -> Result<Vec<Blake3Call>, NativeBusCircuitError> {
    let mut calls = Vec::new();
    for (operation, op) in circuit.ops.iter().enumerate() {
        if let Op::NonPrimitiveOpWithExecutor {
            inputs,
            outputs,
            executor,
            ..
        } = op
            && executor.op_type() == &NpoTypeId::native_blake3_compress()
        {
            if inputs.len() != 1
                || outputs.len() != 1
                || inputs[0].len() != BLAKE3_INPUT_LIMBS
                || ![NATIVE_BLAKE3_OUTPUT_LIMBS, 2 * NATIVE_BLAKE3_OUTPUT_LIMBS]
                    .contains(&outputs[0].len())
            {
                return Err(NativeBusCircuitError::Blake3Layout { operation });
            }
            let id = |i: usize| outputs[0][i].0 as usize;
            calls.push(Blake3Call {
                input: array::from_fn(|i| inputs[0][i].0 as usize),
                output: array::from_fn(id),
                swapped: (outputs[0].len() > NATIVE_BLAKE3_OUTPUT_LIMBS)
                    .then(|| array::from_fn(|m| id(NATIVE_BLAKE3_OUTPUT_LIMBS + m))),
                bound: Vec::new(),
            });
        }
    }
    Ok(calls)
}

/// The preprocessed rows of a table of `height` rows that binds elements to `slots`, when it
/// binds any: a call's row is active and labels its columns (see [`Blake3Call::labels`]) by
/// witness ID plus one, activates its swapped output limbs when the call outputs them, and
/// activates each bound slot. Every other cell is zero. `label` encodes a label.
pub(crate) fn blake3_preprocessed<F: Field>(
    calls: &[Blake3Call],
    slots: Option<ElementSlots>,
    height: usize,
    label: impl Fn(usize) -> Result<F, NativeBusCircuitError>,
) -> Result<RowMajorMatrix<F>, NativeBusCircuitError> {
    let width = blake3_preprocessed_width(slots);
    let mut pp = F::zero_vec(cells(height, width)?);
    for (row, call) in pp.chunks_exact_mut(width).zip(calls) {
        row[ACTIVE] = F::ONE;
        for (cell, id) in row[LABELS..].iter_mut().zip(call.labels(slots)) {
            if let Some(id) = id {
                *cell = label(id + 1)?;
            }
        }
        row[SWAPPED_ACTIVE] = F::from_bool(call.swapped.is_some());
        for (cell, element) in row[BOUND..].iter_mut().zip(&call.bound) {
            *cell = F::from_bool(element.is_some());
        }
    }
    Ok(RowMajorMatrix::new(pp, width))
}

/// Compression inputs of the calls, padded to `height` with zero inputs, after checking every
/// input and output limb spans 16 bits. Callers validate witness IDs first.
fn blake3_inputs<F: BinaryCoordinateField>(
    calls: &[Blake3Call],
    witness: &WitnessTrace<F>,
    height: usize,
) -> Result<Vec<Blake3CompressionInput>, NativeBusCircuitError> {
    let limb = |w: usize| {
        let value = witness
            .get_value(WitnessId(w as u32))
            .expect("validated witness length and call IDs");
        u16::try_from(value.to_raw_coordinates())
            .map_err(|_| NativeBusCircuitError::InvalidBlake3Limb { witness: w })
    };
    let mut inputs = Vec::with_capacity(height);
    for call in calls {
        let mut limbs = [0u16; BLAKE3_INPUT_LIMBS];
        for (limb_value, &w) in limbs.iter_mut().zip(&call.input) {
            *limb_value = limb(w)?;
        }
        for &w in &call.output {
            limb(w)?;
        }
        let words = limbs_to_words(&limbs);
        inputs.push(Blake3CompressionInput {
            block: array::from_fn(|j| words[j]),
            chaining_value: array::from_fn(|j| words[16 + j]),
            counter: u64::from(words[24]) | u64::from(words[25]) << 32,
            block_len: words[26],
            flags: words[27],
        });
    }
    inputs.resize(height, Blake3CompressionInput::default());
    Ok(inputs)
}

/// The table's bits, one compression per row; rows past the calls compress zero inputs. Callers
/// validate witness IDs and bound the planned trace geometry first.
pub(crate) fn blake3_trace<F: BinaryCoordinateField>(
    calls: &[Blake3Call],
    witness: &WitnessTrace<F>,
    height: usize,
) -> Result<RowMajorMatrix<F>, NativeBusCircuitError> {
    Ok(generate_binary_trace_rows(
        blake3_inputs(calls, witness, height)?,
        0,
    ))
}

/// The bits of [`blake3_trace`] as one word per 64 rows and column, in the layout of
/// `Table::from_packed_bits`: block `b` holds rows `64 * b..64 * b + 64`, bit zero first. Bits
/// past `height` in the last block are zero.
pub(crate) fn blake3_packed_words<F: BinaryCoordinateField>(
    calls: &[Blake3Call],
    witness: &WitnessTrace<F>,
    height: usize,
) -> Result<RowMajorMatrix<u64>, NativeBusCircuitError> {
    Ok(generate_binary_trace_packed::<F>(blake3_inputs(
        calls, witness, height,
    )?))
}

/// Constrains the current row to one compression, with the booleanity of its input cells unless
/// `assume_boolean`, and pushes its limbs onto `witness_bus`, the element of each slot of `slots`
/// that the row binds in place of the slot's limbs. `row` and `pp` are the row's main and
/// preprocessed cells. `assume_boolean` is sound only when the table is committed as bits.
pub(crate) fn eval_blake3<AB>(
    builder: &mut AB,
    row: &[AB::Var],
    pp: &[AB::Var],
    weights: &[AB::F; 16],
    slots: Option<ElementSlots>,
    assume_boolean: bool,
    witness_bus: BusName<'_>,
) where
    AB: AirBuilder + BusInteractionBuilder,
    AB::F: BinaryCoordinateField,
{
    let air = if assume_boolean {
        Blake3BinaryAir::assuming_boolean_trace()
    } else {
        Blake3BinaryAir::default()
    };
    air.eval(builder);
    let cols: &Blake3BinaryCols<AB::Var> = row.borrow();
    let limbs = pushed_limbs::<AB::Var, AB::Expr, AB::F>(cols, weights);
    let mut slot_of = [None; PUSHED_LIMBS];
    if let Some(slots) = slots {
        for slot in 0..slots.count() {
            for limb in slots.limbs(slot) {
                slot_of[limb] = Some(slot);
            }
        }
    }
    for (i, limb) in limbs.iter().enumerate() {
        let active: AB::Expr = if i < CALL_LIMBS {
            pp[ACTIVE]
        } else {
            pp[SWAPPED_ACTIVE]
        }
        .into();
        // A slot is bound only on an active row and, for a swapped slot, only when the call
        // outputs swapped limbs, so the difference is Boolean: zero exactly on a bound slot.
        let active = match slot_of[i] {
            Some(slot) => active - pp[BOUND + slot],
            None => active,
        };
        builder.push_bus_interaction(
            witness_bus,
            BusDirection::Push,
            [pp[LABELS + i].into(), limb.clone()],
            BusActivation::Boolean(active),
        );
    }
    let Some(slots) = slots else {
        return;
    };
    let shifts = slots.shifts::<AB::F>();
    for slot in 0..slots.count() {
        let element: AB::Expr = slots
            .limbs(slot)
            .zip(&shifts)
            .map(|(limb, &shift)| limbs[limb].clone() * shift)
            .sum();
        let first = slots.limbs(slot).next().expect("a slot has words");
        builder.push_bus_interaction(
            witness_bus,
            BusDirection::Push,
            [pp[LABELS + first].into(), element],
            BusActivation::Boolean(pp[BOUND + slot].into()),
        );
    }
}

/// The limbs a row pushes, in label order: the 56 input limbs, the 16 output limbs, then the 16
/// output limbs with their two bytes swapped. Each is the sum of its sixteen bits weighted by
/// `weights`, low bit first; exchanging the weights of a limb's two bytes swaps them.
fn pushed_limbs<T, E, F>(cols: &Blake3BinaryCols<T>, weights: &[F; 16]) -> Vec<E>
where
    T: Copy,
    E: Algebra<T> + Algebra<F>,
    F: Field,
{
    let swapped: [F; 16] = array::from_fn(|bit| weights[bit ^ 8]);
    let limb = |bits: &[E], weights: &[F; 16]| -> E {
        bits.iter()
            .zip(weights)
            .map(|(bit, &weight)| bit.clone() * weight)
            .sum()
    };
    let output: Vec<[E; 32]> = (0..8).map(|word| output_word(cols, word)).collect();
    let mut limbs = Vec::with_capacity(PUSHED_LIMBS);
    for word in 0..BLAKE3_INPUT_LIMBS / 2 {
        let bits = input_word(cols, word).map(E::from);
        limbs.extend(bits.chunks(16).map(|half| limb(half, weights)));
    }
    for weights in [weights, &swapped] {
        for bits in &output {
            limbs.extend(bits.chunks(16).map(|half| limb(half, weights)));
        }
    }
    limbs
}

/// Input word `word` of the call: the sixteen block words, the eight chaining-value words, the
/// counter's low and high words, the block length and the flags.
const fn input_word<T: Copy>(cols: &Blake3BinaryCols<T>, word: usize) -> [T; 32] {
    match word {
        0..16 => cols.block[word],
        16..24 => cols.chaining_value[word - 16],
        24 => cols.counter_low,
        25 => cols.counter_high,
        26 => cols.block_len,
        _ => cols.flags,
    }
}

/// The bits of output word `word < 8`: `v[word] ^ v[word + 8]` of the final state. Each state
/// word is read from the last-round step that last writes it, where `a = d1 ^ (d2 <<< 8)`,
/// `b = b2`, `c = b1 ^ (b2 <<< 7)` and `d = d2`, so each bit is a sum of two or four cells.
fn output_word<T: Copy, E: Algebra<T>>(cols: &Blake3BinaryCols<T>, word: usize) -> [E; 32] {
    let round = cols.rounds.last().expect("a compression has rounds");
    let last = |position: usize, index: usize| -> &Blake3BinaryGCols<T> {
        let step = G_SCHEDULE
            .iter()
            .rposition(|step| step[position] == index)
            .expect("every round writes every state word");
        &round[step]
    };
    // Bit `i` of `x <<< s` is bit `(i - s) mod 32` of `x`.
    if word < 4 {
        let (a, c) = (last(0, word), last(2, word));
        array::from_fn(|i| E::from(a.d1[i]) + a.d2[(i + 24) % 32] + c.b1[i] + c.b2[(i + 25) % 32])
    } else {
        let (b, d) = (last(1, word - 4), last(3, word - 4));
        array::from_fn(|i| E::from(b.b2[i]) + d.d2[i])
    }
}

#[cfg(test)]
mod tests {
    use p3_blake3_air::NUM_BLAKE3_BINARY_COLS;
    use p3_circuit::ops::{blake3_compress, words_to_limbs};
    use p3_field::PrimeCharacteristicRing;
    use p3_test_utils::binary_field_params::BinaryField128;

    use super::*;

    type F = BinaryField128;

    /// The pushed limb expressions of rows generated by the upstream AIR are the input words,
    /// the compression output and its byte-swapped limbs. This pins the local step schedule and
    /// the rotations against the upstream trace.
    #[test]
    fn pushed_limbs_are_the_inputs_and_the_compression_output() {
        let weights: [F; 16] = array::from_fn(|i| F::from_raw_coordinates(1 << i).unwrap());
        let inputs: Vec<Blake3CompressionInput> = (0..8u32)
            .map(|seed| {
                let word = |i: u32| {
                    (i + 1).wrapping_mul(0x9E37_79B1).rotate_left(seed + 3)
                        ^ seed.wrapping_mul(0x85EB_CA6B)
                };
                Blake3CompressionInput {
                    block: array::from_fn(|j| word(j as u32)),
                    chaining_value: array::from_fn(|j| word(16 + j as u32)),
                    counter: u64::from(word(24)) | u64::from(word(25)) << 32,
                    block_len: word(26),
                    flags: word(27),
                }
            })
            .collect();
        let trace = generate_binary_trace_rows::<F>(inputs.clone(), 0);
        for (row, input) in trace.values.chunks(NUM_BLAKE3_BINARY_COLS).zip(&inputs) {
            let cols: &Blake3BinaryCols<F> = row.borrow();
            let mut words = input.block.to_vec();
            words.extend(input.chaining_value);
            words.extend([
                input.counter as u32,
                (input.counter >> 32) as u32,
                input.block_len,
                input.flags,
            ]);
            let output = cols.compression_output();
            let expected = blake3_compress(&words.clone().try_into().unwrap());
            assert_eq!(output, expected);
            let output = words_to_limbs(&output[..8]);
            let mut limbs = words_to_limbs(&words);
            limbs.extend(&output);
            limbs.extend(output.iter().map(|limb| limb.swap_bytes()));
            let actual = pushed_limbs::<F, F, F>(cols, &weights);
            let expected: Vec<F> = limbs
                .into_iter()
                .map(|limb| F::from_raw_coordinates(limb.into()).unwrap())
                .collect();
            assert_eq!(actual, expected);
        }
    }

    #[test]
    fn preprocessing_labels_the_pushed_limbs_in_order() {
        let call = Blake3Call {
            input: array::from_fn(|i| 100 + i),
            output: array::from_fn(|i| 200 + i),
            swapped: Some(array::from_fn(|i| 300 + i)),
            bound: Vec::new(),
        };
        let plain = Blake3Call {
            swapped: None,
            ..call.clone()
        };
        let label = |id: usize| Ok(F::from_raw_coordinates(id as u128).unwrap());
        let pp = blake3_preprocessed::<F>(&[call, plain], None, 4, label).unwrap();
        let rows = pp.values.as_chunks::<BLAKE3_PP>().0;
        let ids: Vec<usize> = (100..156).chain(200..216).chain(300..316).collect();
        for (row, swapped) in rows.iter().zip([true, false]) {
            assert_eq!(row[ACTIVE], F::ONE);
            assert_eq!(row[SWAPPED_ACTIVE], F::from_bool(swapped));
            for (i, &id) in ids.iter().enumerate() {
                let expected = if i < CALL_LIMBS || swapped { id + 1 } else { 0 };
                assert_eq!(
                    row[LABELS + i],
                    F::from_raw_coordinates(expected as u128).unwrap()
                );
            }
        }
        assert!(rows[2..].iter().flatten().all(|&cell| cell == F::ZERO));
    }
}
