//! The native BLAKE3 table of the native bus circuit: one compression per row.
//!
//! A row holds the bits of one compression in the upstream binary BLAKE3 AIR. Every input and
//! output limb of a call, and its output limbs with their two bytes swapped when the call outputs
//! them, is a weighted sum of sixteen of those bits, and the row pushes it onto the witness bus
//! under its preprocessed witness label. Output bits are sums of the last round's cells, so every
//! pushed limb has degree one. The bits are Boolean by the AIR, or by a commitment that stores
//! bits, so every pushed limb spans sixteen coordinates. A row may push a slot of limbs as one
//! carrier element instead, see [`ElementSlots`], and may take constant tail and chaining-value
//! words from preprocessing instead of pushing their limbs, see [`Blake3Layout`].

use alloc::vec::Vec;
use core::array;
use core::borrow::Borrow;
use core::ops::Range;

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
/// Input limbs of a call's chaining value: its next eight input words.
const CHAINING_VALUE: Range<usize> = BLOCK_LIMBS..BLOCK_LIMBS + 16;
/// Input limbs of a call's tail: the counter's low and high words, the block length and the
/// flags.
const TAIL: Range<usize> = CHAINING_VALUE.end..BLAKE3_INPUT_LIMBS;
const CHAINING_VALUE_WORDS: usize = 8;
const TAIL_WORDS: usize = 4;
const ACTIVE: usize = 0;
const LABELS: usize = 1;

/// The preprocessed columns of a BLAKE3 table, in order: the call activation, a witness label
/// per pushed limb that a row can push, the swapped-digest activation, the four tail words when
/// every row takes its tail from preprocessing, a chaining-value flag and eight words when some
/// row takes its chaining value from preprocessing, and an activation per element slot when the
/// rows bind elements.
///
/// A row that takes its tail pushes no tail limb, and the table has no tail label columns: it
/// constrains each tail word `sum_b bit_b * x_b`, over its 32 bits with `x_b` the element of
/// raw coordinate `b`, to equal the preprocessed word, which is zero on a padding row whose
/// inputs are zero. A flagged row takes its chaining value the same way under the flag, and
/// pushes its chaining-value limbs under the call activation minus the flag. The bits are
/// Boolean and the `x_b` independent, so the preprocessed words fix the bits.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct Blake3Layout {
    /// Whether every row takes its tail words from preprocessing.
    pub(crate) constant_tails: bool,
    /// Whether flagged rows take their chaining values from preprocessing.
    pub(crate) constant_chaining_values: bool,
    /// The slots its rows bind elements to, when they bind any.
    pub(crate) elements: Option<ElementSlots>,
}

impl Blake3Layout {
    /// The label column of pushed limb `limb`, unless no row pushes it.
    fn label(self, limb: usize) -> Option<usize> {
        if !self.constant_tails || limb < TAIL.start {
            Some(LABELS + limb)
        } else if TAIL.contains(&limb) {
            None
        } else {
            Some(LABELS + limb - TAIL.len())
        }
    }

    fn swapped_active(self) -> usize {
        LABELS + PUSHED_LIMBS - if self.constant_tails { TAIL.len() } else { 0 }
    }

    /// The first of the four tail-word columns, when every row takes its tail from them.
    fn tail(self) -> Option<usize> {
        self.constant_tails.then(|| self.swapped_active() + 1)
    }

    /// The chaining-value flag column, its eight words following, when rows take constant
    /// chaining values.
    fn chaining_value(self) -> Option<usize> {
        let tail_words = if self.constant_tails { TAIL_WORDS } else { 0 };
        self.constant_chaining_values
            .then(|| self.swapped_active() + 1 + tail_words)
    }

    /// The activation column of element slot 0, the other slots' following.
    fn bound(self) -> usize {
        let tail_words = if self.constant_tails { TAIL_WORDS } else { 0 };
        let chaining_value = if self.constant_chaining_values {
            1 + CHAINING_VALUE_WORDS
        } else {
            0
        };
        self.swapped_active() + 1 + tail_words + chaining_value
    }

    pub(crate) fn width(self) -> usize {
        self.bound() + self.elements.map_or(0, ElementSlots::count)
    }
}

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
    /// The tail words the row takes from preprocessing, when it takes them.
    pub(crate) tail: Option<[u32; TAIL_WORDS]>,
    /// The chaining-value words the row takes from preprocessing, when it takes them.
    pub(crate) chaining_value: Option<[u32; CHAINING_VALUE_WORDS]>,
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
    /// except that the limbs of a tail or chaining value the row takes from preprocessing are
    /// unlabelled, and a slot bound under `layout` labels its word 0's column with its element
    /// and leaves its other columns unlabelled. The row pushes exactly the labelled limbs.
    pub(crate) fn labels(&self, layout: Blake3Layout) -> [Option<usize>; PUSHED_LIMBS] {
        let mut labels = array::from_fn(|limb| self.limb(limb));
        if self.tail.is_some() {
            labels[TAIL].fill(None);
        }
        if self.chaining_value.is_some() {
            labels[CHAINING_VALUE].fill(None);
        }
        for (slot, &element) in self.bound.iter().enumerate() {
            if let (Some(element), Some(slots)) = (element, layout.elements) {
                for (j, limb) in slots.limbs(slot).enumerate() {
                    labels[limb] = (j == 0).then_some(element);
                }
            }
        }
        labels
    }

    /// The words of input limbs `limbs` when each is a constant sixteen-bit limb under
    /// `constant`, which gives the value a witness is fixed to.
    fn constant_words<F: BinaryCoordinateField, const WORDS: usize>(
        &self,
        limbs: Range<usize>,
        constant: &impl Fn(usize) -> Option<F>,
    ) -> Option<[u32; WORDS]> {
        let raw = self.input[limbs]
            .iter()
            .map(|&w| constant(w).and_then(|value| u16::try_from(value.to_raw_coordinates()).ok()))
            .collect::<Option<Vec<u16>>>()?;
        limbs_to_words(&raw).try_into().ok()
    }
}

/// Lays out a table of `calls` that binds no element. When the carrier spans a 32-bit word,
/// every row takes its tail from preprocessing if every call's tail limbs are constant
/// sixteen-bit limbs under `constant`, which gives the value a witness is fixed to, and a row
/// takes its chaining value from preprocessing if its chaining-value limbs are. Every other
/// row and limb keeps its pushes. Records what each call's row takes.
pub(crate) fn blake3_layout<F: BinaryCoordinateField>(
    calls: &mut [Blake3Call],
    constant: impl Fn(usize) -> Option<F>,
) -> Blake3Layout {
    if F::COORDINATE_BITS < 32 {
        return Blake3Layout::default();
    }
    for call in calls.iter_mut() {
        call.tail = call.constant_words(TAIL, &constant);
        call.chaining_value = call.constant_words(CHAINING_VALUE, &constant);
    }
    let constant_tails = !calls.is_empty() && calls.iter().all(|call| call.tail.is_some());
    if !constant_tails {
        for call in calls.iter_mut() {
            call.tail = None;
        }
    }
    Blake3Layout {
        constant_tails,
        constant_chaining_values: calls.iter().any(|call| call.chaining_value.is_some()),
        elements: None,
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
                tail: None,
                chaining_value: None,
            });
        }
    }
    Ok(calls)
}

/// The preprocessed rows of a table of `height` rows laid out as `layout`: a call's row is
/// active and labels its columns (see [`Blake3Call::labels`]) by witness ID plus one,
/// activates its swapped output limbs when the call outputs them, holds the tail words and the
/// flagged chaining-value words it takes, and activates each bound slot. Every other cell is
/// zero. `label` encodes a label.
pub(crate) fn blake3_preprocessed<F: BinaryCoordinateField>(
    calls: &[Blake3Call],
    layout: Blake3Layout,
    height: usize,
    label: impl Fn(usize) -> Result<F, NativeBusCircuitError>,
) -> Result<RowMajorMatrix<F>, NativeBusCircuitError> {
    let width = layout.width();
    let raw_word = |word: &u32| {
        F::from_raw_coordinates(u128::from(*word)).expect("a table taking words spans a word")
    };
    let mut pp = F::zero_vec(cells(height, width)?);
    for (row, call) in pp.chunks_exact_mut(width).zip(calls) {
        row[ACTIVE] = F::ONE;
        for (limb, id) in call.labels(layout).into_iter().enumerate() {
            if let (Some(column), Some(id)) = (layout.label(limb), id) {
                row[column] = label(id + 1)?;
            }
        }
        row[layout.swapped_active()] = F::from_bool(call.swapped.is_some());
        if let (Some(column), Some(tail)) = (layout.tail(), call.tail) {
            for (cell, word) in row[column..].iter_mut().zip(&tail) {
                *cell = raw_word(word);
            }
        }
        if let (Some(flag), Some(chaining_value)) = (layout.chaining_value(), call.chaining_value) {
            row[flag] = F::ONE;
            for (cell, word) in row[flag + 1..].iter_mut().zip(&chaining_value) {
                *cell = raw_word(word);
            }
        }
        for (cell, element) in row[layout.bound()..].iter_mut().zip(&call.bound) {
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
/// `assume_boolean`, and to the tail and chaining-value words it takes from preprocessing under
/// `layout`, and pushes its other limbs onto `witness_bus`, the element of each slot that the
/// row binds in place of the slot's limbs. `row` and `pp` are the row's main and preprocessed
/// cells. `assume_boolean` is sound only when the table is committed as bits.
pub(crate) fn eval_blake3<AB>(
    builder: &mut AB,
    row: &[AB::Var],
    pp: &[AB::Var],
    weights: &[AB::F; 16],
    layout: Blake3Layout,
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
    let word = |bits: [AB::Var; 32]| -> AB::Expr {
        bits.into_iter()
            .enumerate()
            .map(|(b, bit)| {
                bit * AB::F::from_raw_coordinates(1 << b)
                    .expect("a table taking words spans a word")
            })
            .sum()
    };
    if let Some(tail) = layout.tail() {
        for k in 0..TAIL_WORDS {
            builder.assert_eq(word(input_word(cols, TAIL.start / 2 + k)), pp[tail + k]);
        }
    }
    let chaining_value = layout.chaining_value();
    if let Some(flag) = chaining_value {
        for k in 0..CHAINING_VALUE_WORDS {
            builder.when(pp[flag]).assert_eq(
                word(input_word(cols, CHAINING_VALUE.start / 2 + k)),
                pp[flag + 1 + k],
            );
        }
    }
    let limbs = pushed_limbs::<AB::Var, AB::Expr, AB::F>(cols, weights);
    let mut slot_of = [None; PUSHED_LIMBS];
    if let Some(slots) = layout.elements {
        for slot in 0..slots.count() {
            for limb in slots.limbs(slot) {
                slot_of[limb] = Some(slot);
            }
        }
    }
    for (i, limb) in limbs.iter().enumerate() {
        let Some(label) = layout.label(i) else {
            continue;
        };
        let mut active: AB::Expr = if i < CALL_LIMBS {
            pp[ACTIVE]
        } else {
            pp[layout.swapped_active()]
        }
        .into();
        // A slot is bound and a chaining value flagged only on an active row and, for a swapped
        // slot, only when the call outputs swapped limbs, so the difference is Boolean: zero
        // exactly on a bound slot or a flagged chaining value.
        if let Some(slot) = slot_of[i] {
            active -= pp[layout.bound() + slot].into();
        }
        if let Some(flag) = chaining_value
            && CHAINING_VALUE.contains(&i)
        {
            active -= pp[flag].into();
        }
        builder.push_bus_interaction(
            witness_bus,
            BusDirection::Push,
            [pp[label].into(), limb.clone()],
            BusActivation::Boolean(active),
        );
    }
    let Some(slots) = layout.elements else {
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
        let label = layout
            .label(first)
            .expect("block and swapped output limbs have labels");
        builder.push_bus_interaction(
            witness_bus,
            BusDirection::Push,
            [pp[label].into(), element],
            BusActivation::Boolean(pp[layout.bound() + slot].into()),
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
    use p3_test_utils::binary_field_params::{BinaryField16, BinaryField128};

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

    fn call(swapped: bool) -> Blake3Call {
        Blake3Call {
            input: array::from_fn(|i| 100 + i),
            output: array::from_fn(|i| 200 + i),
            swapped: swapped.then(|| array::from_fn(|i| 300 + i)),
            bound: Vec::new(),
            tail: None,
            chaining_value: None,
        }
    }

    fn label(id: usize) -> Result<F, NativeBusCircuitError> {
        Ok(F::from_raw_coordinates(id as u128).unwrap())
    }

    #[test]
    fn preprocessing_labels_the_pushed_limbs_in_order() {
        const WIDTH: usize = 90;
        let layout = Blake3Layout::default();
        assert_eq!(layout.width(), WIDTH);
        let pp = blake3_preprocessed::<F>(&[call(true), call(false)], layout, 4, label).unwrap();
        let rows = pp.values.as_chunks::<WIDTH>().0;
        let ids: Vec<usize> = (100..156).chain(200..216).chain(300..316).collect();
        for (row, swapped) in rows.iter().zip([true, false]) {
            assert_eq!(row[ACTIVE], F::ONE);
            assert_eq!(row[WIDTH - 1], F::from_bool(swapped));
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

    /// Rows that take their tails from preprocessing have no tail label columns: the output
    /// labels follow the chaining value's, and the tail words follow the swapped-digest
    /// activation, then the chaining-value flag and words. A flagged row leaves its
    /// chaining-value labels empty and holds its words; another row leaves the flag and the
    /// words zero and labels its chaining value.
    #[test]
    fn preprocessing_holds_constant_words_in_place_of_their_labels() {
        const WIDTH: usize = 1 + 80 + 1 + 4 + 9;
        let tail = [7, 0, 64, 11];
        let chaining_value = array::from_fn(|k| 0x1357_9bdf ^ (k as u32) << 28);
        let flagged = Blake3Call {
            tail: Some(tail),
            chaining_value: Some(chaining_value),
            ..call(true)
        };
        let chained = Blake3Call {
            tail: Some(tail),
            ..call(true)
        };
        let layout = Blake3Layout {
            constant_tails: true,
            constant_chaining_values: true,
            elements: None,
        };
        assert_eq!(layout.width(), WIDTH);
        let pp = blake3_preprocessed::<F>(&[flagged, chained], layout, 4, label).unwrap();
        let rows = pp.values.as_chunks::<WIDTH>().0;
        let raw = |value: u32| F::from_raw_coordinates(value.into()).unwrap();
        let ids: Vec<usize> = (100..148).chain(200..216).chain(300..316).collect();
        for (row, flagged) in rows.iter().zip([true, false]) {
            assert_eq!(row[ACTIVE], F::ONE);
            for (i, &id) in ids.iter().enumerate() {
                let empty = flagged && CHAINING_VALUE.contains(&i);
                let expected = if empty { 0 } else { id as u32 + 1 };
                assert_eq!(row[LABELS + i], raw(expected), "label {i}");
            }
            assert_eq!(row[81], F::ONE);
            assert_eq!(&row[82..86], tail.map(raw));
            assert_eq!(row[86], F::from_bool(flagged));
            let words = if flagged { chaining_value } else { [0; 8] };
            assert_eq!(&row[87..WIDTH], words.map(raw));
        }
        assert!(rows[2..].iter().flatten().all(|&cell| cell == F::ZERO));
    }

    /// A row takes a tail or chaining value only when every limb of it is a constant below
    /// `2^16`, and the table takes tails only when every row does; a carrier narrower than a
    /// word takes neither.
    #[test]
    fn rows_take_only_wholly_constant_words() {
        let value = |w: usize| (w % 7) as u128 * 0x1111;
        let constant = |w: usize| (w != 999).then(|| F::from_raw_coordinates(value(w)).unwrap());
        let words = |limbs: Range<usize>| -> Vec<u32> {
            let raw: Vec<u16> = limbs.map(|i| value(100 + i) as u16).collect();
            limbs_to_words(&raw)
        };

        let mut calls = [call(false), call(true)];
        let layout = blake3_layout(&mut calls, constant);
        assert!(layout.constant_tails && layout.constant_chaining_values);
        for call in &calls {
            assert_eq!(call.tail.unwrap().to_vec(), words(TAIL));
            assert_eq!(call.chaining_value.unwrap().to_vec(), words(CHAINING_VALUE));
        }

        let mut witness_tail = call(false);
        witness_tail.input[TAIL.start + 2] = 999;
        let mut calls = [call(false), witness_tail];
        let layout = blake3_layout(&mut calls, constant);
        assert!(!layout.constant_tails && layout.constant_chaining_values);
        assert!(calls.iter().all(|call| call.tail.is_none()));
        assert!(calls.iter().all(|call| call.chaining_value.is_some()));

        let wide = |w: usize| {
            let value = if w == 100 + CHAINING_VALUE.start + 8 {
                0x1_0000
            } else {
                value(w)
            };
            Some(F::from_raw_coordinates(value).unwrap())
        };
        let mut calls = [call(false)];
        let layout = blake3_layout(&mut calls, wide);
        assert!(layout.constant_tails && !layout.constant_chaining_values);
        assert_eq!(calls[0].chaining_value, None);

        let mut calls = [call(false)];
        let layout = blake3_layout(&mut calls, |_| Some(BinaryField16::ONE));
        assert_eq!(layout, Blake3Layout::default());
        assert_eq!((calls[0].tail, calls[0].chaining_value), (None, None));
    }
}
