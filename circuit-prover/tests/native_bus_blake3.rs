//! The native BLAKE3 table proves one compression per row, pushes every call's limbs onto the
//! witness bus, and is committed densely or as packed bits of its own width.

use core::borrow::Borrow;

use p3_air::{AirLayout, BaseAir, check_constraints};
use p3_blake3_air::{Blake3BinaryCols, NUM_BLAKE3_BINARY_COLS};
use p3_bus::{BusDebugInstance, BusDebugReport, BusSymbolicBuilder};
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::{
    BLAKE3_INPUT_WORDS, ExecutionContext, NonPrimitiveExecutor, NpoTypeId, blake3_compress,
    limbs_to_words, words_to_limbs,
};
use p3_circuit::tables::WitnessTrace;
use p3_circuit::{Circuit, CircuitBuilder, CircuitError, ExprId, NonPrimitiveOpId, Op, WitnessId};
use p3_circuit_prover::direct::{DirectCircuitError, DirectCircuitLimits};
use p3_circuit_prover::native_binary::NativeBinaryCircuit;
use p3_circuit_prover::native_bus::{
    KeccakCommitment, NativeBusCircuit, NativeBusCircuitError, NativeBusTrace,
};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use p3_sumcheck::layout::Table;
use p3_test_utils::binary_field_params::{BinaryField8, BinaryField128, Poly64};

type F = BinaryField128;

const WIDTH: usize = NUM_BLAKE3_BINARY_COLS;
/// Preprocessed columns: the call activation, the labels of 56 input, 16 output and 16 swapped
/// output limbs, and the swapped-digest activation.
const PP_WIDTH: usize = 90;
/// Coordinates indexing the 11536 columns once packed: `2^14` is the next power of two.
const COLUMN_VARIABLES: usize = 14;

fn raw<F: BinaryCoordinateField>(limb: u16) -> F {
    F::from_raw_coordinates(limb.into()).unwrap()
}

/// The counter, block length and flags of chain call `call`: a full 64-byte block, no flags.
const fn tail(call: usize) -> [u32; 4] {
    [call as u32, 0, 64, 0]
}

/// A chain of `calls` compressions of one public block: call `i` compresses it from the
/// previous chaining value, the public one for the first call, with counter `i`. The last
/// chaining value, followed by its byte-swapped limbs when `swapped`, is bound to public values.
/// Returns the circuit and its public values.
fn chain<F: BinaryCoordinateField>(calls: usize, swapped: bool) -> (Circuit<F>, Vec<F>) {
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_blake3_compress().unwrap();
    let block = b.alloc_public_input_array::<32>("block");
    let mut cv = b.alloc_public_input_array::<16>("chaining value");
    let mut swapped_limbs = None;
    for call in 0..calls {
        let mut input: Vec<ExprId> = block.iter().chain(&cv).copied().collect();
        for limb in words_to_limbs(&tail(call)) {
            input.push(b.define_const(raw(limb)));
        }
        if swapped && call + 1 == calls {
            let (output, limbs) = b
                .add_native_blake3_compress_with_swapped_digest(&input)
                .unwrap();
            cv = output;
            swapped_limbs = Some(limbs);
        } else {
            cv = b.add_native_blake3_compress(&input).unwrap();
        }
    }
    for actual in cv.into_iter().chain(swapped_limbs.into_iter().flatten()) {
        let expected = b.public_input();
        b.connect(actual, expected);
    }

    let block: [u32; 16] = core::array::from_fn(|j| (j as u32 + 1).wrapping_mul(0x9E37_79B1));
    let mut cv: [u32; 8] =
        core::array::from_fn(|j| 0x6A09_E667_u32.rotate_left(5 * j as u32) ^ j as u32);
    let mut public = words_to_limbs(&block);
    public.extend(words_to_limbs(&cv));
    for call in 0..calls {
        let mut input = [0; BLAKE3_INPUT_WORDS];
        input[..16].copy_from_slice(&block);
        input[16..24].copy_from_slice(&cv);
        input[24..].copy_from_slice(&tail(call));
        cv = core::array::from_fn(|j| blake3_compress(&input)[j]);
    }
    let output = words_to_limbs(&cv);
    public.extend(&output);
    if swapped {
        public.extend(output.iter().map(|limb| limb.swap_bytes()));
    }
    (b.build().unwrap(), public.into_iter().map(raw).collect())
}

fn witness<F: BinaryCoordinateField>(circuit: &Circuit<F>, public: &[F]) -> WitnessTrace<F> {
    let mut runner = circuit.runner();
    runner.set_public_inputs(public).unwrap();
    runner.run().unwrap().witness_trace
}

/// `witness` with the value of `id` replaced.
fn replaced<F: BinaryCoordinateField>(
    witness: &WitnessTrace<F>,
    id: usize,
    value: F,
) -> WitnessTrace<F> {
    let mut values: Vec<F> = (0..witness.num_rows())
        .map(|i| *witness.get_value(WitnessId(i as u32)).unwrap())
        .collect();
    values[id] = value;
    WitnessTrace::new(values)
}

fn build<F: BinaryCoordinateField>(
    circuit: &Circuit<F>,
    min_log_height: usize,
    mode: KeccakCommitment,
) -> NativeBusCircuit<F> {
    NativeBusCircuit::with_options(
        circuit,
        "blake3",
        min_log_height,
        DirectCircuitLimits::default(),
        mode,
    )
    .unwrap()
}

/// The native BLAKE3 calls of a circuit: their inputs and outputs, swapped limbs included.
fn calls<F: BinaryCoordinateField>(circuit: &Circuit<F>) -> Vec<(Vec<WitnessId>, Vec<WitnessId>)> {
    circuit
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::NonPrimitiveOpWithExecutor {
                inputs,
                outputs,
                executor,
                ..
            } if executor.op_type() == &NpoTypeId::native_blake3_compress() => {
                Some((inputs[0].clone(), outputs[0].clone()))
            }
            _ => None,
        })
        .collect()
}

/// The bus declarations and preprocessing of a native bus circuit, replayed over the dense
/// traces of a witness.
struct Replay<'a, F: BinaryCoordinateField> {
    prepared: &'a NativeBusCircuit<F>,
    preprocessed: Vec<Option<Table<F>>>,
    profiles: Vec<BusSymbolicBuilder<F>>,
}

impl<'a, F: BinaryCoordinateField> Replay<'a, F> {
    fn new(prepared: &'a NativeBusCircuit<F>) -> Self {
        Self {
            prepared,
            preprocessed: prepared
                .airs()
                .iter()
                .map(|air| {
                    air.preprocessed_trace()
                        .map(|pp| Table::new(pp.transpose()))
                })
                .collect(),
            profiles: prepared
                .airs()
                .iter()
                .map(|air| BusSymbolicBuilder::<F>::from_air(air, AirLayout::from_air::<F>(air)))
                .collect(),
        }
    }

    /// Whether every product bus balances over the dense traces of `witness`.
    fn balanced(&self, witness: &WitnessTrace<F>, public: &[F]) -> bool {
        let traces: Vec<_> = self
            .prepared
            .traces(witness)
            .unwrap()
            .into_iter()
            .map(|trace| Table::new(trace.transpose()))
            .collect();
        let public = self.prepared.public_values(public).unwrap();
        let instances: Vec<_> = (0..traces.len())
            .map(|i| {
                BusDebugInstance::new(
                    &traces[i],
                    self.preprocessed[i].as_ref(),
                    &public[i],
                    &self.profiles[i],
                )
                .unwrap()
            })
            .collect();
        BusDebugReport::check(&instances).unwrap().is_balanced()
    }
}

/// Every table satisfies its local constraints over the dense traces of `witness`.
fn check_local<F: BinaryCoordinateField>(
    prepared: &NativeBusCircuit<F>,
    witness: &WitnessTrace<F>,
    public: &[F],
) {
    let traces = prepared.traces(witness).unwrap();
    let public = prepared.public_values(public).unwrap();
    for ((air, trace), public) in prepared.airs().iter().zip(&traces).zip(&public) {
        check_constraints(air, trace, public);
    }
}

/// The honest chain balances every bus, its last output limbs and swapped limbs included; a
/// witness that changes a bound output limb or swapped limb leaves the BLAKE3 table's push of
/// the true limb unmatched.
fn honest_chain_balances_and_forged_outputs_do_not<F: BinaryCoordinateField>() {
    for (calls_count, swapped, min_log_height) in [(1, false, 1), (3, true, 3), (2, true, 1)] {
        let (circuit, public) = chain::<F>(calls_count, swapped);
        let witness = witness(&circuit, &public);
        let last = calls(&circuit).pop().unwrap().1;
        assert_eq!(last.len(), if swapped { 32 } else { 16 });
        for mode in [KeccakCommitment::Dense, KeccakCommitment::Bits] {
            let prepared = build(&circuit, min_log_height, mode);
            check_local(&prepared, &witness, &public);
            let replay = Replay::new(&prepared);
            assert!(replay.balanced(&witness, &public));
            for index in [0, 15, 16, 31].into_iter().filter(|&m| m < last.len()) {
                let id = last[index].0 as usize;
                let value = *witness.get_value(last[index]).unwrap() + F::ONE;
                let forged = replaced(&witness, id, value);
                assert!(
                    !replay.balanced(&forged, &public),
                    "{mode:?}, output {index}"
                );
            }
        }
    }
}

#[test]
fn honest_chains_balance_and_forged_outputs_do_not_in_both_bases() {
    honest_chain_balances_and_forged_outputs_do_not::<F>();
    honest_chain_balances_and_forged_outputs_do_not::<Poly64>();
}

/// The select rows and the multiply-adds by one of a prepared circuit's gate table.
fn selects_and_additions(prepared: &NativeBusCircuit<F>) -> [usize; 2] {
    let gate_pp = prepared.airs()[1].preprocessed_trace().unwrap();
    let rows = gate_pp.values.as_chunks::<14>().0;
    let count = |selector: usize, constant: F| {
        rows.iter()
            .filter(|row| row[6 + selector] == F::ONE && row[5] == constant)
            .count()
    };
    [count(1, F::ZERO), count(6, F::ONE)]
}

/// A difference that a select reads and that a BLAKE3 call hashes as its first block limb keeps
/// its addition: a select in its place would leave the hashed limb free. A prover who forges the
/// limb, compresses the forged block and claims its digest balances every bus and satisfies
/// every table but the gate table.
#[test]
fn a_difference_hashed_by_blake3_keeps_its_addition() {
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_blake3_compress().unwrap();
    let [s, t, e, selected] = b.alloc_public_input_array::<4>("select");
    let difference = b.sub(t, e);
    let mix = b.mul_add(s, difference, e);
    b.connect(mix, selected);
    let block = b.alloc_public_input_array::<31>("block");
    let cv = b.alloc_public_input_array::<16>("chaining value");
    let mut input = vec![difference];
    input.extend(block.iter().chain(&cv));
    for limb in words_to_limbs(&tail(0)) {
        input.push(b.define_const(raw(limb)));
    }
    for actual in b.add_native_blake3_compress(&input).unwrap() {
        let expected = b.public_input();
        b.connect(actual, expected);
    }
    let circuit = b.build().unwrap();
    let prepared = build(&circuit, 1, KeccakCommitment::Dense);
    assert_eq!(selects_and_additions(&prepared), [0, 1]);

    let rest: Vec<u16> = (1..48u16)
        .map(|i| i.wrapping_mul(0x9e37) ^ 0x6a09)
        .collect();
    let digest = |first: u16| -> Vec<F> {
        let mut limbs = vec![first];
        limbs.extend(&rest);
        limbs.extend(words_to_limbs(&tail(0)));
        let input: [u32; BLAKE3_INPUT_WORDS] = limbs_to_words(&limbs).try_into().unwrap();
        words_to_limbs(&blake3_compress(&input)[..8])
            .into_iter()
            .map(raw)
            .collect()
    };
    let s_value = F::from_raw_coordinates(0x8123456789abcdef).unwrap();
    let [t_limb, e_limb] = [0x5a5a, 0x1234];
    let [t_value, e_value] = [t_limb, e_limb].map(raw::<F>);
    let mut statement = vec![
        s_value,
        t_value,
        e_value,
        s_value * (t_value - e_value) + e_value,
    ];
    statement.extend(rest.iter().map(|&limb| raw::<F>(limb)));
    statement.extend(digest(t_limb ^ e_limb));
    let honest = witness(&circuit, &statement);
    let replay = Replay::new(&prepared);
    assert!(replay.balanced(&honest, &statement));
    let refusing = |witness: &WitnessTrace<F>, statement: &[F]| -> Vec<usize> {
        let traces = prepared.traces(witness).unwrap();
        let public = prepared.public_values(statement).unwrap();
        (0..traces.len())
            .filter(|&i| {
                std::panic::catch_unwind(|| {
                    check_constraints(&prepared.airs()[i], &traces[i], &public[i]);
                })
                .is_err()
            })
            .collect()
    };
    assert!(refusing(&honest, &statement).is_empty());

    let forged_limb = t_limb ^ e_limb ^ 1;
    let id = circuit.expr_to_widx[&difference].0 as usize;
    let mut forged = replaced(&honest, id, raw(forged_limb));
    let mut forged_statement = statement.clone();
    let output = calls(&circuit).pop().unwrap().1;
    let claimed = digest(forged_limb);
    for ((limb, value), public) in output
        .iter()
        .zip(&claimed)
        .zip(&mut forged_statement[statement.len() - 16..])
    {
        forged = replaced(&forged, limb.0 as usize, *value);
        *public = *value;
    }
    assert!(replay.balanced(&forged, &forged_statement));
    assert_eq!(refusing(&forged, &forged_statement), [1]);
}

/// The column of `cell` in a row of the table.
fn column(cell: impl Fn(&Blake3BinaryCols<usize>) -> usize) -> usize {
    let indices: Vec<usize> = (0..WIDTH).collect();
    cell(indices.as_slice().borrow())
}

fn refused(
    prepared: &NativeBusCircuit<F>,
    table: usize,
    trace: &p3_matrix::dense::RowMajorMatrix<F>,
) -> bool {
    std::panic::catch_unwind(|| check_constraints(&prepared.airs()[table], trace, &[])).is_err()
}

/// A changed internal bit fails the compression constraints on a call row and on a padding row
/// in both modes; a non-bit input cell is refused in dense mode. That the dense table checks
/// the booleanity of the input words itself is pinned by `packed_words_match_dense_bits`.
#[test]
fn compression_cells_are_constrained_on_every_row() {
    let (circuit, public) = chain::<F>(3, false);
    let witness = witness(&circuit, &public);
    for mode in [KeccakCommitment::Dense, KeccakCommitment::Bits] {
        let prepared = build(&circuit, 3, mode);
        let table = prepared.airs().len() - 1;
        let trace = &prepared.traces(&witness).unwrap()[table];
        assert_eq!(trace.height(), 8);
        for row in [1, 6] {
            for cell in [
                column(|cols| cols.rounds[0][0].d1[5]),
                column(|cols| cols.rounds[3][6].add2_carries[9]),
                column(|cols| cols.rounds[6][7].b2[31]),
            ] {
                let mut flipped = trace.clone();
                flipped.values[row * WIDTH + cell] += F::ONE;
                assert!(refused(&prepared, table, &flipped), "{mode:?}, row {row}");
            }
        }
        let mut wide = trace.clone();
        wide.values[column(|cols| cols.block[3][4])] = F::from_raw_coordinates(2).unwrap();
        if mode == KeccakCommitment::Dense {
            assert!(refused(&prepared, table, &wide));
        }
    }
}

/// A circuit with both kinds of native hash call has no single hash table, and the indexed
/// backend, which supplies only the Keccak table, refuses a BLAKE3 call.
#[test]
fn mixed_hash_calls_and_the_indexed_backend_are_refused() {
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_blake3_compress().unwrap();
    b.enable_native_keccak_f1600().unwrap();
    let state = b.alloc_public_input_array::<100>("state");
    b.add_native_keccak_f1600(&state).unwrap();
    b.add_native_blake3_compress(&state[..56]).unwrap();
    let circuit = b.build().unwrap();
    assert!(matches!(
        NativeBusCircuit::new(&circuit, "mixed"),
        Err(NativeBusCircuitError::MixedHashTables)
    ));

    let (circuit, _) = chain::<F>(2, false);
    assert!(NativeBinaryCircuit::new(&circuit).is_err());
}

/// A native BLAKE3 operation over a carrier the builder refuses: it computes nothing.
#[derive(Clone, Debug)]
struct NarrowBlake3(NpoTypeId);

impl NonPrimitiveExecutor<BinaryField8> for NarrowBlake3 {
    fn execute(
        &self,
        _inputs: &[Vec<WitnessId>],
        _outputs: &[Vec<WitnessId>],
        _ctx: &mut ExecutionContext<'_, BinaryField8>,
    ) -> Result<(), CircuitError> {
        Ok(())
    }

    fn op_type(&self) -> &NpoTypeId {
        &self.0
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<BinaryField8>> {
        Box::new(self.clone())
    }
}

/// An output group of neither 16 nor 32 limbs, and a carrier narrower than a 16-bit limb, are
/// refused before any table is laid out.
#[test]
fn malformed_calls_and_narrow_carriers_are_refused() {
    let is_blake3 = |op: &Op<F>| {
        matches!(op, Op::NonPrimitiveOpWithExecutor { executor, .. }
            if executor.op_type() == &NpoTypeId::native_blake3_compress())
    };
    let (mut circuit, _) = chain::<F>(1, true);
    let operation = circuit.ops.iter().position(is_blake3).unwrap();
    let Op::NonPrimitiveOpWithExecutor { outputs, .. } = &mut circuit.ops[operation] else {
        unreachable!()
    };
    outputs[0].truncate(17);
    assert!(matches!(
        NativeBusCircuit::new(&circuit, "blake3"),
        Err(NativeBusCircuitError::Blake3Layout { operation: refused }) if refused == operation
    ));

    let mut b = CircuitBuilder::<BinaryField8>::new();
    assert!(b.enable_native_blake3_compress().is_err());
    b.alloc_public_input_array::<72>("limbs");
    let mut circuit = b.build().unwrap();
    let limbs = circuit.public_rows.clone();
    circuit.ops.push(Op::NonPrimitiveOpWithExecutor {
        inputs: vec![limbs[..56].to_vec()],
        outputs: vec![limbs[56..].to_vec()],
        executor: Box::new(NarrowBlake3(NpoTypeId::native_blake3_compress())),
        op_id: NonPrimitiveOpId(0),
    });
    assert!(matches!(
        NativeBusCircuit::new(&circuit, "blake3"),
        Err(NativeBusCircuitError::Blake3CoordinateWidth { bits: 8 })
    ));
}

/// The BLAKE3 table is the last AIR. It reads no next row, assumes a Boolean trace only when bit
/// committed, and labels each call's limbs in its preprocessed row: the swapped output limbs
/// only on the call that outputs them. The fanout table reads every labelled limb once.
#[test]
fn blake3_table_shape_and_preprocessing() {
    let (circuit, public) = chain::<F>(3, true);
    let public = public.len();
    let calls = calls(&circuit);
    for mode in [KeccakCommitment::Dense, KeccakCommitment::Bits] {
        let prepared = build(&circuit, 1, mode);
        let table = prepared.airs().len() - 1;
        let air = &prepared.airs()[table];
        assert_eq!(BaseAir::<F>::width(air), WIDTH);
        assert_eq!(BaseAir::<F>::preprocessed_width(air), PP_WIDTH);
        assert!(BaseAir::<F>::main_next_row_columns(air).is_empty());
        let bits = mode == KeccakCommitment::Bits;
        for (i, air) in prepared.airs().iter().enumerate() {
            assert_eq!(BaseAir::<F>::assumes_boolean_trace(air), bits && i == table);
        }
        assert_eq!(prepared.packed_table_index(), bits.then_some(table));
        assert_eq!(prepared.keccak_table_index(), None);
        assert_eq!(prepared.log_heights()[table], 2);

        let pp = air.preprocessed_trace().unwrap();
        let rows = pp.values.as_chunks::<PP_WIDTH>().0;
        let label = |id: &WitnessId| F::from_raw_coordinates(u128::from(id.0) + 1).unwrap();
        for (row, (inputs, outputs)) in rows.iter().zip(&calls) {
            let swapped = outputs.len() == 32;
            assert_eq!(row[0], F::ONE);
            assert_eq!(row[PP_WIDTH - 1], F::from_bool(swapped));
            let labels: Vec<F> = inputs.iter().chain(outputs).map(label).collect();
            assert_eq!(&row[1..1 + labels.len()], labels.as_slice());
            assert!(
                row[1 + labels.len()..PP_WIDTH - 1]
                    .iter()
                    .all(|&cell| cell == F::ZERO)
            );
        }
        assert!(rows[3].iter().all(|&cell| cell == F::ZERO));

        // Fanout reads: the public values, the gates' used slots by selector, and the 72 limbs
        // of each call with the 16 swapped limbs of the last.
        let gate_reads: usize = prepared.airs()[1]
            .preprocessed_trace()
            .unwrap()
            .values
            .as_chunks::<14>()
            .0
            .iter()
            .map(|row| {
                row[6..14]
                    .iter()
                    .zip([1, 4, 3, 2, 4, 5, 3, 3])
                    .filter_map(|(&selector, reads)| (selector == F::ONE).then_some(reads))
                    .sum::<usize>()
            })
            .sum();
        let fanout = prepared.airs()[0].preprocessed_trace().unwrap();
        let reads = fanout
            .values
            .as_chunks::<4>()
            .0
            .iter()
            .filter(|row| row[1] == F::ONE)
            .count();
        assert_eq!(reads, public + gate_reads + 3 * 72 + 16);
    }
}

/// Bits mode commits the very bits of the dense table, one word per column and block of 64
/// rows, stacks only the other tables, and drops exactly the booleanity of the input words.
#[test]
fn packed_words_match_dense_bits() {
    const BITS: usize = 64;
    for (calls, min_log_height) in [(1, 1), (3, 1), (5, 4), (70, 1)] {
        let (circuit, public) = chain::<F>(calls, true);
        let witness = witness(&circuit, &public);
        let dense = build(&circuit, min_log_height, KeccakCommitment::Dense);
        let bits = build(&circuit, min_log_height, KeccakCommitment::Bits);
        assert_eq!(dense.log_heights(), bits.log_heights());
        assert_eq!(dense.packed_table_index(), None);
        assert_eq!(dense.packed_bit_variables(), None);
        let table = bits.packed_table_index().unwrap();
        let log_height = bits.log_heights()[table];
        assert_eq!(
            1 << log_height,
            calls.max(1 << min_log_height).next_power_of_two()
        );
        assert_eq!(
            bits.packed_bit_variables(),
            Some(COLUMN_VARIABLES + log_height)
        );
        assert!(bits.main_variables() < dense.main_variables());
        assert_eq!(
            bits.preprocessed_variables(),
            dense.preprocessed_variables()
        );

        let expected = dense.traces(&witness).unwrap();
        for (index, (table_trace, expected)) in bits
            .trace_tables(&witness)
            .unwrap()
            .iter()
            .zip(&expected)
            .enumerate()
        {
            match table_trace {
                NativeBusTrace::PackedBits {
                    words,
                    log_height: log,
                } => {
                    assert_eq!(index, table);
                    assert_eq!(*log, log_height);
                    let height = 1usize << log_height;
                    assert_eq!(words.width, WIDTH);
                    assert_eq!(words.values.len(), WIDTH * height.div_ceil(BITS));
                    for row in 0..height {
                        for column in 0..WIDTH {
                            let word = words.values[(row / BITS) * WIDTH + column];
                            assert_eq!(
                                expected.values[row * WIDTH + column],
                                F::from_bool((word >> (row % BITS)) & 1 == 1),
                                "calls {calls}, row {row}, column {column}"
                            );
                        }
                    }
                    if height < BITS {
                        assert!(words.values.iter().all(|&word| word >> height == 0));
                    }
                }
                NativeBusTrace::Dense(matrix) => {
                    assert_ne!(index, table);
                    assert_eq!(matrix.values, expected.values);
                }
            }
        }
    }

    let (circuit, _) = chain::<F>(2, false);
    let count = |air| {
        BusSymbolicBuilder::<F>::from_air(air, AirLayout::from_air::<F>(air))
            .base_constraints()
            .len()
    };
    let dense = build(&circuit, 1, KeccakCommitment::Dense);
    let bits = build(&circuit, 1, KeccakCommitment::Bits);
    for (i, (d, b)) in dense.airs().iter().zip(bits.airs()).enumerate() {
        let booleanity = if i == bits.packed_table_index().unwrap() {
            BLAKE3_INPUT_WORDS * 32
        } else {
            0
        };
        assert_eq!(count(d), count(b) + booleanity);
    }
}

/// A call input or output limb wider than sixteen coordinates in the supplied witness is
/// refused before any hash trace is built.
#[test]
fn witnesses_wider_than_a_limb_are_refused() {
    let (circuit, public) = chain::<F>(2, false);
    let witness = witness(&circuit, &public);
    let (inputs, outputs) = calls(&circuit).pop().unwrap();
    for id in [inputs[3], outputs[15]] {
        let wide = replaced(
            &witness,
            id.0 as usize,
            F::from_raw_coordinates(0x1_0000).unwrap(),
        );
        for mode in [KeccakCommitment::Dense, KeccakCommitment::Bits] {
            let prepared = build(&circuit, 1, mode);
            let refused = |result: Result<_, NativeBusCircuitError>| {
                matches!(result, Err(NativeBusCircuitError::InvalidBlake3Limb { witness })
                    if witness == id.0 as usize)
            };
            assert!(refused(prepared.traces(&wide).map(|_| ())));
            assert!(refused(prepared.trace_tables(&wide).map(|_| ())));
        }
    }
}

/// Main and preprocessed cells of every table at its final height.
fn table_cells(prepared: &NativeBusCircuit<F>) -> usize {
    prepared
        .airs()
        .iter()
        .zip(prepared.log_heights())
        .map(|(air, &log)| {
            (BaseAir::<F>::width(air) + BaseAir::<F>::preprocessed_width(air)) << log
        })
        .sum()
}

/// 128-bit cells, two words each, holding a packed BLAKE3 table of `height` rows.
const fn packed_cells(height: usize) -> usize {
    (WIDTH * height.div_ceil(64)).div_ceil(2)
}

fn with_trace_cells(
    circuit: &Circuit<F>,
    min_log_height: usize,
    max_trace_cells: usize,
    mode: KeccakCommitment,
) -> Result<NativeBusCircuit<F>, NativeBusCircuitError> {
    let limits = DirectCircuitLimits {
        max_trace_cells,
        ..DirectCircuitLimits::default()
    };
    NativeBusCircuit::with_options(circuit, "blake3", min_log_height, limits, mode)
}

/// Whether `result` is the trace-cell limit refusing `actual` cells under `limit`.
const fn over_limit<T>(
    result: &Result<T, NativeBusCircuitError>,
    actual: usize,
    limit: usize,
) -> bool {
    matches!(
        result,
        Err(NativeBusCircuitError::Primitive(DirectCircuitError::ResourceLimit {
            actual: refused,
            limit: max,
            ..
        })) if *refused == actual && *max == limit
    )
}

/// A Bits circuit is charged the packed words of its BLAKE3 table, and building its dense
/// traces is charged the dense table; the generators allocate no other hash table.
#[test]
fn trace_cell_limit_charges_the_blake3_table_as_committed() {
    for (calls, min_log_height) in [(1, 1), (3, 1), (3, 7)] {
        let (circuit, public) = chain::<F>(calls, false);
        let witness = witness(&circuit, &public);
        let dense = build(&circuit, min_log_height, KeccakCommitment::Dense);
        let table = dense.airs().len() - 1;
        let height = 1usize << dense.log_heights()[table];
        let dense_bound = table_cells(&dense);
        let bits_bound = dense_bound - WIDTH * height + packed_cells(height);
        assert!(bits_bound < dense_bound);
        for (mode, bound) in [
            (KeccakCommitment::Dense, dense_bound),
            (KeccakCommitment::Bits, bits_bound),
        ] {
            assert!(
                with_trace_cells(&circuit, min_log_height, bound, mode).is_ok(),
                "{mode:?}, calls {calls}"
            );
            assert!(
                over_limit(
                    &with_trace_cells(&circuit, min_log_height, bound - 1, mode),
                    bound,
                    bound - 1
                ),
                "{mode:?}, calls {calls}"
            );
        }
        let bits =
            with_trace_cells(&circuit, min_log_height, bits_bound, KeccakCommitment::Bits).unwrap();
        assert!(bits.trace_tables(&witness).is_ok());
        assert!(over_limit(&bits.traces(&witness), dense_bound, bits_bound));
        let bits = with_trace_cells(
            &circuit,
            min_log_height,
            dense_bound,
            KeccakCommitment::Bits,
        )
        .unwrap();
        assert_eq!(
            bits.traces(&witness).unwrap()[table].values,
            dense.traces(&witness).unwrap()[table].values
        );
    }
}
