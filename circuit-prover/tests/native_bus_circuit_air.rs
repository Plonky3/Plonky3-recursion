//! Fanout adjacency, sentinel values and native hash schedules are local AIR relations.

use p3_air::{BaseAir, check_constraints};
use p3_blake3::Blake3;
use p3_circuit::ops::binary_encoding::NativeBinaryEncoding;
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::{ByteHash, DIGEST_LIMBS, bytes_to_limbs, keccak_state_to_limbs};
use p3_circuit::tables::WitnessTrace;
use p3_circuit::{Circuit, CircuitBuilder, ExprId, WitnessId};
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::indexed::IndexedCircuit;
use p3_circuit_prover::native_binary::NativeBinaryCircuit;
use p3_circuit_prover::native_bus::NativeBusCircuit;
use p3_commit::Mmcs;
use p3_field::PrimeCharacteristicRing;
use p3_keccak::{Keccak256Hash, KeccakF};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{
    CompressionFunctionFromHasher, CryptographicHasher, Permutation, SerializingHasher,
};
use p3_test_utils::binary_field_params::{BinaryField8, BinaryField128, TowerLevel};

type F = BinaryField128;

#[test]
fn trusted_minimum_height_repeats_public_values_and_bounds_all_tables() {
    let mut b = CircuitBuilder::<F>::new();
    b.public_input();
    let circuit = b.build().unwrap();
    let prepared = NativeBusCircuit::with_min_log_height_and_limits(
        &circuit,
        "floor",
        4,
        DirectCircuitLimits::default(),
    )
    .unwrap();
    assert!(prepared.log_heights().iter().all(|&log| log >= 4));
    let public = [F::from_raw_coordinates(0x8912).unwrap()];
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    let traces = prepared
        .traces(&runner.run().unwrap().witness_trace)
        .unwrap();
    let public = prepared.public_values(&public).unwrap();
    for ((air, trace), public) in prepared.airs().iter().zip(&traces).zip(&public) {
        check_constraints(air, trace, public);
    }
    assert!(
        NativeBusCircuit::with_min_log_height_and_limits(
            &circuit,
            "floor",
            usize::BITS as usize,
            DirectCircuitLimits::default(),
        )
        .is_err()
    );
    assert!(
        NativeBusCircuit::with_min_log_height_and_limits(
            &circuit,
            "floor",
            4,
            DirectCircuitLimits {
                max_trace_cells: 10,
                ..Default::default()
            },
        )
        .is_err()
    );
}

#[test]
fn fanout_copies_and_unused_gate_slots_are_constrained() {
    let mut b = CircuitBuilder::<F>::new();
    let input = b.public_input();
    let expected = b.public_input();
    let product = b.mul(input, input);
    let out = b.add(product, input);
    b.connect(out, expected);
    let circuit = b.build().unwrap();
    let prepared = NativeBusCircuit::new(&circuit, "local").unwrap();
    let a = F::from_raw_coordinates(0x8123456789abcdef).unwrap();
    let public = [a, a * a + a];
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    let traces = prepared
        .traces(&runner.run().unwrap().witness_trace)
        .unwrap();
    let public = prepared.public_values(&public).unwrap();
    for ((air, trace), public) in prepared.airs().iter().zip(&traces).zip(&public) {
        check_constraints(air, trace, public);
    }
    let pp = prepared.airs()[0].preprocessed_trace().unwrap();
    assert_eq!(prepared.airs()[0].main_next_row_columns(), vec![0]);
    let adjacent = pp
        .values
        .as_chunks::<4>()
        .0
        .iter()
        .position(|row| row[0] != F::ZERO && row[2] == F::ONE)
        .unwrap();
    {
        let mut wrong = traces[0].clone();
        wrong.values[adjacent] += F::ONE;
        assert!(
            std::panic::catch_unwind(|| check_constraints(&prepared.airs()[0], &wrong, &[]))
                .is_err()
        );
    }
    let mut unused = traces[1].clone();
    // The accumulator slot is unused by the addition/multiplication fixture.
    unused.values[3] += F::ONE;
    assert!(
        std::panic::catch_unwind(|| check_constraints(&prepared.airs()[1], &unused, &[])).is_err()
    );
    let gate_pp = prepared.airs()[1].preprocessed_trace().unwrap();
    let expected_occurrences = public.iter().map(Vec::len).sum::<usize>()
        + gate_pp
            .values
            .as_chunks::<14>()
            .0
            .iter()
            .map(|row| {
                row[6..14]
                    .iter()
                    .zip([1, 4, 3, 2, 4, 5, 3, 3])
                    .filter_map(|(&selector, count)| (selector == F::ONE).then_some(count))
                    .sum::<usize>()
            })
            .sum::<usize>();
    assert_eq!(
        pp.values
            .as_chunks::<4>()
            .0
            .iter()
            .filter(|row| row[1] == F::ONE)
            .count(),
        expected_occurrences
    );
    let last_live = pp
        .values
        .as_chunks::<4>()
        .0
        .iter()
        .rposition(|row| row[1] == F::ONE)
        .unwrap();
    assert_eq!(pp.values[4 * last_live + 2], F::ZERO);
    for row in pp.values.as_chunks::<4>().0.iter().skip(last_live + 1) {
        assert_eq!(row, &[F::ZERO; 4]);
    }
    assert!(prepared.public_values(&[a]).is_err());
    for namespace in ["", "0bus", "bad/name", "bad name", "memοry"] {
        assert!(NativeBusCircuit::new(&circuit, namespace).is_err());
    }
    assert!(NativeBusCircuit::new(&circuit, &"x".repeat(57)).is_err());
    assert!(NativeBusCircuit::new(&circuit, &"x".repeat(56)).is_ok());
    assert!(
        NativeBusCircuit::with_limits(
            &circuit,
            "local",
            DirectCircuitLimits {
                max_trace_cells: 10,
                ..Default::default()
            }
        )
        .is_err()
    );
}

/// A bit decomposition multiplies every bit after the first by a constant weight. The gate
/// table reads each weight from preprocessing and checks the bit in that product's row, so
/// four bits cost one Boolean gate and three fused gates, each reading three witnesses.
#[test]
fn constant_products_check_their_multiplicands_in_one_row() {
    let mut b = CircuitBuilder::<F>::new();
    let expected = b.public_input();
    let bits = b.alloc_private_input_array::<4>("bits");
    let sum = b.binary_recompose_coordinates(&bits).unwrap();
    b.connect(sum, expected);
    let circuit = b.build().unwrap();
    let prepared = NativeBusCircuit::new(&circuit, "fused").unwrap();
    let statement = [F::from_raw_coordinates(0b1101).unwrap()];
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    runner
        .set_private_inputs(&[F::ONE, F::ZERO, F::ONE, F::ONE])
        .unwrap();
    let traces = prepared
        .traces(&runner.run().unwrap().witness_trace)
        .unwrap();
    let public = prepared.public_values(&statement).unwrap();
    for ((air, trace), public) in prepared.airs().iter().zip(&traces).zip(&public) {
        check_constraints(air, trace, public);
    }

    let gate_pp = prepared.airs()[1].preprocessed_trace().unwrap();
    let rows = gate_pp.values.as_chunks::<14>().0;
    let selected = |selector: usize| -> Vec<usize> {
        (0..rows.len())
            .filter(|&row| rows[row][6 + selector] == F::ONE)
            .collect()
    };
    // The first bit's weight is one, so it is added rather than multiplied and keeps its check.
    assert_eq!(selected(3).len(), 1);
    assert!(selected(4).is_empty() && selected(6).is_empty());
    let fused = selected(7);
    let weights: Vec<_> = fused.iter().map(|&row| rows[row][5]).collect();
    assert_eq!(
        weights,
        [2, 4, 8].map(|w| F::from_raw_coordinates(w).unwrap())
    );
    for &row in &fused {
        assert_eq!([rows[row][1], rows[row][3]], [F::ZERO; 2]);
    }
    let fanout = prepared.airs()[0].preprocessed_trace().unwrap();
    let reads = fanout
        .values
        .as_chunks::<4>()
        .0
        .iter()
        .filter(|row| row[1] == F::ONE)
        .count();
    let gate_reads: usize = rows
        .iter()
        .map(|row| {
            row[6..14]
                .iter()
                .zip([1, 4, 3, 2, 4, 5, 3, 3])
                .filter_map(|(&selector, count)| (selector == F::ONE).then_some(count))
                .sum::<usize>()
        })
        .sum();
    assert_eq!(reads, statement.len() + gate_reads);

    let rejects = |forge: &dyn Fn(&mut [F], F)| {
        // A row whose bit is one, so that every constant gives a different product.
        let row = *fused
            .iter()
            .find(|&&row| traces[1].values[5 * row] == F::ONE)
            .unwrap();
        let mut forged = traces[1].clone();
        forge(&mut forged.values[5 * row..5 * (row + 1)], rows[row][5]);
        std::panic::catch_unwind(|| check_constraints(&prepared.airs()[1], &forged, &[])).is_err()
    };
    let two = F::from_raw_coordinates(2).unwrap();
    assert!(rejects(&|cells, weight| {
        cells[0] = two;
        cells[4] = two * weight + cells[2];
    }));
    assert!(rejects(&|cells, weight| {
        cells[4] = cells[0] * (weight + F::ONE) + cells[2];
    }));
}

/// A select `s * (t - e) + e` is one gate of four reads: nothing else reads its difference, so
/// the addition defining it is dropped. The gate is that polynomial rather than a multiplexer, so
/// a selector outside {0, 1} needs nothing more. A difference that a third gate also reads keeps
/// its addition, a multiply-add by one, so forging it with the square read from it is refused.
#[test]
fn selects_fuse_only_differences_their_select_alone_reads() {
    let mut b = CircuitBuilder::<F>::new();
    let [s, t, e, selected] = b.alloc_public_input_array::<4>("select");
    let select = b.select(s, t, e);
    b.connect(select, selected);
    let [u, v, w, mixed, squared] = b.alloc_public_input_array::<5>("shared difference");
    let difference = b.sub(v, w);
    let mix = b.mul_add(u, difference, w);
    let square = b.mul(difference, difference);
    b.connect(mix, mixed);
    b.connect(square, squared);
    let circuit = b.build().unwrap();
    let prepared = NativeBusCircuit::new(&circuit, "select").unwrap();
    let witness_of = |expr: ExprId| circuit.expr_to_widx[&expr].0 as usize;
    let label = |expr: ExprId| witness_of(expr) + 1;

    let raw = |x: u128| F::from_raw_coordinates(x).unwrap();
    let [s_value, t_value, e_value, u_value, v_value, w_value] = [
        0x8123456789abcdef,
        0x5a5a,
        0x12345678,
        3,
        0xdeadbeef,
        0xfeed,
    ]
    .map(raw);
    let statement = [
        s_value,
        t_value,
        e_value,
        s_value * (t_value - e_value) + e_value,
        u_value,
        v_value,
        w_value,
        u_value * (v_value - w_value) + w_value,
        (v_value - w_value).square(),
    ];
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let traces = prepared.traces(&witness).unwrap();
    let public = prepared.public_values(&statement).unwrap();
    for ((air, trace), public) in prepared.airs().iter().zip(&traces).zip(&public) {
        check_constraints(air, trace, public);
    }

    let gate_pp = prepared.airs()[1].preprocessed_trace().unwrap();
    let rows = gate_pp.values.as_chunks::<14>().0;
    let labels = |row: usize| {
        core::array::from_fn::<_, 5, _>(|i| rows[row][i].to_raw_coordinates() as usize)
    };
    let selected_rows = |selector: usize| -> Vec<usize> {
        (0..rows.len())
            .filter(|&row| rows[row][6 + selector] == F::ONE)
            .collect()
    };
    let selects = selected_rows(1);
    assert_eq!(selects.len(), 1);
    assert_eq!(
        labels(selects[0]),
        [label(s), label(t), label(e), 0, label(selected)]
    );
    let additions: Vec<_> = selected_rows(6)
        .into_iter()
        .filter(|&row| rows[row][5] == F::ONE)
        .collect();
    assert_eq!(additions.len(), 1);
    let [a, unused, addend, accumulator, out] = labels(additions[0]);
    assert_eq!([unused, accumulator], [0, 0]);
    let mut read = [a, addend, out];
    read.sort_unstable();
    let mut expected = [label(v), label(w), label(difference)];
    expected.sort_unstable();
    assert_eq!(read, expected);
    let products = selected_rows(4);
    assert_eq!(products.len(), 1);
    assert!(labels(products[0])[..2].contains(&label(difference)));

    let mut forged = traces[1].clone();
    forged.values[5 * selects[0] + 4] += F::ONE;
    assert!(
        std::panic::catch_unwind(|| check_constraints(&prepared.airs()[1], &forged, &[])).is_err()
    );

    // Only the gate table refuses a forged difference whose square is claimed.
    let mut values: Vec<F> = (0..witness.num_rows() as u32)
        .map(|id| *witness.get_value(WitnessId(id)).unwrap())
        .collect();
    let forged_difference = v_value - w_value + F::ONE;
    values[witness_of(difference)] = forged_difference;
    values[witness_of(square)] = forged_difference.square();
    let mut forged_statement = statement;
    forged_statement[8] = forged_difference.square();
    let traces = prepared.traces(&WitnessTrace::new(values)).unwrap();
    let public = prepared.public_values(&forged_statement).unwrap();
    for (table, ((air, trace), public)) in
        prepared.airs().iter().zip(&traces).zip(&public).enumerate()
    {
        let refused = std::panic::catch_unwind(|| check_constraints(air, trace, public)).is_err();
        assert_eq!(refused, table == 1, "table {table}");
    }
}

/// A product of two differences `(t - e) * (u - e) + e` fuses one of them into a select whose
/// selector is the other, so the other keeps its addition and a forged selector is refused.
#[test]
fn a_difference_read_as_a_selector_keeps_its_addition() {
    let mut b = CircuitBuilder::<F>::new();
    let [t, u, e, expected] = b.alloc_public_input_array::<4>("differences");
    let first = b.sub(t, e);
    let second = b.sub(u, e);
    let out = b.mul_add(first, second, e);
    b.connect(out, expected);
    let circuit = b.build().unwrap();
    let prepared = NativeBusCircuit::new(&circuit, "selector").unwrap();
    let witness_of = |expr: ExprId| circuit.expr_to_widx[&expr].0 as usize;

    let raw = |x: u128| F::from_raw_coordinates(x).unwrap();
    let [t_value, u_value, e_value] = [0x8123456789abcdef, 0x5a5a, 0x1234].map(raw);
    let statement = [
        t_value,
        u_value,
        e_value,
        (t_value - e_value) * (u_value - e_value) + e_value,
    ];
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let traces = prepared.traces(&witness).unwrap();
    let public = prepared.public_values(&statement).unwrap();
    for ((air, trace), public) in prepared.airs().iter().zip(&traces).zip(&public) {
        check_constraints(air, trace, public);
    }

    let gate_pp = prepared.airs()[1].preprocessed_trace().unwrap();
    let rows = gate_pp.values.as_chunks::<14>().0;
    let count = |selector: usize, constant: F| {
        rows.iter()
            .filter(|row| row[6 + selector] == F::ONE && row[5] == constant)
            .count()
    };
    assert_eq!([count(1, F::ZERO), count(6, F::ONE)], [1, 1]);
    let select = rows.iter().find(|row| row[7] == F::ONE).unwrap();
    let selector = select[0].to_raw_coordinates() as usize - 1;
    let [kept, fused] = if selector == witness_of(first) {
        [first, second]
    } else {
        [second, first]
    };
    assert_eq!(selector, witness_of(kept));

    let mut values: Vec<F> = (0..witness.num_rows() as u32)
        .map(|id| *witness.get_value(WitnessId(id)).unwrap())
        .collect();
    let forged = values[witness_of(kept)] + F::ONE;
    values[witness_of(kept)] = forged;
    let forged_out = forged * values[witness_of(fused)] + e_value;
    values[witness_of(out)] = forged_out;
    let mut forged_statement = statement;
    forged_statement[3] = forged_out;
    let traces = prepared.traces(&WitnessTrace::new(values)).unwrap();
    let public = prepared.public_values(&forged_statement).unwrap();
    for (table, ((air, trace), public)) in
        prepared.airs().iter().zip(&traces).zip(&public).enumerate()
    {
        let refused = std::panic::catch_unwind(|| check_constraints(air, trace, public)).is_err();
        assert_eq!(refused, table == 1, "table {table}");
    }
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

/// Runs `circuit` on `statement`, applies `forge` to its witness values and the statement, and
/// returns the tables refusing the result.
fn refusing_tables(
    circuit: &Circuit<F>,
    prepared: &NativeBusCircuit<F>,
    statement: &[F],
    forge: impl FnOnce(&mut [F], &mut [F]),
) -> Vec<usize> {
    let mut runner = circuit.runner();
    runner.set_public_inputs(statement).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let mut values: Vec<F> = (0..witness.num_rows() as u32)
        .map(|id| *witness.get_value(WitnessId(id)).unwrap())
        .collect();
    let mut statement = statement.to_vec();
    forge(&mut values, &mut statement);
    let traces = prepared.traces(&WitnessTrace::new(values)).unwrap();
    let public = prepared.public_values(&statement).unwrap();
    prepared
        .airs()
        .iter()
        .zip(&traces)
        .zip(&public)
        .enumerate()
        .filter(|(_, ((air, trace), public))| {
            std::panic::catch_unwind(|| check_constraints(*air, *trace, public)).is_err()
        })
        .map(|(table, _)| table)
        .collect()
}

/// A difference that a select reads and that is also a public value keeps its addition: a select
/// in its place would leave the public difference unconstrained. A forged difference beside an
/// honest select output is refused, and only by the gate table.
#[test]
fn a_difference_read_outside_the_gates_keeps_its_addition() {
    let mut b = CircuitBuilder::<F>::new();
    let [s, t, e, public_difference, selected] = b.alloc_public_input_array::<5>("public");
    let difference = b.sub(t, e);
    b.connect(difference, public_difference);
    let mix = b.mul_add(s, difference, e);
    b.connect(mix, selected);
    let circuit = b.build().unwrap();
    let prepared = NativeBusCircuit::new(&circuit, "public").unwrap();
    assert_eq!(selects_and_additions(&prepared), [0, 1]);

    let raw = |x: u128| F::from_raw_coordinates(x).unwrap();
    let [s_value, t_value, e_value] = [0x8123456789abcdef, 0x5a5a, 0x12345678].map(raw);
    let statement = [
        s_value,
        t_value,
        e_value,
        t_value - e_value,
        s_value * (t_value - e_value) + e_value,
    ];
    assert!(refusing_tables(&circuit, &prepared, &statement, |_, _| {}).is_empty());
    let difference = circuit.expr_to_widx[&difference].0 as usize;
    let forged = refusing_tables(&circuit, &prepared, &statement, |values, statement| {
        values[difference] += F::ONE;
        statement[3] += F::ONE;
    });
    assert_eq!(forged, [1]);
}

/// A difference squared by a multiply-add `d * d + e` is read by that row as both factors, so the
/// row is no select of it and the difference keeps its addition: a select there would still read
/// the difference with nothing left defining it. A difference forged to zero, whose square is
/// then `e`, is refused, and only by the gate table.
#[test]
fn a_squared_difference_keeps_its_addition() {
    let mut b = CircuitBuilder::<F>::new();
    let [t, e, squared] = b.alloc_public_input_array::<3>("squared");
    let difference = b.sub(t, e);
    let square = b.mul_add(difference, difference, e);
    b.connect(square, squared);
    let circuit = b.build().unwrap();
    let prepared = NativeBusCircuit::new(&circuit, "squared").unwrap();
    assert_eq!(selects_and_additions(&prepared), [0, 1]);

    let raw = |x: u128| F::from_raw_coordinates(x).unwrap();
    let [t_value, e_value] = [0x8123456789abcdef, 0x5a5a].map(raw);
    let statement = [t_value, e_value, (t_value - e_value).square() + e_value];
    assert!(refusing_tables(&circuit, &prepared, &statement, |_, _| {}).is_empty());
    let [difference, square] = [difference, square].map(|expr| circuit.expr_to_widx[&expr].0);
    let forged = refusing_tables(&circuit, &prepared, &statement, |values, statement| {
        values[difference as usize] = F::ZERO;
        values[square as usize] = e_value;
        statement[2] = e_value;
    });
    assert_eq!(forged, [1]);
}

/// A four-digest Merkle level places the current digest at the position of its two index bits
/// and the siblings in increasing position in the other slots: six selects per word, one gate
/// each, and every position closes in the native tables. A group of four equal digests fills
/// the slots alike under any flags, so a non-Boolean index bit leaves the root intact and only
/// that bit's Boolean check refuses it. The slots are the same under Keccak-256 and BLAKE3.
#[test]
fn four_digest_level_slots_are_one_select_gate_each() {
    four_digest_level_slots(ByteHash::Keccak256, Keccak256Hash);
    four_digest_level_slots(ByteHash::Blake3, Blake3);
}

/// [`four_digest_level_slots_are_one_select_gate_each`] under `hash`, whose byte hasher is
/// `hasher`.
fn four_digest_level_slots<H>(hash: ByteHash, hasher: H)
where
    H: CryptographicHasher<u8, [u8; 32]> + Clone + Sync,
{
    type Mmcs<H> = MerkleTreeMmcs<
        BinaryField8,
        u8,
        SerializingHasher<H>,
        CompressionFunctionFromHasher<H, 4, 32>,
        4,
        32,
    >;
    let mmcs = Mmcs::<H>::new(
        SerializingHasher::new(hasher.clone()),
        CompressionFunctionFromHasher::new(hasher),
        0,
    );
    let mut b = CircuitBuilder::<F>::new();
    match hash {
        ByteHash::Keccak256 => b.enable_native_keccak_f1600().unwrap(),
        ByteHash::Blake3 => b.enable_native_blake3_compress().unwrap(),
    }
    let row = vec![b.public_input()];
    let bits = [b.public_input(), b.public_input()];
    let digests: Vec<Vec<ExprId>> = (0..4)
        .map(|_| (0..DIGEST_LIMBS).map(|_| b.public_input()).collect())
        .collect();
    b.verify_byte_hash_mmcs_opening_words_with_host_arity::<NativeBinaryEncoding, 4>(
        hash,
        &[row],
        &[4],
        &bits,
        &digests[..3],
        &digests[3..],
    )
    .unwrap();
    let circuit = b.build().unwrap();
    let prepared = NativeBusCircuit::new(&circuit, "arity4").unwrap();
    let gate_pp = prepared.airs()[1].preprocessed_trace().unwrap();
    let selects = gate_pp
        .values
        .as_chunks::<14>()
        .0
        .iter()
        .filter(|row| row[7] == F::ONE)
        .count();
    assert_eq!(selects, 6 * DIGEST_LIMBS);

    let raw = |word: u16| F::from_raw_coordinates(word.into()).unwrap();
    // Opens `index` of the tree over `rows` with index bits `bits`; whether the gate table holds.
    let gates_hold = |rows: [[u8; 2]; 4], index: usize, bits: [F; 2]| {
        let values = rows
            .iter()
            .flatten()
            .map(|&byte| BinaryField8::from_repr(byte))
            .collect();
        let (commitment, data) = mmcs.commit(vec![RowMajorMatrix::new(values, 2)]);
        let opening = mmcs.open_batch(index, &data);
        let statement: Vec<F> = core::iter::once(raw(u16::from_le_bytes(rows[index])))
            .chain(bits)
            .chain(
                opening
                    .opening_proof
                    .iter()
                    .chain(commitment.roots())
                    .flat_map(|digest| bytes_to_limbs(digest))
                    .map(raw),
            )
            .collect();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&statement).unwrap();
        let traces = prepared
            .traces(&runner.run().unwrap().witness_trace)
            .unwrap();
        let public = prepared.public_values(&statement).unwrap();
        for (table, ((air, trace), public)) in
            prepared.airs().iter().zip(&traces).zip(&public).enumerate()
        {
            if table != 1 {
                check_constraints(air, trace, public);
            }
        }
        std::panic::catch_unwind(|| check_constraints(&prepared.airs()[1], &traces[1], &[])).is_ok()
    };
    let bit = |index: usize, k: usize| F::from_bool(index >> k & 1 == 1);
    let distinct = [[1, 2], [3, 4], [5, 6], [7, 8]];
    for index in 0..4 {
        assert!(
            gates_hold(distinct, index, [bit(index, 0), bit(index, 1)]),
            "position {index}"
        );
    }
    let equal = [[9, 9]; 4];
    let two = F::from_raw_coordinates(2).unwrap();
    assert!(gates_hold(equal, 0, [F::ONE, F::ONE]));
    assert!(!gates_hold(equal, 0, [two, F::ZERO]));
    assert!(!gates_hold(equal, 0, [F::ZERO, two]));
}

#[test]
fn bus_labels_fit_independently_of_fanout_row_positions() {
    let mut b = CircuitBuilder::<BinaryField8>::new();
    b.alloc_public_input_array::<130>("public");
    let circuit = b.build().unwrap();
    assert!(IndexedCircuit::new(&circuit).is_err());
    let prepared = NativeBusCircuit::new(&circuit, "local").unwrap();
    assert!(prepared.log_heights()[0] >= 8);
    let mut b = CircuitBuilder::<BinaryField8>::new();
    b.alloc_public_input_array::<256>("public");
    assert!(NativeBusCircuit::new(&b.build().unwrap(), "labels").is_err());
}

#[test]
fn three_native_hash_calls_have_fixed_schedules_and_unique_boundary_tags() {
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let input = b.alloc_public_input_array::<100>("input");
    let expected = b.alloc_public_input_array::<100>("output");
    let mut state = input;
    for _ in 0..3 {
        state = b.add_native_keccak_f1600(&state).unwrap();
    }
    for i in 0..100 {
        b.connect(state[i], expected[i]);
    }
    let circuit = b.build().unwrap();
    let prepared = NativeBusCircuit::with_min_log_height_and_limits(
        &circuit,
        "local",
        8,
        DirectCircuitLimits::default(),
    )
    .unwrap();
    assert!(prepared.log_heights().iter().all(|&log| log >= 8));
    let input: [u64; 25] =
        core::array::from_fn(|i| 0x8123456789abcdefu64.rotate_left(3 * i as u32));
    let mut output = input;
    for _ in 0..3 {
        KeccakF.permute_mut(&mut output);
    }
    let public: Vec<_> = [input, output]
        .into_iter()
        .flat_map(|state| keccak_state_to_limbs(&state))
        .map(|word| F::from_raw_coordinates(word as u128).unwrap())
        .collect();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let traces = prepared.traces(&witness).unwrap();
    let indexed = NativeBinaryCircuit::new(&circuit).unwrap();
    let indexed_traces = indexed.traces(&witness).unwrap();
    let public = prepared.public_values(&public).unwrap();
    for ((air, trace), public) in prepared.airs().iter().zip(&traces).zip(&public) {
        check_constraints(air, trace, public);
    }
    let hash = traces.len() - 2;
    let bridge = traces.len() - 1;
    assert_eq!(traces[hash].width, 1625);
    assert_eq!(traces[bridge].width, 116);
    let indexed_hash = &indexed_traces[indexed_traces.len() - 2];
    for (row, indexed) in traces[hash]
        .values
        .as_chunks::<1625>()
        .0
        .iter()
        .zip(indexed_hash.values.as_chunks::<1725>().0.iter())
    {
        for limb in 0..100 {
            let value: F = (0..16)
                .map(|bit| row[25 + 16 * limb + bit] * F::from_raw_coordinates(1 << bit).unwrap())
                .sum();
            assert_eq!(value, indexed[1625 + limb]);
        }
    }
    let hash_pp = prepared.airs()[hash].preprocessed_trace().unwrap();
    let bridge_pp = prepared.airs()[bridge].preprocessed_trace().unwrap();
    for call in 0..3 {
        for boundary in 0..2 {
            let row = 25 * call + 24 * boundary;
            assert_eq!(hash_pp.values[3 * row + 2], F::ONE);
            assert_eq!(
                hash_pp.values[3 * row + 1],
                bridge_pp.values[119 * (2 * call + boundary) + 116]
            );
            assert_eq!(
                hash_pp.values[3 * row + 1].to_raw_coordinates(),
                (2 * call + boundary + 1) as u128
            );
        }
    }
    for (row, labels) in bridge_pp.values.as_chunks::<119>().0.iter().enumerate() {
        assert_eq!(labels[117], F::from_bool(row < 6));
        // Plain calls push no swapped digest limb onto the witness bus.
        assert_eq!(labels[118], F::ZERO);
        assert!(labels[100..116].iter().all(|&label| label == F::ZERO));
    }
    for row in traces[hash].values.as_chunks::<1625>().0.iter().skip(128) {
        assert_eq!(row[24], F::ONE);
        assert!(
            row.iter()
                .enumerate()
                .all(|(i, &value)| i == 24 || value == F::ZERO)
        );
    }
    let mut missing = traces[hash].clone();
    missing.values[25 * 1625] = F::ZERO;
    assert!(
        std::panic::catch_unwind(|| check_constraints(&prepared.airs()[hash], &missing, &[]))
            .is_err()
    );
}

/// A call that also outputs its swapped digest limbs pushes them onto the witness bus from its
/// output boundary row only, under their own activation. Every boundary row carries its first
/// sixteen limbs byte-swapped, as the Keccak table pushes them on the hash bus. The indexed
/// backend has no such columns and refuses the call.
#[test]
fn swapped_digest_outputs_are_bridged_from_the_output_boundary() {
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let input = b.alloc_public_input_array::<100>("input");
    let expected = b.alloc_public_input_array::<16>("swapped digest");
    let (_, swapped) = b
        .add_native_keccak_f1600_with_swapped_digest(&input)
        .unwrap();
    for (actual, expected) in swapped.into_iter().zip(expected) {
        b.connect(actual, expected);
    }
    let circuit = b.build().unwrap();
    let input: [u64; 25] =
        core::array::from_fn(|i| 0x0f1e2d3c4b5a6978u64.rotate_left(7 * i as u32));
    let output = keccak_state_to_limbs(&KeccakF.permute(input));
    let raw = |word: u16| F::from_raw_coordinates(word.into()).unwrap();
    let public: Vec<_> = keccak_state_to_limbs(&input)
        .into_iter()
        .chain(output[..16].iter().map(|limb| limb.swap_bytes()))
        .map(raw)
        .collect();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let prepared = NativeBusCircuit::new(&circuit, "swapped").unwrap();
    let traces = prepared.traces(&witness).unwrap();
    let values = prepared.public_values(&public).unwrap();
    for ((air, trace), public) in prepared.airs().iter().zip(&traces).zip(&values) {
        check_constraints(air, trace, public);
    }
    let bridge = traces.len() - 1;
    let pp = prepared.airs()[bridge].preprocessed_trace().unwrap();
    let rows = traces[bridge].values.as_chunks::<116>().0;
    let labels = pp.values.as_chunks::<119>().0;
    let swapped_ids: Vec<_> = circuit
        .ops
        .iter()
        .find_map(|op| match op {
            p3_circuit::Op::NonPrimitiveOpWithExecutor { outputs, .. } => {
                Some(outputs[0][100..].to_vec())
            }
            _ => None,
        })
        .unwrap();
    for boundary in 0..2 {
        for m in 0..16 {
            let limb = rows[boundary][m].to_raw_coordinates() as u16;
            assert_eq!(rows[boundary][100 + m], raw(limb.swap_bytes()));
        }
        assert_eq!(labels[boundary][118], F::from_bool(boundary == 1));
    }
    for (m, id) in swapped_ids.iter().enumerate() {
        assert_eq!(rows[1][100 + m], public[100 + m]);
        assert_eq!(
            labels[1][100 + m].to_raw_coordinates(),
            u128::from(id.0) + 1
        );
        assert_eq!(labels[0][100 + m], F::ZERO);
    }
    assert!(NativeBinaryCircuit::new(&circuit).is_err());
}
