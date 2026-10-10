//! The packed-bit Keccak mode commits the same bit table as the dense mode and drops only the
//! booleanity constraints.

use p3_air::{AirLayout, BaseAir};
use p3_bus::BusSymbolicBuilder;
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::tables::WitnessTrace;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::native_bus::{KeccakCommitment, NativeBusCircuit, NativeBusTrace};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::KeccakF;
use p3_symmetric::Permutation;
use p3_test_utils::binary_field_params::BinaryField128;

type F = BinaryField128;

const WIDTH: usize = 1625;

/// A chain of `calls` Keccak-f permutations from public inputs.
fn chain(calls: usize) -> (Circuit<F>, Vec<F>) {
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let mut state = b.alloc_public_input_array::<100>("input").to_vec();
    for _ in 0..calls {
        state = b.add_native_keccak_f1600(&state).unwrap().to_vec();
    }
    let expected = b.alloc_public_input_array::<100>("output");
    for (actual, expected) in state.iter().zip(expected) {
        b.connect(*actual, expected);
    }
    let mut lanes: [u64; 25] =
        core::array::from_fn(|i| 0x8123456789abcdefu64.rotate_left(5 * i as u32) ^ i as u64);
    let mut public = limbs(&lanes);
    for _ in 0..calls {
        KeccakF.permute_mut(&mut lanes);
    }
    public.extend(limbs(&lanes));
    (b.build().unwrap(), public)
}

fn limbs(lanes: &[u64; 25]) -> Vec<F> {
    p3_circuit::ops::keccak_state_to_limbs(lanes)
        .into_iter()
        .map(|word| F::from_raw_coordinates(word as u128).unwrap())
        .collect()
}

fn witness(circuit: &Circuit<F>, public: &[F]) -> WitnessTrace<F> {
    let mut runner = circuit.runner();
    runner.set_public_inputs(public).unwrap();
    runner.run().unwrap().witness_trace
}

fn build(
    circuit: &Circuit<F>,
    min_log_height: usize,
    keccak: KeccakCommitment,
) -> NativeBusCircuit<F> {
    NativeBusCircuit::with_options(
        circuit,
        "packed",
        min_log_height,
        DirectCircuitLimits::default(),
        keccak,
    )
    .unwrap()
}

const fn bit(words: &[u64], row: usize, column: usize) -> bool {
    (words[(row / 64) * WIDTH + column] >> (row % 64)) & 1 == 1
}

#[test]
fn packed_words_match_dense_bits() {
    for (calls, min_log_height) in [(1, 1), (2, 1), (3, 1), (6, 1), (11, 1), (1, 9), (3, 10)] {
        let (circuit, public) = chain(calls);
        let witness = witness(&circuit, &public);
        let dense = build(&circuit, min_log_height, KeccakCommitment::Dense);
        let bits = build(&circuit, min_log_height, KeccakCommitment::Bits);
        assert_eq!(dense.log_heights(), bits.log_heights());

        let keccak = bits.keccak_table_index().unwrap();
        let dense_traces = dense.traces(&witness).unwrap();
        let tables = bits.trace_tables(&witness).unwrap();
        let log_height = bits.log_heights()[keccak];
        assert_eq!(bits.packed_bit_variables(), Some(11 + log_height));
        for (index, (table, expected)) in tables.iter().zip(&dense_traces).enumerate() {
            match table {
                NativeBusTrace::PackedBits {
                    words,
                    log_height: log,
                } => {
                    assert_eq!(index, keccak);
                    assert_eq!(*log, log_height);
                    let height = 1usize << log_height;
                    assert_eq!(words.width, WIDTH);
                    assert_eq!(words.values.len(), WIDTH * height.div_ceil(64));
                    for row in 0..height {
                        for column in 0..WIDTH {
                            assert_eq!(
                                expected.values[row * WIDTH + column],
                                F::from_bool(bit(&words.values, row, column)),
                                "calls {calls}, row {row}, column {column}"
                            );
                        }
                    }
                    if height < 64 {
                        for column in 0..WIDTH {
                            assert_eq!(words.values[column] >> height, 0);
                        }
                    }
                }
                NativeBusTrace::Dense(matrix) => {
                    assert_ne!(index, keccak);
                    assert_eq!(matrix.values, expected.values);
                }
            }
        }
        assert_eq!(bits.traces(&witness).unwrap().len(), dense_traces.len());
        assert_eq!(
            bits.traces(&witness).unwrap()[keccak].values,
            dense_traces[keccak].values
        );
    }
}

#[test]
fn dense_mode_is_unchanged_and_has_no_packed_table() {
    let (circuit, public) = chain(2);
    let witness = witness(&circuit, &public);
    let dense = build(&circuit, 1, KeccakCommitment::Dense);
    assert_eq!(dense.keccak_table_index(), None);
    assert_eq!(dense.packed_bit_variables(), None);
    let traces = dense.traces(&witness).unwrap();
    let tables = dense.trace_tables(&witness).unwrap();
    for (table, trace) in tables.iter().zip(&traces) {
        let NativeBusTrace::Dense(matrix) = table else {
            panic!("dense mode returned a packed table");
        };
        assert_eq!(matrix.values, trace.values);
    }
    let default = NativeBusCircuit::new(&circuit, "packed").unwrap();
    assert_eq!(default.log_heights(), dense.log_heights());
    assert_eq!(default.main_variables(), dense.main_variables());
}

#[test]
fn boolean_assumption_reported_only_for_bits_keccak() {
    let (circuit, _) = chain(2);
    for keccak in [KeccakCommitment::Dense, KeccakCommitment::Bits] {
        let prepared = build(&circuit, 1, keccak);
        let index = prepared.airs().len() - 2;
        for (i, air) in prepared.airs().iter().enumerate() {
            assert_eq!(
                BaseAir::<F>::assumes_boolean_trace(air),
                keccak == KeccakCommitment::Bits && i == index,
                "{keccak:?}, table {i}"
            );
        }
        assert_eq!(
            prepared.keccak_table_index(),
            (keccak == KeccakCommitment::Bits).then_some(index)
        );
    }
}

#[test]
fn bits_mode_drops_exactly_the_booleanity_constraints() {
    let (circuit, _) = chain(2);
    let dense = build(&circuit, 1, KeccakCommitment::Dense);
    let bits = build(&circuit, 1, KeccakCommitment::Bits);
    let count = |air| {
        BusSymbolicBuilder::<F>::from_air(air, AirLayout::from_air::<F>(air))
            .base_constraints()
            .len()
    };
    for (i, (d, b)) in dense.airs().iter().zip(bits.airs()).enumerate() {
        let (d, b) = (count(d), count(b));
        if i == bits.keccak_table_index().unwrap() {
            assert_eq!(d, b + 1600);
        } else {
            assert_eq!(d, b);
        }
    }
}

#[test]
fn bits_mode_stacks_only_the_other_tables() {
    let (circuit, _) = chain(3);
    let dense = build(&circuit, 1, KeccakCommitment::Dense);
    let bits = build(&circuit, 1, KeccakCommitment::Bits);
    assert!(bits.main_variables() < dense.main_variables());
    assert_eq!(
        bits.preprocessed_variables(),
        dense.preprocessed_variables()
    );
}
