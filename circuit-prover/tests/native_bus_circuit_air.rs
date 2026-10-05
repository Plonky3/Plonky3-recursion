//! Fanout adjacency, sentinel values and native hash schedules are local AIR relations.

use p3_air::{BaseAir, check_constraints};
use p3_circuit::{
    CircuitBuilder,
    ops::{binary_native::BinaryCoordinateField, keccak_state_to_limbs},
};
use p3_circuit_prover::{
    direct::DirectCircuitLimits, indexed::IndexedCircuit, native_bus::NativeBusCircuit,
};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::KeccakF;
use p3_symmetric::Permutation;
use p3_test_utils::binary_field_params::{BinaryField8, BinaryField128};

type F = BinaryField128;

#[test]
fn fanout_copies_and_zero_sentinels_are_constrained() {
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
        .chunks_exact(4)
        .position(|row| row[0] != F::ZERO && row[2] == F::ONE)
        .unwrap();
    let sentinel = pp
        .values
        .chunks_exact(4)
        .position(|row| row[3] == F::ONE)
        .unwrap();
    for row in [adjacent, sentinel] {
        let mut wrong = traces[0].clone();
        wrong.values[row] += F::ONE;
        assert!(
            std::panic::catch_unwind(|| check_constraints(&prepared.airs()[0], &wrong, &[]))
                .is_err()
        );
    }
    let last_live = pp
        .values
        .chunks_exact(4)
        .rposition(|row| row[1] == F::ONE)
        .unwrap();
    assert_eq!(pp.values[4 * last_live + 2], F::ZERO);
    for row in pp.values.chunks_exact(4).skip(last_live + 1) {
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
    let prepared = NativeBusCircuit::new(&circuit, "local").unwrap();
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
    let traces = prepared
        .traces(&runner.run().unwrap().witness_trace)
        .unwrap();
    let public = prepared.public_values(&public).unwrap();
    for ((air, trace), public) in prepared.airs().iter().zip(&traces).zip(&public) {
        check_constraints(air, trace, public);
    }
    let hash = traces.len() - 2;
    let bridge = traces.len() - 1;
    assert_eq!(traces[hash].width, 1725);
    assert_eq!(traces[bridge].width, 100);
    let hash_pp = prepared.airs()[hash].preprocessed_trace().unwrap();
    let bridge_pp = prepared.airs()[bridge].preprocessed_trace().unwrap();
    for call in 0..3 {
        for boundary in 0..2 {
            let row = 25 * call + 24 * boundary;
            assert_eq!(hash_pp.values[3 * row + 2], F::ONE);
            assert_eq!(
                hash_pp.values[3 * row + 1],
                bridge_pp.values[102 * (2 * call + boundary) + 100]
            );
            assert_eq!(
                hash_pp.values[3 * row + 1].to_raw_coordinates(),
                (2 * call + boundary + 1) as u128
            );
        }
    }
    for row in bridge_pp.values.chunks_exact(102).skip(6) {
        assert_eq!(row[101], F::ZERO);
    }
    let mut missing = traces[hash].clone();
    missing.values[25 * 1725] = F::ZERO;
    assert!(
        std::panic::catch_unwind(|| check_constraints(&prepared.airs()[hash], &missing, &[]))
            .is_err()
    );
}
