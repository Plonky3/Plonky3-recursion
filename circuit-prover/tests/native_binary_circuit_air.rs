//! Native custom hash tables must bind both sides to the canonical witness.

use p3_air::{BaseAir, check_constraints};
use p3_circuit::{CircuitBuilder, ops::binary_native::BinaryCoordinateField};
use p3_circuit_prover::{
    direct::{DirectCircuitAir, DirectCircuitLimits},
    indexed::IndexedCircuit,
    native_binary::NativeBinaryCircuit,
};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::KeccakF;
use p3_symmetric::Permutation;
use p3_test_utils::binary_field_params::BinaryField128;

type F = BinaryField128;

#[test]
fn native_keccak_tables_pin_all_calls_and_boundary_reads() {
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_keccak_f1600().unwrap();
    let input = builder.alloc_public_input_array::<100>("input");
    let expected = builder.alloc_public_input_array::<100>("output");
    let mut state = input;
    for _ in 0..3 {
        state = builder.add_native_keccak_f1600(&state).unwrap();
    }
    for i in 0..100 {
        builder.connect(state[i], expected[i]);
    }
    let circuit = builder.build().unwrap();
    assert!(DirectCircuitAir::new(&circuit).is_err());
    assert!(IndexedCircuit::new(&circuit).is_err());
    assert!(
        NativeBinaryCircuit::with_limits(
            &circuit,
            DirectCircuitLimits {
                max_trace_cells: 100,
                ..Default::default()
            }
        )
        .is_err()
    );
    let prepared = NativeBinaryCircuit::new(&circuit).unwrap();
    let input: [u64; 25] =
        core::array::from_fn(|i| 0x8123_4567_89ab_cdefu64.rotate_left(3 * i as u32));
    let mut output = input;
    for _ in 0..3 {
        KeccakF.permute_mut(&mut output);
    }
    let public: Vec<_> = [input, output]
        .into_iter()
        .flat_map(|state| p3_circuit::ops::keccak_state_to_limbs(&state))
        .map(|limb| F::from_raw_coordinates(limb as u128).unwrap())
        .collect();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    let traces = prepared
        .traces(&runner.run().unwrap().witness_trace)
        .unwrap();
    let public_by_air = prepared.public_values(&public).unwrap();
    for ((air, trace), public) in prepared.airs().iter().zip(&traces).zip(&public_by_air) {
        check_constraints(air, trace, public);
    }
    let hash_index = traces.len() - 2;
    let bridge_index = traces.len() - 1;
    assert_eq!(prepared.airs()[hash_index].width(), 1725);
    assert_eq!(
        prepared.airs()[hash_index].main_next_row_columns().len(),
        1625
    );
    assert!(
        prepared.airs()[bridge_index]
            .main_next_row_columns()
            .is_empty()
    );
    let mut wrong_position = traces[bridge_index].clone();
    wrong_position.values[0] += F::ONE;
    assert!(
        std::panic::catch_unwind(|| check_constraints(
            &prepared.airs()[bridge_index],
            &wrong_position,
            &[]
        ))
        .is_err()
    );
    let mut missing_call = traces[hash_index].clone();
    missing_call.values[25 * 1725] = F::ZERO;
    assert!(
        std::panic::catch_unwind(|| check_constraints(
            &prepared.airs()[hash_index],
            &missing_call,
            &[]
        ))
        .is_err()
    );
    let mut non_bit = traces[hash_index].clone();
    non_bit.values[25] = F::from_raw_coordinates(2).unwrap();
    assert!(
        std::panic::catch_unwind(|| check_constraints(&prepared.airs()[hash_index], &non_bit, &[]))
            .is_err()
    );
}

#[test]
fn native_primitive_only_circuit_omits_hash_tables() {
    let mut builder = CircuitBuilder::<F>::new();
    let input = builder.public_input();
    builder.assert_bool(input);
    let circuit = builder.build().unwrap();
    let prepared = NativeBinaryCircuit::new(&circuit).unwrap();
    assert_eq!(
        prepared.airs().len(),
        IndexedCircuit::new(&circuit).unwrap().airs().len()
    );
}
