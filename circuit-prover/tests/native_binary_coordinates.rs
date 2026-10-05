//! Reconstruction alone must not permit non-Boolean coordinate witnesses.

use p3_air::check_constraints;
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit_prover::direct::DirectCircuitAir;
use p3_field::PrimeCharacteristicRing;
use p3_test_utils::binary_field_params::BinaryField128;

#[test]
fn coordinate_codec_proves_booleanity_even_for_consistent_reconstruction() {
    type F = BinaryField128;
    let mut builder = CircuitBuilder::<F>::new();
    let bits = builder.alloc_public_input_array::<8>("coordinate bits");
    let expected = builder.public_input();
    let reconstructed = builder.binary_recompose_coordinates(&bits).unwrap();
    builder.connect(reconstructed, expected);
    let circuit = builder.build().unwrap();
    let air = DirectCircuitAir::new(&circuit).unwrap();
    for non_boolean in [false, true] {
        let bit = F::from_raw_coordinates(if non_boolean { 2 } else { 1 }).unwrap();
        let mut public = vec![F::ZERO; 9];
        public[7] = bit;
        public[8] = bit * F::from_raw_coordinates(1 << 7).unwrap();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public).unwrap();
        // The runner generates arithmetic values; the AIR checks Booleanity.
        let trace = air.trace(&runner.run().unwrap().witness_trace, 1).unwrap();
        let checked = std::panic::catch_unwind(|| check_constraints(&air, &trace, &public));
        assert_eq!(checked.is_err(), non_boolean);
    }
}
