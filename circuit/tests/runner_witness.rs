use p3_baby_bear::BabyBear;
use p3_circuit::CircuitBuilder;
use p3_field::PrimeCharacteristicRing;

#[test]
fn witness_execution_matches_full_traces_with_connected_outputs() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let input = builder.public_input();
    let expected = builder.public_input();
    let private = builder.alloc_private_input("multiplier");
    let five = builder.define_const(BabyBear::from_u8(5));
    let output = builder.mul_add(input, private, five);
    builder.connect(output, expected);
    let circuit = builder.build().unwrap();
    let execute = || {
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&[BabyBear::from_u8(3), BabyBear::from_u8(17)])
            .unwrap();
        runner.set_private_inputs(&[BabyBear::from_u8(4)]).unwrap();
        runner
    };
    assert_eq!(
        execute().run_witness().unwrap(),
        execute().run().unwrap().witness_trace
    );
}

#[test]
fn witness_execution_keeps_input_and_constraint_errors() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let input = builder.public_input();
    let expected = builder.public_input();
    let five = builder.define_const(BabyBear::from_u8(5));
    let output = builder.add(input, five);
    builder.connect(output, expected);
    let circuit = builder.build().unwrap();
    assert!(circuit.runner().run_witness().is_err());
    let mut runner = circuit.runner();
    let result = runner
        .set_public_inputs(&[BabyBear::from_u8(3), BabyBear::from_u8(9)])
        .and_then(|()| runner.run_witness());
    assert!(result.is_err());
}
