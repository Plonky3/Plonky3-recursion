//! External input slots remain initialized and retain distinct public creators.

use p3_baby_bear::BabyBear;
use p3_circuit::CircuitBuilder;
use p3_circuit_prover::batch_stark_prover::BatchStarkProver;
use p3_circuit_prover::{ConstraintProfile, config};
use p3_field::PrimeCharacteristicRing;

#[test]
fn deduplicated_public_constraints_preserve_each_public_producer() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let a = builder.alloc_private_input("a");
    let a1 = builder.alloc_private_input("a1");
    let a2 = builder.alloc_private_input("a2");
    builder.connect(a, a1);
    builder.connect(a, a2);
    let k = builder.define_const(BabyBear::from_u8(7));
    let _ = builder.add(a, k);
    let p0 = builder.public_input();
    let p1 = builder.public_input();
    let d0 = builder.add(a1, k);
    let d1 = builder.add(a2, k);
    builder.connect(p0, d0);
    builder.connect(p1, d1);
    let circuit = builder.build().unwrap();
    let mut runner = circuit.runner();
    runner
        .set_private_inputs(&[BabyBear::from_u8(5); 3])
        .unwrap();
    runner
        .set_public_inputs(&[BabyBear::from_u8(12); 2])
        .unwrap();
    let traces = runner.run().unwrap();
    let prepared = BatchStarkProver::new(config::baby_bear())
        .prepare_circuit::<BabyBear, 1>(&circuit, &[], &[], ConstraintProfile::Standard)
        .unwrap();
    let proof = prepared.prove(&traces).unwrap();
    prepared.verifier().verify(&proof, &[]).unwrap();
}

#[test]
fn zero_private_decomposition_constraints_prove_after_deduplication() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    for _ in 0..2 {
        let input = builder.alloc_private_input("zero limb");
        for bit in builder.decompose_to_bits::<BabyBear>(input, 16).unwrap() {
            builder.assert_zero(bit);
        }
    }
    let circuit = builder.build().unwrap();
    let mut runner = circuit.runner();
    runner.set_private_inputs(&[BabyBear::ZERO; 2]).unwrap();
    let traces = runner.run().unwrap();
    let prepared = BatchStarkProver::new(config::baby_bear())
        .prepare_circuit::<BabyBear, 1>(&circuit, &[], &[], ConstraintProfile::Standard)
        .unwrap();
    let proof = prepared.prove(&traces).unwrap();
    prepared.verifier().verify(&proof, &[]).unwrap();
}
