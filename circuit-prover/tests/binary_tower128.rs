//! Prover-level ingress checks for non-native BinaryField128 values.

#[cfg(debug_assertions)]
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use p3_circuit::{CircuitBuilder, CircuitError};
use p3_circuit_prover::batch_stark_prover::BatchStarkProver;
use p3_circuit_prover::{BatchStarkProverError, ConstraintProfile, config};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_test_utils::baby_bear_params::{BabyBear, BinomialExtensionField};
#[cfg(debug_assertions)]
use p3_test_utils::rejection_oracle::{DebugRejectionKind, classify_debug_diagnostic};

type EF = BinomialExtensionField<BabyBear, 4>;

fn assert_algebraic_rejection(
    context: &str,
    check: impl FnOnce() -> Result<(), BatchStarkProverError>,
) {
    #[cfg(debug_assertions)]
    match catch_unwind(AssertUnwindSafe(check)) {
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied());
            match message.and_then(classify_debug_diagnostic) {
                Some(DebugRejectionKind::Constraint | DebugRejectionKind::Lookup) => {}
                None => resume_unwind(payload),
            }
        }
        Ok(result) => panic!("{context}: invalid witness lacked an AIR rejection: {result:?}"),
    }

    #[cfg(not(debug_assertions))]
    assert!(
        matches!(check(), Err(BatchStarkProverError::Verify(_))),
        "{context}: the generated proof must fail verification"
    );
}

#[test]
fn raw_nonbits_reach_boolean_air_and_are_rejected() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let input = builder.alloc_private_input("raw binary bit");
    let zero = builder.define_const(BabyBear::ZERO);
    let mut bits = [zero; 128];
    bits[0] = input;
    let _target = builder.binary128_from_bits(bits).unwrap();
    let circuit = builder.build().unwrap();
    let prepared = BatchStarkProver::new(config::baby_bear())
        .prepare_circuit::<BabyBear, 1>(&circuit, &[], &[], ConstraintProfile::Standard)
        .unwrap();

    let mut runner = circuit.runner();
    runner.set_private_inputs(&[BabyBear::ONE]).unwrap();
    let proof = prepared.prove(&runner.run().unwrap()).unwrap();
    prepared.verifier().verify(&proof, &[]).unwrap();

    for (label, invalid) in [
        ("raw bit two", BabyBear::from_u64(2)),
        ("raw bit minus one", -BabyBear::ONE),
    ] {
        let mut runner = circuit.runner();
        runner.set_private_inputs(&[invalid]).unwrap();
        let traces = runner
            .run()
            .expect("BoolCheck forwards the invalid witness");
        assert_algebraic_rejection(label, || {
            let proof = prepared.prove(&traces)?;
            prepared.verifier().verify(&proof, &[])
        });
    }
}

#[test]
fn extension_nonbit_reaches_boolean_air_and_is_rejected() {
    let mut builder = CircuitBuilder::<EF>::new();
    let input = builder.alloc_private_input("extension-valued raw bit");
    let zero = builder.define_const(EF::ZERO);
    let mut bits = [zero; 128];
    bits[127] = input;
    let _target = builder.binary128_from_bits(bits).unwrap();
    let circuit = builder.build().unwrap();
    let prepared = BatchStarkProver::new(config::baby_bear())
        .prepare_circuit::<EF, 4>(&circuit, &[], &[], ConstraintProfile::Standard)
        .unwrap();

    let mut runner = circuit.runner();
    runner.set_private_inputs(&[EF::ONE]).unwrap();
    let proof = prepared.prove(&runner.run().unwrap()).unwrap();
    prepared.verifier().verify(&proof, &[]).unwrap();

    let nonbase = EF::from_basis_coefficients_slice(&[
        BabyBear::ZERO,
        BabyBear::ONE,
        BabyBear::ZERO,
        BabyBear::ZERO,
    ])
    .unwrap();
    let mut runner = circuit.runner();
    runner.set_private_inputs(&[nonbase]).unwrap();
    let traces = runner.run().expect("BoolCheck forwards extension values");
    assert_algebraic_rejection("extension-valued raw bit", || {
        let proof = prepared.prove(&traces)?;
        prepared.verifier().verify(&proof, &[])
    });
}

#[test]
fn limb_out_of_range_cannot_produce_a_proof_witness() {
    let mut builder = CircuitBuilder::<BabyBear>::new();
    let input = builder.alloc_private_input("binary limb");
    let zero = builder.define_const(BabyBear::ZERO);
    let mut limbs = [zero; 8];
    limbs[7] = input;
    let _target = builder.binary128_from_limbs::<BabyBear>(limbs).unwrap();
    let circuit = builder.build().unwrap();
    let prepared = BatchStarkProver::new(config::baby_bear())
        .prepare_circuit::<BabyBear, 1>(&circuit, &[], &[], ConstraintProfile::Standard)
        .unwrap();

    let mut runner = circuit.runner();
    runner
        .set_private_inputs(&[BabyBear::from_u64(65535)])
        .unwrap();
    let proof = prepared.prove(&runner.run().unwrap()).unwrap();
    prepared.verifier().verify(&proof, &[]).unwrap();

    let mut runner = circuit.runner();
    runner
        .set_private_inputs(&[BabyBear::from_u64(65536)])
        .unwrap();
    assert!(
        matches!(runner.run(), Err(CircuitError::WitnessConflict { .. })),
        "a 65536 limb must conflict with its 16-bit reconstruction"
    );
}

#[test]
fn extension_limb_cannot_produce_a_proof_witness() {
    let mut builder = CircuitBuilder::<EF>::new();
    let input = builder.alloc_private_input("extension-valued binary limb");
    let zero = builder.define_const(EF::ZERO);
    let mut limbs = [zero; 8];
    limbs[0] = input;
    let _target = builder.binary128_from_limbs::<BabyBear>(limbs).unwrap();
    let circuit = builder.build().unwrap();
    let prepared = BatchStarkProver::new(config::baby_bear())
        .prepare_circuit::<EF, 4>(&circuit, &[], &[], ConstraintProfile::Standard)
        .unwrap();

    let mut runner = circuit.runner();
    runner
        .set_private_inputs(&[EF::from(BabyBear::from_u64(65535))])
        .unwrap();
    let proof = prepared.prove(&runner.run().unwrap()).unwrap();
    prepared.verifier().verify(&proof, &[]).unwrap();

    let nonbase = EF::from_basis_coefficients_slice(&[
        BabyBear::ONE,
        BabyBear::ONE,
        BabyBear::ZERO,
        BabyBear::ZERO,
    ])
    .unwrap();
    let mut runner = circuit.runner();
    runner.set_private_inputs(&[nonbase]).unwrap();
    assert!(
        matches!(runner.run(), Err(CircuitError::WitnessConflict { .. })),
        "a nonbase limb must conflict with its base-valued reconstruction"
    );
}
