//! Actual prime-field proofs check polynomial-basis arithmetic and Boolean ingress.

#[cfg(debug_assertions)]
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use p3_baby_bear::BabyBear;
use p3_circuit::{CircuitBuilder, ExprId, StatementExport};
use p3_circuit_prover::{
    BatchStarkProver, BatchStarkProverError, ConstraintProfile, StatementAirBuilder,
    StatementPreprocessor, StatementProver, config,
};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_test_utils::binary_field_params::{Poly64, Poly192};
#[cfg(debug_assertions)]
use p3_test_utils::rejection_oracle::{DebugRejectionKind, classify_debug_diagnostic};

fn limbs(value: Poly192) -> Vec<BabyBear> {
    value
        .coefficients()
        .into_iter()
        .flat_map(|coefficient| {
            let raw = coefficient.to_bits();
            (0..4).map(move |i| BabyBear::from_u16((raw >> (16 * i)) as u16))
        })
        .collect()
}

#[test]
fn constant_one_inverse_checks_preserve_private_limb_creators() {
    for extension in [false, true] {
        let mut b = CircuitBuilder::<BabyBear>::new();
        let count = if extension { 12 } else { 4 };
        let inputs = b.alloc_private_inputs(count, "constant-one polynomial inverse");
        if extension {
            let one = b.binary_poly192_constant([1, 0, 0]).unwrap();
            let candidate = b
                .binary_poly192_from_limbs::<BabyBear>(inputs.try_into().unwrap())
                .unwrap();
            b.assert_binary_poly192_inverse(&one, &candidate);
        } else {
            let one = b.binary_poly64_constant(1).unwrap();
            let candidate = b
                .binary_poly64_from_limbs::<BabyBear>(inputs.try_into().unwrap())
                .unwrap();
            b.assert_binary_poly64_inverse(&one, &candidate);
        }
        let circuit = b.build().unwrap();
        let prepared = BatchStarkProver::new(config::baby_bear())
            .prepare_circuit::<BabyBear, 1>(&circuit, &[], &[], ConstraintProfile::Standard)
            .unwrap();
        let mut honest = vec![BabyBear::ZERO; count];
        honest[0] = BabyBear::ONE;
        let mut runner = circuit.runner();
        runner.set_private_inputs(&honest).unwrap();
        let proof = prepared.prove(&runner.run().unwrap()).unwrap();
        prepared.verifier().verify(&proof, &[]).unwrap();
        for offset in [0, count - 1] {
            let mut wrong = honest.clone();
            wrong[offset] += BabyBear::ONE;
            let mut runner = circuit.runner();
            runner.set_private_inputs(&wrong).unwrap();
            assert!(runner.run().is_err());
        }
    }
}

#[test]
fn polynomial_arithmetic_and_inverse_constraints_verify_in_a_prime_proof() {
    let mut b = CircuitBuilder::<BabyBear>::new();
    let a = b.alloc_private_input_array::<12>("Poly192 operand");
    let inverse = b.alloc_private_input_array::<12>("Poly192 inverse");
    let expected = b.alloc_public_input_array::<12>("Poly192 square");
    let schema = b
        .set_statement_exports::<BabyBear>(&expected.map(StatementExport::Base))
        .unwrap();
    let a = b.binary_poly192_from_limbs::<BabyBear>(a).unwrap();
    let inverse = b.binary_poly192_from_limbs::<BabyBear>(inverse).unwrap();
    b.assert_binary_poly192_inverse(&a, &inverse);
    let square = b.binary_poly192_square(&a);
    let actual = b.binary_poly192_to_limbs::<BabyBear>(&square).unwrap();
    for (actual, expected) in actual.into_iter().zip(expected) {
        let difference = b.sub(actual, expected);
        b.assert_zero(difference);
    }
    let circuit = b.build().unwrap();
    let mut prover = BatchStarkProver::new(config::baby_bear());
    prover.register_table_prover(Box::new(StatementProver::<1>::new(schema.clone())));
    let prepared = prover
        .prepare_circuit::<BabyBear, 1>(
            &circuit,
            &[Box::new(StatementPreprocessor::new(schema.clone()))],
            &[Box::new(StatementAirBuilder::<1>::new(schema))],
            ConstraintProfile::Standard,
        )
        .unwrap();
    for coefficients in [
        [
            0x0123_4567_89ab_cdef,
            0xfedc_ba98_7654_3210,
            0x8000_0000_0000_0001,
        ],
        [0, 1, 0],
    ] {
        let value = Poly192::new(coefficients.map(Poly64::new));
        let mut private = limbs(value);
        private.extend(limbs(value.try_inverse().unwrap()));
        let public = limbs(value.square());
        let mut runner = circuit.runner();
        runner.set_private_inputs(&private).unwrap();
        runner.set_public_inputs(&public).unwrap();
        let proof = prepared.prove(&runner.run().unwrap()).unwrap();
        prepared.verifier().verify(&proof, &public).unwrap();
        let mut wrong = public.clone();
        wrong[11] += BabyBear::ONE;
        assert!(prepared.verifier().verify(&proof, &wrong).is_err());
        private[23] += BabyBear::ONE;
        let mut runner = circuit.runner();
        runner.set_private_inputs(&private).unwrap();
        runner.set_public_inputs(&public).unwrap();
        assert!(runner.run().is_err());
    }
}

fn algebraic_rejection(check: impl FnOnce() -> Result<(), BatchStarkProverError>) {
    #[cfg(debug_assertions)]
    match catch_unwind(AssertUnwindSafe(check)) {
        Err(payload) => {
            let diagnostic = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied());
            match diagnostic.and_then(classify_debug_diagnostic) {
                Some(DebugRejectionKind::Constraint | DebugRejectionKind::Lookup) => {}
                None => resume_unwind(payload),
            }
        }
        Ok(result) => panic!("invalid Poly bit lacked an AIR rejection: {result:?}"),
    }
    #[cfg(not(debug_assertions))]
    assert!(matches!(check(), Err(BatchStarkProverError::Verify(_))));
}

#[test]
fn polynomial_bits_reject_nonbinary_and_extension_valued_coordinates_in_the_air() {
    type EF = BinomialExtensionField<BabyBear, 4>;
    let mut b = CircuitBuilder::<EF>::new();
    let input = b.alloc_private_input("Poly192 high coefficient bit");
    let mut high = [ExprId::ZERO; 64];
    high[63] = input;
    let zero = b.binary_poly64_from_bits([ExprId::ZERO; 64]).unwrap();
    let high = b.binary_poly64_from_bits(high).unwrap();
    b.binary_poly192_from_coefficients([zero.clone(), zero, high]);
    let circuit = b.build().unwrap();
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
    for value in [EF::TWO, -EF::ONE, nonbase] {
        let mut runner = circuit.runner();
        runner.set_private_inputs(&[value]).unwrap();
        let traces = runner
            .run()
            .expect("BoolCheck forwards coordinates to the AIR");
        algebraic_rejection(|| {
            let proof = prepared.prove(&traces)?;
            prepared.verifier().verify(&proof, &[])
        });
    }
}
