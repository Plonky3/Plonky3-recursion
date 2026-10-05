//! Circuit graphs produce native binary proofs, with no prime-field prover.

use core::hash::Hash;

use p3_air::BaseAir;
use p3_binary_field::{BinaryField128, Poly64, TowerLevel};
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsParams};
use p3_circuit::ops::ByteHash;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_circuit_prover::direct::DirectCircuitAir;
use p3_field::{Field, PrimeCharacteristicRing};
use p3_recursion::artifact::{
    BinaryNativeAuthority, BinaryNativePcsParameters, BinaryNativePolyWhirAuthority,
    BinaryNativePolyWhirPcsParameters, BinaryNativeVerifierSpec,
};
use p3_recursion::verifier::VerifierLimits;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

const LOG_HEIGHT: usize = 2;

fn computation<F: Field + Eq + Hash>(constant: F) -> Circuit<F> {
    let mut builder = CircuitBuilder::new();
    let input = builder.public_input();
    let output = builder.public_input();
    let factor = builder.alloc_private_input("factor");
    let constant = builder.define_const(constant);
    let value = builder.mul_add(input, factor, constant);
    builder.connect(value, output);
    builder.build().unwrap()
}

#[test]
fn circuit_is_proved_and_verified_natively_over_tower128() {
    type F = BinaryField128;
    let [input, factor, constant] = [
        0xfedc_ba98_7654_3210,
        0xdeaf_bead_9283_7465,
        0x9876_1234_abcd,
    ]
    .map(F::from_repr);
    let public = vec![vec![input, input * factor + constant]];
    let circuit = computation(constant);
    let air = DirectCircuitAir::new(&circuit).unwrap();
    let variables = LOG_HEIGHT + air.width().next_power_of_two().ilog2() as usize;
    let spec = BinaryNativeVerifierSpec {
        main: BinaryNativePcsParameters {
            config: BinaryPcsConfig::try_new::<F, F>(
                variables,
                BinaryPcsParams {
                    log_inv_rate: 2,
                    pow_bits: 0,
                    security_level: 8,
                },
            )
            .unwrap(),
            hash: ByteHash::Blake3,
            cap_height: 0,
            max_query_draws: 128,
        },
        preprocessed: None,
        transcript_hash: ByteHash::Blake3,
        initial_bytes: b"native-binary-circuit-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    };
    let (prover, authority) = BinaryNativeAuthority::<F, F, _>::setup(
        vec![air.clone()],
        vec![LOG_HEIGHT],
        spec,
        &VerifierLimits::default(),
    )
    .unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public[0]).unwrap();
    runner.set_private_inputs(&[factor]).unwrap();
    let trace = air
        .trace(&runner.run().unwrap().witness_trace, LOG_HEIGHT)
        .unwrap();
    let proof = prover.prove(&public, vec![trace]).unwrap();
    let checked = authority.verify_native(&proof, &public).unwrap();
    assert_eq!(checked.public_values(), public);
    let mut wrong = public.clone();
    wrong[0][1] += F::ONE;
    assert!(authority.verify_native(&proof, &wrong).is_err());
    let mut altered = proof;
    altered.opening.base_opened_values[0][0] += F::ONE;
    assert!(authority.verify_native(&altered, &public).is_err());
}

#[test]
fn circuit_is_proved_and_verified_natively_over_poly64_with_poly192_challenges() {
    type F = Poly64;
    let [input, factor, constant] = [
        0xfedc_ba98_7654_3210,
        0xdeaf_bead_9283_7465,
        0x9876_1234_abcd,
    ]
    .map(F::new);
    let public = vec![vec![input, input * factor + constant]];
    let circuit = computation(constant);
    let air = DirectCircuitAir::new(&circuit).unwrap();
    let variables = LOG_HEIGHT + air.width().next_power_of_two().ilog2() as usize;
    let spec = BinaryNativeVerifierSpec {
        main: BinaryNativePolyWhirPcsParameters::new(
            variables,
            ProtocolParameters {
                starting_log_inv_rate: 2,
                round_log_inv_rates: vec![],
                folding_factor: FoldingFactor::Constant(1),
                soundness_type: SecurityAssumption::JohnsonBound,
                security_level: 24,
                pow_bits: 0,
            },
            ByteHash::Blake3,
            0,
        )
        .unwrap(),
        preprocessed: None,
        transcript_hash: ByteHash::Blake3,
        initial_bytes: b"native-polynomial-circuit-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 16,
    };
    let (prover, authority) = BinaryNativePolyWhirAuthority::<_>::setup(
        vec![air.clone()],
        vec![LOG_HEIGHT],
        spec,
        &VerifierLimits::default(),
    )
    .unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public[0]).unwrap();
    runner.set_private_inputs(&[factor]).unwrap();
    let trace = air
        .trace(&runner.run().unwrap().witness_trace, LOG_HEIGHT)
        .unwrap();
    let proof = prover.prove(&public, vec![trace]).unwrap();
    let checked = authority.verify_native(&proof, &public).unwrap();
    assert_eq!(checked.public_values(), public);
    let mut wrong = public.clone();
    wrong[0][1] += F::ONE;
    assert!(authority.verify_native(&proof, &wrong).is_err());
}
