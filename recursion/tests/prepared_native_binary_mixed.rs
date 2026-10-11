//! Binary-in, packed-Keccak-out native recursion with an independently supplied statement.

use p3_air::BaseAir;
use p3_binary_field::BinaryField128;
use p3_circuit::ops::ByteHash;
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::{CircuitBuilder, CircuitConstructionLimits};
use p3_circuit_prover::direct::{DirectCircuitAir, DirectCircuitLimits};
use p3_field::PrimeCharacteristicRing;
use p3_recursion::artifact::{
    ArtifactLimits, BinaryNativeVerifierSpec, BinaryNativeWhirAuthority,
    BinaryNativeWhirPcsParameters,
};
use p3_recursion::prepared::{
    NativeBinaryMixedRecursionOptions, NativeBinaryRecursionOptions,
    PreparedNativeBinaryMixedWhirLayer,
};
use p3_recursion::verifier::{VerificationError, VerifierLimits};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

type F = BinaryField128;

const fn protocol(security_level: usize, folding: usize) -> ProtocolParameters {
    ProtocolParameters {
        security_level,
        pow_bits: 0,
        round_log_inv_rates: vec![],
        folding_factor: FoldingFactor::Constant(folding),
        soundness_type: SecurityAssumption::JohnsonBound,
        starting_log_inv_rate: 1,
    }
}

fn options() -> NativeBinaryMixedRecursionOptions {
    NativeBinaryMixedRecursionOptions {
        base: NativeBinaryRecursionOptions {
            main: protocol(32, 4),
            preprocessed: protocol(32, 4),
            cap_height: 0,
            initial_bytes: b"native-mixed-recursion-layer-v1".to_vec(),
            sumcheck_pow_bits: 0,
            max_tau_draws: 32,
            security_bits: 4,
            max_pcs_codeword_cells: 1 << 27,
            artifact_limits: ArtifactLimits {
                verifier: VerifierLimits {
                    max_rounds: 256,
                    max_metadata_entries: 1 << 20,
                    ..Default::default()
                },
                ..Default::default()
            },
        },
        packed: protocol(32, 4),
    }
}

#[test]
fn mixed_output_layer_proves_and_binds_the_original_statement() {
    let [input, factor, constant] = [0xfedcba9876543210, 0x8123456789abcdef, 0x8912]
        .map(|raw| F::from_raw_coordinates(raw).unwrap());
    let mut builder = CircuitBuilder::<F>::new();
    let a = builder.public_input();
    let expected = builder.public_input();
    let private = builder.alloc_private_input("factor");
    let c = builder.define_const(constant);
    let out = builder.mul_add(a, private, c);
    builder.connect(out, expected);
    let circuit = builder.build().unwrap();
    let air = DirectCircuitAir::new(&circuit).unwrap();
    let variables = 1 + air.width().next_power_of_two().ilog2() as usize;
    let spec = BinaryNativeVerifierSpec {
        main: BinaryNativeWhirPcsParameters::<F>::new(
            variables,
            protocol(8, 1),
            ByteHash::Keccak256,
            0,
        )
        .unwrap(),
        preprocessed: None,
        transcript_hash: ByteHash::Keccak256,
        initial_bytes: b"native-recursion-child-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    };
    let mut foreign_spec = spec.clone();
    foreign_spec.initial_bytes.push(99);
    let (prover, authority) = BinaryNativeWhirAuthority::<F, _>::setup(
        vec![air.clone()],
        vec![1],
        spec,
        &VerifierLimits::default(),
    )
    .unwrap();
    let public = vec![vec![input, input * factor + constant]];
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public[0]).unwrap();
    runner.set_private_inputs(&[factor]).unwrap();
    let trace = air.trace(&runner.run().unwrap().witness_trace, 1).unwrap();
    let proof = prover.prove(&public, vec![trace.clone()]).unwrap();
    let checked = authority.verify_native(&proof, &public).unwrap();
    let (foreign_prover, foreign_authority) = BinaryNativeWhirAuthority::<F, _>::setup(
        vec![air],
        vec![1],
        foreign_spec,
        &VerifierLimits::default(),
    )
    .unwrap();
    let foreign_proof = foreign_prover.prove(&public, vec![trace]).unwrap();
    let foreign = foreign_authority
        .verify_native(&foreign_proof, &public)
        .unwrap();
    let limits = DirectCircuitLimits {
        max_trace_cells: 1 << 27,
        ..Default::default()
    };
    let layer = PreparedNativeBinaryMixedWhirLayer::from_native_authority_with_construction_limits(
        &authority,
        options(),
        &limits,
        &CircuitConstructionLimits {
            max_expression_nodes: 1 << 22,
            max_pending_connects: 1 << 22,
            max_non_primitive_calls: 1 << 20,
            max_non_primitive_slots: 1 << 27,
        },
    )
    .unwrap();
    assert!(matches!(
        layer.prove_verified(&foreign),
        Err(VerificationError::PreparedInputMismatch { .. })
    ));
    let outer = layer.prove_verified(&checked).unwrap();
    assert!(outer.opening.packed.is_some());
    let token = layer.verify(&outer, &public).unwrap();
    assert_eq!(
        token
            .public_values()
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>(),
        layer
            .output_public_values(&public)
            .unwrap()
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>()
    );
    let mut wrong = public.clone();
    wrong[0][1] += F::ONE;
    assert!(layer.verify(&outer, &wrong).is_err());
    assert!(layer.verify(&outer, &[]).is_err());
}
