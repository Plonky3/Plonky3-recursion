//! Binary-in, binary-out recursion with an independently supplied statement.

use p3_air::BaseAir;
use p3_binary_field::{BinaryField32, BinaryField128, TowerLevel};
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::{CircuitBuilder, CircuitConstructionLimits, ops::ByteHash};
use p3_circuit_prover::direct::{DirectCircuitAir, DirectCircuitLimits};
use p3_field::ExtensionField;
use p3_recursion::pcs::binary::RecursiveBinaryWhirTowerField;
use p3_recursion::{
    artifact::{
        ArtifactLimits, BinaryNativeVerifierSpec, BinaryNativeWhirAuthority,
        BinaryNativeWhirPcsParameters,
    },
    prepared::{NativeBinaryRecursionOptions, PreparedNativeBinaryWhirLayer},
    verifier::VerifierLimits,
};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

type F = BinaryField128;
fn protocol() -> ProtocolParameters {
    ProtocolParameters {
        security_level: 8,
        pow_bits: 0,
        round_log_inv_rates: vec![],
        folding_factor: FoldingFactor::Constant(1),
        soundness_type: SecurityAssumption::JohnsonBound,
        starting_log_inv_rate: 1,
    }
}
fn recursive_protocol() -> ProtocolParameters {
    ProtocolParameters {
        security_level: 32,
        folding_factor: FoldingFactor::Constant(4),
        ..protocol()
    }
}
fn options() -> NativeBinaryRecursionOptions {
    NativeBinaryRecursionOptions {
        main: recursive_protocol(),
        preprocessed: recursive_protocol(),
        cap_height: 0,
        initial_bytes: b"native-recursion-layer-v1".to_vec(),
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
    }
}

#[test]
#[ignore = "proves a full native binary verifier; run explicitly"]
fn native_layer_proves_and_binds_the_original_statement() {
    prove_native_layer::<F>();
}

#[test]
#[ignore = "proves a complete Tower32 child verifier over Tower128; run explicitly"]
fn tower32_child_is_proved_over_tower128() {
    prove_native_layer::<BinaryField32>();
}

fn prove_native_layer<B>()
where
    B: RecursiveBinaryWhirTowerField
        + BinaryCoordinateField
        + p3_binary_dft::EncodableLevel
        + p3_binary_pcs::FoldAlphabet<F>
        + p3_field::PackedValue<Value = B>
        + Ord,
    F: ExtensionField<B> + p3_binary_pcs::ChallengeField<B>,
    p3_binary_pcs::whir::BinaryWhirDomain<B>: p3_whir::WhirDomain<B, F>,
{
    let [input, factor, constant] = [0xfedcba9876543210, 0x8123456789abcdef, 0x8912]
        .map(|raw| B::from_raw_coordinates(raw & (u128::MAX >> (128 - B::RAW_BITS))).unwrap());
    let mut builder = CircuitBuilder::<B>::new();
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
        main: BinaryNativeWhirPcsParameters::<B>::new(
            variables,
            protocol(),
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
    let (prover, authority) = BinaryNativeWhirAuthority::<B, _>::setup(
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
    let (foreign_prover, foreign_authority) = BinaryNativeWhirAuthority::<B, _>::setup(
        vec![air.clone()],
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
    let layer = PreparedNativeBinaryWhirLayer::from_native_authority_with_construction_limits(
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
        Err(p3_recursion::verifier::VerificationError::PreparedInputMismatch { .. })
    ));
    eprintln!(
        "native layer: {} witnesses, {} operations",
        layer.circuit().witness_count,
        layer.circuit().ops.len()
    );
    let outer = layer.prove_verified(&checked).unwrap();
    let token = layer.verify(&outer, &public).unwrap();
    assert_eq!(
        token
            .public_values()
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>(),
        public[0]
            .iter()
            .map(|value| F::from_repr(value.raw_coordinates()))
            .collect::<Vec<_>>()
    );
    let mut wrong = public.clone();
    wrong[0][1] += B::ONE;
    assert!(layer.verify(&outer, &wrong).is_err());
    assert!(layer.verify(&outer, &[]).is_err());
    // The output authority is a native binary input for another recursion layer.
    let mut builder = CircuitBuilder::<F>::new();
    assert!(
        layer
            .authority()
            .recursive_verifier()
            .input_shape()
            .allocate_native_targets(&mut builder)
            .is_ok()
    );
}
