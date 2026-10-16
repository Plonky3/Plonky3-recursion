//! Folding binary-in, folding binary-out recursion with an independent statement.

use p3_air::BaseAir;
use p3_binary_field::{BinaryField32, BinaryField128, TowerLevel};
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsParams};
use p3_circuit::ops::ByteHash;
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, CircuitConstructionLimits, NpoTypeId};
use p3_circuit_prover::direct::{DirectCircuitAir, DirectCircuitLimits};
use p3_field::{ExtensionField, PrimeCharacteristicRing};
use p3_recursion::artifact::{
    ArtifactLimits, BinaryNativeAuthority, BinaryNativeGroupedAuthority,
    BinaryNativeGroupedPcsParameters, BinaryNativeGroupedProver, BinaryNativePcsParameters,
    BinaryNativeProver, BinaryNativeVerifierSpec,
};
use p3_recursion::pcs::binary::{BinaryCodewordGrouping, RecursiveBinaryTowerField};
use p3_recursion::prepared::{
    NativeBinaryFoldingRecursionOptions, PreparedNativeBinaryGroupedLayer,
    PreparedNativeBinaryLayer,
};
use p3_recursion::verifier::{VerificationError, VerifierLimits};

type F = BinaryField128;

fn options() -> NativeBinaryFoldingRecursionOptions {
    let params = BinaryPcsParams {
        log_inv_rate: 1,
        pow_bits: 0,
        security_level: 32,
    };
    NativeBinaryFoldingRecursionOptions {
        main: params,
        preprocessed: params,
        log_folding_factor: 4,
        cap_height: 0,
        query_draw_slack: 8,
        initial_bytes: b"native-folding-layer-v1".to_vec(),
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

const fn construction() -> CircuitConstructionLimits {
    CircuitConstructionLimits {
        max_expression_nodes: 1 << 22,
        max_pending_connects: 1 << 22,
        max_non_primitive_calls: 1 << 20,
        max_non_primitive_slots: 1 << 27,
    }
}

fn limits() -> DirectCircuitLimits {
    DirectCircuitLimits {
        max_trace_cells: 1 << 27,
        ..Default::default()
    }
}

type Child<B> = (
    BinaryNativeProver<B, F, DirectCircuitAir<B>>,
    BinaryNativeAuthority<B, F, DirectCircuitAir<B>>,
    Vec<Vec<B>>,
    p3_matrix::dense::RowMajorMatrix<B>,
);

fn child<B>(transcript_hash: ByteHash, tag: u8) -> Child<B>
where
    B: RecursiveBinaryTowerField
        + BinaryCoordinateField
        + p3_binary_dft::EncodableLevel
        + p3_binary_pcs::FoldAlphabet<F>
        + p3_field::PackedValue<Value = B>,
    F: ExtensionField<B> + p3_binary_pcs::ChallengeField<B>,
{
    let mask = u128::MAX >> (128 - B::RAW_BITS);
    let [input, factor, constant] = [0xfedcba9876543210, 0x8123456789abcdef, 0x8912]
        .map(|raw| B::from_raw_coordinates(raw & mask).unwrap());
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
        main: BinaryNativePcsParameters {
            config: BinaryPcsConfig::try_new::<B, F>(
                variables,
                BinaryPcsParams {
                    log_inv_rate: 1,
                    pow_bits: 0,
                    security_level: 8,
                },
            )
            .unwrap(),
            hash: ByteHash::Keccak256,
            cap_height: 0,
            max_query_draws: 512,
        },
        preprocessed: None,
        transcript_hash,
        initial_bytes: vec![b'c', tag],
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    };
    let (prover, authority) = BinaryNativeAuthority::<B, F, _>::setup(
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
    (prover, authority, public, trace)
}

/// The folding layer enables only native Keccak-f, so it is not allowed to
/// hash a Blake3 child's transcript.
#[test]
fn blake3_transcript_child_needs_the_native_blake3_compression() {
    let (_, authority, _, _) = child::<F>(ByteHash::Blake3, 0);
    assert!(matches!(
        PreparedNativeBinaryLayer::from_native_authority(&authority, options(), &limits()),
        Err(VerificationError::CircuitBuilder(
            CircuitBuilderError::OpNotAllowed { op }
        )) if op == NpoTypeId::native_blake3_compress()
    ));
}

#[test]
fn codeword_budget_is_checked_before_key_generation() {
    let (_, authority, _, _) = child::<F>(ByteHash::Keccak256, 0);
    let mut small = options();
    small.max_pcs_codeword_cells = 1;
    assert!(matches!(
        PreparedNativeBinaryLayer::from_native_authority_with_construction_limits(
            &authority,
            small,
            &limits(),
            &construction(),
        ),
        Err(VerificationError::ResourceLimitExceeded { .. })
    ));
}

#[test]
#[ignore = "proves a full native folding verifier; run explicitly"]
fn native_folding_layer_proves_and_binds_the_original_statement() {
    prove_layer::<F>();
}

#[test]
#[ignore = "proves a Tower32 folding child verifier over Tower128; run explicitly"]
fn tower32_folding_child_is_proved_over_tower128() {
    prove_layer::<BinaryField32>();
}

fn prove_layer<B>()
where
    B: RecursiveBinaryTowerField
        + BinaryCoordinateField
        + p3_binary_dft::EncodableLevel
        + p3_binary_pcs::FoldAlphabet<F>
        + p3_field::PackedValue<Value = B>,
    F: ExtensionField<B> + p3_binary_pcs::ChallengeField<B>,
{
    let (prover, authority, public, trace) = child::<B>(ByteHash::Keccak256, 0);
    let proof = prover.prove(&public, vec![trace.clone()]).unwrap();
    let checked = authority.verify_native(&proof, &public).unwrap();
    let (foreign_prover, foreign_authority, _, _) = child::<B>(ByteHash::Keccak256, 1);
    let foreign_proof = foreign_prover.prove(&public, vec![trace]).unwrap();
    let foreign = foreign_authority
        .verify_native(&foreign_proof, &public)
        .unwrap();
    let layer = PreparedNativeBinaryLayer::from_native_authority_with_construction_limits(
        &authority,
        options(),
        &limits(),
        &construction(),
    )
    .unwrap();
    assert!(matches!(
        layer.prove_verified(&foreign),
        Err(VerificationError::PreparedInputMismatch { .. })
    ));
    eprintln!(
        "native folding layer: {} witnesses, {} operations, {} initial codeword cells",
        layer.circuit().witness_count,
        layer.circuit().ops.len(),
        layer.initial_codeword_cells()
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
            .map(|v| F::from_repr(v.raw_coordinates()))
            .collect::<Vec<_>>()
    );
    let mut wrong = public;
    wrong[0][1] += B::ONE;
    assert!(layer.verify(&outer, &wrong).is_err());
    assert!(layer.verify(&outer, &[]).is_err());
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

type GroupedChild<B> = (
    BinaryNativeGroupedProver<B, F, DirectCircuitAir<B>>,
    BinaryNativeGroupedAuthority<B, F, DirectCircuitAir<B>>,
    Vec<Vec<B>>,
    p3_matrix::dense::RowMajorMatrix<B>,
);

/// The `child` relation committed with one fold coset per Merkle leaf.
fn grouped_child<B>(tag: u8) -> GroupedChild<B>
where
    B: RecursiveBinaryTowerField
        + BinaryCoordinateField
        + p3_binary_dft::EncodableLevel
        + p3_binary_pcs::FoldAlphabet<F>
        + p3_field::PackedValue<Value = B>,
    F: ExtensionField<B> + p3_binary_pcs::ChallengeField<B>,
{
    let mask = u128::MAX >> (128 - B::RAW_BITS);
    let [input, factor, constant] = [0xfedcba9876543210, 0x8123456789abcdef, 0x8912]
        .map(|raw| B::from_raw_coordinates(raw & mask).unwrap());
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
        main: BinaryNativeGroupedPcsParameters {
            pcs: BinaryNativePcsParameters {
                config: BinaryPcsConfig::try_new_with_folding::<B, F>(
                    variables,
                    BinaryPcsParams {
                        log_inv_rate: 1,
                        pow_bits: 0,
                        security_level: 8,
                    },
                    variables.min(4),
                )
                .unwrap(),
                hash: ByteHash::Keccak256,
                cap_height: 0,
                max_query_draws: 512,
            },
            base_grouping: BinaryCodewordGrouping::Folding,
            round_grouping: BinaryCodewordGrouping::Folding,
        },
        preprocessed: None,
        transcript_hash: ByteHash::Keccak256,
        initial_bytes: vec![b'g', tag],
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    };
    let (prover, authority) = BinaryNativeGroupedAuthority::<B, F, _>::setup(
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
    (prover, authority, public, trace)
}

#[test]
fn grouped_cap_above_log_inv_rate_is_rejected_before_graph_construction() {
    let (_, authority, _, _) = grouped_child::<F>(0);
    // A single expression node would stop any graph construction first.
    let tiny = CircuitConstructionLimits {
        max_expression_nodes: 1,
        ..construction()
    };
    for (main, preprocessed) in [(1, 1), (2, 1), (1, 2)] {
        let mut wide = options();
        wide.main.log_inv_rate = main;
        wide.preprocessed.log_inv_rate = preprocessed;
        wide.cap_height = 2;
        let error =
            PreparedNativeBinaryGroupedLayer::from_native_authority_with_construction_limits(
                &authority,
                wide,
                &limits(),
                &tiny,
            )
            .err()
            .unwrap();
        assert!(
            matches!(&error, VerificationError::InvalidProofShape(message) if message.contains("cap height")),
            "log inverse rates {main} and {preprocessed}: {error}"
        );
    }
}

#[test]
fn grouped_layer_rejects_a_token_of_another_child_authority() {
    let (_, authority, _, _) = grouped_child::<F>(0);
    let (foreign_prover, foreign_authority, public, trace) = grouped_child::<F>(1);
    let foreign_proof = foreign_prover.prove(&public, vec![trace]).unwrap();
    let foreign = foreign_authority
        .verify_native(&foreign_proof, &public)
        .unwrap();
    // A cap equal to both output log inverse rates is the largest accepted.
    let mut at_rate = options();
    assert_eq!(at_rate.main.log_inv_rate, 1);
    assert_eq!(at_rate.preprocessed.log_inv_rate, 1);
    at_rate.cap_height = 1;
    let layer = PreparedNativeBinaryGroupedLayer::from_native_authority_with_construction_limits(
        &authority,
        at_rate,
        &limits(),
        &construction(),
    )
    .unwrap();
    assert!(matches!(
        layer.prove_verified(&foreign),
        Err(VerificationError::PreparedInputMismatch { .. })
    ));
    // The output commits coset leaves, so the next grouped layer can
    // allocate its native targets.
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

#[test]
fn grouped_folding_layer_proves_and_binds_the_original_statement() {
    let (prover, authority, public, trace) = grouped_child::<F>(0);
    let proof = prover.prove(&public, vec![trace]).unwrap();
    let checked = authority.verify_native(&proof, &public).unwrap();
    let layer = PreparedNativeBinaryGroupedLayer::from_native_authority_with_construction_limits(
        &authority,
        options(),
        &limits(),
        &construction(),
    )
    .unwrap();
    eprintln!(
        "grouped native folding layer: {} witnesses, {} operations, {} initial codeword cells",
        layer.circuit().witness_count,
        layer.circuit().ops.len(),
        layer.initial_codeword_cells()
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
            .map(|v| F::from_repr(v.raw_coordinates()))
            .collect::<Vec<_>>()
    );
    let mut wrong = public;
    wrong[0][1] += F::ONE;
    assert!(layer.verify(&outer, &wrong).is_err());
    assert!(layer.verify(&outer, &[]).is_err());
}
