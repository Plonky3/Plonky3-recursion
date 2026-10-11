//! Binary-in, packed-Keccak-out native recursion with an independently supplied statement.

use p3_air::BaseAir;
use p3_baby_bear::BabyBear;
use p3_binary_field::BinaryField128;
use p3_circuit::ops::ByteHash;
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::{Circuit, CircuitBuilder, CircuitConstructionLimits};
use p3_circuit_prover::direct::{DirectCircuitAir, DirectCircuitLimits};
use p3_field::PrimeCharacteristicRing;
use p3_recursion::ProveNextLayerParams;
use p3_recursion::artifact::{
    ArtifactLimits, BinaryNativeVerifierSpec, BinaryNativeWhirAuthority,
    BinaryNativeWhirPcsParameters, VerifiedBinaryNativeWhirProof,
};
use p3_recursion::builtin_config::{
    BabyBearD4Poseidon2BinaryConfig, FriConfigV1, SuiteIdV1, baby_bear_d4_poseidon2_binary,
};
use p3_recursion::pcs::binary::MerkleArity;
use p3_recursion::prepared::{
    NativeBinaryMixedRecursionOptions, NativeBinaryRecursionOptions,
    PreparedBinaryMixedWhirMultiStarkLayer, PreparedNativeBinaryMixedWhirLayer,
};
use p3_recursion::verifier::{VerificationError, VerifierLimits};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

type F = BinaryField128;
type C = BabyBearD4Poseidon2BinaryConfig;

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

/// Output commitments of `arity` trees.
fn options(arity: MerkleArity) -> NativeBinaryMixedRecursionOptions {
    NativeBinaryMixedRecursionOptions {
        base: NativeBinaryRecursionOptions {
            main: protocol(32, 4),
            preprocessed: protocol(32, 4),
            arity,
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

fn run(circuit: &Circuit<F>, public: &[F], private: &[F]) -> bool {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public)
        .and_then(|()| runner.set_private_inputs(private))
        .and_then(|()| runner.run())
        .is_ok()
}

/// A small dense child statement, its checked proof, a checked proof of the same statement
/// under a foreign child authority, the checked proof's private native verifier values, and
/// the L1 layer over the child authority.
struct Fixture {
    public: Vec<Vec<F>>,
    checked: VerifiedBinaryNativeWhirProof<F>,
    foreign: VerifiedBinaryNativeWhirProof<F>,
    private: Vec<F>,
    layer: PreparedNativeBinaryMixedWhirLayer,
}

/// A layer over a dense child; the child and the layer's outputs commit with `arity` trees.
fn prepare(arity: MerkleArity) -> Fixture {
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
        main: BinaryNativeWhirPcsParameters::<F>::with_limits(
            variables,
            protocol(8, 1),
            ByteHash::Keccak256,
            arity,
            0,
            &VerifierLimits::default(),
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
        options(arity),
        &limits,
        &CircuitConstructionLimits {
            max_expression_nodes: 1 << 22,
            max_pending_connects: 1 << 22,
            max_non_primitive_calls: 1 << 20,
            max_non_primitive_slots: 1 << 27,
        },
    )
    .unwrap();
    let private = checked
        .native_input()
        .private_native_values(&authority.recursive_verifier().input_shape())
        .unwrap();
    Fixture {
        public,
        checked,
        foreign,
        private,
        layer,
    }
}

/// The layer refuses a token checked under a foreign child authority before witness
/// generation. The child statement and every verifier value reach the layer circuit: witness
/// generation accepts the checked child and fails once any of them changes.
#[test]
fn tampered_child_fails_mixed_layer_witness_generation() {
    let Fixture {
        public,
        foreign,
        private,
        layer,
        ..
    } = prepare(MerkleArity::Two);
    assert!(matches!(
        layer.prove_verified(&foreign),
        Err(VerificationError::PreparedInputMismatch { .. })
    ));
    // A Tower128 child statement is the layer circuit's public input unchanged.
    let flat = &public[0];
    assert!(run(layer.circuit(), flat, &private));
    let mut wrong = flat.clone();
    wrong[1] += F::ONE;
    assert!(!run(layer.circuit(), &wrong, &private));
    for index in [0, 16, private.len() - 1] {
        let mut wrong = private.clone();
        wrong[index] += F::ONE;
        assert!(!run(layer.circuit(), flat, &wrong));
    }
}

#[test]
#[ignore = "proves a full native binary verifier with a packed Keccak table; run explicitly"]
fn mixed_output_layer_proves_and_binds_the_original_statement() {
    prove_mixed_output_layer(MerkleArity::Two);
}

/// The dense child and both parts of the mixed layer's output commit with four-digest trees.
#[test]
#[ignore = "proves a full native binary verifier with a packed Keccak table; run explicitly"]
fn four_digest_trees_carry_through_a_mixed_layer() {
    prove_mixed_output_layer(MerkleArity::Four);
}

/// Proves the mixed layer over a child of `arity` trees, its output committed with `arity`
/// trees, and checks the output against the child's statement.
fn prove_mixed_output_layer(arity: MerkleArity) {
    let Fixture {
        public,
        checked,
        layer,
        ..
    } = prepare(arity);
    let outer = layer.prove_verified(&checked).unwrap();
    assert!(outer.opening.packed.is_some());
    let token = layer.verify(&outer, &public).unwrap();
    // The Bits-mode bus exports the Tower128 child statement unchanged and in order.
    assert_eq!(
        token
            .public_values()
            .iter()
            .flatten()
            .copied()
            .collect::<Vec<_>>(),
        public[0]
    );
    let mut wrong = public;
    wrong[0][1] += F::ONE;
    assert!(layer.verify(&outer, &wrong).is_err());
    assert!(layer.verify(&outer, &[]).is_err());
}

/// The mixed layer's output token is wrapped by the prime-field layer built from the mixed
/// layer's output authority, and the wrap proves the token's statement.
#[test]
#[ignore = "builds and proves a prime-field verifier of a full packed-Keccak native proof; run explicitly"]
fn mixed_output_layer_token_is_wrapped_by_the_prime_layer() {
    wrap_mixed_output_layer(MerkleArity::Two);
}

/// The prime-field layer opens the four-digest trees of the mixed layer's output.
#[test]
#[ignore = "builds and proves a prime-field verifier of a full packed-Keccak native proof; run explicitly"]
fn four_digest_mixed_output_token_is_wrapped_by_the_prime_layer() {
    wrap_mixed_output_layer(MerkleArity::Four);
}

/// Wraps the output token of the mixed layer over a child of `arity` trees, its output
/// committed with `arity` trees, in the prime-field layer and checks the wrap's proof.
fn wrap_mixed_output_layer(arity: MerkleArity) {
    let Fixture {
        public,
        checked,
        layer,
        ..
    } = prepare(arity);
    let outer = layer.prove_verified(&checked).unwrap();
    let token = layer.verify(&outer, &public).unwrap();
    let authority = layer.authority().clone();
    drop(layer);
    let config = baby_bear_d4_poseidon2_binary(
        &FriConfigV1::new(
            SuiteIdV1::BabyBearD4Poseidon2BinaryFri,
            1,
            0,
            2,
            2,
            0,
            0,
            0,
            0,
            0,
            0,
        ),
        &authority.artifact_limits().verifier,
    )
    .unwrap();
    let wrap = PreparedBinaryMixedWhirMultiStarkLayer::<C, 4>::from_native_authority(
        &authority,
        config,
        ProveNextLayerParams::default(),
    )
    .unwrap();
    let output = wrap.prove_verified(&token).unwrap();
    let statement = wrap
        .statement_layout()
        .pack::<BabyBear>(token.public_values())
        .unwrap();
    wrap.verifier().verify(&output.0, &statement).unwrap();
}
