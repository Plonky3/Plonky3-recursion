//! Binary-in, binary-out recursion with an independently supplied statement.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::Poly64;
use p3_circuit::ops::ByteHash;
use p3_circuit::{CircuitBuilder, CircuitBuilderError, CircuitConstructionLimits, NpoTypeId};
use p3_circuit_prover::direct::{DirectCircuitAir, DirectCircuitLimits};
use p3_recursion::artifact::{
    ArtifactLimits, BinaryNativePolyWhirAuthority, BinaryNativePolyWhirPcsParameters,
    BinaryNativeVerifierSpec,
};
use p3_recursion::pcs::binary::MerkleArity;
use p3_recursion::prepared::{NativeBinaryRecursionOptions, PreparedNativeBinaryPolyWhirLayer};
use p3_recursion::verifier::{VerificationError, VerifierLimits};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

type F = Poly64;
use p3_field::PrimeCharacteristicRing;
const fn protocol() -> ProtocolParameters {
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
/// Output commitments of `arity` trees.
fn options(arity: MerkleArity) -> NativeBinaryRecursionOptions {
    NativeBinaryRecursionOptions {
        main: recursive_protocol(),
        preprocessed: recursive_protocol(),
        arity,
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
#[ignore = "proves a full native Poly64/Poly192 verifier; run explicitly"]
fn native_poly_layer_proves_and_binds_the_original_statement() {
    prove_native_poly_layer(MerkleArity::Two, ByteHash::Keccak256);
}

/// A BLAKE3 child's verifier hashes with native BLAKE3, and the layer's output commits and
/// hashes its transcript with BLAKE3.
#[test]
#[ignore = "proves a full native Poly64/Poly192 verifier; run explicitly"]
fn blake3_native_poly_layer_proves_and_binds_the_original_statement() {
    prove_native_poly_layer(MerkleArity::Two, ByteHash::Blake3);
}

/// The child and the layer's outputs commit with four-digest trees.
#[test]
#[ignore = "proves a full native Poly64/Poly192 verifier; run explicitly"]
fn four_digest_trees_carry_through_a_native_poly_layer() {
    prove_native_poly_layer(MerkleArity::Four, ByteHash::Keccak256);
}

/// The child and the layer's outputs commit with `arity` trees of `hash`.
fn prove_native_poly_layer(arity: MerkleArity, hash: ByteHash) {
    let [input, factor, constant] = [0xfedcba9876543210, 0x8123456789abcdef, 0x8912].map(F::new);
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
        main: BinaryNativePolyWhirPcsParameters::with_limits(
            variables,
            protocol(),
            hash,
            arity,
            0,
            &VerifierLimits::default(),
        )
        .unwrap(),
        preprocessed: None,
        transcript_hash: hash,
        initial_bytes: b"native-recursion-child-v1".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    };
    let mut foreign_spec = spec.clone();
    foreign_spec.initial_bytes.push(99);
    let (prover, authority) = BinaryNativePolyWhirAuthority::<_>::setup(
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
    let (foreign_prover, foreign_authority) = BinaryNativePolyWhirAuthority::<_>::setup(
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
    let layer = PreparedNativeBinaryPolyWhirLayer::from_native_authority_with_construction_limits(
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
    assert!(matches!(
        layer.prove_verified(&foreign),
        Err(p3_recursion::verifier::VerificationError::PreparedInputMismatch { .. })
    ));
    assert_eq!(layer.authority().transcript_hash(), hash);
    eprintln!(
        "native Poly layer: {} witnesses, {} operations",
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
    );
    let mut wrong = public.clone();
    wrong[0][1] += F::ONE;
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

#[derive(Clone)]
struct ConstantAir;
impl BaseAir<F> for ConstantAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        1
    }
}
impl<AB: AirBuilder<F = F>> Air<AB> for ConstantAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        b.assert_eq(main.current_slice()[0], b.public_values()[0]);
    }
}
/// A child committed with `pcs` trees whose transcript hashes with `transcript`.
fn authority(pcs: ByteHash, transcript: ByteHash) -> BinaryNativePolyWhirAuthority<ConstantAir> {
    let spec = BinaryNativeVerifierSpec {
        main: BinaryNativePolyWhirPcsParameters::new(1, protocol(), pcs, 0).unwrap(),
        preprocessed: None,
        transcript_hash: transcript,
        initial_bytes: b"native-recursion-limit-test".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    };
    BinaryNativePolyWhirAuthority::setup(
        vec![ConstantAir],
        vec![1],
        spec,
        &VerifierLimits::default(),
    )
    .unwrap()
    .1
}
fn limit_options() -> NativeBinaryRecursionOptions {
    let mut options = options(MerkleArity::Two);
    options.max_pcs_codeword_cells = 0;
    options
}
#[test]
fn native_poly_preparation_checks_host_graph_and_codeword_limits() {
    // The layer enables only the child's transcript hash, so a child whose commitments use
    // the other hash cannot have its openings verified.
    for (pcs, transcript, op) in [
        (
            ByteHash::Blake3,
            ByteHash::Keccak256,
            NpoTypeId::native_blake3_compress(),
        ),
        (
            ByteHash::Keccak256,
            ByteHash::Blake3,
            NpoTypeId::native_keccak_f1600(),
        ),
    ] {
        assert!(matches!(
            PreparedNativeBinaryPolyWhirLayer::from_native_authority(
                &authority(pcs, transcript),
                limit_options(),
                &DirectCircuitLimits::default()
            ),
            Err(VerificationError::CircuitBuilder(
                CircuitBuilderError::OpNotAllowed { op: refused }
            )) if refused == op
        ));
    }
    let authority = authority(ByteHash::Keccak256, ByteHash::Keccak256);
    for folding in [
        FoldingFactor::PerRound(vec![]),
        FoldingFactor::Constant(0),
        FoldingFactor::Constant(usize::MAX),
    ] {
        let mut invalid = limit_options();
        invalid.main.folding_factor = folding;
        assert!(matches!(
            PreparedNativeBinaryPolyWhirLayer::from_native_authority(
                &authority,
                invalid,
                &DirectCircuitLimits::default()
            ),
            Err(VerificationError::InvalidProofShape(_))
        ));
    }
    let mut invalid = limit_options();
    invalid.preprocessed.folding_factor = FoldingFactor::Constant(2);
    assert!(matches!(
        PreparedNativeBinaryPolyWhirLayer::from_native_authority(
            &authority,
            invalid,
            &DirectCircuitLimits::default()
        ),
        Err(VerificationError::InvalidProofShape(_))
    ));
    let graph_limits = DirectCircuitLimits {
        max_witnesses: 0,
        ..Default::default()
    };
    assert!(matches!(
        PreparedNativeBinaryPolyWhirLayer::from_native_authority(
            &authority,
            limit_options(),
            &graph_limits
        ),
        Err(VerificationError::NativeBusCircuit(_))
    ));
    let trace_limits = DirectCircuitLimits {
        max_trace_cells: 1 << 27,
        ..Default::default()
    };
    assert!(
        matches!(PreparedNativeBinaryPolyWhirLayer::from_native_authority(&authority, limit_options(), &trace_limits), Err(VerificationError::ResourceLimitExceeded { component: "native recursive PCS codeword cells", limit: 0, actual }) if actual > 0)
    );
}
