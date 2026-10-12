//! A second native Poly64 recursion layer over a first layer whose Keccak table is committed as
//! packed bits, with the second layer's Keccak table committed as packed bits too.
//!
//! The child is a real first-layer proof: its Keccak table opened through the column batch, the
//! bit ring switch and the packed WHIR opening, every other table through a dense WHIR opening,
//! over four-digest Merkle trees under a cap and with grinding. Building the second layer and
//! its witness takes seconds, while proving it takes gigabytes of codewords, so the default test
//! bounds the circuit size and the Keccak-f calls, checks that witness generation refuses a
//! forged packed opened value or a changed child statement, and that proving refuses a token of
//! a foreign child authority. Under BLAKE3, the first layer proves over a BLAKE3 source and the
//! second layer generates its witness over the first layer's proof.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::Poly64;
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::{ByteHash, NpoTypeId};
use p3_circuit::{CircuitBuilder, CircuitConstructionLimits, ExprId, Op};
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::native_bus::{KeccakCommitment, NativeBusCircuit};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::artifact::{
    ArtifactLimits, BinaryNativePolyWhirAuthority, BinaryNativePolyWhirPcsParameters,
    BinaryNativeVerifierSpec, VerifiedBinaryNativePolyMixedWhirProof,
    VerifiedBinaryNativePolyWhirProof,
};
use p3_recursion::pcs::binary::MerkleArity;
use p3_recursion::prepared::{
    NativeBinaryMixedRecursionOptions, NativeBinaryPolyMixedRecursiveProof,
    NativeBinaryRecursionOptions, PreparedNativeBinaryPolyMixedWhirLayer,
};
use p3_recursion::verifier::{
    BinaryPolyMixedWhirMultiStarkInputShape, VerificationError, VerifierLimits,
};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

type F = Poly64;
type H = NativeBinaryEncoding;
/// A layer whose child is itself a mixed proof.
type SecondLayer = PreparedNativeBinaryPolyMixedWhirLayer<BinaryPolyMixedWhirMultiStarkInputShape>;

/// Four-digest output trees under a cap of one level: 4 roots.
const ARITY: MerkleArity = MerkleArity::Four;
const CAP_HEIGHT: usize = 1;
/// Initial fold of every recursive commitment, and so the bus tables' minimum log height.
const FOLD: usize = 4;

/// About 12% above the measured second-layer construction: 738,234 expression nodes, 37,129
/// pending connections, 16,704 non-primitive calls and 771,232 slots.
const CONSTRUCTION: CircuitConstructionLimits = CircuitConstructionLimits {
    max_expression_nodes: 827_000,
    max_pending_connects: 41_600,
    max_non_primitive_calls: 18_800,
    max_non_primitive_slots: 864_000,
};
/// About 12% above the measured 689,761 witnesses and 475,887 operations. The trace cells
/// follow from the table heights below.
const CIRCUIT: DirectCircuitLimits = DirectCircuitLimits {
    max_witnesses: 773_000,
    max_operations: 533_000,
    max_trace_cells: 1 << 27,
};
/// About 12% above the measured 710,891 expression nodes of the child's mixed verifier.
const MAX_VERIFIER_NODES: usize = 797_000;
/// About 8% above the measured 1,464 native Keccak-f calls, and below the 1,591 calls of a
/// second layer over a dense child (`native_poly_second_layer`), so a layer whose child
/// verifier hashed the Keccak table densely fails it.
const MAX_KECCAK_CALLS: usize = 1_580;
/// About 12% above the measured 54,525,952 initial codeword cells.
const MAX_CODEWORD_CELLS: usize = 61_100_000;
/// Measured padded witness, gate, public, Keccak and bridge table heights. One more row of
/// growth at a power-of-two boundary doubles that table.
const MAX_LOG_HEIGHTS: [usize; 5] = [21, 19, 4, 16, 12];

/// Limits of the second BLAKE3 layer, whose size this file does not bound.
const BLAKE3: DirectCircuitLimits = DirectCircuitLimits {
    max_witnesses: 1 << 22,
    max_operations: 1 << 22,
    max_trace_cells: 1 << 28,
};

struct SquaringAir;
impl BaseAir<F> for SquaringAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        2
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![0]
    }
}
impl<AB: AirBuilder<F = F>> Air<AB> for SquaringAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main();
        let current = main.current_slice()[0];
        let next = main.next_slice()[0];
        let initial = b.public_values()[0];
        let expected = b.public_values()[1];
        b.when_first_row().assert_eq(current, initial);
        b.when_transition().assert_eq(next, current * current);
        b.when_last_row().assert_eq(current, expected);
    }
}

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

/// A low WHIR security level that still meets the four-bit composed target, with four of its
/// bits ground, for the dense and the packed commitment alike.
fn options(depth: usize) -> NativeBinaryMixedRecursionOptions {
    let recursive = ProtocolParameters {
        pow_bits: 4,
        folding_factor: FoldingFactor::Constant(FOLD),
        ..protocol()
    };
    NativeBinaryMixedRecursionOptions {
        base: NativeBinaryRecursionOptions {
            main: recursive.clone(),
            preprocessed: recursive.clone(),
            arity: ARITY,
            cap_height: CAP_HEIGHT,
            initial_bytes: format!("native-poly-mixed-layer-{depth}").into_bytes(),
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
        packed: recursive,
    }
}

/// The source statement, authority and checked proof, the first layer's checked mixed proof,
/// and the second layer over the first layer's output authority.
struct Fixture {
    expected: Vec<Vec<F>>,
    authority: BinaryNativePolyWhirAuthority<SquaringAir>,
    source: VerifiedBinaryNativePolyWhirProof,
    first: PreparedNativeBinaryPolyMixedWhirLayer,
    first_proof: NativeBinaryPolyMixedRecursiveProof,
    checked: VerifiedBinaryNativePolyMixedWhirProof,
    second: SecondLayer,
}

/// The squaring source statement, its authority committing and hashing its transcript with
/// `hash`, and its checked proof.
fn source(
    hash: ByteHash,
) -> (
    Vec<Vec<F>>,
    BinaryNativePolyWhirAuthority<SquaringAir>,
    VerifiedBinaryNativePolyWhirProof,
) {
    let input = F::new(0xfedcba9876543210);
    let mut values = vec![input];
    for _ in 0..3 {
        let value = *values.last().unwrap();
        values.push(value * value);
    }
    let expected = vec![vec![input, *values.last().unwrap()]];
    let spec = BinaryNativeVerifierSpec {
        main: BinaryNativePolyWhirPcsParameters::new(2, protocol(), hash, 0).unwrap(),
        preprocessed: None,
        transcript_hash: hash,
        initial_bytes: b"native-poly-mixed-second-layer-source".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    };
    let (prover, authority) = BinaryNativePolyWhirAuthority::<_>::setup(
        vec![SquaringAir],
        vec![2],
        spec,
        &VerifierLimits::default(),
    )
    .unwrap();
    let proof = prover
        .prove(&expected, vec![RowMajorMatrix::new(values, 1)])
        .unwrap();
    let source = authority.verify_native(&proof, &expected).unwrap();
    (expected, authority, source)
}

fn prepare() -> Fixture {
    let (expected, authority, source) = source(ByteHash::Keccak256);
    let first = PreparedNativeBinaryPolyMixedWhirLayer::from_native_authority(
        &authority,
        options(1),
        &DirectCircuitLimits::default(),
    )
    .unwrap();
    let first_proof = first.prove_verified(&source).unwrap();
    let checked = first.verify(&first_proof, &expected).unwrap();
    let second =
        PreparedNativeBinaryPolyMixedWhirLayer::from_mixed_authority_with_construction_limits(
            first.authority(),
            options(2),
            &CIRCUIT,
            &CONSTRUCTION,
        )
        .unwrap();
    Fixture {
        expected,
        authority,
        source,
        first,
        first_proof,
        checked,
        second,
    }
}

#[test]
fn second_poly_mixed_layer_is_bounded_and_refuses_a_forged_child() {
    let Fixture {
        expected,
        authority,
        source,
        first,
        first_proof,
        checked,
        second,
    } = prepare();
    let child = first.authority();
    let verifier = child.recursive_verifier();
    let shape = verifier.input_shape();
    assert_eq!(
        second.child_public_value_counts(),
        shape.public_value_counts().collect::<Vec<_>>()
    );

    // The child verifier rebuilt as the layer builds it: public statement, proof targets,
    // initial transcript, then the native mixed verifier.
    let mut scratch = CircuitBuilder::<F>::new();
    scratch.enable_native_keccak_f1600().unwrap();
    let public: Vec<Vec<_>> = shape
        .public_value_counts()
        .map(|count| (0..count).map(|_| scratch.public_input()).collect())
        .collect();
    let targets = shape.allocate_native_targets(&mut scratch).unwrap();
    let initial: Vec<_> = child
        .initial_bytes()
        .iter()
        .map(|&byte| scratch.define_const(H::encode_u16(u16::from(byte)).unwrap()))
        .collect();
    let challenger = BinaryTower128Challenger::with_initial_bytes_with_host::<H, F>(
        &mut scratch,
        child.transcript_hash(),
        &initial,
    )
    .unwrap();
    let before = scratch.construction_usage().unwrap().expression_nodes;
    verifier
        .verify_native(&mut scratch, challenger, &public, &targets)
        .unwrap();
    let nodes = scratch.construction_usage().unwrap().expression_nodes - before;
    let scratch = scratch.build().unwrap();

    let circuit = second.circuit();
    let keccak_calls = circuit
        .ops
        .iter()
        .filter(|op| {
            matches!(op, Op::NonPrimitiveOpWithExecutor { executor, .. }
                if executor.op_type() == &NpoTypeId::native_keccak_f1600())
        })
        .count();
    // The layer's product-bus relation over its circuit, with the Keccak table as bits.
    let bus =
        NativeBusCircuit::with_options(circuit, "recursion", FOLD, CIRCUIT, KeccakCommitment::Bits)
            .unwrap();
    eprintln!(
        "second Poly64 mixed layer: {nodes} child verifier nodes, {} witnesses, {} operations, \
         {keccak_calls} Keccak-f calls, log heights {:?}, {:?} packed bit variables, {} initial \
         codeword cells",
        circuit.witness_count,
        circuit.ops.len(),
        bus.log_heights(),
        bus.packed_bit_variables(),
        second.initial_codeword_cells(),
    );
    assert_eq!(scratch.witness_count, circuit.witness_count);
    assert!(nodes <= MAX_VERIFIER_NODES);
    assert!(keccak_calls <= MAX_KECCAK_CALLS);
    assert!(second.initial_codeword_cells() <= MAX_CODEWORD_CELLS);
    assert_eq!(bus.log_heights().len(), MAX_LOG_HEIGHTS.len());
    assert!(
        bus.log_heights()
            .iter()
            .zip(MAX_LOG_HEIGHTS)
            .all(|(&height, max)| height <= max)
    );

    // The verifier allocates its private inputs only through the child input shape and in this
    // order, so the scratch circuit locates proof fields in the layer circuit.
    let position = |expr: ExprId| {
        let id = scratch.expr_to_widx[&expr];
        scratch
            .private_input_rows
            .iter()
            .position(|&row| row == id)
            .unwrap()
    };
    let statement: Vec<F> = checked.public_values().iter().flatten().copied().collect();
    // The first layer's public table carries the source statement unchanged.
    assert_eq!(statement, expected.concat());
    let private = checked
        .native_input()
        .private_native_values(&shape)
        .unwrap();
    assert_eq!(scratch.private_input_rows.len(), private.len());
    assert_eq!(circuit.private_input_rows.len(), private.len());
    let run = |statement: &[F], private: &[F]| {
        let mut runner = circuit.runner();
        runner.set_public_inputs(statement).unwrap();
        runner.set_private_inputs(private).unwrap();
        runner.run().map(|traces| traces.witness_trace)
    };
    let witness = run(&statement, &private).unwrap();
    assert_eq!(witness.num_rows(), circuit.witness_count as usize);
    let mut wrong = statement.clone();
    wrong[1] += F::ONE;
    assert!(run(&wrong, &private).is_err());

    // Every coefficient of the bit-committed Keccak table's first opened value, as the child
    // proof carries it.
    let packed = &first_proof.opening.packed.as_ref().unwrap().values;
    for (opened, value) in targets.packed.values[0]
        .coefficients()
        .iter()
        .zip(packed[0].coefficients())
    {
        let opened = position(*opened);
        assert_eq!(private[opened], value);
        let mut forged = private.clone();
        forged[opened] += F::ONE;
        assert!(run(&statement, &forged).is_err());
    }

    // The same source proof through a first layer that differs only in its initial transcript
    // bytes: a checked mixed token of the child's shape and statement, under a foreign child
    // authority.
    let mut foreign_options = options(1);
    foreign_options.base.initial_bytes.push(0);
    let foreign_first = PreparedNativeBinaryPolyMixedWhirLayer::from_native_authority(
        &authority,
        foreign_options,
        &DirectCircuitLimits::default(),
    )
    .unwrap();
    let foreign = foreign_first
        .verify(&foreign_first.prove_verified(&source).unwrap(), &expected)
        .unwrap();
    assert_eq!(foreign.public_values(), checked.public_values());
    assert!(matches!(
        second.prove_verified(&foreign),
        Err(VerificationError::PreparedInputMismatch { .. })
    ));
}

#[test]
#[ignore = "proves a second native layer over a packed-Keccak child; run explicitly"]
fn second_poly_mixed_layer_proves_and_binds_the_original_statement() {
    let Fixture {
        expected,
        first,
        checked,
        second,
        ..
    } = prepare();
    let outer = second.prove_verified(&checked).unwrap();
    assert!(outer.opening.packed.is_some());
    let child_statement = first.output_public_values(&expected).unwrap();
    let token = second.verify(&outer, &child_statement).unwrap();
    assert_eq!(
        token.public_values(),
        second
            .output_public_values(&child_statement)
            .unwrap()
            .as_slice()
    );
    // Only the first layer's public table carries its statement.
    let mut wrong = child_statement;
    let values = wrong.iter_mut().find(|values| !values.is_empty()).unwrap();
    values[0] += F::ONE;
    assert!(second.verify(&outer, &wrong).is_err());
}

/// Under BLAKE3 the source and both layers commit and hash their transcripts with BLAKE3, and
/// each layer commits its BLAKE3 table as packed bits. The first layer proves and verifies. The
/// second layer, over the first layer's packed-BLAKE3 output, runs native BLAKE3 compressions
/// only, and its witness generation accepts the first layer's proof under the original
/// statement but not under a changed one.
#[test]
fn blake3_poly_mixed_layers_commit_their_blake3_tables_as_packed_bits() {
    let (expected, authority, source) = source(ByteHash::Blake3);
    let first = PreparedNativeBinaryPolyMixedWhirLayer::from_native_authority(
        &authority,
        options(1),
        &DirectCircuitLimits::default(),
    )
    .unwrap();
    let first_proof = first.prove_verified(&source).unwrap();
    assert!(first_proof.opening.packed.is_some());
    let checked = first.verify(&first_proof, &expected).unwrap();
    let child = first.authority();
    assert_eq!(child.transcript_hash(), ByteHash::Blake3);
    let second =
        PreparedNativeBinaryPolyMixedWhirLayer::from_mixed_authority(child, options(2), &BLAKE3)
            .unwrap();
    assert_eq!(second.authority().transcript_hash(), ByteHash::Blake3);

    let circuit = second.circuit();
    let calls = |op: NpoTypeId| {
        circuit
            .ops
            .iter()
            .filter(|call| {
                matches!(call, Op::NonPrimitiveOpWithExecutor { executor, .. }
                    if executor.op_type() == &op)
            })
            .count()
    };
    assert!(calls(NpoTypeId::native_blake3_compress()) > 0);
    assert_eq!(calls(NpoTypeId::native_keccak_f1600()), 0);
    let statement: Vec<F> = checked.public_values().iter().flatten().copied().collect();
    assert_eq!(statement, expected.concat());
    let private = checked
        .native_input()
        .private_native_values(&child.recursive_verifier().input_shape())
        .unwrap();
    let run = |statement: &[F]| {
        let mut runner = circuit.runner();
        runner.set_public_inputs(statement).unwrap();
        runner.set_private_inputs(&private).unwrap();
        runner.run().map(|traces| traces.witness_trace)
    };
    let witness = run(&statement).unwrap();
    assert_eq!(witness.num_rows(), circuit.witness_count as usize);
    let mut wrong = statement;
    wrong[1] += F::ONE;
    assert!(run(&wrong).is_err());
}
