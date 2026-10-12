//! A second native Tower128 recursion layer over a first layer whose BLAKE3 table is committed
//! as packed bits, with the second layer's BLAKE3 table committed as packed bits too.
//!
//! The source proof commits and hashes its transcript with BLAKE3, and every layer takes its
//! child's hash: the first layer's verifier circuit runs native BLAKE3 compressions, and its
//! output commits its tables and hashes its transcript with BLAKE3. The child of the second
//! layer is a real first-layer proof: its BLAKE3 table opened through the column batch, the bit
//! ring switch and the packed WHIR opening, every other table through a dense WHIR opening,
//! over pairwise Merkle trees under a cap and with grinding. The default test bounds the
//! circuit size, checks that witness generation refuses a forged packed opened value, a forged
//! cap limb or a changed child statement, and that proving refuses a token of a foreign child
//! authority.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::{ByteHash, NpoTypeId};
use p3_circuit::{CircuitBuilder, CircuitConstructionLimits, CircuitError, ExprId, Op};
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::native_bus::{KeccakCommitment, NativeBusCircuit};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::artifact::{
    ArtifactLimits, BinaryNativeVerifierSpec, BinaryNativeWhirAuthority,
    BinaryNativeWhirPcsParameters, VerifiedBinaryNativeMixedWhirProof,
    VerifiedBinaryNativeWhirProof,
};
use p3_recursion::pcs::binary::MerkleArity;
use p3_recursion::prepared::{
    NativeBinaryMixedRecursionOptions, NativeBinaryMixedRecursiveProof,
    NativeBinaryRecursionOptions, PreparedNativeBinaryMixedWhirLayer,
};
use p3_recursion::verifier::{
    BinaryMixedWhirMultiStarkInputShape, VerificationError, VerifierLimits,
};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

type F = BinaryField128;
type H = NativeBinaryEncoding;
/// A layer whose child is itself a mixed proof.
type SecondLayer = PreparedNativeBinaryMixedWhirLayer<F, BinaryMixedWhirMultiStarkInputShape>;

/// Pairwise output trees under a cap of two levels: 4 roots.
const ARITY: MerkleArity = MerkleArity::Two;
const CAP_HEIGHT: usize = 2;
/// Initial fold of every recursive commitment, and so the bus tables' minimum log height.
const FOLD: usize = 4;

/// About 12% above the measured second-layer construction: 504,458 expression nodes, 32,852
/// pending connections, 17,474 non-primitive calls and 879,998 slots.
const CONSTRUCTION: CircuitConstructionLimits = CircuitConstructionLimits {
    max_expression_nodes: 565_000,
    max_pending_connects: 36_800,
    max_non_primitive_calls: 19_600,
    max_non_primitive_slots: 982_000,
};
/// About 12% above the measured 455,504 witnesses and 289,681 operations. The trace cells
/// follow from the table heights below.
const CIRCUIT: DirectCircuitLimits = DirectCircuitLimits {
    max_witnesses: 511_000,
    max_operations: 324_500,
    max_trace_cells: 1 << 27,
};
/// About 12% above the measured 484,029 expression nodes of the child's mixed verifier.
const MAX_VERIFIER_NODES: usize = 543_000;
/// About 12% above the measured 4,187 native BLAKE3 compressions.
const MAX_COMPRESSIONS: usize = 4_700;
/// Measured padded witness, gate, public and BLAKE3 table heights: the fanout and gate rows
/// fit 2^20 and 2^18 rows, and the compressions 2^13. One more row of growth at a
/// power-of-two boundary doubles that table.
const MAX_LOG_HEIGHTS: [usize; 4] = [20, 18, 4, 13];
/// Measured variables of the packed BLAKE3 table: 14 column and 13 row variables.
const MAX_PACKED_BIT_VARIABLES: usize = 27;
/// Measured initial codeword cells: 2^23 main, 2^25 preprocessing and 2^21 packed cells.
const MAX_CODEWORD_CELLS: usize = 44_040_192;

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
/// bits ground, for the dense and the packed commitment alike. The codeword budget covers the
/// second layer's initial cells, and a BLAKE3 table AIR needs more metadata entries than the
/// default verifier limits allow.
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
            initial_bytes: format!("native-binary-mixed-blake3-layer-{depth}").into_bytes(),
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
    authority: BinaryNativeWhirAuthority<F, SquaringAir>,
    source: VerifiedBinaryNativeWhirProof<F>,
    first: PreparedNativeBinaryMixedWhirLayer,
    first_proof: NativeBinaryMixedRecursiveProof,
    checked: VerifiedBinaryNativeMixedWhirProof,
    second: SecondLayer,
}

fn prepare() -> Fixture {
    let input = F::from_repr(0xfedcba98765432108123456789abcdef);
    let mut values = vec![input];
    for _ in 0..3 {
        let value = *values.last().unwrap();
        values.push(value * value);
    }
    let expected = vec![vec![input, *values.last().unwrap()]];
    let spec = BinaryNativeVerifierSpec {
        main: BinaryNativeWhirPcsParameters::<F>::new(2, protocol(), ByteHash::Blake3, 0).unwrap(),
        preprocessed: None,
        transcript_hash: ByteHash::Blake3,
        initial_bytes: b"native-binary-mixed-blake3-second-layer-source".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    };
    let (prover, authority) = BinaryNativeWhirAuthority::<F, _>::setup(
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
    let first =
        PreparedNativeBinaryMixedWhirLayer::from_native_authority(&authority, options(1), &CIRCUIT)
            .unwrap();
    let first_proof = first.prove_verified(&source).unwrap();
    let checked = first.verify(&first_proof, &expected).unwrap();
    let second = PreparedNativeBinaryMixedWhirLayer::from_mixed_authority_with_construction_limits(
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
fn second_blake3_mixed_layer_is_bounded_and_refuses_a_forged_child() {
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
    assert_eq!(child.transcript_hash(), ByteHash::Blake3);
    assert_eq!(second.authority().transcript_hash(), ByteHash::Blake3);
    let verifier = child.recursive_verifier();
    let shape = verifier.input_shape();
    assert_eq!(
        second.child_public_value_counts(),
        shape.public_value_counts().collect::<Vec<_>>()
    );

    // The child verifier rebuilt as the layer builds it: public statement, proof targets,
    // initial transcript, then the native mixed verifier.
    let mut scratch = CircuitBuilder::<F>::new();
    scratch.enable_native_blake3_compress().unwrap();
    let public: Vec<Vec<_>> = shape
        .public_value_counts()
        .map(|count| {
            (0..count)
                .map(|_| {
                    let value = scratch.public_input();
                    scratch.native_tower128_from_expr(value)
                })
                .collect()
        })
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
    let compressions = calls(NpoTypeId::native_blake3_compress());
    assert_eq!(calls(NpoTypeId::native_keccak_f1600()), 0);
    // The layer's product-bus relation over its circuit, with the BLAKE3 table as bits.
    let bus =
        NativeBusCircuit::with_options(circuit, "recursion", FOLD, CIRCUIT, KeccakCommitment::Bits)
            .unwrap();
    eprintln!(
        "second BLAKE3 mixed layer: {nodes} child verifier nodes, {} witnesses, {} operations, \
         {compressions} BLAKE3 compressions, log heights {:?}, {:?} packed bit variables, {} \
         initial codeword cells",
        circuit.witness_count,
        circuit.ops.len(),
        bus.log_heights(),
        bus.packed_bit_variables(),
        second.initial_codeword_cells(),
    );
    assert_eq!(scratch.witness_count, circuit.witness_count);
    assert!(nodes <= MAX_VERIFIER_NODES);
    assert!(compressions <= MAX_COMPRESSIONS);
    assert_eq!(bus.log_heights().len(), MAX_LOG_HEIGHTS.len());
    assert!(
        bus.log_heights()
            .iter()
            .zip(MAX_LOG_HEIGHTS)
            .all(|(&height, max)| height <= max)
    );
    assert!(bus.packed_bit_variables().unwrap() <= MAX_PACKED_BIT_VARIABLES);
    assert!(second.initial_codeword_cells() <= MAX_CODEWORD_CELLS);

    // The verifier allocates its private inputs only through the child input shape and in
    // this order, so the scratch circuit locates proof fields in the layer circuit.
    let position = |expr: ExprId| {
        let id = scratch.expr_to_widx[&expr];
        scratch
            .private_input_rows
            .iter()
            .position(|&row| row == id)
            .unwrap()
    };
    let statement: Vec<F> = checked.public_values().iter().flatten().copied().collect();
    // The first layer's public table carries the source statement unchanged: the squaring's
    // input, then its output.
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

    // The first opened value of the bit-committed BLAKE3 table, as the child proof carries it.
    let packed = &first_proof.opening.packed.as_ref().unwrap().values;
    let opened = position(targets.packed.values[0].as_expr());
    assert_eq!(private[opened], packed[0]);
    let mut forged = private.clone();
    forged[opened] += F::ONE;
    assert!(run(&statement, &forged).is_err());

    let forge = |expr: ExprId, delta: F| {
        let mut forged = private.clone();
        forged[position(expr)] += delta;
        run(&statement, &forged)
    };
    // A cap limb reaches the transcript as a word, and a flipped limb changes the draws. In the
    // child's commitment cap and in its dense opening's first WHIR round cap alike, the next
    // refill absorbs it as a block word of a native BLAKE3 compression, which refuses a
    // seventeenth coordinate; in a proof, the BLAKE3 AIR rejects it.
    let wide = F::from_raw_coordinates(1 << 16).unwrap();
    for limb in [targets.commitment[0][5], targets.dense.rounds[0].cap[0][5]] {
        assert!(private[position(limb)].to_raw_coordinates() < 1 << 16);
        assert!(forge(limb, F::ONE).is_err());
        assert!(matches!(
            forge(limb, wide),
            Err(CircuitError::InvalidNonPrimitiveOpInput { op, .. })
                if op == NpoTypeId::native_blake3_compress()
        ));
    }

    // The same source proof through a first layer that differs only in its initial transcript
    // bytes: a checked mixed token of the child's shape and statement, under a foreign child
    // authority.
    let mut foreign_options = options(1);
    foreign_options.base.initial_bytes.push(0);
    let foreign_first = PreparedNativeBinaryMixedWhirLayer::from_native_authority(
        &authority,
        foreign_options,
        &CIRCUIT,
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
#[ignore = "proves a second native layer over a packed-BLAKE3 child; run explicitly"]
fn second_blake3_mixed_layer_proves_and_binds_the_original_statement() {
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
