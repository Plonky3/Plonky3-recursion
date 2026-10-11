//! A second native Tower128 recursion layer over a first layer whose Keccak table is committed
//! as packed bits, with the second layer's Keccak table committed as packed bits too.
//!
//! The child is a real first-layer proof: its Keccak table opened through the column batch,
//! the bit ring switch and the packed WHIR opening, every other table through a dense WHIR
//! opening, under a Merkle cap and with grinding. Building the second layer and its witness
//! takes seconds, while proving it takes gigabytes of codewords, so the default test bounds the
//! circuit size and checks that witness generation refuses a forged packed opened value.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::{ByteHash, NpoTypeId};
use p3_circuit::{CircuitBuilder, CircuitConstructionLimits, ExprId, Op};
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::native_bus::{KeccakCommitment, NativeBusCircuit};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::artifact::{
    ArtifactLimits, BinaryNativeVerifierSpec, BinaryNativeWhirAuthority,
    BinaryNativeWhirPcsParameters, VerifiedBinaryNativeMixedWhirProof,
};
use p3_recursion::prepared::{
    NativeBinaryMixedRecursionOptions, NativeBinaryMixedRecursiveProof,
    NativeBinaryRecursionOptions, PreparedNativeBinaryMixedWhirLayer,
};
use p3_recursion::verifier::{BinaryMixedWhirMultiStarkInputShape, VerifierLimits};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

type F = BinaryField128;
type H = NativeBinaryEncoding;
/// A layer whose child is itself a mixed proof.
type SecondLayer = PreparedNativeBinaryMixedWhirLayer<F, BinaryMixedWhirMultiStarkInputShape>;

const CAP_HEIGHT: usize = 2;
/// Initial fold of every recursive commitment, and so the bus tables' minimum log height.
const FOLD: usize = 4;

/// About 12% above the measured second-layer construction: 904,649 expression nodes, 275,357
/// pending connections, 11,499 non-primitive calls and 978,522 slots.
const CONSTRUCTION: CircuitConstructionLimits = CircuitConstructionLimits {
    max_expression_nodes: 1_014_000,
    max_pending_connects: 309_000,
    max_non_primitive_calls: 12_900,
    max_non_primitive_slots: 1_096_000,
};
/// About 12% above the measured 763,323 witnesses and 555,809 operations. The trace cells
/// follow from the table heights below.
const CIRCUIT: DirectCircuitLimits = DirectCircuitLimits {
    max_witnesses: 855_000,
    max_operations: 623_000,
    max_trace_cells: 1 << 27,
};
/// About 12% above the measured 890,554 expression nodes of the child's mixed verifier.
const MAX_VERIFIER_NODES: usize = 998_000;
/// About 12% above the measured 1,598 native Keccak-f calls.
const MAX_KECCAK_CALLS: usize = 1_790;
/// Measured padded witness, gate, public, Keccak and bridge table heights. One more row of
/// growth at a power-of-two boundary doubles that table.
const MAX_LOG_HEIGHTS: [usize; 5] = [22, 20, 4, 16, 12];

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
/// second layer's measured 102,760,448 initial cells.
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
            cap_height: CAP_HEIGHT,
            initial_bytes: format!("native-binary-mixed-layer-{depth}").into_bytes(),
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

/// The source statement, the first layer's checked mixed proof, and the second layer over the
/// first layer's output authority.
struct Fixture {
    expected: Vec<Vec<F>>,
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
        main: BinaryNativeWhirPcsParameters::<F>::new(2, protocol(), ByteHash::Keccak256, 0)
            .unwrap(),
        preprocessed: None,
        transcript_hash: ByteHash::Keccak256,
        initial_bytes: b"native-binary-mixed-second-layer-source".to_vec(),
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
    let first = PreparedNativeBinaryMixedWhirLayer::from_native_authority(
        &authority,
        options(1),
        &DirectCircuitLimits::default(),
    )
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
        first,
        first_proof,
        checked,
        second,
    }
}

#[test]
fn second_mixed_layer_is_bounded_and_refuses_a_forged_packed_value() {
    let Fixture {
        first,
        first_proof,
        checked,
        second,
        ..
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
        "second mixed layer: {nodes} child verifier nodes, {} witnesses, {} operations, \
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
    assert_eq!(bus.log_heights().len(), MAX_LOG_HEIGHTS.len());
    assert!(
        bus.log_heights()
            .iter()
            .zip(MAX_LOG_HEIGHTS)
            .all(|(&height, max)| height <= max)
    );

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
    let private = checked
        .native_input()
        .private_native_values(&shape)
        .unwrap();
    assert_eq!(scratch.private_input_rows.len(), private.len());
    assert_eq!(circuit.private_input_rows.len(), private.len());
    let run = |private: &[F]| {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&statement).unwrap();
        runner.set_private_inputs(private).unwrap();
        runner.run().map(|traces| traces.witness_trace)
    };
    let witness = run(&private).unwrap();
    assert_eq!(witness.num_rows(), circuit.witness_count as usize);

    // The first opened value of the bit-committed Keccak table, as the child proof carries it.
    let packed = &first_proof.opening.packed.as_ref().unwrap().values;
    let opened = position(targets.packed.values[0].as_expr());
    assert_eq!(private[opened], packed[0]);
    let mut forged = private;
    forged[opened] += F::ONE;
    assert!(run(&forged).is_err());
}

#[test]
#[ignore = "proves a second native layer over a packed-Keccak child; run explicitly"]
fn second_mixed_layer_proves_and_binds_the_original_statement() {
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
