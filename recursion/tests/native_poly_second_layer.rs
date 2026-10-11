//! A second native Poly64 recursion layer, built and run without proving.
//!
//! Its child is a real first-layer proof: a five-table product-bus circuit with
//! the 1,625-column native Keccak table, opened by a multi-round Poly64 WHIR
//! proof under a Merkle cap and with grinding. Building the verifier and its
//! witness takes seconds, while proving it takes gigabytes of codewords, so
//! this bounds the circuit size and checks that witness generation refuses
//! forged proof fields.

use std::collections::HashMap;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::Poly64;
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::{ByteHash, KECCAK256_RATE_BYTES, NpoTypeId};
use p3_circuit::{CircuitBuilder, CircuitConstructionLimits, CircuitError, ExprId, Op, WitnessId};
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::NUM_KECCAK_BINARY_COLS;
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::artifact::{
    ArtifactLimits, BinaryNativePolyWhirAuthority, BinaryNativePolyWhirPcsParameters,
    BinaryNativeVerifierSpec,
};
use p3_recursion::prepared::{NativeBinaryRecursionOptions, PreparedNativeBinaryPolyWhirLayer};
use p3_recursion::verifier::{VerificationError, VerifierLimits};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

type F = Poly64;

const CAP_HEIGHT: usize = 2;

/// About 12% above the measured second-layer verifier: 1,425,015 expression
/// nodes, 55,058 pending connections, 15,918 non-primitive calls and 907,116
/// slots.
const CONSTRUCTION: CircuitConstructionLimits = CircuitConstructionLimits {
    max_expression_nodes: 1_597_000,
    max_pending_connects: 61_700,
    max_non_primitive_calls: 17_830,
    max_non_primitive_slots: 1_016_000,
};
/// About 12% above the measured 1,376,727 witnesses and 1,124,034 operations.
/// The trace cells follow from the table heights below.
const CIRCUIT: DirectCircuitLimits = DirectCircuitLimits {
    max_witnesses: 1_542_000,
    max_operations: 1_259_000,
    max_trace_cells: 1 << 28,
};
/// About 12% above the measured 1,844 native Keccak-f calls.
const MAX_KECCAK_CALLS: usize = 2_070;
/// About 12% above the measured 53 calls of the first transcript refill,
/// whose 148 constant leading blocks take none.
const MAX_FIRST_REFILL_CALLS: usize = 60;
/// Measured padded witness, gate, public, Keccak and bridge table heights.
/// One more row of growth at a power-of-two boundary doubles that table.
const MAX_LOG_HEIGHTS: [usize; 5] = [22, 21, 4, 16, 12];

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

/// A low WHIR security level that still meets the four-bit composed target,
/// with four of its bits ground.
fn options() -> NativeBinaryRecursionOptions {
    let recursive = ProtocolParameters {
        pow_bits: 4,
        folding_factor: FoldingFactor::Constant(4),
        ..protocol()
    };
    NativeBinaryRecursionOptions {
        main: recursive.clone(),
        preprocessed: recursive,
        cap_height: CAP_HEIGHT,
        initial_bytes: b"native-poly-second-layer-test".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 32,
        security_bits: 4,
        max_pcs_codeword_cells: 1 << 24,
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
fn second_native_poly_layer_verifier_is_bounded_and_refuses_forged_proof_fields() {
    let input = F::new(0xfedcba9876543210);
    let mut values = vec![input];
    for _ in 0..3 {
        let value = *values.last().unwrap();
        values.push(value * value);
    }
    let expected = vec![vec![input, *values.last().unwrap()]];
    let spec = BinaryNativeVerifierSpec {
        main: BinaryNativePolyWhirPcsParameters::new(2, protocol(), ByteHash::Keccak256, 0)
            .unwrap(),
        preprocessed: None,
        transcript_hash: ByteHash::Keccak256,
        initial_bytes: b"native-poly-second-layer-source".to_vec(),
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
    let first = PreparedNativeBinaryPolyWhirLayer::from_native_authority(
        &authority,
        options(),
        &DirectCircuitLimits::default(),
    )
    .unwrap();
    let proof = first.prove_verified(&source).unwrap();
    let checked = first.verify(&proof, &expected).unwrap();
    let child = first.authority();
    let shape = child.recursive_verifier().input_shape();
    assert_eq!(shape.public_value_counts().len(), 5);

    let (circuit, bus) = PreparedNativeBinaryPolyWhirLayer::verifier_circuit(
        child,
        &options(),
        &CIRCUIT,
        Some(&CONSTRUCTION),
    )
    .unwrap();
    let calls: Vec<_> = circuit
        .ops
        .iter()
        .filter_map(|op| match op {
            Op::NonPrimitiveOpWithExecutor {
                executor,
                inputs,
                outputs,
                ..
            } if executor.op_type() == &NpoTypeId::native_keccak_f1600() => {
                Some((&inputs[0], &outputs[0]))
            }
            _ => None,
        })
        .collect();
    let keccak_calls = calls.len();
    eprintln!(
        "second native Poly64 layer: {} witnesses, {} operations, {keccak_calls} Keccak-f calls, log heights {:?}",
        circuit.witness_count,
        circuit.ops.len(),
        bus.log_heights()
    );
    assert!(keccak_calls <= MAX_KECCAK_CALLS);
    // The first transcript refill starts from the sponge state of its constant
    // leading blocks, held as constant capacity limbs, and each of its later
    // calls continues from the previous call's capacity output.
    let constants: HashMap<WitnessId, F> = circuit
        .ops
        .iter()
        .filter_map(|op| match *op {
            Op::Const { out, val } => Some((out, val)),
            _ => None,
        })
        .collect();
    let capacity = KECCAK256_RATE_BYTES / 2;
    let start = &calls[0].0[capacity..];
    assert!(start.iter().all(|id| constants.contains_key(id)));
    assert!(start.iter().any(|id| constants[id] != F::ZERO));
    let refill = 1 + calls
        .windows(2)
        .take_while(|pair| pair[1].0[capacity..] == pair[0].1[capacity..])
        .count();
    assert!(refill <= MAX_FIRST_REFILL_CALLS);
    assert_eq!(bus.log_heights().len(), MAX_LOG_HEIGHTS.len());
    assert!(
        bus.log_heights()
            .iter()
            .zip(MAX_LOG_HEIGHTS)
            .all(|(&height, max)| height <= max)
    );
    // Building the circuit refuses a nonzero draw budget below the tallest
    // table's log height, as preparation does.
    let required_draws = *bus.log_heights().iter().max().unwrap();
    let short = NativeBinaryRecursionOptions {
        max_tau_draws: required_draws - 1,
        ..options()
    };
    let refused = PreparedNativeBinaryPolyWhirLayer::verifier_circuit(
        child,
        &short,
        &CIRCUIT,
        Some(&CONSTRUCTION),
    );
    assert!(matches!(
        refused,
        Err(VerificationError::InvalidProofShape(message)) if message.contains("draw budget")
    ));

    // The verifier allocates its private inputs only through the child input
    // shape and in this order, so a scratch allocation locates proof fields.
    let mut scratch = CircuitBuilder::<F>::new();
    let targets = shape.allocate_native_targets(&mut scratch).unwrap();
    let scratch = scratch.build().unwrap();
    let position = |expr: ExprId| {
        let id = scratch.expr_to_widx[&expr];
        scratch
            .private_input_rows
            .iter()
            .position(|&row| row == id)
            .unwrap()
    };
    let keccak = targets
        .opening
        .evals
        .iter()
        .position(|batch| batch.current().len() == NUM_KECCAK_BINARY_COLS)
        .expect("the native Keccak table is opened");
    assert!(targets.opening.rounds.len() > 1);
    assert_eq!(targets.commitment.len(), 1 << CAP_HEIGHT);

    let public: Vec<F> = checked.public_values().iter().flatten().copied().collect();
    let private = checked
        .native_input()
        .private_native_values(&shape)
        .unwrap();
    assert_eq!(scratch.private_input_rows.len(), private.len());
    assert_eq!(circuit.private_input_rows.len(), private.len());
    let run = |private: &[F]| {
        let mut runner = circuit.runner();
        runner.set_public_inputs(&public).unwrap();
        runner.set_private_inputs(private).unwrap();
        runner.run().map(|traces| traces.witness_trace)
    };
    let witness = run(&private).unwrap();
    assert_eq!(witness.num_rows(), circuit.witness_count as usize);
    let forge = |expr: ExprId, delta: F| {
        let mut forged = private.clone();
        forged[position(expr)] += delta;
        run(&forged)
    };

    // A sibling word with a seventeenth coordinate reaches a native Keccak
    // lane, in the initial commitment and in the last folded oracle alike. The
    // runner refuses such a lane; in a proof, the Keccak AIR rejects it.
    let wide = F::from_raw_coordinates(1 << 16).unwrap();
    let initial = &targets.opening.rounds[0].paths[0];
    let last = targets.opening.final_paths[0]
        .last()
        .expect("the final oracle has a Merkle path below its cap");
    for sibling in [initial[0][3], last[12]] {
        assert!(private[position(sibling)].to_raw_coordinates() < 1 << 16);
        assert!(matches!(
            forge(sibling, wide),
            Err(CircuitError::InvalidNonPrimitiveOpInput { op, .. })
                if op == NpoTypeId::native_keccak_f1600()
        ));
    }
    // An opened Keccak column coefficient changes the transcript and the
    // claims, and a leaf value changes its committed row's digest.
    for opened in targets.opening.evals[keccak].current()[0].coefficients() {
        assert!(forge(*opened, F::ONE).is_err());
    }
    let leaf = targets.opening.rounds[0].rows[0][0].coefficients()[0];
    assert!(forge(leaf, F::new(1 << 40)).is_err());
    // Each WHIR round of both openings grinds two to four bits here. A witness
    // for zero bits is constrained to zero, so a nonzero one shows grinding.
    // Changing any witness fails its own check or moves the later queries.
    let pow: Vec<_> = [
        Some(&targets.opening),
        targets.preprocessed_opening.as_ref(),
    ]
    .into_iter()
    .flatten()
    .flat_map(|opening| {
        opening
            .rounds
            .iter()
            .map(|round| round.pow_witness)
            .chain([opening.final_pow_witness])
    })
    .collect();
    assert!(
        pow.iter()
            .any(|&witness| private[position(witness)] != F::ZERO)
    );
    for witness in pow {
        assert!(forge(witness, F::ONE).is_err());
    }
}
