//! Fiat-Shamir binding tests for the extension-field ([`CircuitChallenger`] `D >= 2`) sponge.
//!
//! The in-circuit challenger keeps its sponge state as `WIDTH` base-field coefficient
//! targets. Each duplex step packs those coefficients into `WIDTH / D` extension limbs,
//! runs one Poseidon2 permutation, and unpacks the result back into coefficients. For the
//! transcript to bind, the limbs the permutation of step `k + 1` reads must be the limbs
//! the permutation of step `k` produced, as seen by the verifier — i.e. tied together on
//! the `WitnessChecks` bus, not merely equal in an honestly generated witness.
//!
//! A permutation limb is verifier-bound either when some table *creates* it on the bus with
//! the permutation's own value, or when an AIR constraint ties it to the permutation's output
//! column directly. `add_poseidon2_perm_for_challenger` requests `out_ctl = [true; rate_ext]`,
//! so only the rate limbs are created on the bus; the capacity limbs are bound instead by the
//! challenger table's sponge chain constraint, which holds regardless of which row writes the
//! witness they are fed from.
//!
//! These tests build the transcript circuit with the real [`CircuitChallenger`], then edit
//! the compiled [`Circuit`] in ways that leave `generate_preprocessed_columns` byte-identical
//! (asserted in every test) and only change prover-side data: the hint executor behind
//! `decompose_ext_to_base_coeffs`, the witness slots a permutation writes for limbs it does
//! not publish on the bus, and the witness slots a `recompose` row reads. Every such edit is
//! a choice a prover assembling trace polynomials directly would be free to make. The
//! resulting traces are then proved against the *unedited* circuit's prover data and
//! verified, so acceptance means the verifier's constraint system does not bind the limb.
//!
//! `control_corrupted_const_value_is_rejected` pins down that this harness is a real
//! oracle: the same pipeline rejects a value the bus does bind.

use std::panic::AssertUnwindSafe;

use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    HintExecutor, Op, Poseidon2Config, generate_poseidon2_trace, generate_recompose_trace,
};
use p3_circuit::tables::Traces;
use p3_circuit::{Circuit, CircuitBuilder, CircuitError, WitnessId};
use p3_circuit_prover::batch_stark_prover::{
    poseidon2_air_builders_for_configs, recompose_air_builders,
};
use p3_circuit_prover::common::{NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::config::KoalaBearConfig;
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, Poseidon2Preprocessor,
    RecomposePreprocessor, TablePacking, config,
};
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::BinomialExtensionField;
use p3_koala_bear::{KoalaBear, default_koalabear_poseidon2_16};
use p3_poseidon2_circuit_air::KoalaBearD4Width16;
use p3_recursion::challenger::CircuitChallenger;
use p3_recursion::traits::RecursiveChallenger;

type F = KoalaBear;
type EF = BinomialExtensionField<F, 4>;

const D: usize = 4;
const WIDTH: usize = 16;
const RATE: usize = 8;
const CFG: Poseidon2Config = Poseidon2Config::KOALA_BEAR_D4_W16;
const RATE_EXT: usize = RATE / D;
const WIDTH_EXT: usize = WIDTH / D;
/// First capacity limb: the lowest limb index the challenger permutation leaves off the bus.
const CAPACITY_LIMB: usize = RATE_EXT;
/// Width of the query index the transcript is asked for.
const QUERY_INDEX_BITS: usize = 8;

/// How `recompose_base_coeffs_to_ext` is lowered: through the dedicated recompose table,
/// or through the ALU `mul_add` chain.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecomposeMode {
    NpoTable,
    AluChain,
}

/// Absorb `RATE` values, then squeeze past the output buffer so a second duplex step runs.
fn build_transcript_circuit(mode: RecomposeMode) -> Circuit<EF> {
    build_transcript_circuit_observing(mode, 1)
}

/// As [`build_transcript_circuit`], with the observed values counting up from `first`.
/// Shifting them keeps the sponge length tag clear of every observed constant, which
/// constant pooling would otherwise fold onto a single witness.
fn build_transcript_circuit_observing(mode: RecomposeMode, first: u64) -> Circuit<EF> {
    let perm = default_koalabear_poseidon2_16();
    let mut circuit = CircuitBuilder::<EF>::new();
    circuit.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
        generate_poseidon2_trace::<EF, KoalaBearD4Width16>,
        perm,
    );
    match mode {
        RecomposeMode::NpoTable => {
            circuit.enable_recompose::<F>(generate_recompose_trace::<F, EF>);
        }
        RecomposeMode::AluChain => {
            circuit.noop_enable_recompose::<F>(generate_recompose_trace::<F, EF>);
        }
    }

    let mut challenger = CircuitChallenger::<WIDTH, RATE, Poseidon2Config>::new_koalabear();
    for i in 0..RATE {
        let t = circuit.define_const(EF::from_u64(first + i as u64));
        RecursiveChallenger::<F, EF>::observe(&mut challenger, &mut circuit, t);
    }
    // `RATE` samples drain the output buffer; the next one forces a second permutation.
    for _ in 0..=RATE {
        let _ = RecursiveChallenger::<F, EF>::sample(&mut challenger, &mut circuit);
    }

    circuit.build().expect("transcript circuit builds")
}

/// Absorb `RATE` public inputs, then `RATE` more so a second permutation absorbs them, then
/// draw the bits a FRI query index would be read from.
///
/// The observed values are public inputs rather than constants so the limbs the second
/// permutation reads are genuinely repacked: an all-`Const` coefficient group folds back into a
/// single `Const` and never reaches a packing row at all.
fn build_absorbing_transcript_circuit(mode: RecomposeMode) -> Circuit<EF> {
    let perm = default_koalabear_poseidon2_16();
    let mut circuit = CircuitBuilder::<EF>::new();
    circuit.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
        generate_poseidon2_trace::<EF, KoalaBearD4Width16>,
        perm,
    );
    match mode {
        RecomposeMode::NpoTable => {
            circuit.enable_recompose::<F>(generate_recompose_trace::<F, EF>);
        }
        RecomposeMode::AluChain => {
            circuit.noop_enable_recompose::<F>(generate_recompose_trace::<F, EF>);
        }
    }

    let mut challenger = CircuitChallenger::<WIDTH, RATE, Poseidon2Config>::new_koalabear();
    for _ in 0..2 * RATE {
        let t = circuit.public_input();
        RecursiveChallenger::<F, EF>::observe(&mut challenger, &mut circuit, t);
    }
    RecursiveChallenger::<F, EF>::sample_bits(&mut challenger, &mut circuit, QUERY_INDEX_BITS)
        .expect("sampling a query index succeeds");

    circuit
        .build()
        .expect("absorbing transcript circuit builds")
}

/// Public input values for [`build_absorbing_transcript_circuit`].
fn absorbed_publics() -> Vec<EF> {
    (0..2 * RATE)
        .map(|i| EF::from_u64(1_000 + i as u64))
        .collect()
}

fn is_op_type(op: &Op<EF>, needle: &str) -> bool {
    match op {
        Op::NonPrimitiveOpWithExecutor { executor, .. } => {
            format!("{:?}", executor.op_type()).contains(needle)
        }
        _ => false,
    }
}

/// Positions of the Poseidon2 permutation ops, in execution order.
fn perm_op_positions(circuit: &Circuit<EF>) -> Vec<usize> {
    (0..circuit.ops.len())
        .filter(|&i| is_op_type(&circuit.ops[i], "poseidon2_perm"))
        .collect()
}

fn npo_io(circuit: &Circuit<EF>, pos: usize) -> (Vec<Vec<WitnessId>>, Vec<Vec<WitnessId>>) {
    match &circuit.ops[pos] {
        Op::NonPrimitiveOpWithExecutor {
            inputs, outputs, ..
        } => (inputs.clone(), outputs.clone()),
        _ => panic!("op {pos} is not a non-primitive op"),
    }
}

/// Position of the `Op::Hint` that decomposes `wid` into its `D` coefficient witnesses.
fn decomposition_hint_position(circuit: &Circuit<EF>, wid: WitnessId) -> usize {
    (0..circuit.ops.len())
        .find(|&i| matches!(&circuit.ops[i], Op::Hint { inputs, .. } if inputs == &[wid]))
        .unwrap_or_else(|| panic!("no decomposition hint reading {wid:?}"))
}

/// Position of the `recompose` row that writes `wid`, if one does.
fn recompose_position_writing_opt(circuit: &Circuit<EF>, wid: WitnessId) -> Option<usize> {
    (0..circuit.ops.len()).find(|&i| match &circuit.ops[i] {
        Op::NonPrimitiveOpWithExecutor { outputs, .. } => {
            is_op_type(&circuit.ops[i], "recompose") && outputs[0][0] == wid
        }
        _ => false,
    })
}

/// Position of the `recompose` row that writes `wid`.
fn recompose_position_writing(circuit: &Circuit<EF>, wid: WitnessId) -> usize {
    recompose_position_writing_opt(circuit, wid)
        .unwrap_or_else(|| panic!("no recompose row writing {wid:?}"))
}

/// Position of the last `Op::Alu` whose output is `wid`, if one exists.
fn alu_position_writing(circuit: &Circuit<EF>, wid: WitnessId) -> Option<usize> {
    (0..circuit.ops.len())
        .rev()
        .find(|&i| matches!(&circuit.ops[i], Op::Alu { out, .. } if *out == wid))
}

/// The bits the transcript's `sample_bits` produced, in circuit order.
///
/// The binary decomposition is the only hint in these circuits that writes more than `D`
/// witnesses, so it is found by width rather than by executor type.
fn query_index_bits(circuit: &Circuit<EF>, witness: &[Option<EF>]) -> Vec<EF> {
    let outputs = circuit
        .ops
        .iter()
        .find_map(|op| match op {
            Op::Hint { outputs, .. } if outputs.len() > D => Some(outputs.clone()),
            _ => None,
        })
        .expect("a binary decomposition hint");
    outputs
        .iter()
        .map(|w| witness[w.0 as usize].expect("bit witness is set"))
        .collect()
}

/// Position of the `Op::Const` that writes `wid`, if one does.
fn const_position_writing(circuit: &Circuit<EF>, wid: WitnessId) -> Option<usize> {
    (0..circuit.ops.len())
        .find(|&i| matches!(&circuit.ops[i], Op::Const { out, .. } if *out == wid))
}

/// How many operand slots in the whole circuit read `wid`.
fn operand_reads(circuit: &Circuit<EF>, wid: WitnessId) -> usize {
    circuit
        .ops
        .iter()
        .map(|op| match op {
            Op::Const { .. } | Op::Public { .. } => 0,
            Op::Alu { a, b, c, .. } => {
                usize::from(*a == wid) + usize::from(*b == wid) + usize::from(*c == Some(wid))
            }
            Op::Hint { inputs, .. } => inputs.iter().filter(|&&w| w == wid).count(),
            Op::NonPrimitiveOpWithExecutor { inputs, .. } => inputs
                .iter()
                .map(|g| g.iter().filter(|&&w| w == wid).count())
                .sum(),
        })
        .sum()
}

/// Hint that ignores its input and writes fixed base-embedded coefficients.
///
/// Stands in for a prover that fills the decomposition witnesses with values of its own
/// choosing instead of the permutation's actual output coefficients.
#[derive(Debug, Clone)]
struct ChosenCoefficients(u64);

impl HintExecutor<EF> for ChosenCoefficients {
    fn execute(
        &self,
        _inputs: &[WitnessId],
        outputs: &[WitnessId],
        witness: &mut [Option<EF>],
    ) -> Result<(), CircuitError> {
        for (i, &out) in outputs.iter().enumerate() {
            witness[out.0 as usize] = Some(EF::from_u64(self.0 + i as u64));
        }
        Ok(())
    }

    fn boxed(&self) -> Box<dyn HintExecutor<EF>> {
        Box::new(self.clone())
    }
}

fn run(circuit: &Circuit<EF>) -> Traces<EF> {
    run_with(circuit, &[])
}

fn run_with(circuit: &Circuit<EF>, publics: &[EF]) -> Traces<EF> {
    let mut runner = circuit.runner();
    runner.set_public_inputs(publics).expect("public inputs");
    runner.run().expect("witness generation succeeds")
}

fn witness_values(circuit: &Circuit<EF>) -> Vec<Option<EF>> {
    witness_values_with(circuit, &[])
}

fn witness_values_with(circuit: &Circuit<EF>, publics: &[EF]) -> Vec<Option<EF>> {
    let mut runner = circuit.runner();
    runner.set_public_inputs(publics).expect("public inputs");
    runner.execute_all().expect("witness generation succeeds");
    runner.witness().to_vec()
}

/// Prove `traces` against the constraint system of `circuit`, then verify.
fn prove_and_verify(circuit: &Circuit<EF>, traces: &Traces<EF>) -> Result<(), String> {
    let table_packing = TablePacking::new(1, 1);
    let stark_config = config::koala_bear();
    let npo_preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
        Box::new(Poseidon2Preprocessor),
        Box::new(RecomposePreprocessor::default()),
    ];
    let mut air_builders =
        poseidon2_air_builders_for_configs::<KoalaBearConfig, D>(vec![CFG.for_challenger(), CFG]);
    air_builders.extend(recompose_air_builders::<KoalaBearConfig, D>(1, false));

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<KoalaBearConfig, EF, D>(
            circuit,
            &table_packing,
            &npo_preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("preprocessed columns");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

    let prover_data = ProverData::from_airs_and_degrees(&stark_config, &airs, &degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let mut prover = BatchStarkProver::new(stark_config).with_table_packing(table_packing);
    prover.register_poseidon2_table::<D>(CFG.for_challenger());
    prover.register_poseidon2_table::<D>(CFG);
    prover.register_recompose_table::<D>(false);

    // An unsatisfied constraint or an unbalanced bus surfaces either as a prover-side panic
    // (both debuggers run under `debug_assertions`) or as a verification failure; all count as
    // rejection.
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        let proof = prover
            .prove_all_tables(traces, &circuit_prover_data)
            .map_err(|e| format!("prove: {e:?}"))?;
        prover
            .verify_all_tables::<EF>(&proof)
            .map_err(|e| format!("verify: {e:?}"))
    }))
    .unwrap_or_else(|_| Err("prover panicked on the tampered trace".to_string()))
}

fn assert_same_constraint_system(honest: &Circuit<EF>, edited: &Circuit<EF>) {
    let honest_prep = honest
        .generate_preprocessed_columns::<D>()
        .expect("honest preprocessed columns");
    let edited_prep = edited
        .generate_preprocessed_columns::<D>()
        .expect("edited preprocessed columns");
    assert!(
        honest_prep == edited_prep,
        "the edit must leave the verifier's preprocessed columns untouched"
    );
    assert_eq!(honest.witness_count, edited.witness_count);
}

// ---------------------------------------------------------------------------
// Baseline and control
// ---------------------------------------------------------------------------

#[test]
fn honest_transcript_proves_and_verifies() {
    for mode in [RecomposeMode::NpoTable, RecomposeMode::AluChain] {
        let circuit = build_transcript_circuit(mode);
        assert!(
            perm_op_positions(&circuit).len() >= 2,
            "{mode:?}: the transcript must run at least two permutations"
        );
        let traces = run(&circuit);
        prove_and_verify(&circuit, &traces)
            .unwrap_or_else(|e| panic!("{mode:?}: honest transcript must verify: {e}"));
    }
}

/// The harness rejects a value the `WitnessChecks` bus does bind, so acceptance in the
/// tests below is evidence about the constraint system rather than about the harness.
#[test]
fn control_corrupted_const_value_is_rejected() {
    let circuit = build_transcript_circuit(RecomposeMode::NpoTable);
    let perms = perm_op_positions(&circuit);
    let (perm_inputs, _) = npo_io(&circuit, perms[0]);
    let read_const = perm_inputs[0][0];

    let mut traces = run(&circuit);
    let row = traces
        .const_trace
        .index
        .iter()
        .position(|i| *i == read_const)
        .expect("a const row feeding the first permutation");
    traces.const_trace.values[row] += EF::ONE;

    assert!(
        prove_and_verify(&circuit, &traces).is_err(),
        "a const value read over the bus must not be freely re-chosen"
    );
}

// ---------------------------------------------------------------------------
// Sponge-chain binding
// ---------------------------------------------------------------------------

/// The capacity limb the second permutation reads must be the capacity limb the first
/// permutation produced.
///
/// The edit gives the first permutation an empty output slot for that limb — a slot the
/// Poseidon2 table neither publishes on the bus nor records in its trace row, so dropping
/// the write is invisible to the verifier — and replaces the decomposition hint with one
/// that supplies coefficients of its own. The recompose that follows is then the only
/// writer of the limb, and the second permutation reads whatever it wrote.
fn capacity_limb_binding(mode: RecomposeMode) {
    let honest = build_transcript_circuit(mode);
    let perms = perm_op_positions(&honest);
    let (_, first_outputs) = npo_io(&honest, perms[0]);
    let (second_inputs, _) = npo_io(&honest, perms[1]);
    let produced = first_outputs[CAPACITY_LIMB][0];
    let consumed = second_inputs[CAPACITY_LIMB][0];

    let honest_witness = witness_values(&honest);
    assert_eq!(
        honest_witness[produced.0 as usize], honest_witness[consumed.0 as usize],
        "{mode:?}: the honest witness must carry the capacity limb forward unchanged"
    );

    let mut edited = honest.clone();
    let hint_pos = decomposition_hint_position(&honest, produced);
    match &mut edited.ops[perms[0]] {
        Op::NonPrimitiveOpWithExecutor { outputs, .. } => {
            outputs[CAPACITY_LIMB].clear();
        }
        _ => unreachable!(),
    }
    match &mut edited.ops[hint_pos] {
        Op::Hint { executor, .. } => *executor = Box::new(ChosenCoefficients(1_000)),
        _ => unreachable!(),
    }
    assert_same_constraint_system(&honest, &edited);

    let edited_witness = witness_values(&edited);
    assert_ne!(
        edited_witness[consumed.0 as usize], honest_witness[produced.0 as usize],
        "{mode:?}: the edit must actually break the capacity chain"
    );

    let traces = run(&edited);
    assert!(
        prove_and_verify(&honest, &traces).is_err(),
        "{mode:?}: a proof whose second permutation reads a capacity limb the first \
         permutation never produced must be rejected"
    );
}

#[test]
fn capacity_limb_is_bound_across_permutations_alu_chain() {
    capacity_limb_binding(RecomposeMode::AluChain);
}

#[test]
fn capacity_limb_is_bound_across_permutations_npo_table() {
    capacity_limb_binding(RecomposeMode::NpoTable);
}

/// The rate limb the second permutation reads must be the rate limb the first permutation
/// produced.
///
/// A `recompose` row creates its own witness from `v_0..v_{D-1}` columns that carry no bus
/// lookup, so whenever one writes the limb the row can be pointed at a different, already
/// computed coefficient group without the verifier's preprocessed columns changing — a free
/// choice of the whole sponge state. This test rejects that: it takes whichever writer the
/// builder produced for the limb, and requires either that there is nothing to re-point (the
/// repacking dedupes back onto the permutation's own output witness) or that re-pointing it is
/// rejected end to end.
#[test]
fn rate_limb_is_bound_across_permutations_npo_table() {
    let honest = build_transcript_circuit(RecomposeMode::NpoTable);
    let perms = perm_op_positions(&honest);
    let (_, first_outputs) = npo_io(&honest, perms[0]);
    let (second_inputs, _) = npo_io(&honest, perms[1]);
    let produced = first_outputs[0][0];
    let consumed = second_inputs[0][0];

    let honest_witness = witness_values(&honest);
    assert_eq!(
        honest_witness[produced.0 as usize], honest_witness[consumed.0 as usize],
        "the honest witness must carry the rate limb forward unchanged"
    );

    let Some(target_row) = recompose_position_writing_opt(&honest, consumed) else {
        assert_eq!(
            consumed, produced,
            "a rate limb no packing row writes must be the permutation's own output witness"
        );
        return;
    };

    let donor_row = recompose_position_writing(&honest, second_inputs[1][0]);
    let (donor_inputs, _) = npo_io(&honest, donor_row);

    let mut edited = honest.clone();
    match &mut edited.ops[target_row] {
        Op::NonPrimitiveOpWithExecutor { inputs, .. } => *inputs = donor_inputs,
        _ => unreachable!(),
    }
    assert_same_constraint_system(&honest, &edited);

    let edited_witness = witness_values(&edited);
    assert_ne!(
        edited_witness[consumed.0 as usize], honest_witness[produced.0 as usize],
        "the edit must actually break the rate chain"
    );

    let traces = run(&edited);
    assert!(
        prove_and_verify(&honest, &traces).is_err(),
        "a proof whose second permutation reads a rate limb the first permutation never \
         produced must be rejected"
    );
}

// ---------------------------------------------------------------------------
// Absorbed values and the query index drawn from them
// ---------------------------------------------------------------------------

/// The limbs a permutation absorbs must be packed from the values the transcript observed, and
/// the query index the transcript then yields must follow from them.
///
/// The second permutation of [`build_absorbing_transcript_circuit`] reads limbs packed from the
/// second batch of observed public inputs. Pointing that packing at a different, already
/// computed coefficient group changes the sampled bits, so a verifier that accepts it accepts a
/// FRI query index the prover chose. Which writer the packing lowers to decides how visible the
/// edit is — a `recompose` row leaves the preprocessed columns untouched, an ALU `mul_add`
/// pins its operand indices there — but either way the resulting proof must not verify.
fn absorbed_limb_binding(mode: RecomposeMode) {
    let publics = absorbed_publics();
    let honest = build_absorbing_transcript_circuit(mode);
    let perms = perm_op_positions(&honest);
    assert!(
        perms.len() >= 2,
        "{mode:?}: the transcript must absorb across two permutations"
    );
    let (first_inputs, _) = npo_io(&honest, perms[0]);
    let (second_inputs, _) = npo_io(&honest, perms[1]);
    let consumed = second_inputs[0][0];
    // A limb the first permutation absorbed: its packing is already complete by the time the
    // second permutation's is built, so the re-pointed row still has its operands available.
    let donor = first_inputs[1][0];

    let mut edited = honest.clone();
    if let Some(target_row) = recompose_position_writing_opt(&honest, consumed) {
        let donor_row = recompose_position_writing(&honest, donor);
        let (donor_inputs, _) = npo_io(&honest, donor_row);
        match &mut edited.ops[target_row] {
            Op::NonPrimitiveOpWithExecutor { inputs, .. } => *inputs = donor_inputs,
            _ => unreachable!(),
        }
    } else {
        let target_row = alu_position_writing(&honest, consumed)
            .unwrap_or_else(|| panic!("{mode:?}: no packing row writes {consumed:?}"));
        let donor_row = alu_position_writing(&honest, donor)
            .unwrap_or_else(|| panic!("{mode:?}: no packing row writes {donor:?}"));
        let (donor_a, donor_c) = match &honest.ops[donor_row] {
            Op::Alu { a, c, .. } => (*a, *c),
            _ => unreachable!(),
        };
        match &mut edited.ops[target_row] {
            Op::Alu { a, c, .. } => {
                *a = donor_a;
                *c = donor_c;
            }
            _ => unreachable!(),
        }
    }

    let honest_witness = witness_values_with(&honest, &publics);
    let edited_witness = witness_values_with(&edited, &publics);
    assert_ne!(
        edited_witness[consumed.0 as usize], honest_witness[consumed.0 as usize],
        "{mode:?}: the edit must actually change the limb the second permutation absorbs"
    );
    assert_ne!(
        query_index_bits(&edited, &edited_witness),
        query_index_bits(&honest, &honest_witness),
        "{mode:?}: the edit must actually change the query index the transcript yields"
    );

    let traces = run_with(&edited, &publics);
    assert!(
        prove_and_verify(&honest, &traces).is_err(),
        "{mode:?}: a query index drawn from limbs the transcript never absorbed must be rejected"
    );
}

#[test]
fn absorbed_limb_is_bound_npo_table() {
    absorbed_limb_binding(RecomposeMode::NpoTable);
}

#[test]
fn absorbed_limb_is_bound_alu_chain() {
    absorbed_limb_binding(RecomposeMode::AluChain);
}

/// Under [`RecomposeMode::AluChain`] the step-`k + 1` packing is deduplicated back onto the
/// permutation's own output witness, which is why the rate limb has no analogous gap there.
#[test]
fn alu_chain_repacking_reuses_the_permutation_output_witness() {
    let circuit = build_transcript_circuit(RecomposeMode::AluChain);
    let perms = perm_op_positions(&circuit);
    let (_, first_outputs) = npo_io(&circuit, perms[0]);
    let (second_inputs, _) = npo_io(&circuit, perms[1]);
    for limb in 0..WIDTH_EXT {
        assert_eq!(
            first_outputs[limb][0], second_inputs[limb][0],
            "limb {limb} must be carried on one witness id, not repacked onto a new one"
        );
    }
}

// ---------------------------------------------------------------------------
// Chain start
// ---------------------------------------------------------------------------

/// The capacity the *first* permutation reads must be a value the verifier fixes.
///
/// Nothing carries a sponge IV forward into the chain start — there is no earlier row for the
/// chain constraint to chain it from — so the transcript binds only if the verifier fixes that
/// capacity outright. The challenger table's AIR pins it to the sponge's initial state on every
/// `new_start` row, and the `WitnessChecks` bus pins the witness the limb is fed from; this test
/// covers the bus half end to end, against the real prove-and-verify pipeline.
///
/// The tamper follows whichever writer the builder produced for that witness, so the test says
/// nothing about how the limb repacking is lowered: an all-`Const` repacking folds back into a
/// `Const` whose value the `Const` table pins, and any other lowering leaves a `recompose` row
/// that can be pointed at a different coefficient group instead.
fn chain_start_capacity_binding(mode: RecomposeMode) {
    let honest = build_transcript_circuit_observing(mode, 1_000);
    let perms = perm_op_positions(&honest);
    let (first_inputs, _) = npo_io(&honest, perms[0]);

    // The length tag, and nothing else, so the rejection below can only come from this limb.
    let tagged = first_inputs[CAPACITY_LIMB][0];
    assert_eq!(
        operand_reads(&honest, tagged),
        1,
        "{mode:?}: {tagged:?} must feed the chain start's capacity and nothing else"
    );

    if const_position_writing(&honest, tagged).is_some() {
        let mut traces = run(&honest);
        let row = traces
            .const_trace
            .index
            .iter()
            .position(|i| *i == tagged)
            .expect("a const row feeding the chain start's capacity");
        traces.const_trace.values[row] += EF::ONE;

        assert!(
            prove_and_verify(&honest, &traces).is_err(),
            "{mode:?}: the capacity the first permutation absorbs must not be freely re-chosen"
        );
        return;
    }

    let target_row = recompose_position_writing(&honest, tagged);
    let donor_row = recompose_position_writing(&honest, first_inputs[0][0]);
    let (donor_inputs, _) = npo_io(&honest, donor_row);

    let mut edited = honest.clone();
    match &mut edited.ops[target_row] {
        Op::NonPrimitiveOpWithExecutor { inputs, .. } => *inputs = donor_inputs,
        _ => unreachable!(),
    }
    assert_same_constraint_system(&honest, &edited);

    let honest_witness = witness_values(&honest);
    let edited_witness = witness_values(&edited);
    assert_ne!(
        edited_witness[tagged.0 as usize], honest_witness[tagged.0 as usize],
        "{mode:?}: the edit must actually change the sponge IV"
    );

    let traces = run(&edited);
    assert!(
        prove_and_verify(&honest, &traces).is_err(),
        "{mode:?}: the capacity the first permutation absorbs must not be freely re-chosen"
    );
}

#[test]
fn chain_start_capacity_is_bound_alu_chain() {
    chain_start_capacity_binding(RecomposeMode::AluChain);
}

#[test]
fn chain_start_capacity_is_bound_npo_table() {
    chain_start_capacity_binding(RecomposeMode::NpoTable);
}
