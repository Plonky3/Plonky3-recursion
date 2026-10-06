//! Fiat-Shamir binding tests for the extension-field ([`CircuitChallenger`] `D >= 2`) sponge.
//!
//! The in-circuit challenger keeps the rate of its sponge state as `RATE` base-field
//! coefficient targets. An absorbing duplex step packs them into `RATE / D` extension limbs
//! fed to one Poseidon2 permutation over the `WitnessChecks` bus, and a sample unpacks only the
//! output limb it reads. The capacity never leaves the permutation table, and a squeeze that
//! continues the sponge feeds no limb at all. For the transcript to bind, every limb the
//! permutation of step `k + 1` reads must be one the verifier sees on the bus, or one an AIR
//! constraint ties to what the permutation of step `k` produced — not merely equal to it in an
//! honestly generated witness.
//!
//! A permutation limb is verifier-bound either when some table *creates* it on the bus with
//! the permutation's own value, or when an AIR constraint ties it to a permutation column
//! directly. `add_poseidon2_perm_for_challenger` requests `out_ctl = [true; rate_ext]`, so only
//! the rate limbs are created on the bus. The challenger table's chain-start constraint pins a
//! fresh sponge's capacity to zero plus the length tag, and its sponge chain constraint binds
//! every later row's capacity, and the rate of a squeeze, to the previous row's output.
//!
//! These tests build the transcript circuit with the real [`CircuitChallenger`], then edit
//! either the compiled [`Circuit`] or the trace it produces, and prove the result against the
//! *unedited* circuit's prover data. What an edit is worth as evidence depends on how much of
//! it the verifier can see, so what each test claims about
//! `generate_preprocessed_columns` differs:
//!
//! - `a_non_base_coefficient_cannot_move_a_squeezed_challenge` asserts it stays byte-identical.
//!   Its edit touches only prover-side data — the hint executor behind
//!   `decompose_ext_to_base_coeffs` — so it is a choice a prover assembling trace polynomials
//!   directly would be free to make.
//! - `absorbed_limb_is_bound_{npo_table,alu_chain}` assert neither. What they pin down is the
//!   query index the transcript yields, under both lowerings, and both lowerings put the edit
//!   on a row whose operand indices the preprocessed columns already carry.
//! - `control_corrupted_const_value_is_rejected`,
//!   `capacity_limb_is_bound_across_permutations_{alu_chain,npo_table}`,
//!   `chain_start_capacity_is_bound_{alu_chain,npo_table}`,
//!   `squeezed_rate_limb_is_bound_across_permutations` and the `shared_challenger_*` tests edit
//!   a trace value rather than the circuit, so there are no two constraint systems to compare.
//!   Apart from the control, the limbs they forge are chained limbs with no witness at all: the
//!   permutation row is their only carrier, so a forged trace is exactly what a cheating prover
//!   would submit.
//! - `honest_transcript_proves_and_verifies`,
//!   `a_challenger_without_the_coeff_table_refuses_to_build` and
//!   `chained_limbs_are_left_off_the_bus` edit nothing.
//!
//! `control_corrupted_const_value_is_rejected` pins down that this harness is a real
//! oracle: the same pipeline rejects a value the bus does bind.

#[path = "common/rejection_oracle.rs"]
#[allow(clippy::duplicate_mod)]
mod rejection_oracle;
use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    HintExecutor, NpoTypeId, Op, Poseidon2Config, Poseidon2PermCall, Poseidon2Trace,
    RecomposeTrace, generate_poseidon2_trace, generate_recompose_trace,
};
use p3_circuit::tables::{Traces, WitnessTrace};
use p3_circuit::{Circuit, CircuitBuilder, CircuitError, WitnessId};
use p3_circuit_prover::batch_stark_prover::{
    poseidon2_air_builders_for_configs, recompose_air_builders,
};
use p3_circuit_prover::common::{NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::config::KoalaBearConfig;
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, Poseidon2Preprocessor,
    Poseidon2SharedPreprocessor, RecomposePreprocessor, TablePacking, config,
};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_koala_bear::{KoalaBear, default_koalabear_poseidon2_16};
use p3_poseidon2_circuit_air::KoalaBearD4Width16;
use p3_recursion::challenger::CircuitChallenger;
use p3_recursion::traits::RecursiveChallenger;
use p3_symmetric::Permutation;
#[cfg(debug_assertions)]
use rejection_oracle::run_with_debug_oracle;
use rejection_oracle::{ProofCheckError, assert_rejected};

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
const SHARED_CFG: Poseidon2Config = CFG.for_shared_challenger_table();

/// How the challenger packs its sponge state: through the `recompose/coeff` table, or through
/// the ALU `mul_add` chain.
///
/// Both are selected explicitly. The builder refuses a `recompose/coeff` call when that table
/// is not enabled rather than substituting the chain, so [`RecomposeMode::AluChain`] has to say
/// so through [`CircuitChallenger::with_alu_state_packing`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RecomposeMode {
    NpoTable,
    AluChain,
}

/// Enables `mode`'s recompose tables on `circuit` and returns a challenger lowered to match.
fn challenger_for(
    mode: RecomposeMode,
    circuit: &mut CircuitBuilder<EF>,
) -> CircuitChallenger<WIDTH, RATE, Poseidon2Config> {
    let challenger = CircuitChallenger::<WIDTH, RATE, Poseidon2Config>::new_koalabear();
    match mode {
        RecomposeMode::NpoTable => {
            circuit.enable_recompose::<F>(generate_recompose_trace::<F, EF>);
            challenger
        }
        RecomposeMode::AluChain => {
            circuit.noop_enable_recompose::<F>(generate_recompose_trace::<F, EF>);
            challenger.with_alu_state_packing()
        }
    }
}

/// Absorb `RATE` values, then squeeze past the output buffer so a second duplex step runs.
fn build_transcript_circuit(mode: RecomposeMode) -> Circuit<EF> {
    let perm = default_koalabear_poseidon2_16();
    let mut circuit = CircuitBuilder::<EF>::new();
    circuit.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
        generate_poseidon2_trace::<EF, KoalaBearD4Width16>,
        perm,
    );
    let mut challenger = challenger_for(mode, &mut circuit);
    for i in 0..RATE {
        let t = circuit.define_const(EF::from_u64(1 + i as u64));
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
    let mut challenger = challenger_for(mode, &mut circuit);
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

/// Public input values for [`build_absorbing_transcript_circuit`] and
/// [`build_unsampled_transcript_circuit`].
fn absorbed_publics() -> Vec<EF> {
    (0..2 * RATE)
        .map(|i| EF::from_u64(1_000 + i as u64))
        .collect()
}

/// Absorb `2 * RATE` public inputs and sample nothing.
///
/// The transcript runs a chain start and one absorbing continuation, and no sample unpacks
/// either permutation's output, so a forged permutation input changes no row outside the
/// challenger table: whatever rejects the forgery is the challenger table's own constraints.
fn build_unsampled_transcript_circuit(mode: RecomposeMode) -> Circuit<EF> {
    let perm = default_koalabear_poseidon2_16();
    let mut circuit = CircuitBuilder::<EF>::new();
    circuit.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
        generate_poseidon2_trace::<EF, KoalaBearD4Width16>,
        perm,
    );
    let mut challenger = challenger_for(mode, &mut circuit);
    for _ in 0..2 * RATE {
        let t = circuit.public_input();
        RecursiveChallenger::<F, EF>::observe(&mut challenger, &mut circuit, t);
    }

    circuit
        .build()
        .expect("unsampled transcript circuit builds")
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

fn shared_publics() -> [EF; 2] {
    [EF::from_u64(RATE as u64), EF::ZERO]
}

fn shared_run(circuit: &Circuit<EF>) -> Traces<EF> {
    run_with(circuit, &shared_publics())
}

fn witness_values_with(circuit: &Circuit<EF>, publics: &[EF]) -> Vec<Option<EF>> {
    let mut runner = circuit.runner();
    runner.set_public_inputs(publics).expect("public inputs");
    runner.execute_all().expect("witness generation succeeds");
    runner.witness().to_vec()
}

/// Prove `traces` against the constraint system of `circuit`, then verify.
fn prove_and_verify(circuit: &Circuit<EF>, traces: &Traces<EF>) -> Result<(), ProofCheckError> {
    let table_packing = TablePacking::new(1, 1);
    let stark_config = config::koala_bear();
    let npo_preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
        Box::new(Poseidon2Preprocessor),
        Box::new(RecomposePreprocessor::new(true)),
    ];
    let mut air_builders =
        poseidon2_air_builders_for_configs::<KoalaBearConfig, D>(vec![CFG.for_challenger(), CFG]);
    air_builders.extend(recompose_air_builders::<KoalaBearConfig, D>(1, true));

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

    let prover_data = ProverData::from_airs_and_degrees(&stark_config, &airs, &degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let mut prover = BatchStarkProver::new(stark_config).with_table_packing(table_packing);
    prover.register_poseidon2_table::<D>(CFG.for_challenger());
    prover.register_poseidon2_table::<D>(CFG);
    prover.register_recompose_table::<D>(true);

    #[cfg(debug_assertions)]
    let result = run_with_debug_oracle(|| {
        let proof = prover
            .prove_all_tables(traces, &circuit_prover_data)
            .map_err(ProofCheckError::Prove)?;
        prover
            .verify_all_tables::<EF>(&proof)
            .map_err(ProofCheckError::Verify)
    });

    #[cfg(not(debug_assertions))]
    let result = {
        let proof = prover
            .prove_all_tables(traces, &circuit_prover_data)
            .map_err(ProofCheckError::Prove)?;
        prover
            .verify_all_tables::<EF>(&proof)
            .map_err(ProofCheckError::Verify)
    };

    #[cfg(debug_assertions)]
    return match result {
        Ok(result) => result,
        Err(kind) => Err(ProofCheckError::DebugPanic(kind)),
    };

    #[cfg(not(debug_assertions))]
    result
}

fn add_shared_challenger_transcript(circuit: &mut CircuitBuilder<EF>, first: u64) {
    let mut challenger = challenger_for(RecomposeMode::NpoTable, circuit);
    for i in 0..RATE {
        let t = circuit.define_const(EF::from_u64(first + i as u64));
        RecursiveChallenger::<F, EF>::observe(&mut challenger, circuit, t);
    }
    for _ in 0..=RATE {
        let _ = RecursiveChallenger::<F, EF>::sample(&mut challenger, circuit);
    }
}

/// Build one circuit whose execution has two independent challenger streams and ordinary
/// sponge/MMCS rows. The logical source traces remain separate; shared materialization is the
/// only place where they become one physical table.
fn build_shared_mixed_circuit() -> Circuit<EF> {
    let perm = default_koalabear_poseidon2_16();
    let mut circuit = CircuitBuilder::<EF>::new();
    circuit.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
        generate_poseidon2_trace::<EF, KoalaBearD4Width16>,
        perm,
    );

    // A direct challenger pair with public capacity limbs gives the proof-level attack mutator
    // a prover-controlled input while keeping the shared preprocessor's challenger layout
    // (including its capacity CTLs) intact. Honest public capacities are zero.
    let rate0 = circuit.define_const(EF::from_u64(1));
    let rate1 = circuit.define_const(EF::from_u64(2));
    let cap0 = circuit.public_input();
    let cap1 = circuit.public_input();
    let config = CFG.for_challenger();
    circuit
        .add_poseidon2_perm(&Poseidon2PermCall {
            config,
            new_start: true,
            merkle_path: false,
            mmcs_bit: None,
            mmcs_bit2: None,
            inputs: vec![Some(rate0), Some(rate1), Some(cap0), Some(cap1)],
            out_ctl: vec![true; RATE_EXT],
            return_all_outputs: false,
            mmcs_index_sum: None,
            absorb_len: RATE,
        })
        .expect("public-capacity challenger start builds");
    add_shared_challenger_transcript(&mut circuit, 100);
    add_shared_challenger_transcript(&mut circuit, 200);

    // An ordinary sponge chain starts from a deliberately nonzero capacity. Its second row is
    // a continuation, so the shared table exercises both the ordinary start and continuation
    // role at a real proof boundary.
    let ordinary_inputs: Vec<_> = (0..WIDTH_EXT)
        .map(|i| circuit.define_const(EF::from_u64(10_000 + i as u64)))
        .collect();
    let (_, ordinary_outputs) = circuit
        .add_poseidon2_perm(&Poseidon2PermCall {
            config: CFG,
            new_start: true,
            merkle_path: false,
            mmcs_bit: None,
            mmcs_bit2: None,
            inputs: ordinary_inputs.into_iter().map(Some).collect(),
            out_ctl: vec![true; RATE_EXT],
            return_all_outputs: true,
            mmcs_index_sum: None,
            absorb_len: 0,
        })
        .expect("ordinary sponge start builds");
    circuit
        .add_poseidon2_perm(&Poseidon2PermCall {
            config: CFG,
            new_start: false,
            merkle_path: false,
            mmcs_bit: None,
            mmcs_bit2: None,
            inputs: vec![None; WIDTH_EXT],
            out_ctl: vec![true; RATE_EXT],
            return_all_outputs: false,
            mmcs_index_sum: None,
            absorb_len: 0,
        })
        .expect("ordinary sponge continuation builds");

    // An ordinary MMCS row follows the source stream as a separate chain start. The shared
    // preprocessing must leave its reserved challenger-role slot clear despite Merkle metadata.
    let merkle_inputs: Vec<_> = (0..WIDTH_EXT)
        .map(|i| circuit.define_const(EF::from_u64(20_000 + i as u64)))
        .collect();
    let mmcs_sum = circuit.define_const(EF::ZERO);
    let mmcs_bit = circuit.define_const(EF::ONE);
    circuit
        .add_poseidon2_perm(&Poseidon2PermCall {
            config: CFG,
            new_start: true,
            merkle_path: true,
            mmcs_bit: Some(mmcs_bit),
            mmcs_bit2: None,
            inputs: merkle_inputs.into_iter().map(Some).collect(),
            out_ctl: vec![true; RATE_EXT],
            return_all_outputs: false,
            mmcs_index_sum: Some(mmcs_sum),
            absorb_len: 0,
        })
        .expect("ordinary MMCS row builds");

    // Keep the output witnesses live so the continuation's CTL rows are part of the proof. The
    // first ordinary operation's returned capacity is intentionally not exposed to the circuit.
    assert_eq!(ordinary_outputs.len(), WIDTH_EXT);
    circuit.build().expect("shared mixed circuit builds")
}

/// Prove `traces` against the single physical shared Poseidon2 table and verify the proof.
fn shared_prove_and_verify(
    circuit: &Circuit<EF>,
    traces: &Traces<EF>,
) -> Result<(), ProofCheckError> {
    let table_packing = TablePacking::new(1, 1);
    let stark_config = config::koala_bear();
    let npo_preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
        Box::new(Poseidon2SharedPreprocessor::new(vec![SHARED_CFG])),
        Box::new(RecomposePreprocessor::new(true)),
    ];
    let mut air_builders =
        poseidon2_air_builders_for_configs::<KoalaBearConfig, D>(vec![SHARED_CFG]);
    air_builders.extend(recompose_air_builders::<KoalaBearConfig, D>(1, true));

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<KoalaBearConfig, EF, D>(
            circuit,
            &table_packing,
            &npo_preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("shared preprocessed columns");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

    let prover_data = ProverData::from_airs_and_degrees(&stark_config, &airs, &degrees).unwrap();
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let mut prover = BatchStarkProver::new(stark_config).with_table_packing(table_packing);
    prover.register_poseidon2_table::<D>(SHARED_CFG);
    prover.register_recompose_table::<D>(true);

    #[cfg(debug_assertions)]
    let result = run_with_debug_oracle(|| {
        let proof = prover
            .prove_all_tables(traces, &circuit_prover_data)
            .map_err(ProofCheckError::Prove)?;
        prover
            .verify_all_tables::<EF>(&proof)
            .map_err(ProofCheckError::Verify)
    });

    #[cfg(not(debug_assertions))]
    let result = {
        let proof = prover
            .prove_all_tables(traces, &circuit_prover_data)
            .map_err(ProofCheckError::Prove)?;
        prover
            .verify_all_tables::<EF>(&proof)
            .map_err(ProofCheckError::Verify)
    };

    #[cfg(debug_assertions)]
    return match result {
        Ok(result) => result,
        Err(kind) => Err(ProofCheckError::DebugPanic(kind)),
    };

    #[cfg(not(debug_assertions))]
    result
}

/// Apply a prover-controlled mutation to one challenger source row, recompute that row's
/// permutation and every later row in the same chain, and carry each recomputed rate output into
/// the witness and into the `recompose/coeff` row that unpacks it, if a sample does. The circuit
/// and its committed preprocessing remain the honest originals.
fn forge_challenger_trace(
    circuit: &Circuit<EF>,
    publics: &[EF],
    target_row: usize,
    mutate: impl FnOnce(&mut p3_circuit::ops::Poseidon2CircuitRow<F>),
) -> Traces<EF> {
    let mut traces = run_with(circuit, publics);
    let source_id = NpoTypeId::poseidon2_perm(CFG.for_challenger());
    let source = traces
        .non_primitive_trace::<Poseidon2Trace<F>>(&source_id)
        .expect("circuit has challenger source trace")
        .clone();
    assert!(target_row < source.operations.len());
    assert!(!source.operations[target_row].merkle_path);
    let unpacked_id = NpoTypeId::recompose_with_coeff_lookups();
    let mut unpacked = traces
        .non_primitive_trace::<RecomposeTrace<F>>(&unpacked_id)
        .cloned();

    let mut forged = source;
    mutate(&mut forged.operations[target_row]);
    let mut witness: Vec<EF> = witness_values_with(circuit, publics)
        .into_iter()
        .map(|value| value.expect("honest witness is complete"))
        .collect();
    // Keep the witness bus and public-input table consistent with the forged row's input state.
    // The targeted direct challenger rows expose their capacity over public CTLs, so this is a
    // prover-controlled main/input mutation rather than a constant-table mismatch. A limb that is
    // not fed over CTL has no witness to keep consistent.
    for limb in (0..WIDTH_EXT).filter(|&limb| forged.operations[target_row].in_ctl[limb]) {
        let wid = forged.operations[target_row].input_indices[limb] as usize;
        let coeffs = &forged.operations[target_row].input_values[limb * D..(limb + 1) * D];
        witness[wid] = <EF as BasedVectorSpace<F>>::from_basis_coefficients_slice(coeffs)
            .expect("challenger input coefficients form an extension element");
    }
    for (wid, value) in traces
        .public_trace
        .index
        .iter()
        .zip(traces.public_trace.values.iter_mut())
    {
        *value = witness[wid.0 as usize];
    }
    let perm = default_koalabear_poseidon2_16();

    let mut chain_end = target_row + 1;
    while chain_end < forged.operations.len() && !forged.operations[chain_end].new_start {
        chain_end += 1;
    }
    for row_index in target_row..chain_end {
        let row = &mut forged.operations[row_index];
        let input: [F; WIDTH] = row
            .input_values
            .as_slice()
            .try_into()
            .expect("Poseidon2 row has fixed width");
        let output = perm.permute(input);
        for (limb, (&ctl, &wid)) in row
            .out_ctl
            .iter()
            .zip(row.output_indices.iter())
            .enumerate()
        {
            if ctl {
                let coeffs = &output[limb * D..(limb + 1) * D];
                let value = <EF as BasedVectorSpace<F>>::from_basis_coefficients_slice(coeffs)
                    .expect("permutation output coefficients form an extension element");
                witness[wid as usize] = value;
                for unpacking in unpacked
                    .iter_mut()
                    .flat_map(|trace| trace.operations.iter_mut())
                    .filter(|unpacking| unpacking.output_wid.0 == wid)
                {
                    unpacking.values = coeffs.to_vec();
                    for (coeff_wid, &coeff) in unpacking.input_wids.iter().zip(coeffs) {
                        witness[coeff_wid.0 as usize] = embed(coeff);
                    }
                }
            }
        }
        if row_index + 1 < chain_end {
            // Only the limbs the next row does not take over CTL follow the chain.
            let next = &mut forged.operations[row_index + 1];
            for limb in (0..WIDTH_EXT).filter(|&limb| !next.in_ctl[limb]) {
                next.input_values[limb * D..(limb + 1) * D]
                    .copy_from_slice(&output[limb * D..(limb + 1) * D]);
            }
            if next.absorb_len > 0 && !next.in_ctl[CAPACITY_LIMB] {
                next.input_values[RATE] += F::from_u8(next.absorb_len as u8);
            }
        }
    }

    traces
        .non_primitive_traces
        .insert(source_id, Box::new(forged));
    if let Some(unpacked) = unpacked {
        traces
            .non_primitive_traces
            .insert(unpacked_id, Box::new(unpacked));
    }
    traces.witness_trace = WitnessTrace::new(witness);
    traces
}

#[cfg(debug_assertions)]
#[test]
fn unrelated_panic_is_not_accepted_as_rejection_oracle() {
    let outcome = std::panic::catch_unwind(|| {
        let _ = rejection_oracle::run_with_debug_oracle(|| panic!("unrelated panic"));
    });
    let payload = outcome.expect_err("an unrelated panic must propagate out of the oracle");
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied())
        .unwrap_or("non-string panic payload");
    assert_eq!(message, "unrelated panic");
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
fn shared_mixed_transcript_proves_and_verifies() {
    let circuit = build_shared_mixed_circuit();
    let traces = shared_run(&circuit);
    let challenger_id = NpoTypeId::poseidon2_perm(CFG.for_challenger());
    let challenger_trace = traces
        .non_primitive_trace::<Poseidon2Trace<F>>(&challenger_id)
        .expect("mixed circuit has challenger source trace");
    assert!(
        !challenger_trace.operations.is_empty(),
        "honest control must execute challenger permutations"
    );
    let ordinary_id = NpoTypeId::poseidon2_perm(CFG);
    let ordinary_trace = traces
        .non_primitive_trace::<Poseidon2Trace<F>>(&ordinary_id)
        .expect("mixed circuit has ordinary source trace");
    assert!(
        !ordinary_trace.operations.is_empty(),
        "honest control must execute ordinary permutations"
    );
    assert!(
        ordinary_trace.operations[0].new_start
            && ordinary_trace.operations[0].input_values[RATE] != F::ZERO,
        "honest ordinary start must carry nonzero capacity"
    );
    shared_prove_and_verify(&circuit, &traces)
        .expect("honest mixed challenger/ordinary proof must verify");
}

#[test]
fn shared_challenger_initial_capacity_is_rejected_with_original_prep() {
    let circuit = build_shared_mixed_circuit();
    let forged = forge_challenger_trace(&circuit, &shared_publics(), 0, |row| {
        // Keep the prefix tag intact and forge the remaining initial capacity limb.
        row.input_values[RATE + D] += F::ONE;
    });
    assert_rejected(
        &shared_prove_and_verify(&circuit, &forged),
        "a shared challenger chain start must retain its trusted zero capacity",
    );
}

#[test]
fn shared_challenger_later_capacity_is_rejected_with_original_prep() {
    let circuit = build_shared_mixed_circuit();
    // Source row 2 is the first transcript's squeeze, which continues the chain row 1 starts.
    let forged = forge_challenger_trace(&circuit, &shared_publics(), 2, |row| {
        assert!(
            !row.new_start,
            "the squeeze continues its transcript's chain"
        );
        row.input_values[RATE + D] += F::ONE;
    });
    assert_rejected(
        &shared_prove_and_verify(&circuit, &forged),
        "a shared challenger continuation must retain the previous capacity output",
    );
}

#[test]
fn shared_challenger_prefix_tag_is_rejected_with_original_prep() {
    let circuit = build_shared_mixed_circuit();
    let forged = forge_challenger_trace(&circuit, &shared_publics(), 0, |row| {
        assert!(
            row.absorb_len > 0,
            "the first challenger row carries its prefix tag"
        );
        row.input_values[RATE] += F::ONE;
    });
    assert_rejected(
        &shared_prove_and_verify(&circuit, &forged),
        "a shared challenger start must retain its trusted prefix-length tag",
    );
}

#[test]
fn shared_challenger_role_metadata_cannot_downgrade_a_forged_start() {
    let circuit = build_shared_mixed_circuit();
    let forged = forge_challenger_trace(&circuit, &shared_publics(), 0, |row| {
        row.challenger = false;
        row.input_values[RATE + D] += F::ONE;
    });
    assert_rejected(
        &shared_prove_and_verify(&circuit, &forged),
        "witness-only challenger role metadata must not downgrade a forged challenger start",
    );
}

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

/// A challenger built on a circuit without the `recompose/coeff` table refuses to build.
///
/// The ALU `mul_add` chain is the lowering [`RecomposeMode::AluChain`] selects on purpose, and
/// it does not bind the transcript's coefficients; substituting it for a circuit that simply
/// never enabled the table would hand a caller who asked for the binding lowering an unbound
/// transcript, with nothing to tell them apart.
#[test]
fn a_challenger_without_the_coeff_table_refuses_to_build() {
    let outcome = std::panic::catch_unwind(|| {
        let perm = default_koalabear_poseidon2_16();
        let mut circuit = CircuitBuilder::<EF>::new();
        circuit.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
            generate_poseidon2_trace::<EF, KoalaBearD4Width16>,
            perm,
        );
        circuit.noop_enable_recompose::<F>(generate_recompose_trace::<F, EF>);

        let mut challenger = CircuitChallenger::<WIDTH, RATE, Poseidon2Config>::new_koalabear();
        for _ in 0..RATE {
            let t = circuit.public_input();
            RecursiveChallenger::<F, EF>::observe(&mut challenger, &mut circuit, t);
        }
        RecursiveChallenger::<F, EF>::sample_ext(&mut challenger, &mut circuit)
    });

    let panic = outcome.expect_err("the challenger must not build");
    let message = panic
        .downcast_ref::<String>()
        .cloned()
        .or_else(|| panic.downcast_ref::<&str>().map(|m| (*m).to_string()))
        .unwrap_or_default();
    assert!(
        message.contains("enable_recompose"),
        "the failure must name what is missing, got: {message}"
    );
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

    assert_rejected(
        &prove_and_verify(&circuit, &traces),
        "a const value read over the bus must not be freely re-chosen",
    );
}

// ---------------------------------------------------------------------------
// Sponge-chain binding
// ---------------------------------------------------------------------------

/// The capacity a continuation reads must be the capacity the previous permutation produced,
/// plus the length tag.
///
/// The continuation feeds no capacity limb over the bus, so the permutation row is that limb's
/// only carrier and the forgery is a trace edit: the continuation's capacity input is moved off
/// the previous row's output and its permutation recomputed, with everything the verifier holds
/// left as it was. Nothing samples either permutation, so no other table sees the edit.
fn capacity_limb_binding(mode: RecomposeMode) {
    let circuit = build_unsampled_transcript_circuit(mode);
    let publics = absorbed_publics();
    prove_and_verify(&circuit, &run_with(&circuit, &publics))
        .unwrap_or_else(|e| panic!("{mode:?}: honest transcript must verify: {e}"));

    let forged = forge_challenger_trace(&circuit, &publics, 1, |row| {
        assert!(!row.new_start, "{mode:?}: row 1 continues the sponge");
        assert!(
            !row.in_ctl[CAPACITY_LIMB],
            "{mode:?}: a continuation's capacity is not fed over the bus"
        );
        row.input_values[RATE + 1] += F::ONE;
    });
    assert_rejected(
        &prove_and_verify(&circuit, &forged),
        &format!(
            "{mode:?}: a proof whose second permutation reads a capacity the first permutation \
             never produced must be rejected"
        ),
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

/// The rate a squeeze permutes must be the rate the previous permutation produced.
///
/// A squeeze that continues the sponge feeds no limb over the bus, so the forgery is a trace
/// edit: the squeeze's rate input is moved off the previous row's output and its permutation
/// recomputed. The output limb the triggering sample unpacks is carried into its
/// `recompose/coeff` row and coefficient witnesses, so every table outside the challenger's
/// stays consistent with the forged permutation.
#[test]
fn squeezed_rate_limb_is_bound_across_permutations() {
    let circuit = build_transcript_circuit(RecomposeMode::NpoTable);
    let forged = forge_challenger_trace(&circuit, &[], 1, |row| {
        assert!(!row.new_start, "row 1 continues the sponge");
        assert!(
            row.in_ctl.iter().all(|&ctl| !ctl),
            "a squeeze that continues the sponge feeds no limb over the bus"
        );
        row.input_values[0] += F::ONE;
    });
    let unpacked = |traces: &Traces<EF>| {
        traces
            .non_primitive_trace::<RecomposeTrace<F>>(&NpoTypeId::recompose_with_coeff_lookups())
            .expect("the samples unpack through `recompose/coeff` rows")
            .operations
            .iter()
            .map(|row| row.values.clone())
            .collect::<Vec<_>>()
    };
    assert_ne!(
        unpacked(&forged),
        unpacked(&run(&circuit)),
        "the forged output limb must reach the row that unpacks it"
    );
    assert_rejected(
        &prove_and_verify(&circuit, &forged),
        "a proof whose squeeze permutes a rate the previous permutation never produced must be \
         rejected",
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
/// FRI query index the prover chose. Which writer the packing lowers to decides which row the
/// edit lands on — a `recompose/coeff` row under [`RecomposeMode::NpoTable`], an ALU `mul_add`
/// under [`RecomposeMode::AluChain`] — and both carry their operand witness indices in the
/// preprocessed columns, so this test claims nothing about those columns either way and asks
/// only that the resulting proof not verify.
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
    assert_rejected(
        &prove_and_verify(&honest, &traces),
        &format!(
            "{mode:?}: a query index drawn from limbs the transcript never absorbed must be rejected"
        ),
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

/// Only the limbs no chain constraint binds go over the bus: the rate of a chain start and of an
/// absorb. Every capacity limb, and every limb of a squeeze that continues the sponge, is left to
/// the challenger table's chain-start and chain constraints.
#[test]
fn chained_limbs_are_left_off_the_bus() {
    for mode in [RecomposeMode::NpoTable, RecomposeMode::AluChain] {
        let squeezing = build_transcript_circuit(mode);
        let absorbing = build_absorbing_transcript_circuit(mode);
        let (start, _) = npo_io(&squeezing, perm_op_positions(&squeezing)[0]);
        let (squeeze, _) = npo_io(&squeezing, perm_op_positions(&squeezing)[1]);
        let (absorb, _) = npo_io(&absorbing, perm_op_positions(&absorbing)[1]);
        for limb in 0..WIDTH_EXT {
            let fed = usize::from(limb < RATE_EXT);
            assert_eq!(start[limb].len(), fed, "{mode:?}: chain-start limb {limb}");
            assert_eq!(absorb[limb].len(), fed, "{mode:?}: absorbing limb {limb}");
            assert!(squeeze[limb].is_empty(), "{mode:?}: squeezing limb {limb}");
        }
    }
}

/// A permutation's rate output is unpacked only when a sample reads it.
///
/// The `RATE` samples drain both output limbs of the first permutation, and the extra sample
/// reads only the last limb of the second, so the second permutation's first limb is never
/// decomposed.
#[test]
fn only_sampled_output_limbs_are_unpacked() {
    for mode in [RecomposeMode::NpoTable, RecomposeMode::AluChain] {
        let circuit = build_transcript_circuit(mode);
        let perms = perm_op_positions(&circuit);
        let unpacked = |perm: usize, limb: usize| {
            let wid = npo_io(&circuit, perms[perm]).1[limb][0];
            circuit
                .ops
                .iter()
                .any(|op| matches!(op, Op::Hint { inputs, .. } if inputs == &[wid]))
        };
        assert!(unpacked(0, 0) && unpacked(0, 1), "{mode:?}: drained limbs");
        assert!(unpacked(1, RATE_EXT - 1), "{mode:?}: the sampled limb");
        assert!(!unpacked(1, 0), "{mode:?}: a limb no sample reads");
    }
}

// ---------------------------------------------------------------------------
// Chain start
// ---------------------------------------------------------------------------

/// The capacity the *first* permutation reads must be a value the verifier fixes.
///
/// Nothing carries a sponge IV forward into the chain start — there is no earlier row for the
/// chain constraint to chain it from — so the transcript binds only if the verifier fixes that
/// capacity outright. The chain start feeds no capacity limb over the bus, and the challenger
/// table's AIR pins it to the sponge's initial state plus the length tag on every `new_start`
/// row. The forgery moves a capacity element the tag does not touch, recomputes the chain
/// start's permutation and re-chains the continuation onto it, so the chain-start constraint is
/// the only one left to fail. Nothing samples either permutation, so no other table sees the
/// edit.
fn chain_start_capacity_binding(mode: RecomposeMode) {
    let circuit = build_unsampled_transcript_circuit(mode);
    let publics = absorbed_publics();
    prove_and_verify(&circuit, &run_with(&circuit, &publics))
        .unwrap_or_else(|e| panic!("{mode:?}: honest transcript must verify: {e}"));

    let forged = forge_challenger_trace(&circuit, &publics, 0, |row| {
        assert!(row.new_start, "{mode:?}: row 0 starts the sponge");
        assert!(
            !row.in_ctl[CAPACITY_LIMB],
            "{mode:?}: a chain start's capacity is not fed over the bus"
        );
        row.input_values[RATE + D] += F::ONE;
    });
    assert_rejected(
        &prove_and_verify(&circuit, &forged),
        &format!(
            "{mode:?}: the capacity the first permutation absorbs must not be freely re-chosen"
        ),
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

// ---------------------------------------------------------------------------
// Coefficients that are not base-field elements
// ---------------------------------------------------------------------------

/// Tag under which [`build_sampling_transcript_circuit`] records its squeezed challenge.
const CHALLENGE_TAG: &str = "squeezed_challenge";

/// The extension basis element `w^i`.
fn basis(i: usize) -> EF {
    let mut coeffs = [F::ZERO; D];
    coeffs[i] = F::ONE;
    <EF as BasedVectorSpace<F>>::from_basis_coefficients_slice(&coeffs)
        .expect("basis coefficients are valid")
}

/// `c` embedded in the extension field.
fn embed(c: F) -> EF {
    let mut coeffs = [F::ZERO; D];
    coeffs[0] = c;
    <EF as BasedVectorSpace<F>>::from_basis_coefficients_slice(&coeffs)
        .expect("basis coefficients are valid")
}

/// Whether `v` is a base-field element embedded in the extension field.
fn is_base(v: EF) -> bool {
    <EF as BasedVectorSpace<F>>::as_basis_coefficients_slice(&v)[1..]
        .iter()
        .all(|c| *c == F::ZERO)
}

/// The honest base decomposition of `x`, as extension elements.
fn base_decomposition(x: EF) -> Vec<EF> {
    <EF as BasedVectorSpace<F>>::as_basis_coefficients_slice(&x)
        .iter()
        .map(|&c| embed(c))
        .collect()
}

/// Hint that decomposes its input honestly, then moves a purely non-base amount between two
/// coefficient slots.
///
/// `c_1 += a·w` and `c_0 -= a·w²`. The two shifts cancel in `sum(c_i·w^i)`, so any constraint
/// that only ties that sum back to the decomposed value is satisfied; and neither shift has a
/// `w⁰` component, so the base decomposition the coefficients stand for is unchanged too. What
/// changes is the extension value each coefficient *witness* holds — the freedom a repacking
/// that reads coefficients as extension operands hands the prover.
#[derive(Debug, Clone)]
struct NonBaseCoefficientShift(u64);

impl HintExecutor<EF> for NonBaseCoefficientShift {
    fn execute(
        &self,
        inputs: &[WitnessId],
        outputs: &[WitnessId],
        witness: &mut [Option<EF>],
    ) -> Result<(), CircuitError> {
        let x = witness[inputs[0].0 as usize].expect("the decomposed value is witnessed");
        let mut coeffs = base_decomposition(x);
        let shift = EF::from_u64(self.0);
        coeffs[0] -= shift * basis(2);
        coeffs[1] += shift * basis(1);
        for (&out, &value) in outputs.iter().zip(coeffs.iter()) {
            witness[out.0 as usize] = Some(value);
        }
        Ok(())
    }

    fn boxed(&self) -> Box<dyn HintExecutor<EF>> {
        Box::new(self.clone())
    }
}

/// The output witnesses of the `Op::Hint` at `pos`.
fn hint_outputs(circuit: &Circuit<EF>, pos: usize) -> Vec<WitnessId> {
    match &circuit.ops[pos] {
        Op::Hint { outputs, .. } => outputs.clone(),
        _ => panic!("op {pos} is not a hint"),
    }
}

/// Absorb `RATE` values, then squeeze one extension challenge and tag it.
///
/// `sample_ext` draws `D` base elements off the output buffer and packs them into an extension
/// challenge, so the tagged witness is exactly the kind of value a Fiat-Shamir round yields:
/// `alpha`, `beta`, or the out-of-domain point.
fn build_sampling_transcript_circuit(mode: RecomposeMode) -> Circuit<EF> {
    let perm = default_koalabear_poseidon2_16();
    let mut circuit = CircuitBuilder::<EF>::new();
    circuit.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
        generate_poseidon2_trace::<EF, KoalaBearD4Width16>,
        perm,
    );
    let mut challenger = challenger_for(mode, &mut circuit);
    for i in 0..RATE {
        let t = circuit.define_const(EF::from_u64(1_000 + i as u64));
        RecursiveChallenger::<F, EF>::observe(&mut challenger, &mut circuit, t);
    }
    let challenge = RecursiveChallenger::<F, EF>::sample_ext(&mut challenger, &mut circuit);
    circuit.tag(challenge, CHALLENGE_TAG).expect("tagging");

    circuit.build().expect("sampling transcript circuit builds")
}

/// The limb `sample_ext` draws its coefficients from: `sample` pops the output buffer, which
/// holds `state[0..RATE]`, so the `D` values it takes are the last limb of the rate.
const SAMPLED_LIMB: usize = RATE_EXT - 1;

/// A squeezed extension challenge must follow from the base decomposition of the sponge state,
/// not from whatever extension values the coefficient witnesses happen to hold.
///
/// [`NonBaseCoefficientShift`] leaves both the weighted sum and every coefficient's base part
/// alone, so the honest runner accepts it and the proof still verifies — the point is what the
/// squeezed challenge comes out as. `sample_ext` packs the coefficients back in the order it
/// popped them, which is the reverse of the order they were unpacked in, so the two shifts no
/// longer cancel: a packing that reads them as extension operands yields a different challenge,
/// one the prover chose. A packing that reads their base parts yields the honest challenge.
#[test]
fn a_non_base_coefficient_cannot_move_a_squeezed_challenge() {
    let honest = build_sampling_transcript_circuit(RecomposeMode::NpoTable);
    let perms = perm_op_positions(&honest);
    let (_, outputs) = npo_io(&honest, perms[0]);
    let produced = outputs[SAMPLED_LIMB][0];
    let hint_pos = decomposition_hint_position(&honest, produced);
    let coeff_wids = hint_outputs(&honest, hint_pos);

    let mut edited = honest.clone();
    match &mut edited.ops[hint_pos] {
        Op::Hint { executor, .. } => *executor = Box::new(NonBaseCoefficientShift(7)),
        _ => unreachable!(),
    }
    assert_same_constraint_system(&honest, &edited);

    let honest_witness = witness_values(&honest);
    let edited_witness = witness_values(&edited);
    assert_ne!(
        edited_witness[coeff_wids[0].0 as usize], honest_witness[coeff_wids[0].0 as usize],
        "the edit must actually change the coefficient witness"
    );
    assert!(
        !is_base(edited_witness[coeff_wids[0].0 as usize].expect("coefficient is witnessed")),
        "the edit must leave a coefficient that is not a base-field element"
    );

    let challenge_wid = honest.tag_to_witness[CHALLENGE_TAG];
    assert_eq!(
        edited_witness[challenge_wid.0 as usize], honest_witness[challenge_wid.0 as usize],
        "an extension challenge must be squeezed from the base decomposition of the sponge \
         state, so a non-base coefficient cannot move it"
    );

    // The tampered witness is a real option for the prover — it passes witness generation and
    // the verifier accepts it — which is what makes the equality above load-bearing rather
    // than a statement about an unreachable state.
    let traces = run(&edited);
    prove_and_verify(&honest, &traces)
        .expect("a shift no table can see must leave the proof valid");
}
