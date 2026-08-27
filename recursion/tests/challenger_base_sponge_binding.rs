//! Fiat-Shamir binding test for the base-field ([`CircuitChallenger`] `D == 1`) sponge IV.
//!
//! The compact D=1 Poseidon2 layout never witness-feeds a sponge row's capacity: the AIR owns
//! it outright, resetting it on a chain start and chaining it on every continuation. That makes
//! the capacity of the row that opens a chain a pure main-trace value — nothing on the
//! `WitnessChecks` bus refers to it — so the only thing standing between a prover and a
//! self-chosen sponge IV is the AIR's own chain-start constraint.
//!
//! The test builds the transcript twice from the same circuit shape. One build runs the real
//! permutation; the other runs a permutation that adds a shift to the first capacity element on
//! its first call only, so the honest runner produces a witness, a transcript and a permutation
//! chain that are all internally consistent with a *different* sponge IV. Bumping that one
//! recorded input element afterwards makes the trace row consistent too, which is exactly the
//! trace a prover assembling polynomials directly would commit to. The proof is then checked
//! against the unshifted build's constraint system, whose preprocessed columns are asserted
//! byte-identical.

use std::panic::AssertUnwindSafe;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use p3_batch_stark::ProverData;
use p3_circuit::ops::{
    KoalaBearD1Width16, NpoTypeId, Poseidon2Config, Poseidon2Trace, generate_poseidon2_trace,
};
use p3_circuit::tables::Traces;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_circuit_prover::batch_stark_prover::poseidon2_air_builders_d5;
use p3_circuit_prover::common::{NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, Poseidon2Preprocessor, TablePacking,
};
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_recursion::challenger::CircuitChallenger;
use p3_recursion::traits::RecursiveChallenger;
use p3_symmetric::Permutation;
use p3_test_utils::koala_bear_quintic_params::*;

const WIDTH: usize = 16;
const RATE: usize = 8;
const CFG: Poseidon2Config = Poseidon2Config::KOALA_BEAR_D1_W16;
/// Index of the first capacity element in the flattened D=1 state.
const CAPACITY_START: usize = RATE;

/// Permutation that shifts the sponge's first capacity element on its first call.
///
/// Stands in for a prover that opens the duplex chain from a state of its own choosing: every
/// later call runs the real permutation, so the chain carries the shifted opening forward
/// exactly as an honest chain would carry the zero opening.
#[derive(Clone)]
struct ShiftFirstCapacity<P> {
    inner: P,
    shift: Challenge,
    pending: Arc<AtomicBool>,
}

impl<P> ShiftFirstCapacity<P> {
    fn new(inner: P, shift: Challenge) -> Self {
        Self {
            inner,
            shift,
            pending: Arc::new(AtomicBool::new(true)),
        }
    }
}

impl<P: Permutation<[Challenge; WIDTH]>> Permutation<[Challenge; WIDTH]> for ShiftFirstCapacity<P> {
    fn permute_mut(&self, input: &mut [Challenge; WIDTH]) {
        if self.pending.swap(false, Ordering::SeqCst) {
            input[CAPACITY_START] += self.shift;
        }
        self.inner.permute_mut(input);
    }
}

/// Absorb `RATE` values, then squeeze past the output buffer so a second duplex step runs.
fn build_transcript_circuit<P>(perm: P) -> Circuit<Challenge>
where
    P: Permutation<[Challenge; WIDTH]> + Clone + Send + Sync + 'static,
{
    let mut circuit = CircuitBuilder::<Challenge>::new();
    circuit.enable_poseidon2_perm_base::<KoalaBearD1Width16, _>(
        generate_poseidon2_trace::<Challenge, KoalaBearD1Width16>,
        perm,
    );

    let mut challenger = CircuitChallenger::<WIDTH, RATE, Poseidon2Config>::new_koalabear_base();
    for i in 0..RATE {
        let t = circuit.define_const(Challenge::from_u64(1_000 + i as u64));
        RecursiveChallenger::<F, Challenge>::observe(&mut challenger, &mut circuit, t);
    }
    // `RATE` samples drain the output buffer; the next one forces a second permutation.
    for _ in 0..=RATE {
        let _ = RecursiveChallenger::<F, Challenge>::sample(&mut challenger, &mut circuit);
    }

    circuit.build().expect("transcript circuit builds")
}

fn run(circuit: &Circuit<Challenge>) -> Traces<Challenge> {
    let mut runner = circuit.runner();
    runner.set_public_inputs(&[]).expect("no public inputs");
    runner.run().expect("witness generation succeeds")
}

/// Prove `traces` against the constraint system of `circuit`, then verify.
fn prove_and_verify(
    circuit: &Circuit<Challenge>,
    traces: &Traces<Challenge>,
) -> Result<(), String> {
    let table_packing = TablePacking::new(1, 8);
    let npo_preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> = vec![Box::new(Poseidon2Preprocessor)];
    let air_builders = poseidon2_air_builders_d5::<MyConfig>();

    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<MyConfig, Challenge, 5>(
            circuit,
            &table_packing,
            &npo_preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("preprocessed columns");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

    let stark_config = make_test_config();
    let prover_data = ProverData::from_airs_and_degrees(&stark_config, &airs, &degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let mut prover = BatchStarkProver::new(stark_config).with_table_packing(table_packing);
    prover.register_poseidon2_table::<5>(CFG);

    // An unsatisfied constraint surfaces either as a prover-side panic (the debug constraint
    // checker runs under `debug_assertions`) or as a verification failure; both count as
    // rejection.
    std::panic::catch_unwind(AssertUnwindSafe(|| {
        let proof = prover
            .prove_all_tables(traces, &circuit_prover_data)
            .map_err(|e| format!("prove: {e:?}"))?;
        prover
            .verify_all_tables::<Challenge>(&proof)
            .map_err(|e| format!("verify: {e:?}"))
    }))
    .unwrap_or_else(|_| Err("prover panicked on the tampered trace".to_string()))
}

fn perm_trace(traces: &Traces<Challenge>) -> Poseidon2Trace<F> {
    traces
        .non_primitive_trace::<Poseidon2Trace<F>>(&NpoTypeId::poseidon2_perm(CFG))
        .expect("the challenger's permutation trace")
        .clone()
}

/// The rate the second permutation absorbs: the `RATE` challenges the first squeeze handed out.
fn squeezed_challenges(traces: &Traces<Challenge>) -> Vec<F> {
    perm_trace(traces).operations[1].input_values[..RATE].to_vec()
}

#[test]
fn honest_base_transcript_proves_and_verifies() {
    let circuit = build_transcript_circuit(LiftKoalaPermForQuintic::new(
        default_koalabear_poseidon2_16(),
    ));
    let traces = run(&circuit);
    assert!(
        perm_trace(&traces).operations.len() >= 2,
        "the transcript must run at least two permutations"
    );
    prove_and_verify(&circuit, &traces).expect("honest transcript must verify");
}

/// The capacity the *first* permutation absorbs — the sponge IV — must be the one the AIR fixes.
///
/// Nothing on the bus refers to it, so if the AIR does not pin it on the row that opens the
/// chain, a prover is free to run the whole Fiat-Shamir transcript from a different IV and still
/// commit to a trace that satisfies every remaining constraint.
#[test]
fn base_chain_start_capacity_is_bound() {
    let shift = Challenge::from_u64(7);
    let honest = build_transcript_circuit(LiftKoalaPermForQuintic::new(
        default_koalabear_poseidon2_16(),
    ));
    let forged = build_transcript_circuit(ShiftFirstCapacity::new(
        LiftKoalaPermForQuintic::new(default_koalabear_poseidon2_16()),
        shift,
    ));
    assert_eq!(
        honest
            .generate_preprocessed_columns::<5>()
            .expect("honest preprocessed columns"),
        forged
            .generate_preprocessed_columns::<5>()
            .expect("forged preprocessed columns"),
        "the two builds must share one constraint system"
    );

    let honest_traces = run(&honest);
    let mut forged_traces = run(&forged);

    // The recorded input still says the sponge opened at the honest IV. Bring it in line with
    // the state the permutation actually ran on, which is the whole point of the forgery: the
    // row is then internally consistent and so is every row that chains from it.
    let mut trace = perm_trace(&forged_traces);
    let base_shift: F = shift.as_basis_coefficients_slice()[0];
    trace.operations[0].input_values[CAPACITY_START] += base_shift;
    forged_traces
        .non_primitive_traces
        .insert(NpoTypeId::poseidon2_perm(CFG), Box::new(trace));

    assert_ne!(
        squeezed_challenges(&honest_traces),
        squeezed_challenges(&forged_traces),
        "the forged IV must actually move the transcript"
    );

    assert!(
        prove_and_verify(&honest, &forged_traces).is_err(),
        "a transcript opened from a prover-chosen sponge IV must be rejected"
    );
}
