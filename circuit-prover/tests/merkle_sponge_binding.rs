//! Cross-key soundness regressions for Poseidon Merkle rows and sponge starts.
//!
//! Each case builds a pair of circuits over identical constant tables that differ in one value the
//! Poseidon table must bind: a Merkle direction bit, a digest entering a Merkle row, or a lane of a
//! sponge's starting state. The honest trace of the first circuit is proven under the second
//! circuit's prepared key and checked by that key's verifier. A sound relation rejects the proof,
//! because the second circuit's statement is false. Changing the claimed root, which the output
//! lookup binds, is the control showing the harness detects a missing binding at all.

#[cfg(debug_assertions)]
use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

use p3_circuit::ops::{
    PermConfig, Poseidon1Config, Poseidon2Config, Poseidon2PermCall, generate_poseidon1_trace,
    generate_poseidon2_trace, perm_private_data,
};
use p3_circuit::tables::Traces;
use p3_circuit::{Circuit, CircuitBuilder, ExprId, NonPrimitiveOpId};
use p3_circuit_prover::batch_stark_prover::{
    poseidon1_air_builders, poseidon1_air_builders_d5, poseidon2_air_builders,
    poseidon2_air_builders_d5,
};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::config::KoalaBearConfig;
use p3_circuit_prover::field_params::ExtractBinomialW;
use p3_circuit_prover::{
    BatchStarkProver, ConstraintProfile, Poseidon1Preprocessor, Poseidon2Preprocessor,
    PreparedCircuitProver, config,
};
use p3_field::extension::{BinomialExtensionField, QuinticTrinomialExtensionField};
use p3_field::{ExtensionField, PrimeCharacteristicRing};
use p3_koala_bear::{
    KoalaBear, default_koalabear_poseidon1_16, default_koalabear_poseidon2_16,
    default_koalabear_poseidon2_32,
};
use p3_poseidon2_circuit_air::{KoalaBearD1Width16, KoalaBearD4Width16, KoalaBearD4Width32};
use p3_symmetric::Permutation;
use p3_test_utils::LiftPermToQuintic;
#[cfg(debug_assertions)]
use p3_test_utils::rejection_oracle::{DebugRejectionKind, classify_debug_diagnostic};

type F = KoalaBear;
type EF4 = BinomialExtensionField<F, 4>;
type EF5 = QuinticTrinomialExtensionField<F>;
type SC = KoalaBearConfig;

const LEAF: u64 = 1;
const OTHER_LEAF: u64 = 5;
const INJECTED: u64 = 3;
const OTHER_INJECTED: u64 = 6;
const SIBLING_0: u64 = 2;
const SIBLING_1: u64 = 4;

fn digest(seed: u64) -> [F; 8] {
    core::array::from_fn(|i| F::from_u64(seed * 100 + i as u64 + 1))
}

/// Pack eight base elements into the circuit limbs a Poseidon config with extension degree
/// `poseidon_d` consumes: `D`-element extension limbs, or one embedded base element per limb.
fn limbs<EF: ExtensionField<F>>(values: &[F], poseidon_d: usize) -> Vec<EF> {
    if poseidon_d == 1 {
        values.iter().map(|&v| EF::from(v)).collect()
    } else {
        values
            .chunks(poseidon_d)
            .map(|c| EF::from_basis_coefficients_slice(c).unwrap())
            .collect()
    }
}

fn define<EF: ExtensionField<F>>(
    b: &mut CircuitBuilder<EF>,
    values: &[F],
    poseidon_d: usize,
) -> Vec<ExprId> {
    limbs::<EF>(values, poseidon_d)
        .into_iter()
        .map(|v| b.define_const(v))
        .collect()
}

fn compress(perm: &impl Permutation<[F; 16]>, left: [F; 8], right: [F; 8]) -> [F; 8] {
    let mut state = [F::ZERO; 16];
    state[..8].copy_from_slice(&left);
    state[8..].copy_from_slice(&right);
    perm.permute(state)[..8].try_into().unwrap()
}

/// One level-0 compression, then a level-1 injection followed by a level-1 compression.
#[derive(Clone, Copy)]
struct MerkleSpec {
    flip_level0_bit: bool,
    leaf: u64,
    injected: u64,
    honest_root: bool,
}

const HONEST: MerkleSpec = MerkleSpec {
    flip_level0_bit: false,
    leaf: LEAF,
    injected: INJECTED,
    honest_root: true,
};

fn honest_root(perm: &impl Permutation<[F; 16]>) -> [F; 8] {
    let h0 = compress(perm, digest(LEAF), digest(SIBLING_0));
    let h1 = compress(perm, h0, digest(INJECTED));
    compress(perm, h1, digest(SIBLING_1))
}

/// Build the Merkle circuit. Every variant defines the same constants in the same order, so the
/// constant table is identical across variants and only the wiring differs.
fn build_merkle<EF: ExtensionField<F>>(
    spec: MerkleSpec,
    cfg: PermConfig,
    root: [F; 8],
    enable: impl FnOnce(&mut CircuitBuilder<EF>),
) -> (Circuit<EF>, Vec<NonPrimitiveOpId>) {
    let d = cfg.d();
    let mut b = CircuitBuilder::<EF>::new();
    enable(&mut b);
    let zero = b.define_const(EF::ZERO);
    let one = b.define_const(EF::ONE);
    let leaf_a = define(&mut b, &digest(LEAF), d);
    let leaf_b = define(&mut b, &digest(OTHER_LEAF), d);
    let inj_a = define(&mut b, &digest(INJECTED), d);
    let inj_b = define(&mut b, &digest(OTHER_INJECTED), d);
    let root_a = define(&mut b, &root, d);
    let root_b = define(&mut b, &digest(7), d);

    let leaf = if spec.leaf == LEAF { leaf_a } else { leaf_b };
    let injected = if spec.injected == INJECTED {
        inj_a
    } else {
        inj_b
    };
    let root = if spec.honest_root { root_a } else { root_b };
    let level0_bit = if spec.flip_level0_bit { one } else { zero };
    let ops = b
        .add_mmcs_verify(cfg, &[leaf, injected], &[level0_bit, zero], &root)
        .unwrap();
    assert_eq!(ops.len(), 2);
    (b.build().unwrap(), ops)
}

fn run_merkle<EF: ExtensionField<F>>(
    circuit: &Circuit<EF>,
    ops: &[NonPrimitiveOpId],
    cfg: PermConfig,
) -> Result<Traces<EF>, String> {
    let mut runner = circuit.runner();
    for (&op, sibling) in ops.iter().zip([SIBLING_0, SIBLING_1]) {
        runner
            .set_private_data(
                op,
                perm_private_data(cfg, limbs::<EF>(&digest(sibling), cfg.d())),
            )
            .unwrap();
    }
    runner.run().map_err(|e| format!("{e:?}"))
}

/// Whether `result` is a rejection by the lookup argument, as opposed to a prover or harness
/// failure: the verifier's in a release build, the prover's lookup check in a debug build.
fn rejected_by_lookups(result: &Result<(), String>) -> bool {
    matches!(result, Err(e) if e.starts_with("verify:") || e.starts_with("lookup:"))
}

/// Prove `traces` under `prepared`'s key and verify with `prepared`'s verifier.
///
/// A debug build checks every lookup while proving and panics on an unbalanced one, so there a
/// forged trace stops at that check and is reported as `lookup:` instead of reaching the verifier.
fn prove_under<EF>(prepared: &PreparedCircuitProver<SC>, traces: &Traces<EF>) -> Result<(), String>
where
    EF: ExtensionField<F> + ExtractBinomialW<F>,
{
    #[cfg(debug_assertions)]
    let proof = match catch_unwind(AssertUnwindSafe(|| prepared.prove(traces))) {
        Ok(proof) => proof,
        Err(payload) => {
            let message = payload
                .downcast_ref::<String>()
                .map(String::as_str)
                .or_else(|| payload.downcast_ref::<&str>().copied());
            match message {
                Some(m) if classify_debug_diagnostic(m) == Some(DebugRejectionKind::Lookup) => {
                    return Err(format!("lookup: {m}"));
                }
                _ => resume_unwind(payload),
            }
        }
    };
    #[cfg(not(debug_assertions))]
    let proof = prepared.prove(traces);
    let proof = proof.map_err(|e| format!("prove: {e:?}"))?;
    prepared
        .verifier()
        .verify(&proof, &[])
        .map_err(|e| format!("verify: {e:?}"))
}

fn prepare<EF, const D: usize>(
    circuit: &Circuit<EF>,
    prep: &[Box<dyn NpoPreprocessor<F>>],
    air_builders: &[Box<dyn NpoAirBuilder<SC, D>>],
    register: impl FnOnce(&mut BatchStarkProver<SC>),
) -> PreparedCircuitProver<SC>
where
    EF: ExtensionField<F> + ExtractBinomialW<F>,
{
    let mut prover = BatchStarkProver::new(config::koala_bear());
    register(&mut prover);
    prover
        .prepare_circuit::<EF, D>(circuit, prep, air_builders, ConstraintProfile::Standard)
        .expect("prepare circuit")
}

/// A Poseidon table family under test: how to enable the op, the native permutation, and how to
/// prepare a circuit's key.
trait Family {
    type EF: ExtensionField<F> + ExtractBinomialW<F>;
    fn cfg() -> PermConfig;
    fn native() -> impl Permutation<[F; 16]>;
    fn enable(b: &mut CircuitBuilder<Self::EF>);
    fn prepare(circuit: &Circuit<Self::EF>) -> PreparedCircuitProver<SC>;
}

struct P2D4;
impl Family for P2D4 {
    type EF = EF4;
    fn cfg() -> PermConfig {
        Poseidon2Config::KOALA_BEAR_D4_W16.into()
    }
    fn native() -> impl Permutation<[F; 16]> {
        default_koalabear_poseidon2_16()
    }
    fn enable(b: &mut CircuitBuilder<EF4>) {
        b.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
            generate_poseidon2_trace::<EF4, KoalaBearD4Width16>,
            default_koalabear_poseidon2_16(),
        );
    }
    fn prepare(circuit: &Circuit<EF4>) -> PreparedCircuitProver<SC> {
        prepare::<EF4, 4>(
            circuit,
            &[Box::new(Poseidon2Preprocessor)],
            &poseidon2_air_builders::<SC, 4>(),
            |p| p.register_poseidon2_table::<4>(Poseidon2Config::KOALA_BEAR_D4_W16),
        )
    }
}

struct P1D4;
impl Family for P1D4 {
    type EF = EF4;
    fn cfg() -> PermConfig {
        Poseidon1Config::KOALA_BEAR_D4_W16.into()
    }
    fn native() -> impl Permutation<[F; 16]> {
        default_koalabear_poseidon1_16()
    }
    fn enable(b: &mut CircuitBuilder<EF4>) {
        b.enable_poseidon1_perm::<p3_circuit::ops::poseidon1_perm::KoalaBearD4Width16, _>(
            generate_poseidon1_trace::<EF4, p3_circuit::ops::poseidon1_perm::KoalaBearD4Width16>,
            default_koalabear_poseidon1_16(),
        );
    }
    fn prepare(circuit: &Circuit<EF4>) -> PreparedCircuitProver<SC> {
        prepare::<EF4, 4>(
            circuit,
            &[Box::new(Poseidon1Preprocessor)],
            &poseidon1_air_builders::<SC, 4>(),
            |p| p.register_poseidon1_table::<4>(Poseidon1Config::KOALA_BEAR_D4_W16),
        )
    }
}

/// The compact D=1 width-16 layout, inside a quintic circuit.
struct P2D1Compact;
impl Family for P2D1Compact {
    type EF = EF5;
    fn cfg() -> PermConfig {
        Poseidon2Config::KOALA_BEAR_D1_W16.into()
    }
    fn native() -> impl Permutation<[F; 16]> {
        default_koalabear_poseidon2_16()
    }
    fn enable(b: &mut CircuitBuilder<EF5>) {
        b.enable_poseidon2_perm_base::<KoalaBearD1Width16, _>(
            generate_poseidon2_trace::<EF5, KoalaBearD1Width16>,
            LiftPermToQuintic::new(default_koalabear_poseidon2_16()),
        );
    }
    fn prepare(circuit: &Circuit<EF5>) -> PreparedCircuitProver<SC> {
        prepare::<EF5, 5>(
            circuit,
            &[Box::new(Poseidon2Preprocessor)],
            &poseidon2_air_builders_d5::<SC>(),
            |p| p.register_poseidon2_table::<5>(Poseidon2Config::KOALA_BEAR_D1_W16),
        )
    }
}

/// The compact D=1 width-16 layout of the Poseidon1 AIR, inside a quintic circuit.
struct P1D1Compact;
impl Family for P1D1Compact {
    type EF = EF5;
    fn cfg() -> PermConfig {
        Poseidon1Config::KOALA_BEAR_D1_W16.into()
    }
    fn native() -> impl Permutation<[F; 16]> {
        default_koalabear_poseidon1_16()
    }
    fn enable(b: &mut CircuitBuilder<EF5>) {
        b.enable_poseidon1_perm_base::<p3_circuit::ops::poseidon1_perm::KoalaBearD1Width16, _>(
            generate_poseidon1_trace::<EF5, p3_circuit::ops::poseidon1_perm::KoalaBearD1Width16>,
            LiftPermToQuintic::new(default_koalabear_poseidon1_16()),
        );
    }
    fn prepare(circuit: &Circuit<EF5>) -> PreparedCircuitProver<SC> {
        prepare::<EF5, 5>(
            circuit,
            &[Box::new(Poseidon1Preprocessor)],
            &poseidon1_air_builders_d5::<SC>(),
            |p| p.register_poseidon1_table::<5>(Poseidon1Config::KOALA_BEAR_D1_W16),
        )
    }
}

fn merkle_cross_key<P: Family>(target: MerkleSpec) -> Result<(), String> {
    let root = honest_root(&P::native());
    let (honest, honest_ops) = build_merkle::<P::EF>(HONEST, P::cfg(), root, P::enable);
    let traces = run_merkle(&honest, &honest_ops, P::cfg()).expect("honest statement executes");

    let (circuit, ops) = build_merkle::<P::EF>(target, P::cfg(), root, P::enable);
    assert!(
        run_merkle(&circuit, &ops, P::cfg()).is_err(),
        "the target statement must be false for the honest prover"
    );
    prove_under(&P::prepare(&circuit), &traces)
}

fn assert_merkle_family<P: Family>() {
    let root = honest_root(&P::native());
    let (honest, ops) = build_merkle::<P::EF>(HONEST, P::cfg(), root, P::enable);
    let traces = run_merkle(&honest, &ops, P::cfg()).expect("honest statement executes");
    prove_under(&P::prepare(&honest), &traces).expect("honest Merkle path verifies");

    let cases = [
        (
            "changed root (control)",
            MerkleSpec {
                honest_root: false,
                ..HONEST
            },
        ),
        (
            "flipped level-0 direction bit",
            MerkleSpec {
                flip_level0_bit: true,
                ..HONEST
            },
        ),
        (
            "different leaf digest",
            MerkleSpec {
                leaf: OTHER_LEAF,
                ..HONEST
            },
        ),
        (
            "different injected digest",
            MerkleSpec {
                injected: OTHER_INJECTED,
                ..HONEST
            },
        ),
    ];
    let not_rejected: Vec<(&str, Result<(), String>)> = cases
        .into_iter()
        .map(|(name, spec)| (name, merkle_cross_key::<P>(spec)))
        .filter(|(_, result)| !rejected_by_lookups(result))
        .collect();
    assert!(
        not_rejected.is_empty(),
        "not rejected under the other circuit's key: {not_rejected:?}"
    );
}

#[test]
fn poseidon2_d4_merkle_rows_bind_bits_and_digests() {
    assert_merkle_family::<P2D4>();
}

#[test]
fn poseidon1_d4_merkle_rows_bind_bits_and_digests() {
    assert_merkle_family::<P1D4>();
}

#[test]
fn poseidon2_compact_d1_merkle_rows_bind_bits_and_digests() {
    assert_merkle_family::<P2D1Compact>();
}

#[test]
fn poseidon1_compact_d1_merkle_rows_bind_bits_and_digests() {
    assert_merkle_family::<P1D1Compact>();
}

/// A one-row sponge whose `honest` variant feeds the lanes in `seeded` explicit constants while
/// the `target` variant leaves them empty. Both variants define the same constants and connect the
/// rate output to the digest of the seeded start state.
fn sponge_start_cross_key<EF: ExtensionField<F> + ExtractBinomialW<F>>(
    cfg: Poseidon2Config,
    enable: impl Fn(&mut CircuitBuilder<EF>),
    prepare: impl Fn(&Circuit<EF>) -> PreparedCircuitProver<SC>,
    native_output: &[F],
    data_lanes: usize,
    seeded: core::ops::Range<usize>,
) -> Result<(), String> {
    let width_ext = cfg.width_ext();
    let rate_ext = cfg.rate_ext();
    let d = cfg.d();
    let build = |seed_lanes: bool| {
        let mut b = CircuitBuilder::<EF>::new();
        enable(&mut b);
        b.define_const(EF::ZERO);
        let lane_value = |lane: usize| -> Vec<F> { lane_state(lane, d, data_lanes) };
        let lanes: Vec<ExprId> = (0..width_ext)
            .map(|lane| define(&mut b, &lane_value(lane), d)[0])
            .collect();
        let outputs = define(&mut b, &native_output[..rate_ext * d], d);
        let inputs = (0..width_ext)
            .map(|lane| {
                (lane < data_lanes || (seed_lanes && seeded.contains(&lane))).then_some(lanes[lane])
            })
            .collect();
        let (_, out) = b
            .add_poseidon2_perm(&Poseidon2PermCall {
                config: cfg,
                new_start: true,
                merkle_path: false,
                mmcs_bit: None,
                mmcs_bit2: None,
                inputs,
                out_ctl: vec![true; rate_ext],
                return_all_outputs: false,
                absorb_len: 0,
            })
            .unwrap();
        for (o, e) in out.iter().take(rate_ext).zip(outputs) {
            b.connect(o.unwrap(), e);
        }
        b.build().unwrap()
    };

    let honest = build(true);
    let traces = honest.runner().run().expect("seeded start state executes");
    prove_under(&prepare(&honest), &traces).expect("seeded start state verifies under its own key");
    let target = build(false);
    assert!(
        target.runner().run().is_err(),
        "the zero-start statement must be false for the seeded digest"
    );
    prove_under(&prepare(&target), &traces)
}

/// Base elements of one start-state lane: data lanes count from 10, seeded lanes from 900.
fn lane_state(lane: usize, d: usize, data_lanes: usize) -> Vec<F> {
    let base = if lane < data_lanes { 10 } else { 900 };
    (0..d)
        .map(|j| F::from_u64(base + (lane * d + j) as u64))
        .collect()
}

fn seeded_state(lanes: usize, d: usize, data_lanes: usize) -> Vec<F> {
    (0..lanes)
        .flat_map(|lane| lane_state(lane, d, data_lanes))
        .collect()
}

#[test]
fn poseidon2_d4_sponge_start_binds_capacity() {
    let state: [F; 16] = seeded_state(4, 4, 2).try_into().unwrap();
    let output = default_koalabear_poseidon2_16().permute(state);
    let result = sponge_start_cross_key::<EF4>(
        Poseidon2Config::KOALA_BEAR_D4_W16,
        P2D4::enable,
        P2D4::prepare,
        &output,
        2,
        2..4,
    );
    assert!(
        rejected_by_lookups(&result),
        "a non-zero starting capacity was not rejected: {result:?}"
    );
}

#[test]
fn poseidon2_compact_d1_sponge_start_binds_rate_lanes() {
    let mut state: [F; 16] = seeded_state(16, 1, 3).try_into().unwrap();
    state[8..].fill(F::ZERO);
    let output = default_koalabear_poseidon2_16().permute(state);
    let result = sponge_start_cross_key::<EF5>(
        Poseidon2Config::KOALA_BEAR_D1_W16,
        P2D1Compact::enable,
        P2D1Compact::prepare,
        &output,
        3,
        3..8,
    );
    assert!(
        rejected_by_lookups(&result),
        "non-zero starting rate lanes were not rejected: {result:?}"
    );
}

#[test]
fn poseidon2_arity4_sponge_start_binds_empty_lanes() {
    let state: [F; 32] = seeded_state(8, 4, 1).try_into().unwrap();
    let output = default_koalabear_poseidon2_32().permute(state);
    let result = sponge_start_cross_key::<EF4>(
        Poseidon2Config::KOALA_BEAR_D4_W32,
        |b| {
            b.enable_poseidon2_perm_width_32::<KoalaBearD4Width32, _>(
                generate_poseidon2_trace::<EF4, KoalaBearD4Width32>,
                default_koalabear_poseidon2_32(),
            );
        },
        |circuit| {
            prepare::<EF4, 4>(
                circuit,
                &[Box::new(Poseidon2Preprocessor)],
                &poseidon2_air_builders::<SC, 4>(),
                |p| p.register_poseidon2_table::<4>(Poseidon2Config::KOALA_BEAR_D4_W32),
            )
        },
        &output,
        1,
        1..8,
    );
    assert!(
        rejected_by_lookups(&result),
        "a non-zero arity-4 starting state was not rejected: {result:?}"
    );
}
