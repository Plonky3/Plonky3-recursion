//! Proof-level binding tests for the fixed-key binary MMCS coefficient path.
//!
//! The fixtures commit honest base-field rows with the native binary MMCS, then feed the
//! resulting cap and opened row to the public `verify_batch_circuit` entry point.  Mutations are
//! run through an edited circuit but proved with the honest circuit's `CircuitProverData`: this
//! is the fixed-key boundary a prover attack must cross.

#[path = "common/rejection_oracle.rs"]
mod rejection_oracle;

use p3_circuit::ops::recompose::RecomposeTrace;
use p3_circuit::ops::{
    NpoTypeId, Op, Poseidon2Config, Poseidon2Trace, generate_poseidon2_trace,
    generate_recompose_trace,
};
use p3_circuit::tables::Traces;
use p3_circuit::{Circuit, CircuitBuilder, WitnessId};
use p3_circuit_prover::batch_stark_prover::{
    poseidon2_air_builders_for_configs, recompose_air_builders,
};
use p3_circuit_prover::common::NpoPreprocessor;
use p3_circuit_prover::config::KoalaBearConfig;
use p3_circuit_prover::{
    BatchStarkProver, ConstraintProfile, Poseidon2Preprocessor, RecomposePreprocessor,
    TablePacking, config,
};
use p3_commit::{BatchOpeningRef, Mmcs};
use p3_field::extension::BinomialExtensionField;
use p3_field::{BasedVectorSpace, PrimeCharacteristicRing};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_poseidon2_circuit_air::KoalaBearD4Width16;
use p3_recursion::pcs::verify_batch_circuit;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
#[cfg(debug_assertions)]
use rejection_oracle::run_with_debug_oracle;
use rejection_oracle::{ProofCheckError, assert_rejected};

type F = KoalaBear;
type EF = BinomialExtensionField<F, 4>;
type Perm = Poseidon2KoalaBear<16>;
type LeafHash = PaddingFreeSponge<Perm, 16, 8, 8>;
type Compress = TruncatedPermutation<Perm, 2, 8, 16>;
type BinaryMmcs = MerkleTreeMmcs<F, F, LeafHash, Compress, 2, 8>;

const D: usize = 4;
const CFG: Poseidon2Config = Poseidon2Config::KOALA_BEAR_D4_W16;

#[derive(Clone)]
struct Fixture {
    circuit: Circuit<EF>,
    public_inputs: Vec<EF>,
    opened: Vec<F>,
    traces: Traces<EF>,
}

fn is_npo(op: &Op<EF>, needle: &str) -> bool {
    match op {
        Op::NonPrimitiveOpWithExecutor { executor, .. } => {
            format!("{:?}", executor.op_type()).contains(needle)
        }
        _ => false,
    }
}

fn npo_io(circuit: &Circuit<EF>, pos: usize) -> (Vec<Vec<WitnessId>>, Vec<Vec<WitnessId>>) {
    match &circuit.ops[pos] {
        Op::NonPrimitiveOpWithExecutor {
            inputs, outputs, ..
        } => (inputs.clone(), outputs.clone()),
        _ => panic!("op {pos} is not a non-primitive op"),
    }
}

fn perm_positions(circuit: &Circuit<EF>) -> Vec<usize> {
    circuit
        .ops
        .iter()
        .enumerate()
        .filter_map(|(i, op)| is_npo(op, "poseidon2_perm").then_some(i))
        .collect()
}

fn recompose_positions(circuit: &Circuit<EF>) -> Vec<usize> {
    circuit
        .ops
        .iter()
        .enumerate()
        .filter_map(|(i, op)| is_npo(op, "recompose").then_some(i))
        .collect()
}

fn build_fixture(width: usize) -> Fixture {
    assert!(matches!(width, 8 | 10));
    let perm = default_koalabear_poseidon2_16();
    let leaf_hash = LeafHash::new(perm.clone());
    let compress = Compress::new(perm);
    let mmcs = BinaryMmcs::new(leaf_hash, compress, 0);
    let opened: Vec<F> = (0..width as u64).map(|i| F::from_u64(100 + i)).collect();
    let matrix = RowMajorMatrix::new(opened.clone(), width);
    let dimensions = [matrix.dimensions()];
    let (commitment, prover_data) = mmcs.commit(vec![matrix]);
    let opening = mmcs.open_batch(0, &prover_data);
    mmcs.verify_batch(
        &commitment,
        &dimensions,
        0,
        BatchOpeningRef::new(&opening.opened_values, &opening.opening_proof),
    )
    .expect("native opening verifies against its cap");

    let mut builder = CircuitBuilder::<EF>::new();
    builder.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
        generate_poseidon2_trace::<EF, KoalaBearD4Width16>,
        default_koalabear_poseidon2_16(),
    );
    builder.enable_recompose::<F>(generate_recompose_trace::<F, EF>);

    let cap = commitment
        .roots()
        .iter()
        .map(|root| {
            root.chunks(D)
                .map(|_| builder.public_input())
                .collect::<Vec<_>>()
        })
        .collect::<Vec<_>>();
    let opened_targets = vec![
        (0..width)
            .map(|_| builder.public_input())
            .collect::<Vec<_>>(),
    ];
    verify_batch_circuit::<F, EF>(
        &mut builder,
        CFG,
        &cap,
        &dimensions,
        &[],
        &opened_targets,
        None,
    )
    .expect("verify_batch_circuit builds");
    let circuit = builder.build().expect("MMCS circuit builds");

    let mut public_inputs = commitment
        .roots()
        .iter()
        .flat_map(|root| {
            root.chunks(D).map(|coeffs| {
                EF::from_basis_coefficients_slice(coeffs).expect("cap packs into extension")
            })
        })
        .collect::<Vec<_>>();
    public_inputs.extend(opened.iter().copied().map(EF::from));
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(&public_inputs)
        .expect("fixture public inputs");
    let traces = runner
        .run()
        .expect("honest MMCS witness generation succeeds");

    Fixture {
        circuit,
        public_inputs,
        opened,
        traces,
    }
}

fn recompose_trace(traces: &Traces<EF>) -> RecomposeTrace<F> {
    traces
        .non_primitive_trace::<RecomposeTrace<F>>(&NpoTypeId::recompose_with_coeff_lookups())
        .expect("coefficient-bound recompose trace")
        .clone()
}

fn poseidon_trace(traces: &Traces<EF>) -> Poseidon2Trace<F> {
    traces
        .non_primitive_trace::<Poseidon2Trace<F>>(&NpoTypeId::poseidon2_perm(CFG))
        .expect("MMCS Poseidon2 trace")
        .clone()
}

/// Forge one full leaf packer in the proof trace while retaining the honest operation metadata.
/// This avoids `CircuitRunner`'s intentional conflict when a changed Poseidon output is wired to
/// the trusted public cap: a prover assembling trace polynomials can choose the row values, but
/// the fixed key still carries the honest coefficient witness indices and native cap trace.
fn forge_full_pack_trace(fixture: &Fixture, target_row: usize, donor_row: usize) -> Traces<EF> {
    let mut traces = fixture.traces.clone();
    let mut recomposes = recompose_trace(&traces);
    let donor_values = recomposes.operations[donor_row].values.clone();
    recomposes.operations[target_row].values = donor_values.clone();
    traces.non_primitive_traces.insert(
        NpoTypeId::recompose_with_coeff_lookups(),
        Box::new(recomposes),
    );

    let mut permutation = poseidon_trace(&traces);
    let start = target_row * D;
    permutation.operations[0].input_values[start..start + D].copy_from_slice(&donor_values);
    traces
        .non_primitive_traces
        .insert(NpoTypeId::poseidon2_perm(CFG), Box::new(permutation));
    traces
}

/// Forge the partial carry's canonical base-field projection after a non-base weighted-sum
/// cancellation. The source-level extension coefficients satisfy the unchanged weighted sum,
/// while the coefficient table sees the changed base projection of the final carry slot.
fn forge_partial_carry_trace(fixture: &Fixture, shift: u64) -> Traces<EF> {
    let mut traces = fixture.traces.clone();
    let mut recomposes = recompose_trace(&traces);
    assert!(
        recomposes.operations.len() >= 4,
        "partial leaf has carry and pack rows"
    );
    let carry_row = 2;
    let source = recomposes.operations[carry_row].values.clone();
    let source_ext = source.iter().copied().map(EF::from).collect::<Vec<_>>();
    let mut forged = source_ext.clone();
    forged[2] += EF::from_u64(shift) * basis(1);
    forged[3] -= EF::from_u64(shift);
    assert_eq!(weighted_sum(&forged), weighted_sum(&source_ext));
    recomposes.operations[carry_row].values = forged
        .iter()
        .map(|value| <EF as BasedVectorSpace<F>>::as_basis_coefficients_slice(value)[0])
        .collect();
    traces.non_primitive_traces.insert(
        NpoTypeId::recompose_with_coeff_lookups(),
        Box::new(recomposes),
    );

    let mut permutation = poseidon_trace(&traces);
    let mut changed = permutation.operations[1].input_values.clone();
    // The second absorb's first extension limb contains two fresh coefficients and the two
    // canonicalized carry coefficients. The carry row's changed c3 is its fourth base slot.
    changed[3] -= F::from_u64(shift);
    permutation.operations[1].input_values = changed;
    traces
        .non_primitive_traces
        .insert(NpoTypeId::poseidon2_perm(CFG), Box::new(permutation));
    traces
}

fn assert_honest_public_trace(honest: &Traces<EF>, forged: &Traces<EF>) {
    assert_eq!(
        honest.public_trace.index, forged.public_trace.index,
        "forged trace must retain the honest public-input witness layout"
    );
    assert_eq!(
        honest.public_trace.values, forged.public_trace.values,
        "forged trace must retain the honest native cap/opened public-input values"
    );
}

/// Prove `traces` against `circuit`'s original constraint system and verify its proof.
fn prove_and_verify(circuit: &Circuit<EF>, traces: &Traces<EF>) -> Result<(), ProofCheckError> {
    let table_packing = TablePacking::new(1, 1);
    let stark_config = config::koala_bear();
    let npo_preprocessors: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
        Box::new(Poseidon2Preprocessor),
        Box::new(RecomposePreprocessor::new(true)),
    ];
    let mut air_builders = poseidon2_air_builders_for_configs::<KoalaBearConfig, D>(vec![CFG]);
    air_builders.extend(recompose_air_builders::<KoalaBearConfig, D>(1, true));
    let mut prover = BatchStarkProver::new(stark_config).with_table_packing(table_packing);
    prover.register_poseidon2_table::<D>(CFG);
    prover.register_recompose_table::<D>(true);
    let prepared = prover
        .prepare_circuit::<EF, D>(
            circuit,
            &npo_preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("trusted fixed-key circuit preparation");
    let verifier = prepared.verifier();

    #[cfg(debug_assertions)]
    let result = run_with_debug_oracle(|| {
        let proof = prepared.prove(traces).map_err(ProofCheckError::Prove)?;
        verifier
            .verify(&proof, &[])
            .map_err(ProofCheckError::Verify)
    });

    #[cfg(not(debug_assertions))]
    let result = {
        let proof = prepared.prove(traces).map_err(ProofCheckError::Prove)?;
        verifier
            .verify(&proof, &[])
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

fn assert_same_constraint_system(honest: &Circuit<EF>, edited: &Circuit<EF>) {
    assert_eq!(honest.witness_count, edited.witness_count);
}

fn basis(i: usize) -> EF {
    let mut coeffs = [F::ZERO; D];
    coeffs[i] = F::ONE;
    EF::from_basis_coefficients_slice(&coeffs).expect("basis coefficient is valid")
}

fn weighted_sum(coeffs: &[EF]) -> EF {
    coeffs
        .iter()
        .enumerate()
        .map(|(i, &coeff)| coeff * basis(i))
        .sum()
}

#[test]
fn honest_full_and_partial_base_leaves_prove_and_verify() {
    for width in [8, 10] {
        let fixture = build_fixture(width);
        assert_eq!(fixture.opened.len(), width);
        assert_eq!(fixture.public_inputs.len(), width + 2);
        assert!(!perm_positions(&fixture.circuit).is_empty());
        prove_and_verify(&fixture.circuit, &fixture.traces)
            .unwrap_or_else(|error| panic!("honest width-{width} proof must verify: {error}"));
    }
}

#[test]
fn leaf_hash_packing_uses_coefficient_bound_rows() {
    let fixture = build_fixture(8);
    let perms = perm_positions(&fixture.circuit);
    let (inputs, _) = npo_io(&fixture.circuit, perms[0]);
    let packers = recompose_positions(&fixture.circuit);
    assert_eq!(packers.len(), 2, "full leaf has two packed extension limbs");
    assert!(
        packers.iter().all(|&pos| {
            matches!(&fixture.circuit.ops[pos], Op::NonPrimitiveOpWithExecutor { inputs, .. }
                if inputs.iter().all(|group| group.len() == D))
        }),
        "each leaf limb must expose all D coefficient witnesses"
    );
    assert!(
        inputs.iter().take(2).all(|limb| {
            packers.iter().any(|&pos| match &fixture.circuit.ops[pos] {
                Op::NonPrimitiveOpWithExecutor { outputs, .. } => outputs[0][0] == limb[0],
                _ => false,
            })
        }),
        "the first permutation must consume the coefficient-bound packing rows"
    );
}

#[test]
fn full_leaf_coefficient_replacement_is_rejected_with_honest_key() {
    let fixture = build_fixture(8);
    let packers = recompose_positions(&fixture.circuit);
    assert_eq!(packers.len(), 2);
    let (donor_inputs, _) = npo_io(&fixture.circuit, packers[1]);
    let (target_inputs, _) = npo_io(&fixture.circuit, packers[0]);
    assert_ne!(target_inputs, donor_inputs);

    let mut edited = fixture.circuit.clone();
    match &mut edited.ops[packers[0]] {
        Op::NonPrimitiveOpWithExecutor { inputs, .. } => *inputs = donor_inputs,
        _ => unreachable!(),
    }
    assert_same_constraint_system(&fixture.circuit, &edited);
    assert_ne!(
        fixture
            .circuit
            .generate_preprocessed_columns::<D>()
            .unwrap(),
        edited.generate_preprocessed_columns::<D>().unwrap(),
        "coefficient-row rewiring must change the verifier-fixed key"
    );
    let honest_perm = poseidon_trace(&fixture.traces);
    let forged = forge_full_pack_trace(&fixture, 0, 1);
    let forged_perm = poseidon_trace(&forged);
    assert_ne!(
        forged_perm.operations[0].input_values, honest_perm.operations[0].input_values,
        "rewiring a full leaf packer must change the authenticated leaf input"
    );
    assert_honest_public_trace(&fixture.traces, &forged);
    assert_rejected(
        &prove_and_verify(&fixture.circuit, &forged),
        "a full leaf coefficient replacement must fail against the trusted key",
    );
}

#[test]
fn repeated_full_leaf_coefficients_are_rejected_with_honest_key() {
    let fixture = build_fixture(8);
    let packers = recompose_positions(&fixture.circuit);
    assert_eq!(packers.len(), 2);
    let (donor_inputs, _) = npo_io(&fixture.circuit, packers[0]);

    let mut edited = fixture.circuit.clone();
    match &mut edited.ops[packers[1]] {
        Op::NonPrimitiveOpWithExecutor { inputs, .. } => *inputs = donor_inputs,
        _ => unreachable!(),
    }
    assert_same_constraint_system(&fixture.circuit, &edited);
    assert_ne!(
        fixture
            .circuit
            .generate_preprocessed_columns::<D>()
            .unwrap(),
        edited.generate_preprocessed_columns::<D>().unwrap(),
        "repeated coefficient rows must not be hidden from the verifier key"
    );
    let honest_perm = poseidon_trace(&fixture.traces);
    let forged = forge_full_pack_trace(&fixture, 1, 0);
    let forged_perm = poseidon_trace(&forged);
    assert_ne!(
        forged_perm.operations[0].input_values, honest_perm.operations[0].input_values,
        "repeating a coefficient group must change the authenticated leaf input"
    );
    assert_honest_public_trace(&fixture.traces, &forged);
    assert_rejected(
        &prove_and_verify(&fixture.circuit, &forged),
        "repeated full-leaf coefficients must fail against the trusted key",
    );
}

#[test]
fn partial_carry_non_base_cancellation_is_rejected_with_honest_key() {
    let fixture = build_fixture(10);
    let honest_perm = poseidon_trace(&fixture.traces);
    let forged = forge_partial_carry_trace(&fixture, 7);
    let forged_perm = poseidon_trace(&forged);
    assert_honest_public_trace(&fixture.traces, &forged);
    assert_ne!(
        forged_perm.operations[1].input_values, honest_perm.operations[1].input_values,
        "canonicalizing the non-base cancellation must change the partial leaf input"
    );

    assert_rejected(
        &prove_and_verify(&fixture.circuit, &forged),
        "non-base weighted-sum cancellation must not forge a partial leaf",
    );
}
