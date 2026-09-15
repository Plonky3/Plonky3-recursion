//! Proof-level binding tests for the fixed-key binary MMCS coefficient path.
//!
//! The fixtures commit honest base-field rows with the native binary MMCS, then feed the
//! resulting cap and opened row to the public `verify_batch_circuit` entry point.  Mutations are
//! run through an edited circuit but proved with the honest circuit's `CircuitProverData`: this
//! is the fixed-key boundary a prover attack must cross.

#[path = "common/rejection_oracle.rs"]
mod rejection_oracle;

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

fn run(circuit: &Circuit<EF>, public_inputs: &[EF]) -> Traces<EF> {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public_inputs)
        .expect("fixture public inputs");
    runner.run().expect("MMCS witness generation succeeds")
}

fn witness_values(circuit: &Circuit<EF>, public_inputs: &[EF]) -> Vec<Option<EF>> {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public_inputs)
        .expect("fixture public inputs");
    runner
        .execute_all()
        .expect("MMCS witness execution succeeds");
    runner.witness().to_vec()
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
    let (airs_degrees, primitive_columns, non_primitive_columns) =
        get_airs_and_degrees_with_prep::<KoalaBearConfig, EF, D>(
            circuit,
            &table_packing,
            &npo_preprocessors,
            &air_builders,
            ConstraintProfile::Standard,
        )
        .expect("fixed-key preprocessed columns");
    let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
    let prover_data = ProverData::from_airs_and_degrees(&stark_config, &airs, &degrees);
    let circuit_prover_data =
        CircuitProverData::new(prover_data, primitive_columns, non_primitive_columns);
    let mut prover = BatchStarkProver::new(stark_config).with_table_packing(table_packing);
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

fn base_decomposition(value: EF) -> Vec<EF> {
    <EF as BasedVectorSpace<F>>::as_basis_coefficients_slice(&value)
        .iter()
        .copied()
        .map(EF::from)
        .collect()
}

fn is_base(value: EF) -> bool {
    <EF as BasedVectorSpace<F>>::as_basis_coefficients_slice(&value)[1..]
        .iter()
        .all(|coefficient| *coefficient == F::ZERO)
}

/// Replace a decomposition hint with a prover-controlled non-base pair whose weighted sum is
/// unchanged. The two changed coefficient witnesses are the carry slots of the second partial
/// absorb in the width-10 fixture.
#[derive(Clone, Debug)]
struct NonBaseCarryShift(u64);

impl HintExecutor<EF> for NonBaseCarryShift {
    fn execute(
        &self,
        inputs: &[WitnessId],
        outputs: &[WitnessId],
        witness: &mut [Option<EF>],
    ) -> Result<(), CircuitError> {
        assert_eq!(inputs.len(), 1);
        assert_eq!(outputs.len(), D);
        let source = witness[inputs[0].0 as usize].expect("carry source is witnessed");
        let mut coeffs = base_decomposition(source);
        let shift = EF::from_u64(self.0);
        // The pair carries the two positions unused by the partial second absorb. Their changes
        // cancel in c2*w^2 + c3*w^3, but each is no longer a base-field element.
        coeffs[2] += shift * basis(1);
        coeffs[3] -= shift;
        assert_eq!(weighted_sum(&coeffs), source);
        for (&output, &value) in outputs.iter().zip(&coeffs) {
            witness[output.0 as usize] = Some(value);
        }
        Ok(())
    }

    fn boxed(&self) -> Box<dyn HintExecutor<EF>> {
        Box::new(self.clone())
    }
}

fn carry_hint_position(circuit: &Circuit<EF>) -> usize {
    let perms = perm_positions(circuit);
    assert!(
        perms.len() >= 2,
        "partial fixture must absorb in two permutations"
    );
    let (_, first_outputs) = npo_io(circuit, perms[0]);
    let carry_source = first_outputs[0][0];
    circuit
        .ops
        .iter()
        .enumerate()
        .find(|(_, op)| {
            matches!(
                op,
                Op::Hint { inputs, outputs, .. }
                    if inputs == &[carry_source] && outputs.len() == D
            )
        })
        .map(|(pos, _)| pos)
        .expect("partial carry decomposition hint")
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
    let (target_inputs, target_outputs) = npo_io(&fixture.circuit, packers[0]);
    assert_ne!(target_inputs, donor_inputs);
    let target_limb = target_outputs[0][0];

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
    let honest_witness = {
        let mut runner = fixture.circuit.runner();
        runner.set_public_inputs(&fixture.public_inputs).unwrap();
        runner.execute_all().unwrap();
        runner.witness().to_vec()
    };
    let edited_witness = {
        let mut runner = edited.runner();
        runner.set_public_inputs(&fixture.public_inputs).unwrap();
        runner.execute_all().unwrap();
        runner.witness().to_vec()
    };
    assert_ne!(
        edited_witness[target_limb.0 as usize], honest_witness[target_limb.0 as usize],
        "rewiring a full leaf packer must change the authenticated limb"
    );
    let forged = run(&edited, &fixture.public_inputs);
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
    let honest_witness = witness_values(&fixture.circuit, &fixture.public_inputs);
    let edited_witness = witness_values(&edited, &fixture.public_inputs);
    let (_, target_outputs) = npo_io(&fixture.circuit, packers[1]);
    assert_ne!(
        edited_witness[target_outputs[0][0].0 as usize],
        honest_witness[target_outputs[0][0].0 as usize],
        "repeating a coefficient group must change the second authenticated limb"
    );
    assert_rejected(
        &prove_and_verify(&fixture.circuit, &run(&edited, &fixture.public_inputs)),
        "repeated full-leaf coefficients must fail against the trusted key",
    );
}

#[test]
fn partial_carry_non_base_cancellation_is_rejected_with_honest_key() {
    let fixture = build_fixture(10);
    let hint_pos = carry_hint_position(&fixture.circuit);
    let mut edited = fixture.circuit.clone();
    match &mut edited.ops[hint_pos] {
        Op::Hint { executor, .. } => *executor = Box::new(NonBaseCarryShift(7)),
        _ => unreachable!(),
    }
    assert_same_constraint_system(&fixture.circuit, &edited);
    assert_eq!(
        fixture
            .circuit
            .generate_preprocessed_columns::<D>()
            .unwrap(),
        edited.generate_preprocessed_columns::<D>().unwrap(),
        "hint tampering must keep the trusted key fixed"
    );

    let honest_witness = witness_values(&fixture.circuit, &fixture.public_inputs);
    let edited_witness = witness_values(&edited, &fixture.public_inputs);
    let perms = perm_positions(&fixture.circuit);
    let (second_inputs, _) = npo_io(&fixture.circuit, perms[1]);
    let hint_outputs = match &fixture.circuit.ops[hint_pos] {
        Op::Hint { outputs, .. } => outputs.clone(),
        _ => unreachable!(),
    };
    assert_ne!(
        edited_witness[hint_outputs[2].0 as usize], honest_witness[hint_outputs[2].0 as usize],
        "the carry hint mutation must change a coefficient witness"
    );
    assert!(
        !is_base(edited_witness[hint_outputs[2].0 as usize].expect("edited carry witness")),
        "the cancellation must use a genuinely non-base coefficient"
    );
    assert_eq!(
        edited_witness[second_inputs[0][0].0 as usize],
        honest_witness[second_inputs[0][0].0 as usize],
        "weighted-sum cancellation must leave the authenticated extension limb unchanged"
    );

    assert_rejected(
        &prove_and_verify(&fixture.circuit, &run(&edited, &fixture.public_inputs)),
        "non-base weighted-sum cancellation must not forge a partial leaf",
    );
}
