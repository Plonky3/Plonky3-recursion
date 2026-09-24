//! Recursive verification of a `HidingFriPcs` proof whose input and FRI commit-phase
//! MMCSs are the *hiding* `MerkleTreeHidingMmcs` (per-leaf salted) variant.
//!
//! This is the configuration from <https://github.com/Plonky3/Plonky3-recursion/issues/440>:
//! both MMCSs are hiding (the upstream-recommended ZK setup), so the recursive verifier
//! must reconstruct each Merkle leaf as `[opened_row | salt]` exactly like the native
//! `MerkleTreeHidingMmcs::verify_batch`.

mod common;

#[path = "common/rejection_oracle.rs"]
mod rejection_oracle;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_batch_stark::{
    BatchVerificationError, ProverData, StarkInstance, prove_batch, verify_batch,
};
use p3_circuit::ops::{
    AluOpKind, NpoTypeId, Poseidon2Trace, generate_poseidon2_trace, generate_recompose_trace,
};
use p3_circuit::{CircuitBuilder, CircuitError, Traces, WitnessId};
use p3_circuit_prover::batch_stark_prover::{
    poseidon2_air_builders_for_configs, recompose_air_builders,
};
use p3_circuit_prover::common::{NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::{
    BatchStarkProver, CircuitProverData, ConstraintProfile, Poseidon2Preprocessor,
    RecomposePreprocessor, TablePacking,
};
use p3_commit::{ExtensionMmcs, Pcs};
use p3_field::Field;
use p3_fri::{FriParameters, HidingFriPcs, TwoAdicFriPcs};
use p3_lookup::logup::LogUpGadget;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_poseidon2_circuit_air::KoalaBearD4Width16;
use p3_recursion::pcs::fri::{
    FriVerifierParams, HidingFriProofTargets, InputProofTargets, MerkleCapTargets,
    RecExtensionValMmcs, RecValHidingMmcs, Witness,
};
use p3_recursion::pcs::{restore_hiding_fri_query_paths, set_fri_mmcs_private_data};
use p3_recursion::{
    BatchStarkVerifierInputsBuilder, OpeningTranscript, Poseidon2Config, PreparedRecursive,
    RecursivePcs, VerificationError, merge_hiding_random_openings, observe_opened_values,
    replay_batch_stark_transcript, verify_batch_circuit,
};
use p3_test_utils::koala_bear_params::*;
use rand::SeedableRng;
use rand::rngs::StdRng;
#[cfg(debug_assertions)]
use rejection_oracle::run_with_debug_oracle;
use rejection_oracle::{ProofCheckError, assert_rejected};

/// Number of random salt elements appended to each Merkle leaf by the hiding MMCS.
const SALT_ELEMS: usize = 4;

type Rng = StdRng;

// Hiding (salted) MMCSs for the inner ZK proof.
type HidingValMmcs = MerkleTreeHidingMmcs<
    <F as Field>::Packing,
    <F as Field>::Packing,
    MyHash,
    MyCompress,
    Rng,
    2,
    DIGEST_ELEMS,
    SALT_ELEMS,
>;
type HidingChallengeMmcs = ExtensionMmcs<F, Challenge, HidingValMmcs>;

// Non-ZK config used for the outer recursive proof of the verification circuit.
type MyConfig = StarkConfig<TwoAdicFriPcs<F, Dft, MyMmcs, ChallengeMmcs>, Challenge, Challenger>;

type MyPcsZk = HidingFriPcs<F, Dft, HidingValMmcs, HidingChallengeMmcs, Rng>;
type MyConfigZk = StarkConfig<MyPcsZk, Challenge, Challenger>;

type RecHidingValMmcs = RecValHidingMmcs<F, DIGEST_ELEMS, SALT_ELEMS, MyHash, MyCompress, Rng>;
type InnerFriZk = HidingFriProofTargets<
    F,
    Challenge,
    RecExtensionValMmcs<F, Challenge, DIGEST_ELEMS, RecHidingValMmcs>,
    InputProofTargets<F, Challenge, RecHidingValMmcs>,
    Witness<F>,
>;

#[derive(Clone, Copy)]
struct AddAir;

impl<Val: Field> BaseAir<Val> for AddAir {
    fn width(&self) -> usize {
        3
    }
}

impl<AB: AirBuilder> Air<AB> for AddAir
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let row = main.current_slice();
        builder.assert_zero(row[0] + row[1] - row[2]);
    }
}

fn generate_add_trace<Val: Field>(rows: usize) -> RowMajorMatrix<Val> {
    let width = 3;
    let mut values = Val::zero_vec(rows * width);
    for row in 0..rows {
        let idx = row * width;
        let a = Val::from_usize(row);
        let b = Val::from_usize(row + 1);
        values[idx] = a;
        values[idx + 1] = b;
        values[idx + 2] = a + b;
    }
    RowMajorMatrix::new(values, width)
}

fn mutate_first_restored_sibling(
    paths: &mut [p3_recursion::pcs::FriQueryPaths<F, DIGEST_ELEMS>],
) -> bool {
    for query in paths {
        for path in query.input.iter_mut().chain(&mut query.commit_phase) {
            if let Some(digest) = path.first_mut() {
                digest[0] += F::ONE;
                return true;
            }
        }
    }
    false
}

fn mutate_salt_leaf_poseidon_trace(
    traces: &mut Traces<Challenge>,
    proof: &p3_batch_stark::BatchProof<MyConfigZk>,
) {
    let opening = &proof.opening_proof.1.input_openings[0];
    let opened_rows = &opening.opened_values[0];
    let salts = &opening.opening_proof.0[0];
    assert_eq!(opened_rows.len(), salts.len());
    assert!(!opened_rows.is_empty());
    assert_eq!(salts[0].len(), SALT_ELEMS);

    let salted_leaf = opened_rows
        .iter()
        .zip(salts)
        .flat_map(|(opened, salt)| opened.iter().chain(salt))
        .copied()
        .collect::<Vec<_>>();
    let first_salt_offset = opened_rows[0].len();
    let salt_chunk_index = first_salt_offset / RATE;
    let salt_offset_in_chunk = first_salt_offset % RATE;
    let salt_chunk = salted_leaf
        .chunks(RATE)
        .nth(salt_chunk_index)
        .expect("salt coordinate belongs to one leaf-hash chunk");
    let op_type = NpoTypeId::poseidon2_perm(Poseidon2Config::KOALA_BEAR_D4_W16);
    let mut poseidon = traces
        .non_primitive_trace::<Poseidon2Trace<F>>(&op_type)
        .expect("hiding MMCS circuit emits the physical Poseidon2 table")
        .clone();
    let leaf_row = poseidon
        .operations
        .iter_mut()
        .find(|row| {
            !row.merkle_path
                && row
                    .input_values
                    .get(..salt_chunk.len())
                    .is_some_and(|prefix| prefix == salt_chunk)
        })
        .expect("the restored hiding-MMCS salt chunk is present in the Poseidon2 trace");
    assert_eq!(leaf_row.input_values[salt_offset_in_chunk], salts[0][0]);
    leaf_row.input_values[salt_offset_in_chunk] += F::ONE;
    traces
        .non_primitive_traces
        .insert(op_type, Box::new(poseidon));
}

fn mutate_salt_alu_bus_row(traces: &mut Traces<Challenge>, salt_witness: WitnessId) {
    let (row, operand) = traces
        .alu_trace
        .indices
        .iter()
        .enumerate()
        .find_map(|(row, indices)| {
            indices[..3]
                .iter()
                .position(|&index| index == salt_witness)
                .map(|operand| (row, operand))
        })
        .expect("the salt private input is consumed by an ALU packing row");
    traces.alu_trace.values[row][operand] += Challenge::ONE;
    let [a, b, c, _] = traces.alu_trace.values[row];
    traces.alu_trace.values[row][3] = match traces.alu_trace.op_kind[row] {
        AluOpKind::Add => a + b,
        AluOpKind::Mul => a * b,
        AluOpKind::MulAdd => a * b + c,
        kind => panic!("salt packing must use a locally recomputable ALU row, got {kind:?}"),
    };
}

fn prove_and_verify_outer_trace(
    prover: &BatchStarkProver<MyConfig>,
    prover_data: &CircuitProverData<MyConfig>,
    traces: &Traces<Challenge>,
) -> Result<(), ProofCheckError> {
    #[cfg(debug_assertions)]
    let result = run_with_debug_oracle(|| {
        let proof = prover
            .prove_all_tables(traces, prover_data)
            .map_err(ProofCheckError::Prove)?;
        prover
            .verify_all_tables::<Challenge>(&proof)
            .map_err(ProofCheckError::Verify)
    });

    #[cfg(not(debug_assertions))]
    let result = {
        let proof = prover
            .prove_all_tables(traces, prover_data)
            .map_err(ProofCheckError::Prove)?;
        prover
            .verify_all_tables::<Challenge>(&proof)
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

/// End-to-end recursive verification of a ZK proof committed with hiding MMCSs.
///
/// Proves an `AddAir` statement with `HidingFriPcs` + `MerkleTreeHidingMmcs`, builds and
/// runs the recursive verification circuit for that proof (exercising salted leaf
/// hashing), and finally proves the verification circuit itself.
#[test]
fn test_batch_verifier_hiding_mmcs() -> Result<(), VerificationError> {
    let air = AddAir;
    let trace = generate_add_trace::<F>(1 << 6);
    let pvs = vec![vec![]];

    // --- Step 1: Prove the AddAir with HidingFriPcs + hiding MMCSs ---
    let perm = default_koalabear_poseidon2_16();
    let hash = MyHash::new(perm.clone());
    let compress = MyCompress::new(perm.clone());
    let val_mmcs = HidingValMmcs::new(hash, compress, 0, StdRng::seed_from_u64(11));
    let challenge_mmcs = HidingChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::default();
    let fri_params = FriParameters::new_testing(challenge_mmcs, 0);
    let pcs_proving = MyPcsZk::new(dft, val_mmcs, fri_params, 2, StdRng::seed_from_u64(1));
    let challenger_proving = Challenger::new(perm);
    let config_proving = MyConfigZk::new(pcs_proving, challenger_proving);

    let instance = StarkInstance {
        air: &air,
        trace: &trace,
        public_values: pvs[0].clone(),
    };
    let instances = vec![instance];
    let prover_data = ProverData::from_instances(&config_proving, &instances);
    let common = &prover_data.common;
    let mut batch_stark_proof = prove_batch(&config_proving, &instances, &prover_data).unwrap();

    verify_batch(&config_proving, &[air], &batch_stark_proof, &pvs, common).unwrap();

    type OpeningTargets = <MyPcsZk as RecursivePcs<
        MyConfigZk,
        InputProofTargets<F, Challenge, RecHidingValMmcs>,
        InnerFriZk,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        <MyPcsZk as Pcs<Challenge, Challenger>>::Domain,
    >>::RecursiveProof;
    let _shape = OpeningTargets::input_shape(&batch_stark_proof.opening_proof)
        .expect("an honest hiding FRI proof has a capturable prepared shape");

    // --- Step 2: Build the recursive verification circuit ---
    let perm2 = default_koalabear_poseidon2_16();
    let hash2 = MyHash::new(perm2.clone());
    let compress2 = MyCompress::new(perm2.clone());
    let val_mmcs2 = HidingValMmcs::new(hash2, compress2, 0, StdRng::seed_from_u64(22));
    let challenge_mmcs2 = HidingChallengeMmcs::new(val_mmcs2.clone());
    let dft2 = Dft::default();
    let fri_params2 = FriParameters::new_testing(challenge_mmcs2, 0);
    // Enable in-circuit MMCS verification so the salted hiding leaves are actually checked.
    let fri_verifier_params = FriVerifierParams::with_mmcs(
        fri_params2.log_blowup,
        fri_params2.log_final_poly_len,
        fri_params2.max_log_arity,
        fri_params2.commit_proof_of_work_bits,
        fri_params2.query_proof_of_work_bits,
        fri_params2.num_queries,
        Poseidon2Config::KOALA_BEAR_D4_W16,
    );
    let pcs_verif = MyPcsZk::new(dft2, val_mmcs2, fri_params2, 2, StdRng::seed_from_u64(2));
    let challenger_verif = Challenger::new(perm2.clone());
    let config = MyConfigZk::new(pcs_verif, challenger_verif);

    let mut circuit_builder = CircuitBuilder::new();
    circuit_builder.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
        generate_poseidon2_trace::<Challenge, KoalaBearD4Width16>,
        perm2,
    );
    circuit_builder.enable_recompose::<F>(generate_recompose_trace::<F, Challenge>);

    let lookup_gadget = LogUpGadget::new();
    let air_public_counts = vec![0usize; batch_stark_proof.opened_values.instances.len()];
    let verifier_inputs = BatchStarkVerifierInputsBuilder::<
        MyConfigZk,
        MerkleCapTargets<F, DIGEST_ELEMS>,
        InnerFriZk,
    >::allocate(
        &mut circuit_builder,
        &batch_stark_proof,
        common,
        &air_public_counts,
    )?;
    let mmcs_op_ids = verify_batch_circuit::<_, _, _, _, _, _, _, WIDTH, RATE>(
        &config,
        &[air],
        &mut circuit_builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &fri_verifier_params,
        &verifier_inputs.common_data,
        &lookup_gadget,
        Poseidon2Config::KOALA_BEAR_D4_W16,
    )?;

    let verification_circuit = circuit_builder.build().unwrap();
    let (public_inputs, private_inputs) =
        verifier_inputs.pack_values(&pvs, &batch_stark_proof, common);
    assert_eq!(public_inputs.len(), verification_circuit.public_flat_len);

    // --- Step 3: Run the verification circuit ---
    let mut verification_runner = verification_circuit.runner();
    verification_runner
        .set_public_inputs(&public_inputs)
        .unwrap();
    verification_runner
        .set_private_inputs(&private_inputs)
        .unwrap();

    // The hiding MMCS opening proof is `(salts, pruned paths)`; the salts are circuit private
    // inputs (set above), while the sibling digests are MMCS private data set here. Restoring
    // them means re-salting each leaf exactly as the hiding tree committed it, and that needs the
    // plain tree the hiding wrapper is built over — which a `MerkleTreeHidingMmcs` does not
    // expose, so it is rebuilt here from the same hasher, compression function and cap height.
    assert!(
        !mmcs_op_ids.is_empty(),
        "hiding MMCS test must exercise Merkle openings"
    );
    let OpeningTranscript {
        mut challenger,
        mut commitments_with_opening_points,
    } = replay_batch_stark_transcript(
        &[air],
        &config,
        &batch_stark_proof,
        &pvs,
        common,
        &lookup_gadget,
    )
    .expect("the proof's transcript replays")
    .0;
    merge_hiding_random_openings::<MyConfigZk>(
        &mut commitments_with_opening_points,
        &batch_stark_proof.opening_proof.0,
    )
    .expect("the random openings match the public ones");
    observe_opened_values::<MyConfigZk>(&mut challenger, &commitments_with_opening_points);

    let restore_perm = default_koalabear_poseidon2_16();
    let restore_hiding_mmcs = HidingValMmcs::new(
        MyHash::new(restore_perm.clone()),
        MyCompress::new(restore_perm.clone()),
        0,
        StdRng::seed_from_u64(33),
    );
    let restore_tree = MyMmcs::new(
        MyHash::new(restore_perm.clone()),
        MyCompress::new(restore_perm),
        0,
    );
    let restore_fri_params =
        FriParameters::new_testing(HidingChallengeMmcs::new(restore_hiding_mmcs.clone()), 0);
    let query_paths = restore_hiding_fri_query_paths(
        &restore_fri_params,
        &restore_hiding_mmcs,
        &restore_tree,
        &restore_tree,
        &batch_stark_proof.opening_proof.1,
        &mut challenger,
        &commitments_with_opening_points,
    )
    .expect("an honest proof's salted Merkle paths restore");
    set_fri_mmcs_private_data::<F, Challenge, DIGEST_ELEMS>(
        &mut verification_runner,
        &mmcs_op_ids,
        &query_paths,
        Poseidon2Config::KOALA_BEAR_D4_W16,
    )
    .expect("Failed to set MMCS private data for hiding ZK proof");

    let verification_traces = verification_runner.run().unwrap();

    // Mutate exactly input-batch 0, query 0, matrix 0, salt coordinate 0. The commitment,
    // statement, common data and AIR are unchanged. Native verification must reject the same
    // proof before we reuse its private-value packing against the already-built circuit.
    let honest_private_inputs = private_inputs.clone();
    let salt = &mut batch_stark_proof.opening_proof.1.input_openings[0]
        .opening_proof
        .0[0][0][0];
    let honest_salt = *salt;
    *salt += F::ONE;
    let native_error = verify_batch(&config_proving, &[air], &batch_stark_proof, &pvs, common)
        .expect_err("a one-coordinate salt mutation must fail native verification");
    assert!(matches!(
        native_error,
        BatchVerificationError::Verification(
            p3_uni_stark::VerificationError::InvalidOpeningArgument(_)
        )
    ));
    let (mutated_public_inputs, mutated_private_inputs) =
        verifier_inputs.pack_values(&pvs, &batch_stark_proof, common);
    batch_stark_proof.opening_proof.1.input_openings[0]
        .opening_proof
        .0[0][0][0] = honest_salt;
    assert_eq!(mutated_public_inputs, public_inputs);
    let changed_private_indices = honest_private_inputs
        .iter()
        .zip(&mutated_private_inputs)
        .enumerate()
        .filter_map(|(index, (honest, mutated))| (honest != mutated).then_some(index))
        .collect::<Vec<_>>();
    assert_eq!(
        changed_private_indices.len(),
        1,
        "salt-only mutation must change exactly one circuit-private coordinate"
    );
    let mutated_salt_private_index = changed_private_indices[0];

    let mut salt_runner = verification_circuit.runner();
    salt_runner.set_public_inputs(&public_inputs).unwrap();
    salt_runner
        .set_private_inputs(&mutated_private_inputs)
        .unwrap();
    set_fri_mmcs_private_data::<F, Challenge, DIGEST_ELEMS>(
        &mut salt_runner,
        &mmcs_op_ids,
        &query_paths,
        Poseidon2Config::KOALA_BEAR_D4_W16,
    )
    .expect("honest restored paths populate the salt-mutation runner");
    assert!(matches!(
        salt_runner.run(),
        Err(CircuitError::WitnessConflict { .. })
    ));

    // The path mutation is independent: use the honest proof/private inputs and change exactly
    // one coefficient in one already-restored sibling digest. Host restoration is deliberately
    // complete before this mutation, so rejection comes from the recursive Merkle check.
    let mut mutated_paths = query_paths.clone();
    assert!(
        mutate_first_restored_sibling(&mut mutated_paths),
        "genuine hiding-MMCS fixture must contain a restored sibling"
    );
    let mut sibling_runner = verification_circuit.runner();
    sibling_runner.set_public_inputs(&public_inputs).unwrap();
    sibling_runner
        .set_private_inputs(&honest_private_inputs)
        .unwrap();
    set_fri_mmcs_private_data::<F, Challenge, DIGEST_ELEMS>(
        &mut sibling_runner,
        &mmcs_op_ids,
        &mutated_paths,
        Poseidon2Config::KOALA_BEAR_D4_W16,
    )
    .expect("mutated restored path has the honest path shape");
    assert!(matches!(
        sibling_runner.run(),
        Err(CircuitError::WitnessConflict { .. })
    ));

    // --- Step 4: Prove the verification circuit itself (non-ZK outer proof) ---
    let perm3 = default_koalabear_poseidon2_16();
    let hash3 = MyHash::new(perm3.clone());
    let compress3 = MyCompress::new(perm3.clone());
    let val_mmcs3 = MyMmcs::new(hash3, compress3, 0);
    let challenge_mmcs3 = ChallengeMmcs::new(val_mmcs3.clone());
    let dft3 = Dft::default();
    let fri_params3 = FriParameters::new_testing(challenge_mmcs3, 0);
    let pcs3 = TwoAdicFriPcs::new(dft3, val_mmcs3, fri_params3);
    let challenger3 = Challenger::new(perm3);
    let config3 = MyConfig::new(pcs3, challenger3);

    let verification_table_packing = TablePacking::new(1, 8);
    let poseidon2_config = Poseidon2Config::KOALA_BEAR_D4_W16;
    let npo_prep: Vec<Box<dyn NpoPreprocessor<F>>> = vec![
        Box::new(Poseidon2Preprocessor),
        Box::new(RecomposePreprocessor::new(true)),
    ];
    let mut air_builders = poseidon2_air_builders_for_configs::<_, 4>(vec![
        poseidon2_config.for_challenger(),
        poseidon2_config,
    ]);
    air_builders.extend(recompose_air_builders(1, true));
    let (
        verification_airs_degrees,
        verification_primitive_columns,
        verification_non_primitive_columns,
    ) = get_airs_and_degrees_with_prep::<MyConfig, _, 4>(
        &verification_circuit,
        &verification_table_packing,
        &npo_prep,
        &air_builders,
        ConstraintProfile::Standard,
    )
    .unwrap();
    let (verification_airs, verification_degrees): (Vec<_>, Vec<usize>) =
        verification_airs_degrees.into_iter().unzip();

    let verification_prover_data =
        ProverData::from_airs_and_degrees(&config3, &verification_airs, &verification_degrees)
            .unwrap();
    let verification_circuit_prover_data = CircuitProverData::new(
        verification_prover_data,
        verification_primitive_columns,
        verification_non_primitive_columns,
    );

    let mut verification_prover =
        BatchStarkProver::new(config3).with_table_packing(verification_table_packing);
    verification_prover.register_poseidon2_table::<4>(poseidon2_config.for_challenger());
    verification_prover.register_poseidon2_table::<4>(poseidon2_config);
    verification_prover.register_recompose_table::<4>(true);

    let verification_proof = verification_prover
        .prove_all_tables(&verification_traces, &verification_circuit_prover_data)
        .expect("Failed to prove hiding-MMCS verification circuit");

    verification_prover
        .verify_all_tables::<Challenge>(&verification_proof)
        .expect("Failed to verify proof of hiding-MMCS verification circuit");

    let mut local_air_mutation = verification_traces.clone();
    mutate_salt_leaf_poseidon_trace(&mut local_air_mutation, &batch_stark_proof);
    let local_result = prove_and_verify_outer_trace(
        &verification_prover,
        &verification_circuit_prover_data,
        &local_air_mutation,
    );
    #[cfg(debug_assertions)]
    assert!(matches!(
        &local_result,
        Err(ProofCheckError::DebugPanic(
            rejection_oracle::DebugRejectionKind::Constraint
        ))
    ));
    assert_rejected(
        &local_result,
        "a changed salt coefficient in the physical leaf-hash row",
    );

    let salt_witness = verification_circuit.private_input_rows[mutated_salt_private_index];
    let mut global_lookup_mutation = verification_traces;
    mutate_salt_alu_bus_row(&mut global_lookup_mutation, salt_witness);
    let global_result = prove_and_verify_outer_trace(
        &verification_prover,
        &verification_circuit_prover_data,
        &global_lookup_mutation,
    );
    #[cfg(debug_assertions)]
    assert!(
        matches!(
            &global_result,
            Err(ProofCheckError::DebugPanic(
                rejection_oracle::DebugRejectionKind::Lookup
            ))
        ),
        "salt witness-only mutation must reach the global lookup oracle, got {global_result:?}"
    );
    assert_rejected(
        &global_result,
        "a changed salt witness disconnected from the honest physical leaf-hash row",
    );

    Ok(())
}
