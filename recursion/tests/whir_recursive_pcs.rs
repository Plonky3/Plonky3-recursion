mod common;

use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_commit::Pcs;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Dimensions;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::pcs::fri::MerkleCapTargets;
use p3_recursion::pcs::whir::uni::{WhirUniProofTargets, WhirUniVerifierParams};
use p3_recursion::pcs::{restore_whir_query_paths, set_whir_mmcs_private_data};
use p3_recursion::public_inputs::StarkVerifierInputsBuilder;
use p3_recursion::traits::RecursivePcs;
use p3_recursion::{Poseidon2Config, VerificationError, verify_p3_uni_proof_circuit};
use p3_sumcheck::layout::{Layout, PrefixProver};
use p3_uni_stark::{StarkGenericConfig, prove, verify};
use p3_whir::parameters::WhirConfig;
use p3_whir::pcs::proof::QueryOpenings;

use crate::common::whir_config::{
    BB_DIGEST_ELEMS, BbChallenger, BbEF, BbF, BbMmcs, BbWhirConfig, BbWhirPcs, bb_whir_mmcs,
    bb_whir_perm, bb_whir_protocol_params,
};

/// The WHIR PCS must satisfy the exact `RecursivePcs` bound
/// `verify_p3_uni_proof_circuit` requires; this fails to compile otherwise.
#[test]
fn whir_pcs_satisfies_the_recursive_pcs_bound() {
    fn assert_bound<P>()
    where
        P: RecursivePcs<
                BbWhirConfig,
                (),
                WhirUniProofTargets<BbF, BbEF, BbMmcs, BB_DIGEST_ELEMS>,
                MerkleCapTargets<BbF, BB_DIGEST_ELEMS>,
                <BbWhirPcs as Pcs<BbEF, <BbWhirConfig as StarkGenericConfig>::Challenger>>::Domain,
            >,
    {
    }
    assert_bound::<BbWhirPcs>();
}

/// Everything a recursive WHIR test needs for one instance.
pub struct WhirSetup {
    pub config: BbWhirConfig,
    pub air: FibonacciAir,
    pub pis: Vec<BbF>,
    pub proof: p3_uni_stark::Proof<BbWhirConfig>,
    pub round_log_inv_rates: Vec<usize>,
}

/// The value [`generate_trace_rows::<BbF>(0, 1, n)`]'s last row claims as its
/// output, i.e. `F(n)` for the sequence started at `F(0) = 0`, `F(1) = 1`.
fn fibonacci_output(n: usize) -> BbF {
    let (mut a, mut b) = (BbF::ZERO, BbF::ONE);
    for _ in 1..n {
        let next = a + b;
        a = b;
        b = next;
    }
    b
}

/// Proves a Fibonacci instance under WHIR with the given round schedule.
pub fn build_whir_setup(log_n: usize, round_log_inv_rates: Vec<usize>) -> WhirSetup {
    let n = 1 << log_n;
    let trace = generate_trace_rows::<BbF>(0, 1, n);
    let pis = vec![BbF::ZERO, BbF::ONE, fibonacci_output(n)];
    let air = FibonacciAir {};
    let config = crate::common::whir_config::bb_whir_config(round_log_inv_rates.clone());
    let proof = prove(&config, &air, trace, &pis);
    assert!(verify(&config, &air, &proof, &pis).is_ok());
    WhirSetup {
        config,
        air,
        pis,
        proof,
        round_log_inv_rates,
    }
}

/// Builds and runs the recursive verifier circuit for `proof` and `pis`.
///
/// `with_mmcs` selects whether in-circuit Merkle path verification runs; when
/// it does, the caller must also supply the restored paths (Task 14 extends
/// this function).
pub fn run_whir_recursive_verifier(
    setup: &WhirSetup,
    proof: &p3_uni_stark::Proof<BbWhirConfig>,
    pis: &[BbF],
) -> Result<(), VerificationError> {
    let mut builder = CircuitBuilder::new();
    builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<BbEF, BabyBearD4Width16>,
        bb_whir_perm(),
    );
    builder.enable_recompose::<BbF>(generate_recompose_trace::<BbF, BbEF>);

    let params = WhirUniVerifierParams::<BbF>::new(
        bb_whir_protocol_params(setup.round_log_inv_rates.clone()),
        PrefixProver::<BbF, BbEF>::variable_order(),
        None,
    );

    let verifier_inputs = StarkVerifierInputsBuilder::<
        BbWhirConfig,
        MerkleCapTargets<BbF, BB_DIGEST_ELEMS>,
        WhirUniProofTargets<BbF, BbEF, BbMmcs, BB_DIGEST_ELEMS>,
    >::allocate(&mut builder, proof, None, pis.len());

    let _op_ids = verify_p3_uni_proof_circuit::<
        FibonacciAir,
        BbWhirConfig,
        MerkleCapTargets<BbF, BB_DIGEST_ELEMS>,
        (),
        WhirUniProofTargets<BbF, BbEF, BbMmcs, BB_DIGEST_ELEMS>,
        _,
        16,
        8,
    >(
        &setup.config,
        &setup.air,
        &mut builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &None,
        &params,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )?;

    let circuit = builder.build()?;
    let mut runner = circuit.runner();
    let (public_inputs, private_inputs) = verifier_inputs.pack_values(pis, proof, &None);
    runner
        .set_public_inputs(&public_inputs)
        .map_err(VerificationError::Circuit)?;
    runner
        .set_private_inputs(&private_inputs)
        .map_err(VerificationError::Circuit)?;
    runner.run().map_err(VerificationError::Circuit)?;
    Ok(())
}

/// A WHIR-backed uni-STARK proof verifies inside the recursive circuit.
#[test]
fn whir_fibonacci_recursive_verifier_arithmetic_only() -> Result<(), VerificationError> {
    let setup = build_whir_setup(10, vec![4]);
    run_whir_recursive_verifier(&setup, &setup.proof, &setup.pis)
}

/// Wrong public inputs must break a circuit constraint, not merely a native check.
#[test]
#[should_panic(expected = "WitnessConflict")]
fn whir_fibonacci_recursive_verifier_rejects_wrong_public_inputs() {
    let setup = build_whir_setup(10, vec![4]);
    let mut wrong = setup.pis.clone();
    wrong[2] += BbF::ONE;
    run_whir_recursive_verifier(&setup, &setup.proof, &wrong).unwrap();
}

/// A tampered opened value (proof data, not a caller-supplied public input)
/// must also break a circuit constraint.
///
/// This exercises a different code path than
/// `whir_fibonacci_recursive_verifier_rejects_wrong_public_inputs`: the
/// quotient commitment's own WHIR opening-claim binding (`add_claim_at`'s
/// absorption of the claimed evaluation into the transcript, and the
/// resulting `claimed_eval` checked against the proof's fixed initial
/// sumcheck data), rather than the outer STARK's public-value transcript
/// absorption. See the Phase 4 report for the witness-id evidence pinning
/// exactly where this fails and why it is not the outer AIR-level
/// `circuit.connect(folded_mul, quotient)` check.
#[test]
#[should_panic(expected = "WitnessConflict")]
fn whir_fibonacci_recursive_verifier_rejects_tampered_opened_value() {
    let mut setup = build_whir_setup(10, vec![4]);
    setup.proof.opened_values.quotient_chunks[0][0] += BbEF::ONE;
    let pis = setup.pis.clone();
    run_whir_recursive_verifier(&setup, &setup.proof, &pis).unwrap();
}

/// Restored Merkle chains for one commitment's WHIR argument.
pub struct WhirRoundPaths {
    /// `rounds[i][q]` is the chain for intermediate round `i`'s query `q`.
    pub rounds: Vec<Vec<Vec<[BbF; BB_DIGEST_ELEMS]>>>,
    /// `final_paths[q]` is the chain for final query `q`.
    pub final_paths: Vec<Vec<[BbF; BB_DIGEST_ELEMS]>>,
}

/// Number of sibling digests one commitment's chains consume, which is exactly
/// the number of non-primitive ops `verify_whir_circuit` emits for it.
fn op_count(paths: &WhirRoundPaths) -> usize {
    paths
        .rounds
        .iter()
        .flatten()
        .map(Vec::len)
        .chain(paths.final_paths.iter().map(Vec::len))
        .sum()
}

/// Restores every commitment's per-query Merkle chains.
///
/// The queried indices are not in the proof: they come out of the WHIR
/// transcript, so this replays a native verification of the same proof and
/// records the indices each round sampled.
pub fn restore_whir_uni_paths(
    setup: &WhirSetup,
    proof: &p3_uni_stark::Proof<BbWhirConfig>,
    pis: &[BbF],
) -> Vec<WhirRoundPaths> {
    let mmcs = bb_whir_mmcs();
    let protocol_params = bb_whir_protocol_params(setup.round_log_inv_rates.clone());
    let folding = 4usize;

    // Replay the native verifier to recover the per-round queried indices.
    let indices = p3_recursion::pcs::whir::uni::replay_whir_query_indices::<
        BbWhirConfig,
        FibonacciAir,
        BbMmcs,
    >(
        &setup.config,
        &setup.air,
        proof,
        pis,
        &protocol_params,
        folding,
        PrefixProver::<BbF, BbEF>::variable_order(),
    )
    .expect("an honest proof's transcript replays");

    let mut out = Vec::with_capacity(proof.opening_proof.rounds.len());
    for (round_idx, round) in proof.opening_proof.rounds.iter().enumerate() {
        let cfg = WhirConfig::<BbEF, BbF, BbChallenger>::new(
            indices[round_idx].stacked_num_variables,
            protocol_params.clone(),
        )
        .expect("the replayed arity yields a valid WHIR config");

        let mut rounds = Vec::new();
        for (i, rp) in cfg.round_parameters.iter().enumerate() {
            let dims = [Dimensions {
                height: rp.domain_size >> rp.folding_factor,
                width: 1 << rp.folding_factor,
            }];
            rounds.push(
                restore_whir_query_paths::<_, _, BbEF, _, _, 2, BB_DIGEST_ELEMS>(
                    &mmcs,
                    &round.whir.rounds[i].openings,
                    &dims,
                    &indices[round_idx].rounds[i],
                )
                .expect("round path restoration"),
            );
        }

        // `folding_factor` here — not `final_sumcheck_rounds` — is the fold
        // applied to enter the final phase; see the Step 0 fix in
        // `recursion/src/pcs/whir/{params,verifier}.rs` for why these two
        // quantities are not interchangeable.
        let final_cfg = cfg.final_round_config();
        let final_dims = [Dimensions {
            height: final_cfg.domain_size >> final_cfg.folding_factor,
            width: 1 << final_cfg.folding_factor,
        }];
        let final_paths = restore_whir_query_paths::<_, _, BbEF, _, _, 2, BB_DIGEST_ELEMS>(
            &mmcs,
            &round.whir.final_openings,
            &final_dims,
            &indices[round_idx].final_queries,
        )
        .expect("final path restoration");

        out.push(WhirRoundPaths {
            rounds,
            final_paths,
        });
    }
    out
}

/// Recursive verification with in-circuit Merkle checking enabled.
pub fn run_whir_recursive_verifier_with_mmcs(
    setup: &WhirSetup,
    proof: &p3_uni_stark::Proof<BbWhirConfig>,
    pis: &[BbF],
    paths: &[WhirRoundPaths],
) -> Result<(), VerificationError> {
    let mut builder = CircuitBuilder::new();
    builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
        generate_poseidon2_trace::<BbEF, BabyBearD4Width16>,
        bb_whir_perm(),
    );
    builder.enable_recompose::<BbF>(generate_recompose_trace::<BbF, BbEF>);

    let params = WhirUniVerifierParams::<BbF>::new(
        bb_whir_protocol_params(setup.round_log_inv_rates.clone()),
        PrefixProver::<BbF, BbEF>::variable_order(),
        Some(Poseidon2Config::BABY_BEAR_D4_W16.into()),
    );

    let verifier_inputs = StarkVerifierInputsBuilder::<
        BbWhirConfig,
        MerkleCapTargets<BbF, BB_DIGEST_ELEMS>,
        WhirUniProofTargets<BbF, BbEF, BbMmcs, BB_DIGEST_ELEMS>,
    >::allocate(&mut builder, proof, None, pis.len());

    let op_ids = verify_p3_uni_proof_circuit::<
        FibonacciAir,
        BbWhirConfig,
        MerkleCapTargets<BbF, BB_DIGEST_ELEMS>,
        (),
        WhirUniProofTargets<BbF, BbEF, BbMmcs, BB_DIGEST_ELEMS>,
        _,
        16,
        8,
    >(
        &setup.config,
        &setup.air,
        &mut builder,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        &None,
        &params,
        Poseidon2Config::BABY_BEAR_D4_W16,
    )?;

    let circuit = builder.build()?;
    let mut runner = circuit.runner();
    let (public_inputs, private_inputs) = verifier_inputs.pack_values(pis, proof, &None);
    runner
        .set_public_inputs(&public_inputs)
        .map_err(VerificationError::Circuit)?;
    runner
        .set_private_inputs(&private_inputs)
        .map_err(VerificationError::Circuit)?;

    // `verify_whir_uni_circuit` emits each commitment's ops contiguously and in
    // commit order, so the op-id list splits by each commitment's sibling count.
    let mut offset = 0usize;
    for round_paths in paths {
        let count = op_count(round_paths);
        set_whir_mmcs_private_data::<BbF, BbEF, BB_DIGEST_ELEMS>(
            &mut runner,
            &op_ids[offset..offset + count],
            &round_paths.rounds,
            &round_paths.final_paths,
            Poseidon2Config::BABY_BEAR_D4_W16,
        )
        .map_err(|e| VerificationError::InvalidProofShape(e.to_string()))?;
        offset += count;
    }
    assert_eq!(offset, op_ids.len(), "op-id accounting must be exact");

    runner.run().map_err(VerificationError::Circuit)?;
    Ok(())
}

/// A WHIR proof verifies in-circuit with real Merkle path checking.
#[test]
fn whir_fibonacci_recursive_verifier_with_mmcs() -> Result<(), VerificationError> {
    let setup = build_whir_setup(10, vec![4]);
    let paths = restore_whir_uni_paths(&setup, &setup.proof, &setup.pis);
    run_whir_recursive_verifier_with_mmcs(&setup, &setup.proof, &setup.pis, &paths)
}

/// The same round trip at a second arity (stacked N=12) where the final
/// phase's true folding factor and `final_sumcheck_rounds` do *not* coincide
/// — the exact arity-coverage gap Step 0's fix closes. Turning on real MMCS
/// verification is what makes a wrong final-phase shape (rather than just a
/// desynced transcript) fail loudly here.
#[test]
fn whir_fibonacci_recursive_verifier_with_mmcs_at_a_second_arity() -> Result<(), VerificationError>
{
    let setup = build_whir_setup(11, vec![4]);
    let paths = restore_whir_uni_paths(&setup, &setup.proof, &setup.pis);
    run_whir_recursive_verifier_with_mmcs(&setup, &setup.proof, &setup.pis, &paths)
}

/// A third arity (stacked N=13), the other one the Step 0 fix's reviewer
/// specifically identified as exercising the final-phase formula bug.
#[test]
fn whir_fibonacci_recursive_verifier_with_mmcs_at_a_third_arity() -> Result<(), VerificationError> {
    let setup = build_whir_setup(12, vec![4]);
    let paths = restore_whir_uni_paths(&setup, &setup.proof, &setup.pis);
    run_whir_recursive_verifier_with_mmcs(&setup, &setup.proof, &setup.pis, &paths)
}

/// A tampered STIR query leaf must fail the circuit's own Merkle constraints,
/// with genuine sibling witnesses supplied so only the leaf is wrong.
///
/// `p3_uni_stark::Proof` does not implement `Clone`, so this restores the
/// honest paths first (capturing the honest sibling digests into an
/// independently-owned `WhirRoundPaths`), then tampers `setup.proof` in
/// place — the paths used for MMCS verification are therefore genuinely
/// honest even though the leaf value fed into the same query is not.
#[test]
#[should_panic(expected = "WitnessConflict")]
fn whir_recursive_verifier_rejects_a_tampered_query_leaf() {
    let mut setup = build_whir_setup(10, vec![4]);
    let paths = restore_whir_uni_paths(&setup, &setup.proof, &setup.pis);

    match &mut setup.proof.opening_proof.rounds[0].whir.rounds[0].openings {
        QueryOpenings::Base(opening) => {
            opening.rows[0][0] += BbF::ONE;
        }
        QueryOpenings::Extension(opening) => {
            opening.rows[0][0] += BbEF::ONE;
        }
    }
    let pis = setup.pis.clone();
    run_whir_recursive_verifier_with_mmcs(&setup, &setup.proof, &pis, &paths).unwrap();
}

/// A tampered Merkle sibling digest must fail the circuit's own Merkle
/// constraints, with an entirely honest proof and honest queried indices —
/// only the restored sibling chain itself is wrong.
///
/// The leaf-tamper test above cannot, on its own, distinguish "the circuit's
/// Merkle-path check caught this" from "some other, unrelated check happened
/// to catch it too": a corrupted leaf value also desyncs the arithmetic
/// values `verify_whir_circuit`'s final consistency check depends on. A
/// sibling digest, by contrast, is a private input that reaches the circuit
/// only through Merkle-path verification — it plays no part in any leaf
/// value, `fold_vals`, or `claimed_eval` computation — so a rejection here
/// can only come from the circuit's own root-equality connect.
#[test]
#[should_panic(expected = "WitnessConflict")]
fn whir_recursive_verifier_rejects_a_tampered_sibling_digest() {
    let setup = build_whir_setup(10, vec![4]);
    let mut paths = restore_whir_uni_paths(&setup, &setup.proof, &setup.pis);

    paths[0].rounds[0][0][0][0] += BbF::ONE;

    run_whir_recursive_verifier_with_mmcs(&setup, &setup.proof, &setup.pis, &paths).unwrap();
}

/// A tampered trace commitment desynchronises the Fiat-Shamir transcript from
/// the values the prover used, so a downstream circuit constraint fails —
/// with in-circuit Merkle verification enabled and genuine sibling witnesses
/// (restored from the honest proof before the mutation) supplied, so only
/// the committed root itself is wrong.
#[test]
#[should_panic(expected = "WitnessConflict")]
fn whir_recursive_verifier_rejects_a_tampered_trace_commitment() {
    let mut setup = build_whir_setup(10, vec![4]);
    let paths = restore_whir_uni_paths(&setup, &setup.proof, &setup.pis);

    let mut roots = setup.proof.commitments.trace.into_roots();
    roots[0][0] += BbF::ONE;
    setup.proof.commitments.trace = roots.into();

    run_whir_recursive_verifier_with_mmcs(&setup, &setup.proof, &setup.pis, &paths).unwrap();
}

/// A tampered opened trace value breaks the `bound * scale == claimed`
/// binding that ties the STARK's claim to what the WHIR argument proves,
/// with in-circuit Merkle verification enabled and genuine sibling witnesses
/// supplied.
#[test]
#[should_panic(expected = "WitnessConflict")]
fn whir_recursive_verifier_rejects_a_tampered_opened_trace_value() {
    let mut setup = build_whir_setup(10, vec![4]);
    let paths = restore_whir_uni_paths(&setup, &setup.proof, &setup.pis);

    setup.proof.opened_values.trace_local[0] += BbEF::ONE;

    run_whir_recursive_verifier_with_mmcs(&setup, &setup.proof, &setup.pis, &paths).unwrap();
}

/// A tampered bound multilinear value breaks the same binding from the other
/// side: the proof's own claimed evaluation no longer rescales to the
/// STARK's opened value.
#[test]
#[should_panic(expected = "WitnessConflict")]
fn whir_recursive_verifier_rejects_a_tampered_bound_eval() {
    let mut setup = build_whir_setup(10, vec![4]);
    let paths = restore_whir_uni_paths(&setup, &setup.proof, &setup.pis);

    let batch = &mut setup.proof.opening_proof.rounds[0].evals[0];
    let mut current = batch.current().to_vec();
    current[0] += BbEF::ONE;
    let next = batch.next().to_vec();
    *batch = p3_sumcheck::OpeningBatch::new(current, next);

    run_whir_recursive_verifier_with_mmcs(&setup, &setup.proof, &setup.pis, &paths).unwrap();
}

/// A tampered final polynomial breaks WHIR's final consistency identity.
#[test]
#[should_panic(expected = "WitnessConflict")]
fn whir_recursive_verifier_rejects_a_tampered_final_poly() {
    let mut setup = build_whir_setup(10, vec![4]);
    let paths = restore_whir_uni_paths(&setup, &setup.proof, &setup.pis);

    setup.proof.opening_proof.rounds[0]
        .whir
        .final_poly
        .as_mut()
        .expect("final polynomial")
        .as_mut_slice()[0] += BbEF::ONE;

    run_whir_recursive_verifier_with_mmcs(&setup, &setup.proof, &setup.pis, &paths).unwrap();
}

/// A tampered sumcheck round polynomial breaks the folded claim.
#[test]
#[should_panic(expected = "WitnessConflict")]
fn whir_recursive_verifier_rejects_a_tampered_sumcheck_round() {
    let mut setup = build_whir_setup(10, vec![4]);
    let paths = restore_whir_uni_paths(&setup, &setup.proof, &setup.pis);

    setup.proof.opening_proof.rounds[0]
        .whir
        .initial_sumcheck
        .polynomial_evaluations[0][0] += BbEF::ONE;

    run_whir_recursive_verifier_with_mmcs(&setup, &setup.proof, &setup.pis, &paths).unwrap();
}
