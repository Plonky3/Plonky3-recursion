//! Real varying-fold WHIR proofs through a trusted prepared recursion layer.

mod common;

use std::collections::BTreeSet;
use std::sync::Arc;

use common::whir_config::{
    BbChallenger, BbEF, BbF, BbMmcs, BbWhirConfig, bb_whir_config_with_protocol_params,
    bb_whir_protocol_params,
};
use p3_circuit::CircuitError;
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_field::PrimeCharacteristicRing;
use p3_recursion::backend::whir::{WhirRecursionBackend, WhirRecursionConfig};
use p3_recursion::pcs::whir::uni::replay_whir_query_indices;
use p3_recursion::{
    Poseidon2Config, ProveNextLayerParams, RecursionInput, TrustedPreparedInput,
    TrustedPreparedLayer, TrustedPreparedSource, VerificationError,
    replay_recursion_input_transcript,
};
use p3_uni_stark::{Proof, StarkGenericConfig, prove, verify};
use p3_whir::parameters::{FoldingFactor, WhirConfig};
use p3_whir::transcript::WhirShape;

fn fibonacci_output(a: u64, b: u64, n: usize) -> BbF {
    let (mut a, mut b) = (BbF::from_u64(a), BbF::from_u64(b));
    for _ in 1..n {
        (a, b) = (b, a + b);
    }
    b
}

/// Read the arities from the real Fiat-Shamir replay, then match the native and
/// recursive schedules against the sumchecks actually carried in the proof.
fn assert_varying_proof_schedule(
    config: &BbWhirConfig,
    air: &FibonacciAir,
    proof: &Proof<BbWhirConfig>,
    statement: &[BbF],
) -> BTreeSet<usize> {
    let input = RecursionInput::UniStark {
        proof,
        air,
        public_inputs: statement.to_vec(),
        preprocessed_commit: None,
    };
    let transcript = replay_recursion_input_transcript(config, &input, &[]).unwrap();
    let shared = config.pcs_verifier_params();
    assert!(matches!(
        shared.protocol_params().folding_factor,
        FoldingFactor::ConstantFromSecondRound(3, 2)
    ));
    assert!(shared.protocol_params().round_log_inv_rates.is_empty());
    assert_eq!(shared.folding(), 3);
    let replay = replay_whir_query_indices::<BbWhirConfig, BbMmcs>(
        transcript,
        &config.initialise_challenger(),
        &proof.opening_proof,
        shared.protocol_params(),
        shared.folding(),
        shared.variable_order(),
    )
    .unwrap();
    assert_eq!(replay.len(), proof.opening_proof.rounds.len());

    let mut arities = BTreeSet::new();
    let mut observed_later_two = false;
    for (sampled, argument) in replay.iter().zip(&proof.opening_proof.rounds) {
        let arity = sampled.stacked_num_variables;
        arities.insert(arity);
        let native =
            WhirConfig::<BbEF, BbF, BbChallenger>::new(arity, shared.protocol_params().clone())
                .unwrap();
        let recursive = shared.round_params::<BbEF, BbChallenger>(arity).unwrap();
        assert_eq!(native.folding_schedule()[0], 3);
        assert_eq!(argument.whir.initial_sumcheck.num_rounds(), 3);
        assert_eq!(recursive.num_variables(), arity);
        assert_eq!(recursive.n_rounds(), native.n_rounds());
        assert_eq!(argument.whir.rounds.len(), native.n_rounds());
        assert_eq!(sampled.rounds.len(), native.n_rounds());
        for (index, (round, round_params)) in argument
            .whir
            .rounds
            .iter()
            .zip(recursive.round_params())
            .enumerate()
        {
            assert_eq!(
                round_params.folding_factor(),
                native.round_parameters()[index].folding_factor
            );
            let next_fold = native.folding_schedule()[index + 1];
            assert_eq!(round.sumcheck.num_rounds(), next_fold);
            observed_later_two |= round.sumcheck.num_rounds() == 2;
        }
        assert_eq!(
            recursive.final_folding_factor(),
            native.final_round_config().folding_factor
        );
        assert_eq!(
            argument
                .whir
                .final_sumcheck
                .as_ref()
                .map_or(0, |sumcheck| sumcheck.num_rounds()),
            native.final_sumcheck_rounds()
        );
        assert_eq!(
            format!(
                "{:?}",
                recursive
                    .transcript_shape()
                    .for_claims(argument.evals.len())
            ),
            format!("{:?}", WhirShape::new(&native, argument.evals.len()))
        );
    }
    assert!(
        observed_later_two,
        "the proof must contain a later two-variable sumcheck"
    );
    arities
}

#[test]
fn varying_folds_prove_two_statements_through_one_trusted_parent() {
    const N: usize = 1 << 10;
    let mut protocol = bb_whir_protocol_params(vec![]);
    protocol.folding_factor = FoldingFactor::ConstantFromSecondRound(3, 2);
    let child = bb_whir_config_with_protocol_params(protocol.clone());
    let output = bb_whir_config_with_protocol_params(protocol);
    let air = FibonacciAir {};
    let first_statement = vec![BbF::ZERO, BbF::ONE, fibonacci_output(0, 1, N)];
    let second_statement = vec![
        BbF::from_u64(2),
        BbF::from_u64(3),
        fibonacci_output(2, 3, N),
    ];
    assert_ne!(first_statement, second_statement);

    let mut first_leaf = prove(
        &child,
        &air,
        generate_trace_rows::<BbF>(0, 1, N),
        &first_statement,
    )
    .unwrap();
    let second_leaf = prove(
        &child,
        &air,
        generate_trace_rows::<BbF>(2, 3, N),
        &second_statement,
    )
    .unwrap();
    verify(&child, &air, &first_leaf, &first_statement).unwrap();
    verify(&child, &air, &second_leaf, &second_statement).unwrap();
    let first_arities = assert_varying_proof_schedule(&child, &air, &first_leaf, &first_statement);
    let second_arities =
        assert_varying_proof_schedule(&child, &air, &second_leaf, &second_statement);
    assert_eq!(first_arities, second_arities);
    assert!(
        first_arities.len() > 1,
        "the leaf must cover distinct stacked arities"
    );

    let backend = WhirRecursionBackend::<16, 8>::new(Poseidon2Config::BABY_BEAR_D4_W16)
        .for_extension_degree::<4>();
    let owner = TrustedPreparedLayer::<BbWhirConfig, BbWhirConfig, FibonacciAir, _, 4>::new(
        TrustedPreparedSource::UniStark {
            config: child.clone(),
            air: &air,
            preprocessed_commit: None,
            proof: &first_leaf,
            public_inputs: &first_statement,
        },
        output,
        backend,
        ProveNextLayerParams::default(),
    )
    .unwrap();
    let first_parent = owner
        .prove(TrustedPreparedInput::UniStark {
            proof: &first_leaf,
            public_inputs: &first_statement,
        })
        .unwrap();
    let second_parent = owner
        .prove(TrustedPreparedInput::UniStark {
            proof: &second_leaf,
            public_inputs: &second_statement,
        })
        .unwrap();
    assert!(Arc::ptr_eq(&first_parent.1, &second_parent.1));
    assert!(first_parent.0.proof.opening_proof.rounds.len() > 1);
    assert!(
        first_parent
            .0
            .proof
            .opening_proof
            .rounds
            .iter()
            .all(|round| round.whir.initial_sumcheck.num_rounds() == 3)
    );
    assert!(
        first_parent
            .0
            .proof
            .opening_proof
            .rounds
            .iter()
            .flat_map(|argument| &argument.whir.rounds)
            .any(|round| round.sumcheck.num_rounds() == 2)
    );

    let verifier = owner.verifier();
    assert_eq!(verifier.statement_layout().schema().base_len(), 3);
    verifier.verify(&first_parent.0, &first_statement).unwrap();
    verifier
        .verify(&second_parent.0, &second_statement)
        .unwrap();
    assert!(verifier.verify(&first_parent.0, &second_statement).is_err());
    assert!(verifier.verify(&second_parent.0, &first_statement).is_err());
    let mut wrong = first_statement.clone();
    wrong[2] += BbF::ONE;
    assert!(verifier.verify(&first_parent.0, &wrong).is_err());

    first_leaf.opening_proof.rounds[0]
        .whir
        .initial_sumcheck
        .polynomial_evaluations[0][0] += BbEF::ONE;
    assert!(verify(&child, &air, &first_leaf, &first_statement).is_err());
    let error = owner
        .prove(TrustedPreparedInput::UniStark {
            proof: &first_leaf,
            public_inputs: &first_statement,
        })
        .err()
        .expect("the trusted parent must reject a tampered child sumcheck");
    assert!(
        matches!(
            &error,
            VerificationError::Circuit(CircuitError::WitnessConflict { .. })
                | VerificationError::InvalidProofShape(_)
        ),
        "unexpected child rejection: {error:?}"
    );
}
