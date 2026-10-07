//! Real Suffix-stacked WHIR leaves and parents through one trusted prepared layer.

use std::collections::BTreeSet;
use std::sync::Arc;

use common::whir_config::{
    BB_DIGEST_ELEMS, BbChallenger, BbDft, BbEF, BbF, BbMmcs, bb_whir_mmcs, bb_whir_perm,
    bb_whir_protocol_params,
};
use p3_circuit::ops::{generate_poseidon2_trace, generate_recompose_trace};
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_circuit::{CircuitBuilder, CircuitError, CircuitRunner, NonPrimitiveOpId, StatementSchema};
use p3_circuit_prover::StatementProver;
use p3_circuit_prover::batch_stark_prover::BatchStarkProver;
use p3_field::PrimeCharacteristicRing;
use p3_lookup::logup::LogUpGadget;
use p3_poseidon2_circuit_air::BabyBearD4Width16;
use p3_recursion::backend::whir::{WhirRecursionBackend, WhirRecursionConfig};
use p3_recursion::generation::OpeningTranscript;
use p3_recursion::pcs::fri::MerkleCapTargets;
use p3_recursion::pcs::set_whir_mmcs_private_data;
use p3_recursion::pcs::whir::uni::{
    VariableOrder, WhirUniPcs, WhirUniProof, WhirUniProofTargets, WhirUniVerifierParams,
    replay_whir_query_indices, restore_whir_recursion_paths, whir_round_paths_op_count,
};
use p3_recursion::traits::RecursiveAir;
use p3_recursion::{
    Poseidon2Config, ProveNextLayerParams, RecursionInput, RecursionOutput, TrustedPreparedInput,
    TrustedPreparedLayer, TrustedPreparedSource, VerificationError,
    replay_recursion_input_transcript,
};
use p3_sumcheck::layout::{Layout, SuffixProver};
use p3_uni_stark::{Proof, StarkGenericConfig, prove, verify};
use p3_whir::parameters::{FoldingFactor, WhirConfig};
use p3_whir::pcs::proof::QueryOpenings;

use crate::common;

type SuffixPcs = WhirUniPcs<BbEF, BbF, BbDft, BbMmcs, BbChallenger, SuffixProver<BbF, BbEF>>;

#[derive(Clone)]
struct SuffixWhirConfig {
    pcs: SuffixPcs,
    challenger: BbChallenger,
    verifier_params: WhirUniVerifierParams<BbF>,
}

fn suffix_whir_config() -> SuffixWhirConfig {
    let mut protocol = bb_whir_protocol_params(vec![]);
    protocol.folding_factor = FoldingFactor::ConstantFromSecondRound(3, 2);
    let challenger = BbChallenger::new(bb_whir_perm());
    let pcs = WhirUniPcs::new(
        protocol.clone(),
        BbDft::default(),
        bb_whir_mmcs(),
        challenger.clone(),
        20,
    );
    let verifier_params = WhirUniVerifierParams::<BbF>::new(
        protocol,
        SuffixProver::<BbF, BbEF>::variable_order(),
        Poseidon2Config::BABY_BEAR_D4_W16,
    )
    .expect("canonical Suffix WHIR parameters");
    SuffixWhirConfig {
        pcs,
        challenger,
        verifier_params,
    }
}

impl StarkGenericConfig for SuffixWhirConfig {
    type Pcs = SuffixPcs;
    type Challenge = BbEF;
    type Challenger = BbChallenger;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn initialise_challenger(&self) -> Self::Challenger {
        self.challenger.clone()
    }
}

impl WhirRecursionConfig for SuffixWhirConfig {
    type Commitment = MerkleCapTargets<BbF, BB_DIGEST_ELEMS>;
    type InputProof = ();
    type OpeningProof = WhirUniProofTargets<BbF, BbEF, BbMmcs, BB_DIGEST_ELEMS>;
    type RawOpeningProof = WhirUniProof<BbF, BbEF, BbMmcs>;

    fn with_whir_opening_proof<'a, A, R>(
        prev: &RecursionInput<'a, Self, A>,
        f: impl FnOnce(&Self::RawOpeningProof) -> R,
    ) -> R
    where
        A: RecursiveAir<BbF, BbEF, LogUpGadget>,
    {
        match prev {
            RecursionInput::UniStark { proof, .. } => f(&proof.opening_proof),
            RecursionInput::BatchStark { proof, .. } => f(&proof.proof.opening_proof),
        }
    }

    fn prepare_circuit_for_verification(
        &self,
        circuit: &mut CircuitBuilder<BbEF>,
    ) -> Result<(), VerificationError> {
        circuit.enable_poseidon2_perm::<BabyBearD4Width16, _>(
            generate_poseidon2_trace::<BbEF, BabyBearD4Width16>,
            bb_whir_perm(),
        );
        circuit.enable_recompose::<BbF>(generate_recompose_trace::<BbF, BbEF>);
        Ok(())
    }

    fn pcs_verifier_params(&self) -> &WhirUniVerifierParams<BbF> {
        &self.verifier_params
    }

    fn set_whir_private_data(
        config: &Self,
        runner: &mut CircuitRunner<'_, BbEF>,
        op_ids: &[NonPrimitiveOpId],
        opening_proof: &Self::RawOpeningProof,
        transcript: OpeningTranscript<Self>,
    ) -> Result<(), &'static str> {
        let params = config.pcs_verifier_params();
        let paths = restore_whir_recursion_paths::<Self, _, _, _, _, _, BB_DIGEST_ELEMS>(
            &bb_whir_mmcs(),
            transcript,
            &config.initialise_challenger(),
            opening_proof,
            params.protocol_params(),
            params.folding(),
            params.variable_order(),
        )
        .map_err(|_| "Failed to restore Suffix WHIR Merkle paths")?;

        let mut offset = 0usize;
        for round_paths in &paths {
            let count = whir_round_paths_op_count(round_paths);
            let ids = op_ids
                .get(offset..offset + count)
                .ok_or("Not enough op_ids for restored Suffix WHIR Merkle paths")?;
            set_whir_mmcs_private_data::<BbF, BbEF, BB_DIGEST_ELEMS>(
                runner,
                ids,
                &round_paths.rounds,
                &round_paths.final_paths,
                Poseidon2Config::BABY_BEAR_D4_W16,
            )?;
            offset += count;
        }
        if offset != op_ids.len() {
            return Err("op-id accounting mismatch in SuffixWhirConfig");
        }
        Ok(())
    }
}

fn fibonacci_output(a: u64, b: u64, n: usize) -> BbF {
    let (mut a, mut b) = (BbF::from_u64(a), BbF::from_u64(b));
    for _ in 1..n {
        (a, b) = (b, a + b);
    }
    b
}

/// Check the concrete WHIR schedule against real child commitments and replayed arities.
fn assert_suffix_child_schedule(
    config: &SuffixWhirConfig,
    air: &FibonacciAir,
    proof: &Proof<SuffixWhirConfig>,
    statement: &[BbF],
) -> BTreeSet<usize> {
    let params = config.pcs_verifier_params();
    assert_eq!(params.variable_order(), VariableOrder::Suffix);
    assert!(matches!(
        params.protocol_params().folding_factor,
        FoldingFactor::ConstantFromSecondRound(3, 2)
    ));
    assert!(params.protocol_params().round_log_inv_rates.is_empty());
    assert_eq!(params.folding(), 3);

    let input = RecursionInput::UniStark {
        proof,
        air,
        public_inputs: statement.to_vec(),
        preprocessed_commit: None,
    };
    let transcript = replay_recursion_input_transcript(config, &input, &[]).unwrap();
    let replay = replay_whir_query_indices::<SuffixWhirConfig, BbMmcs>(
        transcript,
        &config.initialise_challenger(),
        &proof.opening_proof,
        params.protocol_params(),
        params.folding(),
        params.variable_order(),
    )
    .unwrap();
    assert_eq!(replay.len(), proof.opening_proof.rounds.len());

    let mut arities = BTreeSet::new();
    let mut later_two = false;
    for (sampled, argument) in replay.iter().zip(&proof.opening_proof.rounds) {
        let arity = sampled.stacked_num_variables;
        arities.insert(arity);
        let native =
            WhirConfig::<BbEF, BbF, BbChallenger>::new(arity, params.protocol_params().clone())
                .unwrap();
        let recursive = params.round_params::<BbEF, BbChallenger>(arity).unwrap();
        assert_eq!(native.folding_schedule()[0], 3);
        assert_eq!(argument.whir.initial_sumcheck.num_rounds(), 3);
        assert_eq!(recursive.variable_order(), VariableOrder::Suffix);
        assert_eq!(recursive.num_variables(), arity);
        assert_eq!(recursive.n_rounds(), native.n_rounds());
        assert_eq!(argument.whir.rounds.len(), native.n_rounds());
        assert_eq!(sampled.rounds.len(), native.n_rounds());
        for (i, (round, round_params)) in argument
            .whir
            .rounds
            .iter()
            .zip(recursive.round_params())
            .enumerate()
        {
            assert_eq!(
                round_params.folding_factor(),
                native.round_parameters()[i].folding_factor
            );
            let next_fold = native.folding_schedule()[i + 1];
            assert_eq!(round.sumcheck.num_rounds(), next_fold);
            later_two |= next_fold == 2;
        }
        assert_eq!(
            recursive.final_folding_factor(),
            native.final_round_config().folding_factor
        );
    }
    assert!(
        later_two,
        "the child proof must contain a later two-variable fold"
    );
    arities
}

fn assert_suffix_parent_schedule(proof: &RecursionOutput<SuffixWhirConfig>) {
    let arguments = &proof.0.proof.opening_proof.rounds;
    assert!(arguments.len() > 1);
    assert!(
        arguments
            .iter()
            .all(|argument| argument.whir.initial_sumcheck.num_rounds() == 3)
    );
    assert!(
        arguments
            .iter()
            .flat_map(|argument| &argument.whir.rounds)
            .any(|round| round.sumcheck.num_rounds() == 2)
    );
}

fn verify_suffix_parent(
    config: &SuffixWhirConfig,
    params: &ProveNextLayerParams,
    schema: &StatementSchema,
    proof: &RecursionOutput<SuffixWhirConfig>,
) {
    let mut verifier =
        BatchStarkProver::new(config.clone()).with_table_packing(params.table_packing.clone());
    verifier.register_poseidon2_table::<4>(
        Poseidon2Config::BABY_BEAR_D4_W16.for_shared_challenger_table(),
    );
    verifier.register_recompose_table::<4>(true);
    verifier.register_table_prover(Box::new(StatementProver::<4>::new(schema.clone())));
    verifier
        .verify_all_tables::<BbEF>(&proof.0)
        .expect("native verifier must accept the Suffix parent proof");
}

#[test]
fn suffix_whir_proves_two_statements_through_one_trusted_parent() {
    const N: usize = 1 << 10;
    let config = suffix_whir_config();
    let output = suffix_whir_config();
    assert_eq!(
        output.pcs_verifier_params().variable_order(),
        VariableOrder::Suffix
    );
    let air = FibonacciAir {};
    let first_statement = vec![BbF::ZERO, BbF::ONE, fibonacci_output(0, 1, N)];
    let second_statement = vec![
        BbF::from_u64(2),
        BbF::from_u64(3),
        fibonacci_output(2, 3, N),
    ];
    assert_ne!(first_statement, second_statement);

    let mut first_leaf = prove(
        &config,
        &air,
        generate_trace_rows::<BbF>(0, 1, N),
        &first_statement,
    )
    .unwrap();
    let second_leaf = prove(
        &config,
        &air,
        generate_trace_rows::<BbF>(2, 3, N),
        &second_statement,
    )
    .unwrap();
    verify(&config, &air, &first_leaf, &first_statement).unwrap();
    verify(&config, &air, &second_leaf, &second_statement).unwrap();
    let first_arities = assert_suffix_child_schedule(&config, &air, &first_leaf, &first_statement);
    let second_arities =
        assert_suffix_child_schedule(&config, &air, &second_leaf, &second_statement);
    assert_eq!(first_arities, second_arities);
    assert!(
        first_arities.len() > 1,
        "the child must cover distinct stacked arities"
    );

    let backend = WhirRecursionBackend::<16, 8>::new(Poseidon2Config::BABY_BEAR_D4_W16)
        .for_extension_degree::<4>();
    let layer_params = ProveNextLayerParams::default();
    let owner =
        TrustedPreparedLayer::<SuffixWhirConfig, SuffixWhirConfig, FibonacciAir, _, 4>::new(
            TrustedPreparedSource::UniStark {
                config: config.clone(),
                air: &air,
                preprocessed_commit: None,
                proof: &first_leaf,
                public_inputs: &first_statement,
            },
            output.clone(),
            backend,
            layer_params.clone(),
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
    assert_suffix_parent_schedule(&first_parent);
    assert_suffix_parent_schedule(&second_parent);
    let verifier = owner.verifier();
    assert_eq!(verifier.statement_layout().schema().base_len(), 3);
    let schema = verifier.statement_layout().schema();
    verify_suffix_parent(&output, &layer_params, schema, &first_parent);
    verify_suffix_parent(&output, &layer_params, schema, &second_parent);
    verifier.verify(&first_parent.0, &first_statement).unwrap();
    verifier
        .verify(&second_parent.0, &second_statement)
        .unwrap();
    assert!(verifier.verify(&first_parent.0, &second_statement).is_err());
    assert!(verifier.verify(&second_parent.0, &first_statement).is_err());
    let mut wrong = first_statement.clone();
    wrong[2] += BbF::ONE;
    assert!(verifier.verify(&first_parent.0, &wrong).is_err());

    // Change an authenticated opened leaf, preserving the proof's shape.
    match &mut first_leaf.opening_proof.rounds[0].whir.final_openings {
        QueryOpenings::Base(opening) => opening.rows[0][0] += BbF::ONE,
        QueryOpenings::Extension(opening) => opening.rows[0][0] += BbEF::ONE,
    }
    assert!(verify(&config, &air, &first_leaf, &first_statement).is_err());
    let error = owner
        .prove(TrustedPreparedInput::UniStark {
            proof: &first_leaf,
            public_inputs: &first_statement,
        })
        .err()
        .expect("the trusted parent must reject a tampered Suffix child leaf");
    assert!(
        matches!(
            &error,
            VerificationError::Circuit(CircuitError::WitnessConflict { .. })
                | VerificationError::InvalidProofShape(_)
        ),
        "unexpected child rejection: {error:?}"
    );
}
