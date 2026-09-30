//! Real WHIR proofs exercising native whole-domain STIR queries and recursive verification.

mod common;

use common::whir_config::{BbChallenger, BbEF, BbF, BbMmcs};
use p3_circuit::CircuitError;
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_field::PrimeCharacteristicRing;
use p3_recursion::backend::whir::WhirRecursionBackend;
use p3_recursion::builtin_config::{
    BabyBearD4Poseidon2WhirConfig, SuiteIdV1, WhirConfigV1, WhirRateModeV1,
    WhirSecurityAssumptionV1, baby_bear_d4_poseidon2_whir,
};
use p3_recursion::pcs::whir::uni::{WhirQueryIndices, replay_whir_query_indices};
use p3_recursion::{
    Poseidon2Config, ProveNextLayerParams, RecursionInput, TrustedPreparedInput,
    TrustedPreparedLayer, TrustedPreparedSource, VerificationError, VerifierLimits,
    replay_recursion_input_transcript,
};
use p3_uni_stark::{Proof, prove, verify};
use p3_whir::pcs::proof::QueryOpenings;

type Config = BabyBearD4Poseidon2WhirConfig;

fn config(security_level: u32) -> Config {
    let descriptor = WhirConfigV1::new(
        SuiteIdV1::BabyBearD4Poseidon2Whir,
        1,
        WhirRateModeV1::Auto,
        4,
        WhirSecurityAssumptionV1::CapacityBound.as_u16(),
        security_level,
        0,
        20,
        0,
    );
    baby_bear_d4_poseidon2_whir(&descriptor, &VerifierLimits::default()).unwrap()
}

fn fibonacci_output(a: u64, b: u64, n: usize) -> BbF {
    let (mut a, mut b) = (BbF::from_u64(a), BbF::from_u64(b));
    for _ in 1..n {
        (a, b) = (b, a + b);
    }
    b
}

const fn query_count<P>(openings: &QueryOpenings<BbF, BbEF, P>) -> usize {
    match openings {
        QueryOpenings::Base(opening) => opening.rows.len(),
        QueryOpenings::Extension(opening) => opening.rows.len(),
    }
}

/// Native replay uses the original Fiat-Shamir sponge and the exact native WHIR sampler.
fn query_indices(
    config: &Config,
    air: &FibonacciAir,
    proof: &Proof<Config>,
    statement: &[BbF],
) -> Vec<WhirQueryIndices> {
    let input = RecursionInput::UniStark {
        proof,
        air,
        public_inputs: statement.to_vec(),
        preprocessed_commit: None,
    };
    let transcript = replay_recursion_input_transcript(config, &input, &[]).unwrap();
    let params = config.whir_verifier_params();
    replay_whir_query_indices::<Config, BbMmcs>(
        transcript,
        &proof.opening_proof,
        params.protocol_params(),
        params.folding(),
        params.variable_order(),
    )
    .unwrap()
}

fn assert_saturated_queries(
    config: &Config,
    proof: &Proof<Config>,
    indices: &[WhirQueryIndices],
    require_intermediate: bool,
) {
    assert_eq!(indices.len(), proof.opening_proof.rounds.len());
    let mut final_saturated = false;
    let mut intermediate_saturated = false;
    let mut post_saturation_sumcheck = false;
    for (argument, sampled) in proof.opening_proof.rounds.iter().zip(indices) {
        let params = config
            .whir_verifier_params()
            .round_params::<BbEF, BbChallenger>(sampled.stacked_num_variables)
            .unwrap();
        assert_eq!(sampled.rounds.len(), params.n_rounds());
        assert_eq!(argument.whir.rounds.len(), params.n_rounds());
        for ((raw, queried), round_proof) in params
            .round_params()
            .iter()
            .zip(&sampled.rounds)
            .zip(&argument.whir.rounds)
        {
            let folded_size = raw.domain_size() >> raw.folding_factor();
            let effective = raw.num_queries().min(folded_size);
            assert_eq!(raw.num_query_openings(), effective);
            assert_eq!(queried.len(), effective);
            assert_eq!(query_count(&round_proof.openings), effective);
            if raw.num_queries() >= folded_size {
                assert_eq!(queried, &(0..folded_size).collect::<Vec<_>>());
                intermediate_saturated = true;
            }
        }
        let folded_size = params.final_domain_size() >> params.final_folding_factor();
        let effective = params.final_queries().min(folded_size);
        assert_eq!(params.final_query_openings(), effective);
        assert_eq!(sampled.final_queries.len(), effective);
        assert_eq!(query_count(&argument.whir.final_openings), effective);
        if params.final_queries() >= folded_size {
            assert_eq!(sampled.final_queries, (0..folded_size).collect::<Vec<_>>());
            final_saturated = true;
            post_saturation_sumcheck |= params.final_sumcheck_rounds() > 0;
        }
    }
    assert!(
        final_saturated,
        "a real WHIR argument must saturate its final phase"
    );
    assert!(
        post_saturation_sumcheck,
        "a saturated final phase must be followed by a challenge-bearing sumcheck"
    );
    if require_intermediate {
        assert!(
            intermediate_saturated,
            "a real WHIR argument must saturate an intermediate phase"
        );
    }
}

fn flip_final_leaf<P>(openings: &mut QueryOpenings<BbF, BbEF, P>, index: usize) {
    match openings {
        QueryOpenings::Base(opening) => opening.rows[index][0] += BbF::ONE,
        QueryOpenings::Extension(opening) => opening.rows[index][0] += BbEF::ONE,
    }
}

fn check_malformed_leaf(
    child: &Config,
    air: &FibonacciAir,
    proof: &Proof<Config>,
    statement: &[BbF],
) -> VerificationError {
    let backend = WhirRecursionBackend::<16, 8>::new(Poseidon2Config::BABY_BEAR_D4_W16)
        .for_extension_degree::<4>();
    TrustedPreparedLayer::<Config, Config, FibonacciAir, _, 4>::new(
        TrustedPreparedSource::UniStark {
            config: child.clone(),
            air,
            preprocessed_commit: None,
            proof,
            public_inputs: statement,
        },
        config(32),
        backend,
        ProveNextLayerParams::default(),
    )
    .err()
    .expect("malformed WHIR opening shape must reject before circuit preparation")
}

fn swap_distinct_final_rows<P>(openings: &mut QueryOpenings<BbF, BbEF, P>) -> bool {
    match openings {
        QueryOpenings::Base(opening) => {
            if let Some(index) =
                (1..opening.rows.len()).find(|&i| opening.rows[i] != opening.rows[0])
            {
                opening.rows.swap(0, index);
                true
            } else {
                false
            }
        }
        QueryOpenings::Extension(opening) => {
            if let Some(index) =
                (1..opening.rows.len()).find(|&i| opening.rows[i] != opening.rows[0])
            {
                opening.rows.swap(0, index);
                true
            } else {
                false
            }
        }
    }
}

#[test]
fn saturated_final_whir_leaf_proves_inside_a_trusted_parent() {
    const N: usize = 1 << 4;
    let child = config(32);
    let output = config(32);
    let air = FibonacciAir {};
    let statement = vec![BbF::ZERO, BbF::ONE, fibonacci_output(0, 1, N)];
    let mut proof = prove(
        &child,
        &air,
        generate_trace_rows::<BbF>(0, 1, N),
        &statement,
    )
    .unwrap();
    verify(&child, &air, &proof, &statement).unwrap();
    let indices = query_indices(&child, &air, &proof, &statement);
    assert_saturated_queries(&child, &proof, &indices, false);
    let second_statement = vec![
        BbF::from_u64(2),
        BbF::from_u64(3),
        fibonacci_output(2, 3, N),
    ];
    let second_proof = prove(
        &child,
        &air,
        generate_trace_rows::<BbF>(2, 3, N),
        &second_statement,
    )
    .unwrap();
    verify(&child, &air, &second_proof, &second_statement).unwrap();
    let second_indices = query_indices(&child, &air, &second_proof, &second_statement);
    assert_saturated_queries(&child, &second_proof, &second_indices, false);

    let backend = WhirRecursionBackend::<16, 8>::new(Poseidon2Config::BABY_BEAR_D4_W16)
        .for_extension_degree::<4>();
    let owner = TrustedPreparedLayer::<Config, Config, FibonacciAir, _, 4>::new(
        TrustedPreparedSource::UniStark {
            config: child.clone(),
            air: &air,
            preprocessed_commit: None,
            proof: &proof,
            public_inputs: &statement,
        },
        output,
        backend,
        ProveNextLayerParams::default(),
    )
    .unwrap();
    let parent = owner
        .prove(TrustedPreparedInput::UniStark {
            proof: &proof,
            public_inputs: &statement,
        })
        .unwrap();
    let second_parent = owner
        .prove(TrustedPreparedInput::UniStark {
            proof: &second_proof,
            public_inputs: &second_statement,
        })
        .unwrap();
    let verifier = owner.verifier();
    assert_eq!(verifier.statement_layout().schema().base_len(), 3);
    verifier.verify(&parent.0, &statement).unwrap();
    verifier
        .verify(&second_parent.0, &second_statement)
        .unwrap();
    let mut changed = statement.clone();
    changed[2] += BbF::ONE;
    assert!(verifier.verify(&parent.0, &changed).is_err());
    assert!(verifier.verify(&second_parent.0, &statement).is_err());

    let original_opening_proof = proof.opening_proof.clone();
    let count = query_count(&proof.opening_proof.rounds[0].whir.final_openings);
    assert!(count >= 2, "need distinct low/high saturated leaves");
    for index in [0, count - 1] {
        flip_final_leaf(
            &mut proof.opening_proof.rounds[0].whir.final_openings,
            index,
        );
        assert!(verify(&child, &air, &proof, &statement).is_err());
        let error = owner
            .prove(TrustedPreparedInput::UniStark {
                proof: &proof,
                public_inputs: &statement,
            })
            .err()
            .expect("the trusted parent must reject an altered final leaf");
        assert!(
            matches!(
                &error,
                VerificationError::Circuit(CircuitError::WitnessConflict { .. })
                    | VerificationError::InvalidProofShape(_)
            ),
            "unexpected altered-leaf error: {error:?}"
        );
        proof.opening_proof = original_opening_proof.clone();
    }
    assert!(swap_distinct_final_rows(
        &mut proof.opening_proof.rounds[0].whir.final_openings
    ));
    assert!(verify(&child, &air, &proof, &statement).is_err());
    let error = owner
        .prove(TrustedPreparedInput::UniStark {
            proof: &proof,
            public_inputs: &statement,
        })
        .err()
        .expect("the trusted parent must reject reordered final rows");
    assert!(
        matches!(
            &error,
            VerificationError::Circuit(CircuitError::WitnessConflict { .. })
                | VerificationError::InvalidProofShape(_)
        ),
        "unexpected reordered-row error: {error:?}"
    );
    proof.opening_proof = original_opening_proof.clone();

    // Full-domain openings need no sibling hashes. An unexpected path digest is malformed.
    match &mut proof.opening_proof.rounds[0].whir.final_openings {
        QueryOpenings::Base(opening) => opening.proof.sibling_hashes.push([BbF::ONE; 8]),
        QueryOpenings::Extension(opening) => opening.proof.sibling_hashes.push([BbF::ONE; 8]),
    }
    assert!(verify(&child, &air, &proof, &statement).is_err());
    let error = owner
        .prove(TrustedPreparedInput::UniStark {
            proof: &proof,
            public_inputs: &statement,
        })
        .err()
        .expect("the trusted parent must reject an unexpected path digest");
    assert!(matches!(&error, VerificationError::InvalidProofShape(_)));
    proof.opening_proof = original_opening_proof.clone();
    drop(owner);

    match &mut proof.opening_proof.rounds[0].whir.final_openings {
        QueryOpenings::Base(opening) => {
            opening.rows.pop();
        }
        QueryOpenings::Extension(opening) => {
            opening.rows.pop();
        }
    }
    assert!(matches!(
        check_malformed_leaf(&child, &air, &proof, &statement),
        VerificationError::InvalidProofShape(_)
    ));
    proof.opening_proof = original_opening_proof;
    match &mut proof.opening_proof.rounds[0].whir.final_openings {
        QueryOpenings::Base(opening) => opening.rows.push(opening.rows[0].clone()),
        QueryOpenings::Extension(opening) => opening.rows.push(opening.rows[0].clone()),
    }
    assert!(matches!(
        check_malformed_leaf(&child, &air, &proof, &statement),
        VerificationError::InvalidProofShape(_)
    ));
}
