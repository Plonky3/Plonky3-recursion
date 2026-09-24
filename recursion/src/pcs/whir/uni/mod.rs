//! Bridge from WHIR's multilinear PCS to the univariate STARK machinery.

#[cfg(test)]
pub(crate) mod acceptance_probe;
pub mod bridge;
pub mod circuit;
pub mod pcs;
pub mod plan;
pub mod recursion_data;
pub mod recursive_pcs;
pub mod targets;

use alloc::format;
use alloc::string::ToString;
use alloc::vec::Vec;

pub use bridge::{univariate_eq_point, univariate_eq_point_circuit};
pub use circuit::{MatrixOpenings, RoundClaims, build_round_claims};
use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_commit::{Mmcs, PolynomialSpace};
use p3_field::{Algebra, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_sumcheck::layout::{LayoutStrategy, Verifier};
use p3_sumcheck::strategy::Basis;
pub use p3_sumcheck::strategy::VariableOrder;
use p3_sumcheck::verify_final_sumcheck_rounds;
use p3_uni_stark::{StarkGenericConfig, SymbolicExpression, SymbolicExpressionExt, Val};
use p3_util::log2_strict_usize;
use p3_whir::parameters::{ProtocolParameters, WhirConfig};
use p3_whir::transcript::{WhirShape, WhirVerifierTranscript};
pub use pcs::{WhirUniPcs, WhirUniPcsError, WhirUniProof, WhirUniProverData};
pub use plan::{StackedPlacement, StackedPlan, StackedSelector, padded_arity};
pub use recursion_data::{WhirRoundPaths, restore_whir_recursion_paths, whir_round_paths_op_count};
pub use recursive_pcs::WhirUniVerifierParams;
pub use targets::{WhirRoundTargets, WhirUniProofTargets, packed_digest_len};

use crate::VerificationError;
use crate::input_contract::whir::{WhirContextParams, validate_whir_pcs_context};
use crate::pcs::whir::uni::plan::checked_stacked_num_variables;
use crate::pcs::whir::uni::recursive_pcs::validate_round_config_inputs;

/// Queried STIR indices one commitment's WHIR argument sampled.
///
/// The queried indices are not carried by the proof: WHIR's now-independent
/// sampler ([`get_challenge_stir_queries`]) draws them straight from the
/// transcript, so recovering them for MMCS path restoration means replaying
/// that transcript rather than reading them off any proof field.
#[derive(Clone, Debug)]
pub struct WhirQueryIndices {
    /// Arity of the stacked polynomial this commitment covers.
    pub stacked_num_variables: usize,
    /// `rounds[i]` are the indices intermediate round `i` sampled.
    pub rounds: Vec<Vec<usize>>,
    /// Indices the final phase sampled.
    pub final_queries: Vec<usize>,
}

/// Replays a WHIR-backed proof's transcript to recover every commitment's
/// STIR query indices.
///
/// Native `WhirVerifier::verify` samples these indices internally
/// ([`get_challenge_stir_queries`]) and never returns them — its job is to
/// check a proof, not report intermediate transcript state. This function
/// walks the identical sequence of transcript operations (per commitment,
/// [`p3_sumcheck::layout::Verifier`]'s opening-claim absorption from
/// `p3-whir`'s `PrescribedPointPcs::verify_at`, then `WhirVerifier::verify`'s
/// own round loop), reusing the same public sub-functions native
/// verification does, but records the indices at each STIR-sampling point
/// instead of discarding them.
///
/// `transcript` must be in the state [`crate::generation::OpeningTranscript`]
/// documents — every commitment and public value observed, no opened value
/// observed yet — exactly what
/// [`crate::backend::replay_recursion_input_transcript`] produces for either
/// a uni-STARK or a batch-STARK recursion input. `opening_proof` is the WHIR
/// opening proof's own data (`proof.opening_proof` for a uni-STARK
/// `Proof<SC>`, or the equivalent field on a batch-STARK proof), supplied
/// separately because it is not part of the transcript.
///
/// This does not re-verify the proof's arithmetic (sumcheck claims, the
/// final consistency check): it trusts a proof that has already verified
/// and only needs to reproduce the *shape* of the transcript walk to land on
/// the same challenger states.
///
/// `variable_order` must match the [`p3_sumcheck::layout::Layout`] the proof
/// was produced under. Every current caller uses
/// `p3_sumcheck::layout::PrefixProver`, whose `reverse_selectors` is `true`;
/// `p3_sumcheck::layout::SuffixProver`'s is `false`. Since this function has
/// no `Layout` type parameter of its own, it derives `reverse_selectors`
/// from `variable_order` under that same correspondence — the only two
/// `Layout` implementations this crate ships.
///
/// # Errors
///
/// Returns [`VerificationError::InvalidProofShape`] wherever the proof's
/// shape (commitment count, opening counts/widths, OOD/round/final-poly
/// lengths, PoW witnesses) disagrees with what `protocol_params` and
/// `transcript` imply, or wherever replaying a sub-step
/// ([`Verifier::add_claim_at`], [`p3_sumcheck::data::SumcheckData::verify_rounds`],
/// [`verify_final_sumcheck_rounds`]) itself fails.
///
/// # Panics
///
/// Panics if a committed matrix's domain size is not a power of two
/// ([`log2_strict_usize`]), or if [`Verifier::add_claim_at`]'s own internal
/// invariants (matched variable counts, non-empty opening batches) are
/// violated by a claim this function's own shape checks did not already
/// reject.
pub fn replay_whir_query_indices<SC, MT>(
    transcript: crate::generation::OpeningTranscript<SC>,
    opening_proof: &WhirUniProof<Val<SC>, SC::Challenge, MT>,
    protocol_params: &ProtocolParameters,
    folding: usize,
    variable_order: VariableOrder,
) -> Result<Vec<WhirQueryIndices>, VerificationError>
where
    SC: StarkGenericConfig,
    Val<SC>: TwoAdicField + PrimeField64,
    SC::Challenge: TwoAdicField,
    SC::Challenger: FieldChallenger<Val<SC>>
        + GrindingChallenger<Witness = Val<SC>>
        + CanSampleUniformBits<Val<SC>>
        + CanObserve<MT::Commitment>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SymbolicExpression<Val<SC>>>,
    MT: Mmcs<Val<SC>>,
{
    type F<SC> = Val<SC>;
    type EF<SC> = <SC as StarkGenericConfig>::Challenge;

    let reverse_selectors = match variable_order {
        VariableOrder::Prefix => true,
        VariableOrder::Suffix => false,
    };
    let strategy = LayoutStrategy::new(reverse_selectors, variable_order);

    if transcript.commitments_with_opening_points.len() != opening_proof.rounds.len() {
        return Err(VerificationError::InvalidProofShape(format!(
            "WHIR commitment count mismatch: transcript expects {}, proof carries {}",
            transcript.commitments_with_opening_points.len(),
            opening_proof.rounds.len()
        )));
    }

    // Preflight the entire proof before taking ownership of, or sampling,
    // the replay challenger. This prevents a malformed later commitment from
    // causing any transcript work for an earlier one.
    for ((_commitment, matrices), round_proof) in transcript
        .commitments_with_opening_points
        .iter()
        .zip(&opening_proof.rounds)
    {
        let mut shapes = Vec::with_capacity(matrices.len());
        for (domain, openings) in matrices {
            let width = openings
                .first()
                .map(|(_, values)| values.len())
                .ok_or_else(|| {
                    VerificationError::InvalidProofShape("WHIR commitment has no openings".into())
                })?;
            if openings.iter().any(|(_, values)| values.len() != width) {
                return Err(VerificationError::InvalidProofShape(
                    "WHIR opening width mismatch within one commitment".into(),
                ));
            }
            shapes.push((log2_strict_usize(domain.size()), width, openings.len()));
        }
        let stacked_num_variables = checked_stacked_num_variables(
            shapes
                .iter()
                .map(|&(log_height, width, _)| (padded_arity(log_height, folding), width)),
        )
        .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
        validate_round_config_inputs(stacked_num_variables, protocol_params)
            .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
        let config = WhirConfig::<EF<SC>, F<SC>, SC::Challenger>::new(
            stacked_num_variables,
            protocol_params.clone(),
        )
        .map_err(|error| {
            VerificationError::InvalidProofShape(format!("invalid WHIR config: {error:?}"))
        })?;
        validate_whir_pcs_context::<F<SC>, EF<SC>, MT>(
            round_proof,
            &WhirContextParams::from_native(&config),
            &shapes,
        )?;
    }

    #[cfg(test)]
    acceptance_probe::query_replay();
    let mut challenger = transcript.challenger;

    let mut out = Vec::with_capacity(opening_proof.rounds.len());
    for ((_commitment, matrices), round_proof) in transcript
        .commitments_with_opening_points
        .iter()
        .zip(&opening_proof.rounds)
    {
        // Rebuild the opening schedule from public data only, exactly as
        // `WhirUniPcs::verify_rounds` does.
        let mut shapes = Vec::with_capacity(matrices.len());
        let mut points_per_matrix = Vec::with_capacity(matrices.len());
        for (domain, openings) in matrices {
            let width = openings
                .first()
                .map(|(_, values)| values.len())
                .ok_or_else(|| {
                    VerificationError::InvalidProofShape("WHIR commitment has no openings".into())
                })?;
            if openings.iter().any(|(_, values)| values.len() != width) {
                return Err(VerificationError::InvalidProofShape(
                    "WHIR opening width mismatch within one commitment".into(),
                ));
            }
            shapes.push((log2_strict_usize(domain.size()), width));
            points_per_matrix.push(openings.iter().map(|&(z, _)| z).collect::<Vec<_>>());
        }
        let schedule = pcs::round_schedule::<F<SC>, EF<SC>>(&shapes, &points_per_matrix, folding);

        let whir_config = WhirConfig::<EF<SC>, F<SC>, SC::Challenger>::new(
            schedule.stacked_num_variables,
            protocol_params.clone(),
        )
        .map_err(|e| VerificationError::InvalidProofShape(format!("invalid WHIR config: {e:?}")))?;

        // Mirror `PrescribedPointPcs::verify_at`'s prefix (p3-whir's
        // `pcs/adapter.rs`): bind the initial OOD answers and every opening
        // claim into the layout verifier, absorbing them into the transcript
        // in the same order the prover did.
        if round_proof.whir.initial_ood_answers.len() != whir_config.commitment_ood_samples() {
            return Err(VerificationError::InvalidProofShape(format!(
                "WHIR initial OOD answer count mismatch: expected {}, got {}",
                whir_config.commitment_ood_samples(),
                round_proof.whir.initial_ood_answers.len()
            )));
        }
        let mut layout_verifier =
            Verifier::<F<SC>, EF<SC>>::new(&schedule.protocol.table_shapes(), strategy);
        for &eval in &round_proof.whir.initial_ood_answers {
            layout_verifier.add_virtual_eval(eval, &mut challenger);
        }
        if schedule.protocol.num_openings() != round_proof.evals.len() {
            return Err(VerificationError::InvalidProofShape(format!(
                "WHIR opening batch count mismatch: expected {}, got {}",
                schedule.protocol.num_openings(),
                round_proof.evals.len()
            )));
        }
        for (((table_idx, batch), point), evals) in schedule
            .protocol
            .iter_openings()
            .zip(&schedule.points)
            .zip(&round_proof.evals)
        {
            if !batch.has_same_shape(evals) {
                return Err(VerificationError::InvalidProofShape(format!(
                    "WHIR opening batch shape mismatch at table {table_idx}"
                )));
            }
            layout_verifier
                .add_claim_at(table_idx, batch, point, evals, &mut challenger)
                .map_err(|e| {
                    VerificationError::InvalidProofShape(format!(
                        "WHIR opening claim replay failed: {e:?}"
                    ))
                })?;
        }
        // Mirror `WhirVerifier::verify` (p3-whir's `pcs/verifier/mod.rs`) through p3-whir's own
        // typed transcript, capturing STIR indices instead of the arithmetic each step also
        // produces.
        let n_rounds = whir_config.n_rounds();
        if round_proof.whir.rounds.len() != n_rounds {
            return Err(VerificationError::InvalidProofShape(format!(
                "WHIR round count mismatch: expected {n_rounds}, got {}",
                round_proof.whir.rounds.len()
            )));
        }
        let final_poly = round_proof.whir.final_poly.as_ref().ok_or_else(|| {
            VerificationError::InvalidProofShape("WHIR proof missing final polynomial".into())
        })?;
        let shape = WhirShape::new(&whir_config, schedule.protocol.num_openings());
        let mut whir_transcript =
            WhirVerifierTranscript::<SC::Challenger, F<SC>, EF<SC>>::new(&mut challenger, shape);
        let replayed = replay_whir_rounds::<SC, MT>(
            &mut whir_transcript,
            &whir_config,
            &layout_verifier,
            &round_proof.whir,
            final_poly.as_slice(),
        );
        let (rounds_indices, final_queries) = match replayed {
            Ok(indices) => {
                whir_transcript.finish();
                indices
            }
            Err(error) => {
                whir_transcript.abort();
                return Err(error);
            }
        };

        out.push(WhirQueryIndices {
            stacked_num_variables: schedule.stacked_num_variables,
            rounds: rounds_indices,
            final_queries,
        });
    }

    Ok(out)
}

/// STIR indices of one WHIR argument: per intermediate round, then the final phase.
type ReplayedWhirIndices = (Vec<Vec<usize>>, Vec<usize>);

/// Replay one WHIR argument's rounds on a live typed transcript.
///
/// The caller seeds the transcript and must `finish` it on success or `abort` it on error.
fn replay_whir_rounds<SC, MT>(
    transcript: &mut WhirVerifierTranscript<'_, SC::Challenger, Val<SC>, SC::Challenge>,
    whir_config: &WhirConfig<SC::Challenge, Val<SC>, SC::Challenger>,
    layout_verifier: &Verifier<Val<SC>, SC::Challenge>,
    proof: &p3_whir::pcs::proof::WhirProof<Val<SC>, SC::Challenge, MT>,
    final_poly: &[SC::Challenge],
) -> Result<ReplayedWhirIndices, VerificationError>
where
    SC: StarkGenericConfig,
    Val<SC>: TwoAdicField + PrimeField64,
    SC::Challenge: TwoAdicField,
    SC::Challenger: FieldChallenger<Val<SC>>
        + GrindingChallenger<Witness = Val<SC>>
        + CanSampleUniformBits<Val<SC>>
        + CanObserve<MT::Commitment>,
    MT: Mmcs<Val<SC>>,
{
    let invalid = |what: &str, e: &dyn core::fmt::Debug| {
        VerificationError::InvalidProofShape(format!("WHIR {what} replay failed: {e:?}"))
    };

    // A dummy running sum: the sumcheck replays fold proof data into it, but its value never
    // feeds back into the challenger, so it plays no part in which indices get sampled.
    let mut claimed_eval = SC::Challenge::ZERO;
    let _ = transcript
        .delegate_initial_fold(|challenger| {
            // The WHIR batching challenge: transcript side effect only.
            let _alpha = layout_verifier.batching_challenge(challenger);
            proof.initial_sumcheck.verify_rounds(
                challenger,
                &mut claimed_eval,
                whir_config.round_folding_factor(0),
                whir_config.starting_folding_pow_bits(),
                Basis::Evaluation,
            )
        })
        .map_err(|e| invalid("initial sumcheck", &e))?;

    let n_rounds = whir_config.n_rounds();
    let mut rounds_indices = Vec::with_capacity(n_rounds);
    for round_index in 0..n_rounds {
        let round_params = &whir_config.round_parameters()[round_index];
        let whir_round = &proof.rounds[round_index];

        // Mirrors `ParsedCommitment::parse_with_round`: the round's commitment root, then per
        // OOD sample a point and its answer.
        let commitment = whir_round.commitment.clone().ok_or_else(|| {
            VerificationError::InvalidProofShape(format!(
                "WHIR round {round_index} is missing its commitment"
            ))
        })?;
        if whir_round.ood_answers.len() != round_params.ood_samples {
            return Err(VerificationError::InvalidProofShape(format!(
                "WHIR round {round_index} OOD answer count mismatch: expected {}, got {}",
                round_params.ood_samples,
                whir_round.ood_answers.len()
            )));
        }
        transcript.commitment(commitment);
        for &eval in &whir_round.ood_answers {
            let _ood_point = transcript.ood_point();
            transcript.ood_answer(eval);
        }

        transcript
            .query_pow(round_index, whir_round.pow_witness)
            .map_err(|e| invalid("round PoW", &e))?;
        rounds_indices.push(transcript.query_indices(round_index));

        // The per-round batching challenge: transcript side effect only.
        let _gamma = transcript.round_batching();

        let _ = transcript
            .delegate_round_fold(|challenger| {
                whir_round.sumcheck.verify_rounds(
                    challenger,
                    &mut claimed_eval,
                    whir_config.round_folding_factor(round_index + 1),
                    round_params.folding_pow_bits,
                    Basis::Evaluation,
                )
            })
            .map_err(|e| invalid("round sumcheck", &e))?;
    }

    // Final phase: the final polynomial, its grind, the final STIR indices, then the optional
    // final plain sumcheck.
    transcript
        .final_poly(final_poly)
        .map_err(|e| invalid("final polynomial", &e))?;
    transcript
        .query_pow(n_rounds, proof.final_pow_witness)
        .map_err(|e| invalid("final PoW", &e))?;
    let final_queries = transcript.query_indices(n_rounds);
    transcript
        .delegate_final_fold(|challenger| {
            verify_final_sumcheck_rounds(
                proof.final_sumcheck.as_ref(),
                challenger,
                &mut claimed_eval,
                whir_config.final_sumcheck_rounds(),
                whir_config.final_folding_pow_bits(),
                Basis::Evaluation,
            )
        })
        .transpose()
        .map_err(|e| invalid("final sumcheck", &e))?;

    Ok((rounds_indices, final_queries))
}
