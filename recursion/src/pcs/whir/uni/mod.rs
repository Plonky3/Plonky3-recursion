//! Bridge from WHIR's multilinear PCS to the univariate STARK machinery.

pub mod bridge;
pub mod circuit;
pub mod pcs;
pub mod plan;
pub mod recursive_pcs;
pub mod targets;

use alloc::format;
use alloc::vec::Vec;

pub use bridge::{univariate_eq_point, univariate_eq_point_circuit};
pub use circuit::{MatrixOpenings, RoundClaims, build_round_claims};
use p3_challenger::{
    CanObserve, CanSample, CanSampleUniformBits, FieldChallenger, GrindingChallenger,
};
use p3_commit::{Mmcs, Pcs as PcsTrait, PolynomialSpace};
use p3_field::{Algebra, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_lookup::logup::LogUpGadget;
use p3_sumcheck::layout::{LayoutStrategy, Verifier};
use p3_sumcheck::strategy::{Basis, VariableOrder};
use p3_sumcheck::verify_final_sumcheck_rounds;
use p3_uni_stark::{StarkGenericConfig, SymbolicExpression, SymbolicExpressionExt, Val};
use p3_util::log2_strict_usize;
use p3_whir::parameters::{ProtocolParameters, WhirConfig};
use p3_whir::pcs::utils::get_challenge_stir_queries;
pub use pcs::{WhirUniPcs, WhirUniPcsError, WhirUniProof, WhirUniProverData};
pub use plan::{StackedPlacement, StackedPlan, StackedSelector, padded_arity};
pub use recursive_pcs::WhirUniVerifierParams;
pub use targets::{WhirRoundTargets, WhirUniProofTargets, packed_digest_len};

use crate::VerificationError;
use crate::generation::replay_uni_stark_transcript;
use crate::traits::RecursiveAir;

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

/// Replays a WHIR-backed uni-STARK proof's transcript to recover every
/// commitment's STIR query indices.
///
/// Native `WhirVerifier::verify` samples these indices internally
/// ([`get_challenge_stir_queries`]) and never returns them — its job is to
/// check a proof, not report intermediate transcript state. This function
/// walks the identical sequence of transcript operations
/// ([`p3_uni_stark::verify`]'s prefix via [`replay_uni_stark_transcript`],
/// then, per commitment, [`p3_sumcheck::layout::Verifier`]'s opening-claim
/// absorption from `p3-whir`'s `PrescribedPointPcs::verify_at`, then
/// `WhirVerifier::verify`'s own round loop), reusing the same public
/// sub-functions native verification does, but records the indices at each
/// STIR-sampling point instead of discarding them.
///
/// This does not re-verify the proof's arithmetic (sumcheck claims, the
/// final consistency check): it trusts a proof that has already verified
/// (via [`p3_uni_stark::verify`]) and only needs to reproduce the *shape* of
/// the transcript walk to land on the same challenger states.
///
/// `variable_order` must match the [`p3_sumcheck::layout::Layout`] the proof
/// was produced under. Every current caller uses
/// `p3_sumcheck::layout::PrefixProver`, whose `reverse_selectors` is `true`;
/// `p3_sumcheck::layout::SuffixProver`'s is `false`. Since this function has
/// no `Layout` type parameter of its own, it derives `reverse_selectors`
/// from `variable_order` under that same correspondence — the only two
/// `Layout` implementations this crate ships.
///
/// Only AIRs with no preprocessed columns are supported: the call into
/// [`replay_uni_stark_transcript`] always passes `None` for the preprocessed
/// commitment. An AIR whose opened values carry a preprocessed part fails
/// there with an `InvalidProofShape`-style error about a commitment/width
/// mismatch, not a dedicated error variant for this specific limitation.
///
/// # Errors
///
/// Returns [`VerificationError::InvalidProofShape`] wherever the proof's
/// shape (commitment count, opening counts/widths, OOD/round/final-poly
/// lengths, PoW witnesses) disagrees with what `protocol_params` and the
/// public inputs imply, or wherever replaying a sub-step
/// ([`replay_uni_stark_transcript`], [`Verifier::add_claim_at`],
/// [`p3_sumcheck::data::SumcheckData::verify_rounds`],
/// [`verify_final_sumcheck_rounds`]) itself fails.
///
/// # Panics
///
/// Panics if a committed matrix's domain size is not a power of two
/// ([`log2_strict_usize`]), or if [`Verifier::add_claim_at`]'s own internal
/// invariants (matched variable counts, non-empty opening batches) are
/// violated by a claim this function's own shape checks did not already
/// reject.
pub fn replay_whir_query_indices<SC, A, MT>(
    config: &SC,
    air: &A,
    proof: &p3_uni_stark::Proof<SC>,
    public_values: &[Val<SC>],
    protocol_params: &ProtocolParameters,
    folding: usize,
    variable_order: VariableOrder,
) -> Result<Vec<WhirQueryIndices>, VerificationError>
where
    SC: StarkGenericConfig,
    SC::Pcs:
        PcsTrait<SC::Challenge, SC::Challenger, Proof = WhirUniProof<Val<SC>, SC::Challenge, MT>>,
    Val<SC>: TwoAdicField + PrimeField64,
    SC::Challenge: TwoAdicField,
    SC::Challenger: FieldChallenger<Val<SC>>
        + GrindingChallenger<Witness = Val<SC>>
        + CanSampleUniformBits<Val<SC>>
        + CanObserve<MT::Commitment>,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SymbolicExpression<Val<SC>>>,
    MT: Mmcs<Val<SC>>,
{
    type F<SC> = Val<SC>;
    type EF<SC> = <SC as StarkGenericConfig>::Challenge;

    let transcript = replay_uni_stark_transcript(config, air, proof, public_values, None)?;
    let mut challenger = transcript.challenger;

    let reverse_selectors = match variable_order {
        VariableOrder::Prefix => true,
        VariableOrder::Suffix => false,
    };
    let strategy = LayoutStrategy::new(reverse_selectors, variable_order);

    if transcript.commitments_with_opening_points.len() != proof.opening_proof.rounds.len() {
        return Err(VerificationError::InvalidProofShape(format!(
            "WHIR commitment count mismatch: transcript expects {}, proof carries {}",
            transcript.commitments_with_opening_points.len(),
            proof.opening_proof.rounds.len()
        )));
    }

    let mut out = Vec::with_capacity(proof.opening_proof.rounds.len());
    for ((_commitment, matrices), round_proof) in transcript
        .commitments_with_opening_points
        .iter()
        .zip(&proof.opening_proof.rounds)
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
        if round_proof.whir.initial_ood_answers.len() != whir_config.commitment_ood_samples {
            return Err(VerificationError::InvalidProofShape(format!(
                "WHIR initial OOD answer count mismatch: expected {}, got {}",
                whir_config.commitment_ood_samples,
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
        // The WHIR batching challenge: sampled here for its transcript side
        // effect only. Its value feeds the arithmetic constraint this
        // replay does not need to build.
        let _alpha: EF<SC> = challenger.sample_algebra_element();

        // Mirror `WhirVerifier::verify`'s round loop (p3-whir's
        // `pcs/verifier/mod.rs`), capturing STIR indices instead of the
        // arithmetic each step also produces.
        let n_rounds = whir_config.n_rounds();
        if round_proof.whir.rounds.len() != n_rounds {
            return Err(VerificationError::InvalidProofShape(format!(
                "WHIR round count mismatch: expected {n_rounds}, got {}",
                round_proof.whir.rounds.len()
            )));
        }

        // A dummy running sum: `verify_rounds`/`verify_final_sumcheck_rounds`
        // fold proof data into it, but its value never feeds back into the
        // challenger, so it plays no part in which indices get sampled.
        let mut claimed_eval = EF::<SC>::ZERO;
        round_proof
            .whir
            .initial_sumcheck
            .verify_rounds(
                &mut challenger,
                &mut claimed_eval,
                whir_config.round_folding_factor(0),
                whir_config.starting_folding_pow_bits,
                Basis::Evaluation,
            )
            .map_err(|e| {
                VerificationError::InvalidProofShape(format!(
                    "WHIR initial sumcheck replay failed: {e:?}"
                ))
            })?;

        let mut rounds_indices = Vec::with_capacity(n_rounds);
        for round_index in 0..n_rounds {
            let round_params = &whir_config.round_parameters[round_index];
            let whir_round = &round_proof.whir.rounds[round_index];

            // Mirrors `ParsedCommitment::parse_with_round` (p3-whir,
            // `pcs/committer/reader.rs`, `pub(crate)` there and so not
            // reachable from this crate): observe the round's commitment
            // root, then per OOD sample, sample a point and observe its
            // answer. Only the transcript side effect matters here — the
            // `EqStatement` native code builds from these samples feeds the
            // arithmetic constraint this replay does not need.
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
            challenger.observe(commitment);
            for &eval in &whir_round.ood_answers {
                let _ood_point: EF<SC> = challenger.sample_algebra_element();
                challenger.observe_algebra_element(eval);
            }

            // PoW check, then the intermediate-round transcript checkpoint
            // (native calls this only for `round_index < n_rounds()`, i.e.
            // every intermediate round but not the final phase), then the
            // STIR indices themselves.
            if round_params.pow_bits > 0
                && !challenger.check_witness(round_params.pow_bits, whir_round.pow_witness)
            {
                return Err(VerificationError::InvalidProofShape(format!(
                    "WHIR round {round_index} PoW check failed during replay"
                )));
            }
            let _checkpoint: F<SC> = challenger.sample();
            rounds_indices.push(get_challenge_stir_queries::<SC::Challenger, F<SC>>(
                round_params.domain_size,
                round_params.folding_factor,
                round_params.num_queries,
                &mut challenger,
            ));

            // The per-round batching challenge: transcript side effect only.
            let _gamma: EF<SC> = challenger.sample_algebra_element();

            whir_round
                .sumcheck
                .verify_rounds(
                    &mut challenger,
                    &mut claimed_eval,
                    whir_config.round_folding_factor(round_index + 1),
                    round_params.folding_pow_bits,
                    Basis::Evaluation,
                )
                .map_err(|e| {
                    VerificationError::InvalidProofShape(format!(
                        "WHIR round {round_index} sumcheck replay failed: {e:?}"
                    ))
                })?;
        }

        // Final phase: observe the final polynomial, PoW-check (no
        // checkpoint sample here — native only takes one for intermediate
        // rounds), sample the final STIR indices, then replay the optional
        // final plain sumcheck.
        let final_round_config = whir_config.final_round_config();
        let final_poly = round_proof.whir.final_poly.as_ref().ok_or_else(|| {
            VerificationError::InvalidProofShape("WHIR proof missing final polynomial".into())
        })?;
        let expected_final_poly_len = 1usize << final_round_config.num_variables;
        if final_poly.num_evals() != expected_final_poly_len {
            return Err(VerificationError::InvalidProofShape(format!(
                "WHIR final polynomial length mismatch: expected {expected_final_poly_len}, got {}",
                final_poly.num_evals()
            )));
        }
        challenger.observe_algebra_slice(final_poly.as_slice());

        if final_round_config.pow_bits > 0
            && !challenger.check_witness(
                final_round_config.pow_bits,
                round_proof.whir.final_pow_witness,
            )
        {
            return Err(VerificationError::InvalidProofShape(
                "WHIR final PoW check failed during replay".into(),
            ));
        }
        let final_queries = get_challenge_stir_queries::<SC::Challenger, F<SC>>(
            final_round_config.domain_size,
            final_round_config.folding_factor,
            final_round_config.num_queries,
            &mut challenger,
        );

        verify_final_sumcheck_rounds(
            round_proof.whir.final_sumcheck.as_ref(),
            &mut challenger,
            &mut claimed_eval,
            whir_config.final_sumcheck_rounds,
            whir_config.final_folding_pow_bits,
            Basis::Evaluation,
        )
        .map_err(|e| {
            VerificationError::InvalidProofShape(format!(
                "WHIR final sumcheck replay failed: {e:?}"
            ))
        })?;

        out.push(WhirQueryIndices {
            stacked_num_variables: schedule.stacked_num_variables,
            rounds: rounds_indices,
            final_queries,
        });
    }

    Ok(out)
}
