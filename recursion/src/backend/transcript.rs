//! Off-circuit replay of the transcript a recursion layer's input proof was verified under.
//!
//! A recursive verifier reproduces its input proof's Fiat-Shamir transcript in-circuit, so nothing
//! about it normally has to exist off-circuit. Witness generation is the exception: a FRI proof's
//! Merkle multiproofs are pruned across queries, and reassembling one full authentication chain per
//! query needs the queried leaf indices and each commit-phase round's reconstructed evaluation row
//! — neither of which the proof carries. Both come out of the verifier's own transcript, which is
//! what this module replays.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::ToString;

use p3_batch_stark::CommonData;
use p3_batch_stark::common::GlobalPreprocessed;
use p3_circuit_prover::batch_stark_prover::{
    BatchStarkProof, TableProver, lookups_for_circuit_table_air,
};
use p3_circuit_prover::field_params::ExtractBinomialW;
use p3_field::{Algebra, ExtensionField, PrimeField64};
use p3_lookup::logup::LogUpGadget;
use p3_uni_stark::{StarkGenericConfig, SymbolicExpression, SymbolicExpressionExt, Val};

use crate::generation::{
    OpeningTranscript, replay_batch_stark_transcript, replay_uni_stark_transcript,
};
use crate::recursion::RecursionInput;
use crate::traits::RecursiveAir;
use crate::verifier::{ReconstructedBatchTables, VerificationError, reconstruct_batch_tables};

/// Replay the transcript of the proof a recursion layer verifies, up to its PCS opening argument.
///
/// Dispatches to [`replay_uni_stark_transcript`] or [`replay_batch_stark_transcript`] depending on
/// the input variant, deriving the batch case's AIRs from the proof's manifest exactly as
/// [`verify_p3_batch_proof_circuit`](crate::verifier::verify_p3_batch_proof_circuit) does.
///
/// `non_primitive_provers` must be the same list the verifier circuit was built with — the plugins
/// that turn the proof's non-primitive manifest entries into AIRs.
pub fn replay_recursion_input_transcript<SC, A>(
    config: &SC,
    prev: &RecursionInput<'_, SC, A>,
    non_primitive_provers: &[Box<dyn TableProver<SC>>],
) -> Result<OpeningTranscript<SC>, VerificationError>
where
    SC: StarkGenericConfig + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    Val<SC>: PrimeField64,
    SC::Challenge: ExtensionField<Val<SC>> + ExtractBinomialW<Val<SC>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    match prev {
        RecursionInput::UniStark {
            proof,
            air,
            public_inputs,
            preprocessed_commit,
        } => replay_uni_stark_transcript(
            config,
            *air,
            proof,
            public_inputs,
            preprocessed_commit.as_ref(),
        )
        .map_err(|e| VerificationError::InvalidProofShape(e.to_string())),
        RecursionInput::BatchStark {
            proof, common_data, ..
        } => match proof.ext_degree {
            1 => replay_batch_layer_transcript::<SC, 1>(
                config,
                proof,
                common_data,
                non_primitive_provers,
            ),
            2 => replay_batch_layer_transcript::<SC, 2>(
                config,
                proof,
                common_data,
                non_primitive_provers,
            ),
            4 => replay_batch_layer_transcript::<SC, 4>(
                config,
                proof,
                common_data,
                non_primitive_provers,
            ),
            5 => replay_batch_layer_transcript::<SC, 5>(
                config,
                proof,
                common_data,
                non_primitive_provers,
            ),
            d => Err(VerificationError::InvalidProofShape(format!(
                "unsupported batch proof ext_degree {d}"
            ))),
        },
    }
}

/// Replay a recursion-layer batch-STARK proof's transcript for a fixed trace extension degree.
///
/// `D` and `non_primitive_provers` must be the ones the verifier circuit was built with — the
/// same arguments passed to
/// [`verify_p3_batch_proof_circuit`](crate::verifier::verify_p3_batch_proof_circuit).
///
/// The lookup contexts come from the rebuilt AIRs rather than from the proof's own `CommonData`,
/// matching what the verifier circuit binds: they drive the CTL folding and hence the challenge
/// layout the transcript commits to.
pub fn replay_batch_layer_transcript<SC, const D: usize>(
    config: &SC,
    proof: &BatchStarkProof<SC>,
    common_data: &CommonData<SC>,
    non_primitive_provers: &[Box<dyn TableProver<SC>>],
) -> Result<OpeningTranscript<SC>, VerificationError>
where
    SC: StarkGenericConfig + 'static,
    Val<SC>: PrimeField64,
    SC::Challenge: ExtensionField<Val<SC>> + ExtractBinomialW<Val<SC>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    let ReconstructedBatchTables {
        airs,
        trace_lens,
        public_values,
    } = reconstruct_batch_tables::<SC, D>(config, proof, non_primitive_provers)?;

    let lookups = airs
        .iter()
        .zip(&trace_lens)
        .map(|(air, &trace_len)| {
            lookups_for_circuit_table_air::<SC, D>(&air.to_table_air(), trace_len, config.is_zk())
        })
        .collect();
    let effective_common = CommonData::new(
        common_data
            .preprocessed
            .as_ref()
            .map(|g| GlobalPreprocessed {
                commitment: g.commitment.clone(),
                instances: g.instances.clone(),
                matrix_to_instance: g.matrix_to_instance.clone(),
            }),
        lookups,
    );

    let (transcript, _) = replay_batch_stark_transcript(
        &airs,
        config,
        &proof.proof,
        &public_values,
        &effective_common,
        &LogUpGadget::new(),
    )
    .map_err(|e| VerificationError::InvalidProofShape(e.to_string()))?;

    Ok(transcript)
}
