//! Off-circuit reconstruction of the per-query Merkle chains a WHIR recursive verifier's
//! in-circuit MMCS gadget needs as private data.
//!
//! A WHIR proof's Merkle openings are pruned multiproofs, the same way FRI's are: siblings
//! shared by two queries are stored once. The in-circuit MMCS gadget walks one full
//! authentication path per query, so this module restores those full chains off-circuit,
//! using the queried indices [`crate::pcs::whir::uni::replay_whir_query_indices`] recovers
//! from the transcript (they are not present in the proof itself).

use alloc::vec::Vec;

use p3_challenger::{CanObserve, CanSampleUniformBits, FieldChallenger, GrindingChallenger};
use p3_field::{Algebra, PackedValue, PrimeField64, TwoAdicField};
use p3_matrix::Dimensions;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CryptographicHasher, MerkleCap, PseudoCompressionFunction};
use p3_uni_stark::{StarkGenericConfig, SymbolicExpression, SymbolicExpressionExt, Val};
use p3_whir::parameters::{ProtocolParameters, WhirConfig};
use serde::{Deserialize, Serialize};

use super::WhirUniProof;
use crate::generation::OpeningTranscript;
use crate::pcs::restore_whir_query_paths;
use crate::pcs::whir::uni::{VariableOrder, replay_whir_query_indices};
use crate::verifier::VerificationError;

/// Restored Merkle chains for one commitment's WHIR argument.
pub struct WhirRoundPaths<F, const DIGEST_ELEMS: usize> {
    /// `rounds[i][q]` is the chain for intermediate round `i`'s query `q`.
    pub rounds: Vec<Vec<Vec<[F; DIGEST_ELEMS]>>>,
    /// `final_paths[q]` is the chain for final query `q`.
    pub final_paths: Vec<Vec<[F; DIGEST_ELEMS]>>,
}

/// Number of sibling digests one commitment's chains consume, which is exactly the number
/// of non-primitive ops `verify_whir_circuit` emits for it.
pub fn whir_round_paths_op_count<F, const DIGEST_ELEMS: usize>(
    paths: &WhirRoundPaths<F, DIGEST_ELEMS>,
) -> usize {
    paths
        .rounds
        .iter()
        .flatten()
        .map(Vec::len)
        .chain(paths.final_paths.iter().map(Vec::len))
        .sum()
}

/// Restore every commitment's per-query Merkle chains for one WHIR-backed recursion input.
///
/// `transcript` must be in the state [`OpeningTranscript`] documents (every commitment and
/// public value observed, no opened value observed yet) — produce it with
/// [`crate::backend::replay_recursion_input_transcript`] for either a uni-STARK or
/// batch-STARK `RecursionInput`. `opening_proof` is the WHIR-native opening proof
/// (`proof.opening_proof` on a uni-STARK `Proof<SC>`; the equivalent field for batch-STARK).
///
/// Generic over the base-field Merkle tree's own components (`P`/`PW`/`H`/`C`/`N`, matching
/// [`restore_whir_query_paths`]'s own parameterization) rather than over a single `Mmcs`-bound
/// type: `restore_whir_query_paths` restores paths through `MerkleTreeMmcs`'s inherent
/// `restore_and_recompute_paths`, which is concrete to that struct, not a method the `Mmcs`
/// trait itself exposes, so a caller's own `MerkleTreeMmcs<P, PW, H, C, N, DIGEST_ELEMS>` alias
/// (e.g. `BbMmcs`) supplies all five at the call site while `SC` and `DIGEST_ELEMS` are given
/// explicitly.
#[expect(clippy::type_complexity)]
pub fn restore_whir_recursion_paths<SC, P, PW, H, C, const N: usize, const DIGEST_ELEMS: usize>(
    mmcs: &MerkleTreeMmcs<P, PW, H, C, N, DIGEST_ELEMS>,
    transcript: OpeningTranscript<SC>,
    opening_proof: &WhirUniProof<
        Val<SC>,
        SC::Challenge,
        MerkleTreeMmcs<P, PW, H, C, N, DIGEST_ELEMS>,
    >,
    protocol_params: &ProtocolParameters,
    folding: usize,
    variable_order: VariableOrder,
) -> Result<Vec<WhirRoundPaths<Val<SC>, DIGEST_ELEMS>>, VerificationError>
where
    SC: StarkGenericConfig,
    Val<SC>: TwoAdicField + PrimeField64,
    SC::Challenge: TwoAdicField,
    SC::Challenger: FieldChallenger<Val<SC>>
        + GrindingChallenger<Witness = Val<SC>>
        + CanSampleUniformBits<Val<SC>>
        + CanObserve<MerkleCap<Val<SC>, [Val<SC>; DIGEST_ELEMS]>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SymbolicExpression<Val<SC>>>,
    P: PackedValue<Value = Val<SC>>,
    PW: PackedValue<Value = Val<SC>>,
    H: CryptographicHasher<Val<SC>, [Val<SC>; DIGEST_ELEMS]>
        + CryptographicHasher<P, [PW; DIGEST_ELEMS]>
        + Sync,
    C: PseudoCompressionFunction<[Val<SC>; DIGEST_ELEMS], N>
        + PseudoCompressionFunction<[PW; DIGEST_ELEMS], N>
        + Sync,
    [Val<SC>; DIGEST_ELEMS]: Serialize + for<'de> Deserialize<'de>,
{
    let indices = replay_whir_query_indices::<SC, MerkleTreeMmcs<P, PW, H, C, N, DIGEST_ELEMS>>(
        transcript,
        opening_proof,
        protocol_params,
        folding,
        variable_order,
    )?;

    let mut out = Vec::with_capacity(opening_proof.rounds.len());
    for (round_idx, round) in opening_proof.rounds.iter().enumerate() {
        let cfg = WhirConfig::<SC::Challenge, Val<SC>, SC::Challenger>::new(
            indices[round_idx].stacked_num_variables,
            protocol_params.clone(),
        )
        .map_err(|e| VerificationError::InvalidProofShape(alloc::format!("{e:?}")))?;

        let mut rounds = Vec::new();
        for (i, rp) in cfg.round_parameters.iter().enumerate() {
            let dims = [Dimensions {
                height: rp.domain_size >> rp.folding_factor,
                width: 1 << rp.folding_factor,
            }];
            rounds.push(
                restore_whir_query_paths::<P, PW, SC::Challenge, H, C, N, DIGEST_ELEMS>(
                    mmcs,
                    &round.whir.rounds[i].openings,
                    &dims,
                    &indices[round_idx].rounds[i],
                )
                .map_err(|e| VerificationError::InvalidProofShape(alloc::format!("{e:?}")))?,
            );
        }

        // The final phase's folded-domain size and STIR index bit-width are sized by the
        // fold applied to *enter* the final phase (`final_cfg.folding_factor`), not by
        // `final_sumcheck_rounds` (the number of plain-sumcheck rounds performed *after*
        // that fold) — these are different quantities that happen to coincide only for
        // specific arities.
        let final_cfg = cfg.final_round_config();
        let final_dims = [Dimensions {
            height: final_cfg.domain_size >> final_cfg.folding_factor,
            width: 1 << final_cfg.folding_factor,
        }];
        let final_paths = restore_whir_query_paths::<P, PW, SC::Challenge, H, C, N, DIGEST_ELEMS>(
            mmcs,
            &round.whir.final_openings,
            &final_dims,
            &indices[round_idx].final_queries,
        )
        .map_err(|e| VerificationError::InvalidProofShape(alloc::format!("{e:?}")))?;

        out.push(WhirRoundPaths {
            rounds,
            final_paths,
        });
    }
    Ok(out)
}
