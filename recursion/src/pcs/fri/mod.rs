//! FRI for recursive verification.

mod context;
mod params;
mod targets;
mod verifier;

pub use context::{CheckedFriCommitment, CheckedFriOpening, ValidatedFriContext};
pub use params::{FriInputError, FriVerifierParams, FriVerifierParamsError, NativeFriParams};
pub(crate) use targets::validate_merkle_cap_context;
pub use targets::{
    BatchOpeningTargets, CommitPhaseProofStepTargets, FriProofTargets, HashProofTargets,
    HidingFriProofTargets, HidingHashProofTargets, HidingOpenedValuesTargets, InputProofTargets,
    MerkleCapTargets, MmcsProofTargets, PreparedRecursiveFriInputOpenings,
    PreparedRecursiveMultiProofTargets, QueryProofTargets, RecExtensionValMmcs,
    RecExtensionValMmcsArity4, RecValHidingMmcs, RecValMmcs, RecValMmcsArity4,
    RecursiveFriInputOpenings, RecursiveMultiProofTargets, TwoAdicFriProofTargets, Witness,
    fri_proof_num_queries,
};
pub(crate) use verifier::commitment_cap_rows_from_lifted;
pub use verifier::verify_fri_circuit;

/// The log arity of one native commit-phase round, read off its sibling rows.
///
/// Since p3-fri 0.8 the fold schedule is derived from the configuration rather than carried in
/// the proof, so a round only records its arity implicitly: every query row holds `2^k - 1`
/// sibling values. Returns `None` when the round has no rows, the rows disagree, or the row width
/// is not of that form. Callers that need the configured schedule itself use
/// [`p3_fri::fold_schedule`]; this helper only recovers what a proof claims.
pub(crate) fn sibling_log_arity<F, M>(step: &p3_fri::CommitPhaseMultiStep<F, M>) -> Option<usize>
where
    F: p3_field::Field,
    M: p3_commit::Mmcs<F>,
{
    let width = step.sibling_values.first()?.len();
    if step.sibling_values.iter().any(|row| row.len() != width) {
        return None;
    }
    let arity = width.checked_add(1)?;
    (arity.is_power_of_two() && arity > 1).then(|| arity.trailing_zeros() as usize)
}
