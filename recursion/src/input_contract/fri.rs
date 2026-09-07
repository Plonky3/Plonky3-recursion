//! Structural descriptors for recursive FRI input allocation.

use alloc::vec::Vec;

/// Number of roots observed from a native Merkle cap.
#[derive(Clone, PartialEq, Eq)]
pub struct MerkleCapShape {
    pub(crate) roots: usize,
}

/// Complete allocation-relevant structure of a native FRI proof.
#[derive(Clone, PartialEq, Eq)]
pub struct FriShape<C, I, M, W> {
    pub(crate) commit_phase_commits: Vec<C>,
    pub(crate) commit_pow_witnesses: Vec<W>,
    pub(crate) input_openings: I,
    pub(crate) commit_phase_openings: Vec<FriCommitStepShape<M>>,
    pub(crate) final_poly: usize,
    pub(crate) query_pow_witness: W,
}

/// Allocation-relevant structure of one FRI commit-phase opening round.
#[derive(Clone, PartialEq, Eq)]
pub struct FriCommitStepShape<M> {
    pub(crate) log_arity: u8,
    pub(crate) sibling_values: Vec<usize>,
    pub(crate) opening_advice: M,
}

/// Allocation-relevant structure of one FRI input batch.
#[derive(Clone, PartialEq, Eq)]
pub struct FriInputBatchShape<M> {
    pub(crate) opened_values: Vec<Vec<usize>>,
    pub(crate) opening_advice: M,
}

/// Per-query, per-matrix salt lengths for a hiding MMCS multiproof.
#[derive(Clone, PartialEq, Eq)]
pub struct HidingOpeningAdviceShape {
    pub(crate) salts: Vec<Vec<usize>>,
}

/// Hiding FRI structure layered over the ordinary FRI descriptor.
#[derive(Clone, PartialEq, Eq)]
pub struct HidingFriShape<P> {
    pub(crate) random_openings: Vec<Vec<Vec<usize>>>,
    pub(crate) inner: P,
}
