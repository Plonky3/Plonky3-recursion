//! Execution state and private data for Poseidon2 permutation operations.

use alloc::vec::Vec;

use crate::ops::poseidon2_perm::trace::Poseidon2CircuitRow;

/// Private data for Poseidon2 permutation.
///
/// Only used for Merkle mode operations, contains exactly `SIBLING_LIMBS` extension field limbs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Poseidon2PermPrivateData<F, const SIBLING_LIMBS: usize> {
    pub sibling: [F; SIBLING_LIMBS],
}

/// Execution state for Poseidon2 permutation operations.
#[derive(Debug)]
pub(crate) struct Poseidon2ExecutionState<F> {
    pub last_output_normal: Option<Vec<F>>,
    pub last_output_merkle: Option<Vec<F>>,
    /// Circuit rows captured during execution.
    pub rows: Vec<Poseidon2CircuitRow<F>>,
}

impl<F> Default for Poseidon2ExecutionState<F> {
    fn default() -> Self {
        let rows = Vec::with_capacity(2048);
        Self {
            last_output_normal: None,
            last_output_merkle: None,
            rows,
        }
    }
}
