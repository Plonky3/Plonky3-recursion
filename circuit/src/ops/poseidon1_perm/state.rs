//! Execution state and private data for Poseidon1 permutation operations.

use crate::ops::poseidon_perm::{
    Poseidon1Variant, PoseidonExecutionState, PoseidonPermPrivateData,
};

/// Private data for Poseidon1 permutation (Merkle-mode `sibling` limbs).
pub type Poseidon1PermPrivateData<F> = PoseidonPermPrivateData<F>;

/// Execution state for Poseidon1 permutation operations.
pub(crate) type Poseidon1ExecutionState<F> = PoseidonExecutionState<Poseidon1Variant, F>;
