//! Execution state and private data for Poseidon2 permutation operations.

use crate::ops::poseidon_perm::{
    Poseidon2Variant, PoseidonExecutionState, PoseidonPermPrivateData,
};

/// Private data for Poseidon2 permutation (Merkle-mode `sibling` limbs).
pub type Poseidon2PermPrivateData<F> = PoseidonPermPrivateData<F>;

/// Execution state for Poseidon2 permutation operations.
pub(crate) type Poseidon2ExecutionState<F> = PoseidonExecutionState<Poseidon2Variant, F>;
