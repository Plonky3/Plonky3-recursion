//! User-facing call structs for adding Poseidon2 permutation rows.
//!
//! These are variant-named aliases of the shared [`crate::ops::poseidon_perm`]
//! call structs.

use crate::ops::poseidon_perm::{Poseidon2Variant, PoseidonPermCall, PoseidonPermCallBase};

/// User-facing arguments for adding a Poseidon2 perm row.
pub type Poseidon2PermCall = PoseidonPermCall<Poseidon2Variant>;

/// User-facing arguments for adding a Poseidon2 perm row with D=1 (base field).
pub type Poseidon2PermCallBase = PoseidonPermCallBase<Poseidon2Variant>;
