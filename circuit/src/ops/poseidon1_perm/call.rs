//! User-facing call structs for adding Poseidon1 permutation rows.
//!
//! These are variant-named aliases of the shared [`crate::ops::poseidon_perm`]
//! call structs.

use crate::ops::poseidon_perm::{Poseidon1Variant, PoseidonPermCall, PoseidonPermCallBase};

/// User-facing arguments for adding a Poseidon1 perm row.
pub type Poseidon1PermCall = PoseidonPermCall<Poseidon1Variant>;

/// User-facing arguments for adding a Poseidon1 perm row with D=1 (base field).
pub type Poseidon1PermCallBase = PoseidonPermCallBase<Poseidon1Variant>;
