//! Poseidon2 circuit plugin — [`NpoCircuitPlugin`] implementation.

use crate::ops::poseidon_perm::{Poseidon2Variant, PoseidonCircuitPlugin};

/// Circuit-layer plugin for Poseidon2 non-primitive operations.
pub(crate) type Poseidon2CircuitPlugin<F> = PoseidonCircuitPlugin<Poseidon2Variant, F>;
