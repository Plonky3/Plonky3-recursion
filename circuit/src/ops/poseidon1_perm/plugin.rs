//! Poseidon1 circuit plugin — [`NpoCircuitPlugin`] implementation.

use crate::ops::poseidon_perm::{Poseidon1Variant, PoseidonCircuitPlugin};

/// Circuit-layer plugin for Poseidon1 non-primitive operations.
pub(crate) type Poseidon1CircuitPlugin<F> = PoseidonCircuitPlugin<Poseidon1Variant, F>;
