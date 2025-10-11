//! Extended Poseidon2 AIR with circuit integration.
//!
//! This module extends Plonky3's base `Poseidon2Air` with input/output indices
//! for circuit wiring, enabling lookups from `SpongeAir` for sponge construction.

pub mod columns;
pub mod wrapper;

pub use columns::{ExtendedPoseidon2Cols, num_cols};
pub use wrapper::ExtendedPoseidon2Air;
