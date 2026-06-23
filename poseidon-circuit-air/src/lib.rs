//! Shared column and preprocessed-row layout for the Poseidon circuit AIRs.
//!
//! The outer circuit-column wrapper and the preprocessed-row encoding are
//! identical for every Poseidon backend, so they live here and are wrapped by
//! backend-specific aliases in each circuit-AIR crate. The inner permutation
//! columns, round constants, and constraint evaluation stay per-backend.

#![no_std]

extern crate alloc;

mod cols;
mod preprocessed;

pub use cols::*;
pub use preprocessed::*;
