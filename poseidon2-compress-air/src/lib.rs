//! An AIR for the Poseidon2 N-to-1 compression.

#![no_std]

extern crate alloc;

mod air;
mod columns;

pub use air::*;
pub use columns::*;
