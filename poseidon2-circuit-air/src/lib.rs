//! An AIR for the Poseidon2 table for recursion. Handles sponge operations and compressions.

#![no_std]

extern crate alloc;

mod air;
mod columns;

pub use air::*;
pub use columns::*;
