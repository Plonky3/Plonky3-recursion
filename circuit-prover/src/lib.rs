#![no_std]

extern crate alloc;

pub mod air;
pub mod config;
pub mod prover;
pub mod transparent;

// Re-export main API
pub use prover::{MultiTableProof, MultiTableProver};
