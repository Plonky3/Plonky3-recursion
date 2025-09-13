#![no_std]

extern crate alloc;

pub mod air;
pub mod config;
pub mod field_params;
pub mod prover;

// Re-export main API
pub use prover::{MultiTableProof, MultiTableProver};
