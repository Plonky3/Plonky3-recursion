pub mod air;
pub mod config;
pub mod prover;

// Re-export main API
pub use prover::{MultiTableProof, MultiTableProver};
