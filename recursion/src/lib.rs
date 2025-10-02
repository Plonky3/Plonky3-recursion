#![no_std]

extern crate alloc;

// Canonical circuit target type used across recursive components.
pub type Target = p3_circuit::ExprId;

pub mod circuit_fri_verifier;
pub mod circuit_mmcs_verifier;
pub mod circuit_verifier;
pub mod recursive_generation;
pub mod recursive_pcs;
pub mod recursive_traits;
