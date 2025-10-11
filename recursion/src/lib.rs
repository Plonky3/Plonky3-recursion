#![no_std]

extern crate alloc;

// Canonical circuit target type used across recursive components.
pub type Target = p3_circuit::ExprId;

pub mod challenges;
pub mod circuit_challenger;
pub mod circuit_fri_verifier;
pub mod circuit_verifier;
pub mod public_inputs;
pub mod recursive_challenger;
pub mod recursive_generation;
pub mod recursive_pcs;
pub mod recursive_traits;
