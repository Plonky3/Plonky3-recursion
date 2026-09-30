//! Challenger implementations for recursive Fiat-Shamir transformations.

mod binary;
mod circuit;

pub use binary::BinaryTower128Challenger;
pub use circuit::CircuitChallenger;
