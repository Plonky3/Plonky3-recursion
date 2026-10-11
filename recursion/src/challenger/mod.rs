//! Challenger implementations for recursive Fiat-Shamir transformations.

mod binary;
mod circuit;
#[cfg(test)]
pub(crate) mod transcript_tests;

pub(crate) use binary::RetainedDigest;
pub use binary::{BinaryQueryContinuation, BinaryTower128Challenger};
pub use circuit::CircuitChallenger;
