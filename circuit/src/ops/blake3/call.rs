//! Blake3 builder call type.

use alloc::vec::Vec;

use crate::types::ExprId;

/// High-level description of a Blake3 round call for the circuit builder.
///
/// Each call represents one round of a Blake3 compression. A full compression
/// requires 8 calls (7 mixing rounds + 1 finalization).
#[derive(Debug, Clone, Default)]
pub struct Blake3Call {
    /// True if this compression starts a fresh chain (cv_in = IV).
    pub new_start: bool,
    /// True if this is round 1 of a compression (initialize state).
    pub is_new_blake: bool,
    /// When true, the cv_out of this step is exposed on the WitnessChecks bus.
    /// Only valid on the last round (round 8) of a compression.
    pub is_hash_output: bool,
    /// Input expressions: 16 cv_in limbs (used on round 1 only, may be None).
    pub inputs: Vec<Option<ExprId>>,
}
