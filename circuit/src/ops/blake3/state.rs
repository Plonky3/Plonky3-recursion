//! Execution state and private data for Blake3 membership proof operations.

use alloc::vec::Vec;

use crate::ops::blake3::trace::Blake3CircuitRow;

/// Private data for a single Blake3 round Op.
///
/// Each of the 8 round Ops in a compression gets its own `Blake3PrivateData`
/// carrying the 8 bytes of `uint8_data` for that row, matching Poseidon2's
/// per-Op private data model.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Blake3PrivateData {
    pub uint8_data: [u8; 8],
}

/// Execution state for Blake3 operations, persisting across invocations.
///
/// Tracks the internal compression state across 8 rounds within a single
/// compression, plus the chaining value between compressions.
#[derive(Debug, Default)]
pub(crate) struct Blake3ExecutionState {
    /// Current round within a compression (1-8), 0 = idle/between compressions.
    pub round_idx: usize,
    /// The 16-word Blake3 state vector, updated each round by the G function.
    pub state: [u32; 16],
    /// Initial chaining value for this compression (first 8 words of state init).
    pub cv_in: [u32; 8],
    /// Current message schedule (16 u32 words), permuted between rounds.
    pub msg: [u32; 16],
    /// Rotating message buffer (16 u32 words), built up from uint8_data across rows.
    pub msg_buffer: [u32; 16],
    /// Last cv_out for chaining to the next compression (8 u32 words).
    pub last_cv_out: Option<[u32; 8]>,
    /// Circuit rows captured during execution for trace generation.
    pub rows: Vec<Blake3CircuitRow>,
}
