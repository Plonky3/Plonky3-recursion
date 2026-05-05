//! Blake3 trace types and trace generation.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::any::Any;

use p3_field::Field;

use crate::CircuitError;
use crate::ops::NpoTypeId;
use crate::ops::blake3::state::Blake3ExecutionState;
use crate::tables::NonPrimitiveTrace;

/// Per-row trace data captured during execution of a single Blake3 round.
///
/// Each compression produces 8 rows (rounds 1-7 = mixing, round 8 = finalization).
/// Stored by [`Blake3ExecutionState`] and later collected into a [`Blake3Trace`]
/// for the batch STARK prover.
///
/// All computation data is stored in `u32` form; the prover-side trace generator
/// decomposes values into 16-bit limbs and bit representations for the AIR columns.
#[derive(Debug, Clone)]
pub struct Blake3CircuitRow {
    /// Round index within the compression (1-8).
    pub round_idx: usize,
    /// True when this is the first round of a compression.
    pub is_new_blake: bool,
    /// True when this is the last round of a compression (round 8).
    pub is_last_round: bool,
    /// True if cv_out is exposed on the WitnessChecks bus.
    pub is_hash_output: bool,
    /// True if this compression starts a fresh chain (no previous cv_out).
    pub new_start: bool,

    // --- AIR selector metadata (set by executor, consumed by trace generator) ---
    /// Message source: general matrix data.
    pub is_msg_mat: bool,
    /// Message source: auxiliary data.
    pub is_msg_aux_data: bool,
    /// Message source: chaining value injected into buffer.
    pub is_msg_cv: bool,
    /// Message source: jackpot data.
    pub is_msg_jackpot: bool,
    /// CV source: use job_key public value as cv_in.
    pub is_use_job_key: bool,
    /// CV source: use commitment_hash public value as cv_in.
    pub is_use_commitment_hash: bool,

    /// The 8 bytes of private data loaded this round.
    pub uint8_data: [u8; 8],
    /// Rotating message buffer state (16 u32 words) after this row's load.
    pub msg_buffer: [u32; 16],
    /// Initial CV for this compression (8 u32 words, same across all 8 rounds).
    pub cv_in: [u32; 8],
    /// Message schedule for this round (16 u32 words, permuted between rounds).
    pub blake3_msg: [u32; 16],
    /// Blake3 state at the start of this round (16 u32 words).
    pub state_before: [u32; 16],
    /// Blake3 state after this round's G operations (16 u32 words).
    pub state_after: [u32; 16],
    /// Output chaining value, only populated on round 8.
    pub cv_out: Option<[u32; 8]>,
    /// Witness indices for exposed cv_out limbs (0 when not exposed).
    pub output_indices: Vec<u32>,
    /// Per-limb CTL exposure flags for cv_out.
    pub out_ctl: Vec<bool>,
}

/// Blake3 trace collecting all round rows in the circuit.
#[derive(Debug, Clone)]
pub struct Blake3Trace {
    pub op_type: NpoTypeId,
    pub operations: Vec<Blake3CircuitRow>,
}

impl Blake3Trace {
    pub const fn total_rows(&self) -> usize {
        self.operations.len()
    }
}

impl<CF> NonPrimitiveTrace<CF> for Blake3Trace {
    fn op_type(&self) -> NpoTypeId {
        self.op_type.clone()
    }

    fn rows(&self) -> usize {
        self.total_rows()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn boxed_clone(&self) -> Box<dyn NonPrimitiveTrace<CF>> {
        Box::new(self.clone())
    }
}

/// Generate the Blake3 trace from execution state.
///
/// Collects all circuit rows recorded during execution into a single
/// [`Blake3Trace`]. Returns `None` if no Blake3 operations were executed.
pub fn generate_blake3_trace<F: Field>(
    op_states: &crate::ops::OpStateMap,
) -> Result<Option<Box<dyn NonPrimitiveTrace<F>>>, CircuitError> {
    let op_type = NpoTypeId::blake3();
    let Some(state) = op_states
        .get(&op_type)
        .and_then(|s| s.downcast_ref::<Blake3ExecutionState>())
    else {
        return Ok(None);
    };

    if state.rows.is_empty() {
        return Ok(None);
    }

    Ok(Some(Box::new(Blake3Trace {
        op_type,
        operations: state.rows.clone(),
    })))
}
