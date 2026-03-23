use alloc::vec::Vec;

use p3_circuit::ops::NpoTypeId;
use p3_circuit::tables::Traces;
use serde::{Deserialize, Serialize};

/// Configuration for packing multiple primitive operations into a single AIR row.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TablePacking {
    /// Number of public-input operations packed per AIR row.
    public_lanes: usize,
    /// Number of ALU operations packed per AIR row.
    alu_lanes: usize,
    /// Per-NPO lane counts: `(op_type, lanes)`. Defaults to 1 for any op not listed.
    #[serde(default)]
    npo_lanes: Vec<(NpoTypeId, usize)>,
    /// Minimum trace height for all tables (must be power of two).
    /// This is required for FRI with higher `log_final_poly_len`.
    /// FRI requires: log_trace_height > log_final_poly_len + log_blowup
    /// So min_trace_height should be >= 2^(log_final_poly_len + log_blowup + 1)
    min_trace_height: usize,
    /// Pack this many consecutive `HornerAcc` ops (same `b` witness) per ALU row on lane 0.
    /// Must be at least 2. Default 2 matches the previous double-step Horner layout.
    #[serde(default = "default_horner_pack_k")]
    horner_packed_steps: usize,
}

const fn default_horner_pack_k() -> usize {
    2
}

impl TablePacking {
    /// Create a new [`TablePacking`] with the given primitive lane counts (clamped to at least 1).
    ///
    /// NPO lanes default to 1. Use [`with_npo_lanes`](Self::with_npo_lanes) to override per op type.
    pub fn new(public_lanes: usize, alu_lanes: usize) -> Self {
        Self {
            public_lanes: public_lanes.max(1),
            alu_lanes: alu_lanes.max(1),
            npo_lanes: Vec::new(),
            min_trace_height: 1,
            horner_packed_steps: 2,
        }
    }

    /// Override packed Horner chain length (must be >= 2).
    #[must_use]
    pub fn with_horner_pack_k(mut self, k: usize) -> Self {
        assert!(k >= 2, "horner_packed_steps must be at least 2");
        self.horner_packed_steps = k;
        self
    }

    /// Override public and ALU lane counts after trace-driven clamping (e.g. dummy-only traces).
    ///
    /// Used when embedding the effective packing in [`super::BatchStarkProof`] so metadata matches
    /// proving while preserving [`Self::horner_packed_steps`] and NPO lane overrides.
    #[must_use]
    pub fn with_public_alu_lanes(mut self, public_lanes: usize, alu_lanes: usize) -> Self {
        self.public_lanes = public_lanes.max(1);
        self.alu_lanes = alu_lanes.max(1);
        self
    }

    /// Override the lane count for a specific NPO type (builder-style).
    ///
    /// Any NPO not listed falls back to the lane count returned by its [`TableProver`].
    #[must_use]
    pub fn with_npo_lanes(mut self, op_type: impl Into<NpoTypeId>, lanes: usize) -> Self {
        let op_type = op_type.into();
        let lanes = lanes.max(1);
        if let Some(entry) = self.npo_lanes.iter_mut().find(|(k, _)| *k == op_type) {
            entry.1 = lanes;
        } else {
            self.npo_lanes.push((op_type, lanes));
        }
        self
    }

    /// Update the current [`TablePacking`] with a minimum trace height requirement.
    ///
    /// Use this when FRI parameters have `log_final_poly_len > 0`.
    /// The minimum trace height must satisfy: `min_trace_height > 2^(log_final_poly_len + log_blowup)`
    ///
    /// For example, with `log_final_poly_len = 3` and `log_blowup = 1`:
    /// - Required: `min_trace_height > 2^(3+1) = 16`
    /// - So use `min_trace_height = 32` (next power of two)
    #[must_use]
    pub fn with_min_trace_height(mut self, min_trace_height: usize) -> Self {
        // Ensure min_trace_height is a power of two and at least 1
        self.min_trace_height = min_trace_height.next_power_of_two().max(1);
        self
    }

    /// Update the current [`TablePacking`] with minimum height derived from FRI parameters.
    ///
    /// This automatically calculates the minimum trace height from `log_final_poly_len` and `log_blowup`.
    #[must_use]
    pub const fn with_fri_params(mut self, log_final_poly_len: usize, log_blowup: usize) -> Self {
        // FRI requires: log_min_height > log_final_poly_len + log_blowup
        // So min_height must be >= 2^(log_final_poly_len + log_blowup + 1)
        let min_log_height = log_final_poly_len + log_blowup + 1;
        self.min_trace_height = 1usize << min_log_height;
        self
    }

    /// Return the number of public-input operations packed per AIR row.
    pub const fn public_lanes(&self) -> usize {
        self.public_lanes
    }

    /// Return the number of ALU operations packed per AIR row.
    pub const fn alu_lanes(&self) -> usize {
        self.alu_lanes
    }

    /// Return the lane count for a specific NPO type.
    ///
    /// Returns the overridden value if one was set via [`with_npo_lanes`](Self::with_npo_lanes),
    /// otherwise returns `None` (the caller should fall back to the prover's own default).
    pub fn npo_lanes(&self, op_type: &NpoTypeId) -> Option<usize> {
        self.npo_lanes
            .iter()
            .find(|(k, _)| k == op_type)
            .map(|(_, v)| *v)
    }

    /// Return the minimum trace height (always a power of two, at least 1).
    pub const fn min_trace_height(&self) -> usize {
        self.min_trace_height
    }

    /// Number of consecutive HornerAcc steps packed into one scheduled ALU row (lane 0).
    pub const fn horner_packed_steps(&self) -> usize {
        self.horner_packed_steps
    }
}

impl Default for TablePacking {
    fn default() -> Self {
        Self::new(1, 1)
    }
}

/// Summary of trace lengths for all circuit tables.
#[derive(Debug, Clone)]
pub(crate) struct TraceLengths {
    /// Number of entries in the constant table.
    pub const_: usize,
    /// Number of logical public-input rows.
    pub public: usize,
    /// Total ALU operations.
    pub alu_ops: usize,
    /// Number of public-input operations packed per AIR row.
    pub public_lanes: usize,
    /// Number of ALU operations packed per AIR row.
    pub alu_lanes: usize,
    /// Per-plugin counts: `(op_type, num_ops, lanes)` for each non-primitive table.
    pub non_primitive: Vec<(NpoTypeId, usize, usize)>,
}

impl TraceLengths {
    /// Compute trace lengths from traces, packing configuration, and a lane-lookup function.
    ///
    /// `lane_for` is called once per registered NPO type to obtain its lane count.
    pub fn from_traces<F>(
        traces: &Traces<F>,
        packing: &TablePacking,
        lane_for: impl Fn(&NpoTypeId) -> usize,
    ) -> Self {
        Self {
            const_: traces.const_trace.values.len(),
            public: traces.public_trace.values.len(),
            alu_ops: traces.alu_trace.op_kind.len(),
            public_lanes: packing.public_lanes(),
            alu_lanes: packing.alu_lanes(),
            non_primitive: traces
                .non_primitive_traces
                .iter()
                .map(|(op, t)| {
                    let lanes = lane_for(op);
                    (op.clone(), t.rows(), lanes)
                })
                .collect(),
        }
    }

    /// Log all trace lengths at info level.
    pub fn log(&self, scheduled_alu_rows: Option<usize>) {
        let alu_rows = scheduled_alu_rows.unwrap_or(self.alu_ops) / self.alu_lanes;
        let public_rows = self.public / self.public_lanes;
        tracing::info!(
            const_ = %self.const_,
            const_lanes = 1usize,
            public = %public_rows,
            public_lanes = %self.public_lanes,
            alu_rows = %alu_rows,
            alu_lanes = %self.alu_lanes,
            "Primitive trace lengths"
        );
        for (op, num_ops, lanes) in &self.non_primitive {
            let air_rows = num_ops.div_ceil(*lanes);
            tracing::info!(?op, air_rows, lanes, "Non-primitive trace length");
        }
    }
}
