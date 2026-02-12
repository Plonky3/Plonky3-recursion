use alloc::vec::Vec;

use p3_circuit::op::NonPrimitiveOpType;
use p3_circuit::tables::Traces;
use p3_field::Field;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

/// Pad a trace matrix to at least `min_height` rows.
/// The height is always rounded up to a power of two.
pub(crate) fn pad_matrix_to_min_height<F: Field>(
    mut matrix: RowMajorMatrix<F>,
    min_height: usize,
) -> RowMajorMatrix<F> {
    let current_height = matrix.height();
    // Target height is max of current power-of-two and min_height
    let target_height = current_height
        .next_power_of_two()
        .max(min_height.next_power_of_two());

    if current_height < target_height {
        // Pad with zeros to reach target height
        let width = matrix.width();
        let padding_rows = target_height - current_height;
        matrix
            .values
            .extend(core::iter::repeat_n(F::ZERO, padding_rows * width));
    }
    matrix
}

/// Configuration for packing multiple primitive operations into a single AIR row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TablePacking {
    witness_lanes: usize,
    public_lanes: usize,
    alu_lanes: usize,
    /// Minimum trace height for all tables (must be power of two).
    /// This is required for FRI with higher `log_final_poly_len`.
    /// FRI requires: log_trace_height > log_final_poly_len + log_blowup
    /// So min_trace_height should be >= 2^(log_final_poly_len + log_blowup + 1)
    min_trace_height: usize,
}

impl TablePacking {
    pub fn new(witness_lanes: usize, public_lanes: usize, alu_lanes: usize) -> Self {
        Self {
            witness_lanes: witness_lanes.max(1),
            public_lanes: public_lanes.max(1),
            alu_lanes: alu_lanes.max(1),
            min_trace_height: 1,
        }
    }

    /// Create TablePacking with a minimum trace height requirement.
    ///
    /// Use this when FRI parameters have `log_final_poly_len > 0`.
    /// The minimum trace height must satisfy: `min_trace_height > 2^(log_final_poly_len + log_blowup)`
    ///
    /// For example, with `log_final_poly_len = 3` and `log_blowup = 1`:
    /// - Required: `min_trace_height > 2^(3+1) = 16`
    /// - So use `min_trace_height = 32` (next power of two)
    pub fn with_min_trace_height(mut self, min_trace_height: usize) -> Self {
        // Ensure min_trace_height is a power of two and at least 1
        self.min_trace_height = min_trace_height.next_power_of_two().max(1);
        self
    }

    /// Create TablePacking with minimum height derived from FRI parameters.
    ///
    /// This automatically calculates the minimum trace height from `log_final_poly_len` and `log_blowup`.
    pub const fn with_fri_params(mut self, log_final_poly_len: usize, log_blowup: usize) -> Self {
        // FRI requires: log_min_height > log_final_poly_len + log_blowup
        // So min_height must be >= 2^(log_final_poly_len + log_blowup + 1)
        let min_log_height = log_final_poly_len + log_blowup + 1;
        self.min_trace_height = 1usize << min_log_height;
        self
    }

    pub const fn witness_lanes(self) -> usize {
        self.witness_lanes
    }

    pub const fn public_lanes(self) -> usize {
        self.public_lanes
    }

    pub const fn alu_lanes(self) -> usize {
        self.alu_lanes
    }

    pub const fn min_trace_height(self) -> usize {
        self.min_trace_height
    }
}

impl Default for TablePacking {
    fn default() -> Self {
        Self::new(1, 1, 1)
    }
}

/// Summary of trace lengths for all circuit tables.
#[derive(Debug, Clone)]
pub struct TraceLengths {
    pub witness: usize,
    pub const_: usize,
    pub public: usize,
    pub alu: usize,
    pub non_primitive: Vec<(NonPrimitiveOpType, usize)>,
}

impl TraceLengths {
    /// Compute trace lengths from traces and packing configuration.
    pub fn from_traces<F>(traces: &Traces<F>, packing: TablePacking) -> Self {
        Self {
            witness: traces.witness_trace.num_rows() / packing.witness_lanes(),
            const_: traces.const_trace.values.len(),
            public: traces.public_trace.values.len() / packing.public_lanes(),
            alu: traces.alu_trace.op_kind.len() / packing.alu_lanes(),
            non_primitive: traces
                .non_primitive_traces
                .iter()
                .map(|(&op, t)| (op, t.rows()))
                .collect(),
        }
    }

    /// Log all trace lengths at info level.
    pub fn log(&self) {
        tracing::info!(
            witness = %self.witness,
            const_ = %self.const_,
            public = %self.public,
            alu = %self.alu,
            "Primitive trace lengths"
        );
        for (op, rows) in &self.non_primitive {
            tracing::info!(?op, rows, "Non-primitive trace length");
        }
    }
}
