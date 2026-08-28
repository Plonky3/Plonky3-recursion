use alloc::string::ToString;
use alloc::vec::Vec;

use p3_circuit::ops::NpoTypeId;
use serde::{Deserialize, Serialize};

use crate::ProofMetadataError;

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
    /// Minimum trace height override for the ALU table (must be power of two).
    /// `None` falls back to [`Self::min_trace_height`].
    #[serde(default)]
    alu_min_height: Option<usize>,
    /// Minimum trace height override for the public-input table (must be power of two).
    /// `None` falls back to [`Self::min_trace_height`].
    #[serde(default)]
    public_min_height: Option<usize>,
    /// Minimum trace height override for the const table (must be power of two).
    /// `None` falls back to [`Self::min_trace_height`].
    #[serde(default)]
    const_min_height: Option<usize>,
    /// Per-NPO minimum trace height overrides: `(op_type, height)`. Any op not listed
    /// falls back to [`Self::min_trace_height`].
    #[serde(default)]
    npo_min_heights: Vec<(NpoTypeId, usize)>,
    /// Minimum trace height for all tables (must be power of two).
    /// This is required for FRI with higher `log_final_poly_len`.
    /// FRI requires: `log_trace_height > log_final_poly_len + log_blowup`
    /// So min_trace_height should be >= `2^(log_final_poly_len + log_blowup + 1)`
    min_trace_height: usize,
    /// Pack this many consecutive `HornerAcc` ops (same `b` witness) per ALU row on lane 0.
    /// Must be at least 2. Default 2 matches the previous double-step Horner layout.
    #[serde(default = "default_horner_pack_k")]
    horner_packed_steps: usize,
    /// When `true`, a table whose natural row count exceeds its configured height is
    /// rejected with `ProofMetadataError::ProfileOverflow` instead of being clamped
    /// (padded) up to fit. `false` preserves today's clamping behavior everywhere.
    #[serde(default)]
    strict: bool,
}

const fn default_horner_pack_k() -> usize {
    2
}

/// Sanity ceiling for lane counts and `horner_packed_steps` in [`TablePacking::validate`].
///
/// Far beyond any real packing (which uses single- to low-double-digit values), but small
/// enough that every width computation derived from these fields (`lanes * lane_width`, and
/// similar) stays comfortably within `usize` range instead of overflowing on proof-controlled
/// metadata.
pub(crate) const MAX_SANE_LANES: usize = 1 << 16;

impl TablePacking {
    /// Create a new [`TablePacking`] with the given primitive lane counts (clamped to at least 1).
    ///
    /// NPO lanes default to 1. Use [`with_npo_lanes`](Self::with_npo_lanes) to override per op type.
    pub fn new(public_lanes: usize, alu_lanes: usize) -> Self {
        Self {
            public_lanes: public_lanes.max(1),
            alu_lanes: alu_lanes.max(1),
            npo_lanes: Vec::new(),
            alu_min_height: None,
            public_min_height: None,
            const_min_height: None,
            npo_min_heights: Vec::new(),
            min_trace_height: 1,
            horner_packed_steps: 2,
            strict: false,
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

    /// Override the lane count for a specific non-primitive op type (builder-style).
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

    /// Override the minimum trace height for the ALU table (builder-style).
    ///
    /// `None` (the default) falls back to [`Self::min_trace_height`].
    #[must_use]
    pub const fn with_alu_min_height(mut self, height: usize) -> Self {
        self.alu_min_height = Some(height);
        self
    }

    /// Override the minimum trace height for the public-input table (builder-style).
    ///
    /// `None` (the default) falls back to [`Self::min_trace_height`].
    #[must_use]
    pub const fn with_public_min_height(mut self, height: usize) -> Self {
        self.public_min_height = Some(height);
        self
    }

    /// Override the minimum trace height for the const table (builder-style).
    ///
    /// `None` (the default) falls back to [`Self::min_trace_height`].
    #[must_use]
    pub const fn with_const_min_height(mut self, height: usize) -> Self {
        self.const_min_height = Some(height);
        self
    }

    /// Override the minimum trace height for a specific non-primitive op type (builder-style).
    ///
    /// Any NPO not listed falls back to [`Self::min_trace_height`].
    #[must_use]
    pub fn with_npo_min_height(mut self, op_type: impl Into<NpoTypeId>, height: usize) -> Self {
        let op_type = op_type.into();
        if let Some(entry) = self.npo_min_heights.iter_mut().find(|(k, _)| *k == op_type) {
            entry.1 = height;
        } else {
            self.npo_min_heights.push((op_type, height));
        }
        self
    }

    /// Update the current [`TablePacking`] with a minimum trace height requirement.
    ///
    /// FRI requires: `log_trace_height > log_final_poly_len + log_blowup`
    /// So `min_trace_height` should be >= `2^(log_final_poly_len + log_blowup + 1)`
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

    /// Enable strict (non-clamping) height enforcement (builder-style).
    ///
    /// Once set, a table whose natural row count exceeds its configured height is
    /// rejected with `ProofMetadataError::ProfileOverflow` instead of being padded
    /// up to fit.
    #[must_use]
    pub const fn with_strict_heights(mut self) -> Self {
        self.strict = true;
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

    /// Return whether strict (non-clamping) height enforcement is enabled.
    ///
    /// See [`with_strict_heights`](Self::with_strict_heights).
    pub const fn is_strict(&self) -> bool {
        self.strict
    }

    /// Return the ALU table's minimum height override, if set via
    /// [`with_alu_min_height`](Self::with_alu_min_height).
    ///
    /// `None` means the caller should fall back to [`Self::min_trace_height`].
    pub const fn alu_min_height(&self) -> Option<usize> {
        self.alu_min_height
    }

    /// Return the public-input table's minimum height override, if set via
    /// [`with_public_min_height`](Self::with_public_min_height).
    ///
    /// `None` means the caller should fall back to [`Self::min_trace_height`].
    pub const fn public_min_height(&self) -> Option<usize> {
        self.public_min_height
    }

    /// Return the const table's minimum height override, if set via
    /// [`with_const_min_height`](Self::with_const_min_height).
    ///
    /// `None` means the caller should fall back to [`Self::min_trace_height`].
    pub const fn const_min_height(&self) -> Option<usize> {
        self.const_min_height
    }

    /// Return the minimum height override for a specific NPO type.
    ///
    /// Returns the overridden value if one was set via
    /// [`with_npo_min_height`](Self::with_npo_min_height), otherwise `None`
    /// (the caller should fall back to [`Self::min_trace_height`]).
    pub fn npo_min_height(&self, op_type: &NpoTypeId) -> Option<usize> {
        self.npo_min_heights
            .iter()
            .find(|(k, _)| k == op_type)
            .map(|(_, v)| *v)
    }

    /// Number of consecutive HornerAcc steps packed into one scheduled ALU row (lane 0).
    pub const fn horner_packed_steps(&self) -> usize {
        self.horner_packed_steps
    }

    /// Re-check the invariants the builder methods enforce, after deserialization.
    pub fn validate(&self) -> Result<(), ProofMetadataError> {
        if self.public_lanes == 0 {
            return Err(ProofMetadataError::ZeroLanes("public_lanes"));
        }
        if self.public_lanes > MAX_SANE_LANES {
            return Err(ProofMetadataError::LanesTooLarge {
                field: "public_lanes",
                got: self.public_lanes,
                max: MAX_SANE_LANES,
            });
        }
        if self.alu_lanes == 0 {
            return Err(ProofMetadataError::ZeroLanes("alu_lanes"));
        }
        if self.alu_lanes > MAX_SANE_LANES {
            return Err(ProofMetadataError::LanesTooLarge {
                field: "alu_lanes",
                got: self.alu_lanes,
                max: MAX_SANE_LANES,
            });
        }
        for (op_type, lanes) in &self.npo_lanes {
            if *lanes == 0 {
                return Err(ProofMetadataError::ZeroNpoLanes(op_type.clone()));
            }
            if *lanes > MAX_SANE_LANES {
                return Err(ProofMetadataError::NpoLanesTooLarge {
                    op_type: op_type.clone(),
                    got: *lanes,
                    max: MAX_SANE_LANES,
                });
            }
        }
        if self.min_trace_height == 0 || !self.min_trace_height.is_power_of_two() {
            return Err(ProofMetadataError::BadMinTraceHeight(self.min_trace_height));
        }
        for h in [
            self.alu_min_height,
            self.public_min_height,
            self.const_min_height,
        ]
        .into_iter()
        .flatten()
        {
            if h == 0 || !h.is_power_of_two() {
                return Err(ProofMetadataError::BadMinTraceHeight(h));
            }
        }
        for (_, h) in &self.npo_min_heights {
            if *h == 0 || !h.is_power_of_two() {
                return Err(ProofMetadataError::BadMinTraceHeight(*h));
            }
        }
        for (label, h) in [
            ("alu_min_height", self.alu_min_height),
            ("public_min_height", self.public_min_height),
            ("const_min_height", self.const_min_height),
        ] {
            if let Some(h) = h
                && h < self.min_trace_height
            {
                return Err(ProofMetadataError::PerTableHeightBelowFloor {
                    table: label.to_string(),
                    override_height: h,
                    floor: self.min_trace_height,
                });
            }
        }
        for (op_type, h) in &self.npo_min_heights {
            if *h < self.min_trace_height {
                return Err(ProofMetadataError::PerTableHeightBelowFloor {
                    table: op_type.to_string(),
                    override_height: *h,
                    floor: self.min_trace_height,
                });
            }
        }
        if self.horner_packed_steps < 2 {
            return Err(ProofMetadataError::BadHornerPackedSteps(
                self.horner_packed_steps,
            ));
        }
        if self.horner_packed_steps > MAX_SANE_LANES {
            return Err(ProofMetadataError::HornerPackedStepsTooLarge(
                self.horner_packed_steps,
                MAX_SANE_LANES,
            ));
        }
        Ok(())
    }
}

impl Default for TablePacking {
    fn default() -> Self {
        Self::new(1, 1)
    }
}

/// Main trace width, preprocessed row width, logical AIR row count, and lane packing for one table.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AirTableShape {
    pub main_cols: usize,
    pub prep_cols: usize,
    pub rows: usize,
    pub lanes: usize,
}

/// Layout of every table in a batch (for prover logging).
#[derive(Debug)]
pub(crate) struct TraceTablesLayout {
    pub const_: AirTableShape,
    pub public: AirTableShape,
    pub alu: AirTableShape,
    pub non_primitives: Vec<(NpoTypeId, AirTableShape)>,
}

impl TraceTablesLayout {
    /// Log each AIR’s main width, preprocessed width, row count, and lanes at info level.
    pub fn log(&self) {
        tracing::info!(
            table = "CONST",
            main_cols = self.const_.main_cols,
            prep_cols = self.const_.prep_cols,
            rows = self.const_.rows,
            "AIR shape"
        );
        tracing::info!(
            table = "PUBLIC",
            main_cols = self.public.main_cols,
            prep_cols = self.public.prep_cols,
            rows = self.public.rows,
            "AIR shape"
        );
        tracing::info!(
            table = "ALU",
            main_cols = self.alu.main_cols,
            prep_cols = self.alu.prep_cols,
            rows = self.alu.rows,
            lanes = self.alu.lanes,
            "AIR shape"
        );
        for (op, shape) in &self.non_primitives {
            tracing::info!(
                table = ?op,
                main_cols = shape.main_cols,
                prep_cols = shape.prep_cols,
                rows = shape.rows,
                lanes = shape.lanes,
                "AIR shape"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_table_min_height_defaults_to_none() {
        let packing = TablePacking::new(1, 3);
        assert_eq!(packing.alu_min_height(), None);
        assert_eq!(packing.public_min_height(), None);
        assert_eq!(packing.const_min_height(), None);
    }

    #[test]
    fn with_alu_min_height_overrides_only_alu() {
        let packing = TablePacking::new(1, 3).with_alu_min_height(65536);
        assert_eq!(packing.alu_min_height(), Some(65536));
        assert_eq!(packing.public_min_height(), None);
    }

    #[test]
    fn with_npo_min_height_is_per_op_type() {
        use p3_circuit::ops::NpoTypeId;
        let recompose: NpoTypeId = NpoTypeId::new("recompose");
        let poseidon2: NpoTypeId = NpoTypeId::new("poseidon2_perm/koala_bear_d4_w16");
        let packing = TablePacking::new(1, 3)
            .with_npo_min_height(recompose.clone(), 32768)
            .with_npo_min_height(poseidon2.clone(), 32768);
        assert_eq!(packing.npo_min_height(&recompose), Some(32768));
        assert_eq!(packing.npo_min_height(&poseidon2), Some(32768));
        let other: NpoTypeId = NpoTypeId::new("unconstrained");
        assert_eq!(packing.npo_min_height(&other), None);
    }

    #[test]
    fn validate_rejects_non_power_of_two_alu_min_height() {
        let bad = TablePacking::new(1, 3).with_alu_min_height(3);
        assert_eq!(
            bad.validate(),
            Err(ProofMetadataError::BadMinTraceHeight(3))
        );
        let good = TablePacking::new(1, 3).with_alu_min_height(4);
        assert_eq!(good.validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_zero_alu_min_height() {
        let bad = TablePacking::new(1, 3).with_alu_min_height(0);
        assert_eq!(
            bad.validate(),
            Err(ProofMetadataError::BadMinTraceHeight(0))
        );
    }

    #[test]
    fn validate_rejects_zero_public_min_height() {
        let bad = TablePacking::new(1, 3).with_public_min_height(0);
        assert_eq!(
            bad.validate(),
            Err(ProofMetadataError::BadMinTraceHeight(0))
        );
    }

    #[test]
    fn validate_rejects_zero_const_min_height() {
        let bad = TablePacking::new(1, 3).with_const_min_height(0);
        assert_eq!(
            bad.validate(),
            Err(ProofMetadataError::BadMinTraceHeight(0))
        );
    }

    #[test]
    fn validate_rejects_zero_npo_min_height() {
        use p3_circuit::ops::NpoTypeId;
        let op = NpoTypeId::new("test_op");
        let bad = TablePacking::new(1, 3).with_npo_min_height(op, 0);
        assert_eq!(
            bad.validate(),
            Err(ProofMetadataError::BadMinTraceHeight(0))
        );
    }

    #[test]
    fn validate_rejects_alu_min_height_below_global_floor() {
        // A valid power of two, but below the 32 global floor -- must be rejected even
        // though it would pass the standalone power-of-two check above.
        let bad = TablePacking::new(1, 1)
            .with_min_trace_height(32)
            .with_alu_min_height(4);
        assert_eq!(
            bad.validate(),
            Err(ProofMetadataError::PerTableHeightBelowFloor {
                table: "alu_min_height".to_string(),
                override_height: 4,
                floor: 32,
            })
        );
    }

    #[test]
    fn validate_accepts_per_table_height_at_or_above_global_floor() {
        let ok = TablePacking::new(1, 1)
            .with_min_trace_height(32)
            .with_alu_min_height(32);
        assert_eq!(ok.validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_npo_min_height_below_global_floor() {
        use p3_circuit::ops::NpoTypeId;
        let op = NpoTypeId::new("test_op");
        let bad = TablePacking::new(1, 1)
            .with_min_trace_height(32)
            .with_npo_min_height(op.clone(), 4);
        assert_eq!(
            bad.validate(),
            Err(ProofMetadataError::PerTableHeightBelowFloor {
                table: op.to_string(),
                override_height: 4,
                floor: 32,
            })
        );
    }
}
