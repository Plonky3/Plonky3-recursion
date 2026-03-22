//! # ALU AIR
//!
//! [`AluAir`] defines the unified AIR for proving arithmetic operations over both
//! base and extension fields.
//!
//! ## Operations
//!
//! Each row encodes one or more arithmetic constraints selected by preprocessed
//! selectors:
//!
//! | Operation      | Constraint                                 | Degree |
//! |----------------|--------------------------------------------|--------|
//! | **ADD**        | `a + b - out = 0`                          | 1      |
//! | **MUL**        | `a * b - out = 0`                          | 2      |
//! | **BOOL_CHECK** | `a * (a - 1) = 0`                          | 2      |
//! | **MUL_ADD**    | `a * b + c - out = 0`                      | 2      |
//! | **HORNER_ACC** | `prev_row_out * b + c - a - out = 0`       | 2      |
//!
//! All constraint degrees are ≤ 3 (after multiplying by a selector), compatible
//! with `log_blowup = 1`.
//!
//! ## Main trace layout
//!
//! Each lane occupies `4 * D` columns: `[a[D], b[D], c[D], out[D]]`.
//! After all lanes, there are `3 * (K - 1) * D` **global** extra columns on lane 0
//! for **K-step** packed HornerAcc (`K >= 2`, fixed per AIR): `(K-1)` intermediate
//! accumulators `int_*[D]`, then `(a_t,c_t)` for steps `t = 1..K-1`. For `K = 2` this
//! matches the previous `[int, a1, c1]` layout (`3D` extra).
//!
//! Total main width = `lanes * 4D + 3 * (K - 1) * D`.
//!
//! ## Preprocessed trace layout
//!
//! Each lane occupies 13 columns (see [`PREP_*`][PREP_MULT_A] constants):
//!
//! | Offset | Name              | Purpose                                        |
//! |--------|-------------------|------------------------------------------------|
//! | 0      | `mult_a`          | Multiplicity for `a` (`-1` = reader, `0` = pad)|
//! | 1      | `sel_add_vs_mul`  | ADD selector                                   |
//! | 2      | `sel_bool`        | BOOL_CHECK selector                            |
//! | 3      | `sel_muladd`      | MUL_ADD selector                               |
//! | 4      | `sel_horner`      | HORNER_ACC selector                            |
//! | 5      | `a_idx`           | Witness index for `a` (D-scaled)               |
//! | 6      | `b_idx`           | Witness index for `b` (D-scaled)               |
//! | 7      | `c_idx`           | Witness index for `c` (D-scaled)               |
//! | 8      | `out_idx`         | Witness index for `out` (D-scaled)             |
//! | 9      | `mult_b`          | Multiplicity for `b`                           |
//! | 10     | `mult_out`        | Multiplicity for `out`                         |
//! | 11     | `a_is_reader`     | 1 if `a` reads from the WitnessChecks bus      |
//! | 12     | `c_is_reader`     | 1 if `c` reads from the WitnessChecks bus      |
//!
//! After all lanes, there are `1 + 4 * (K - 1)` **global** extra preprocessed
//! columns for packed HornerAcc: column 0 is `sel_horner_packed`; for each step
//! `t = 1..K-1`, four columns `a_t_idx`, `c_t_idx`, `a_t_reader`, `c_t_reader`.
//!
//! Total preprocessed width = `lanes * 13 + 1 + 4 * (K - 1)`.
//!
//! ## K-step packed HornerAcc
//!
//! When HornerAcc operations are present, [`compute_schedule`] places Horner chains
//! on lane 0 and packs each contiguous run of **K** ops (same `b` witness index)
//! into [`ScheduleEntry::PackedHorner`]. Remainder ops use single-step rows.
//!
//! 1. **Inter-row** (prev row `out` → next row first intermediate):
//!    `int_0 = prev_out * b + c - a`
//! 2. **Intra-row**: `int_{s+1} = int_s * b + c_{s+1} - a_{s+1}` for `s < K-2`, and
//!    `out = int_{K-2} * b + c_{K-1} - a_{K-1}`.
//!
//! A leading [`ScheduleEntry::Separator`] prevents bogus inter-row Horner on row 0.
//!
//! ## WitnessChecks bus
//!
//! Each lane contributes 4 lookups. Packed Horner adds `2 * (K - 1)` extra lookups
//! for `(a_t, c_t)`, `t = 1..K-1`. Total = `lanes * 4 + 2 * (K - 1)`.

#![allow(clippy::needless_range_loop)]

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_circuit::tables::AluTrace;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_lookup::LookupAir;
use p3_lookup::lookup_traits::{Direction, Kind, Lookup};
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::SymbolicExpression;

use crate::air::utils::{create_symbolic_variables, get_alu_index_lookups};

// ── Preprocessed column offsets within each lane (13 columns) ────────────────
pub(crate) const PREP_MULT_A: usize = 0;
pub(crate) const PREP_SEL_ADD: usize = 1;
pub(crate) const PREP_SEL_BOOL: usize = 2;
pub(crate) const PREP_SEL_MULADD: usize = 3;
pub(crate) const PREP_SEL_HORNER: usize = 4;
pub(crate) const PREP_A_IDX: usize = 5;
pub(crate) const PREP_B_IDX: usize = 6;
pub(crate) const PREP_C_IDX: usize = 7;
pub(crate) const PREP_OUT_IDX: usize = 8;
pub(crate) const PREP_MULT_B: usize = 9;
pub(crate) const PREP_MULT_OUT: usize = 10;
pub(crate) const PREP_A_IS_READER: usize = 11;
pub(crate) const PREP_C_IS_READER: usize = 12;

/// Number of preprocessed columns per lane.
pub(crate) const PREP_LANE_WIDTH: usize = 13;

// ── Global extra preprocessed: column 0 = packed Horner selector ──────────────
pub(crate) const EXTRA_PREP_SEL_PACKED: usize = 0;

/// Preprocessed offset for step `t`'s `a_idx` (`t` in `1..K-1`).
#[inline]
pub(crate) const fn extra_prep_a_idx_for_step(t: usize) -> usize {
    1 + 4 * (t - 1)
}

/// Number of global extra preprocessed columns for K-step packed Horner (`K >= 2`).
#[inline]
pub(crate) const fn horner_extra_prep_width(k: usize) -> usize {
    1 + 4 * (k - 1)
}

/// Entry in the HornerAcc lane schedule.
#[derive(Debug, Clone, Copy)]
enum ScheduleEntry {
    /// A real ALU op at the given original index.
    Op(usize),
    /// K consecutive HornerAcc ops with indices `first..first+K` in the original trace.
    PackedHorner(usize),
    /// A virtual zero-separator (multiplicity 0, all values 0).
    Separator,
}

/// AIR for proving unified arithmetic operations.
///
/// Supports ADD, MUL, BOOL_CHECK, and MUL_ADD operations with preprocessed selectors.
#[derive(Debug, Clone)]
pub struct AluAir<F, const D: usize = 1> {
    /// Total number of logical ALU operations in the trace.
    pub(crate) num_ops: usize,
    /// Number of independent operations packed per trace row.
    pub(crate) lanes: usize,
    /// For binomial extensions x^D = W (D > 1).
    pub(crate) w_binomial: Option<F>,
    /// Flattened preprocessed values (selectors + indices), in original op order.
    pub(crate) preprocessed: Vec<F>,
    /// Number of lookup columns registered so far.
    pub(crate) num_lookup_columns: usize,
    /// Minimum trace height (for FRI compatibility with higher log_final_poly_len).
    pub(crate) min_height: usize,
    /// HornerAcc lane schedule. When present, ops are reordered so that HornerAcc
    /// chains occupy lane 0 in consecutive rows, with zero-separators between chains.
    schedule: Option<Vec<ScheduleEntry>>,
    /// Pack size K for [`ScheduleEntry::PackedHorner`] (>= 2).
    pub(crate) horner_packed_steps: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field + PrimeCharacteristicRing, const D: usize> AluAir<F, D> {
    /// Construct a new `AluAir` for base-field operations (D=1).
    pub const fn new(num_ops: usize, lanes: usize) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");
        assert!(D == 1, "Use new_binomial for D > 1");
        Self {
            num_ops,
            lanes,
            w_binomial: None,
            preprocessed: Vec::new(),
            num_lookup_columns: 0,
            min_height: 1,
            schedule: None,
            horner_packed_steps: 2,
            _phantom: PhantomData,
        }
    }

    /// Construct a new `AluAir` for base-field operations with preprocessed data.
    pub fn new_with_preprocessed(
        num_ops: usize,
        lanes: usize,
        preprocessed: Vec<F>,
        horner_packed_steps: usize,
    ) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");
        assert!(D == 1, "Use new_binomial_with_preprocessed for D > 1");
        assert!(
            horner_packed_steps >= 2,
            "horner_packed_steps must be at least 2"
        );
        let schedule = Self::compute_schedule(&preprocessed, lanes, horner_packed_steps);
        Self {
            num_ops,
            lanes,
            w_binomial: None,
            preprocessed,
            num_lookup_columns: 0,
            min_height: 1,
            schedule,
            horner_packed_steps,
            _phantom: PhantomData,
        }
    }

    /// Construct a new `AluAir` for binomial extension-field operations (D > 1).
    pub const fn new_binomial(num_ops: usize, lanes: usize, w: F) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");
        assert!(D >= 2, "Binomial constructor requires D >= 2");
        Self {
            num_ops,
            lanes,
            w_binomial: Some(w),
            preprocessed: Vec::new(),
            num_lookup_columns: 0,
            min_height: 1,
            schedule: None,
            horner_packed_steps: 2,
            _phantom: PhantomData,
        }
    }

    /// Construct a new `AluAir` for binomial extension-field operations with preprocessed data.
    pub fn new_binomial_with_preprocessed(
        num_ops: usize,
        lanes: usize,
        w: F,
        preprocessed: Vec<F>,
        horner_packed_steps: usize,
    ) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");
        assert!(D >= 2, "Binomial constructor requires D >= 2");
        assert!(
            horner_packed_steps >= 2,
            "horner_packed_steps must be at least 2"
        );
        let schedule = Self::compute_schedule(&preprocessed, lanes, horner_packed_steps);
        Self {
            num_ops,
            lanes,
            w_binomial: Some(w),
            preprocessed,
            num_lookup_columns: 0,
            min_height: 1,
            schedule,
            horner_packed_steps,
            _phantom: PhantomData,
        }
    }

    /// Set the minimum trace height for FRI compatibility.
    ///
    /// FRI requires: `log_trace_height > log_final_poly_len + log_blowup`
    /// So `min_height` should be >= `2^(log_final_poly_len + log_blowup + 1)`.
    pub const fn with_min_height(mut self, min_height: usize) -> Self {
        self.min_height = min_height;
        self
    }

    /// Override packed Horner chain length (default 2 from [`Self::new`] / [`Self::new_binomial`]).
    ///
    /// Batch verification rebuilds a symbolic ALU without committed preprocessed data; this must
    /// match [`crate::batch_stark_prover::TablePacking::horner_packed_steps`] from the proof.
    pub const fn with_horner_pack_k(mut self, k: usize) -> Self {
        assert!(k >= 2, "horner_packed_steps must be at least 2");
        self.horner_packed_steps = k;
        self
    }

    /// Number of main columns per lane: a[D], b[D], c[D], out[D]
    pub const fn lane_width() -> usize {
        4 * D
    }

    /// Total main trace width for this AIR instance.
    pub const fn total_width(&self) -> usize {
        let extra = 3 * (self.horner_packed_steps - 1) * D;
        self.lanes * Self::lane_width() + extra
    }

    /// Number of preprocessed columns per lane (see `PREP_*` constants).
    pub const fn preprocessed_lane_width() -> usize {
        PREP_LANE_WIDTH
    }

    /// Total preprocessed width: per-lane base columns plus global packed Horner columns.
    pub const fn preprocessed_width(&self) -> usize {
        self.lanes * PREP_LANE_WIDTH + horner_extra_prep_width(self.horner_packed_steps)
    }

    /// Total entries in the scheduled trace (including separators).
    pub fn scheduled_entry_count(&self) -> usize {
        self.schedule.as_ref().map_or(self.num_ops, |s| s.len())
    }

    /// Compute a lane schedule that places HornerAcc chains in lane 0.
    ///
    /// Returns `None` if no HornerAcc ops are present.
    /// Even with `lanes == 1`, scheduling is required: chains must start at
    /// row 0 so the cyclic wrap from the last (zero-padded) row provides
    /// `prev_out = 0`, and separators must appear between chains.
    fn compute_schedule(
        preprocessed: &[F],
        lanes: usize,
        pack_k: usize,
    ) -> Option<Vec<ScheduleEntry>> {
        let plw = PREP_LANE_WIDTH;
        let num_ops = preprocessed.len() / plw;
        if num_ops == 0 {
            return None;
        }

        let is_horner: Vec<bool> = (0..num_ops)
            .map(|i| preprocessed[i * plw + PREP_SEL_HORNER] == F::ONE)
            .collect();

        if !is_horner.iter().any(|&h| h) {
            return None;
        }

        // Find maximal runs of consecutive HornerAcc ops (chains)
        let mut chains: Vec<Vec<usize>> = Vec::new();
        let mut current_chain: Vec<usize> = Vec::new();
        let mut non_chain: Vec<usize> = Vec::new();

        for (i, &h) in is_horner.iter().enumerate() {
            if h {
                current_chain.push(i);
            } else {
                if !current_chain.is_empty() {
                    chains.push(core::mem::take(&mut current_chain));
                }
                non_chain.push(i);
            }
        }
        if !current_chain.is_empty() {
            chains.push(current_chain);
        }

        let mut schedule: Vec<ScheduleEntry> = Vec::new();
        let mut nc = 0; // cursor into non_chain

        // Helper: fill remaining slots in current row with non-chain ops or separators
        let fill_row = |schedule: &mut Vec<ScheduleEntry>, nc: &mut usize, non_chain: &[usize]| {
            while !schedule.len().is_multiple_of(lanes) {
                if *nc < non_chain.len() {
                    schedule.push(ScheduleEntry::Op(non_chain[*nc]));
                    *nc += 1;
                } else {
                    schedule.push(ScheduleEntry::Separator);
                }
            }
        };

        // Leading separator before the first chain. The cyclic constraint
        // wraps from the last row back to row 0, and without this separator
        // the first chain would be a Horner row whose `sel_horner_packed` = 1,
        schedule.push(ScheduleEntry::Separator);
        fill_row(&mut schedule, &mut nc, &non_chain);

        for (chain_idx, chain) in chains.iter().enumerate() {
            if chain_idx > 0 {
                // Complete previous row
                fill_row(&mut schedule, &mut nc, &non_chain);
                // Separator row: lane 0 = zero, other lanes = non-chain or zero
                schedule.push(ScheduleEntry::Separator);
                fill_row(&mut schedule, &mut nc, &non_chain);
            }

            let mut i = 0;
            while i < chain.len() {
                debug_assert_eq!(schedule.len() % lanes, 0, "chain op not at lane 0");
                if i + pack_k <= chain.len() {
                    let mut contiguous = true;
                    for j in 1..pack_k {
                        if chain[i + j] != chain[i] + j {
                            contiguous = false;
                            break;
                        }
                    }
                    let slice = &chain[i..i + pack_k];
                    let share_b = Self::horner_ops_share_b_idx(preprocessed, plw, slice);
                    if contiguous && share_b {
                        schedule.push(ScheduleEntry::PackedHorner(chain[i]));
                        i += pack_k;
                    } else {
                        schedule.push(ScheduleEntry::Op(chain[i]));
                        i += 1;
                    }
                } else {
                    schedule.push(ScheduleEntry::Op(chain[i]));
                    i += 1;
                }
                fill_row(&mut schedule, &mut nc, &non_chain);
            }
        }

        // Complete last chain row
        fill_row(&mut schedule, &mut nc, &non_chain);

        // Remaining non-chain ops fill all lanes
        while nc < non_chain.len() {
            schedule.push(ScheduleEntry::Op(non_chain[nc]));
            nc += 1;
        }
        // Pad final row
        fill_row(&mut schedule, &mut nc, &non_chain);

        Some(schedule)
    }

    /// All ops in `op_indices` use the same `b` witness index in preprocessed data.
    fn horner_ops_share_b_idx(preprocessed: &[F], plw: usize, op_indices: &[usize]) -> bool {
        if op_indices.is_empty() {
            return true;
        }
        let b0 = preprocessed[op_indices[0] * plw + PREP_B_IDX];
        op_indices
            .iter()
            .all(|&idx| preprocessed[idx * plw + PREP_B_IDX] == b0)
    }

    /// Write the 4 operands `[a, b, c, out]` of operation `op_idx` into `dst`
    /// starting at `cursor`, advancing it by `4 * D`.
    #[inline]
    fn write_operands<ExtF: BasedVectorSpace<F>>(
        dst: &mut [F],
        cursor: &mut usize,
        trace: &AluTrace<ExtF>,
        op_idx: usize,
    ) {
        for operand in 0..4 {
            let coeffs = trace.values[op_idx][operand].as_basis_coefficients_slice();
            dst[*cursor..*cursor + D].copy_from_slice(coeffs);
            *cursor += D;
        }
    }

    /// Convert an `AluTrace` into a `RowMajorMatrix` suitable for the STARK prover.
    pub fn trace_to_matrix<ExtF: BasedVectorSpace<F>>(
        &self,
        trace: &AluTrace<ExtF>,
    ) -> RowMajorMatrix<F> {
        let lanes = self.lanes;
        assert!(lanes > 0, "lane count must be non-zero");

        let lane_width = Self::lane_width();
        let width = self.total_width();
        let entry_count = self.scheduled_entry_count();
        let row_count = entry_count.div_ceil(lanes);

        let mut values = F::zero_vec(width * row_count.max(1));

        if let Some(ref schedule) = self.schedule {
            for (pos, entry) in schedule.iter().enumerate() {
                let row = pos / lanes;
                let lane = pos % lanes;

                match entry {
                    ScheduleEntry::Op(i) => {
                        let mut cursor = row * width + lane * lane_width;
                        Self::write_operands(&mut values, &mut cursor, trace, *i);
                    }
                    ScheduleEntry::PackedHorner(first_idx) => {
                        let k = self.horner_packed_steps;
                        let base = row * width + lane * lane_width;
                        let mut cursor = base;

                        for operand in 0..3 {
                            let coeffs =
                                trace.values[*first_idx][operand].as_basis_coefficients_slice();
                            values[cursor..cursor + D].copy_from_slice(coeffs);
                            cursor += D;
                        }
                        let last = first_idx + k - 1;
                        let out_last = trace.values[last][3].as_basis_coefficients_slice();
                        values[cursor..cursor + D].copy_from_slice(out_last);

                        if lane == 0 {
                            let extra = row * width + self.lanes * lane_width;
                            let num_int = k - 1;
                            for s in 0..num_int {
                                let acc =
                                    trace.values[*first_idx + s][3].as_basis_coefficients_slice();
                                let off = extra + s * D;
                                values[off..off + D].copy_from_slice(acc);
                            }
                            let ac_base = extra + num_int * D;
                            for t in 1..k {
                                let op_t = *first_idx + t;
                                let a_t = trace.values[op_t][0].as_basis_coefficients_slice();
                                let c_t = trace.values[op_t][2].as_basis_coefficients_slice();
                                let off = ac_base + 2 * (t - 1) * D;
                                values[off..off + D].copy_from_slice(a_t);
                                values[off + D..off + 2 * D].copy_from_slice(c_t);
                            }
                        }
                    }
                    ScheduleEntry::Separator => {}
                }
            }
        } else {
            for op_idx in 0..trace.values.len() {
                let row = op_idx / lanes;
                let lane = op_idx % lanes;
                let mut cursor = row * width + lane * lane_width;
                Self::write_operands(&mut values, &mut cursor, trace, op_idx);
            }
        }

        let mut mat = RowMajorMatrix::new(values, width);
        mat.pad_to_power_of_two_height(F::ZERO);
        mat
    }

    /// Build the preprocessed trace matrix with HornerAcc scheduling applied.
    ///
    /// Separator entries get multiplicity=0 (no lookups), all selectors/indices=0.
    fn build_scheduled_preprocessed_trace(&self, schedule: &[ScheduleEntry]) -> RowMajorMatrix<F> {
        let plw = PREP_LANE_WIDTH;
        let row_count = schedule.len().div_ceil(self.lanes);
        let row_width = self.preprocessed_width();

        let mut values = F::zero_vec(row_count.max(1) * row_width);

        for (pos, entry) in schedule.iter().enumerate() {
            let row = pos / self.lanes;
            let lane = pos % self.lanes;
            let base = row * row_width + lane * plw;

            match entry {
                ScheduleEntry::Op(i) => {
                    let src = &self.preprocessed[i * plw..(i + 1) * plw];
                    values[base..base + plw].copy_from_slice(src);
                }
                ScheduleEntry::PackedHorner(first_idx) => {
                    if lane == 0 {
                        let k = self.horner_packed_steps;
                        let src0 = &self.preprocessed[*first_idx * plw..(*first_idx + 1) * plw];
                        let last = *first_idx + k - 1;
                        let src_last = &self.preprocessed[last * plw..(last + 1) * plw];

                        values[base..base + plw].copy_from_slice(src0);

                        values[base + PREP_OUT_IDX] = src_last[PREP_OUT_IDX];
                        values[base + PREP_MULT_OUT] = src_last[PREP_MULT_OUT];

                        let mult_b0 = values[base + PREP_MULT_B];
                        let mut mult_b_scaled = F::ZERO;
                        for _ in 0..k {
                            mult_b_scaled += mult_b0;
                        }
                        values[base + PREP_MULT_B] = mult_b_scaled;

                        let extra_base = row * row_width + self.lanes * plw;
                        values[extra_base + EXTRA_PREP_SEL_PACKED] = F::ONE;
                        for t in 1..k {
                            let src_t = &self.preprocessed
                                [(*first_idx + t) * plw..(*first_idx + t + 1) * plw];
                            let p = extra_base + extra_prep_a_idx_for_step(t);
                            values[p] = src_t[PREP_A_IDX];
                            values[p + 1] = src_t[PREP_C_IDX];
                            values[p + 2] = src_t[PREP_A_IS_READER];
                            values[p + 3] = src_t[PREP_C_IS_READER];
                        }
                    }
                }
                ScheduleEntry::Separator => {}
            }
        }

        let mut mat = RowMajorMatrix::new(values, row_width);
        mat.pad_to_min_power_of_two_height(self.min_height, F::ZERO);
        mat
    }
}

impl<F: Field, const D: usize> BaseAir<F> for AluAir<F, D> {
    fn width(&self) -> usize {
        self.total_width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        self.schedule.as_ref().map_or_else(
            || {
                // No Horner scheduling: build the preprocessed trace at the
                // base width, then widen with zero columns for scheduling slots.
                let base_width = self.lanes * PREP_LANE_WIDTH;
                let mut mat = RowMajorMatrix::from_flat_padded(
                    self.preprocessed.to_vec(),
                    base_width,
                    F::ZERO,
                );
                mat.widen_right(horner_extra_prep_width(self.horner_packed_steps), F::ZERO);
                mat.pad_to_min_power_of_two_height(self.min_height, F::ZERO);
                Some(mat)
            },
            |schedule| Some(self.build_scheduled_preprocessed_trace(schedule)),
        )
    }
}

/// Compute `x * y` as a D-coefficient extension-field product, where
/// `w` is the binomial parameter (only used when `D > 1`).
///
/// When `D == 1` the `w` parameter is unused and all loops degenerate to a
/// single scalar multiply, so this is zero-cost for base-field AIRs.
#[inline]
fn ext_mul<AB: AirBuilder, const D: usize>(
    x: &[AB::Var],
    y: &[AB::Var],
    w: &Option<AB::Expr>,
) -> Vec<AB::Expr> {
    let mut acc = vec![AB::Expr::ZERO; D];
    for i in 0..D {
        for j in 0..D {
            let term = x[i] * y[j];
            let k = i + j;
            if k < D {
                acc[k] = acc[k].clone() + term;
            } else {
                acc[k - D] = acc[k - D].clone() + w.clone().unwrap() * term;
            }
        }
    }
    acc
}

impl<AB: AirBuilder, const D: usize> Air<AB> for AluAir<AB::F, D>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        debug_assert_eq!(
            main.current_slice().len(),
            self.total_width(),
            "column width mismatch"
        );

        let local = main.current_slice();
        let next = main.next_slice();
        let lane_width = Self::lane_width();

        let preprocessed = builder.preprocessed().clone();
        let prep_local = preprocessed.current_slice();
        let prep_next = preprocessed.next_slice();

        let w: Option<AB::Expr> = self.w_binomial.as_ref().map(|w| AB::Expr::from(*w));

        for lane in 0..self.lanes {
            let m = lane * lane_width;
            let p = lane * PREP_LANE_WIDTH;

            let a = &local[m..m + D];
            let b = &local[m + D..m + 2 * D];
            let c = &local[m + 2 * D..m + 3 * D];
            let out = &local[m + 3 * D..m + 4 * D];

            let mult_a = prep_local[p + PREP_MULT_A];
            let sel_add = prep_local[p + PREP_SEL_ADD];
            let sel_bool = prep_local[p + PREP_SEL_BOOL];
            let sel_muladd = prep_local[p + PREP_SEL_MULADD];
            let sel_horner = prep_local[p + PREP_SEL_HORNER];

            let active = AB::Expr::ZERO - mult_a;
            let sel_mul = active - sel_bool - sel_muladd - sel_horner - sel_add;

            // ── ADD: a + b - out = 0 ────────────────────────────────────
            for i in 0..D {
                builder.assert_zero(sel_add * (a[i] + b[i] - out[i]));
            }

            // ── MUL: a * b - out = 0 ────────────────────────────────────
            let ab = ext_mul::<AB, D>(a, b, &w);
            for i in 0..D {
                builder.assert_zero(sel_mul.clone() * (ab[i].clone() - out[i]));
            }

            // ── BOOL_CHECK: a[0]*(a[0]-1)=0, a[1..D]=0 ─────────────────
            let one = AB::Expr::ONE;
            builder.assert_zero(sel_bool * a[0] * (a[0] - one));
            for i in 1..D {
                builder.assert_zero(sel_bool * a[i]);
            }

            // ── MUL_ADD: a * b + c - out = 0 ────────────────────────────
            for i in 0..D {
                builder.assert_zero(sel_muladd * (ab[i].clone() + c[i] - out[i]));
            }

            // ── HORNER_ACC ───────────────────────────────────────────────
            let next_sel_horner = prep_next[p + PREP_SEL_HORNER];

            let next_a = &next[m..m + D];
            let next_b = &next[m + D..m + 2 * D];
            let next_c = &next[m + 2 * D..m + 3 * D];
            let next_out = &next[m + 3 * D..m + 4 * D];

            let out_next_b = ext_mul::<AB, D>(out, next_b, &w);

            let extra_main = self.lanes * lane_width;
            let extra_prep = self.lanes * PREP_LANE_WIDTH;
            let k = self.horner_packed_steps;
            let extra_coeff_width = 3 * (k - 1) * D;
            let has_extra_cols = extra_main + extra_coeff_width <= local.len()
                && extra_prep + horner_extra_prep_width(k) <= prep_local.len()
                && extra_prep + horner_extra_prep_width(k) <= prep_next.len();

            if lane == 0 && has_extra_cols {
                let next_int0 = &next[extra_main..extra_main + D];

                let sel_packed = prep_local[extra_prep + EXTRA_PREP_SEL_PACKED];
                let next_sel_packed = prep_next[extra_prep + EXTRA_PREP_SEL_PACKED];

                // 1) Packed inter-row: prev_out -> next row's first intermediate
                for i in 0..D {
                    builder.assert_zero(
                        next_sel_packed
                            * (out_next_b[i].clone() + next_c[i] - next_a[i] - next_int0[i]),
                    );
                }

                // 2) Single-step fallback: prev_out -> next_out
                let next_sel_single = next_sel_horner - next_sel_packed;
                for i in 0..D {
                    builder.assert_zero(
                        next_sel_single.clone()
                            * (out_next_b[i].clone() + next_c[i] - next_a[i] - next_out[i]),
                    );
                }

                // 3) Intra-row: int_s * b + c_{s+1} - a_{s+1} - int_{s+1} = 0, last leg -> out
                let num_int = k - 1;
                let ac_base = extra_main + num_int * D;
                for s in 0..num_int.saturating_sub(1) {
                    let int_s = &local[extra_main + s * D..extra_main + (s + 1) * D];
                    let int_sp1 = &local[extra_main + (s + 1) * D..extra_main + (s + 2) * D];
                    let t = s + 1;
                    let off = ac_base + 2 * (t - 1) * D;
                    let a_t = &local[off..off + D];
                    let c_t = &local[off + D..off + 2 * D];
                    let int_s_b = ext_mul::<AB, D>(int_s, b, &w);
                    for i in 0..D {
                        builder.assert_zero(
                            sel_packed * (int_s_b[i].clone() + c_t[i] - a_t[i] - int_sp1[i]),
                        );
                    }
                }
                if k >= 2 {
                    let s_last = k - 2;
                    let int_last = &local[extra_main + s_last * D..extra_main + (s_last + 1) * D];
                    let t = k - 1;
                    let off = ac_base + 2 * (t - 1) * D;
                    let a_t = &local[off..off + D];
                    let c_t = &local[off + D..off + 2 * D];
                    let int_last_b = ext_mul::<AB, D>(int_last, b, &w);
                    for i in 0..D {
                        builder.assert_zero(
                            sel_packed * (int_last_b[i].clone() + c_t[i] - a_t[i] - out[i]),
                        );
                    }
                }
            } else {
                for i in 0..D {
                    builder.assert_zero(
                        next_sel_horner
                            * (out_next_b[i].clone() + next_c[i] - next_a[i] - next_out[i]),
                    );
                }
            }
        }
    }
}

impl<F: Field, const D: usize> LookupAir<F> for AluAir<F, D> {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let new_idx = self.num_lookup_columns;
        self.num_lookup_columns += 1;
        vec![new_idx]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        let mut lookups = Vec::new();
        self.num_lookup_columns = 0;

        let (symbolic_main_local, preprocessed_local) = create_symbolic_variables::<F>(
            self.preprocessed_width(),
            BaseAir::<F>::width(self),
            0,
            0,
        );

        for lane in 0..self.lanes {
            let lane_offset = lane * Self::lane_width();
            let preprocessed_lane_offset = lane * Self::preprocessed_lane_width();

            // 4 lookups per lane: a, b, c, out (all Direction::Receive)
            let lane_lookup_inputs = get_alu_index_lookups::<F, D>(
                lane_offset,
                preprocessed_lane_offset,
                &symbolic_main_local,
                &preprocessed_local,
            );
            lookups.extend(lane_lookup_inputs.into_iter().map(|inps| {
                LookupAir::register_lookup(self, Kind::Global("WitnessChecks".to_string()), &[inps])
            }));
        }

        // Extra lookups for (a_t, c_t), t = 1..K-1, on packed Horner rows.
        let extra_main = self.lanes * Self::lane_width();
        let extra_prep = self.lanes * Self::preprocessed_lane_width();
        let k = self.horner_packed_steps;
        let num_int = k - 1;
        let ac_base = extra_main + num_int * D;

        let mult_a_lane0 = SymbolicExpression::from(preprocessed_local[PREP_MULT_A]);

        for t in 1..k {
            let p = extra_prep + extra_prep_a_idx_for_step(t);
            let a_reader = SymbolicExpression::from(preprocessed_local[p + 2]);
            let c_reader = SymbolicExpression::from(preprocessed_local[p + 3]);
            let eff_mult_a = mult_a_lane0.clone() * a_reader.clone();
            let eff_mult_c = mult_a_lane0.clone() * c_reader;

            let a_idx = SymbolicExpression::from(preprocessed_local[p]);
            let main_off = ac_base + 2 * (t - 1) * D;
            let mut a_inps = vec![a_idx];
            for j in 0..D {
                a_inps.push(SymbolicExpression::from(symbolic_main_local[main_off + j]));
            }
            lookups.push(LookupAir::register_lookup(
                self,
                Kind::Global("WitnessChecks".to_string()),
                &[(a_inps, eff_mult_a, Direction::Receive)],
            ));

            let c_idx = SymbolicExpression::from(preprocessed_local[p + 1]);
            let mut c_inps = vec![c_idx];
            for j in 0..D {
                c_inps.push(SymbolicExpression::from(
                    symbolic_main_local[main_off + D + j],
                ));
            }
            lookups.push(LookupAir::register_lookup(
                self,
                Kind::Global("WitnessChecks".to_string()),
                &[(c_inps, eff_mult_c, Direction::Receive)],
            ));
        }

        lookups
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use p3_circuit::WitnessId;
    use p3_circuit::ops::AluOpKind;
    use p3_field::BasedVectorSpace;
    use p3_matrix::Matrix;
    use p3_test_utils::baby_bear_params::{
        BabyBear as Val, BinomialExtensionField, PrimeCharacteristicRing,
    };
    use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
    use p3_util::log2_ceil_usize;

    use super::*;
    use crate::air::test_utils::build_test_config;

    /// Convert an `AluTrace` to preprocessed values (13 columns per op) for standalone tests.
    fn trace_to_preprocessed<F: Field, ExtF: BasedVectorSpace<F>, const D: usize>(
        trace: &AluTrace<ExtF>,
    ) -> Vec<F> {
        let total_len = trace.indices.len() * AluAir::<F, D>::preprocessed_lane_width();
        let mut preprocessed_values = Vec::with_capacity(total_len);
        let neg_one = F::ZERO - F::ONE;

        for (i, kind) in trace.op_kind.iter().enumerate() {
            let (sel_add_vs_mul, sel_bool, sel_muladd, sel_horner) = match kind {
                AluOpKind::Add => (F::ONE, F::ZERO, F::ZERO, F::ZERO),
                AluOpKind::Mul => (F::ZERO, F::ZERO, F::ZERO, F::ZERO),
                AluOpKind::BoolCheck => (F::ZERO, F::ONE, F::ZERO, F::ZERO),
                AluOpKind::MulAdd => (F::ZERO, F::ZERO, F::ONE, F::ZERO),
                AluOpKind::HornerAcc => (F::ZERO, F::ZERO, F::ZERO, F::ONE),
            };

            preprocessed_values.extend(&[
                neg_one, // mult_a (base; active = 1)
                sel_add_vs_mul,
                sel_bool,
                sel_muladd,
                sel_horner,
                F::from_u32(trace.indices[i][0].0 * D as u32),
                F::from_u32(trace.indices[i][1].0 * D as u32),
                F::from_u32(trace.indices[i][2].0 * D as u32),
                F::from_u32(trace.indices[i][3].0 * D as u32),
                neg_one, // mult_b (reader placeholder)
                F::ONE,  // mult_out (creator placeholder)
                F::ONE,  // a_is_reader (standalone: constrained)
                F::ONE,  // c_is_reader (standalone: constrained)
            ]);
        }

        preprocessed_values
    }

    #[test]
    fn prove_verify_alu_add_base_field() {
        let n = 8;
        let op_kind = vec![AluOpKind::Add; n];
        let values = vec![
            [
                Val::from_u64(3),
                Val::from_u64(5),
                Val::ZERO,
                Val::from_u64(8)
            ];
            n
        ];
        let indices = vec![[WitnessId(1), WitnessId(2), WitnessId(0), WitnessId(3)]; n];

        let trace = AluTrace {
            op_kind,
            values,
            indices,
        };

        let preprocessed_values = trace_to_preprocessed::<Val, _, 1>(&trace);
        let air = AluAir::<Val, 1>::new_with_preprocessed(n, 1, preprocessed_values, 2);
        let matrix: RowMajorMatrix<Val> = air.trace_to_matrix(&trace);
        assert_eq!(matrix.width(), air.total_width());

        let config = build_test_config();
        let pis: Vec<Val> = vec![];
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("verification failed");
    }

    #[test]
    fn prove_verify_alu_mul_base_field() {
        let n = 8;
        let op_kind = vec![AluOpKind::Mul; n];
        let values = vec![
            [
                Val::from_u64(3),
                Val::from_u64(5),
                Val::ZERO,
                Val::from_u64(15)
            ];
            n
        ];
        let indices = vec![[WitnessId(1), WitnessId(2), WitnessId(0), WitnessId(3)]; n];

        let trace = AluTrace {
            op_kind,
            values,
            indices,
        };

        let preprocessed_values = trace_to_preprocessed::<Val, _, 1>(&trace);
        let air = AluAir::<Val, 1>::new_with_preprocessed(n, 1, preprocessed_values, 2);
        let matrix: RowMajorMatrix<Val> = air.trace_to_matrix(&trace);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("verification failed");
    }

    #[test]
    fn prove_verify_alu_bool_check() {
        let n = 8;
        // Test with valid boolean values (0 and 1)
        let op_kind = vec![AluOpKind::BoolCheck; n];
        let values = (0..n)
            .map(|i| {
                [
                    Val::from_u64(i as u64 % 2),
                    Val::ZERO,
                    Val::ZERO,
                    Val::from_u64(i as u64 % 2),
                ]
            })
            .collect();
        let indices = vec![[WitnessId(1), WitnessId(0), WitnessId(0), WitnessId(1)]; n];

        let trace = AluTrace {
            op_kind,
            values,
            indices,
        };

        let preprocessed_values = trace_to_preprocessed::<Val, _, 1>(&trace);
        let air = AluAir::<Val, 1>::new_with_preprocessed(n, 1, preprocessed_values, 2);
        let matrix: RowMajorMatrix<Val> = air.trace_to_matrix(&trace);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("verification failed");
    }

    #[test]
    fn prove_verify_alu_muladd() {
        let n = 8;
        // a * b + c = out => 3 * 5 + 2 = 17
        let op_kind = vec![AluOpKind::MulAdd; n];
        let values = vec![
            [
                Val::from_u64(3),
                Val::from_u64(5),
                Val::from_u64(2),
                Val::from_u64(17)
            ];
            n
        ];
        let indices = vec![[WitnessId(1), WitnessId(2), WitnessId(3), WitnessId(4)]; n];

        let trace = AluTrace {
            op_kind,
            values,
            indices,
        };

        let preprocessed_values = trace_to_preprocessed::<Val, _, 1>(&trace);
        let air = AluAir::<Val, 1>::new_with_preprocessed(n, 1, preprocessed_values, 2);
        let matrix: RowMajorMatrix<Val> = air.trace_to_matrix(&trace);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("verification failed");
    }

    #[test]
    fn prove_verify_alu_mixed_ops() {
        // Mix of ADD and MUL operations
        let op_kind = vec![AluOpKind::Add, AluOpKind::Mul];
        let values = vec![
            [
                Val::from_u64(3),
                Val::from_u64(5),
                Val::ZERO,
                Val::from_u64(8),
            ],
            [
                Val::from_u64(4),
                Val::from_u64(6),
                Val::ZERO,
                Val::from_u64(24),
            ],
        ];
        let indices = vec![
            [WitnessId(1), WitnessId(2), WitnessId(0), WitnessId(3)],
            [WitnessId(1), WitnessId(2), WitnessId(0), WitnessId(3)],
        ];

        let trace = AluTrace {
            op_kind,
            values,
            indices,
        };

        let preprocessed_values = trace_to_preprocessed::<Val, _, 1>(&trace);
        let air = AluAir::<Val, 1>::new_with_preprocessed(2, 1, preprocessed_values, 2);
        let matrix: RowMajorMatrix<Val> = air.trace_to_matrix(&trace);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("verification failed");
    }

    #[test]
    fn prove_verify_alu_double_step_horner_base_field() {
        // Build a simple Horner chain of length 3 over the base field and
        // check that the scheduled ALU trace with double-step rows verifies.
        // Relation: out = prev_out * b + c - a; double-step shares b for two steps.
        let n = 3;
        let op_kind = vec![AluOpKind::HornerAcc; n];

        let prev_out = Val::ZERO;
        let a0 = Val::from_u64(1);
        let b0 = Val::from_u64(2);
        let c0 = Val::from_u64(5);
        let out0 = prev_out * b0 + c0 - a0;

        let a1 = Val::ZERO;
        let b1 = b0;
        let c1 = Val::from_u64(3);
        let out1 = out0 * b1 + c1 - a1;

        let a2 = Val::from_u64(1);
        let b2 = Val::from_u64(3);
        let c2 = Val::from_u64(2);
        let out2 = out1 * b2 + c2 - a2;

        let values = vec![[a0, b0, c0, out0], [a1, b1, c1, out1], [a2, b2, c2, out2]];
        let indices = vec![[WitnessId(1), WitnessId(2), WitnessId(3), WitnessId(4)]; n];

        let trace = AluTrace {
            op_kind,
            values,
            indices,
        };

        let preprocessed_values = trace_to_preprocessed::<Val, _, 1>(&trace);
        let air = AluAir::<Val, 1>::new_with_preprocessed(n, 1, preprocessed_values, 2);
        let matrix: RowMajorMatrix<Val> = air.trace_to_matrix(&trace);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("double-step horner base-field verification failed");
    }

    #[test]
    fn prove_verify_alu_k4_packed_horner_base_field() {
        const K: usize = 4;
        let n = 8;
        let op_kind = vec![AluOpKind::HornerAcc; n];
        let b = Val::from_u64(2);
        let mut acc = Val::ZERO;
        let mut values = Vec::with_capacity(n);
        for step in 0..n {
            let a = Val::from_u64((step + 1) as u64);
            let c = Val::from_u64(5);
            let out = acc * b + c - a;
            values.push([a, b, c, out]);
            acc = out;
        }
        let indices = vec![[WitnessId(1), WitnessId(2), WitnessId(3), WitnessId(4)]; n];

        let trace = AluTrace {
            op_kind,
            values,
            indices,
        };

        let preprocessed_values = trace_to_preprocessed::<Val, _, 1>(&trace);
        let air = AluAir::<Val, 1>::new_with_preprocessed(n, 1, preprocessed_values, K);
        assert_eq!(air.horner_packed_steps, K);
        let matrix: RowMajorMatrix<Val> = air.trace_to_matrix(&trace);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("K=4 packed horner base-field verification failed");
    }

    #[test]
    fn prove_verify_alu_extension_field_d4() {
        type ExtField = BinomialExtensionField<Val, 4>;
        let n = 4;

        let a = ExtField::from_basis_coefficients_slice(&[
            Val::from_u64(7),
            Val::from_u64(3),
            Val::from_u64(4),
            Val::from_u64(5),
        ])
        .unwrap();

        let b = ExtField::from_basis_coefficients_slice(&[
            Val::from_u64(11),
            Val::from_u64(2),
            Val::from_u64(9),
            Val::from_u64(6),
        ])
        .unwrap();

        let c = ExtField::ZERO;
        let out = a * b; // multiplication result

        let trace = AluTrace {
            op_kind: vec![AluOpKind::Mul; n],
            values: vec![[a, b, c, out]; n],
            indices: vec![[WitnessId(1), WitnessId(2), WitnessId(0), WitnessId(3)]; n],
        };

        let preprocessed_values = trace_to_preprocessed::<Val, _, 4>(&trace);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        // Get w from the extension field
        let w = Val::from_u64(11); // BabyBear's binomial extension uses w=11

        let air = AluAir::<Val, 4>::new_binomial_with_preprocessed(n, 1, w, preprocessed_values, 2);
        let matrix: RowMajorMatrix<Val> = air.trace_to_matrix(&trace);
        assert_eq!(matrix.width(), air.total_width());
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("extension field verification failed");
    }

    #[test]
    fn prove_verify_alu_bool_check_extension_field_d4() {
        type ExtField = BinomialExtensionField<Val, 4>;
        let n = 4;
        let w = Val::from_u64(11);

        // Valid booleans: [0,0,0,0] and [1,0,0,0] interleaved
        let zero =
            ExtField::from_basis_coefficients_slice(&[Val::ZERO, Val::ZERO, Val::ZERO, Val::ZERO])
                .unwrap();
        let one =
            ExtField::from_basis_coefficients_slice(&[Val::ONE, Val::ZERO, Val::ZERO, Val::ZERO])
                .unwrap();

        let values: Vec<[ExtField; 4]> = (0..n)
            .map(|i| {
                let v = if i % 2 == 0 { zero } else { one };
                [v, zero, zero, v]
            })
            .collect();
        let indices = vec![[WitnessId(1), WitnessId(0), WitnessId(0), WitnessId(1)]; n];

        let trace = AluTrace {
            op_kind: vec![AluOpKind::BoolCheck; n],
            values,
            indices,
        };

        let preprocessed_values = trace_to_preprocessed::<Val, _, 4>(&trace);
        let air = AluAir::<Val, 4>::new_binomial_with_preprocessed(n, 1, w, preprocessed_values, 2);
        let matrix: RowMajorMatrix<Val> = air.trace_to_matrix(&trace);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("extension field bool_check verification failed");
    }

    /// The prover should panic with an unsatisfied as higher limbs constraints are not satisfied.
    #[test]
    #[should_panic]
    fn bool_check_extension_field_rejects_nonzero_higher_coefficients() {
        type ExtField = BinomialExtensionField<Val, 4>;
        let n = 4;
        let w = Val::from_u64(11);

        // a[0]=1 is a valid boolean, but a[1]=5 is non-zero — must be rejected.
        let bad = ExtField::from_basis_coefficients_slice(&[
            Val::ONE,
            Val::from_u64(5),
            Val::ZERO,
            Val::ZERO,
        ])
        .unwrap();
        let zero = ExtField::ZERO;

        let values: Vec<[ExtField; 4]> = vec![[bad, zero, zero, bad]; n];
        let indices = vec![[WitnessId(1), WitnessId(0), WitnessId(0), WitnessId(1)]; n];

        let trace = AluTrace {
            op_kind: vec![AluOpKind::BoolCheck; n],
            values,
            indices,
        };

        let preprocessed_values = trace_to_preprocessed::<Val, _, 4>(&trace);
        let air = AluAir::<Val, 4>::new_binomial_with_preprocessed(n, 1, w, preprocessed_values, 2);
        let matrix: RowMajorMatrix<Val> = air.trace_to_matrix(&trace);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        // Verification must fail — the constraint a[1] = 0 is violated.
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("should have failed");
    }

    #[test]
    fn test_alu_air_constraint_degree() {
        let preprocessed = vec![Val::ZERO; 8 * 13]; // 8 ops * 13 preprocessed columns per op
        let air = AluAir::<Val, 1>::new_with_preprocessed(8, 2, preprocessed, 2);
        p3_test_utils::assert_air_constraint_degree!(air, "AluAir");
    }
}
