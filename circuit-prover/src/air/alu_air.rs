//! [`AluAir`] defines the unified AIR for proving arithmetic operations over both base and extension fields.
//!
//! This AIR combines addition, multiplication, boolean checks, fused multiply-add, and
//! row-chained Horner accumulator operations into a single table.
//!
//! Conceptually, each row of the trace encodes one or more arithmetic constraints based on
//! preprocessed operation selectors:
//!
//! - **ADD**: `a + b = out`
//! - **MUL**: `a * b = out`
//! - **BOOL_CHECK**: `a * (a - 1) = 0`, `out = a`
//! - **MUL_ADD**: `a * b + c = out`
//! - **HORNER_ACC**: `out = prev_row_out * b + c - a` (inter-row constraint)
//!
//! # Column layout
//!
//! For each logical operation (lane) we allocate `4 * D` main columns:
//!
//! - `D` columns for operand `a` (basis coefficients),
//! - `D` columns for operand `b` (basis coefficients),
//! - `D` columns for operand `c` (basis coefficients, used for MulAdd/HornerAcc),
//! - `D` columns for output `out` (basis coefficients).
//!
//! Preprocessed columns per lane (13 total):
//!
//! - 1 column `active` (1 for active row, 0 for padding)
//! - 1 column `mult_a`: signed multiplicity for `a` (`-1` reader, `+N` first unconstrained creator, `0` padding)
//! - 4 columns for operation selectors (sel_add_vs_mul, sel_bool, sel_muladd, sel_horner)
//! - 4 columns for operand indices (a_idx, b_idx, c_idx, out_idx)
//! - 1 column `mult_b`, 1 column `mult_out`, 1 column `mult_c` (same multiplicity convention)
//!
//! # Constraints (degree ≤ 3)
//!
//! All constraint degrees are within the limit for `log_blowup = 1`:
//!
//! - ADD: `a + b - out = 0` (degree 1)
//! - MUL: `a * b - out = 0` (degree 2)
//! - BOOL_CHECK: `a * (a - 1) = 0` (degree 2)
//! - MUL_ADD: `a * b + c - out = 0` (degree 2)
//! - HORNER_ACC: `prev_row_out * b + c - a - out = 0` (degree 2, inter-row)

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_circuit::op::AluOpKind;
use p3_circuit::tables::AluTrace;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_lookup::LookupAir;
use p3_lookup::lookup_traits::{Kind, Lookup};
use p3_matrix::dense::RowMajorMatrix;

use crate::air::utils::{
    create_direct_preprocessed_trace, create_symbolic_variables, get_alu_index_lookups,
    pad_matrix_with_min_height,
};

/// Entry in the HornerAcc lane schedule.
#[derive(Debug, Clone, Copy)]
enum ScheduleEntry {
    /// A real ALU op at the given original index.
    Op(usize),
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
            _phantom: PhantomData,
        }
    }

    /// Construct a new `AluAir` for base-field operations with preprocessed data.
    pub fn new_with_preprocessed(num_ops: usize, lanes: usize, preprocessed: Vec<F>) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");
        assert!(D == 1, "Use new_binomial_with_preprocessed for D > 1");
        let schedule = Self::compute_schedule(&preprocessed, lanes);
        Self {
            num_ops,
            lanes,
            w_binomial: None,
            preprocessed,
            num_lookup_columns: 0,
            min_height: 1,
            schedule,
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
            _phantom: PhantomData,
        }
    }

    /// Construct a new `AluAir` for binomial extension-field operations with preprocessed data.
    pub fn new_binomial_with_preprocessed(
        num_ops: usize,
        lanes: usize,
        w: F,
        preprocessed: Vec<F>,
    ) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");
        assert!(D >= 2, "Binomial constructor requires D >= 2");
        let schedule = Self::compute_schedule(&preprocessed, lanes);
        Self {
            num_ops,
            lanes,
            w_binomial: Some(w),
            preprocessed,
            num_lookup_columns: 0,
            min_height: 1,
            schedule,
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

    /// Number of main columns per lane: a[D], b[D], c[D], out[D]
    pub const fn lane_width() -> usize {
        4 * D
    }

    /// Total main trace width for this AIR instance.
    pub const fn total_width(&self) -> usize {
        self.lanes * Self::lane_width()
    }

    /// Number of preprocessed columns per lane (12 total):
    /// [active, mult_a, sel1, sel2, sel3, sel4, a_idx, b_idx, c_idx, out_idx, mult_b, mult_out, mult_c]
    pub const fn preprocessed_lane_width() -> usize {
        13
    }

    /// Total preprocessed width for this AIR instance.
    pub const fn preprocessed_width(&self) -> usize {
        self.lanes * Self::preprocessed_lane_width()
    }

    /// Number of preprocessed columns excluding multiplicity.
    pub const fn preprocessed_width_without_multiplicity(&self) -> usize {
        self.lanes * (Self::preprocessed_lane_width() - 1)
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
    fn compute_schedule(preprocessed: &[F], lanes: usize) -> Option<Vec<ScheduleEntry>> {
        let plw = Self::preprocessed_lane_width(); // 13
        let num_ops = preprocessed.len() / plw;
        if num_ops == 0 {
            return None;
        }

        let is_horner: Vec<bool> = (0..num_ops)
            .map(|i| preprocessed[i * plw + 4] == F::ONE) // sel_horner at offset 4
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

        for (chain_idx, chain) in chains.iter().enumerate() {
            if chain_idx > 0 {
                // Complete previous row
                fill_row(&mut schedule, &mut nc, &non_chain);
                // Separator row: lane 0 = zero, other lanes = non-chain or zero
                schedule.push(ScheduleEntry::Separator);
                fill_row(&mut schedule, &mut nc, &non_chain);
            }

            // Place chain ops in lane 0
            for &op_idx in chain {
                debug_assert_eq!(schedule.len() % lanes, 0, "chain op not at lane 0");
                schedule.push(ScheduleEntry::Op(op_idx));
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

    /// Convert an `AluTrace` into a `RowMajorMatrix` suitable for the STARK prover.
    pub fn trace_to_matrix<ExtF: BasedVectorSpace<F>>(
        &self,
        trace: &AluTrace<ExtF>,
    ) -> RowMajorMatrix<F> {
        let lanes = self.lanes;
        assert!(lanes > 0, "lane count must be non-zero");

        let lane_width = Self::lane_width();
        let width = lane_width * lanes;
        let entry_count = self.scheduled_entry_count();
        let row_count = entry_count.div_ceil(lanes);

        let mut values = F::zero_vec(width * row_count.max(1));

        // Write one entry at position `pos` (row = pos/lanes, lane = pos%lanes)
        let mut write_op =
            |pos: usize, a_val: &ExtF, b_val: &ExtF, c_val: &ExtF, out_val: &ExtF| {
                let row = pos / lanes;
                let lane = pos % lanes;
                let mut cursor = row * width + lane * lane_width;

                let a_coeffs = a_val.as_basis_coefficients_slice();
                values[cursor..cursor + D].copy_from_slice(a_coeffs);
                cursor += D;
                let b_coeffs = b_val.as_basis_coefficients_slice();
                values[cursor..cursor + D].copy_from_slice(b_coeffs);
                cursor += D;
                let c_coeffs = c_val.as_basis_coefficients_slice();
                values[cursor..cursor + D].copy_from_slice(c_coeffs);
                cursor += D;
                let out_coeffs = out_val.as_basis_coefficients_slice();
                values[cursor..cursor + D].copy_from_slice(out_coeffs);
            };

        if let Some(ref schedule) = self.schedule {
            for (pos, entry) in schedule.iter().enumerate() {
                if let ScheduleEntry::Op(i) = entry {
                    write_op(
                        pos,
                        &trace.values[*i][0], // a
                        &trace.values[*i][1], // b
                        &trace.values[*i][2], // c
                        &trace.values[*i][3], // out
                    );
                }
                // Separator entries stay zero (already initialized)
            }
        } else {
            for op_idx in 0..trace.values.len() {
                write_op(
                    op_idx,
                    &trace.values[op_idx][0], // a
                    &trace.values[op_idx][1], // b
                    &trace.values[op_idx][2], // c
                    &trace.values[op_idx][3], // out
                );
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
        let plw = Self::preprocessed_lane_width(); // 13
        let row_count = schedule.len().div_ceil(self.lanes);
        let row_width = self.lanes * plw;

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
                ScheduleEntry::Separator => {
                    // multiplicity = 0, all zeros — already initialized
                }
            }
        }

        let mat = RowMajorMatrix::new(values, row_width);
        pad_matrix_with_min_height(mat, self.min_height)
    }

    /// Convert an `AluTrace` to preprocessed values (13 columns per op).
    ///
    /// Layout: `[mult_a, sel_add_vs_mul, sel_bool, sel_muladd, sel_horner, a_idx, b_idx, c_idx, out_idx, mult_b, mult_out, a_is_reader, c_is_reader]`.
    /// Indices are D-scaled. In standalone tests, `a_is_reader = c_is_reader = 1`.
    pub fn trace_to_preprocessed<ExtF: BasedVectorSpace<F>>(trace: &AluTrace<ExtF>) -> Vec<F> {
        let total_len = trace.indices.len() * Self::preprocessed_lane_width();
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
}

impl<F: Field, const D: usize> BaseAir<F> for AluAir<F, D> {
    fn width(&self) -> usize {
        self.total_width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        self.schedule.as_ref().map_or_else(
            || {
                Some(create_direct_preprocessed_trace(
                    &self.preprocessed,
                    Self::preprocessed_lane_width(),
                    self.lanes,
                    self.min_height,
                ))
            },
            |schedule| Some(self.build_scheduled_preprocessed_trace(schedule)),
        )
    }
}

impl<AB: AirBuilder, const D: usize> Air<AB> for AluAir<AB::F, D>
where
    AB::F: Field,
{
    #[unroll::unroll_for_loops]
    #[allow(clippy::needless_range_loop)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        debug_assert_eq!(
            main.current_slice().len(),
            self.total_width(),
            "column width mismatch"
        );

        let local = main.current_slice();
        let lane_width = Self::lane_width();

        // Get preprocessed columns
        let preprocessed = builder.preprocessed().clone();
        let preprocessed_local = preprocessed.current_slice();
        let preprocessed_lane_width = Self::preprocessed_lane_width();

        // Next-row access for HornerAcc inter-row constraint
        let next = main.next_slice();
        let preprocessed_next = preprocessed.next_slice();

        // D=1 specialization
        if D == 1 {
            debug_assert_eq!(lane_width, 4);

            for lane in 0..self.lanes {
                let main_offset = lane * lane_width;
                let prep_offset = lane * preprocessed_lane_width;

                let a = local[main_offset];
                let b = local[main_offset + 1];
                let c = local[main_offset + 2];
                let out = local[main_offset + 3];

                // Preprocessed layout: [mult_a, sel_add_vs_mul, sel_bool, sel_muladd, sel_horner, a_idx, b_idx, c_idx, out_idx, mult_b, mult_out, a_is_reader, c_is_reader]
                let mult_a = preprocessed_local[prep_offset];
                let sel_add_vs_mul = preprocessed_local[prep_offset + 1];
                let sel_bool = preprocessed_local[prep_offset + 2];
                let sel_muladd = preprocessed_local[prep_offset + 3];
                let sel_horner = preprocessed_local[prep_offset + 4];

                // active = -mult_a: 1 for active rows, 0 for padding
                let active = AB::Expr::ZERO - mult_a;
                // sel_mul = active - sel_bool - sel_muladd - sel_horner - sel_add_vs_mul
                let sel_mul = active - sel_bool - sel_muladd - sel_horner - sel_add_vs_mul;

                // ADD constraint: sel_add_vs_mul * (a + b - out) = 0
                builder.assert_zero(sel_add_vs_mul * (a + b - out));

                // MUL constraint: sel_mul * (a * b - out) = 0
                builder.assert_zero(sel_mul * (a * b - out));

                // BOOL_CHECK constraint: sel_bool * a * (a - 1) = 0
                let one = AB::Expr::ONE;
                builder.assert_zero(sel_bool * a * (a - one));

                // MUL_ADD constraint: sel_muladd * (a * b + c - out) = 0
                builder.assert_zero(sel_muladd * (a * b + c - out));

                // HORNER_ACC constraint (inter-row): next_sel_horner * (local_out * next_b + next_c - next_a - next_out) = 0
                let next_sel_horner = preprocessed_next[prep_offset + 4];
                let next_b = next[main_offset + 1];
                let next_c = next[main_offset + 2];
                let next_a = next[main_offset];
                let next_out = next[main_offset + 3];
                builder.assert_zero(next_sel_horner * (out * next_b + next_c - next_a - next_out));
            }
        } else {
            // Extension field case (D > 1)
            let w = self
                .w_binomial
                .as_ref()
                .map(|w| AB::Expr::from(*w))
                .expect("AluAir with D>1 requires binomial parameter W");

            for lane in 0..self.lanes {
                let main_offset = lane * lane_width;
                let prep_offset = lane * preprocessed_lane_width;

                let a_slice = &local[main_offset..main_offset + D];
                let b_slice = &local[main_offset + D..main_offset + 2 * D];
                let c_slice = &local[main_offset + 2 * D..main_offset + 3 * D];
                let out_slice = &local[main_offset + 3 * D..main_offset + 4 * D];

                // Preprocessed layout: [mult_a, sel_add_vs_mul, sel_bool, sel_muladd, sel_horner, a_idx, b_idx, c_idx, out_idx, mult_b, mult_out, a_is_reader, c_is_reader]
                let mult_a = preprocessed_local[prep_offset];
                let sel_add_vs_mul = preprocessed_local[prep_offset + 1];
                let sel_bool = preprocessed_local[prep_offset + 2];
                let sel_muladd = preprocessed_local[prep_offset + 3];
                let sel_horner = preprocessed_local[prep_offset + 4];

                // active = -mult_a: 1 for active rows, 0 for padding
                let active = AB::Expr::ZERO - mult_a;
                // sel_mul = active - sel_bool - sel_muladd - sel_horner - sel_add_vs_mul
                let sel_mul = active - sel_bool - sel_muladd - sel_horner - sel_add_vs_mul;

                // ADD constraints
                for i in 0..D {
                    builder.assert_zero(sel_add_vs_mul * (a_slice[i] + b_slice[i] - out_slice[i]));
                }

                // MUL constraints: extension field multiplication
                let mut mul_acc = vec![AB::Expr::ZERO; D];
                for i in 0..D {
                    for j in 0..D {
                        let term = a_slice[i] * b_slice[j];
                        let k = i + j;
                        if k < D {
                            mul_acc[k] = mul_acc[k].clone() + term;
                        } else {
                            mul_acc[k - D] = mul_acc[k - D].clone() + w.clone() * term;
                        }
                    }
                }
                for i in 0..D {
                    builder.assert_zero(sel_mul.clone() * (mul_acc[i].clone() - out_slice[i]));
                }

                // BOOL_CHECK constraint: a's lowest coefficient must be boolean
                // and all higher extension coefficients must be zero.
                let one = AB::Expr::ONE;
                builder.assert_zero(sel_bool * a_slice[0] * (a_slice[0] - one));
                for i in 1..D {
                    builder.assert_zero(sel_bool * a_slice[i]);
                }

                // MUL_ADD constraints: a * b + c = out (extension field), reuse mul_acc
                let mut muladd_acc = mul_acc.clone();
                for i in 0..D {
                    muladd_acc[i] = muladd_acc[i].clone() + c_slice[i];
                }
                for i in 0..D {
                    builder.assert_zero(sel_muladd * (muladd_acc[i].clone() - out_slice[i]));
                }

                // HORNER_ACC constraint (inter-row, extension field):
                // next_out = local_out * next_b + next_c - next_a
                let next_sel_horner = preprocessed_next[prep_offset + 4];
                let next_a_slice = &next[main_offset..main_offset + D];
                let next_b_slice = &next[main_offset + D..main_offset + 2 * D];
                let next_c_slice = &next[main_offset + 2 * D..main_offset + 3 * D];
                let next_out_slice = &next[main_offset + 3 * D..main_offset + 4 * D];

                // Compute local_out * next_b as extension field product
                let mut horner_mul = vec![AB::Expr::ZERO; D];
                for i in 0..D {
                    for j in 0..D {
                        let term = out_slice[i] * next_b_slice[j];
                        let k = i + j;
                        if k < D {
                            horner_mul[k] = horner_mul[k].clone() + term;
                        } else {
                            horner_mul[k - D] = horner_mul[k - D].clone() + w.clone() * term;
                        }
                    }
                }
                // horner_result = local_out * next_b + next_c - next_a
                for i in 0..D {
                    builder.assert_zero(
                        next_sel_horner
                            * (horner_mul[i].clone() + next_c_slice[i]
                                - next_a_slice[i]
                                - next_out_slice[i]),
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
        lookups
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use p3_circuit::WitnessId;
    use p3_matrix::Matrix;
    use p3_test_utils::baby_bear_params::{
        BabyBear as Val, BinomialExtensionField, PrimeCharacteristicRing,
    };
    use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
    use p3_util::log2_ceil_usize;

    use super::*;
    use crate::air::test_utils::build_test_config;

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

        let preprocessed_values = AluAir::<Val, 1>::trace_to_preprocessed(&trace);
        let air = AluAir::<Val, 1>::new_with_preprocessed(n, 1, preprocessed_values);
        let matrix: RowMajorMatrix<Val> = air.trace_to_matrix(&trace);
        assert_eq!(matrix.width(), 4);

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

        let preprocessed_values = AluAir::<Val, 1>::trace_to_preprocessed(&trace);
        let air = AluAir::<Val, 1>::new_with_preprocessed(n, 1, preprocessed_values);
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

        let preprocessed_values = AluAir::<Val, 1>::trace_to_preprocessed(&trace);
        let air = AluAir::<Val, 1>::new_with_preprocessed(n, 1, preprocessed_values);
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

        let preprocessed_values = AluAir::<Val, 1>::trace_to_preprocessed(&trace);
        let air = AluAir::<Val, 1>::new_with_preprocessed(n, 1, preprocessed_values);
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

        let preprocessed_values = AluAir::<Val, 1>::trace_to_preprocessed(&trace);
        let air = AluAir::<Val, 1>::new_with_preprocessed(2, 1, preprocessed_values);
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

        let preprocessed_values = AluAir::<Val, 4>::trace_to_preprocessed(&trace);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        // Get w from the extension field
        let w = Val::from_u64(11); // BabyBear's binomial extension uses w=11

        let air = AluAir::<Val, 4>::new_binomial_with_preprocessed(n, 1, w, preprocessed_values);
        let matrix: RowMajorMatrix<Val> = air.trace_to_matrix(&trace);
        assert_eq!(matrix.width(), AluAir::<Val, 4>::lane_width());
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

        let preprocessed_values = AluAir::<Val, 4>::trace_to_preprocessed(&trace);
        let air = AluAir::<Val, 4>::new_binomial_with_preprocessed(n, 1, w, preprocessed_values);
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

        let preprocessed_values = AluAir::<Val, 4>::trace_to_preprocessed(&trace);
        let air = AluAir::<Val, 4>::new_binomial_with_preprocessed(n, 1, w, preprocessed_values);
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
        let air = AluAir::<Val, 1>::new_with_preprocessed(8, 2, preprocessed);
        p3_test_utils::assert_air_constraint_degree!(air, "AluAir");
    }
}
