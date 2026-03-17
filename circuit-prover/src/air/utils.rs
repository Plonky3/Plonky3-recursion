use alloc::vec::Vec;
use core::iter;

use itertools::Itertools;
use p3_air::{Air, AirBuilder, AirLayout, PermutationAirBuilder};
use p3_field::Field;
use p3_lookup::lookup_traits::{Direction, Lookup, LookupInput};
use p3_lookup::{AirWithLookups, LookupAir, LookupEvaluator};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{SymbolicAirBuilder, SymbolicExpression, SymbolicVariable};

use super::alu_air::{
    PREP_A_IDX, PREP_A_IS_READER, PREP_C_IS_READER, PREP_MULT_A, PREP_MULT_B, PREP_MULT_OUT,
};

pub fn get_index_lookups<F: Field, const D: usize>(
    main_start: usize,
    preprocessed_start: usize,
    num_lookups: usize,
    main: &[SymbolicVariable<F>],
    preprocessed: &[SymbolicVariable<F>],
    direction: Direction,
) -> Vec<LookupInput<F>> {
    (0..num_lookups)
        .map(|i| {
            let idx = SymbolicExpression::from(preprocessed[1 + preprocessed_start + i]);

            let multiplicity = SymbolicExpression::from(preprocessed[preprocessed_start]);

            let values = (0..D).map(|j| SymbolicExpression::from(main[main_start + i * D + j]));
            let inps = iter::once(idx).chain(values).collect::<Vec<_>>();

            (inps, multiplicity, direction)
        })
        .collect()
}

/// Get ALU lookups for the 4 operands (a, b, c, out).
///
/// Uses the `PREP_*` constants from [`super::alu_air`] for column offsets.
pub fn get_alu_index_lookups<F: Field, const D: usize>(
    main_start: usize,
    preprocessed_start: usize,
    main: &[SymbolicVariable<F>],
    preprocessed: &[SymbolicVariable<F>],
) -> Vec<LookupInput<F>> {
    let mult_a = SymbolicExpression::from(preprocessed[preprocessed_start + PREP_MULT_A]);
    let mult_b = SymbolicExpression::from(preprocessed[preprocessed_start + PREP_MULT_B]);
    let mult_out = SymbolicExpression::from(preprocessed[preprocessed_start + PREP_MULT_OUT]);
    let a_is_reader = SymbolicExpression::from(preprocessed[preprocessed_start + PREP_A_IS_READER]);
    let c_is_reader = SymbolicExpression::from(preprocessed[preprocessed_start + PREP_C_IS_READER]);

    let eff_mult_a = mult_a.clone() * a_is_reader;
    let eff_mult_c = mult_a * c_is_reader;

    let multiplicities = [eff_mult_a, mult_b, eff_mult_c, mult_out];

    (0..4)
        .map(|i| {
            let idx = SymbolicExpression::from(preprocessed[preprocessed_start + PREP_A_IDX + i]);

            let values = (0..D).map(|j| SymbolicExpression::from(main[main_start + i * D + j]));
            let inps = iter::once(idx).chain(values).collect::<Vec<_>>();

            (inps, multiplicities[i].clone(), Direction::Receive)
        })
        .collect()
}

/// Helper to create a preprocessed trace from complete preprocessed values (already including
/// multiplicities). Simply reshapes the flat per-op data into a row-major matrix.
pub fn create_direct_preprocessed_trace<F: Field>(
    preprocessed_values: &[F],
    preprocessed_lane_width: usize,
    num_lanes: usize,
    min_height: usize,
) -> RowMajorMatrix<F> {
    let preprocessed_width = num_lanes * preprocessed_lane_width;

    let mut values = preprocessed_values.to_vec();

    // Pad to a multiple of the full row width
    if preprocessed_width > 0 && !values.len().is_multiple_of(preprocessed_width) {
        let padding = preprocessed_width - (values.len() % preprocessed_width);
        values.extend(core::iter::repeat_n(F::ZERO, padding));
    }

    // Ensure at least one row
    if values.is_empty() {
        values.extend(core::iter::repeat_n(F::ZERO, preprocessed_width.max(1)));
    }

    let mat = RowMajorMatrix::new(values, preprocessed_width);
    pad_matrix_with_min_height(mat, min_height)
}

/// Like [`create_direct_preprocessed_trace`], but allocates the *final* width
/// directly by appending a fixed number of zero columns to every row.
///
/// This is useful when an AIR wants its preprocessed trace to have extra
/// global columns (e.g. selectors) that are always zero in the unscheduled
/// case: we can avoid building a narrow matrix and widening it row-by-row.
pub fn create_direct_preprocessed_trace_with_extra<F: Field>(
    preprocessed_values: &[F],
    preprocessed_lane_width: usize,
    extra_cols_per_row: usize,
    num_lanes: usize,
    min_height: usize,
) -> RowMajorMatrix<F> {
    let base_width = num_lanes * preprocessed_lane_width;

    let mut values = preprocessed_values.to_vec();

    // Pad to a multiple of the *base* row width.
    if base_width > 0 && !values.len().is_multiple_of(base_width) {
        let padding = base_width - (values.len() % base_width);
        values.extend(core::iter::repeat_n(F::ZERO, padding));
    }

    // Ensure at least one base row.
    if values.is_empty() {
        values.extend(core::iter::repeat_n(F::ZERO, base_width.max(1)));
    }

    let num_rows = values.len() / base_width;
    let target_width = base_width + extra_cols_per_row;

    // Build the widened matrix in one pass: copy each base row into the
    // prefix of the widened row and leave the extra columns zero.
    let mut widened = RowMajorMatrix::new(F::zero_vec(num_rows * target_width), target_width);
    for r in 0..num_rows {
        let src_start = r * base_width;
        let dst_start = r * target_width;
        widened.values[dst_start..dst_start + base_width]
            .copy_from_slice(&values[src_start..src_start + base_width]);
        // trailing extra_cols_per_row entries stay zero
    }

    pad_matrix_with_min_height(widened, min_height)
}

/// Object‑safe gadget shim.
pub trait LookupEvaluatorDyn<AB: PermutationAirBuilder> {
    fn num_aux_cols(&self) -> usize;
    fn num_challenges(&self) -> usize;
    fn eval_with_lookups_dyn(&self, builder: &mut AB, contexts: &[Lookup<AB::F>]);
}

/// Blanket: any concrete `LookupEvaluator` becomes object‑safe.
impl<AB, LE> LookupEvaluatorDyn<AB> for LE
where
    AB: PermutationAirBuilder,
    LE: LookupEvaluator,
{
    fn num_aux_cols(&self) -> usize {
        LE::num_aux_cols(self)
    }
    fn num_challenges(&self) -> usize {
        LE::num_challenges(self)
    }
    fn eval_with_lookups_dyn(&self, builder: &mut AB, contexts: &[Lookup<AB::F>]) {
        // forward to the generic method on the concrete handler
        LE::eval_lookups(self, builder, contexts);
    }
}

/// Object‑safe AIR shim.
pub trait AirDyn<AB>
where
    AB: PermutationAirBuilder,
{
    fn add_lookup_columns_dyn(&mut self) -> Vec<usize>;
    fn get_lookups_dyn(&mut self) -> Vec<Lookup<AB::F>>;
    fn eval_with_lookups_dyn<LE: LookupEvaluator>(
        &self,
        builder: &mut AB,
        contexts: &[Lookup<AB::F>],
        lookup_evaluator: &LE,
    );
}

/// Blanket: any existing `Air` now satisfies the object‑safe shim.
impl<AB, T> AirDyn<AB> for T
where
    AB: PermutationAirBuilder,
    T: Air<AB> + LookupAir<AB::F>,
{
    fn add_lookup_columns_dyn(&mut self) -> Vec<usize> {
        self.add_lookup_columns()
    }

    fn get_lookups_dyn(&mut self) -> Vec<Lookup<AB::F>> {
        self.get_lookups()
    }

    fn eval_with_lookups_dyn<LE: LookupEvaluator>(
        &self,
        builder: &mut AB,
        contexts: &[Lookup<AB::F>],
        lookup_evaluator: &LE,
    ) {
        T::eval_with_lookups(self, builder, contexts, lookup_evaluator);
    }
}

/// Helper to create symbolic air builder and extract symbolic variables for lookup generation.
///
/// Returns `(symbolic_main_local, preprocessed_local)` slices for use in lookup generation.
pub fn create_symbolic_variables<F: Field>(
    preprocessed_width: usize,
    main_width: usize,
    num_public_values: usize,
    num_permutation_cols: usize,
) -> (Vec<SymbolicVariable<F>>, Vec<SymbolicVariable<F>>) {
    let layout = AirLayout {
        preprocessed_width,
        main_width,
        num_public_values,
        permutation_width: num_permutation_cols,
        num_permutation_challenges: 0,
        num_permutation_values: 0,
        num_periodic_columns: 0,
    };
    let symbolic_air_builder = SymbolicAirBuilder::<F>::new(layout);

    let symbolic_main = symbolic_air_builder.main();
    let symbolic_main_local = symbolic_main.row_slice(0).unwrap().to_vec();

    let preprocessed = symbolic_air_builder.preprocessed().clone();
    let preprocessed_local = preprocessed
        .row_slice(0)
        .expect("The preprocessed matrix has only one row?")
        .to_vec();

    (symbolic_main_local, preprocessed_local)
}

/// Helper to pad a matrix to power-of-two height and then to min_height if needed.
pub fn pad_matrix_with_min_height<F: Field>(
    mut mat: RowMajorMatrix<F>,
    min_height: usize,
) -> RowMajorMatrix<F> {
    mat.pad_to_power_of_two_height(F::ZERO);

    let min_rows = min_height.next_power_of_two();
    if mat.height() < min_rows {
        let width = mat.width();
        let padding_rows = min_rows - mat.height();
        mat.values
            .extend(core::iter::repeat_n(F::ZERO, padding_rows * width));
    }

    mat
}

/// Helper to create preprocessed trace with multiplicity insertion and padding.
///
/// Takes preprocessed values (one per op, without multiplicities) and inserts multiplicities
/// at the start of each lane, then pads to power-of-two and min_height.
/// This version assumes each op has exactly one preprocessed value (like PublicAir).
pub fn create_preprocessed_trace_with_multiplicity<F: Field>(
    preprocessed_values: &[F],
    preprocessed_lane_width: usize,
    num_lanes: usize,
    min_height: usize,
    get_multiplicity: impl Fn(usize) -> F,
) -> RowMajorMatrix<F> {
    let num_ops = preprocessed_values.len();
    let num_rows = num_ops.div_ceil(num_lanes);
    let row_width = num_lanes * preprocessed_lane_width;

    let mut values = Vec::with_capacity(num_rows * row_width);
    for row_idx in 0..num_rows {
        for lane in 0..num_lanes {
            let op_idx = row_idx * num_lanes + lane;
            if op_idx < num_ops {
                values.push(get_multiplicity(op_idx));
                values.push(preprocessed_values[op_idx]);
                // Add remaining columns if preprocessed_lane_width > 2
                if preprocessed_lane_width > 2 {
                    values.extend(core::iter::repeat_n(F::ZERO, preprocessed_lane_width - 2));
                }
            } else {
                values.extend(core::iter::repeat_n(F::ZERO, preprocessed_lane_width));
            }
        }
    }

    let mat = RowMajorMatrix::new(values, row_width);
    pad_matrix_with_min_height(mat, min_height)
}

/// Helper to create preprocessed trace for single-row-per-op AIRs (like ConstAir).
///
/// Inserts multiplicity before each preprocessed value, then pads.
pub fn create_simple_preprocessed_trace<F: Field>(
    preprocessed_values: &[F],
    preprocessed_width: usize,
    min_height: usize,
) -> RowMajorMatrix<F> {
    let preprocessed_with_multiplicity: Vec<F> = preprocessed_values
        .iter()
        .flat_map(|v| [F::ONE, *v])
        .collect();

    let mat = RowMajorMatrix::new(preprocessed_with_multiplicity, preprocessed_width);
    pad_matrix_with_min_height(mat, min_height)
}

/// Helper to create preprocessed trace for AIRs with chunked preprocessed values (like AluAir).
///
/// Takes preprocessed values grouped in chunks of (preprocessed_lane_width - 1) per op,
/// inserts multiplicity at the start of each chunk, then pads.
pub fn create_chunked_preprocessed_trace<F: Field>(
    preprocessed_values: &[F],
    preprocessed_lane_width: usize,
    num_lanes: usize,
    min_height: usize,
) -> RowMajorMatrix<F> {
    // Add multiplicity to preprocessed values
    let mut preprocessed_with_multiplicity: Vec<F> = preprocessed_values
        .iter()
        .chunks(preprocessed_lane_width - 1)
        .into_iter()
        .flat_map(|chunk| iter::once(F::ONE).chain(chunk.into_iter().cloned()))
        .collect();

    debug_assert!(
        preprocessed_with_multiplicity
            .len()
            .is_multiple_of(preprocessed_lane_width),
        "Preprocessed trace length mismatch"
    );

    let preprocessed_width = num_lanes * preprocessed_lane_width;
    let padding_len =
        preprocessed_width - preprocessed_with_multiplicity.len() % preprocessed_width;
    if padding_len != preprocessed_width {
        preprocessed_with_multiplicity.extend(core::iter::repeat_n(F::ZERO, padding_len));
    }

    let mat = RowMajorMatrix::new(preprocessed_with_multiplicity, preprocessed_width);
    pad_matrix_with_min_height(mat, min_height)
}
