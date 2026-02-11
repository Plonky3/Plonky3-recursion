use alloc::vec;
use alloc::vec::Vec;
use core::iter;

use itertools::Itertools;
use p3_air::lookup::LookupEvaluator;
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, PermutationAirBuilder};
use p3_field::Field;
use p3_lookup::lookup_traits::{Direction, Lookup, LookupData, LookupInput};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{SymbolicAirBuilder, SymbolicExpression, SymbolicVariable};

pub fn get_index_lookups<AB: PermutationAirBuilder + AirBuilderWithPublicValues, const D: usize>(
    main_start: usize,
    preprocessed_start: usize,
    num_lookups: usize,
    main: &[SymbolicVariable<<AB as AirBuilder>::F>],
    preprocessed: &[SymbolicVariable<<AB as AirBuilder>::F>],
    direction: Direction,
) -> Vec<LookupInput<AB::F>> {
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
/// ALU preprocessed layout per lane:
/// - 0: multiplicity
/// - 1-3: selectors (add_vs_mul, bool, muladd)
/// - 4-7: indices (a_idx, b_idx, c_idx, out_idx)
///
/// Main layout per lane: a[D], b[D], c[D], out[D]
pub fn get_alu_index_lookups<
    AB: PermutationAirBuilder + AirBuilderWithPublicValues,
    const D: usize,
>(
    main_start: usize,
    preprocessed_start: usize,
    main: &[SymbolicVariable<<AB as AirBuilder>::F>],
    preprocessed: &[SymbolicVariable<<AB as AirBuilder>::F>],
    direction: Direction,
) -> Vec<LookupInput<AB::F>> {
    let multiplicity = SymbolicExpression::from(preprocessed[preprocessed_start]);

    // Indices are at positions 4, 5, 6, 7 (after multiplicity + 3 selectors)
    let idx_offset = 4;

    (0..4)
        .map(|i| {
            let idx = SymbolicExpression::from(preprocessed[preprocessed_start + idx_offset + i]);

            let values = (0..D).map(|j| SymbolicExpression::from(main[main_start + i * D + j]));
            let inps = iter::once(idx).chain(values).collect::<Vec<_>>();

            (inps, multiplicity.clone(), direction)
        })
        .collect()
}

/// Object‑safe gadget shim.
pub trait LookupEvaluatorDyn<AB: PermutationAirBuilder + AirBuilderWithPublicValues> {
    fn num_aux_cols(&self) -> usize;
    fn num_challenges(&self) -> usize;
    fn eval_with_lookups_dyn(
        &self,
        builder: &mut AB,
        contexts: &[Lookup<AB::F>],
        lookup_data: &[LookupData<AB::ExprEF>],
    );
}

/// Blanket: any concrete `LookupEvaluator` becomes object‑safe.
impl<AB, LE> LookupEvaluatorDyn<AB> for LE
where
    AB: PermutationAirBuilder + AirBuilderWithPublicValues,
    LE: LookupEvaluator,
{
    fn num_aux_cols(&self) -> usize {
        LE::num_aux_cols(self)
    }
    fn num_challenges(&self) -> usize {
        LE::num_challenges(self)
    }
    fn eval_with_lookups_dyn(
        &self,
        builder: &mut AB,
        contexts: &[Lookup<AB::F>],
        lookup_data: &[LookupData<AB::ExprEF>],
    ) {
        // forward to the generic method on the concrete handler
        LE::eval_lookups(self, builder, contexts, lookup_data);
    }
}

/// Object‑safe AIR shim.
pub trait AirDyn<AB>
where
    AB: PermutationAirBuilder + AirBuilderWithPublicValues,
{
    fn add_lookup_columns_dyn(&mut self) -> Vec<usize>;
    fn get_lookups_dyn(&mut self) -> Vec<Lookup<AB::F>>;
    fn eval_with_lookups_dyn<LE: LookupEvaluator>(
        &self,
        builder: &mut AB,
        contexts: &[Lookup<AB::F>],
        lookup_data: &[LookupData<AB::ExprEF>],
        lookup_evaluator: &LE,
    );
}

/// Blanket: any existing `Air` now satisfies the object‑safe shim.
impl<AB, T> AirDyn<AB> for T
where
    AB: PermutationAirBuilder + AirBuilderWithPublicValues,
    T: Air<AB>,
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
        lookup_data: &[LookupData<AB::ExprEF>],
        lookup_evaluator: &LE,
    ) {
        Air::<AB>::eval_with_lookups(self, builder, contexts, lookup_data, lookup_evaluator);
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
    let symbolic_air_builder = SymbolicAirBuilder::<F>::new(
        preprocessed_width,
        main_width,
        0,
        num_public_values,
        num_permutation_cols,
    );

    let symbolic_main = symbolic_air_builder.main();
    let symbolic_main_local = symbolic_main.row_slice(0).unwrap().to_vec();

    let preprocessed = symbolic_air_builder
        .preprocessed()
        .expect("Expected preprocessed columns");
    let preprocessed_local = preprocessed.row_slice(0).unwrap().to_vec();

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
        preprocessed_with_multiplicity.extend(vec![F::ZERO; padding_len]);
    }

    let mat = RowMajorMatrix::new(preprocessed_with_multiplicity, preprocessed_width);
    pad_matrix_with_min_height(mat, min_height)
}
