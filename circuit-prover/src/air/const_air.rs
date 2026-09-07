//! [`ConstAir`] stores constants either in the base field or the extension field (of extension degree `D`).
//!
//! # Column layout
//!
//! The AIR is generic over an extension degree `D`.
//!
//! Main trace (per row): `D` columns for the constant's value (basis coefficients).
//!
//! Preprocessed (per row): `2 + D` base-field columns — multiplicity, the witness-bus index,
//! then the constant's own value (the same `D` basis coefficients as the main row). Both
//! prover and verifier know these values in advance, so the value is part of the circuit's
//! committed preprocessing rather than a free per-proof witness.
//!
//! # Constraints
//!
//! For each of the `D` value coordinates, the main-trace value equals the preprocessed
//! (fixed, committed) value: this is what makes the constant's value binding rather than
//! merely advisory.
//!
//! # Global Interactions
//!
//! One interaction with the global witness bus (WitnessChecks):
//!
//! - send `(index, value[0..D])` with multiplicity `ext_mult`

use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_circuit::tables::ConstTrace;
use p3_field::{BasedVectorSpace, Field};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use tracing::instrument;

use crate::air::column_layout::{WITNESS_LOOKUP_PREP_COL_MAP, WITNESS_LOOKUP_PREP_LANE_WIDTH};
use crate::air::public_air::WitnessSendAir;

/// ConstAir: vector-valued constant binding with generic extension degree D.
///
/// Each row binds one compile-time-fixed constant: its value is preprocessed (committed)
/// rather than a free per-proof witness, so two circuits differing only in a constant's value
/// commit to different preprocessed data.
///
/// It wraps [`WitnessSendAir`] for its `num_ops` / `preprocessed` / `min_height` storage
/// (single-lane), but defines its own `BaseAir`/`Air` behavior — its preprocessed layout and
/// constraints differ from the shared witness-lookup layout `PublicAir` uses.
///
/// Layout per row:
/// - Main: `[value[0..D)]`, width = D
/// - Preprocessed: `[multiplicity, index, value[0..D)]`, width = 2 + D
#[derive(Debug, Clone)]
pub struct ConstAir<F, const D: usize = 1>(WitnessSendAir<F, D>);

impl<F: Field, const D: usize> ConstAir<F, D> {
    /// Construct a new `ConstAir` instance.
    ///
    /// - `height`: The number of constant values to be exposed.
    pub const fn new(height: usize) -> Self {
        Self(WitnessSendAir::new(height, 1))
    }

    pub const fn new_with_preprocessed(height: usize, preprocessed: Vec<F>) -> Self {
        Self(WitnessSendAir::new_with_preprocessed(
            height,
            1,
            preprocessed,
        ))
    }

    /// Set the minimum trace height for FRI compatibility.
    ///
    /// FRI requires: `log_trace_height > log_final_poly_len + log_blowup`
    /// So `min_height` should be >= `2^(log_final_poly_len + log_blowup + 1)`.
    pub const fn with_min_height(mut self, min_height: usize) -> Self {
        self.0.min_height = min_height;
        self
    }

    /// Number of preprocessed columns: multiplicity + index + the constant's D value coefficients.
    pub const fn preprocessed_width() -> usize {
        WITNESS_LOOKUP_PREP_LANE_WIDTH + D
    }
    /// Convert a `ConstTrace` into a `RowMajorMatrix` suitable for the STARK prover.
    ///
    /// This function is responsible for:
    ///
    /// 1. Decomposing each extension element in the trace into `D` basis coordinates.
    /// 2. Padding the trace to have a power-of-two number of rows.
    #[inline]
    #[instrument(skip_all, name = "ConstAir::build_trace")]
    pub fn trace_to_matrix<ExtF: BasedVectorSpace<F>>(
        trace: &ConstTrace<ExtF>,
        min_height: usize,
    ) -> RowMajorMatrix<F> {
        let height = trace.values.len();
        assert_eq!(
            height,
            trace.index.len(),
            "ConstTrace column length mismatch: values vs indices"
        );
        let width = D;

        let mut values = Vec::with_capacity(height * width);

        // Iterate over values and indices, populating the flat vector.
        for i in 0..height {
            // Extract basis coefficients.
            let coeffs = trace.values[i].as_basis_coefficients_slice();
            debug_assert_eq!(
                coeffs.len(),
                D,
                "extension degree mismatch for ConstTrace value"
            );
            // Copy coefficients into the first D columns.
            values.extend_from_slice(coeffs);
        }

        // Pad to power of two by repeating last row
        let mut mat = RowMajorMatrix::new(values, width);
        mat.pad_to_min_power_of_two_height(
            core::cmp::max(min_height, mat.height().next_power_of_two()),
            F::ZERO,
        );

        mat
    }
}

impl<F: Field, const D: usize> BaseAir<F> for ConstAir<F, D> {
    fn width(&self) -> usize {
        self.0.width()
    }

    fn preprocessed_width(&self) -> usize {
        WITNESS_LOOKUP_PREP_LANE_WIDTH + D
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let width = WITNESS_LOOKUP_PREP_LANE_WIDTH + D;
        let mut mat =
            RowMajorMatrix::from_flat_padded(self.0.preprocessed.to_vec(), width, F::ZERO);
        mat.pad_to_min_power_of_two_height(self.0.min_height, F::ZERO);
        Some(mat)
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        self.0.main_next_row_columns()
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        self.0.preprocessed_next_row_columns()
    }
}

impl<AB: AirBuilder + InteractionBuilder, const D: usize> Air<AB> for ConstAir<AB::F, D>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let main_local = main.current_slice();
        let prep = builder.preprocessed().clone();
        let prep_local = prep.current_slice();

        let multiplicity: AB::Expr = prep_local[WITNESS_LOOKUP_PREP_COL_MAP.multiplicity].into();
        let witness_idx: AB::Expr = prep_local[WITNESS_LOOKUP_PREP_COL_MAP.witness_idx].into();

        // Bind the free main-trace value to the fixed (preprocessed, committed) constant
        // value: a trace claiming a different value than the circuit's constant fails this
        // constraint, regardless of what the preprocessed commitment would otherwise allow.
        let mut fields: Vec<AB::Expr> = Vec::with_capacity(1 + D);
        fields.push(witness_idx);
        for j in 0..D {
            let main_val: AB::Expr = main_local[j].into();
            let prep_val: AB::Expr = prep_local[WITNESS_LOOKUP_PREP_LANE_WIDTH + j].into();
            builder.assert_eq(main_val.clone(), prep_val);
            fields.push(main_val);
        }

        builder.push_interaction("WitnessChecks", fields, Count::bounded(multiplicity, 1));
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_circuit::WitnessId;
    use p3_matrix::Matrix;
    use p3_test_utils::baby_bear_params::{
        BabyBear as F, BinomialExtensionField, PrimeCharacteristicRing,
    };

    use super::*;

    type EF = BinomialExtensionField<F, 4>;

    #[test]
    fn test_const_air_base_field() {
        // Create a CONST trace with several constant values
        // Toy example used: assert(37 * x - 111 = 0)
        let const_values = vec![
            F::from_u64(37),  // CONST 1 37
            F::from_u64(111), // CONST 3 111
            F::from_u64(0),   // CONST 4 0
        ];
        // Witness IDs these constants bind to
        let const_indices = vec![WitnessId(1), WitnessId(3), WitnessId(4)];

        // Preprocessed rows are [ext_mult, index, value] (D=1): the value column binds the
        // main trace's free value to the constant's fixed value.
        let preprocessed_values = const_indices
            .iter()
            .zip(const_values.iter())
            .flat_map(|(idx, val)| [F::ONE, F::from_u64(idx.0 as u64), *val])
            .collect::<Vec<_>>();

        let trace = ConstTrace {
            index: const_indices.clone(),
            values: const_values.clone(),
        };

        // Convert to matrix using the ConstAir
        let matrix = ConstAir::<F, 1>::trace_to_matrix(&trace, 1);

        // Verify matrix dimensions
        assert_eq!(matrix.width(), 1);

        // Height should be next power of two >= 3
        let height = matrix.height();
        assert_eq!(height, 4);

        // Verify the data layout: [value] per row (no index in main trace)
        let data = &matrix.values;

        // First row: value=37
        assert_eq!(data[0], F::from_u64(37));

        // Second row: value=111
        assert_eq!(data[1], F::from_u64(111));

        // Third row: value=0
        assert_eq!(data[2], F::from_u64(0));

        let air = ConstAir::<F, 1>::new_with_preprocessed(height, preprocessed_values);

        let preprocessed_matrix = air.preprocessed_trace().unwrap();
        assert_eq!(preprocessed_matrix.height(), height);
        assert_eq!(preprocessed_matrix.width(), 3);

        // Assert the preprocessed values were properly created.
        // Layout: [ext_mult, index, value] (width=3 for D=1)
        const_indices
            .iter()
            .zip(const_values.iter())
            .enumerate()
            .for_each(|(i, (const_idx, val))| {
                let row = preprocessed_matrix.row_slice(i).unwrap();
                assert_eq!(row[0], F::ONE);
                assert_eq!(row[1], F::from_u32(const_idx.0));
                assert_eq!(row[2], *val);
            });
        // Check the padding row
        let last_row = preprocessed_matrix.row_slice(height - 1).unwrap();
        assert_eq!(last_row[0], F::ZERO);
        assert_eq!(last_row[1], F::ZERO);
        assert_eq!(last_row[2], F::ZERO);
    }

    #[test]
    fn test_const_air_extension_field() {
        // Create extension field constants with all non-zero coefficients
        let const1 = EF::from_basis_coefficients_slice(&[
            F::from_u64(1), // a0
            F::from_u64(2), // a1
            F::from_u64(3), // a2
            F::from_u64(4), // a3
        ])
        .unwrap();

        let const2 = EF::from_basis_coefficients_slice(&[
            F::from_u64(5), // b0
            F::from_u64(6), // b1
            F::from_u64(7), // b2
            F::from_u64(8), // b3
        ])
        .unwrap();

        let const_values = vec![const1, const2];
        let const_indices = vec![WitnessId(10), WitnessId(20)];
        // Preprocessed rows are [ext_mult, index, value[0..4)] (D=4, D-scaled indices).
        let preprocessed_values = const_indices
            .iter()
            .zip(const_values.iter())
            .flat_map(|(idx, val)| {
                let mut row = vec![F::ONE, F::from_u64(idx.0 as u64 * 4)];
                row.extend_from_slice(val.as_basis_coefficients_slice());
                row
            })
            .collect::<Vec<_>>();

        let trace = ConstTrace {
            index: const_indices,
            values: const_values.clone(),
        };

        // Convert to matrix for D=4 extension field
        let matrix: RowMajorMatrix<F> = ConstAir::<F, 4>::trace_to_matrix(&trace, 1);

        // Verify matrix dimensions: D = 4 (4 value coefficients)
        assert_eq!(matrix.width(), 4);
        let height = matrix.height();
        assert_eq!(height, 2);

        let data = &matrix.values;

        // First row: [a0, a1, a2, a3] = [1, 2, 3, 4]
        assert_eq!(data[0], F::from_u64(1));
        assert_eq!(data[1], F::from_u64(2));
        assert_eq!(data[2], F::from_u64(3));
        assert_eq!(data[3], F::from_u64(4));

        // Second row: [b0, b1, b2, b3] = [5, 6, 7, 8]
        assert_eq!(data[4], F::from_u64(5));
        assert_eq!(data[5], F::from_u64(6));
        assert_eq!(data[6], F::from_u64(7));
        assert_eq!(data[7], F::from_u64(8));

        let air = ConstAir::<F, 4>::new_with_preprocessed(height, preprocessed_values);
        let preprocessed_matrix = air.preprocessed_trace().unwrap();
        assert_eq!(preprocessed_matrix.width(), 6);
        // Layout: [ext_mult, index, value[0..4)] (width=6, D-scaled indices)
        let row0 = preprocessed_matrix.row_slice(0).unwrap();
        assert_eq!(row0[0], F::ONE); // ext_mult
        // D-scaled index: WitnessId(10) → 10 * 4 = 40
        assert_eq!(row0[1], F::from_u64(40));
        let coeffs0 = const_values[0].as_basis_coefficients_slice();
        assert_eq!(row0[2], coeffs0[0]);
        assert_eq!(row0[3], coeffs0[1]);
        assert_eq!(row0[4], coeffs0[2]);
        assert_eq!(row0[5], coeffs0[3]);
        let last_row = preprocessed_matrix.row_slice(height - 1).unwrap();
        assert_eq!(last_row[0], F::ONE); // ext_mult
        // D-scaled index: WitnessId(20) → 20 * 4 = 80
        assert_eq!(last_row[1], F::from_u64(80));
        let coeffs1 = const_values[1].as_basis_coefficients_slice();
        assert_eq!(last_row[2], coeffs1[0]);
        assert_eq!(last_row[3], coeffs1[1]);
        assert_eq!(last_row[4], coeffs1[2]);
        assert_eq!(last_row[5], coeffs1[3]);
    }

    #[test]
    fn test_air_constraint_degree() {
        // 8 ops * 3 columns per op ([ext_mult, index, value] for D=1)
        let air = ConstAir::<F, 1>::new_with_preprocessed(8, vec![F::ZERO; 24]);
        p3_test_utils::assert_air_constraint_degree!(air, "ConstAir");
    }
}
