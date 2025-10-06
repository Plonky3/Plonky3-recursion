//! [`AddAir`] deals with addition and subtraction. In the case of subtraction, `a - b = c` is written in the table as `b + c = a`. \
//! The chip handles both base field and extension field operations, as it is parametrized by the extension degree `D`.
//! The runtime parameter `lanes` also controls the number of operations carried out in a row.
//!
//! # Columns
//!
//! The AIR has `3 * D + 3` columns for each operation:
//!
//! - `D` columns for the left operand,
//! - 1 column for `index_left`: the index of the left operand in the witness bus,
//! - `D` columns for the right operand,
//! - 1 column for `index_right`: the index of the right operand in the witness bus,
//! - `D` columns for the output,
//! - 1 column for `index_output`:  the index of the output in the witness bus.
//!
//! # Constraints
//!
//! - for each triple `(left, right, output)`: `left[i] + right[i] - output[i]`, for `i` in `0..D`.
//!
//! # Global Interactions
//!
//! There are three interactions per operation with the witness bus:
//! - send `(index_left, left)`
//! - send `(index_right, right)`
//! - send `(index_output, output)`

#![allow(clippy::needless_range_loop)]
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_circuit::tables::AddTrace;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

use super::utils::pad_to_power_of_two;

/// AIR for proving addition operations: lhs + rhs = result.
/// Generic over extension degree `D` (component-wise addition) and a runtime lane count
/// that controls how many additions are packed side-by-side in a single row.
#[derive(Debug, Clone)]
pub struct AddAir<F, const D: usize = 1> {
    /// Number of logical addition operations in the trace.
    pub num_ops: usize,
    /// Number of lanes (operations) packed per row.
    pub lanes: usize,
    _phantom: core::marker::PhantomData<F>,
}

impl<F: Field + PrimeCharacteristicRing, const D: usize> AddAir<F, D> {
    /// Number of base-field columns contributed by a single lane.
    pub const LANE_WIDTH: usize = 3 * D + 3;

    pub const fn new(num_ops: usize, lanes: usize) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");
        Self {
            num_ops,
            lanes,
            _phantom: core::marker::PhantomData,
        }
    }

    pub const fn lane_width() -> usize {
        Self::LANE_WIDTH
    }

    pub fn total_width(&self) -> usize {
        self.lanes * Self::lane_width()
    }

    /// Convert `AddTrace` to a row-major matrix, packing `lanes` additions per row.
    /// Resulting layout per row:
    /// `[lhs[D], lhs_idx, rhs[D], rhs_idx, result[D], result_idx]` repeated `lanes` times.
    pub fn trace_to_matrix<ExtF: BasedVectorSpace<F>>(
        trace: &AddTrace<ExtF>,
        lanes: usize,
    ) -> RowMajorMatrix<F> {
        assert!(lanes > 0, "lane count must be non-zero");

        let lane_width = Self::lane_width();
        let width = lane_width * lanes;
        let op_count = trace.lhs_values.len();
        let row_count = op_count.div_ceil(lanes);

        let mut values = Vec::with_capacity(width * row_count.max(1));

        for row in 0..row_count {
            for lane in 0..lanes {
                let op_idx = row * lanes + lane;
                if op_idx < op_count {
                    // LHS limbs + index
                    let lhs_coeffs = trace.lhs_values[op_idx].as_basis_coefficients_slice();
                    assert_eq!(
                        lhs_coeffs.len(),
                        D,
                        "Extension field degree mismatch for lhs",
                    );
                    values.extend_from_slice(lhs_coeffs);
                    values.push(F::from_u64(trace.lhs_index[op_idx].0 as u64));

                    // RHS limbs + index
                    let rhs_coeffs = trace.rhs_values[op_idx].as_basis_coefficients_slice();
                    assert_eq!(
                        rhs_coeffs.len(),
                        D,
                        "Extension field degree mismatch for rhs",
                    );
                    values.extend_from_slice(rhs_coeffs);
                    values.push(F::from_u64(trace.rhs_index[op_idx].0 as u64));

                    // Result limbs + index
                    let result_coeffs = trace.result_values[op_idx].as_basis_coefficients_slice();
                    assert_eq!(
                        result_coeffs.len(),
                        D,
                        "Extension field degree mismatch for result",
                    );
                    values.extend_from_slice(result_coeffs);
                    values.push(F::from_u64(trace.result_index[op_idx].0 as u64));
                } else {
                    // Filler lane: append zeros for unused slot to keep the row width uniform.
                    values.resize(values.len() + lane_width, F::ZERO);
                }
            }
        }

        pad_to_power_of_two(&mut values, width, row_count);

        RowMajorMatrix::new(values, width)
    }
}

impl<F: Field, const D: usize> BaseAir<F> for AddAir<F, D> {
    fn width(&self) -> usize {
        self.total_width()
    }
}

impl<AB: AirBuilder, const D: usize> Air<AB> for AddAir<AB::F, D>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        debug_assert_eq!(main.width(), self.total_width(), "column width mismatch");

        let local = main.row_slice(0).expect("matrix must be non-empty");
        let local = &*local;
        let lane_width = Self::lane_width();

        for lane in 0..self.lanes {
            let mut cursor = lane * lane_width;
            let lhs_slice = &local[cursor..cursor + D];
            cursor += D + 1; // Skip lhs index
            let rhs_slice = &local[cursor..cursor + D];
            cursor += D + 1; // Skip rhs index
            let result_slice = &local[cursor..cursor + D];

            for i in 0..D {
                builder.assert_zero(
                    lhs_slice[i].clone() + rhs_slice[i].clone() - result_slice[i].clone(),
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear as Val;
    use p3_circuit::WitnessId;
    use p3_circuit::tables::AddTrace;
    use p3_field::BasedVectorSpace;
    use p3_field::extension::BinomialExtensionField;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_uni_stark::{prove, verify};

    use super::*;
    use crate::air::test_utils::build_test_config;

    #[test]
    fn prove_verify_add_base_field() {
        let n = 8;
        let lhs_values = vec![Val::from_u64(3); n];
        let rhs_values = vec![Val::from_u64(5); n];
        let result_values = vec![Val::from_u64(8); n];
        let lhs_index = vec![WitnessId(1); n];
        let rhs_index = vec![WitnessId(2); n];
        let result_index = vec![WitnessId(3); n];

        let trace = AddTrace {
            lhs_values,
            lhs_index,
            rhs_values,
            rhs_index,
            result_values,
            result_index,
        };

        let matrix: RowMajorMatrix<Val> = AddAir::<Val, 1>::trace_to_matrix(&trace, 1);
        assert_eq!(matrix.width(), 6);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        let air = AddAir::<Val, 1>::new(n, 1);
        let proof = prove(&config, &air, matrix, &pis);
        verify(&config, &air, &proof, &pis).expect("verification failed");
    }

    #[test]
    fn prove_verify_add_extension_field_d4() {
        type ExtField = BinomialExtensionField<Val, 4>;
        let n = 4;

        // Build genuine degree-4 elements via explicit coefficients with ALL non-zero values:
        // a = a0 + a1 x + a2 x^2 + a3 x^3
        let lhs = ExtField::from_basis_coefficients_slice(&[
            Val::from_u64(7), // a0
            Val::from_u64(3), // a1
            Val::from_u64(4), // a2
            Val::from_u64(5), // a3
        ])
        .unwrap();

        let rhs = ExtField::from_basis_coefficients_slice(&[
            Val::from_u64(11), // b0
            Val::from_u64(2),  // b1
            Val::from_u64(9),  // b2
            Val::from_u64(6),  // b3
        ])
        .unwrap();

        let result = lhs + rhs;

        // Sanity: basis length is D
        assert_eq!(
            <ExtField as BasedVectorSpace<Val>>::as_basis_coefficients_slice(&lhs).len(),
            4
        );

        let lhs_values = vec![lhs; n];
        let rhs_values = vec![rhs; n];
        let result_values = vec![result; n];
        let lhs_index = vec![WitnessId(1); n];
        let rhs_index = vec![WitnessId(2); n];
        let result_index = vec![WitnessId(3); n];

        let trace = AddTrace {
            lhs_values,
            lhs_index,
            rhs_values,
            rhs_index,
            result_values,
            result_index,
        };

        let matrix: RowMajorMatrix<Val> = AddAir::<Val, 4>::trace_to_matrix(&trace, 1);
        assert_eq!(matrix.height(), n);
        assert_eq!(matrix.width(), AddAir::<Val, 4>::lane_width());

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        let air = AddAir::<Val, 4>::new(n, 1);
        let proof = prove(&config, &air, matrix, &pis);
        verify(&config, &air, &proof, &pis).expect("extension field verification failed");
    }

    #[test]
    fn trace_to_matrix_packs_multiple_lanes() {
        let n = 3;
        let lanes = 2;
        let lhs_values = vec![Val::from_u64(1); n];
        let rhs_values = vec![Val::from_u64(2); n];
        let result_values = vec![Val::from_u64(3); n];
        let lhs_index = vec![WitnessId(10); n];
        let rhs_index = vec![WitnessId(20); n];
        let result_index = vec![WitnessId(30); n];

        let trace = AddTrace {
            lhs_values,
            lhs_index,
            rhs_values,
            rhs_index,
            result_values,
            result_index,
        };

        let matrix: RowMajorMatrix<Val> = AddAir::<Val, 1>::trace_to_matrix(&trace, lanes);
        assert_eq!(matrix.width(), AddAir::<Val, 1>::lane_width() * lanes);
        assert_eq!(matrix.height(), 2);
    }
}
