#![allow(clippy::needless_range_loop)]
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_circuit::tables::SubTrace;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

use super::utils::pad_to_power_of_two;

/// AIR for proving subtraction operations: lhs - rhs = result
/// Generic over extension degree D (component-wise subtraction)
/// Layout: [lhs[0..D-1], lhs_index, rhs[0..D-1], rhs_index, result[0..D-1], result_index]
/// Width = 3*D + 3
#[derive(Debug, Clone)]
pub struct SubAir<F, const D: usize = 1> {
    /// Number of subtraction operations (height of the trace)
    pub num_ops: usize,
    _phantom: core::marker::PhantomData<F>,
}

impl<F: Field + PrimeCharacteristicRing, const D: usize> SubAir<F, D> {
    pub fn new(num_ops: usize) -> Self {
        Self {
            num_ops,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Convert SubTrace to RowMajorMatrix for proving with generic extension degree D
    /// Layout: [lhs[0..D-1], lhs_index, rhs[0..D-1], rhs_index, result[0..D-1], result_index]
    pub fn trace_to_matrix<ExtF: BasedVectorSpace<F>>(trace: &SubTrace<ExtF>) -> RowMajorMatrix<F> {
        let height = trace.lhs_values.len();
        let width = 3 * D + 3; // D coefficients each for lhs, rhs, result + 3 indices

        let mut values = Vec::with_capacity(height * width);

        for i in 0..height {
            // LHS
            let lhs_coeffs = trace.lhs_values[i].as_basis_coefficients_slice();
            assert_eq!(
                lhs_coeffs.len(),
                D,
                "Extension field degree mismatch for lhs"
            );
            values.extend_from_slice(lhs_coeffs);
            values.push(F::from_u64(trace.lhs_index[i] as u64));

            // RHS
            let rhs_coeffs = trace.rhs_values[i].as_basis_coefficients_slice();
            assert_eq!(
                rhs_coeffs.len(),
                D,
                "Extension field degree mismatch for rhs"
            );
            values.extend_from_slice(rhs_coeffs);
            values.push(F::from_u64(trace.rhs_index[i] as u64));

            // RESULT
            let result_coeffs = trace.result_values[i].as_basis_coefficients_slice();
            assert_eq!(
                result_coeffs.len(),
                D,
                "Extension field degree mismatch for result"
            );
            values.extend_from_slice(result_coeffs);
            values.push(F::from_u64(trace.result_index[i] as u64));
        }

        // Pad to power of two by repeating last row
        pad_to_power_of_two(&mut values, width, height);

        RowMajorMatrix::new(values, width)
    }
}

impl<F: Field, const D: usize> BaseAir<F> for SubAir<F, D> {
    fn width(&self) -> usize {
        3 * D + 3 // D coefficients each for lhs, rhs, result + 3 indices
    }
}

impl<AB: AirBuilder, const D: usize> Air<AB> for SubAir<AB::F, D>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        debug_assert_eq!(main.width(), 3 * D + 3, "column width mismatch");

        let local = main.row_slice(0).expect("matrix must be non-empty");

        // Offsets:
        // [0..D)           -> lhs coefficients
        // [D]              -> lhs_index
        // [D+1 .. 2D+1)    -> rhs coefficients
        // [2D+1]           -> rhs_index
        // [2D+2 .. 3D+2)   -> result coefficients
        // [3D+2]           -> result_index
        let lhs = &local[0..D];
        let _lhs_idx = local[D].clone();
        let rhs = &local[D + 1..2 * D + 1];
        let _rhs_idx = local[2 * D + 1].clone();
        let out = &local[2 * D + 2..3 * D + 2];
        let _out_idx = local[3 * D + 2].clone();

        // Component-wise: lhs[i] - rhs[i] = out[i]
        for i in 0..D {
            builder.assert_zero(lhs[i].clone() - rhs[i].clone() - out[i].clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear as Val;
    use p3_circuit::tables::SubTrace;
    use p3_field::BasedVectorSpace;
    use p3_field::extension::BinomialExtensionField;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_uni_stark::{prove, verify};

    use super::*;
    use crate::air::test_utils::build_test_config;

    #[test]
    fn prove_verify_sub_base_field() {
        let n = 8;
        let lhs_values = vec![Val::from_u64(10); n];
        let rhs_values = vec![Val::from_u64(4); n];
        let result_values = vec![Val::from_u64(6); n];
        let lhs_index = vec![1u32; n];
        let rhs_index = vec![2u32; n];
        let result_index = vec![3u32; n];

        let trace = SubTrace {
            lhs_values,
            lhs_index,
            rhs_values,
            rhs_index,
            result_values,
            result_index,
        };

        let matrix: RowMajorMatrix<Val> = SubAir::<Val, 1>::trace_to_matrix(&trace);
        assert_eq!(matrix.width(), 6);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        let air = SubAir::<Val, 1>::new(n);
        let proof = prove(&config, &air, matrix, &pis);
        verify(&config, &air, &proof, &pis).expect("verification failed");
    }

    #[test]
    fn prove_verify_sub_extension_field_d4() {
        type ExtField = BinomialExtensionField<Val, 4>;
        let n = 4;

        // Build genuine degree-4 elements via explicit coefficients with ALL non-zero values:
        // a = a0 + a1 x + a2 x^2 + a3 x^3
        let lhs = ExtField::from_basis_coefficients_slice(&[
            Val::from_u64(20), // a0
            Val::from_u64(3),  // a1
            Val::from_u64(9),  // a2
            Val::from_u64(7),  // a3
        ])
        .unwrap();

        let rhs = ExtField::from_basis_coefficients_slice(&[
            Val::from_u64(5), // b0
            Val::from_u64(2), // b1
            Val::from_u64(4), // b2
            Val::from_u64(1), // b3
        ])
        .unwrap();

        let result = lhs - rhs;

        // Sanity: basis length is D
        assert_eq!(
            <ExtField as BasedVectorSpace<Val>>::as_basis_coefficients_slice(&lhs).len(),
            4
        );

        let lhs_values = vec![lhs; n];
        let rhs_values = vec![rhs; n];
        let result_values = vec![result; n];
        let lhs_index = vec![1u32; n];
        let rhs_index = vec![2u32; n];
        let result_index = vec![3u32; n];

        let trace = SubTrace {
            lhs_values,
            lhs_index,
            rhs_values,
            rhs_index,
            result_values,
            result_index,
        };

        // Pack coefficients for D=4: width must be 3*4 + 3 = 15.
        let matrix: RowMajorMatrix<Val> = SubAir::<Val, 4>::trace_to_matrix(&trace);
        assert_eq!(matrix.height(), n);
        assert_eq!(matrix.width(), 15);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        let air = SubAir::<Val, 4>::new(n);
        let proof = prove(&config, &air, matrix, &pis);
        verify(&config, &air, &proof, &pis).expect("extension field verification failed");
    }
}
