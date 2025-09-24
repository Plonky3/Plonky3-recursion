use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_circuit::tables::FakeMerkleTrace;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

use super::utils::pad_to_power_of_two;

#[derive(Debug, Clone)]
pub struct FakeMerkleVerifyAir<F> {
    /// Number of rows in the trace
    pub num_rows: usize,
    _phantom: core::marker::PhantomData<F>,
}

impl<F: Field + PrimeCharacteristicRing> FakeMerkleVerifyAir<F> {
    pub const fn new(num_rows: usize) -> Self {
        Self {
            num_rows,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Convert FakeMerkleTrace to RowMajorMatrix for proving
    /// Layout: [left_value, left_index, right_value, right_index, result_value, result_index, path_direction]
    pub fn trace_to_matrix<ExtF: BasedVectorSpace<F>>(
        trace: &FakeMerkleTrace<ExtF>,
    ) -> RowMajorMatrix<F> {
        let height = trace.left_values.len();
        let width = 7; // left, left_index, right, right_index, result, result_index, direction

        let mut values = Vec::with_capacity(height * width);

        for i in 0..height {
            // LEFT - extract base field coefficient (assert D=1)
            let left_coeffs = trace.left_values[i].as_basis_coefficients_slice();
            assert_eq!(
                left_coeffs.len(),
                1,
                "FakeMerkleVerifyAir only supports base field elements (D=1)"
            );
            values.push(left_coeffs[0]);
            values.push(F::from_u64(trace.left_index[i] as u64));

            // RIGHT
            let right_coeffs = trace.right_values[i].as_basis_coefficients_slice();
            assert_eq!(
                right_coeffs.len(),
                1,
                "FakeMerkleVerifyAir only supports base field elements (D=1)"
            );
            values.push(right_coeffs[0]);
            values.push(F::from_u64(trace.right_index[i] as u64));

            // RESULT
            let result_coeffs = trace.result_values[i].as_basis_coefficients_slice();
            assert_eq!(
                result_coeffs.len(),
                1,
                "FakeMerkleVerifyAir only supports base field elements (D=1)"
            );
            values.push(result_coeffs[0]);
            values.push(F::from_u64(trace.result_index[i] as u64));

            // DIRECTION
            values.push(F::from_u64(trace.path_directions[i] as u64));
        }

        // Pad to power of two by repeating last row
        pad_to_power_of_two(&mut values, width, height);

        RowMajorMatrix::new(values, width)
    }
}

impl<F: Field> BaseAir<F> for FakeMerkleVerifyAir<F> {
    fn width(&self) -> usize {
        7 // left, left_index, right, right_index, result, result_index, direction
    }
}

impl<AB: AirBuilder> Air<AB> for FakeMerkleVerifyAir<AB::F>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        debug_assert_eq!(main.width(), 7, "column width mismatch");

        let local = main.row_slice(0).expect("matrix must be non-empty");

        // Offsets:
        // [0] -> left_value
        // [1] -> left_index
        // [2] -> right_value
        // [3] -> right_index
        // [4] -> result_value
        // [5] -> result_index
        // [6] -> path_direction
        let left = local[0].clone();
        let _left_idx = local[1].clone();
        let right = local[2].clone();
        let _right_idx = local[3].clone();
        let result = local[4].clone();
        let _result_idx = local[5].clone();
        let direction = local[6].clone();

        // Mock hash constraint: result = left + right + direction
        builder.assert_zero(left + right + direction - result);
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear as Val;
    use p3_circuit::tables::FakeMerkleTrace;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_uni_stark::{prove, verify};

    use super::*;
    use crate::air::test_utils::build_test_config;

    #[test]
    fn prove_verify_fake_merkle_base_field() {
        let n = 4;
        let left_values = vec![Val::from_u64(42); n];
        let right_values = vec![Val::from_u64(50); n];
        let result_values = vec![Val::from_u64(92); n]; // 42 + 50 + 0
        let left_index = vec![1u32; n];
        let right_index = vec![2u32; n];
        let result_index = vec![3u32; n];
        let path_directions = vec![0u32; n]; // left direction

        let trace = FakeMerkleTrace {
            left_values,
            left_index,
            right_values,
            right_index,
            result_values,
            result_index,
            path_directions,
        };

        let matrix: RowMajorMatrix<Val> = FakeMerkleVerifyAir::trace_to_matrix(&trace);
        assert_eq!(matrix.width(), 7);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        let air = FakeMerkleVerifyAir::new(n);
        let proof = prove(&config, &air, matrix, &pis);
        verify(&config, &air, &proof, &pis).expect("verification failed");
    }
}
