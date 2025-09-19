#![allow(clippy::needless_range_loop)]
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_circuit::tables::MulTrace;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

use super::utils::pad_to_power_of_two;

/// AIR for proving multiplication operations: lhs * rhs = result.
/// Parameterised over extension degree `D` and a runtime lane count controlling how many
/// multiplications are packed side-by-side in each row.
///
/// Column layout (main trace):
///   For D == 1 (base field):
///     [lhs_value, lhs_index, rhs_value, rhs_index, result_value, result_index]  (width = 6)
///
///   For D > 1 (extension, using a basis of size D):
///     [lhs[0..D-1], lhs_index, rhs[0..D-1], rhs_index, result[0..D-1], result_index] (width = 3*D + 3)
///
/// If `w_binomial` is `Some(W)`, we assume a polynomial basis {1, x, ..., x^(D-1)}
/// for the binomial extension defined by x^D = W. Constraints are generated via
/// schoolbook convolution with the reduction x^k = W * x^(k-D) for k >= D.
#[derive(Debug, Clone)]
pub struct MulAir<F, const D: usize = 1> {
    /// Number of logical multiplication operations in the trace.
    pub num_ops: usize,
    /// Number of lanes (operations) packed per row.
    pub lanes: usize,
    /// For binomial extensions x^D = W over a polynomial basis; None for non-binomial / base cases.
    pub w_binomial: Option<F>,
    _phantom: core::marker::PhantomData<F>,
}

impl<F: Field + PrimeCharacteristicRing, const D: usize> MulAir<F, D> {
    /// Number of base-field columns contributed by a single multiplication lane.
    pub const LANE_WIDTH: usize = 3 * D + 3;

    /// Constructor for base-field or non-binomial cases (`D == 1`).
    pub fn new(num_ops: usize, lanes: usize) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");
        Self {
            num_ops,
            lanes,
            w_binomial: None,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Constructor for binomial polynomial-basis extensions x^D = W.
    /// Works for any D >= 2 (for D==1 this is meaningless).
    pub fn new_binomial(num_ops: usize, lanes: usize, w: F) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");
        assert!(D >= 2, "Binomial constructor requires D >= 2");
        Self {
            num_ops,
            lanes,
            w_binomial: Some(w),
            _phantom: core::marker::PhantomData,
        }
    }

    pub const fn lane_width() -> usize {
        Self::LANE_WIDTH
    }

    pub fn total_width(&self) -> usize {
        self.lanes * Self::lane_width()
    }

    /// Convert `MulTrace` to a row-major matrix, packing `lanes` multiplications per row.
    /// Layout per lane mirrors the addition table: `[lhs[D], lhs_idx, rhs[D], rhs_idx, result[D], result_idx]`.
    pub fn trace_to_matrix<ExtF: BasedVectorSpace<F>>(
        trace: &MulTrace<ExtF>,
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
                    assert_eq!(lhs_coeffs.len(), D, "Extension degree mismatch for lhs");
                    values.extend_from_slice(lhs_coeffs);
                    values.push(F::from_u64(trace.lhs_index[op_idx] as u64));

                    // RHS limbs + index
                    let rhs_coeffs = trace.rhs_values[op_idx].as_basis_coefficients_slice();
                    assert_eq!(rhs_coeffs.len(), D, "Extension degree mismatch for rhs");
                    values.extend_from_slice(rhs_coeffs);
                    values.push(F::from_u64(trace.rhs_index[op_idx] as u64));

                    // Result limbs + index
                    let result_coeffs = trace.result_values[op_idx].as_basis_coefficients_slice();
                    assert_eq!(
                        result_coeffs.len(),
                        D,
                        "Extension degree mismatch for result",
                    );
                    values.extend_from_slice(result_coeffs);
                    values.push(F::from_u64(trace.result_index[op_idx] as u64));
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

impl<F: Field, const D: usize> BaseAir<F> for MulAir<F, D> {
    fn width(&self) -> usize {
        self.total_width()
    }
}

impl<AB: AirBuilder, const D: usize> Air<AB> for MulAir<AB::F, D>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();

        debug_assert_eq!(main.width(), self.total_width(), "column width mismatch");

        let local = main.row_slice(0).expect("matrix must be non-empty");
        let local = &*local;
        let lane_width = Self::lane_width();

        if D == 1 {
            for lane in 0..self.lanes {
                let mut cursor = lane * lane_width;
                let lhs_value = local[cursor].clone();
                cursor += 2; // skip lhs limb and index
                let rhs_value = local[cursor].clone();
                cursor += 2; // skip rhs limb and index
                let out_value = local[cursor].clone();
                builder.assert_zero(lhs_value * rhs_value - out_value);
            }
            return;
        }

        let w = self
            .w_binomial
            .as_ref()
            .map(|w| AB::Expr::from(*w))
            .expect("MulAir with D>1 requires binomial parameter W for wrap-around");

        for lane in 0..self.lanes {
            let mut cursor = lane * lane_width;
            let lhs_slice = &local[cursor..cursor + D];
            cursor += D + 1;
            let rhs_slice = &local[cursor..cursor + D];
            cursor += D + 1;
            let result_slice = &local[cursor..cursor + D];

            let mut acc: Vec<AB::Expr> = (0..D).map(|_| AB::Expr::ZERO).collect();

            for i in 0..D {
                for j in 0..D {
                    let term = lhs_slice[i].clone() * rhs_slice[j].clone();
                    let k = i + j;
                    if k < D {
                        acc[k] = acc[k].clone() + term;
                    } else {
                        acc[k - D] = acc[k - D].clone() + w.clone() * term;
                    }
                }
            }

            for k in 0..D {
                builder.assert_zero(result_slice[k].clone() - acc[k].clone());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear as Val;
    use p3_circuit::tables::MulTrace;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{BasedVectorSpace, Field};
    use p3_matrix::dense::RowMajorMatrix;
    use p3_uni_stark::{prove, verify};

    use super::*;
    use crate::air::test_utils::build_test_config;

    #[test]
    fn prove_verify_mul_base_field() {
        let n = 8usize;
        let lhs_values = vec![Val::from_u64(3); n];
        let rhs_values = vec![Val::from_u64(7); n];
        let result_values = vec![Val::from_u64(21); n];
        let lhs_index = vec![1u32; n];
        let rhs_index = vec![2u32; n];
        let result_index = vec![3u32; n];

        let trace = MulTrace {
            lhs_values,
            lhs_index,
            rhs_values,
            rhs_index,
            result_values,
            result_index,
        };

        let matrix: RowMajorMatrix<Val> = MulAir::<Val, 1>::trace_to_matrix(&trace, 1);
        assert_eq!(matrix.width(), MulAir::<Val, 1>::lane_width());

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        let air = MulAir::<Val, 1>::new(n, 1);
        let proof = prove(&config, &air, matrix, &pis);
        verify(&config, &air, &proof, &pis).expect("verification failed");
    }

    #[test]
    fn prove_verify_mul_extension_binomial_d4() {
        type ExtField = BinomialExtensionField<Val, 4>;

        let n = 4usize;

        // Derive W from the field definition by computing x^4, where x = (0,1,0,0).
        let x =
            ExtField::from_basis_coefficients_slice(&[Val::ZERO, Val::ONE, Val::ZERO, Val::ZERO])
                .unwrap();
        let x4 = x.exp_u64(4);

        let x4_coeffs = <ExtField as BasedVectorSpace<Val>>::as_basis_coefficients_slice(&x4);
        // In a binomial polynomial basis, x^4 should be scalar: (W, 0, 0, 0).
        assert_eq!(x4_coeffs[1], Val::ZERO);
        assert_eq!(x4_coeffs[2], Val::ZERO);
        assert_eq!(x4_coeffs[3], Val::ZERO);

        let w: Val = x4_coeffs[0];
        assert!(!w.is_zero(), "W must be non-zero");

        let lhs = ExtField::from_basis_coefficients_slice(&[
            Val::from_u64(3), // a0
            Val::from_u64(1), // a1
            Val::from_u64(4), // a2
            Val::from_u64(2), // a3
        ])
        .unwrap();

        let rhs = ExtField::from_basis_coefficients_slice(&[
            Val::from_u64(2), // b0
            Val::from_u64(5), // b1
            Val::from_u64(1), // b2
            Val::from_u64(3), // b3
        ])
        .unwrap();

        let result = lhs * rhs;

        let lhs_values = vec![lhs; n];
        let rhs_values = vec![rhs; n];
        let result_values = vec![result; n];
        let lhs_index = vec![1u32; n];
        let rhs_index = vec![2u32; n];
        let result_index = vec![3u32; n];

        let trace = MulTrace {
            lhs_values,
            lhs_index,
            rhs_values,
            rhs_index,
            result_values,
            result_index,
        };

        let matrix: RowMajorMatrix<Val> = MulAir::<Val, 4>::trace_to_matrix(&trace, 1);
        assert_eq!(matrix.height(), n);
        assert_eq!(matrix.width(), MulAir::<Val, 4>::lane_width());

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        let air = MulAir::<Val, 4>::new_binomial(n, 1, w);
        let proof = prove(&config, &air, matrix, &pis);
        verify(&config, &air, &proof, &pis).expect("extension field verification failed");
    }

    #[test]
    fn trace_to_matrix_packs_multiple_lanes() {
        let n = 3;
        let lanes = 2;
        let lhs_values = vec![Val::from_u64(1); n];
        let rhs_values = vec![Val::from_u64(2); n];
        let result_values = vec![Val::from_u64(2); n];
        let lhs_index = vec![10u32; n];
        let rhs_index = vec![20u32; n];
        let result_index = vec![30u32; n];

        let trace = MulTrace {
            lhs_values,
            lhs_index,
            rhs_values,
            rhs_index,
            result_values,
            result_index,
        };

        let matrix: RowMajorMatrix<Val> = MulAir::<Val, 1>::trace_to_matrix(&trace, lanes);
        assert_eq!(matrix.width(), MulAir::<Val, 1>::lane_width() * lanes);
        assert_eq!(matrix.height(), 2);
    }
}
