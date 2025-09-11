#![allow(clippy::needless_range_loop)]
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_circuit::tables::MulTrace;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

use super::utils::pad_to_power_of_two;

/// AIR for proving multiplication operations: lhs * rhs = result
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
    /// Number of multiplication operations (height of the trace)
    pub num_ops: usize,
    /// For binomial extensions x^D = W over a polynomial basis; None for non-binomial / base cases.
    pub w_binomial: Option<F>,
    _phantom: core::marker::PhantomData<F>,
}

impl<F: Field + PrimeCharacteristicRing, const D: usize> MulAir<F, D> {
    /// Constructor for base or non-binomial cases (no W).
    pub fn new(num_ops: usize) -> Self {
        Self {
            num_ops,
            w_binomial: None,
            _phantom: core::marker::PhantomData,
        }
    }

    /// Constructor for binomial polynomial-basis extensions x^D = W.
    /// Works for any D >= 2 (for D==1 this is meaningless).
    pub fn new_binomial(num_ops: usize, w: F) -> Self {
        assert!(D >= 2, "Binomial constructor requires D >= 2");
        Self {
            num_ops,
            w_binomial: Some(w),
            _phantom: core::marker::PhantomData,
        }
    }

    /// Convert MulTrace to RowMajorMatrix for proving with generic extension degree D.
    ///
    /// For D==1: packs base elements directly (ignoring basis logic).
    /// For D>1: flattens each extension element into D coefficients followed by index columns.
    pub fn trace_to_matrix<ExtF: BasedVectorSpace<F>>(trace: &MulTrace<ExtF>) -> RowMajorMatrix<F> {
        let height = trace.lhs_values.len();
        let width = 3 * D + 3; // D coeffs each for lhs/rhs/result + 3 indices
        let mut values = Vec::with_capacity(height * width);

        for i in 0..height {
            // LHS
            let lhs_coeffs = trace.lhs_values[i].as_basis_coefficients_slice();
            assert_eq!(lhs_coeffs.len(), D, "Extension degree mismatch for lhs");
            for j in 0..D {
                values.push(lhs_coeffs[j]);
            }
            values.push(F::from_u64(trace.lhs_index[i] as u64));

            // RHS
            let rhs_coeffs = trace.rhs_values[i].as_basis_coefficients_slice();
            assert_eq!(rhs_coeffs.len(), D, "Extension degree mismatch for rhs");
            for j in 0..D {
                values.push(rhs_coeffs[j]);
            }
            values.push(F::from_u64(trace.rhs_index[i] as u64));

            // RESULT
            let result_coeffs = trace.result_values[i].as_basis_coefficients_slice();
            assert_eq!(
                result_coeffs.len(),
                D,
                "Extension degree mismatch for result"
            );
            for j in 0..D {
                values.push(result_coeffs[j]);
            }
            values.push(F::from_u64(trace.result_index[i] as u64));
        }

        // Pad to power of two by repeating last row
        pad_to_power_of_two(&mut values, width, height);

        RowMajorMatrix::new(values, width)
    }
}

impl<F: Field, const D: usize> BaseAir<F> for MulAir<F, D> {
    fn width(&self) -> usize {
        3 * D + 3
    }
}

impl<AB: AirBuilder, const D: usize> Air<AB> for MulAir<AB::F, D>
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

        if D == 1 && self.w_binomial.is_none() {
            // Base field constraint: lhs * rhs = out
            let lhs_value = lhs[0].clone();
            let rhs_value = rhs[0].clone();
            let out_value = out[0].clone();
            builder.assert_zero(lhs_value * rhs_value - out_value);
            return;
        }

        // Binomial polynomial-basis path: x^D = W
        if let Some(w_raw) = self.w_binomial {
            let w = AB::Expr::from(w_raw);

            // acc[k] = sum_{i+j=k} a_i b_j + W * sum_{i+j=k+D} a_i b_j
            let mut acc: Vec<AB::Expr> = (0..D).map(|_| AB::Expr::ZERO).collect();

            for i in 0..D {
                for j in 0..D {
                    let term = lhs[i].clone() * rhs[j].clone();
                    let k = i + j;
                    if k < D {
                        acc[k] = acc[k].clone() + term;
                    } else {
                        acc[k - D] = acc[k - D].clone() + w.clone() * term;
                    }
                }
            }

            for k in 0..D {
                builder.assert_zero(out[k].clone() - acc[k].clone());
            }
            return;
        }

        // If we got here, we don't know how to multiply for this D.
        panic!(
            "Unsupported configuration: D={} with w_binomial={:?}",
            D, self.w_binomial
        );
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

        let matrix: RowMajorMatrix<Val> = MulAir::<Val, 1>::trace_to_matrix(&trace);
        assert_eq!(matrix.width(), 6); // 3*1 + 3

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        let air = MulAir::<Val, 1>::new(n);
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

        // Build genuine extension elements with ALL non-zero coefficients
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

        // Pack coefficients for D=4: width must be 3*4 + 3 = 15.
        let matrix: RowMajorMatrix<Val> = MulAir::<Val, 4>::trace_to_matrix(&trace);
        assert_eq!(matrix.height(), n);
        assert_eq!(matrix.width(), 15);

        // AIR configured with the derived W for binomial x^4 = W
        let air = MulAir::<Val, 4>::new_binomial(n, w);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        let proof = prove(&config, &air, matrix, &pis);
        verify(&config, &air, &proof, &pis).expect("extension field verification failed");
    }
}
