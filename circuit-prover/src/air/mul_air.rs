//! [`MulAir`] defines the AIR for proving multiplication and division over both base and extension fields.
//!
//! Conceptually, each row of the trace encodes one or more multiplication constraints of the form
//! $$
//!     lhs * rhs = result
//! $$
//!
//! When the circuit wants to prove a division, it is expressed as a multiplication by rewriting
//! $$
//!     a / b = c
//! $$
//!
//! as
//! $$
//!     b * c = a
//! $$
//!
//! so that division is handled uniformly as a multiplication gate in the AIR.
//!
//! The AIR is generic over an extension degree `D`. Each operand and result is treated as
//! an element of an extension field of degree `D` over the base field. Internally, this is
//! represented as `D` base-field coordinates (basis coefficients).
//!
//! The runtime parameter `lanes` controls how many independent multiplications are packed
//! side-by-side in a single row of the trace.
//!
//! # Column layout
//!
//! For each logical operation (lane) we allocate `3 * D + 3` base-field columns. These are
//! grouped as:
//!
//! - `D` columns for the left operand (lhs) basis coefficients,
//! - `1` column for `index_left`: the witness-bus index of the lhs operand,
//! - `D` columns for the right operand (rhs) basis coefficients,
//! - `1` column for `index_right`: the witness-bus index of the rhs operand,
//! - `D` columns for the result operand basis coefficients,
//! - `1` column for `index_output`: the witness-bus index of the result.
//!
//! In other words, for a single lane the layout is:
//!
//! ```text
//!     [lhs[0..D), lhs_index, rhs[0..D), rhs_index, result[0..D), result_index]
//! ```
//!
//! A single row can pack several of these lanes side-by-side, so the full row layout is
//! this pattern repeated `lanes` times.
//!
//! # Constraints
//!
//! ## Base Field (D=1)
//!
//! Let `left`, `right`, and `output` be the single base-field coordinates. The AIR
//! enforces the constraint:
//!
//! $$
//! left \cdot right - output = 0.
//! $$
//!
//! ## Binomial Extension (D > 1)
//!
//! This AIR currently supports binomial extensions using a polynomial basis $\{1, x, \dots, x^{D-1}\}$
//! where the field is defined by $x^D = W$ for some $W \in F$.
//!
//! - $L(x) = \sum_{i=0}^{D-1} left[i] x^i$
//! - $R(x) = \sum_{i=0}^{D-1} right[i] x^i$
//! - $O(x) = \sum_{i=0}^{D-1} output[i] x^i$
//!
//! The AIR enforces the polynomial identity:
//!
//! $$
//! L(x) \cdot R(x) \equiv O(x) \pmod{x^D - W}
//! $$
//!
//! # Global interactions
//!
//! Each operation (lane) has three interactions with the global witness bus:
//!
//! - send `(index_left,  left)`
//! - send `(index_right, right)`
//! - send `(index_output, result)`
//!
//! The AIR defined here focuses on the algebraic relation between the operands. The
//! correctness of the indices with respect to the global witness bus is enforced by the
//! bus interaction logic elsewhere in the system.

use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_circuit::tables::MulTrace;
use p3_circuit::utils::pad_to_power_of_two;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

/// AIR for proving multiplication operations: lhs * rhs = result.
///
/// Parameterised over extension degree `D` and a runtime lane count controlling how many
/// multiplications are packed side-by-side in each row.
///
/// Column layout (main trace):
///   - For D == 1 (base field):
///     [lhs_value, lhs_index, rhs_value, rhs_index, result_value, result_index]  (width = 6)
///
///   - For D > 1 (extension, using a basis of size D):
///     [lhs[0..D-1], lhs_index, rhs[0..D-1], rhs_index, result[0..D-1], result_index] (width = 3*D + 3)
///
/// If `w_binomial` is `Some(W)`, we assume a polynomial basis {1, x, ..., x^(D-1)}
/// for the binomial extension defined by x^D = W. Constraints are generated via
/// schoolbook convolution with the reduction x^k = W * x^(k-D) for k >= D.
#[derive(Debug, Clone)]
pub struct MulAir<F, const D: usize = 1> {
    /// Total number of logical multiplication operations (gates) in the trace.
    pub num_ops: usize,
    /// Number of independent multiplication gates packed per trace row.
    ///
    /// The last row is padded if the number of operations is not a multiple of this value.
    pub lanes: usize,
    /// For binomial extensions $x^D = W$ over a polynomial basis.
    ///
    /// This should be:
    /// - `Some(W)` if `D > 1`,
    /// - `None` if `D == 1`.
    pub w_binomial: Option<F>,
    /// Preprocessed values. They are used for generating the common data,
    /// as well as by the prover, to compute the constraint polynomial.
    /// Preprocessed values correspond to the indices of the inputs and outputs within the `Witness`.
    pub preprocessed: Vec<F>,
    /// Marker tying this AIR to its base field.
    _phantom: PhantomData<F>,
}

impl<F: Field + PrimeCharacteristicRing, const D: usize> MulAir<F, D> {
    /// Construct a new `MulAir` for base-field operations (D=1).
    ///
    /// Panics if `lanes == 0` or `D > 1`.
    pub const fn new(num_ops: usize, lanes: usize) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");
        assert!(D == 1, "Use new_binomial for D > 1");
        Self {
            num_ops,
            lanes,
            w_binomial: None,
            preprocessed: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// Construct a new `MulAir` for base-field operations (D=1).
    ///
    /// Panics if `lanes == 0` or `D > 1`.
    pub const fn new_with_preprocessed(num_ops: usize, lanes: usize, preprocessed: Vec<F>) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");
        assert!(D == 1, "Use new_binomial for D > 1");
        Self {
            num_ops,
            lanes,
            w_binomial: None,
            preprocessed,
            _phantom: PhantomData,
        }
    }

    /// Construct a new `MulAir` for binomial extension-field operations ($x^D = W$, D > 1).
    ///
    /// Panics if `lanes == 0` or if `D < 2`.
    pub const fn new_binomial(num_ops: usize, lanes: usize, w: F) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");
        assert!(D >= 2, "Binomial constructor requires D >= 2");
        Self {
            num_ops,
            lanes,
            w_binomial: Some(w),
            preprocessed: Vec::new(),
            _phantom: PhantomData,
        }
    }

    /// Construct a new `MulAir` for binomial extension-field operations ($x^D = W$, D > 1).
    ///
    /// Panics if `lanes == 0` or if `D < 2`.
    pub const fn new_binomial_with_preprocessed(
        num_ops: usize,
        lanes: usize,
        w: F,
        preprocessed: Vec<F>,
    ) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");
        assert!(D >= 2, "Binomial constructor requires D >= 2");
        Self {
            num_ops,
            lanes,
            w_binomial: Some(w),
            preprocessed,
            _phantom: PhantomData,
        }
    }

    /// Number of base-field columns occupied by a single lane.
    ///
    /// Each lane stores:
    /// - `3 * D` coordinates (for `lhs`, `rhs`, and `result`),
    /// - `3` indices (one for each operand).
    ///
    /// The total width of a single row is `3 * D + 3`
    pub const fn lane_width() -> usize {
        3 * D
    }

    /// Total number of columns in the main trace for this AIR instance.
    pub const fn total_width(&self) -> usize {
        self.lanes * Self::lane_width()
    }

    /// Number of preprocessed base-field columns occupied by a single lane.
    ///
    /// Each lane stores 3 indices (one for each operand)
    pub const fn prep_lane_width() -> usize {
        3
    }

    /// Number of preprocessed columns for this AIR instance.
    ///
    /// Each lane stores 3 indices (one for each operand)
    pub const fn prep_width(&self) -> usize {
        self.lanes * Self::prep_lane_width()
    }

    /// Convert a `MulTrace` into a `RowMajorMatrix` suitable for the STARK prover.
    ///
    /// This function is responsible for:
    ///
    /// 1. Taking the logical operations from the `MulTrace`:
    ///    - `lhs_values`, `rhs_values`, `result_values` (extension elements),
    ///    - `lhs_index`, `rhs_index`, `result_index` (witness-bus indices),
    /// 2. Decomposing each extension element into its `D` basis coordinates,
    /// 3. Packing `lanes` operations side-by-side in each row,
    /// 4. Padding the trace to have a power-of-two number of rows for FFT-friendly
    ///    execution by the STARK prover.
    ///
    /// The resulting matrix has:
    ///
    /// - width = lanes * `LANE_WIDTH`,
    /// - height equal to the number of rows after packing and padding.
    ///
    /// The layout within a row is:
    ///
    /// ```text
    ///     [lhs[0..D), lhs_index, rhs[0..D), rhs_index, result[0..D), result_index] repeated `lanes` times.
    /// ```
    pub fn trace_to_matrix<ExtF: BasedVectorSpace<F>>(
        trace: &MulTrace<ExtF>,
        lanes: usize,
    ) -> RowMajorMatrix<F> {
        // Lanes must be strictly positive.
        //
        // Zero lanes would make it impossible to construct a row.
        assert!(lanes > 0, "lane count must be non-zero");

        // Per-lane width in base-field columns.
        let lane_width = Self::lane_width();
        // Total width of each row once all lanes are packed.
        let width = lane_width * lanes;
        // Number of logical operations we need to pack into the trace.
        let op_count = trace.lhs_values.len();
        // Number of rows needed to hold `op_count` operations.
        let row_count = op_count.div_ceil(lanes);

        // Pre-allocate the entire trace as a flat vector in row-major order.
        //
        // We start with `row_count` rows, each of width `width`, and fill it with zeros.
        // This automatically provides a clean padding for any unused lanes in the final row.
        let mut values = F::zero_vec(width * row_count.max(1));

        // Iterate over all operations in lockstep across the trace arrays.
        for (op_idx, ((lhs_val, rhs_val), res_val)) in trace
            .lhs_values
            .iter()
            .zip(trace.rhs_values.iter())
            .zip(trace.result_values.iter())
            .enumerate()
        {
            // Determine the target row index.
            let row = op_idx / lanes;
            // Determine which lane within that row this operation occupies.
            let lane = op_idx % lanes;

            // Compute the starting column index (cursor) for this lane within the flat vector.
            //
            // Row-major layout means:
            //   row_offset = row * width,
            //   lane_offset = lane * lane_width.
            let mut cursor = (row * width) + (lane * lane_width);

            // Write LHS coordinates and LHS witness index.
            //
            // Extract the basis coefficients of the lhs extension element.
            let lhs_coeffs = lhs_val.as_basis_coefficients_slice();
            // Sanity check: the extension degree must match the generic parameter `D`.
            assert_eq!(
                lhs_coeffs.len(),
                D,
                "Extension field degree mismatch for lhs"
            );
            // Copy the `D` lhs coordinates into the trace row.
            values[cursor..cursor + D].copy_from_slice(lhs_coeffs);
            cursor += D;

            // Write RHS coordinates and RHS witness index.
            //
            // Extract the basis coefficients of the rhs extension element.
            let rhs_coeffs = rhs_val.as_basis_coefficients_slice();
            // Sanity check: the extension degree must match the generic parameter `D`.
            assert_eq!(
                rhs_coeffs.len(),
                D,
                "Extension field degree mismatch for rhs"
            );
            // Copy the `D` rhs coordinates into the trace row.
            values[cursor..cursor + D].copy_from_slice(rhs_coeffs);
            cursor += D;

            // Write result coordinates and result witness index.
            //
            // Extract the basis coefficients of the result extension element.
            let res_coeffs = res_val.as_basis_coefficients_slice();
            debug_assert_eq!(
                res_coeffs.len(),
                D,
                "Extension field degree mismatch for result"
            );
            // Copy the `D` result coordinates into the trace row.
            values[cursor..cursor + D].copy_from_slice(res_coeffs);
        }

        // Pad the matrix to a power-of-two height.
        pad_to_power_of_two(&mut values, width, row_count);

        // Build the row-major matrix with the computed width.
        RowMajorMatrix::new(values, width)
    }

    pub fn prep_from_trace<ExtF: BasedVectorSpace<F>>(
        trace: &MulTrace<ExtF>,
        lanes: usize,
    ) -> Vec<F> {
        let total_prep_len = trace.lhs_values.len() * Self::prep_lane_width() * lanes;
        let mut prep = Vec::with_capacity(total_prep_len);
        trace
            .lhs_index
            .iter()
            .zip(trace.rhs_index.clone())
            .zip(trace.result_index.clone())
            .for_each(|((lhs_idx, rhs_idx), res_idx)| {
                prep.extend(&[
                    F::from_u64(lhs_idx.0 as u64),
                    F::from_u64(rhs_idx.0 as u64),
                    F::from_u64(res_idx.0 as u64),
                ]);
            });

        prep
    }
}

impl<F: Field, const D: usize> BaseAir<F> for MulAir<F, D> {
    fn width(&self) -> usize {
        self.total_width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let original_height = self.num_ops.div_ceil(self.lanes);

        let mut prep_values = self.preprocessed.clone();
        let padding_len = self.prep_width() - prep_values.len() % self.prep_width();
        if padding_len != self.prep_width() {
            prep_values.extend(vec![F::ZERO; padding_len]);
        }
        pad_to_power_of_two(&mut prep_values, self.prep_width(), original_height);

        Some(RowMajorMatrix::new(prep_values, self.prep_width()))
    }
}

impl<AB: AirBuilder, const D: usize> Air<AB> for MulAir<AB::F, D>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        // Access the main trace view from the builder.
        let main = builder.main();

        // Make sure that the matrix width matches what this AIR expects.
        debug_assert_eq!(main.width(), self.total_width(), "column width mismatch");

        // Get the evaluation at evaluation point `zeta`
        let local = main.row_slice(0).expect("matrix must be non-empty");
        let lane_width = Self::lane_width();

        // Specialized Path for D=1 (Base Field)
        if D == 1 {
            // For D=1, lane_width is 3.
            // Layout: [lhs, lhs_idx, rhs, rhs_idx, result, result_idx]
            debug_assert_eq!(lane_width, 3);

            for lane_data in local.chunks_exact(lane_width) {
                let lhs_value = lane_data[0].clone();
                // lane_data[1] is lhs_idx
                let rhs_value = lane_data[1].clone();
                // lane_data[3] is rhs_idx
                let out_value = lane_data[2].clone();
                // lane_data[5] is result_idx

                // Enforce: lhs * rhs - result = 0
                builder.assert_zero(lhs_value * rhs_value - out_value);
            }
        } else {
            // Specialized Path for D > 1 (Extension Field)

            // For D > 1, we must have the binomial parameter W.
            //
            // We can 'expect' it once, outside the loop.
            let w = self
                .w_binomial
                .as_ref()
                .map(|w| AB::Expr::from(*w))
                .expect("MulAir with D>1 requires binomial parameter W");

            for lane_data in local.chunks_exact(lane_width) {
                // Data Extraction
                //
                // We are proving a polynomial multiplication:
                //   L(x) * R(x) = O(x)  (mod x^D - W)
                //
                // L(x) = lhs[0] + lhs[1]x + ... + lhs[D-1]x^(D-1)
                // R(x) = rhs[0] + rhs[1]x + ... + rhs[D-1]x^(D-1)
                // O(x) = result[0] + result[1]x + ... + result[D-1]x^(D-1)
                //
                // Here, we extract the slices of coefficients for L(x), R(x), and O(x).

                // Split off the lhs block and its index:
                //   lhs_and_idx = [lhs[0..D), lhs_idx]
                //   rest        = [rhs[0..D), rhs_idx, result[0..D), result_idx]
                let (lhs_slice, rest) = lane_data.split_at(D);

                // Split the remaining data:
                //   rhs_and_idx    = [rhs[0..D), rhs_idx]
                //   result_and_idx = [result[0..D), result_idx]
                let (rhs_slice, result_slice) = rest.split_at(D);

                // Compute the Product C(x) = L(x) * R(x) (mod x^D - W)
                //
                // Accumulator for the coefficients of the reduced product polynomial.
                let mut acc = vec![AB::Expr::ZERO; D];

                // We perform "schoolbook" multiplication term-by-term.
                //
                // We reduce each term *immediately* using the rule $x^D = W$.
                for (i, lhs) in lhs_slice.iter().enumerate().take(D) {
                    // This is the i-th term of L(x): lhs[i] * x^i
                    for (j, rhs) in rhs_slice.iter().enumerate().take(D) {
                        // This is the j-th term of R(x): rhs[j] * x^j

                        // Multiplying them gives: (lhs[i] * rhs[j]) * x^(i+j)
                        let term = lhs.clone() * rhs.clone();
                        let k = i + j;

                        // Now, we reduce the $x^k$ term and add its coefficient
                        // (which is 'term') to the correct spot in 'acc'.
                        if k < D {
                            // Case 1: k < D
                            //
                            // The degree 'k' is already in the valid range [0, D-1].
                            // No reduction is needed.
                            // The term is: term * x^k
                            // We add 'term' to the k-th coefficient in our accumulator.
                            //
                            // Math: acc[k] = acc[k] + term
                            acc[k] += term;
                        } else {
                            // Case 2: k >= D
                            //
                            // The degree 'k' is "out of bounds" and must be reduced.
                            // We use the rule: $x^D = W$
                            //
                            // We can rewrite $x^k$ as:
                            //   $x^k = x^{k-D} * x^D$
                            //
                            // Substituting the rule gives:
                            //   $x^k = x^{k-D} * W$
                            //
                            // So our full term (term * x^k) becomes:
                            //   term * (W * x^{k-D})
                            //
                            // This is a new term of degree (k-D), with a new
                            // coefficient of (term * W).
                            //
                            // Math: acc[k-D] = acc[k-D] + (term * W)
                            acc[k - D] += w.clone() * term;
                        }
                    }
                }

                // Enforce the Constraint
                //
                // At this point, 'acc' holds the coefficients of the correctly
                // computed product C(x).
                //
                // 'result_slice' holds the coefficients of the polynomial O(x)
                // provided by the prover (the witness).
                //
                // We must assert that they are equal, coefficient by coefficient.
                //
                // Enforces: C(x) = O(x)
                for k in 0..D {
                    // result_slice[k] - acc[k] = 0
                    builder.assert_zero(result_slice[k].clone() - acc[k].clone());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use p3_baby_bear::BabyBear as Val;
    use p3_circuit::WitnessId;
    use p3_field::extension::BinomialExtensionField;
    use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
    use p3_util::log2_ceil_usize;

    use super::*;
    use crate::air::test_utils::build_test_config;

    #[test]
    fn prove_verify_mul_base_field() {
        let n = 8usize;
        let lhs_values = vec![Val::from_u64(3); n];
        let rhs_values = vec![Val::from_u64(7); n];
        let result_values = vec![Val::from_u64(21); n];
        let lhs_index = vec![WitnessId(1); n];
        let rhs_index = vec![WitnessId(2); n];
        let result_index = vec![WitnessId(3); n];
        let mut prep_values = Vec::with_capacity(n * 3);
        lhs_index
            .iter()
            .zip(rhs_index.iter())
            .zip(result_index.iter())
            .for_each(|((lhs_idx, rhs_idx), result_idx)| {
                prep_values.extend(&[
                    Val::from_u32(lhs_idx.0),
                    Val::from_u32(rhs_idx.0),
                    Val::from_u32(result_idx.0),
                ]);
            });
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

        let air = MulAir::<Val, 1>::new_with_preprocessed(n, 1, prep_values);
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("verification failed");
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
        let lhs_index = vec![WitnessId(1); n];
        let rhs_index = vec![WitnessId(2); n];
        let result_index = vec![WitnessId(3); n];

        // Get preprocessed index values.
        let mut prep_values = Vec::with_capacity(n * 3);
        lhs_index
            .iter()
            .zip(rhs_index.iter())
            .zip(result_index.iter())
            .for_each(|((lhs_idx, rhs_idx), result_idx)| {
                prep_values.extend(&[
                    Val::from_u32(lhs_idx.0),
                    Val::from_u32(rhs_idx.0),
                    Val::from_u32(result_idx.0),
                ]);
            });

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

        let air = MulAir::<Val, 4>::new_binomial_with_preprocessed(n, 1, w, prep_values);
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("extension field verification failed");
    }

    #[test]
    fn trace_to_matrix_packs_multiple_lanes() {
        let n = 3;
        let lanes = 2;
        let lhs_values = vec![Val::from_u64(1); n];
        let rhs_values = vec![Val::from_u64(2); n];
        let result_values = vec![Val::from_u64(2); n];
        let lhs_index = vec![WitnessId(10); n];
        let rhs_index = vec![WitnessId(20); n];
        let result_index = vec![WitnessId(30); n];

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
