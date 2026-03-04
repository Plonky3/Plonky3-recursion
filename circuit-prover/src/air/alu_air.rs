//! [`AluAir`] defines the unified AIR for proving arithmetic operations over both base and extension fields.
//!
//! This AIR combines addition, multiplication, boolean checks, and fused multiply-add operations
//! into a single table, reducing the number of table commitments in the proof.
//!
//! Conceptually, each row of the trace encodes one or more arithmetic constraints based on
//! preprocessed operation selectors:
//!
//! - **ADD**: `a + b = out`
//! - **MUL**: `a * b = out`
//! - **BOOL_CHECK**: `a * (a - 1) = 0`, `out = a`
//! - **MUL_ADD**: `a * b + c = out`
//!
//! # Column layout
//!
//! For each logical operation (lane) we allocate `4 * D` main columns:
//!
//! - `D` columns for operand `a` (basis coefficients),
//! - `D` columns for operand `b` (basis coefficients),
//! - `D` columns for operand `c` (basis coefficients, only used for MulAdd),
//! - `D` columns for output `out` (basis coefficients).
//!
//! Preprocessed columns per lane (12 total):
//!
//! - 1 column `active` (1 for active row, 0 for padding)
//! - 1 column `mult_a`: signed multiplicity for `a` (`-1` reader, `+N` first unconstrained creator, `0` padding)
//! - 3 columns for operation selectors (sel_add_vs_mul, sel_bool, sel_muladd)
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

use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder};
use p3_circuit::op::AluOpKind;
use p3_circuit::tables::AluTrace;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_lookup::lookup_traits::{Kind, Lookup};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

use crate::air::utils::{
    create_direct_preprocessed_trace, create_symbolic_variables, get_alu_index_lookups,
};

/// AIR for proving unified arithmetic operations.
///
/// Supports ADD, MUL, BOOL_CHECK, and MUL_ADD operations with preprocessed selectors.
#[derive(Debug, Clone)]
pub struct AluAir<F, const D: usize = 1> {
    /// Total number of logical ALU operations in the trace.
    pub num_ops: usize,
    /// Number of independent operations packed per trace row.
    pub lanes: usize,
    /// For binomial extensions x^D = W (D > 1).
    pub w_binomial: Option<F>,
    /// Flattened preprocessed values (selectors + indices).
    pub preprocessed: Vec<F>,
    /// Number of lookup columns registered so far.
    pub num_lookup_columns: usize,
    /// Minimum trace height (for FRI compatibility with higher log_final_poly_len).
    pub min_height: usize,
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
            _phantom: PhantomData,
        }
    }

    /// Construct a new `AluAir` for base-field operations with preprocessed data.
    pub const fn new_with_preprocessed(num_ops: usize, lanes: usize, preprocessed: Vec<F>) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");
        assert!(D == 1, "Use new_binomial_with_preprocessed for D > 1");
        Self {
            num_ops,
            lanes,
            w_binomial: None,
            preprocessed,
            num_lookup_columns: 0,
            min_height: 1,
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
            _phantom: PhantomData,
        }
    }

    /// Construct a new `AluAir` for binomial extension-field operations with preprocessed data.
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
            num_lookup_columns: 0,
            min_height: 1,
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
    /// [active, mult_a, sel1, sel2, sel3, a_idx, b_idx, c_idx, out_idx, mult_b, mult_out, mult_c]
    pub const fn preprocessed_lane_width() -> usize {
        12
    }

    /// Total preprocessed width for this AIR instance.
    pub const fn preprocessed_width(&self) -> usize {
        self.lanes * Self::preprocessed_lane_width()
    }

    /// Convert an `AluTrace` into a `RowMajorMatrix` suitable for the STARK prover.
    pub fn trace_to_matrix<ExtF: BasedVectorSpace<F>>(
        trace: &AluTrace<ExtF>,
        lanes: usize,
    ) -> RowMajorMatrix<F> {
        assert!(lanes > 0, "lane count must be non-zero");

        let lane_width = Self::lane_width();
        let width = lane_width * lanes;
        let op_count = trace.a_values.len();
        let row_count = op_count.div_ceil(lanes);

        let mut values = F::zero_vec(width * row_count.max(1));

        for (op_idx, (((a_val, b_val), c_val), out_val)) in trace
            .a_values
            .iter()
            .zip(trace.b_values.iter())
            .zip(trace.c_values.iter())
            .zip(trace.out_values.iter())
            .enumerate()
        {
            let row = op_idx / lanes;
            let lane = op_idx % lanes;
            let mut cursor = (row * width) + (lane * lane_width);

            // Write a[D]
            let a_coeffs = a_val.as_basis_coefficients_slice();
            assert_eq!(a_coeffs.len(), D, "Extension field degree mismatch for a");
            values[cursor..cursor + D].copy_from_slice(a_coeffs);
            cursor += D;

            // Write b[D]
            let b_coeffs = b_val.as_basis_coefficients_slice();
            assert_eq!(b_coeffs.len(), D, "Extension field degree mismatch for b");
            values[cursor..cursor + D].copy_from_slice(b_coeffs);
            cursor += D;

            // Write c[D]
            let c_coeffs = c_val.as_basis_coefficients_slice();
            assert_eq!(c_coeffs.len(), D, "Extension field degree mismatch for c");
            values[cursor..cursor + D].copy_from_slice(c_coeffs);
            cursor += D;

            // Write out[D]
            let out_coeffs = out_val.as_basis_coefficients_slice();
            assert_eq!(
                out_coeffs.len(),
                D,
                "Extension field degree mismatch for out"
            );
            values[cursor..cursor + D].copy_from_slice(out_coeffs);
        }

        let mut mat = RowMajorMatrix::new(values, width);
        mat.pad_to_power_of_two_height(F::ZERO);
        mat
    }

    /// Convert an `AluTrace` to preprocessed values (12 columns per op).
    ///
    /// Layout: `[active, mult_a, sel1, sel2, sel3, a_idx, b_idx, c_idx, out_idx, mult_b, mult_out, mult_c]`.
    pub fn trace_to_preprocessed<ExtF: BasedVectorSpace<F>>(trace: &AluTrace<ExtF>) -> Vec<F> {
        let total_len = trace.a_index.len() * Self::preprocessed_lane_width();
        let mut preprocessed_values = Vec::with_capacity(total_len);
        let neg_one = F::NEG_ONE;

        for (i, kind) in trace.op_kind.iter().enumerate() {
            let (sel_add_vs_mul, sel_bool, sel_muladd) = match kind {
                AluOpKind::Add => (F::ONE, F::ZERO, F::ZERO),
                AluOpKind::Mul => (F::ZERO, F::ZERO, F::ZERO),
                AluOpKind::BoolCheck => (F::ZERO, F::ONE, F::ZERO),
                AluOpKind::MulAdd => (F::ZERO, F::ZERO, F::ONE),
            };

            preprocessed_values.extend(&[
                F::ONE, // active
                neg_one,
                sel_add_vs_mul,
                sel_bool,
                sel_muladd,
                F::from_u32(trace.a_index[i].0 * D as u32),
                F::from_u32(trace.b_index[i].0 * D as u32),
                F::from_u32(trace.c_index[i].0 * D as u32),
                F::from_u32(trace.out_index[i].0 * D as u32),
                neg_one,
                F::ONE,
                neg_one, // mult_c
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
        if self.num_ops > 0 {
            assert!(!self.preprocessed.is_empty());
        }

        Some(create_direct_preprocessed_trace(
            &self.preprocessed,
            Self::preprocessed_lane_width(),
            self.lanes,
            self.min_height,
        ))
    }
}

impl<AB: AirBuilder, const D: usize> Air<AB> for AluAir<AB::F, D>
where
    AB::F: Field,
{
    #[allow(clippy::needless_range_loop)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        debug_assert_eq!(main.width(), self.total_width(), "column width mismatch");

        let local = main.row_slice(0).expect("matrix must be non-empty");
        let lane_width = Self::lane_width();

        // Get preprocessed columns
        let preprocessed = builder
            .preprocessed()
            .expect("AluAir requires preprocessed trace");
        let preprocessed_local = preprocessed
            .row_slice(0)
            .expect("preprocessed must be non-empty");
        let preprocessed_lane_width = Self::preprocessed_lane_width();

        // D=1 specialization
        if D == 1 {
            debug_assert_eq!(lane_width, 4);

            for lane in 0..self.lanes {
                let main_offset = lane * lane_width;
                let prep_offset = lane * preprocessed_lane_width;

                let a = local[main_offset].clone();
                let b = local[main_offset + 1].clone();
                let c = local[main_offset + 2].clone();
                let out = local[main_offset + 3].clone();

                // Preprocessed layout: [active, mult_a, sel1, sel2, sel3, a_idx, b_idx, c_idx, out_idx, mult_b, mult_out, mult_c]
                let active = preprocessed_local[prep_offset].clone();
                let sel_add_vs_mul = preprocessed_local[prep_offset + 2].clone();
                let sel_bool = preprocessed_local[prep_offset + 3].clone();
                let sel_muladd = preprocessed_local[prep_offset + 4].clone();

                // Derive MUL selector linearly:
                // sel_mul = active - sel_bool - sel_muladd - sel_add_vs_mul
                let sel_mul =
                    active - sel_bool.clone() - sel_muladd.clone() - sel_add_vs_mul.clone();

                // ADD constraint: sel_add_vs_mul * (a + b - out) = 0
                builder.assert_zero(sel_add_vs_mul.clone() * (a.clone() + b.clone() - out.clone()));

                // MUL constraint: sel_mul * (a * b - out) = 0
                builder.assert_zero(sel_mul.clone() * (a.clone() * b.clone() - out.clone()));

                // BOOL_CHECK constraint: sel_bool * a * (a - 1) = 0
                let one = AB::Expr::ONE;
                builder.assert_zero(sel_bool.clone() * a.clone() * (a.clone() - one.clone()));

                // MUL_ADD constraint: sel_muladd * (a * b + c - out) = 0
                builder.assert_zero(
                    sel_muladd.clone() * (a.clone() * b.clone() + c.clone() - out.clone()),
                );
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

                // Preprocessed layout: [active, mult_a, sel1, sel2, sel3, a_idx, b_idx, c_idx, out_idx, mult_b, mult_out, mult_c]
                let active = preprocessed_local[prep_offset].clone();
                let sel_add_vs_mul = preprocessed_local[prep_offset + 2].clone();
                let sel_bool = preprocessed_local[prep_offset + 3].clone();
                let sel_muladd = preprocessed_local[prep_offset + 4].clone();

                let sel_mul =
                    active - sel_bool.clone() - sel_muladd.clone() - sel_add_vs_mul.clone();

                // ADD constraints: sel_add_vs_mul * (a[i] + b[i] - out[i]) = 0
                for i in 0..D {
                    builder.assert_zero(
                        sel_add_vs_mul.clone()
                            * (a_slice[i].clone() + b_slice[i].clone() - out_slice[i].clone()),
                    );
                }

                // MUL constraints: extension field multiplication
                let mut mul_acc = vec![AB::Expr::ZERO; D];
                for i in 0..D {
                    for j in 0..D {
                        let term = a_slice[i].clone() * b_slice[j].clone();
                        let k = i + j;
                        if k < D {
                            mul_acc[k] = mul_acc[k].clone() + term;
                        } else {
                            mul_acc[k - D] = mul_acc[k - D].clone() + w.clone() * term;
                        }
                    }
                }
                for i in 0..D {
                    builder
                        .assert_zero(sel_mul.clone() * (mul_acc[i].clone() - out_slice[i].clone()));
                }

                // BOOL_CHECK constraints: sel_bool * a[i] * (a[i] - 1) = 0 for i=0 only (base component)
                // For extension fields, boolean check only makes sense on the base component
                let one = AB::Expr::ONE;
                builder.assert_zero(
                    sel_bool.clone() * a_slice[0].clone() * (a_slice[0].clone() - one.clone()),
                );

                // MUL_ADD constraints: a * b + c = out (extension field)
                let mut muladd_acc = vec![AB::Expr::ZERO; D];
                for i in 0..D {
                    for j in 0..D {
                        let term = a_slice[i].clone() * b_slice[j].clone();
                        let k = i + j;
                        if k < D {
                            muladd_acc[k] = muladd_acc[k].clone() + term;
                        } else {
                            muladd_acc[k - D] = muladd_acc[k - D].clone() + w.clone() * term;
                        }
                    }
                }
                // Add c component-wise
                for i in 0..D {
                    muladd_acc[i] = muladd_acc[i].clone() + c_slice[i].clone();
                }
                for i in 0..D {
                    builder.assert_zero(
                        sel_muladd.clone() * (muladd_acc[i].clone() - out_slice[i].clone()),
                    );
                }
            }
        }
    }

    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let new_idx = self.num_lookup_columns;
        self.num_lookup_columns += 1;
        vec![new_idx]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<<AB>::F>>
    where
        AB: PermutationAirBuilder,
    {
        let mut lookups = Vec::new();
        self.num_lookup_columns = 0;

        let (symbolic_main_local, preprocessed_local) = create_symbolic_variables::<AB::F>(
            self.preprocessed_width(),
            BaseAir::<AB::F>::width(self),
            0,
            0,
        );

        for lane in 0..self.lanes {
            let lane_offset = lane * Self::lane_width();
            let preprocessed_lane_offset = lane * Self::preprocessed_lane_width();

            // 4 lookups per lane: a, b, c, out (all Direction::Receive)
            let lane_lookup_inputs = get_alu_index_lookups::<AB, D>(
                lane_offset,
                preprocessed_lane_offset,
                &symbolic_main_local,
                &preprocessed_local,
            );
            lookups.extend(lane_lookup_inputs.into_iter().map(|inps| {
                <Self as Air<AB>>::register_lookup(
                    self,
                    Kind::Global("WitnessChecks".to_string()),
                    &[inps],
                )
            }));
        }
        lookups
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
    fn prove_verify_alu_add_base_field() {
        let n = 8;
        let a_values = vec![Val::from_u64(3); n];
        let b_values = vec![Val::from_u64(5); n];
        let c_values = vec![Val::ZERO; n];
        let out_values = vec![Val::from_u64(8); n];
        let op_kind = vec![AluOpKind::Add; n];
        let a_index = vec![WitnessId(1); n];
        let b_index = vec![WitnessId(2); n];
        let c_index = vec![WitnessId(0); n];
        let out_index = vec![WitnessId(3); n];

        let trace = AluTrace {
            op_kind,
            a_values,
            a_index,
            b_values,
            b_index,
            c_values,
            c_index,
            out_values,
            out_index,
        };

        let preprocessed_values = AluAir::<Val, 1>::trace_to_preprocessed(&trace);
        let matrix: RowMajorMatrix<Val> = AluAir::<Val, 1>::trace_to_matrix(&trace, 1);
        assert_eq!(matrix.width(), 4);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        let air = AluAir::<Val, 1>::new_with_preprocessed(n, 1, preprocessed_values);
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("verification failed");
    }

    #[test]
    fn prove_verify_alu_mul_base_field() {
        let n = 8;
        let a_values = vec![Val::from_u64(3); n];
        let b_values = vec![Val::from_u64(5); n];
        let c_values = vec![Val::ZERO; n];
        let out_values = vec![Val::from_u64(15); n];
        let op_kind = vec![AluOpKind::Mul; n];
        let a_index = vec![WitnessId(1); n];
        let b_index = vec![WitnessId(2); n];
        let c_index = vec![WitnessId(0); n];
        let out_index = vec![WitnessId(3); n];

        let trace = AluTrace {
            op_kind,
            a_values,
            a_index,
            b_values,
            b_index,
            c_values,
            c_index,
            out_values,
            out_index,
        };

        let preprocessed_values = AluAir::<Val, 1>::trace_to_preprocessed(&trace);
        let matrix: RowMajorMatrix<Val> = AluAir::<Val, 1>::trace_to_matrix(&trace, 1);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        let air = AluAir::<Val, 1>::new_with_preprocessed(n, 1, preprocessed_values);
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
        let a_values: Vec<Val> = (0..n).map(|i| Val::from_u64(i as u64 % 2)).collect();
        let b_values = vec![Val::ZERO; n]; // unused for bool check
        let c_values = vec![Val::ZERO; n];
        let out_values = a_values.clone(); // out = a for bool check
        let op_kind = vec![AluOpKind::BoolCheck; n];
        let a_index = vec![WitnessId(1); n];
        let b_index = vec![WitnessId(0); n];
        let c_index = vec![WitnessId(0); n];
        let out_index = vec![WitnessId(1); n]; // out points to same as a

        let trace = AluTrace {
            op_kind,
            a_values,
            a_index,
            b_values,
            b_index,
            c_values,
            c_index,
            out_values,
            out_index,
        };

        let preprocessed_values = AluAir::<Val, 1>::trace_to_preprocessed(&trace);
        let matrix: RowMajorMatrix<Val> = AluAir::<Val, 1>::trace_to_matrix(&trace, 1);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        let air = AluAir::<Val, 1>::new_with_preprocessed(n, 1, preprocessed_values);
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
        let a_values = vec![Val::from_u64(3); n];
        let b_values = vec![Val::from_u64(5); n];
        let c_values = vec![Val::from_u64(2); n];
        let out_values = vec![Val::from_u64(17); n];
        let op_kind = vec![AluOpKind::MulAdd; n];
        let a_index = vec![WitnessId(1); n];
        let b_index = vec![WitnessId(2); n];
        let c_index = vec![WitnessId(3); n];
        let out_index = vec![WitnessId(4); n];

        let trace = AluTrace {
            op_kind,
            a_values,
            a_index,
            b_values,
            b_index,
            c_values,
            c_index,
            out_values,
            out_index,
        };

        let preprocessed_values = AluAir::<Val, 1>::trace_to_preprocessed(&trace);
        let matrix: RowMajorMatrix<Val> = AluAir::<Val, 1>::trace_to_matrix(&trace, 1);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        let air = AluAir::<Val, 1>::new_with_preprocessed(n, 1, preprocessed_values);
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("verification failed");
    }

    #[test]
    fn prove_verify_alu_mixed_ops() {
        // Mix of ADD and MUL operations
        let a_vals = vec![Val::from_u64(3), Val::from_u64(4)];
        let b_vals = vec![Val::from_u64(5), Val::from_u64(6)];
        let c_vals = vec![Val::ZERO, Val::ZERO];
        let out_vals = vec![Val::from_u64(8), Val::from_u64(24)]; // 3+5=8, 4*6=24
        let ops = vec![AluOpKind::Add, AluOpKind::Mul];

        let trace = AluTrace {
            op_kind: ops,
            a_values: a_vals,
            a_index: vec![WitnessId(0), WitnessId(1)],
            b_values: b_vals,
            b_index: vec![WitnessId(2), WitnessId(3)],
            c_values: c_vals,
            c_index: vec![WitnessId(0), WitnessId(0)],
            out_values: out_vals,
            out_index: vec![WitnessId(4), WitnessId(5)],
        };

        let preprocessed_values = AluAir::<Val, 1>::trace_to_preprocessed(&trace);
        let matrix: RowMajorMatrix<Val> = AluAir::<Val, 1>::trace_to_matrix(&trace, 1);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        let air = AluAir::<Val, 1>::new_with_preprocessed(2, 1, preprocessed_values);
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
            a_values: vec![a; n],
            a_index: vec![WitnessId(1); n],
            b_values: vec![b; n],
            b_index: vec![WitnessId(2); n],
            c_values: vec![c; n],
            c_index: vec![WitnessId(0); n],
            out_values: vec![out; n],
            out_index: vec![WitnessId(3); n],
        };

        let preprocessed_values = AluAir::<Val, 4>::trace_to_preprocessed(&trace);
        let matrix: RowMajorMatrix<Val> = AluAir::<Val, 4>::trace_to_matrix(&trace, 1);
        assert_eq!(matrix.width(), AluAir::<Val, 4>::lane_width());

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        // Get w from the extension field
        let w = Val::from_u64(11); // BabyBear's binomial extension uses w=11

        let air = AluAir::<Val, 4>::new_binomial_with_preprocessed(n, 1, w, preprocessed_values);
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("extension field verification failed");
    }

    #[test]
    fn test_alu_air_constraint_degree() {
        // 8 ops * 12 columns per op (new layout including multiplicities)
        let preprocessed = vec![Val::ZERO; 8 * AluAir::<Val, 1>::preprocessed_lane_width()];
        let air = AluAir::<Val, 1>::new_with_preprocessed(8, 2, preprocessed);
        p3_test_utils::assert_air_constraint_degree!(air, "AluAir");
    }
}
