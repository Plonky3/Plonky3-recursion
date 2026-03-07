//! [`AluAir`] defines the unified AIR for proving arithmetic operations over both base and extension fields.
//!
//! This AIR combines addition, multiplication, boolean checks and fused multiply-add.
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
//! - `D` columns for operand `c` (basis coefficients, used for MulAdd),
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

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_circuit::op::AluOpKind;
use p3_circuit::tables::AluTrace;
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
use p3_lookup::LookupAir;
use p3_lookup::lookup_traits::{Kind, Lookup};
use p3_matrix::dense::RowMajorMatrix;

use crate::air::utils::{
    create_direct_preprocessed_trace, create_symbolic_variables, get_alu_index_lookups,
};

/// AIR for proving unified arithmetic operations.
///
/// Supports ADD, MUL, BOOL_CHECK, and MUL_ADD operations with preprocessed selectors.
#[derive(Debug, Clone)]
pub struct AluAir<F, const D: usize = 1> {
    /// Number of independent operations packed per trace row.
    pub(crate) lanes: usize,
    /// For binomial extensions x^D = W (D > 1).
    pub(crate) w_binomial: Option<F>,
    /// Flattened preprocessed values (selectors + indices), in original op order.
    pub(crate) preprocessed: Vec<F>,
    /// Number of lookup columns registered so far.
    pub(crate) num_lookup_columns: usize,
    /// Minimum trace height (for FRI compatibility with higher log_final_poly_len).
    pub(crate) min_height: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field + PrimeCharacteristicRing, const D: usize> AluAir<F, D> {
    /// Construct a new `AluAir` for base-field operations (D=1).
    pub const fn new(lanes: usize) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");
        assert!(D == 1, "Use new_binomial for D > 1");
        Self {
            lanes,
            w_binomial: None,
            preprocessed: Vec::new(),
            num_lookup_columns: 0,
            min_height: 1,
            _phantom: PhantomData,
        }
    }

    /// Construct a new `AluAir` for base-field operations with preprocessed data.
    pub fn new_with_preprocessed(lanes: usize, preprocessed: Vec<F>) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");
        assert!(D == 1, "Use new_binomial_with_preprocessed for D > 1");
        Self {
            lanes,
            w_binomial: None,
            preprocessed,
            num_lookup_columns: 0,
            min_height: 1,
            _phantom: PhantomData,
        }
    }

    /// Construct a new `AluAir` for binomial extension-field operations (D > 1).
    pub const fn new_binomial(lanes: usize, w: F) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");
        assert!(D >= 2, "Binomial constructor requires D >= 2");
        Self {
            lanes,
            w_binomial: Some(w),
            preprocessed: Vec::new(),
            num_lookup_columns: 0,
            min_height: 1,
            _phantom: PhantomData,
        }
    }

    /// Construct a new `AluAir` for binomial extension-field operations with preprocessed data.
    pub fn new_binomial_with_preprocessed(lanes: usize, w: F, preprocessed: Vec<F>) -> Self {
        assert!(lanes > 0, "lane count must be non-zero");
        assert!(D >= 2, "Binomial constructor requires D >= 2");
        Self {
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
    /// [active, mult_a, sel_add_vs_mul, sel_bool, sel_muladd, a_idx, b_idx, c_idx, out_idx, mult_b, mult_out, mult_c]
    pub const fn preprocessed_lane_width() -> usize {
        12
    }

    /// Total preprocessed width for this AIR instance.
    pub const fn preprocessed_width(&self) -> usize {
        self.lanes * Self::preprocessed_lane_width()
    }

    /// Number of preprocessed columns excluding multiplicity.
    pub const fn preprocessed_width_without_multiplicity(&self) -> usize {
        self.lanes * (Self::preprocessed_lane_width() - 1)
    }

    /// Convert an `AluTrace` into a `RowMajorMatrix` suitable for the STARK prover.
    pub fn trace_to_matrix<ExtF: BasedVectorSpace<F>>(
        &self,
        trace: &AluTrace<ExtF>,
    ) -> RowMajorMatrix<F> {
        let lanes = self.lanes;
        assert!(lanes > 0, "lane count must be non-zero");

        let lane_width = Self::lane_width();
        let width = lane_width * lanes;
        let row_count = trace.values.len().div_ceil(lanes);

        let mut values = F::zero_vec(width * row_count.max(1));

        // Write one entry at position `pos` (row = pos/lanes, lane = pos%lanes)
        let mut write_op =
            |pos: usize, a_val: &ExtF, b_val: &ExtF, c_val: &ExtF, out_val: &ExtF| {
                let row = pos / lanes;
                let lane = pos % lanes;
                let mut cursor = row * width + lane * lane_width;

                let a_coeffs = a_val.as_basis_coefficients_slice();
                values[cursor..cursor + D].copy_from_slice(a_coeffs);
                cursor += D;
                let b_coeffs = b_val.as_basis_coefficients_slice();
                values[cursor..cursor + D].copy_from_slice(b_coeffs);
                cursor += D;
                let c_coeffs = c_val.as_basis_coefficients_slice();
                values[cursor..cursor + D].copy_from_slice(c_coeffs);
                cursor += D;
                let out_coeffs = out_val.as_basis_coefficients_slice();
                values[cursor..cursor + D].copy_from_slice(out_coeffs);
            };

        for op_idx in 0..trace.values.len() {
            write_op(
                op_idx,
                &trace.values[op_idx][0], // a
                &trace.values[op_idx][1], // b
                &trace.values[op_idx][2], // c
                &trace.values[op_idx][3], // out
            );
        }

        let mut mat = RowMajorMatrix::new(values, width);
        mat.pad_to_power_of_two_height(F::ZERO);
        mat
    }

    /// Convert an `AluTrace` to preprocessed values (12 columns per op).
    ///
    /// Layout: `[mult_a, sel_add_vs_mul, sel_bool, sel_muladd, a_idx, b_idx, c_idx, out_idx, mult_b, mult_out, a_is_reader, c_is_reader]`.
    /// Indices are D-scaled. In standalone tests, `a_is_reader = c_is_reader = 1`.
    pub fn trace_to_preprocessed<ExtF: BasedVectorSpace<F>>(trace: &AluTrace<ExtF>) -> Vec<F> {
        let total_len = trace.indices.len() * Self::preprocessed_lane_width();
        let mut preprocessed_values = Vec::with_capacity(total_len);
        let neg_one = F::ZERO - F::ONE;

        for (i, kind) in trace.op_kind.iter().enumerate() {
            let (sel_add_vs_mul, sel_bool, sel_muladd) = match kind {
                AluOpKind::Add => (F::ONE, F::ZERO, F::ZERO),
                AluOpKind::Mul => (F::ZERO, F::ZERO, F::ZERO),
                AluOpKind::BoolCheck => (F::ZERO, F::ONE, F::ZERO),
                AluOpKind::MulAdd => (F::ZERO, F::ZERO, F::ONE),
            };

            preprocessed_values.extend(&[
                neg_one, // mult_a (base; active = 1)
                sel_add_vs_mul,
                sel_bool,
                sel_muladd,
                F::from_u32(trace.indices[i][0].0 * D as u32),
                F::from_u32(trace.indices[i][1].0 * D as u32),
                F::from_u32(trace.indices[i][2].0 * D as u32),
                F::from_u32(trace.indices[i][3].0 * D as u32),
                neg_one, // mult_b (reader placeholder)
                F::ONE,  // mult_out (creator placeholder)
                F::ONE,  // a_is_reader (standalone: constrained)
                F::ONE,  // c_is_reader (standalone: constrained)
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
    #[unroll::unroll_for_loops]
    #[allow(clippy::needless_range_loop)]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        debug_assert_eq!(
            main.current_slice().len(),
            self.total_width(),
            "column width mismatch"
        );

        let local = main.current_slice();
        let lane_width = Self::lane_width();

        // Get preprocessed columns
        let preprocessed = builder.preprocessed().clone();
        let preprocessed_local = preprocessed.current_slice();
        let preprocessed_lane_width = Self::preprocessed_lane_width();

        // D=1 specialization
        if D == 1 {
            debug_assert_eq!(lane_width, 4);

            for lane in 0..self.lanes {
                let main_offset = lane * lane_width;
                let prep_offset = lane * preprocessed_lane_width;

                let a = local[main_offset];
                let b = local[main_offset + 1];
                let c = local[main_offset + 2];
                let out = local[main_offset + 3];

                // Preprocessed layout: [mult_a, sel_add_vs_mul, sel_bool, sel_muladd, a_idx, b_idx, c_idx, out_idx, mult_b, mult_out, a_is_reader, c_is_reader]
                let mult_a = preprocessed_local[prep_offset];
                let sel_add_vs_mul = preprocessed_local[prep_offset + 1];
                let sel_bool = preprocessed_local[prep_offset + 2];
                let sel_muladd = preprocessed_local[prep_offset + 3];

                // active = -mult_a: 1 for active rows, 0 for padding
                let active = AB::Expr::ZERO - mult_a;
                // sel_mul = active - sel_bool - sel_muladd - sel_add_vs_mul
                let sel_mul = active - sel_bool - sel_muladd - sel_add_vs_mul;

                // ADD constraint: sel_add_vs_mul * (a + b - out) = 0
                builder.assert_zero(sel_add_vs_mul * (a + b - out));

                // MUL constraint: sel_mul * (a * b - out) = 0
                builder.assert_zero(sel_mul * (a * b - out));

                // BOOL_CHECK constraint: sel_bool * a * (a - 1) = 0
                let one = AB::Expr::ONE;
                builder.assert_zero(sel_bool * a * (a - one));

                // MUL_ADD constraint: sel_muladd * (a * b + c - out) = 0
                builder.assert_zero(sel_muladd * (a * b + c - out));
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

                // Preprocessed layout: [mult_a, sel_add_vs_mul, sel_bool, sel_muladd, a_idx, b_idx, c_idx, out_idx, mult_b, mult_out, a_is_reader, c_is_reader]
                let mult_a = preprocessed_local[prep_offset];
                let sel_add_vs_mul = preprocessed_local[prep_offset + 1];
                let sel_bool = preprocessed_local[prep_offset + 2];
                let sel_muladd = preprocessed_local[prep_offset + 3];

                // active = -mult_a: 1 for active rows, 0 for padding
                let active = AB::Expr::ZERO - mult_a;
                // sel_mul = active - sel_bool - sel_muladd - sel_add_vs_mul
                let sel_mul = active - sel_bool - sel_muladd - sel_add_vs_mul;

                // ADD constraints
                for i in 0..D {
                    builder.assert_zero(sel_add_vs_mul * (a_slice[i] + b_slice[i] - out_slice[i]));
                }

                // MUL constraints: extension field multiplication
                let mut mul_acc = vec![AB::Expr::ZERO; D];
                for i in 0..D {
                    for j in 0..D {
                        let term = a_slice[i] * b_slice[j];
                        let k = i + j;
                        if k < D {
                            mul_acc[k] = mul_acc[k].clone() + term;
                        } else {
                            mul_acc[k - D] = mul_acc[k - D].clone() + w.clone() * term;
                        }
                    }
                }
                for i in 0..D {
                    builder.assert_zero(sel_mul.clone() * (mul_acc[i].clone() - out_slice[i]));
                }

                // BOOL_CHECK constraint (base component only)
                let one = AB::Expr::ONE;
                builder.assert_zero(sel_bool * a_slice[0] * (a_slice[0] - one));

                // MUL_ADD constraints: a * b + c = out (extension field), reuse mul_acc
                let mut muladd_acc = mul_acc.clone();
                for i in 0..D {
                    muladd_acc[i] = muladd_acc[i].clone() + c_slice[i];
                }
                for i in 0..D {
                    builder.assert_zero(sel_muladd * (muladd_acc[i].clone() - out_slice[i]));
                }
            }
        }
    }
}

impl<F: Field, const D: usize> LookupAir<F> for AluAir<F, D> {
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let new_idx = self.num_lookup_columns;
        self.num_lookup_columns += 1;
        vec![new_idx]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<F>> {
        let mut lookups = Vec::new();
        self.num_lookup_columns = 0;

        let (symbolic_main_local, preprocessed_local) = create_symbolic_variables::<F>(
            self.preprocessed_width(),
            BaseAir::<F>::width(self),
            0,
            0,
        );

        for lane in 0..self.lanes {
            let lane_offset = lane * Self::lane_width();
            let preprocessed_lane_offset = lane * Self::preprocessed_lane_width();

            // 4 lookups per lane: a, b, c, out (all Direction::Receive)
            let lane_lookup_inputs = get_alu_index_lookups::<F, D>(
                lane_offset,
                preprocessed_lane_offset,
                &symbolic_main_local,
                &preprocessed_local,
            );
            lookups.extend(lane_lookup_inputs.into_iter().map(|inps| {
                LookupAir::register_lookup(self, Kind::Global("WitnessChecks".to_string()), &[inps])
            }));
        }
        lookups
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use p3_circuit::WitnessId;
    use p3_matrix::Matrix;
    use p3_test_utils::baby_bear_params::{
        BabyBear as Val, BinomialExtensionField, PrimeCharacteristicRing,
    };
    use p3_uni_stark::{prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed};
    use p3_util::log2_ceil_usize;

    use super::*;
    use crate::air::test_utils::build_test_config;

    #[test]
    fn prove_verify_alu_add_base_field() {
        let n = 8;
        let op_kind = vec![AluOpKind::Add; n];
        let values = vec![
            [
                Val::from_u64(3),
                Val::from_u64(5),
                Val::ZERO,
                Val::from_u64(8)
            ];
            n
        ];
        let indices = vec![[WitnessId(1), WitnessId(2), WitnessId(0), WitnessId(3)]; n];

        let trace = AluTrace {
            op_kind,
            values,
            indices,
        };

        let preprocessed_values = AluAir::<Val, 1>::trace_to_preprocessed(&trace);
        let air = AluAir::<Val, 1>::new_with_preprocessed(1, preprocessed_values);
        let matrix: RowMajorMatrix<Val> = air.trace_to_matrix(&trace);
        assert_eq!(matrix.width(), 4);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("verification failed");
    }

    #[test]
    fn prove_verify_alu_mul_base_field() {
        let n = 8;
        let op_kind = vec![AluOpKind::Mul; n];
        let values = vec![
            [
                Val::from_u64(3),
                Val::from_u64(5),
                Val::ZERO,
                Val::from_u64(15)
            ];
            n
        ];
        let indices = vec![[WitnessId(1), WitnessId(2), WitnessId(0), WitnessId(3)]; n];

        let trace = AluTrace {
            op_kind,
            values,
            indices,
        };

        let preprocessed_values = AluAir::<Val, 1>::trace_to_preprocessed(&trace);
        let air = AluAir::<Val, 1>::new_with_preprocessed(1, preprocessed_values);
        let matrix: RowMajorMatrix<Val> = air.trace_to_matrix(&trace);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

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
        let op_kind = vec![AluOpKind::BoolCheck; n];
        let values = (0..n)
            .map(|i| {
                [
                    Val::from_u64(i as u64 % 2),
                    Val::ZERO,
                    Val::ZERO,
                    Val::from_u64(i as u64 % 2),
                ]
            })
            .collect();
        let indices = vec![[WitnessId(1), WitnessId(0), WitnessId(0), WitnessId(1)]; n];

        let trace = AluTrace {
            op_kind,
            values,
            indices,
        };

        let preprocessed_values = AluAir::<Val, 1>::trace_to_preprocessed(&trace);
        let air = AluAir::<Val, 1>::new_with_preprocessed(1, preprocessed_values);
        let matrix: RowMajorMatrix<Val> = air.trace_to_matrix(&trace);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

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
        let op_kind = vec![AluOpKind::MulAdd; n];
        let values = vec![
            [
                Val::from_u64(3),
                Val::from_u64(5),
                Val::from_u64(2),
                Val::from_u64(17)
            ];
            n
        ];
        let indices = vec![[WitnessId(1), WitnessId(2), WitnessId(3), WitnessId(4)]; n];

        let trace = AluTrace {
            op_kind,
            values,
            indices,
        };

        let preprocessed_values = AluAir::<Val, 1>::trace_to_preprocessed(&trace);
        let air = AluAir::<Val, 1>::new_with_preprocessed(1, preprocessed_values);
        let matrix: RowMajorMatrix<Val> = air.trace_to_matrix(&trace);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("verification failed");
    }

    #[test]
    fn prove_verify_alu_mixed_ops() {
        // Mix of ADD and MUL operations
        let op_kind = vec![AluOpKind::Add, AluOpKind::Mul];
        let values = vec![
            [
                Val::from_u64(3),
                Val::from_u64(5),
                Val::ZERO,
                Val::from_u64(8),
            ],
            [
                Val::from_u64(4),
                Val::from_u64(6),
                Val::ZERO,
                Val::from_u64(24),
            ],
        ];
        let indices = vec![
            [WitnessId(1), WitnessId(2), WitnessId(0), WitnessId(3)],
            [WitnessId(1), WitnessId(2), WitnessId(0), WitnessId(3)],
        ];

        let trace = AluTrace {
            op_kind,
            values,
            indices,
        };

        let preprocessed_values = AluAir::<Val, 1>::trace_to_preprocessed(&trace);
        let air = AluAir::<Val, 1>::new_with_preprocessed(1, preprocessed_values);
        let matrix: RowMajorMatrix<Val> = air.trace_to_matrix(&trace);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];
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
            values: vec![[a, b, c, out]; n],
            indices: vec![[WitnessId(1), WitnessId(2), WitnessId(0), WitnessId(3)]; n],
        };

        let preprocessed_values = AluAir::<Val, 4>::trace_to_preprocessed(&trace);

        let config = build_test_config();
        let pis: Vec<Val> = vec![];

        // Get w from the extension field
        let w = Val::from_u64(11); // BabyBear's binomial extension uses w=11

        let air = AluAir::<Val, 4>::new_binomial_with_preprocessed(1, w, preprocessed_values);
        let matrix: RowMajorMatrix<Val> = air.trace_to_matrix(&trace);
        assert_eq!(matrix.width(), AluAir::<Val, 4>::lane_width());
        let (prover_data, verifier_data) =
            setup_preprocessed(&config, &air, log2_ceil_usize(matrix.height())).unwrap();
        let proof = prove_with_preprocessed(&config, &air, matrix, &pis, Some(&prover_data));
        verify_with_preprocessed(&config, &air, &proof, &pis, Some(&verifier_data))
            .expect("extension field verification failed");
    }

    #[test]
    fn test_alu_air_constraint_degree() {
        let preprocessed = vec![Val::ZERO; 8 * 12]; // 8 ops * 12 preprocessed columns per op
        let air = AluAir::<Val, 1>::new_with_preprocessed(2, preprocessed);
        p3_test_utils::assert_air_constraint_degree!(air, "AluAir");
    }
}
