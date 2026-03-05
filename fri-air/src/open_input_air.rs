use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::iter;

use p3_air::lookup::{Direction, Kind, Lookup};
use p3_air::{Air, AirBuilder, BaseAir, PermutationAirBuilder, SymbolicExpression};
use p3_circuit::ops::open_input::{OpenInputRow, OpenInputTrace};
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::SymbolicAirBuilder;

#[derive(Debug, Clone)]
pub struct OpenInputAir<F, const D: usize = 1> {
    pub w_binomial: F,
    pub generator: F, // Coset generator (F::GENERATOR) for EvalPoint constraints
    pub preprocessed: Vec<F>,
    pub min_height: usize,
    pub num_lookup_columns: usize,
}

impl<F: Field, const D: usize> OpenInputAir<F, D> {
    pub const fn new(w_binomial: F) -> Self {
        Self {
            w_binomial,
            generator: F::ZERO, // Will be set properly when EvalPoint rows are used
            preprocessed: Vec::new(),
            min_height: 1,
            num_lookup_columns: 0,
        }
    }

    pub const fn new_with_preprocessed(w_binomial: F, preprocessed: Vec<F>) -> Self {
        Self {
            w_binomial,
            generator: F::ZERO,
            preprocessed,
            min_height: 1,
            num_lookup_columns: 0,
        }
    }

    pub const fn with_generator(mut self, generator: F) -> Self {
        self.generator = generator;
        self
    }

    pub const fn with_min_height(mut self, min_height: usize) -> Self {
        self.min_height = min_height;
        self
    }

    pub const fn width() -> usize {
        4 * D
    }

    pub const fn preprocessed_width() -> usize {
        4 // Indices for alpha, p_at_x, p_at_z, ro.
        + 2 // is_last and is_real
        + 1 // ro_ext_mult: creator multiplicity for ro output (= ext_reads[ro_wid])
        + 1 // is_eval: 1 for EvalPoint rows, 0 for ReducedOpening rows
        + 1 // g_power: g^(2^i) for EvalPoint rows, 0 otherwise
    }

    pub fn trace_to_matrix<ExtF: ExtensionField<F>>(
        &self,
        open_input_ops: &[OpenInputRow<ExtF>],
    ) -> RowMajorMatrix<F> {
        let n = open_input_ops.len();
        let new_n = n.next_power_of_two();

        let mut values = Vec::with_capacity(new_n * Self::width());

        let mut ro = ExtF::ZERO;
        let mut reset = true;

        let generator_ef = ExtF::from(self.generator);

        for row in open_input_ops {
            if row.is_eval {
                // EvalPoint row: compute eval accumulator
                debug_assert_eq!(row.pow_at_x.len(), 1);

                if reset {
                    ro = ExtF::ZERO; // Will be overwritten below
                }

                let rev_bit = row.pow_at_x[0];
                let g_power = row.g_power;
                let mult = ExtF::ONE + rev_bit * (g_power - ExtF::ONE);

                let eval = if reset {
                    // First in sequence
                    generator_ef * mult
                } else {
                    ro * mult
                };

                // alpha columns: zeros
                for _ in 0..D {
                    values.push(F::ZERO);
                }
                // pow_at_x columns: [rev_bit, 0, ..., 0]
                let rev_bit_basis = rev_bit.as_basis_coefficients_slice();
                values.extend_from_slice(rev_bit_basis);
                // pow_at_z columns: zeros
                for _ in 0..D {
                    values.push(F::ZERO);
                }
                // ro columns: [eval, 0, ..., 0] (base field value in first component)
                let eval_basis = eval.as_basis_coefficients_slice();
                values.extend_from_slice(eval_basis);

                ro = eval;
            } else {
                // ReducedOpening row: original logic
                debug_assert_eq!(row.alpha.len(), 1);
                debug_assert_eq!(row.pow_at_x.len(), 1);
                debug_assert_eq!(row.pow_at_z.len(), 1);

                if reset {
                    ro = ExtF::ZERO;
                }

                let new_ro = ro * row.alpha[0] + (row.pow_at_z[0] - row.pow_at_x[0]);

                let alpha = row.alpha[0].as_basis_coefficients_slice();
                let pow_at_x = row.pow_at_x[0].as_basis_coefficients_slice();
                let pow_at_z = row.pow_at_z[0].as_basis_coefficients_slice();
                let new_ro_basis = new_ro.as_basis_coefficients_slice();

                debug_assert_eq!(alpha.len(), D);
                debug_assert_eq!(pow_at_x.len(), D);
                debug_assert_eq!(pow_at_z.len(), D);
                debug_assert_eq!(new_ro_basis.len(), D);

                values.extend_from_slice(alpha);
                values.extend_from_slice(pow_at_x);
                values.extend_from_slice(pow_at_z);
                values.extend_from_slice(new_ro_basis);

                ro = new_ro;
            }

            reset = row.is_last;
        }
        for _ in n..new_n {
            values.extend_from_slice(&vec![F::ZERO; Self::width()]);
        }

        RowMajorMatrix::new(values, Self::width())
    }

    pub fn trace_to_preprocessed<ExtF: BasedVectorSpace<F>>(
        trace: &OpenInputTrace<ExtF>,
    ) -> Vec<F> {
        trace
            .rows
            .iter()
            .flat_map(|row| {
                // g_power is a base field element embedded in ExtF; extract the first coefficient.
                let g_power_base = row.g_power.as_basis_coefficients_slice()[0];
                [
                    F::from_u64(row.is_last as u64),
                    F::from_u64(row.is_real as u64),
                    F::from_u64(row.alpha_index as u64),
                    F::from_u64(row.pow_at_x_index as u64),
                    F::from_u64(row.pow_at_z_index as u64),
                    F::from_u64(row.ro_index as u64),
                    F::ZERO, // ro_ext_mult placeholder (populated by committed preprocessed)
                    F::from_u64(row.is_eval as u64),
                    g_power_base,
                ]
            })
            .collect()
    }
}

impl<F: Field + Sync, const D: usize> BaseAir<F> for OpenInputAir<F, D> {
    fn width(&self) -> usize {
        Self::width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        debug_assert!(
            self.preprocessed
                .len()
                .is_multiple_of(Self::preprocessed_width()),
            "Preprocessed trace length is not a multiple of preprocessed width. Expected multiple of {}, got {}",
            Self::preprocessed_width(),
            self.preprocessed.len(),
        );

        let width = Self::preprocessed_width();
        let natural_rows = self.preprocessed.len() / width;
        let num_extra_rows = natural_rows
            .next_power_of_two()
            .saturating_sub(natural_rows);

        let mut preprocessed = self.preprocessed.clone();
        let start_len = preprocessed.len();
        preprocessed.resize(start_len + num_extra_rows * width, F::ZERO);

        let mut mat = RowMajorMatrix::new(preprocessed, width);
        let current_height = mat.height();

        let target_height = current_height
            .next_power_of_two()
            .max(self.min_height.next_power_of_two());
        if current_height < target_height {
            let padding_rows = target_height - current_height;
            mat.values
                .extend(core::iter::repeat_n(F::ZERO, padding_rows * width));
        }

        Some(mat)
    }
}

fn extension_multiplication<AB: AirBuilder, const D: usize>(
    w_binomial: AB::Expr,
    a: &[AB::Expr; D],
    b: &[AB::Expr; D],
) -> [AB::Expr; D]
where
    AB::F: Field,
{
    debug_assert_eq!(a.len(), b.len());
    // MUL constraints: extension field multiplication
    let mut mul_acc = [AB::Expr::ZERO; D];
    for i in 0..D {
        for j in 0..D {
            let term = a[i].clone() * b[j].clone();
            let k = i + j;
            if k < D {
                mul_acc[k] = mul_acc[k].clone() + term;
            } else {
                mul_acc[k - D] = mul_acc[k - D].clone() + w_binomial.clone() * term;
            }
        }
    }
    mul_acc
}

fn sub_extension<AB: AirBuilder, const D: usize>(
    a: &[AB::Expr; D],
    b: &[AB::Expr; D],
) -> [AB::Expr; D] {
    debug_assert_eq!(a.len(), b.len());
    let mut result = [AB::Expr::ZERO; D];
    for i in 0..D {
        result[i] = a[i].clone() - b[i].clone();
    }
    result
}

impl<AB: AirBuilder, const D: usize> Air<AB> for OpenInputAir<AB::F, D>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        debug_assert_eq!(main.width(), self.width(), "column width mismatch");

        let local = main.row_slice(0).expect("matrix must be non-empty");
        let next = main.row_slice(1).expect("matrix must have at least 2 rows");

        let preprocessed = builder
            .preprocessed()
            .expect("OpenInputAir requires preprocessed trace");
        let preprocessed_local = preprocessed
            .row_slice(0)
            .expect("preprocessed trace must be non-empty");
        let preprocessed_next = preprocessed
            .row_slice(1)
            .expect("preprocessed trace must have at least 2 rows");

        // Current row traced columns.
        let w = AB::Expr::from(self.w_binomial);
        let alpha: &[AB::Expr; D] = &core::array::from_fn(|i| AB::Expr::from(local[i]));
        let pow_at_x: &[AB::Expr; D] = &core::array::from_fn(|i| AB::Expr::from(local[D + i]));
        let pow_at_z: &[AB::Expr; D] = &core::array::from_fn(|i| AB::Expr::from(local[2 * D + i]));
        let ro: &[AB::Expr; D] = &core::array::from_fn(|i| AB::Expr::from(local[3 * D + i]));

        // Next row traced columns.
        let alpha_next: &[AB::Expr; D] = &core::array::from_fn(|i| AB::Expr::from(next[i]));
        let pow_at_x_next: &[AB::Expr; D] = &core::array::from_fn(|i| AB::Expr::from(next[D + i]));
        let pow_at_z_next: &[AB::Expr; D] =
            &core::array::from_fn(|i| AB::Expr::from(next[2 * D + i]));
        let ro_next: &[AB::Expr; D] = &core::array::from_fn(|i| AB::Expr::from(next[3 * D + i]));

        // Preprocessed columns (current row).
        let is_last = AB::Expr::from(preprocessed_local[0]);
        let not_is_last = AB::Expr::ONE - is_last.clone();
        let is_eval = AB::Expr::from(preprocessed_local[7]);
        let not_is_eval = AB::Expr::ONE - is_eval.clone();
        let g_power = AB::Expr::from(preprocessed_local[8]);

        // Preprocessed columns (next row).
        let is_eval_next = AB::Expr::from(preprocessed_next[7]);
        let not_is_eval_next = AB::Expr::ONE - is_eval_next.clone();
        let g_power_next = AB::Expr::from(preprocessed_next[8]);

        let generator = AB::Expr::from(self.generator);

        // ===== Common constraints =====

        // Assert that `is_last` is boolean.
        builder.assert_bool(is_last.clone());

        // ===== ReducedOpening constraints (multiplied by 1 - is_eval) =====

        // First row init: ro = p_at_z - p_at_x
        let p_at_z_minus_pow_at_x: [AB::Expr; D] = sub_extension::<AB, D>(pow_at_z, pow_at_x);
        for i in 0..D {
            builder.when_first_row().assert_zero(
                not_is_eval.clone() * (ro[i].clone() - p_at_z_minus_pow_at_x[i].clone()),
            );
        }

        // Transition recurrence: ro_next = ro * alpha_next + (p_at_z_next - p_at_x_next)
        let ro_mul_alpha = extension_multiplication::<AB, D>(w, ro, alpha_next);
        let p_at_z_minus_pow_at_x_next: [AB::Expr; D] =
            sub_extension::<AB, D>(pow_at_z_next, pow_at_x_next);
        let lhs: [AB::Expr; D] = sub_extension::<AB, D>(ro_next, &p_at_z_minus_pow_at_x_next);
        let ro_constraint: [AB::Expr; D] = sub_extension::<AB, D>(&lhs, &ro_mul_alpha);
        for i in 0..D {
            builder
                .when_transition()
                .assert_zero(not_is_eval.clone() * not_is_last.clone() * ro_constraint[i].clone());
        }

        // Alpha unchanged when not is_last (ReducedOpening only).
        for i in 0..D {
            builder
                .when_transition()
                .when(not_is_last.clone())
                .assert_zero(not_is_eval.clone() * (alpha_next[i].clone() - alpha[i].clone()));
        }

        // After is_last, init the next ReducedOpening sequence: ro_next = p_at_z_next - p_at_x_next
        for i in 0..D {
            builder.when_transition().assert_zero(
                is_last.clone()
                    * not_is_eval_next.clone()
                    * (ro_next[i].clone() - p_at_z_minus_pow_at_x_next[i].clone()),
            );
        }

        // ===== EvalPoint constraints =====
        // mult = 1 + rev_bit * (g_power - 1)
        // And rev_bit = pow_at_x[0] when the operation is EvalPoint

        // First row init: ro[0] = mult * GENERATOR, ro[1..D] = 0
        let mult_local = AB::Expr::ONE + pow_at_x[0].clone() * (g_power - AB::Expr::ONE);
        for j in 0..D {
            if j == 0 {
                builder.when_first_row().assert_zero(
                    is_eval.clone() * (ro[0].clone() - mult_local.clone() * generator.clone()),
                );
            } else {
                builder
                    .when_first_row()
                    .assert_zero(is_eval.clone() * ro[j].clone());
            }
        }

        // After is_last, init next EvalPoint sequence: ro_next[0] = mult_next * GENERATOR
        let mult_next = AB::Expr::ONE + pow_at_x_next[0].clone() * (g_power_next - AB::Expr::ONE);
        for j in 0..D {
            if j == 0 {
                builder.when_transition().assert_zero(
                    is_last.clone()
                        * is_eval_next.clone()
                        * (ro_next[0].clone() - mult_next.clone() * generator.clone()),
                );
            } else {
                builder
                    .when_transition()
                    .assert_zero(is_last.clone() * is_eval_next.clone() * ro_next[j].clone());
            }
        }

        // Transition: ro_next[0] = ro[0] * mult_next, ro_next[1..D] = 0
        for j in 0..D {
            if j == 0 {
                builder.when_transition().assert_zero(
                    is_eval_next.clone()
                        * not_is_last.clone()
                        * (ro_next[0].clone() - ro[0].clone() * mult_next.clone()),
                );
            } else {
                builder
                    .when_transition()
                    .assert_zero(is_eval_next.clone() * not_is_last.clone() * ro_next[j].clone());
            }
        }

        // p_at_x[0] is boolean for EvalPoint rows.
        builder.assert_zero(
            is_eval.clone() * pow_at_x[0].clone() * (AB::Expr::ONE - pow_at_x[0].clone()),
        );

        // p_at_x[1..D] must be zero for EvalPoint rows.
        for j in 1..D {
            builder.assert_zero(is_eval.clone() * pow_at_x[j].clone());
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
        let symbolic_air_builder =
            SymbolicAirBuilder::<AB::F>::new(Self::preprocessed_width(), Self::width(), 0, 0, 0, 0);

        let symbolic_main = symbolic_air_builder.main();
        let symbolic_main_local = symbolic_main.row_slice(0).unwrap().to_vec();

        let preprocessed = symbolic_air_builder
            .preprocessed()
            .expect("Expected preprocessed columns");
        let preprocessed_local = preprocessed.row_slice(0).unwrap().to_vec();
        // Preprocessed layout per row (9 columns):
        //   [0] is_last, [1] is_real,
        //   [2] alpha_idx, [3] p_at_x_idx, [4] p_at_z_idx, [5] ro_idx,
        //   [6] ro_ext_mult, [7] is_eval, [8] g_power
        let is_real = SymbolicExpression::from(preprocessed_local[1]);
        let ro_ext_mult = SymbolicExpression::from(preprocessed_local[6]);
        let is_eval = SymbolicExpression::from(preprocessed_local[7]);
        let not_is_eval = SymbolicExpression::ONE - is_eval;

        let kind = Kind::Global("WitnessChecks".to_string());

        // Inputs are READS from the bus → Send (negative multiplicity).
        // alpha (i=0) and p_at_z (i=2): multiplicity = is_real * (1 - is_eval)
        // p_at_x (i=1): multiplicity = is_real (active for both op types)
        let global_lookups = (0..3).map(|i| {
            let index = SymbolicExpression::from(preprocessed_local[2 + i]);
            let values = (0..D).map(|j| SymbolicExpression::from(symbolic_main_local[i * D + j]));

            let inputs = iter::once(index).chain(values).collect::<Vec<_>>();

            let multiplicity = if i == 0 || i == 2 {
                // alpha and p_at_z: disabled for EvalPoint rows
                is_real.clone() * not_is_eval.clone()
            } else {
                // p_at_x: active for both (reads rev_bit for EvalPoint, p_at_x for ReducedOpening)
                is_real.clone()
            };

            (inputs, multiplicity, Direction::Send)
        });

        // ro is an OUTPUT created by this table → Receive (positive multiplicity).
        // Multiplicity = ro_ext_mult = ext_reads[ro_wid] (set by prover preprocessing).
        // On non-last rows ro_ext_mult is 0, so no bus contribution.
        let ro_idx = SymbolicExpression::from(preprocessed_local[5]);
        let ro = (0..D).map(|i| SymbolicExpression::from(symbolic_main_local[3 * D + i]));
        let ro_inputs = iter::once(ro_idx).chain(ro).collect::<Vec<_>>();

        let ro_inputs = (ro_inputs, ro_ext_mult, Direction::Receive);
        let ro_lookup = <Self as Air<AB>>::register_lookup(self, kind.clone(), &[ro_inputs]);
        let mut lookups = vec![];
        lookups.push(ro_lookup);

        lookups.extend(
            global_lookups
                .into_iter()
                .map(|l| <Self as Air<AB>>::register_lookup(self, kind.clone(), &[l])),
        );

        lookups
    }
}
