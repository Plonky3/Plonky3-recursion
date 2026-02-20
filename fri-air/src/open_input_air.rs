use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_circuit::ops::open_input::{OpenInputRow, OpenInputTrace};
use p3_circuit::tables::NonPrimitiveTrace;
use p3_circuit::{CircuitError, NonPrimitiveOpType};
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeField};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

#[derive(Debug, Clone)]
pub struct OpenInputAir<F, const D: usize = 1> {
    pub preprocessed: Vec<F>,
    pub min_height: usize,
    pub num_lookup_columns: usize,
}

impl<F: Field, const D: usize> OpenInputAir<F, D> {
    pub const fn new() -> Self {
        Self {
            preprocessed: Vec::new(),
            min_height: 1,
            num_lookup_columns: 0,
        }
    }

    pub const fn new_with_preprocessed(preprocessed: Vec<F>) -> Self {
        Self {
            preprocessed,
            min_height: 1,
            num_lookup_columns: 0,
        }
    }

    pub const fn width() -> usize {
        7 * D
    }

    pub const fn preprocessed_width() -> usize {
        6 // Indices for alpha, x, z, p_at_x, p_at_z, ro. We don't need to keep track of alpha_pow's index
        + 1 // ìs_last
    }

    pub fn trace_to_matrix<ExtF: ExtensionField<F>>(
        &self,
        open_input_ops: &[OpenInputRow<ExtF>],
    ) -> RowMajorMatrix<F> {
        let n = open_input_ops.len();
        let new_n = n.next_power_of_two();

        let mut values = Vec::with_capacity(new_n * Self::width());

        let mut alpha_pow = if open_input_ops.is_empty() {
            ExtF::ZERO
        } else {
            open_input_ops[0].alpha[0]
        };
        let mut ro = ExtF::ZERO;
        let mut reset = false;

        for row in open_input_ops {
            debug_assert_eq!(row.alpha.len(), 1);
            debug_assert_eq!(row.x.len(), 1);
            debug_assert_eq!(row.z.len(), 1);
            debug_assert_eq!(row.pow_at_x.len(), 1);
            debug_assert_eq!(row.pow_at_z.len(), 1);

            if reset {
                alpha_pow = row.alpha[0];
                ro = ExtF::ZERO;
            }

            let new_ro =
                ro + alpha_pow * (row.pow_at_z[0] - row.pow_at_x[0]) / (row.z[0] - row.x[0]);
            let new_alpha_pow = alpha_pow * row.alpha[0];

            let alpha = row.alpha[0].as_basis_coefficients_slice();
            let x = row.x[0].as_basis_coefficients_slice();
            let z = row.z[0].as_basis_coefficients_slice();
            let alpha_pow_basis = alpha_pow.as_basis_coefficients_slice();
            let pow_at_x = row.pow_at_x[0].as_basis_coefficients_slice();
            let pow_at_z = row.pow_at_z[0].as_basis_coefficients_slice();
            let ro_basis = new_ro.as_basis_coefficients_slice();

            debug_assert_eq!(alpha.len(), D);
            debug_assert_eq!(x.len(), D);
            debug_assert_eq!(z.len(), D);
            debug_assert_eq!(alpha_pow_basis.len(), D);
            debug_assert_eq!(pow_at_x.len(), D);
            debug_assert_eq!(pow_at_z.len(), D);
            debug_assert_eq!(ro_basis.len(), D);

            values.extend_from_slice(alpha);
            values.extend_from_slice(alpha_pow_basis);
            values.extend_from_slice(x);
            values.extend_from_slice(z);
            values.extend_from_slice(pow_at_x);
            values.extend_from_slice(pow_at_z);
            values.extend_from_slice(ro_basis);

            ro = new_ro;
            alpha_pow = new_alpha_pow;
            if row.is_last {
                reset = true;
            } else {
                reset = false;
            }
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
                [
                    F::from_u64(row.alpha_index as u64),
                    F::from_u64(row.x_index as u64),
                    F::from_u64(row.z_index as u64),
                    F::from_u64(row.pow_at_x_index as u64),
                    F::from_u64(row.pow_at_z_index as u64),
                    F::from_u64(row.is_last as u64),
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

impl<AB: AirBuilder, const D: usize> Air<AB> for OpenInputAir<AB::F, D>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        debug_assert_eq!(main.width(), self.width(), "column width mismatch");

        let local = main.row_slice(0).expect("matrix must be non-empty");

        let preprocessed = builder
            .preprocessed()
            .expect("OpenInputAir requires preprocessed trace");
        let preprocessed_local = preprocessed
            .row_slice(0)
            .expect("preprocessed trace must be non-empty");

        builder.when_first_row();
    }
}
