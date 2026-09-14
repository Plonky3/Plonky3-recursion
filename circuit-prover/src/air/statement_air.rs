//! AIR for one ordered, fixed-width statement row.

use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_lookup::{Count, InteractionBuilder};
use p3_matrix::dense::RowMajorMatrix;

/// One active statement row followed by canonical inactive zero padding.
#[derive(Clone, Debug)]
pub struct StatementAir<F, const D: usize> {
    public_len: usize,
    preprocessed: Vec<F>,
    min_height: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field + PrimeCharacteristicRing, const D: usize> StatementAir<F, D> {
    pub const fn new_with_preprocessed(
        public_len: usize,
        preprocessed: Vec<F>,
        min_height: usize,
    ) -> Self {
        Self {
            public_len,
            preprocessed,
            min_height,
            _phantom: PhantomData,
        }
    }

    pub const fn public_len(&self) -> usize {
        self.public_len
    }

    pub const fn preprocessed_row_width(&self) -> usize {
        1 + self.public_len
    }

    pub fn trace_to_matrix(values: &[F]) -> RowMajorMatrix<F> {
        let mut matrix = RowMajorMatrix::new(values.to_vec(), values.len());
        matrix.pad_to_power_of_two_height(F::ZERO);
        matrix
    }
}

impl<F: Field, const D: usize> BaseAir<F> for StatementAir<F, D> {
    fn width(&self) -> usize {
        self.public_len
    }

    fn num_public_values(&self) -> usize {
        self.public_len
    }

    fn preprocessed_width(&self) -> usize {
        self.preprocessed_row_width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        let mut matrix = RowMajorMatrix::from_flat_padded(
            self.preprocessed.clone(),
            self.preprocessed_row_width(),
            F::ZERO,
        );
        matrix.pad_to_min_power_of_two_height(self.min_height, F::ZERO);
        Some(matrix)
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }

    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}

impl<AB: AirBuilder + InteractionBuilder, const D: usize> Air<AB> for StatementAir<AB::F, D>
where
    AB::F: Field,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let main_local = main.current_slice();
        let prep = builder.preprocessed().clone();
        let prep_local = prep.current_slice();
        let public: Vec<AB::Expr> = builder
            .public_values()
            .iter()
            .map(|value| (*value).into())
            .collect();
        let active: AB::Expr = prep_local[0].into();

        for slot in 0..self.public_len {
            let value: AB::Expr = main_local[slot].into();
            let expected = public[slot].clone();
            builder.assert_zero(active.clone() * (value.clone() - expected));
            builder.assert_zero((AB::Expr::ONE - active.clone()) * value.clone());

            let mut tuple = Vec::with_capacity(1 + D);
            tuple.push(prep_local[1 + slot].into());
            tuple.push(value);
            tuple.extend((1..D).map(|_| AB::Expr::ZERO));
            builder.push_interaction(
                "WitnessChecks",
                tuple,
                Count::bounded(AB::Expr::ZERO - active.clone(), 1),
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_air::check_constraints;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_test_utils::baby_bear_params::{BabyBear, PrimeCharacteristicRing};

    use super::StatementAir;

    fn padded_main(first: [BabyBear; 2]) -> RowMajorMatrix<BabyBear> {
        RowMajorMatrix::new(
            vec![
                first[0],
                first[1],
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO,
            ],
            2,
        )
    }

    #[test]
    fn active_row_equals_public_values_and_inactive_padding_is_zero() {
        let air = StatementAir::<BabyBear, 4>::new_with_preprocessed(
            2,
            vec![BabyBear::ONE, BabyBear::ZERO, BabyBear::from_u64(4)],
            4,
        );
        check_constraints(
            &air,
            &padded_main([BabyBear::from_u64(9), BabyBear::from_u64(10)]),
            &[BabyBear::from_u64(9), BabyBear::from_u64(10)],
        );
    }

    /// Removing the active-row equality constraint makes this test stop rejecting.
    #[test]
    #[should_panic(expected = "constraints not satisfied on row 0")]
    fn active_row_rejects_a_wrong_public_value() {
        let air = StatementAir::<BabyBear, 4>::new_with_preprocessed(
            2,
            vec![BabyBear::ONE, BabyBear::ZERO, BabyBear::from_u64(4)],
            4,
        );
        check_constraints(
            &air,
            &padded_main([BabyBear::from_u64(9), BabyBear::from_u64(10)]),
            &[BabyBear::from_u64(9), BabyBear::from_u64(99)],
        );
    }

    /// Removing `(1-active) * main = 0` makes noncanonical padding pass.
    #[test]
    #[should_panic(expected = "constraints not satisfied on row 1")]
    fn inactive_padding_rejects_nonzero_values() {
        let air = StatementAir::<BabyBear, 4>::new_with_preprocessed(
            2,
            vec![BabyBear::ONE, BabyBear::ZERO, BabyBear::from_u64(4)],
            4,
        );
        let mut main = padded_main([BabyBear::from_u64(9), BabyBear::from_u64(10)]);
        main.values[3] = BabyBear::ONE;
        check_constraints(
            &air,
            &main,
            &[BabyBear::from_u64(9), BabyBear::from_u64(10)],
        );
    }
}
