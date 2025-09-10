//! An AIR for a sponge construction using an arbitrary permutation on field elements.
//!
//! For each instance, the sponge hashes a certain number of chunks of `RATE` field elements across multiple rows,
//! and outputs exactly one chunk of `RATE` field elements.
//! The sponge is in overwrite mode: at each step, the next `RATE` input elements overwrite the
//! first `RATE` elements of the state, while the capacity is unchanged.
//! On the last row of the instance, the `rate` columns contain the output of the sponge.
//!
//! We assume that the input is correctly padded, and that its length is a multiple of `RATE`.

use core::borrow::Borrow;
use core::marker::PhantomData;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::{PrimeCharacteristicRing, PrimeField};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;

use crate::sponge_air::columns::{SpongeCols, num_cols};

#[derive(Debug)]
pub struct SpongeAir<F: PrimeCharacteristicRing, const RATE: usize, const CAPACITY: usize> {
    _phantom: PhantomData<F>,
}

impl<F, const RATE: usize, const CAPACITY: usize> Default for SpongeAir<F, RATE, CAPACITY>
where
    F: PrimeCharacteristicRing,
{
    fn default() -> Self {
        Self::new()
    }
}

impl<F: PrimeCharacteristicRing, const RATE: usize, const CAPACITY: usize>
    SpongeAir<F, RATE, CAPACITY>
{
    pub const fn new() -> Self {
        Self {
            _phantom: PhantomData,
        }
    }

    pub fn generate_trace_rows(&self) -> RowMajorMatrix<F>
    where
        F: PrimeField,
    {
        todo!()
    }
}

impl<F: PrimeCharacteristicRing + Sync, const RATE: usize, const CAPACITY: usize> BaseAir<F>
    for SpongeAir<F, RATE, CAPACITY>
{
    fn width(&self) -> usize {
        num_cols::<RATE, CAPACITY>()
    }
}

impl<AB: AirBuilder, const RATE: usize, const CAPACITY: usize> Air<AB>
    for SpongeAir<AB::F, RATE, CAPACITY>
{
    #[inline]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (
            main.row_slice(0).expect("Matrix is empty?"),
            main.row_slice(1).expect("Matrix only has 1 row?"),
        );
        let local: &SpongeCols<AB::Var, RATE, CAPACITY> = (*local).borrow();
        let _next: &SpongeCols<AB::Var, RATE, CAPACITY> = (*next).borrow();

        let _is_not_final = AB::Expr::ONE - local.is_final.clone();

        // TODO: Add all lookups.
        todo!()
    }
}
