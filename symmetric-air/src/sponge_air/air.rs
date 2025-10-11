//! An AIR for a sponge construction using an arbitrary permutation on field elements.
//!
//! We instantiate a duplex challenger in overwrite mode: at each row, the challenger applies
//! one permutation.
//! Depending on the situation, the rate part of the state comes either from the input
//! (during absorbing) or is the output of the previous row (during squeezing).
//! When we want to clear the state, we set the `reset` flag to 1 to clear the capacity.
//!
//! We assume that the input is correctly padded, and that its length is a multiple of `RATE`.

use core::array;
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
    /// Sponge construction constraints with lookups to Poseidon2Air for permutations.
    #[inline]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let (local, next) = (
            main.row_slice(0).expect("Matrix is empty?"),
            main.row_slice(1).expect("Matrix only has 1 row?"),
        );
        let local: &SpongeCols<AB::Var, RATE, CAPACITY> = (*local).borrow();
        let _next: &SpongeCols<AB::Var, RATE, CAPACITY> = (*next).borrow();

        let _output_mode = AB::Expr::ONE - local.absorb.clone();

        // Constraint 1: reset and absorb are boolean flags
        builder.assert_bool(local.reset.clone());
        builder.assert_bool(local.absorb.clone());

        // Constraint 2: When resetting, capacity is cleared
        // (Rate will be overwritten by input during absorb)
        builder
            .when(local.reset.clone())
            .assert_zeros::<CAPACITY, _>(array::from_fn(|i| local.capacity[i].clone()));

        // Constraint 3: Lookup to ExtendedPoseidon2Air for permutation correctness
        //
        // The permutation is: (local.rate || local.capacity) -> (next.rate || next.capacity)
        // when not resetting and when a permutation is needed.
        //
        // TODO: Add lookup/interaction with ExtendedPoseidon2Air:
        //   send(
        //       local.input_addresses,  // Witness indices for inputs
        //       local.rate ++ local.capacity,  // Input state
        //       next.rate ++ next.capacity     // Output state (from Poseidon2)
        //   )
        //
        // This lookup ensures:
        // - Poseidon2Air validates: output = Poseidon2(input)
        // - Input/output addresses match circuit witness indices
        // - SpongeAir manages state flow and sponge semantics

        // Constraint 4: Input/output wiring (will be handled via lookups)
        //
        // TODO: Add lookups for circuit I/O:
        // - If local.absorb = 1: lookup circuit inputs at local.input_addresses -> local.rate
        // - If local.absorb = 0: send local.rate to circuit outputs at local.input_addresses
    }
}
