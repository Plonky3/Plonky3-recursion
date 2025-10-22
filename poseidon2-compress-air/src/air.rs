use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeCharacteristicRing;
use p3_matrix::Matrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{Poseidon2Air, RoundConstants};

use crate::{Poseidon2CompressCols, num_cols};

/// Extends the Poseidon2 AIR with recursion circuit-specific columns and constraints.
/// Assumes the field size is at least 16 bits.
///
/// It compresses `N` chunks of size 'CHUNK' of degree-`D` extension field elements into one chunk.
#[derive(Debug)]
pub struct Poseidon2CompressAir<
    F: PrimeCharacteristicRing,
    LinearLayers,
    const D: usize,
    const N: usize,
    const WIDTH: usize,
    const CHUNK: usize,
    const INPUT_EXTF: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> {
    p3_poseidon2: Poseidon2Air<
        F,
        LinearLayers,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
}

impl<
    F: PrimeCharacteristicRing,
    LinearLayers,
    const D: usize,
    const N: usize,
    const WIDTH: usize,
    const CHUNK: usize,
    const INPUT_EXTF: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>
    Poseidon2CompressAir<
        F,
        LinearLayers,
        D,
        N,
        WIDTH,
        CHUNK,
        INPUT_EXTF,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >
{
    pub const fn new(
        constants: RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    ) -> Self {
        assert!(CHUNK * N == INPUT_EXTF);
        assert!(D * INPUT_EXTF == WIDTH);

        Self {
            p3_poseidon2: Poseidon2Air::new(constants),
        }
    }
}

impl<
    F: PrimeCharacteristicRing + Sync,
    LinearLayers: Sync,
    const D: usize,
    const N: usize,
    const WIDTH: usize,
    const CHUNK: usize,
    const INPUT_EXTF: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> BaseAir<F>
    for Poseidon2CompressAir<
        F,
        LinearLayers,
        D,
        N,
        WIDTH,
        CHUNK,
        INPUT_EXTF,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >
{
    fn width(&self) -> usize {
        num_cols::<
            WIDTH,
            CHUNK,
            INPUT_EXTF,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >()
    }
}

pub(crate) fn eval<
    AB: AirBuilder,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
    const D: usize,
    const N: usize,
    const WIDTH: usize,
    const CHUNK: usize,
    const INPUT_EXTF: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>(
    air: &Poseidon2CompressAir<
        AB::F,
        LinearLayers,
        D,
        N,
        WIDTH,
        CHUNK,
        INPUT_EXTF,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
    builder: &mut AB,
    _local: &Poseidon2CompressCols<
        AB::Var,
        WIDTH,
        CHUNK,
        INPUT_EXTF,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
) {
    air.p3_poseidon2.eval(builder);

    // TODO: Add all lookups:
    // - Receive input columns from witness table.
    // - Send output columns to witness table.
}

impl<
    AB: AirBuilder,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
    const D: usize,
    const N: usize,
    const WIDTH: usize,
    const CHUNK: usize,
    const INPUT_EXTF: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> Air<AB>
    for Poseidon2CompressAir<
        AB::F,
        LinearLayers,
        D,
        N,
        WIDTH,
        CHUNK,
        INPUT_EXTF,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >
{
    #[inline]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("The matrix is empty?");
        let local = (*local).borrow();

        eval::<
            _,
            _,
            D,
            N,
            WIDTH,
            CHUNK,
            INPUT_EXTF,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >(self, builder, local);
    }
}
