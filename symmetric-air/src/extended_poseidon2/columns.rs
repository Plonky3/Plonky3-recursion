//! Column definitions for extended Poseidon2 AIR with circuit indices.

use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use p3_poseidon2_air::Poseidon2Cols;

/// Extended Poseidon2 columns with circuit integration.
///
/// This extends the base Poseidon2 permutation with:
/// - Full Poseidon2Cols from base AIR (validates permutation correctness)
/// - Input/output witness indices for circuit wiring
/// - Support for lookups from SpongeAir
#[repr(C)]
pub struct ExtendedPoseidon2Cols<
    T,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> {
    /// The full Poseidon2 columns (for permutation validation)
    pub poseidon2:
        Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,

    /// Witness indices for input values (for circuit lookups)
    /// These allow the SpongeAir to reference specific circuit witnesses
    pub input_indices: [T; WIDTH],

    /// Witness indices for output values (for circuit lookups)
    pub output_indices: [T; WIDTH],
}

pub const fn num_cols<
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>() -> usize {
    size_of::<
        ExtendedPoseidon2Cols<
            u8,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >,
    >()
}

impl<
    T,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>
    Borrow<
        ExtendedPoseidon2Cols<
            T,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >,
    > for [T]
{
    fn borrow(
        &self,
    ) -> &ExtendedPoseidon2Cols<
        T,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    > {
        let (prefix, shorts, suffix) = unsafe {
            self.align_to::<ExtendedPoseidon2Cols<
                T,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >>()
        };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<
    T,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>
    BorrowMut<
        ExtendedPoseidon2Cols<
            T,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >,
    > for [T]
{
    fn borrow_mut(
        &mut self,
    ) -> &mut ExtendedPoseidon2Cols<
        T,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    > {
        let (prefix, shorts, suffix) = unsafe {
            self.align_to_mut::<ExtendedPoseidon2Cols<
                T,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >>()
        };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_num_cols_babybear() {
        // BabyBear Poseidon2: WIDTH=16, SBOX_DEGREE=7, SBOX_REGISTERS=0, HALF_FULL_ROUNDS=4, PARTIAL_ROUNDS=13
        // Base Poseidon2 columns + input_indices(16) + output_indices(16)
        let cols = num_cols::<16, 7, 0, 4, 13>();
        // Base has: export(1) + inputs(16) + rounds + indices(32)
        assert!(cols > 48); // At least base + indices
    }
}
