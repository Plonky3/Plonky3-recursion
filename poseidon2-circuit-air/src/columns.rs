use core::borrow::{Borrow, BorrowMut};

use p3_poseidon2_air::Poseidon2Cols;

/// Columns for a Poseidon2 AIR which computes one permutation per row.
///
/// They extend the P3 columns with some circuit-specific columns.
///
/// `is_sponge` (transparent): if `1`, this row performs a sponge operation (absorb or squeeze);
/// otherwise, it performs a compression.
/// `reset` (transparent): indicates whether the state is being reset this row.
/// `sponge_reset`: auxiliary column to keep constraint degrees below three.
/// `absorb_flags` (transparent): for each rate element, indicates if it is being absorbed this row.
/// At most one flag is set to 1 per row: if `absorb_flags[i]` is 1, then all elements up to the `i`-th
/// are absorbed; the rest are propagated from the previous row.
/// `input_indices` (transparent): for each input element, indicates the index in the witness table for the
/// memory lookup. It's either received (for an absorb or a compression) or sent (for a squeeze).
/// `output_indices` (transparent): for each output element, indicates the index in the witness table for the
/// memory lookup. Only used by compressions to send the output.
#[repr(C)]
pub struct Poseidon2CircuitCols<
    T,
    const WIDTH_EXT: usize,
    const RATE_EXT: usize,
    P: PermutationColumns<T>,
> {
    pub poseidon2: P,
    pub is_sponge: T,
    pub reset: T,
    pub sponge_reset: T,
    pub absorb_flags: [T; RATE_EXT],
    pub input_indices: [T; WIDTH_EXT],
    pub output_indices: [T; RATE_EXT],
}

pub trait PermutationColumns<T> {}

impl<
    T,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> PermutationColumns<T>
    for Poseidon2Cols<T, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>
{
}

pub const fn num_cols<const WIDTH_EXT: usize, const RATE_EXT: usize, P: PermutationColumns<u8>>()
-> usize {
    size_of::<Poseidon2CircuitCols<u8, WIDTH_EXT, RATE_EXT, P>>()
}

impl<T, const WIDTH_EXT: usize, const RATE_EXT: usize, P: PermutationColumns<T>>
    Borrow<Poseidon2CircuitCols<T, WIDTH_EXT, RATE_EXT, P>> for [T]
{
    fn borrow(&self) -> &Poseidon2CircuitCols<T, WIDTH_EXT, RATE_EXT, P> {
        let (prefix, shorts, suffix) =
            unsafe { self.align_to::<Poseidon2CircuitCols<T, WIDTH_EXT, RATE_EXT, P>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T, const WIDTH_EXT: usize, const RATE_EXT: usize, P: PermutationColumns<T>>
    BorrowMut<Poseidon2CircuitCols<T, WIDTH_EXT, RATE_EXT, P>> for [T]
{
    fn borrow_mut(&mut self) -> &mut Poseidon2CircuitCols<T, WIDTH_EXT, RATE_EXT, P> {
        let (prefix, shorts, suffix) =
            unsafe { self.align_to_mut::<Poseidon2CircuitCols<T, WIDTH_EXT, RATE_EXT, P>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}
