use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use p3_poseidon2_air::Poseidon2Cols;

pub const POSEIDON2_LIMBS: usize = 4;
pub const POSEIDON2_PUBLIC_OUTPUT_LIMBS: usize = 2;

/// Columns for a Poseidon2 AIR which computes one permutation per row.
///
/// This implements the Poseidon2 Permutation Table specification.
/// See: https://github.com/Plonky3/Plonky3-recursion/discussions/186
///
/// The table implements a WIDTH_EXT-limb Poseidon2 permutation supporting:
/// - Standard chaining (Challenger-style sponge use)
/// - Merkle-path chaining (MMCS directional hashing)
/// - Optional MMCS index accumulator
///
/// Column layout (per spec section 2):
/// - Value columns: `poseidon2` (contains in[0..WIDTH_EXT-1] and out[0..WIDTH_EXT-1]), `mmcs_index_sum`, `mmcs_bit`
#[repr(C)]
pub struct Poseidon2CircuitCols<
    T,
    P: PermutationColumns<T>,
    const WIDTH_EXT: usize,
    const RATE_EXT: usize,
    const DIGEST_EXT: usize,
> {
    /// The p3 Poseidon2 columns containing the permutation state.
    /// Contains in[0..WIDTH_EXT-1] (WIDTH_EXT extension limbs input) and out[0..WIDTH_EXT-1] (WIDTH_EXT extension limbs output).
    pub poseidon2: P,
    /// Value: Direction bit for Merkle left/right hashing (only meaningful when merkle_path = 1).
    /// This is a value column (not transparent) because it's used in constraints with mmcs_index_sum.
    pub mmcs_bit: T,
    /// Value column: Optional MMCS accumulator (base field, encodes a u32-like integer).
    pub mmcs_index_sum: T,
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

pub const fn num_cols<
    P: PermutationColumns<u8>,
    const WIDTH_EXT: usize,
    const RATE_EXT: usize,
    const DIGEST_EXT: usize,
>() -> usize {
    size_of::<Poseidon2CircuitCols<u8, P, WIDTH_EXT, RATE_EXT, DIGEST_EXT>>()
}

impl<
    T,
    P: PermutationColumns<T>,
    const WIDTH_EXT: usize,
    const RATE_EXT: usize,
    const DIGEST_EXT: usize,
> Borrow<Poseidon2CircuitCols<T, P, WIDTH_EXT, RATE_EXT, DIGEST_EXT>> for [T]
{
    fn borrow(&self) -> &Poseidon2CircuitCols<T, P, WIDTH_EXT, RATE_EXT, DIGEST_EXT> {
        let (prefix, shorts, suffix) = unsafe {
            self.align_to::<Poseidon2CircuitCols<T, P, WIDTH_EXT, RATE_EXT, DIGEST_EXT>>()
        };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<
    T,
    P: PermutationColumns<T>,
    const WIDTH_EXT: usize,
    const RATE_EXT: usize,
    const DIGEST_EXT: usize,
> BorrowMut<Poseidon2CircuitCols<T, P, WIDTH_EXT, RATE_EXT, DIGEST_EXT>> for [T]
{
    fn borrow_mut(&mut self) -> &mut Poseidon2CircuitCols<T, P, WIDTH_EXT, RATE_EXT, DIGEST_EXT> {
        let (prefix, shorts, suffix) = unsafe {
            self.align_to_mut::<Poseidon2CircuitCols<T, P, WIDTH_EXT, RATE_EXT, DIGEST_EXT>>()
        };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}
