use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use p3_poseidon2_air::Poseidon2Cols;

pub const POSEIDON_LIMBS: usize = 4;
pub const POSEIDON_PUBLIC_OUTPUT_LIMBS: usize = 2;

/// Columns for a Poseidon2 AIR which computes one permutation per row.
///
/// They extend the P3 columns with chaining metadata and CTL exposure indices.
#[repr(C)]
pub struct Poseidon2CircuitCols<T, P: PermutationColumns<T>> {
    pub poseidon2: P,
    pub new_start: T,
    pub merkle_path: T,
    pub mmcs_bit: T,
    pub mmcs_index_sum: T,
    pub in_ctl: [T; POSEIDON_LIMBS],
    pub in_idx: [T; POSEIDON_LIMBS],
    pub out_ctl: [T; POSEIDON_PUBLIC_OUTPUT_LIMBS],
    pub out_idx: [T; POSEIDON_PUBLIC_OUTPUT_LIMBS],
    pub mmcs_index_sum_idx: T,
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

pub const fn num_cols<P: PermutationColumns<u8>>() -> usize {
    size_of::<Poseidon2CircuitCols<u8, P>>()
}

impl<T, P: PermutationColumns<T>> Borrow<Poseidon2CircuitCols<T, P>> for [T] {
    fn borrow(&self) -> &Poseidon2CircuitCols<T, P> {
        let (prefix, shorts, suffix) = unsafe { self.align_to::<Poseidon2CircuitCols<T, P>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T, P: PermutationColumns<T>> BorrowMut<Poseidon2CircuitCols<T, P>> for [T] {
    fn borrow_mut(&mut self) -> &mut Poseidon2CircuitCols<T, P> {
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<Poseidon2CircuitCols<T, P>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}
