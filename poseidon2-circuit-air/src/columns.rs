use alloc::vec::Vec;
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
/// The table implements a 4-limb Poseidon2 permutation supporting:
/// - Standard chaining (Challenger-style sponge use)
/// - Merkle-path chaining (MMCS directional hashing)
/// - Selective limb exposure to the witness via CTL
/// - Optional MMCS index accumulator
///
/// Column layout (per spec section 2):
/// - Value columns: `poseidon2` (contains in[0..3] and out[0..3]), `mmcs_index_sum`, `mmcs_bit`
/// - Transparent columns: `new_start`, `merkle_path`, CTL flags and indices
/// - Selector columns (not in spec): `normal_chain_sel`, `merkle_chain_sel`
///   These are precomputed to reduce constraint degree to 3.
#[repr(C)]
pub struct Poseidon2CircuitCols<T, P: PermutationColumns<T>> {
    /// The p3 Poseidon2 columns containing the permutation state.
    /// Contains in[0..3] (4 extension limbs input) and out[0..3] (4 extension limbs output).
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

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct Poseidon2PrepInputLimb<T> {
    pub idx: T,
    pub in_ctl: T,
    pub normal_chain_sel: T,
    pub merkle_chain_sel: T,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct Poseidon2PrepOutputLimb<T> {
    pub idx: T,
    pub out_ctl: T,
}

#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct Poseidon2PreprocessedRow<T> {
    pub input_limbs: [Poseidon2PrepInputLimb<T>; POSEIDON2_LIMBS],
    pub output_limbs: [Poseidon2PrepOutputLimb<T>; POSEIDON2_PUBLIC_OUTPUT_LIMBS],
    pub mmcs_index_sum_ctl_idx: T,
    pub mmcs_merkle_flag: T,
    pub new_start: T,
    pub merkle_path: T,
}

impl<T: Copy> Poseidon2PreprocessedRow<T> {
    pub fn write_into(self, buf: &mut Vec<T>) {
        for limb in self.input_limbs {
            buf.push(limb.idx);
            buf.push(limb.in_ctl);
            buf.push(limb.normal_chain_sel);
            buf.push(limb.merkle_chain_sel);
        }
        for limb in self.output_limbs {
            buf.push(limb.idx);
            buf.push(limb.out_ctl);
        }
        buf.push(self.mmcs_index_sum_ctl_idx);
        buf.push(self.mmcs_merkle_flag);
        buf.push(self.new_start);
        buf.push(self.merkle_path);
    }
}

impl<T> Borrow<Poseidon2PreprocessedRow<T>> for [T] {
    fn borrow(&self) -> &Poseidon2PreprocessedRow<T> {
        let (prefix, rows, suffix) = unsafe { self.align_to::<Poseidon2PreprocessedRow<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(rows.len(), 1);
        &rows[0]
    }
}

impl<T> BorrowMut<Poseidon2PreprocessedRow<T>> for [T] {
    fn borrow_mut(&mut self) -> &mut Poseidon2PreprocessedRow<T> {
        let (prefix, rows, suffix) = unsafe { self.align_to_mut::<Poseidon2PreprocessedRow<T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(rows.len(), 1);
        &mut rows[0]
    }
}
