use alloc::vec::Vec;
use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use p3_poseidon2_air::Poseidon2Cols;

/// Number of extension-field limbs used for Poseidon2 input/output in the circuit table.
pub const POSEIDON2_LIMBS: usize = 4;
/// Number of extension-field output limbs exposed as public values via CTL.
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

/// Marker trait for types that represent the Poseidon2 permutation columns.
///
/// Implemented for [`p3_poseidon2_air::Poseidon2Cols`] with matching const parameters.
/// Used as a bound on [`Poseidon2CircuitCols`] to remain generic over the concrete
/// Poseidon2 column layout.
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

/// Return the total number of columns in a [`Poseidon2CircuitCols`] row for permutation type `P`.
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

/// Preprocessed columns for a single Poseidon2 input limb.
///
/// Each of the [`POSEIDON2_LIMBS`] input limbs has its own set of preprocessed
/// columns that encode CTL membership and chain selectors.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct Poseidon2PrepInputLimb<T> {
    /// Witness index for this input limb (used in the CTL lookup).
    pub idx: T,
    /// Cross-table-lookup flag: 1 when this limb participates in an input CTL.
    pub in_ctl: T,
    /// Selector for the normal (challenger-style sponge) chain.
    pub normal_chain_sel: T,
    /// Selector for the Merkle-path chain.
    pub merkle_chain_sel: T,
}

/// Preprocessed columns for a single Poseidon2 output limb.
///
/// Only the first [`POSEIDON2_PUBLIC_OUTPUT_LIMBS`] output limbs are exposed
/// publicly via CTL.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct Poseidon2PrepOutputLimb<T> {
    /// Witness index for this output limb (used in the CTL lookup).
    pub idx: T,
    /// Cross-table-lookup flag: 1 when this limb participates in an output CTL.
    pub out_ctl: T,
}

/// Full preprocessed row for the Poseidon2 circuit table.
///
/// One row is generated per Poseidon2 permutation invocation. The preprocessed
/// data is committed once during setup and reused across all proofs.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct Poseidon2PreprocessedRow<T> {
    /// Per-limb preprocessed input columns (length = [`POSEIDON2_LIMBS`]).
    pub input_limbs: [Poseidon2PrepInputLimb<T>; POSEIDON2_LIMBS],
    /// Per-limb preprocessed output columns (length = [`POSEIDON2_PUBLIC_OUTPUT_LIMBS`]).
    pub output_limbs: [Poseidon2PrepOutputLimb<T>; POSEIDON2_PUBLIC_OUTPUT_LIMBS],
    /// CTL index for the MMCS index-sum accumulator column.
    pub mmcs_index_sum_ctl_idx: T,
    /// Flag indicating this row is part of a Merkle-path hashing chain.
    pub mmcs_merkle_flag: T,
    /// Flag indicating this row starts a new sponge or Merkle chain.
    pub new_start: T,
    /// Flag indicating this row is a Merkle-path step (as opposed to a sponge step).
    pub merkle_path: T,
}

impl<T: Copy> Poseidon2PreprocessedRow<T> {
    /// Serialize this row into `buf` in column-major order matching the `#[repr(C)]` layout.
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
