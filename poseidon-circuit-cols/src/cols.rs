//! Outer circuit-column wrapper shared by the Poseidon circuit AIRs.

use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

/// Number of extension-field limbs for the Poseidon input and output.
///
/// Each limb is one extension-field element.
///
/// It is stored as a group of base-field columns whose count equals the
/// extension degree.
///
/// The Poseidon state has this many limbs on both the input and output
/// sides.
pub const POSEIDON_LIMBS: usize = 4;

/// Number of output limbs exposed publicly via cross-table lookup.
///
/// Only the first two output limbs are sent to the Witness table.
///
/// The remaining output limbs are consumed internally by the chaining
/// constraints.
pub const POSEIDON_PUBLIC_OUTPUT_LIMBS: usize = 2;

/// Value columns for one row of a Poseidon circuit table.
///
/// The type parameter carries the inner permutation columns.
///
/// It holds the full input/output state plus all intermediate round
/// registers.
///
/// Two extra circuit-specific columns follow the permutation block.
///
/// # Memory Layout
///
/// ```text
///     [ ── permutation columns ── | mmcs_bit | mmcs_index_sum ]
/// ```
#[repr(C)]
pub struct PoseidonCircuitCols<T, P> {
    /// Inner permutation columns.
    ///
    /// Holds input limbs, output limbs, and all intermediate round state.
    ///
    /// The exact width depends on the permutation parameters.
    pub perm: P,

    /// Merkle direction bit.
    ///
    /// Zero means the current digest is the left child.
    ///
    /// One means the current digest is the right child.
    ///
    /// Only meaningful on rows where the Merkle-path flag is set.
    ///
    /// Constrained to be boolean on every row regardless.
    ///
    /// This is a value column, not preprocessed, because the prover
    /// chooses it at runtime based on the Merkle proof path.
    pub mmcs_bit: T,

    /// Running MMCS query-index accumulator.
    ///
    /// Across a chain of Merkle rows this accumulates the binary
    /// decomposition of the leaf index.
    ///
    /// The recurrence is:
    ///
    /// ```text
    ///     next_sum = current_sum × 2 + next_bit
    /// ```
    ///
    /// The constraint is only active when the row is not a chain start
    /// and the Merkle-path flag is set.
    ///
    /// On chain-start rows the prover may write any value.
    pub mmcs_index_sum: T,
}

/// Return the total number of columns in a single row.
///
/// Relies on the `size_of` trick: instantiate the struct with `u8` so
/// that every field occupies exactly one byte.
///
/// The struct size in bytes then equals the column count.
pub const fn num_cols<P>() -> usize {
    size_of::<PoseidonCircuitCols<u8, P>>()
}

/// `true` when the outer wrapper adds exactly two circuit columns over the
/// inner permutation block.
///
/// The wrapper lays out the inner permutation block first, then the two
/// circuit-specific value columns (`mmcs_bit`, `mmcs_index_sum`). The
/// `align_to` casts and the `circuit_ncols = ncols - inner_ncols` arithmetic
/// in trace generation rely on that boundary.
pub const fn circuit_cols_add_two(outer_num_cols: usize, inner_num_cols: usize) -> bool {
    outer_num_cols == inner_num_cols + 2
}

impl<T, P> Borrow<PoseidonCircuitCols<T, P>> for [T] {
    fn borrow(&self) -> &PoseidonCircuitCols<T, P> {
        let (prefix, shorts, suffix) = unsafe { self.align_to::<PoseidonCircuitCols<T, P>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T, P> BorrowMut<PoseidonCircuitCols<T, P>> for [T] {
    fn borrow_mut(&mut self) -> &mut PoseidonCircuitCols<T, P> {
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<PoseidonCircuitCols<T, P>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}
