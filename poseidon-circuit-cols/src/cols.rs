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

/// Number of arity-4 circuit columns added between `mmcs_bit` and
/// `mmcs_index_sum`.
///
/// An arity-4 Merkle row carries the high direction bit `mmcs_bit2` and the
/// product `mmcs_bit_x_bit2 = mmcs_bit · mmcs_bit2`. The product linearizes the
/// four-way one-hot so the placement constraint stays degree three.
pub const ARITY4_EXTRA_COLS: usize = 2;

/// Position of `mmcs_bit2` within the [`PoseidonCircuitCols::mmcs_extra`] array
/// in the arity-4 layout.
pub const ARITY4_BIT2_IDX: usize = 0;

/// Position of `mmcs_bit_x_bit2` within the [`PoseidonCircuitCols::mmcs_extra`]
/// array in the arity-4 layout.
pub const ARITY4_BIT_X_BIT2_IDX: usize = 1;

/// Value columns for one row of a Poseidon circuit table.
///
/// The type parameter carries the inner permutation columns.
///
/// It holds the full input/output state plus all intermediate round
/// registers.
///
/// The circuit-specific value columns follow the permutation block. `N_EXTRA`
/// selects the Merkle arity:
///
/// - `N_EXTRA = 0` (default): arity-2 layout, two circuit columns
///   (`mmcs_bit`, `mmcs_index_sum`).
/// - `N_EXTRA = `[`ARITY4_EXTRA_COLS`]: arity-4 layout, four circuit columns
///   (`mmcs_bit`, `mmcs_bit2`, `mmcs_bit_x_bit2`, `mmcs_index_sum`).
///
/// # Memory Layout
///
/// ```text
///     arity-2:  [ ── permutation columns ── | mmcs_bit | mmcs_index_sum ]
///     arity-4:  [ ── permutation columns ── | mmcs_bit | mmcs_bit2 | mmcs_bit_x_bit2 | mmcs_index_sum ]
/// ```
#[repr(C)]
pub struct PoseidonCircuitCols<T, P, const N_EXTRA: usize = 0> {
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
    /// In the arity-4 layout this is the low bit of the two-bit position
    /// selector `pos = mmcs_bit + 2·mmcs_bit2 ∈ {0, 1, 2, 3}`.
    ///
    /// Only meaningful on rows where the Merkle-path flag is set.
    ///
    /// Constrained to be boolean on every row regardless.
    ///
    /// This is a value column, not preprocessed, because the prover
    /// chooses it at runtime based on the Merkle proof path.
    pub mmcs_bit: T,

    /// Arity-4 direction and product columns.
    ///
    /// Empty in the arity-2 layout (`N_EXTRA = 0`). In the arity-4 layout
    /// (`N_EXTRA = `[`ARITY4_EXTRA_COLS`]) this holds, in order:
    ///
    /// - `mmcs_bit2`: the high bit of the position selector
    ///   `pos = mmcs_bit + 2·mmcs_bit2`. Constrained to boolean.
    /// - `mmcs_bit_x_bit2`: equal to `mmcs_bit · mmcs_bit2`. Linearizes the
    ///   four-way one-hot so the placement constraint stays degree three.
    pub mmcs_extra: [T; N_EXTRA],

    /// Running MMCS query-index accumulator.
    ///
    /// Across a chain of Merkle rows this accumulates the index decomposition
    /// of the leaf index:
    ///
    /// ```text
    ///     arity-2:  next_sum = current_sum × 2 + next_bit
    ///     arity-4:  next_sum = current_sum × 4 + next_bit + 2 · next_bit2
    /// ```
    ///
    /// The constraint is only active when the row is not a chain start
    /// and the Merkle-path flag is set.
    ///
    /// On chain-start rows the prover may write any value.
    pub mmcs_index_sum: T,
}

/// Return the total number of columns in a single arity-2 row.
///
/// Relies on the `size_of` trick: instantiate the struct with `u8` so
/// that every field occupies exactly one byte.
///
/// The struct size in bytes then equals the column count.
pub const fn num_cols<P>() -> usize {
    size_of::<PoseidonCircuitCols<u8, P>>()
}

/// Return the total number of columns in a single arity-4 row.
///
/// Same `size_of` trick as [`num_cols`], but with the arity-4 layout that adds
/// [`ARITY4_EXTRA_COLS`] columns between `mmcs_bit` and `mmcs_index_sum`.
pub const fn num_cols_arity4<P>() -> usize {
    size_of::<PoseidonCircuitCols<u8, P, ARITY4_EXTRA_COLS>>()
}

/// `true` when the outer wrapper adds exactly two circuit columns over the
/// inner permutation block (arity-2 layout).
///
/// The wrapper lays out the inner permutation block first, then the two
/// circuit-specific value columns (`mmcs_bit`, `mmcs_index_sum`). The
/// `align_to` casts and the `circuit_ncols = ncols - inner_ncols` arithmetic
/// in trace generation rely on that boundary.
pub const fn circuit_cols_add_two(outer_num_cols: usize, inner_num_cols: usize) -> bool {
    outer_num_cols == inner_num_cols + 2
}

/// `true` when the outer wrapper adds exactly four circuit columns over the
/// inner permutation block (arity-4 layout).
///
/// The wrapper lays out the inner permutation block first, then the four
/// circuit-specific value columns (`mmcs_bit`, `mmcs_bit2`, `mmcs_bit_x_bit2`,
/// `mmcs_index_sum`). The `align_to` casts and the
/// `circuit_ncols = ncols - inner_ncols` arithmetic in trace generation rely on
/// that boundary.
pub const fn circuit_cols_add_four(outer_num_cols: usize, inner_num_cols: usize) -> bool {
    outer_num_cols == inner_num_cols + 2 + ARITY4_EXTRA_COLS
}

impl<T, P, const N_EXTRA: usize> Borrow<PoseidonCircuitCols<T, P, N_EXTRA>> for [T] {
    fn borrow(&self) -> &PoseidonCircuitCols<T, P, N_EXTRA> {
        let (prefix, shorts, suffix) =
            unsafe { self.align_to::<PoseidonCircuitCols<T, P, N_EXTRA>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T, P, const N_EXTRA: usize> BorrowMut<PoseidonCircuitCols<T, P, N_EXTRA>> for [T] {
    fn borrow_mut(&mut self) -> &mut PoseidonCircuitCols<T, P, N_EXTRA> {
        let (prefix, shorts, suffix) =
            unsafe { self.align_to_mut::<PoseidonCircuitCols<T, P, N_EXTRA>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}
