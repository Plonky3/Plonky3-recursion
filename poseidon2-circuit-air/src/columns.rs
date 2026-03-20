//! Column definitions for the Poseidon2 circuit AIR.

use alloc::vec::Vec;
use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

/// Number of extension-field limbs for Poseidon2 input and output.
///
/// Each limb is one extension-field element.
///
/// It is stored as a group of base-field columns whose count equals the
/// extension degree.
///
/// The Poseidon2 state has this many limbs on both the input and output
/// sides.
pub const POSEIDON2_LIMBS: usize = 4;

/// Number of output limbs exposed publicly via cross-table lookup.
///
/// Only the first two output limbs are sent to the Witness table.
///
/// The remaining output limbs are consumed internally by the chaining
/// constraints.
pub const POSEIDON2_PUBLIC_OUTPUT_LIMBS: usize = 2;

/// Value columns for one row of the Poseidon2 circuit table.
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
pub struct Poseidon2CircuitCols<T, P> {
    /// Inner Poseidon2 permutation columns.
    ///
    /// Holds input limbs, output limbs, and all intermediate round state.
    ///
    /// The exact width depends on the permutation parameters.
    pub poseidon2: P,

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
    size_of::<Poseidon2CircuitCols<u8, P>>()
}

impl<T, P> Borrow<Poseidon2CircuitCols<T, P>> for [T] {
    fn borrow(&self) -> &Poseidon2CircuitCols<T, P> {
        let (prefix, shorts, suffix) = unsafe { self.align_to::<Poseidon2CircuitCols<T, P>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &shorts[0]
    }
}

impl<T, P> BorrowMut<Poseidon2CircuitCols<T, P>> for [T] {
    fn borrow_mut(&mut self) -> &mut Poseidon2CircuitCols<T, P> {
        let (prefix, shorts, suffix) = unsafe { self.align_to_mut::<Poseidon2CircuitCols<T, P>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(shorts.len(), 1);
        &mut shorts[0]
    }
}

/// Preprocessed columns for a single Poseidon2 **input** limb.
///
/// Each input limb carries its own copy of these four columns.
///
/// They encode three things:
///
/// 1. Which witness slot the limb reads from.
///
/// 2. Whether the limb participates in a cross-table lookup.
///
/// 3. Whether the limb is chained from the previous row in sponge mode
///    or in Merkle mode.
///
/// The two chain selectors are mutually exclusive.
///
/// They are precomputed to keep constraint degree at three.
///
/// ```text
///     sponge_chain  = !new_start && !merkle_path && !in_ctl
///     merkle_chain  = !new_start &&  merkle_path && !in_ctl
/// ```
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct Poseidon2PrepInputLimb<T> {
    /// Witness index for this input limb.
    ///
    /// Used in the cross-table lookup.
    ///
    /// Scaled by the extension degree so that the key directly indexes
    /// into the flattened witness table.
    pub idx: T,

    /// Cross-table lookup enable flag.
    ///
    /// When set, this limb is looked up in the Witness table.
    ///
    /// When clear, the limb's value comes from chaining or is unconstrained.
    pub in_ctl: T,

    /// Sponge-mode chain selector.
    ///
    /// When set, the AIR enforces that the next row's input equals
    /// the current row's output for this limb.
    ///
    /// This is standard sponge chaining across all base-field elements.
    pub normal_chain_sel: T,

    /// Merkle-mode chain selector.
    ///
    /// When set, the AIR enforces directional chaining gated by the
    /// direction bit.
    ///
    /// If the direction bit is zero (left child), the output chains to
    /// the first half of the next input.
    ///
    /// If the direction bit is one (right child), the output chains to
    /// the second half of the next input.
    ///
    /// Only the first two limbs carry a meaningful Merkle selector.
    ///
    /// The last two limbs reuse the first two selectors, gated on the
    /// opposite direction.
    pub merkle_chain_sel: T,
}

/// Preprocessed columns for a single Poseidon2 **output** limb.
///
/// Only the first two output limbs are exposed via cross-table lookup.
///
/// The remaining outputs are consumed internally by the chaining
/// constraints.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct Poseidon2PrepOutputLimb<T> {
    /// Witness index for this output limb.
    ///
    /// Scaled by the extension degree, same convention as input limbs.
    pub idx: T,

    /// Cross-table lookup enable flag.
    ///
    /// When set, this limb is received from the Witness table.
    ///
    /// This proves the output matches a committed value.
    pub out_ctl: T,
}

/// Full preprocessed row for the Poseidon2 circuit table.
///
/// One row per Poseidon2 permutation invocation.
///
/// The preprocessed data is committed once at setup and reused across
/// all proofs.
///
/// # Memory Layout
///
/// ```text
///     [ input_limbs (4 × 4 fields) | output_limbs (2 × 2 fields)
///       | mmcs_index_sum_ctl_idx | mmcs_merkle_flag
///       | new_start | merkle_path ]
/// ```
///
/// Total width: 24 columns.
///
/// # Padding
///
/// When padded to a power-of-two height, the **first** padding row sets
/// the chain-start flag to one.
///
/// This prevents chaining constraints from firing across the real/padding
/// boundary.
///
/// All other padding fields are zero.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct Poseidon2PreprocessedRow<T> {
    /// Per-limb preprocessed input columns.
    ///
    /// One entry per extension-field input limb.
    pub input_limbs: [Poseidon2PrepInputLimb<T>; POSEIDON2_LIMBS],

    /// Per-limb preprocessed output columns.
    ///
    /// One entry per publicly exposed output limb.
    pub output_limbs: [Poseidon2PrepOutputLimb<T>; POSEIDON2_PUBLIC_OUTPUT_LIMBS],

    /// Witness index for the MMCS accumulator column.
    ///
    /// Used in the cross-table lookup that exposes the accumulator
    /// to the Witness table at the end of a Merkle chain.
    pub mmcs_index_sum_ctl_idx: T,

    /// Precomputed product of the MMCS-enabled flag and the Merkle-path
    /// flag.
    ///
    /// This is the row-local part of the multiplicity expression for the
    /// accumulator lookup.
    ///
    /// The full multiplicity also involves the next row's chain-start
    /// flag, so the lookup fires on the last Merkle row before a chain
    /// boundary.
    ///
    /// Precomputing this product keeps the overall multiplicity at
    /// degree two.
    pub mmcs_merkle_flag: T,

    /// Chain boundary flag.
    ///
    /// Set on the first row of a new sponge or Merkle chain.
    ///
    /// When set, all chaining constraints and the MMCS accumulator
    /// update are disabled.
    pub new_start: T,

    /// Merkle-path flag.
    ///
    /// Set when this row is a Merkle-path step with directional hashing.
    ///
    /// Clear for standard sponge rows.
    pub merkle_path: T,
}

impl<T: Copy> Poseidon2PreprocessedRow<T> {
    /// Flatten this row into a buffer, preserving the field order.
    ///
    /// Uses a raw pointer cast instead of pushing fields one by one.
    ///
    /// This is automatically correct for any field ordering because
    /// `#[repr(C)]` guarantees the in-memory layout matches the
    /// declaration order.
    ///
    /// A manual push sequence would need to be kept in sync with the
    /// struct definition. The pointer cast avoids that fragility.
    pub fn write_into(self, buf: &mut Vec<T>) {
        // Compute the number of elements in the struct.
        //
        // For single-byte types this equals the struct size directly.
        // For larger field types we divide out the element size.
        let num_elements = size_of::<Self>() / size_of::<T>();

        // SAFETY: the struct is `#[repr(C)]` with `T: Copy` and all fields
        // are plain `T` values. No padding exists between same-typed fields.
        // The resulting slice covers exactly `num_elements` contiguous items.
        let ptr = &self as *const Self as *const T;
        let slice = unsafe { core::slice::from_raw_parts(ptr, num_elements) };
        buf.extend_from_slice(slice);
    }
}

/// Number of contiguous column slots in one Poseidon2 preprocessed row (matches `Poseidon2PreprocessedRow<u8>` width).
pub const POSEIDON2_PREPROCESSED_NUM_COLS: usize = size_of::<Poseidon2PreprocessedRow<u8>>();

/// Load one preprocessed row from a flat column slice.
///
/// The slice may be **unaligned** for [`Poseidon2PreprocessedRow`], which happens when the
/// STARK prover evaluates constraints on vertically packed rows (`PackedVal`): row data is
/// contiguous in column-major packed layout but the row start address is not necessarily
/// aligned to the row struct's alignment requirement.
///
/// `slice.len()` must equal [`POSEIDON2_PREPROCESSED_NUM_COLS`] (one `T` per logical column).
/// Do not compare `slice.len() * size_of::<T>()` to `size_of::<Poseidon2PreprocessedRow<T>>()`:
/// the row struct can carry trailing padding, so those byte sizes need not match.
#[inline]
pub fn load_poseidon2_preprocessed_row_unaligned<T: Copy>(
    slice: &[T],
) -> Poseidon2PreprocessedRow<T> {
    assert_eq!(
        slice.len(),
        POSEIDON2_PREPROCESSED_NUM_COLS,
        "Poseidon2 preprocessed row: expected one packed column per logical prep column"
    );
    unsafe { (slice.as_ptr() as *const Poseidon2PreprocessedRow<T>).read_unaligned() }
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
