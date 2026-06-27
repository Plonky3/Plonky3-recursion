//! Preprocessed-row layout shared by the Poseidon circuit AIRs.

use alloc::vec::Vec;
use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

/// Preprocessed columns for a single Poseidon **input** limb.
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
pub struct PoseidonPrepInputLimb<T> {
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

/// Preprocessed columns for a single Poseidon **output** limb.
///
/// Only the first two output limbs are exposed via cross-table lookup.
///
/// The remaining outputs are consumed internally by the chaining
/// constraints.
#[derive(Clone, Copy, Debug, Default)]
#[repr(C)]
pub struct PoseidonPrepOutputLimb<T> {
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

/// Number of preprocessed columns for one Poseidon row.
///
/// `input_limbs` is the number of logical input limbs (`WIDTH_EXT` in the
/// AIR). Each [`PoseidonPrepInputLimb`] occupies four scalar columns.
/// `output_limbs` is the number of rate output limbs exposed via CTL
/// (`RATE_EXT`). Each [`PoseidonPrepOutputLimb`] occupies two columns.
/// The row ends with four single-column flags.
///
/// For D=1 width-16 / rate-8 Poseidon, use [`poseidon_preprocessed_row_width_for_air`] instead.
#[inline]
pub const fn poseidon_preprocessed_row_width(input_limbs: usize, output_limbs: usize) -> usize {
    input_limbs * size_of::<PoseidonPrepInputLimb<u8>>()
        + output_limbs * size_of::<PoseidonPrepOutputLimb<u8>>()
        + 4
}

/// `true` when the Poseidon AIR uses the compact D=1 preprocessed layout.
///
/// Compact D=1 layout applies to the width-16 / rate-8 base-field instance.
#[inline]
pub const fn poseidon_uses_compact_d1_preprocessed(
    poseidon_d: usize,
    width_ext: usize,
    rate_ext: usize,
) -> bool {
    poseidon_d == 1 && width_ext == 16 && rate_ext == 8
}

/// Scalar columns before input indices in the compact D=1 layout: `rate_ext` per-limb `in_ctl`,
/// unused `cap_in_ctl` (always zero; kept for fixed offset), `cap_chain_enable`, then `rate_ext`
/// sponge-chain helpers `(1 − new_start) * (1 − merkle_path) * (1 − in_ctl_i)` and `rate_ext`
/// Merkle-chain helpers `(1 − new_start) * merkle_path * (1 − in_ctl_i)` so transition gates stay degree-3.
#[inline]
pub const fn poseidon_d1_compact_preprocessed_header_cols(rate_ext: usize) -> usize {
    rate_ext + 2 + rate_ext + rate_ext
}

/// Preprocessed row width for a Poseidon circuit AIR with the given const parameters.
#[inline]
pub const fn poseidon_preprocessed_row_width_for_air(
    poseidon_d: usize,
    width_ext: usize,
    rate_ext: usize,
) -> usize {
    if poseidon_uses_compact_d1_preprocessed(poseidon_d, width_ext, rate_ext) {
        // Compact D=1: per-rate-limb in_ctl + cap_in_ctl (zero) + cap_chain + input idx + output idx +
        // per-limb out_ctl (out_ctl stays per limb for prover multiplicity pass).
        poseidon_d1_compact_preprocessed_header_cols(rate_ext) + width_ext + rate_ext + rate_ext + 4
    } else {
        poseidon_preprocessed_row_width(width_ext, rate_ext)
    }
}

/// Full preprocessed row for a Poseidon circuit table.
///
/// One row per Poseidon permutation invocation.
///
/// `INPUT_LIMBS` matches the AIR's `WIDTH_EXT` (state width in logical
/// limbs). `OUTPUT_LIMBS` matches `RATE_EXT` (rate in logical limbs).
///
/// # Padding
///
/// When padded to a power-of-two height, the **first** padding row sets
/// the chain-start flag to one.
#[derive(Clone, Copy, Debug)]
#[repr(C)]
pub struct PoseidonPreprocessedRow<const INPUT_LIMBS: usize, const OUTPUT_LIMBS: usize, T> {
    /// Per-limb preprocessed input columns (one logical limb = `D` bases in the trace).
    pub input_limbs: [PoseidonPrepInputLimb<T>; INPUT_LIMBS],

    /// Per-limb preprocessed output columns for rate outputs under CTL.
    pub output_limbs: [PoseidonPrepOutputLimb<T>; OUTPUT_LIMBS],

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

impl<const INPUT_LIMBS: usize, const OUTPUT_LIMBS: usize, T: Copy + Default> Default
    for PoseidonPreprocessedRow<INPUT_LIMBS, OUTPUT_LIMBS, T>
{
    fn default() -> Self {
        Self {
            input_limbs: [PoseidonPrepInputLimb::default(); INPUT_LIMBS],
            output_limbs: [PoseidonPrepOutputLimb::default(); OUTPUT_LIMBS],
            mmcs_index_sum_ctl_idx: T::default(),
            mmcs_merkle_flag: T::default(),
            new_start: T::default(),
            merkle_path: T::default(),
        }
    }
}

impl<const INPUT_LIMBS: usize, const OUTPUT_LIMBS: usize, T: Copy>
    PoseidonPreprocessedRow<INPUT_LIMBS, OUTPUT_LIMBS, T>
{
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

impl<const INPUT_LIMBS: usize, const OUTPUT_LIMBS: usize, T>
    Borrow<PoseidonPreprocessedRow<INPUT_LIMBS, OUTPUT_LIMBS, T>> for [T]
{
    fn borrow(&self) -> &PoseidonPreprocessedRow<INPUT_LIMBS, OUTPUT_LIMBS, T> {
        debug_assert_eq!(
            self.len(),
            poseidon_preprocessed_row_width(INPUT_LIMBS, OUTPUT_LIMBS)
        );
        let (prefix, rows, suffix) =
            unsafe { self.align_to::<PoseidonPreprocessedRow<INPUT_LIMBS, OUTPUT_LIMBS, T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(rows.len(), 1);
        &rows[0]
    }
}

impl<const INPUT_LIMBS: usize, const OUTPUT_LIMBS: usize, T>
    BorrowMut<PoseidonPreprocessedRow<INPUT_LIMBS, OUTPUT_LIMBS, T>> for [T]
{
    fn borrow_mut(&mut self) -> &mut PoseidonPreprocessedRow<INPUT_LIMBS, OUTPUT_LIMBS, T> {
        debug_assert_eq!(
            self.len(),
            poseidon_preprocessed_row_width(INPUT_LIMBS, OUTPUT_LIMBS)
        );
        let (prefix, rows, suffix) =
            unsafe { self.align_to_mut::<PoseidonPreprocessedRow<INPUT_LIMBS, OUTPUT_LIMBS, T>>() };
        debug_assert!(prefix.is_empty(), "Alignment should match");
        debug_assert!(suffix.is_empty(), "Alignment should match");
        debug_assert_eq!(rows.len(), 1);
        &mut rows[0]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_uses_compact_d1_true() {
        assert!(poseidon_uses_compact_d1_preprocessed(1, 16, 8));
    }

    #[test]
    fn test_uses_compact_d1_false_wrong_d() {
        assert!(!poseidon_uses_compact_d1_preprocessed(4, 16, 8));
    }

    #[test]
    fn test_uses_compact_d1_false_wrong_width() {
        assert!(!poseidon_uses_compact_d1_preprocessed(1, 8, 4));
    }

    #[test]
    fn test_uses_compact_d1_false_wrong_rate() {
        assert!(!poseidon_uses_compact_d1_preprocessed(1, 16, 4));
    }

    #[test]
    fn test_d1_compact_header_cols() {
        assert_eq!(poseidon_d1_compact_preprocessed_header_cols(8), 3 * 8 + 2);
    }

    #[test]
    fn test_d1_compact_header_cols_12() {
        assert_eq!(poseidon_d1_compact_preprocessed_header_cols(12), 3 * 12 + 2);
    }

    #[test]
    fn test_preprocessed_row_width_zero_limbs() {
        assert_eq!(poseidon_preprocessed_row_width(0, 0), 4);
    }

    #[test]
    fn test_preprocessed_row_width_basic() {
        // PoseidonPrepInputLimb<u8>: 4 fields × 1 byte = 4 bytes per limb
        // PoseidonPrepOutputLimb<u8>: 2 fields × 1 byte = 2 bytes per limb
        // 4 input limbs × 4 + 2 output limbs × 2 + 4 header = 24
        assert_eq!(poseidon_preprocessed_row_width(4, 2), 24);
    }
}
