use core::borrow::{Borrow, BorrowMut};
use core::mem::size_of;

use p3_poseidon2_air::Poseidon2Cols;

/// Columns for a Poseidon2 AIR which computes one permutation per row.
///
/// This implements the Poseidon Permutation Table specification.
/// See: https://github.com/Plonky3/Plonky3-recursion/discussions/186
///
/// The table implements a WIDTH_EXT-limb Poseidon2 permutation supporting:
/// - Standard chaining (Challenger-style sponge use)
/// - Merkle-path chaining (MMCS directional hashing)
/// - Selective limb exposure to the witness via CTL
/// - Optional MMCS index accumulator
///
/// Column layout (per spec section 2):
/// - Value columns: `poseidon2` (contains in[0..WIDTH_EXT-1] and out[0..WIDTH_EXT-1]), `mmcs_index_sum`, `mmcs_bit`
/// - Transparent columns: `new_start`, `merkle_path`, CTL flags and indices
/// - Selector columns (not in spec): `normal_chain_sel`, `merkle_chain_sel`
///   These are precomputed to reduce constraint degree to 3.
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

    /// Control: If 1, row begins a new independent Poseidon chain.
    pub new_start: T,
    /// Control: 0 → normal sponge/Challenger mode, 1 → Merkle-path mode.
    pub merkle_path: T,
    /// Value: Direction bit for Merkle left/right hashing (only meaningful when merkle_path = 1).
    /// This is a value column (not transparent) because it's used in constraints with mmcs_index_sum.
    pub mmcs_bit: T,

    /// Value column: Optional MMCS accumulator (base field, encodes a u32-like integer).
    pub mmcs_index_sum: T,

    /// Selector: enables normal chaining for a limb when the previous row's output should fill it.
    /// Computed as (1 - new_start) * (1 - merkle_path) * (1 - in_ctl[i]) for i in {0,..., POSEIDON_LIMBS - 1}.
    /// NOTE: This column is not in the spec but is added to reduce constraint degree to 3.
    pub normal_chain_sel: [T; WIDTH_EXT],

    /// Selector: enables Merkle chaining for rate limbs when the previous row's output should fill them.
    /// Computed as (1 - new_start) * merkle_path * (1 - in_ctl[i]) for i in {0..RATE_EXT-1}.
    /// NOTE: This column is not in the spec but is added to reduce constraint degree to 3.
    pub merkle_chain_sel: [T; RATE_EXT],

    /// Input exposure flags: for each limb i, if 1, in[i] must match witness lookup at in_idx[i].
    pub in_ctl: [T; WIDTH_EXT],
    /// Input exposure indices: index into the witness table for each limb.
    pub in_idx: [T; WIDTH_EXT],

    /// Output exposure flags: for digest limbs only, if 1, out[i] must match witness lookup at out_idx[i].
    /// Note: capacity limbs are never publicly exposed (always private).
    pub out_ctl: [T; DIGEST_EXT],
    /// Output exposure indices: index into the witness table for digest limbs.
    pub out_idx: [T; DIGEST_EXT],

    /// MMCS index exposure: index for CTL exposure of mmcs_index_sum.
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
