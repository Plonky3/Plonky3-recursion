//! Column definitions for the Poseidon1 circuit AIR.

use alloc::vec::Vec;

use p3_poseidon_circuit_air::circuit_cols_add_two;
pub use p3_poseidon_circuit_air::{
    POSEIDON_LIMBS as POSEIDON2_LIMBS,
    POSEIDON_PUBLIC_OUTPUT_LIMBS as POSEIDON2_PUBLIC_OUTPUT_LIMBS,
    PoseidonCircuitCols as Poseidon1CircuitCols, PoseidonPrepInputLimb as Poseidon1PrepInputLimb,
    PoseidonPrepOutputLimb as Poseidon1PrepOutputLimb,
    PoseidonPreprocessedRow as Poseidon1PreprocessedRow, num_cols,
    poseidon_d1_compact_preprocessed_header_cols as poseidon1_d1_compact_preprocessed_header_cols,
    poseidon_preprocessed_row_width as poseidon1_preprocessed_row_width,
    poseidon_preprocessed_row_width_for_air as poseidon1_preprocessed_row_width_for_air,
    poseidon_uses_compact_d1_preprocessed as poseidon1_uses_compact_d1_preprocessed,
};
use p3_poseidon1_air::Poseidon1Cols;

/// Per-row input description for a Poseidon1 circuit operation.
///
/// One entry per Poseidon1 permutation invocation; consumed by trace and
/// preprocessed generation.
#[derive(Clone, Debug)]
pub struct Poseidon1CircuitRow<F> {
    /// Control: if true, this row begins a new independent Poseidon chain.
    pub new_start: bool,
    /// Control: false → sponge/challenger mode, true → Merkle-path mode.
    pub merkle_path: bool,
    /// Control: Merkle left/right direction bit (only used when `merkle_path`).
    pub mmcs_bit: bool,
    /// Optional MMCS leaf-index accumulator value.
    pub mmcs_index_sum: F,
    /// Flattened Poseidon1 input state.
    pub input_values: Vec<F>,
    /// Per-input-limb CTL exposure flags.
    pub in_ctl: Vec<bool>,
    /// Per-input-limb CTL witness indices.
    pub input_indices: Vec<u32>,
    /// Per-rate-output-limb CTL exposure flags.
    pub out_ctl: Vec<bool>,
    /// Per-rate-output-limb CTL witness indices.
    pub output_indices: Vec<u32>,
    /// CTL witness index for `mmcs_index_sum`.
    pub mmcs_index_sum_idx: u32,
    /// Whether the `mmcs_index_sum` CTL is enabled.
    pub mmcs_ctl_enabled: bool,
}

/// Compile-time guard pinning the [`Poseidon1CircuitCols`] `#[repr(C)]` split.
///
/// The wrapper lays out the inner permutation block first, then the two
/// circuit-specific value columns (`mmcs_bit`, `mmcs_index_sum`). The
/// `align_to` casts in this module and the `circuit_ncols = ncols - p1_ncols`
/// arithmetic in trace generation rely on that boundary, so this asserts the
/// wrapper adds exactly two columns over [`p3_poseidon1_air::num_cols`].
pub const fn assert_circuit_cols_split<
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>() {
    assert!(
        circuit_cols_add_two(
            num_cols::<
                Poseidon1Cols<
                    u8,
                    WIDTH,
                    SBOX_DEGREE,
                    SBOX_REGISTERS,
                    HALF_FULL_ROUNDS,
                    PARTIAL_ROUNDS,
                >,
            >(),
            p3_poseidon1_air::num_cols::<
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >(),
        ),
        "Poseidon1CircuitCols must add exactly two circuit columns over the permutation block",
    );
}
