//! Column definitions for the Poseidon2 circuit AIR.

pub use p3_poseidon_circuit_cols::{
    ARITY4_BIT_X_BIT2_IDX, ARITY4_BIT2_IDX, ARITY4_EXTRA_COLS, POSEIDON_LIMBS as POSEIDON2_LIMBS,
    POSEIDON_PUBLIC_OUTPUT_LIMBS as POSEIDON2_PUBLIC_OUTPUT_LIMBS,
    PoseidonCircuitCols as Poseidon2CircuitCols, PoseidonPrepInputLimb as Poseidon2PrepInputLimb,
    PoseidonPrepOutputLimb as Poseidon2PrepOutputLimb,
    PoseidonPreprocessedRow as Poseidon2PreprocessedRow, num_cols, num_cols_arity4,
    poseidon_d1_compact_preprocessed_header_cols as poseidon2_d1_compact_preprocessed_header_cols,
    poseidon_preprocessed_row_width as poseidon2_preprocessed_row_width,
    poseidon_preprocessed_row_width_for_air as poseidon2_preprocessed_row_width_for_air,
    poseidon_uses_compact_d1_preprocessed as poseidon2_uses_compact_d1_preprocessed,
};
use p3_poseidon_circuit_cols::{circuit_cols_add_four, circuit_cols_add_two};
use p3_poseidon2_air::Poseidon2Cols;

/// Compile-time guard pinning the [`Poseidon2CircuitCols`] `#[repr(C)]` split.
///
/// The wrapper lays out the inner permutation block first, then the two
/// circuit-specific value columns (`mmcs_bit`, `mmcs_index_sum`). The
/// `align_to` casts in this module and the `circuit_ncols = ncols - p2_ncols`
/// arithmetic in trace generation rely on that boundary, so this asserts the
/// wrapper adds exactly two columns over [`p3_poseidon2_air::num_cols`].
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
                Poseidon2Cols<
                    u8,
                    WIDTH,
                    SBOX_DEGREE,
                    SBOX_REGISTERS,
                    HALF_FULL_ROUNDS,
                    PARTIAL_ROUNDS,
                >,
            >(),
            p3_poseidon2_air::num_cols::<
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >(),
        ),
        "Poseidon2CircuitCols must add exactly two circuit columns over the permutation block",
    );
}

/// Compile-time guard pinning the arity-4 [`Poseidon2CircuitCols`] `#[repr(C)]` split.
///
/// The arity-4 wrapper lays out the inner permutation block first, then four
/// circuit-specific value columns (`mmcs_bit`, `mmcs_bit2`, `mmcs_bit_x_bit2`,
/// `mmcs_index_sum`). The `align_to` casts in this module and the
/// `circuit_ncols = ncols - p2_ncols` arithmetic in trace generation rely on
/// that boundary, so this asserts the wrapper adds exactly four columns over
/// [`p3_poseidon2_air::num_cols`].
pub const fn assert_circuit_cols_split_arity4<
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>() {
    assert!(
        circuit_cols_add_four(
            num_cols_arity4::<
                Poseidon2Cols<
                    u8,
                    WIDTH,
                    SBOX_DEGREE,
                    SBOX_REGISTERS,
                    HALF_FULL_ROUNDS,
                    PARTIAL_ROUNDS,
                >,
            >(),
            p3_poseidon2_air::num_cols::<
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >(),
        ),
        "arity-4 Poseidon2CircuitCols must add exactly four circuit columns over the permutation block",
    );
}
