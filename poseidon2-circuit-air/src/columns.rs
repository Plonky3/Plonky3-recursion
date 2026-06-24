//! Column definitions for the Poseidon2 circuit AIR.

use p3_poseidon_circuit_air::circuit_cols_add_two;
pub use p3_poseidon_circuit_air::{
    POSEIDON_LIMBS as POSEIDON2_LIMBS,
    POSEIDON_PUBLIC_OUTPUT_LIMBS as POSEIDON2_PUBLIC_OUTPUT_LIMBS,
    PoseidonCircuitCols as Poseidon2CircuitCols, PoseidonPrepInputLimb as Poseidon2PrepInputLimb,
    PoseidonPrepOutputLimb as Poseidon2PrepOutputLimb,
    PoseidonPreprocessedRow as Poseidon2PreprocessedRow, num_cols,
    poseidon_d1_compact_preprocessed_header_cols as poseidon2_d1_compact_preprocessed_header_cols,
    poseidon_preprocessed_row_width as poseidon2_preprocessed_row_width,
    poseidon_preprocessed_row_width_for_air as poseidon2_preprocessed_row_width_for_air,
    poseidon_uses_compact_d1_preprocessed as poseidon2_uses_compact_d1_preprocessed,
};
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
