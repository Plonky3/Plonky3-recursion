//! Extended Poseidon2 AIR that wraps the base Poseidon2Air with circuit indices.

use alloc::vec::Vec;
use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_field::PrimeField;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{Poseidon2Air, RoundConstants};

use super::columns::{ExtendedPoseidon2Cols, num_cols};

/// Extended Poseidon2 AIR with circuit integration.
///
/// This wraps Plonky3's `Poseidon2Air` and adds:
/// - Input/output witness indices for circuit lookups
/// - Lookup support from SpongeAir
///
/// The base `Poseidon2Air` handles the permutation correctness constraints.
/// This wrapper adds the glue for circuit integration.
#[derive(Debug)]
pub struct ExtendedPoseidon2Air<
    F: PrimeField,
    LinearLayers,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> {
    /// The base Poseidon2 AIR from Plonky3
    pub base_air: Poseidon2Air<
        F,
        LinearLayers,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
}

impl<
    F: PrimeField,
    LinearLayers,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>
    ExtendedPoseidon2Air<
        F,
        LinearLayers,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >
{
    /// Create a new extended Poseidon2 AIR with the given round constants.
    pub fn new(constants: RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>) -> Self {
        Self {
            base_air: Poseidon2Air::new(constants),
        }
    }

    /// Generate trace rows for the extended Poseidon2 AIR.
    ///
    /// This generates base Poseidon2 traces and adds the circuit index columns.
    /// Note: This is a TODO - proper trace generation with circuit indices
    /// requires integration with the actual circuit execution.
    #[allow(dead_code)]
    pub fn generate_trace_rows_placeholder(
        &self,
        _num_hashes: usize,
        _extra_capacity_bits: usize,
    ) -> RowMajorMatrix<F> {
        // TODO: Implement trace generation once we have:
        // 1. Actual LinearLayers type from p3-poseidon2
        // 2. Circuit index assignment logic
        // 3. Integration with base_air.generate_trace_rows()
        //
        // For now, return empty trace
        let width =
            num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>();
        RowMajorMatrix::new(Vec::new(), width)
    }
}

// Note: No Default implementation since we need RoundConstants

impl<
    F: PrimeField + Sync,
    LinearLayers: Sync,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> BaseAir<F>
    for ExtendedPoseidon2Air<
        F,
        LinearLayers,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >
{
    fn width(&self) -> usize {
        num_cols::<WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>()
    }
}

impl<
    AB: AirBuilder,
    LinearLayers,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> Air<AB>
    for ExtendedPoseidon2Air<
        AB::F,
        LinearLayers,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >
where
    AB::F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH> + Sync,
{
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("Matrix is empty?");
        let local: &ExtendedPoseidon2Cols<
            AB::Var,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        > = (*local).borrow();

        // 1. Delegate permutation correctness to base Poseidon2Air
        //
        // The base_air.eval() call validates the Poseidon2 permutation using the
        // `poseidon2` field of our ExtendedPoseidon2Cols structure.
        //
        // Since Poseidon2Cols is #[repr(C)] and is the first field of ExtendedPoseidon2Cols,
        // the memory layout is compatible and the base AIR can directly access it.
        self.base_air.eval(builder);

        // 2. Add constraints for input/output index wiring
        //
        // These constraints ensure that the witness indices are valid and consistent.
        // The actual witness value lookups will be handled by the SpongeAir via
        // lookup arguments (see step 3).

        // Constraint: Input indices should be valid witness IDs
        // For now, we just ensure they're consistent across the row.
        // The actual constraint "witness[input_indices[i]] = poseidon2.inputs[i]"
        // is enforced via lookup arguments from SpongeAir.
        for i in 0..WIDTH {
            // Input index consistency: indices should be non-negative field elements
            // representing valid witness IDs. The actual range check and witness
            // lookup is done via bus/lookup arguments.
            let _input_idx = local.input_indices[i].clone();
            let _output_idx = local.output_indices[i].clone();

            // TODO: Add range constraints to ensure indices are valid witness IDs
            // builder.assert_bool or range_check(input_idx, max_witness_id)

            // TODO: The core constraint is enforced via lookup/bus:
            //   For each i in 0..WIDTH:
            //     SEND to witness bus: (input_indices[i], poseidon2.inputs[i])
            //     SEND to witness bus: (output_indices[i], final_output[i])
            //
            //   This ensures:
            //   - witness[input_indices[i]] == poseidon2.inputs[i]
            //   - witness[output_indices[i]] == final_permutation_output[i]
        }

        // 3. Provide lookup interface for SpongeAir
        //
        // SpongeAir will send lookup queries to validate permutations:
        //
        // TODO: Implement interaction/lookup protocol:
        //   RECEIVE from SpongeAir:
        //     - (state_input_indices[0..WIDTH], state_input_values[0..WIDTH])
        //     - (state_output_indices[0..WIDTH], state_output_values[0..WIDTH])
        //
        //   Validate via this AIR:
        //     1. state_input_indices == local.input_indices
        //     2. state_input_values == local.poseidon2.inputs
        //     3. state_output_indices == local.output_indices
        //     4. state_output_values == final permutation output
        //     5. Poseidon2(state_input_values) == state_output_values (via base_air)
        //
        //   This ensures the SpongeAir's permutation calls are correctly validated.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_column_count_babybear() {
        // BabyBear Poseidon2: WIDTH=16, SBOX_DEGREE=7, SBOX_REGISTERS=0, HALF_FULL_ROUNDS=4, PARTIAL_ROUNDS=13
        // Base Poseidon2 columns + input_indices(16) + output_indices(16)
        let cols = num_cols::<16, 7, 0, 4, 13>();
        // Should include all base columns plus 32 index columns
        assert!(cols > 32);
    }
}
