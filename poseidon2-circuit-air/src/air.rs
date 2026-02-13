use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::iter;
use core::mem::MaybeUninit;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, PermutationAirBuilder};
use p3_circuit::ops::Poseidon2CircuitRow;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField};
use p3_lookup::lookup_traits::{Direction, Kind, Lookup};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{Poseidon2Air, Poseidon2Cols, RoundConstants, generate_trace_rows_for_perm};
use p3_uni_stark::{SubAirBuilder, SymbolicAirBuilder, SymbolicExpression, SymbolicVariable};

use crate::columns::{POSEIDON2_LIMBS, POSEIDON2_PUBLIC_OUTPUT_LIMBS};
use crate::{Poseidon2CircuitCols, num_cols};

/// Extends the Poseidon2 AIR with recursion circuit-specific columns and constraints.
///
/// This implements the Poseidon2 Permutation Table specification.
/// See: https://github.com/Plonky3/Plonky3-recursion/discussions/186
///
/// The AIR enforces:
/// - Poseidon2 permutation constraint: out[0..3] = Poseidon2(in[0..3])
/// - Chaining rules for normal sponge and Merkle-path modes
/// - MMCS index accumulator updates
///
/// Assumes the field size is at least 16 bits.
///
/// SPECIFIC ASSUMPTIONS:
/// - Memory elements from the witness table are extension elements of degree D.
/// - RATE and CAPACITY are the number of extension elements in the rate/capacity.
/// - WIDTH is the number of field elements in the state, i.e., (RATE + CAPACITY) * D.
#[derive(Debug)]
pub struct Poseidon2CircuitAir<
    F: PrimeCharacteristicRing,
    LinearLayers,
    const D: usize,
    const WIDTH: usize,
    const WIDTH_EXT: usize,
    const RATE_EXT: usize,
    const CAPACITY_EXT: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> {
    p3_poseidon2: Poseidon2Air<
        F,
        LinearLayers,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
    /// Current number of lookup columns registered.
    pub num_lookup_cols: usize,
    /// Preprocessed values for the AIR. These values are only needed by the prover. During verification, the `Vec` can be empty.
    preprocessed: Vec<F>,
    /// Minimum trace height (for FRI compatibility with higher log_final_poly_len).
    min_height: usize,
}

impl<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
    const D: usize,
    const WIDTH: usize,
    const WIDTH_EXT: usize,
    const RATE_EXT: usize,
    const CAPACITY_EXT: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> Clone
    for Poseidon2CircuitAir<
        F,
        LinearLayers,
        D,
        WIDTH,
        WIDTH_EXT,
        RATE_EXT,
        CAPACITY_EXT,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >
{
    fn clone(&self) -> Self {
        Self {
            p3_poseidon2: self.p3_poseidon2.clone(),
            num_lookup_cols: self.num_lookup_cols,
            preprocessed: self.preprocessed.clone(),
            min_height: self.min_height,
        }
    }
}

pub const fn poseidon2_preprocessed_width() -> usize {
    // Witness index, `in_ctl`, `normal_chain_sel` and `merkle_chain_sel` for all input limbs,
    // witness index and `out_ctl` for all output limbs,
    // `mmcs_index_sum_ctl_idx`, `mmcs_merkle_flag` (precomputed: mmcs_ctl * merkle_path),
    // `new_start` and `merkle_path`.
    4 * POSEIDON2_LIMBS + 2 * POSEIDON2_PUBLIC_OUTPUT_LIMBS + 4
}

impl<
    F: PrimeField,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
    const D: usize,
    const WIDTH: usize,
    const WIDTH_EXT: usize,
    const RATE_EXT: usize,
    const CAPACITY_EXT: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>
    Poseidon2CircuitAir<
        F,
        LinearLayers,
        D,
        WIDTH,
        WIDTH_EXT,
        RATE_EXT,
        CAPACITY_EXT,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >
{
    pub const fn new(
        constants: RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    ) -> Self {
        const {
            assert!(CAPACITY_EXT + RATE_EXT == WIDTH_EXT);
            assert!(WIDTH_EXT * D == WIDTH);
        }

        Self {
            p3_poseidon2: Poseidon2Air::new(constants),
            num_lookup_cols: 0,
            preprocessed: Vec::new(),
            min_height: 1,
        }
    }

    pub fn with_min_height(mut self, min_height: usize) -> Self {
        self.min_height = min_height.next_power_of_two().max(1);
        self
    }

    pub const fn new_with_preprocessed(
        constants: RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
        preprocessed: Vec<F>,
    ) -> Self {
        const {
            assert!(CAPACITY_EXT + RATE_EXT == WIDTH_EXT);
            assert!(WIDTH_EXT * D == WIDTH);
        }

        Self {
            p3_poseidon2: Poseidon2Air::new(constants),
            num_lookup_cols: 0,
            preprocessed,
            min_height: 1,
        }
    }

    pub const fn preprocessed_width() -> usize {
        poseidon2_preprocessed_width()
    }

    pub fn generate_trace_rows(
        &self,
        sponge_ops: &[Poseidon2CircuitRow<F>],
        constants: &RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
        extra_capacity_bits: usize,
    ) -> RowMajorMatrix<F> {
        let n = sponge_ops.len();
        assert!(
            n.is_power_of_two(),
            "Callers expected to pad inputs to a power of two"
        );

        let p2_ncols = p3_poseidon2_air::num_cols::<
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >();
        let ncols = self.width();
        let circuit_ncols = ncols - p2_ncols;

        // We allocate the final vector immediately with uninitialized memory.
        //
        // The extra capacity bits only enlarges the Poseidon2 columns, not the circuit columns.
        let mut trace_vec: Vec<F> =
            Vec::with_capacity(n * ((p2_ncols << extra_capacity_bits) + circuit_ncols));
        let trace_slice = trace_vec.spare_capacity_mut();

        // We need a lightweight vector to store the state inputs for the parallel pass.
        //
        // This is much smaller than the full trace (WIDTH vs NUM_COLS).
        let mut inputs = Vec::with_capacity(n);
        let mut prev_mmcs_index_sum = F::ZERO;

        // Split slice into rows
        let rows = trace_slice[..n * ncols].chunks_exact_mut(ncols);

        for (row_index, (op, row)) in sponge_ops.iter().zip(rows).enumerate() {
            let Poseidon2CircuitRow {
                new_start,
                merkle_path,
                mmcs_bit,
                mmcs_index_sum,
                input_values,
                ..
            } = op;

            // Copy input_values into fixed-size array, padding with zeros.
            // Note: input_values already contains the fully resolved state with chaining
            // applied during circuit execution, so no additional chaining is needed here.
            assert_eq!(
                input_values.len(),
                WIDTH,
                "Trace row input_values must have length WIDTH"
            );
            let mut state = [F::ZERO; WIDTH];
            state[..WIDTH].copy_from_slice(&input_values[..WIDTH]);

            // Update MMCS index accumulator
            let acc = if row_index > 0 && *merkle_path && !*new_start {
                // mmcs_index_sum_{r+1} = mmcs_index_sum_r * 2 + mmcs_bit_r
                prev_mmcs_index_sum + prev_mmcs_index_sum + F::from_bool(*mmcs_bit)
            } else {
                // Reset / non-Merkle behavior.
                // The AIR does not constrain mmcs_index_sum on these rows;
                // we simply use the value stored in the op.
                *mmcs_index_sum
            };
            prev_mmcs_index_sum = acc;

            let (_p2_part, circuit_part) = row.split_at_mut(p2_ncols);

            circuit_part[0].write(F::from_bool(*mmcs_bit));
            circuit_part[1].write(acc);

            // Save the state to be used as input for the heavy Poseidon2 trace generation
            inputs.push(state);
        }

        // Poseidon2 trace generation
        //
        // Now that we have the inputs, we can generate the expensive Poseidon2 columns in parallel.

        trace_slice[..n * ncols]
            .par_chunks_exact_mut(ncols)
            .zip(inputs.into_par_iter())
            .for_each(|(row, input)| {
                let (p2_part, _circuit_part) = row.split_at_mut(p2_ncols);

                // Align the raw field elements to the Poseidon2Cols struct
                let (prefix, p2_cols, suffix) = unsafe {
                    p2_part.align_to_mut::<Poseidon2Cols<
                        MaybeUninit<F>,
                        WIDTH,
                        SBOX_DEGREE,
                        SBOX_REGISTERS,
                        HALF_FULL_ROUNDS,
                        PARTIAL_ROUNDS,
                    >>()
                };

                // Sanity checks to ensure memory layout is what we expect
                debug_assert!(prefix.is_empty(), "Alignment mismatch");
                debug_assert!(suffix.is_empty(), "Alignment mismatch");
                debug_assert_eq!(p2_cols.len(), 1);

                // Generate the heavy trace
                generate_trace_rows_for_perm::<
                    F,
                    LinearLayers,
                    WIDTH,
                    SBOX_DEGREE,
                    SBOX_REGISTERS,
                    HALF_FULL_ROUNDS,
                    PARTIAL_ROUNDS,
                >(&mut p2_cols[0], input, constants);
            });

        // SAFETY: We have written to all columns in the slice [0..n*ncols].
        // 1. Circuit columns were written in the sequential loop.
        // 2. Poseidon2 columns were written in the parallel loop.
        unsafe {
            trace_vec.set_len(n * ncols);
        }

        RowMajorMatrix::new(trace_vec, ncols)
    }
}

impl<
    F: PrimeField + Sync,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH> + Sync,
    const D: usize,
    const WIDTH: usize,
    const WIDTH_EXT: usize,
    const RATE_EXT: usize,
    const CAPACITY_EXT: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> BaseAir<F>
    for Poseidon2CircuitAir<
        F,
        LinearLayers,
        D,
        WIDTH,
        WIDTH_EXT,
        RATE_EXT,
        CAPACITY_EXT,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >
{
    fn width(&self) -> usize {
        num_cols::<
            Poseidon2Cols<u8, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
        >()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        debug_assert!(
            self.preprocessed
                .len()
                .is_multiple_of(Self::preprocessed_width()),
            "Preprocessed trace length is not a multiple of preprocessed width. Expected multiple of {}, got {}",
            Self::preprocessed_width(),
            self.preprocessed.len(),
        );

        let width = Self::preprocessed_width();
        let natural_rows = self.preprocessed.len() / width;
        let num_extra_rows = natural_rows
            .next_power_of_two()
            .saturating_sub(natural_rows);

        let mut preprocessed = self.preprocessed.clone();
        let start_len = preprocessed.len();
        preprocessed.resize(start_len + num_extra_rows * width, F::ZERO);

        if num_extra_rows > 0 {
            preprocessed[start_len + width - 2] = F::ONE;
        }

        let mut mat = RowMajorMatrix::new(preprocessed, width);
        let current_height = mat.height();
        let target_height = current_height
            .next_power_of_two()
            .max(self.min_height.next_power_of_two());
        if current_height < target_height {
            let padding_rows = target_height - current_height;
            mat.values
                .extend(core::iter::repeat_n(F::ZERO, padding_rows * width));
        }
        Some(mat)
    }
}

pub fn extract_preprocessed_from_operations<F: Field, OF: Field>(
    operations: &[Poseidon2CircuitRow<OF>],
) -> Vec<F> {
    let mut preprocessed = Vec::with_capacity(operations.len() * poseidon2_preprocessed_width());

    for operation in operations {
        let Poseidon2CircuitRow {
            in_ctl,
            input_indices,
            out_ctl,
            output_indices,
            mmcs_index_sum_idx,
            mmcs_ctl_enabled,
            new_start,
            merkle_path,
            ..
        } = operation;

        for limb_idx in 0..4 {
            let ctl = in_ctl[limb_idx];
            let idx = input_indices[limb_idx];

            preprocessed.extend(&[F::from_u32(idx), F::from_bool(ctl)]);

            let normal_chain_sel = if !*new_start && !*merkle_path && !ctl {
                F::ONE
            } else {
                F::ZERO
            };
            preprocessed.push(normal_chain_sel);

            let merkle_chain_sel = if !new_start && *merkle_path && !ctl {
                F::ONE
            } else {
                F::ZERO
            };
            preprocessed.push(merkle_chain_sel);
        }
        out_ctl
            .iter()
            .zip(output_indices.iter())
            .for_each(|(ctl, idx)| {
                preprocessed.extend(&[F::from_u32(*idx), F::from_bool(*ctl)]);
            });
        preprocessed.push(F::from_u64(*mmcs_index_sum_idx as u64));
        // mmcs_merkle_flag = mmcs_ctl_enabled * merkle_path (precomputed)
        let mmcs_merkle_flag = if *mmcs_ctl_enabled && *merkle_path {
            F::ONE
        } else {
            F::ZERO
        };
        preprocessed.push(mmcs_merkle_flag);
        preprocessed.push(F::from_bool(*new_start));
        preprocessed.push(F::from_bool(*merkle_path));
    }

    preprocessed
}

pub(crate) fn eval<
    AB: AirBuilder,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
    const D: usize,
    const WIDTH: usize,
    const WIDTH_EXT: usize,
    const RATE_EXT: usize,
    const CAPACITY_EXT: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>(
    air: &Poseidon2CircuitAir<
        AB::F,
        LinearLayers,
        D,
        WIDTH,
        WIDTH_EXT,
        RATE_EXT,
        CAPACITY_EXT,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
    builder: &mut AB,
    local: &Poseidon2CircuitCols<
        AB::Var,
        Poseidon2Cols<
            AB::Var,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >,
    >,
    next: &Poseidon2CircuitCols<
        AB::Var,
        Poseidon2Cols<
            AB::Var,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >,
    >,
    next_preprocessed: &[AB::Var],
) {
    // Control flags (new_start, merkle_path, in_ctl, out_ctl) are preprocessed columns,
    // so they are known to the verifier and don't need bool assertions.
    // Note: mmcs_bit is a value column (not transparent) because it's used in constraints
    // with the value column mmcs_index_sum.

    let next_bit = next.mmcs_bit.clone();
    let local_out = &local.poseidon2.ending_full_rounds[HALF_FULL_ROUNDS - 1].post;
    let next_in = &next.poseidon2.inputs;

    // mmcs_bit should always be boolean.
    builder.assert_bool(local.mmcs_bit.clone());

    // Preprocessing layout:
    // [in_idx[0], in_ctl[0], normal_chain_sel[0], merkle_chain_sel[0], ..., in_idx[3], in_ctl[3], normal_chain_sel[3], merkle_chain_sel[3],
    //  out_idx[0], out_ctl[0], out_idx[1], out_ctl[1], mmcs_index_sum_ctl_idx, mmcs_merkle_flag, new_start, merkle_path]
    // The following corresponds to the size of the data related to one input limb (in_idx[i], in_ctl[i], normal_chain_sel[i], merkle_chain_sel[i]).
    let preprocessing_limb_data_size = 4;
    let normal_chain_idx = 2;
    let merkle_chain_idx = 3;
    let new_start_idx = 4 * POSEIDON2_LIMBS + 2 * POSEIDON2_PUBLIC_OUTPUT_LIMBS + 2;
    let merkle_path_idx = new_start_idx + 1;
    // Normal chaining.
    // If new_start_{r+1} = 0 and merkle_path_{r+1} = 0:
    //   in_{r+1}[i] = out_r[i] for i = 0..3
    // BUT: If in_ctl[i] = 1, CTL overrides chaining (limb is not chained).
    // Chaining only applies when in_ctl[limb] = 0.
    for limb in 0..POSEIDON2_LIMBS {
        for d in 0..D {
            let idx = limb * D + d;
            let gate =
                next_preprocessed[preprocessing_limb_data_size * limb + normal_chain_idx].clone();
            builder
                .when_transition()
                .when(gate)
                .assert_zero(next_in[idx].clone() - local_out[idx].clone());
        }
    }

    // Merkle-path chaining.
    // If new_start_{r+1} = 0 and merkle_path_{r+1} = 1:
    //   - If mmcs_bit_{r+1} = 0 (left = previous hash): in_{r+1}[0] = out_r[0], in_{r+1}[1] = out_r[1].
    //     Input limbs 2-3 are free/private.
    //   - If mmcs_bit_{r+1} = 1 (right = previous hash): in_{r+1}[2] = out_r[0], in_{r+1}[3] = out_r[1].
    //     Input limbs 0-1 are free/private.
    // BUT: If in_ctl[i] = 1, CTL overrides chaining (limb is not chained).
    // Chaining only applies when in_ctl[limb] = 0.
    let is_left = AB::Expr::ONE - next_bit.clone();

    // Limb 0: chain from out_r[0] when mmcs_bit = 0 (left), unless in_ctl[0] = 1.
    // When mmcs_bit = 1 (right), limb 0 is private (sibling).
    for d in 0..D {
        let gate_left_0 = next_preprocessed[merkle_chain_idx].clone() * is_left.clone();
        builder
            .when_transition()
            .when(gate_left_0)
            .assert_zero(next_in[d].clone() - local_out[d].clone());
    }

    // Limb 1: chain from out_r[1] when mmcs_bit = 0 (left), unless in_ctl[1] = 1.
    // When mmcs_bit = 1 (right), limb 1 is private (sibling).
    for d in 0..D {
        let gate_left_1 = next_preprocessed[preprocessing_limb_data_size + merkle_chain_idx]
            .clone()
            * is_left.clone();
        builder
            .when_transition()
            .when(gate_left_1)
            .assert_zero(next_in[D + d].clone() - local_out[D + d].clone());
    }

    // Limb 2: chain from out_r[0] when mmcs_bit = 1. Uses merkle_chain_sel[0] since
    // physical limb 2 contains logical limb 0's value when permuted.
    for d in 0..D {
        let gate_right_2 = next_preprocessed[merkle_chain_idx].clone() * next_bit.clone();
        builder
            .when_transition()
            .when(gate_right_2)
            .assert_zero(next_in[2 * D + d].clone() - local_out[d].clone());
    }

    // Limb 3: chain from out_r[1] when mmcs_bit = 1. Uses merkle_chain_sel[1].
    for d in 0..D {
        let gate_right_3 = next_preprocessed[preprocessing_limb_data_size + merkle_chain_idx]
            .clone()
            * next_bit.clone();
        builder
            .when_transition()
            .when(gate_right_3)
            .assert_zero(next_in[3 * D + d].clone() - local_out[D + d].clone());
    }

    // MMCS accumulator update.
    // If merkle_path_{r+1} = 1 and new_start_{r+1} = 0:
    //   mmcs_index_sum_{r+1} = mmcs_index_sum_r * 2 + mmcs_bit_{r+1}
    let two = AB::Expr::ONE + AB::Expr::ONE;
    let not_next_new_start = AB::Expr::ONE - next_preprocessed[new_start_idx].clone();
    builder
        .when_transition()
        .when(not_next_new_start)
        .when(next_preprocessed[merkle_path_idx].clone())
        .assert_zero(
            next.mmcs_index_sum.clone()
                - (local.mmcs_index_sum.clone() * two + next.mmcs_bit.clone()),
        );

    let p3_poseidon2_num_cols = p3_poseidon2_air::num_cols::<
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >();
    let mut sub_builder = SubAirBuilder::<
        AB,
        Poseidon2Air<
            AB::F,
            LinearLayers,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >,
        AB::Var,
    >::new(builder, 0..p3_poseidon2_num_cols);

    // Enforce Poseidon2 permutation constraint:
    // out[0..3] = Poseidon2(in[0..3])
    // This holds regardless of merkle_path, new_start, CTL flags, chaining, or MMCS accumulator.
    air.p3_poseidon2.eval(&mut sub_builder);
}

/// Unsafe version of `eval` that allows calling with a builder whose field type
/// doesn't match the AIR's field type at compile time, but matches at runtime.
///
/// # Safety
/// The caller must ensure that `F == AB::F` at runtime. Violating this will cause
/// undefined behavior.
pub unsafe fn eval_unchecked<
    F: PrimeField,
    AB: AirBuilder,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
    const D: usize,
    const WIDTH: usize,
    const WIDTH_EXT: usize,
    const RATE_EXT: usize,
    const CAPACITY_EXT: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>(
    air: &Poseidon2CircuitAir<
        F,
        LinearLayers,
        D,
        WIDTH,
        WIDTH_EXT,
        RATE_EXT,
        CAPACITY_EXT,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
    builder: &mut AB,
    local: &Poseidon2CircuitCols<
        AB::Var,
        Poseidon2Cols<
            AB::Var,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >,
    >,
    next: &Poseidon2CircuitCols<
        AB::Var,
        Poseidon2Cols<
            AB::Var,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >,
    >,
    next_preprocessed: &[AB::Var],
) where
    AB::F: PrimeField,
{
    // SAFETY: Caller guarantees F == AB::F at runtime, so the struct layouts are identical.
    // The transmute is safe because all field types have the same runtime representation.
    unsafe {
        let air_transmuted: &Poseidon2CircuitAir<
            AB::F,
            LinearLayers,
            D,
            WIDTH,
            WIDTH_EXT,
            RATE_EXT,
            CAPACITY_EXT,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        > = core::mem::transmute(air);

        eval::<
            AB,
            LinearLayers,
            D,
            WIDTH,
            WIDTH_EXT,
            RATE_EXT,
            CAPACITY_EXT,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >(air_transmuted, builder, local, next, next_preprocessed);
    }
}

impl<
    AB: AirBuilder,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
    const D: usize,
    const WIDTH: usize,
    const WIDTH_EXT: usize,
    const RATE_EXT: usize,
    const CAPACITY_EXT: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> Air<AB>
    for Poseidon2CircuitAir<
        AB::F,
        LinearLayers,
        D,
        WIDTH,
        WIDTH_EXT,
        RATE_EXT,
        CAPACITY_EXT,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >
where
    AB::F: PrimeField,
{
    #[inline]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("The matrix is empty?");
        let local = (*local).borrow();
        let next = main.row_slice(1).expect("The matrix has only one row?");
        let next = (*next).borrow();

        let preprocessed = builder
            .preprocessed()
            .expect("Expected preprocessed columns");
        let next_preprocessed = preprocessed
            .row_slice(1)
            .expect("The preprocessed matrix has only one row?");
        let next_preprocessed = (*next_preprocessed).borrow();

        eval::<
            _,
            _,
            D,
            WIDTH,
            WIDTH_EXT,
            RATE_EXT,
            CAPACITY_EXT,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >(self, builder, local, next, next_preprocessed);
    }

    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let lookup_column_idx = self.num_lookup_cols;
        self.num_lookup_cols += 1;
        vec![lookup_column_idx]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<<AB>::F>>
    where
        AB: PermutationAirBuilder + AirBuilderWithPublicValues,
    {
        let symbolic_air_builder = SymbolicAirBuilder::<AB::F>::new(
            Self::preprocessed_width(),
            BaseAir::<AB::F>::width(self),
            0,
            0, // Here, we do not need the permutation trace
            0,
        );
        let symbolic_main = symbolic_air_builder.main();
        let symbolic_main_local = symbolic_main.row_slice(0).expect("The matrix is empty?");

        let local: &Poseidon2CircuitCols<
            SymbolicVariable<AB::F>,
            Poseidon2Cols<
                SymbolicVariable<AB::F>,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >,
        > = (*symbolic_main_local).borrow();

        // Preprocessing layout:
        // [in_idx[0], in_ctl[0], normal_chain_sel[0], merkle_chain_sel[0], ..., in_idx[3], in_ctl[3], normal_chain_sel[3], merkle_chain_sel[3],
        //  out_idx[0], out_ctl[0], out_idx[1], out_ctl[1], mmcs_index_sum_ctl_idx, mmcs_merkle_flag, new_start, merkle_path]
        // The following corresponds to the size of the data related to one input limb (in_idx[i], in_ctl[i], normal_chain_sel[i], merkle_chain_sel[i]).
        let preprocessing_limb_input_data_size = 4;
        let preprocessing_limb_output_data_size = 2;
        let in_ctl_idx = 1;
        let start_output_idx = preprocessing_limb_input_data_size * POSEIDON2_LIMBS;
        let mmcs_index_sum_ctl_idx =
            start_output_idx + preprocessing_limb_output_data_size * POSEIDON2_PUBLIC_OUTPUT_LIMBS;
        let mmcs_merkle_flag_idx = mmcs_index_sum_ctl_idx + 1;
        let new_start_idx = mmcs_merkle_flag_idx + 1;
        let merkle_path_idx = new_start_idx + 1;

        let preprocessed = symbolic_air_builder
            .preprocessed()
            .expect("Expected preprocessed columns");
        let local_preprocessed = preprocessed
            .row_slice(0)
            .expect("The preprocessed matrix has only one row?");
        let local_preprocessed: &[SymbolicVariable<AB::F>] = (*local_preprocessed).borrow();
        let next_preprocessed = preprocessed
            .row_slice(1)
            .expect("The preprocessed matrix has only one row?");
        let next_preprocessed: &[SymbolicVariable<AB::F>] = (*next_preprocessed).borrow();
        // There are POSEIDON2_LIMBS input limbs and POSEIDON2_PUBLIC_OUTPUT_LIMBS output limbs to be looked up in the `Witness` table.
        let mut lookups = Vec::with_capacity(POSEIDON2_LIMBS + POSEIDON2_PUBLIC_OUTPUT_LIMBS);

        // Input CTL lookups disabled for merkle_path=1 rows due to degree constraints:
        // permuting CTL metadata based on runtime would make `mmcs_bit` exceed degree 3.
        //
        // This is sound because:
        // - Row digest values are bound to expression IDs that were CTL-verified
        //   during creation (in `add_hash_slice` with merkle_path=false)
        // - Sibling values are private proof data (wrong siblings → wrong root)
        // - Chained values are AIR-constrained to equal previous Poseidon2 outputs
        let local_merkle_path = local_preprocessed[merkle_path_idx];
        let not_merkle =
            SymbolicExpression::Constant(AB::F::ONE) - SymbolicExpression::from(local_merkle_path);

        for limb_idx in 0..POSEIDON2_LIMBS {
            let in_ctl =
                local_preprocessed[limb_idx * preprocessing_limb_input_data_size + in_ctl_idx];
            let input_idx_limb =
                iter::once(local_preprocessed[limb_idx * preprocessing_limb_input_data_size])
                    .chain(
                        local.poseidon2.inputs[limb_idx * D..(limb_idx + 1) * D]
                            .iter()
                            .cloned(),
                    )
                    .map(SymbolicExpression::from)
                    .collect::<Vec<_>>();

            // Multiplicity = in_ctl * (1 - merkle_path), both preprocessed, so degree 0
            let mult = SymbolicExpression::from(in_ctl) * not_merkle.clone();

            lookups.push(<Self as Air<AB>>::register_lookup(
                self,
                Kind::Global("WitnessChecks".to_string()),
                &[(input_idx_limb, mult, Direction::Send)],
            ));
        }

        for limb_idx in 0..POSEIDON2_PUBLIC_OUTPUT_LIMBS {
            let out_ctl = local_preprocessed[start_output_idx + limb_idx * 2 + 1];

            let output_idx_limb = iter::once(local_preprocessed[start_output_idx + limb_idx * 2]) // output witness index
                .chain(
                    local.poseidon2.ending_full_rounds[HALF_FULL_ROUNDS - 1].post
                        [limb_idx * D..(limb_idx + 1) * D]
                        .iter()
                        .cloned(),
                )
                .map(SymbolicExpression::from)
                .collect::<Vec<_>>();

            let lookup_output = vec![(
                output_idx_limb,
                SymbolicExpression::from(out_ctl),
                Direction::Send,
            )];

            lookups.push(<Self as Air<AB>>::register_lookup(
                self,
                Kind::Global("WitnessChecks".to_string()),
                &lookup_output,
            ));
        }

        // If mmcs_merkle_flag = 1 AND next.new_start = 1, then mmcs_index_sum is exposed via CTL.
        // mmcs_merkle_flag is precomputed as: mmcs_ctl_enabled * merkle_path
        // This keeps the multiplicity at degree 2 (safe for constraint evaluation).
        // When mmcs_index_sum is not allocated (mmcs_ctl = 0) or merkle_path = 0, the flag is 0.
        let local_mmcs_merkle_flag = local_preprocessed[mmcs_merkle_flag_idx];
        let next_new_start = next_preprocessed[new_start_idx];
        let multiplicity = local_mmcs_merkle_flag * next_new_start;

        let local_mmcs_index_sum_idx = local_preprocessed[mmcs_index_sum_ctl_idx];
        let mut mmcs_index_sum_lookup = vec![
            SymbolicExpression::from(local_mmcs_index_sum_idx),
            SymbolicExpression::from(local.mmcs_index_sum),
        ];
        // Extend `mmcs_index_sum` to D elements with zeros.
        mmcs_index_sum_lookup.extend(iter::repeat_n(
            SymbolicExpression::Constant(AB::F::ZERO),
            D - 1,
        ));

        let lookup_mmcs = (
            mmcs_index_sum_lookup.to_vec(),
            multiplicity,
            Direction::Send,
        );
        lookups.push(<Self as Air<AB>>::register_lookup(
            self,
            Kind::Global("WitnessChecks".to_string()),
            &[lookup_mmcs],
        ));

        lookups
    }
}

#[cfg(test)]
mod test {
    use alloc::vec;

    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::{HashChallenger, SerializingChallenger32};
    use p3_commit::ExtensionMmcs;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{TwoAdicFriPcs, create_benchmark_fri_params};
    use p3_keccak::{Keccak256Hash, KeccakF};
    use p3_merkle_tree::MerkleTreeHidingMmcs;
    use p3_poseidon2::ExternalLayerConstants;
    use p3_poseidon2_air::RoundConstants;
    use p3_symmetric::{
        CompressionFunctionFromHasher, PaddingFreeSponge, Permutation, SerializingHasher,
    };
    use p3_uni_stark::{
        StarkConfig, prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed,
    };
    use rand::rngs::SmallRng;
    use rand::{RngExt, SeedableRng};

    use super::*;
    use crate::Poseidon2CircuitAirBabyBearD4Width16;
    use crate::columns::{POSEIDON2_LIMBS, POSEIDON2_PUBLIC_OUTPUT_LIMBS};

    const WIDTH: usize = 16;

    #[test]
    fn prove_poseidon2_sponge() -> Result<
        (),
        p3_uni_stark::VerificationError<
            p3_fri::verifier::FriError<
                p3_merkle_tree::MerkleTreeError,
                p3_merkle_tree::MerkleTreeError,
            >,
        >,
    > {
        type Val = BabyBear;
        type Challenge = BinomialExtensionField<Val, 4>;

        type ByteHash = Keccak256Hash;
        let byte_hash = ByteHash {};

        type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
        let u64_hash = U64Hash::new(KeccakF {});

        type FieldHash = SerializingHasher<U64Hash>;
        let field_hash = FieldHash::new(u64_hash);

        type MyCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
        let compress = MyCompress::new(u64_hash);

        // WARNING: DO NOT USE SmallRng in proper applications! Use a real PRNG instead!
        type ValMmcs = MerkleTreeHidingMmcs<
            [Val; p3_keccak::VECTOR_LEN],
            [u64; p3_keccak::VECTOR_LEN],
            FieldHash,
            MyCompress,
            SmallRng,
            4,
            4,
        >;
        let mut rng = SmallRng::seed_from_u64(1);
        let val_mmcs = ValMmcs::new(field_hash, compress, 0, rng.clone());

        type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

        type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
        let challenger = Challenger::from_hasher(vec![], byte_hash);

        let mut fri_params = create_benchmark_fri_params(challenge_mmcs);
        fri_params.log_blowup = 4;

        let beginning_full_constants = rng.random();
        let partial_constants = rng.random();
        let ending_full_constants = rng.random();

        let constants = RoundConstants::new(
            beginning_full_constants,
            partial_constants,
            ending_full_constants,
        );

        let perm = Poseidon2BabyBear::<WIDTH>::new(
            ExternalLayerConstants::new(
                beginning_full_constants.to_vec(),
                ending_full_constants.to_vec(),
            ),
            partial_constants.to_vec(),
        );

        // Generate random inputs.
        let mut rng = SmallRng::seed_from_u64(1);

        // Row A: new_start=true, sponge mode - use random initial state
        let state_a: [Val; WIDTH] = core::array::from_fn(|_| rng.random());
        let output_a = perm.permute(state_a);

        let sponge_a: Poseidon2CircuitRow<Val> = Poseidon2CircuitRow {
            new_start: true,
            merkle_path: false,
            mmcs_bit: false,
            mmcs_index_sum: Val::ZERO,
            input_values: state_a.to_vec(),
            in_ctl: [false; POSEIDON2_LIMBS],
            input_indices: [0; POSEIDON2_LIMBS],
            out_ctl: [false; POSEIDON2_PUBLIC_OUTPUT_LIMBS],
            output_indices: [0; POSEIDON2_PUBLIC_OUTPUT_LIMBS],
            mmcs_index_sum_idx: 0,
            mmcs_ctl_enabled: false,
        };

        // Row B: new_start=false, sponge mode - chain from output_a
        let state_b = output_a;
        let output_b = perm.permute(state_b);

        let sponge_b: Poseidon2CircuitRow<Val> = Poseidon2CircuitRow {
            new_start: false,
            merkle_path: false,
            mmcs_bit: true,
            mmcs_index_sum: Val::ZERO,
            input_values: state_b.to_vec(),
            in_ctl: [false; POSEIDON2_LIMBS],
            input_indices: [0; POSEIDON2_LIMBS],
            out_ctl: [false; POSEIDON2_PUBLIC_OUTPUT_LIMBS],
            output_indices: [0; POSEIDON2_PUBLIC_OUTPUT_LIMBS],
            mmcs_index_sum_idx: 0,
            mmcs_ctl_enabled: false,
        };

        // Row C: new_start=false, merkle mode, mmcs_bit=false
        // In merkle mode with mmcs_bit=0: prev digest (out[0..1]) goes to input limbs 0..1
        // The rest (limbs 2..3) can be zeros (sibling)
        const D: usize = 4; // extension degree
        let mut state_c = [Val::ZERO; WIDTH];
        // Chain prev output[0..2*D] into input[0..2*D] (limbs 0-1)
        state_c[0..2 * D].copy_from_slice(&output_b[0..2 * D]);
        let output_c = perm.permute(state_c);

        let sponge_c: Poseidon2CircuitRow<Val> = Poseidon2CircuitRow {
            new_start: false,
            merkle_path: true,
            mmcs_bit: false,
            mmcs_index_sum: Val::ZERO,
            input_values: state_c.to_vec(),
            in_ctl: [false; POSEIDON2_LIMBS],
            input_indices: [0; POSEIDON2_LIMBS],
            out_ctl: [false; POSEIDON2_PUBLIC_OUTPUT_LIMBS],
            output_indices: [0; POSEIDON2_PUBLIC_OUTPUT_LIMBS],
            mmcs_index_sum_idx: 0,
            mmcs_ctl_enabled: false,
        };

        // Row D: new_start=false, sponge mode - chain from output_c
        let state_d = output_c;

        let sponge_d: Poseidon2CircuitRow<Val> = Poseidon2CircuitRow {
            new_start: false,
            merkle_path: false,
            mmcs_bit: false,
            mmcs_index_sum: Val::ZERO,
            input_values: state_d.to_vec(),
            in_ctl: [false; POSEIDON2_LIMBS],
            input_indices: [0; POSEIDON2_LIMBS],
            out_ctl: [false; POSEIDON2_PUBLIC_OUTPUT_LIMBS],
            output_indices: [0; POSEIDON2_PUBLIC_OUTPUT_LIMBS],
            mmcs_index_sum_idx: 0,
            mmcs_ctl_enabled: false,
        };

        let mut rows = vec![sponge_a, sponge_b, sponge_c, sponge_d];
        let degree_bits = 5;
        let target_rows = 1 << degree_bits;
        if rows.len() < target_rows {
            // Filler rows must have new_start=true to avoid chaining constraints
            let filler = Poseidon2CircuitRow {
                new_start: true,
                merkle_path: false,
                mmcs_bit: false,
                mmcs_index_sum: Val::ZERO,
                input_values: vec![Val::ZERO; WIDTH],
                in_ctl: [false; POSEIDON2_LIMBS],
                input_indices: [0; POSEIDON2_LIMBS],
                out_ctl: [false; POSEIDON2_PUBLIC_OUTPUT_LIMBS],
                output_indices: [0; POSEIDON2_PUBLIC_OUTPUT_LIMBS],
                mmcs_index_sum_idx: 0,
                mmcs_ctl_enabled: false,
            };
            rows.resize(target_rows, filler);
        }

        let preprocessed = extract_preprocessed_from_operations::<Val, Val>(&rows);
        let air = Poseidon2CircuitAirBabyBearD4Width16::new_with_preprocessed(
            constants.clone(),
            preprocessed,
        );

        let trace = air.generate_trace_rows(&rows, &constants, fri_params.log_blowup);

        type Dft = p3_dft::Radix2Bowers;
        let dft = Dft::default();

        type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
        let pcs = Pcs::new(dft, val_mmcs, fri_params);

        type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
        let config = MyConfig::new(pcs, challenger);

        let (preprocessed_prover, preprocessed_verifier) =
            setup_preprocessed(&config, &air, degree_bits).unzip();
        let proof =
            prove_with_preprocessed(&config, &air, trace, &[], preprocessed_prover.as_ref());

        verify_with_preprocessed(&config, &air, &proof, &[], preprocessed_verifier.as_ref())
    }

    #[test]
    fn test_air_constraint_degree() {
        let mut rng = SmallRng::seed_from_u64(1);
        let constants = RoundConstants::new(rng.random(), rng.random(), rng.random());

        let air = Poseidon2CircuitAirBabyBearD4Width16::new(constants);
        p3_test_utils::assert_air_constraint_degree!(air, "Poseidon2CircuitAir");
    }
}
