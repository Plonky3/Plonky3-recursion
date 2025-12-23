use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::iter;
use core::mem::MaybeUninit;

use p3_air::{
    Air, AirBuilder, AirBuilderWithPublicValues, BaseAir, PairBuilder, PermutationAirBuilder,
};
use p3_circuit::tables::{Poseidon2CircuitRow, Poseidon2CircuitTrace};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField};
use p3_lookup::lookup_traits::{AirLookupHandler, Direction, Kind, Lookup};
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_maybe_rayon::prelude::*;
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{Poseidon2Air, Poseidon2Cols, RoundConstants, generate_trace_rows_for_perm};
use p3_symmetric::CryptographicPermutation;
use p3_uni_stark::{SubAirBuilder, SymbolicAirBuilder, SymbolicExpression, SymbolicVariable};

use crate::columns::{POSEIDON_LIMBS, POSEIDON_PUBLIC_OUTPUT_LIMBS};
use crate::{Poseidon2CircuitCols, num_cols};

/// Extends the Poseidon2 AIR with recursion circuit-specific columns and constraints.
///
/// This implements the Poseidon Permutation Table specification.
/// See: https://github.com/Plonky3/Plonky3-recursion/discussions/186
///
/// The AIR enforces:
/// - Poseidon permutation constraint: out[0..3] = Poseidon2(in[0..3])
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
}

pub const fn poseidon_preprocessed_width() -> usize {
    // Witness index, `in_ctl`, `normal_chain_sel` and `merkle_chain_sel` for all input limbs, witness index and `out_ctl` for all output limbs, `mmcs_index_sum_ctl`, `new_start` and `merkle_path`.
    4 * POSEIDON_LIMBS + 2 * POSEIDON_PUBLIC_OUTPUT_LIMBS + 3
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
        }
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
        }
    }

    pub const fn preprocessed_width() -> usize {
        poseidon_preprocessed_width()
    }

    pub fn generate_trace_rows<P: CryptographicPermutation<[F; WIDTH]>>(
        &self,
        sponge_ops: &Poseidon2CircuitTrace<F>,
        constants: &RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
        extra_capacity_bits: usize,
        perm: &P,
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
        let mut prev_output: Option<[F; WIDTH]> = None;
        let mut prev_mmcs_index_sum = F::ZERO;

        // Split slice into rows
        let rows = trace_slice[..n * ncols].chunks_exact_mut(ncols);

        for (op, row) in sponge_ops.iter().zip(rows) {
            let Poseidon2CircuitRow {
                new_start,
                merkle_path,
                mmcs_bit,
                mmcs_index_sum,
                input_values,
                in_ctl,
                ..
            } = op;

            let mut padded_inputs = [F::ZERO; WIDTH];
            for (dst, src) in padded_inputs
                .iter_mut()
                .zip(
                    input_values
                        .iter()
                        .copied()
                        .chain(core::iter::repeat(F::ZERO)),
                )
                .take(WIDTH)
            {
                *dst = src;
            }

            // Apply chaining rules.
            // NOTE: For rows with new_start = false:
            // - Sponge mode (merkle_path = 0): all limbs come from the previous output unless
            //   a limb is exposed via in_ctl, in which case the provided input overrides it.
            // - Merkle mode (merkle_path = 1): the previous digest is always the previous output limbs 0-1.
            //   If mmcs_bit = 0 (previous digest is left child), chain into input limbs 0-1; input limbs 2-3 come from inputs.
            //   If mmcs_bit = 1 (previous digest is right child), chain into input limbs 2-3; input limbs 0-1 come from inputs.
            // - If in_ctl[i] = 1, that limb is NOT chained and comes from CTL/witness instead.
            //   The AIR constraints will enforce this (chaining is gated by 1 - in_ctl[i]).
            let mut state = padded_inputs;
            let i = inputs.len();
            if i > 0 && !*new_start {
                if *merkle_path {
                    // Merkle-path mode: the previous digest is always the previous row's out[0..1].
                    // `mmcs_bit` selects whether that digest is the left (0) or right (1) child:
                    // - bit=0: chain into input limbs 0..1
                    // - bit=1: chain into input limbs 2..3
                    if let Some(prev_out) = prev_output {
                        if !*mmcs_bit {
                            if !in_ctl[0] {
                                state[0..D].copy_from_slice(&prev_out[0..D]);
                            }
                            if !in_ctl[1] {
                                state[D..2 * D].copy_from_slice(&prev_out[D..2 * D]);
                            }
                        } else {
                            if !in_ctl[2] {
                                state[2 * D..3 * D].copy_from_slice(&prev_out[0..D]);
                            }
                            if !in_ctl[3] {
                                state[3 * D..4 * D].copy_from_slice(&prev_out[D..2 * D]);
                            }
                        }
                    }
                } else {
                    // Normal sponge mode: in_{r+1}[i] = out_r[i] for i = 0..3
                    if let Some(prev_out) = prev_output {
                        state
                            .chunks_exact_mut(D)
                            .zip(prev_out.chunks_exact(D))
                            .zip(in_ctl.iter())
                            .for_each(|((dst, src), ctl)| {
                                if !*ctl {
                                    dst.copy_from_slice(src);
                                }
                            });
                    }
                }
            }
            // If new_start = 1: no chaining, input determined solely by CTL

            // Update MMCS index accumulator
            let acc = if i > 0 && *merkle_path && !*new_start {
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

            // Save the state to be used as input for the heavy Poseidon trace generation
            inputs.push(state);
            prev_output = Some(perm.permute(state));
        }

        // Poseidon trace generation
        //
        // Now that we have the inputs, we can generate the expensive Poseidon columns in parallel.

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
        // 2. Poseidon columns were written in the parallel loop.
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

        let padded_height = self
            .preprocessed
            .len()
            .div_ceil(Self::preprocessed_width())
            .next_power_of_two()
            * Self::preprocessed_width();
        let mut preprocessed = self.preprocessed.clone();
        preprocessed.resize(padded_height, F::ZERO);

        Some(RowMajorMatrix::new(
            preprocessed,
            Self::preprocessed_width(),
        ))
    }
}

pub fn extract_preprocessed_from_operations<F: Field, OF: Field>(
    operations: &[Poseidon2CircuitRow<OF>],
) -> Vec<F> {
    let mut preprocessed = Vec::with_capacity(operations.len() * poseidon_preprocessed_width());

    for operation in operations {
        let Poseidon2CircuitRow {
            in_ctl,
            input_indices,
            out_ctl,
            output_indices,
            mmcs_index_sum_idx,
            new_start,
            merkle_path,
            ..
        } = operation;

        // One row of preprocessed values is of the form:
        // [input_indices[0], in_ctl[0], normal_chain_sel[0], merkle_chain_sel[0], ..., output_indices[1], out_ctl[1], output_indices[2], out_ctl[2], mmcs_index_sum_idx, new_start, merkle_path]
        in_ctl
            .iter()
            .zip(input_indices.iter())
            .for_each(|(ctl, idx)| {
                preprocessed.extend(&[F::from_u32(*idx), F::from_bool(*ctl)]);
                let normal_chain_sel = if !*new_start && !*merkle_path && !ctl {
                    F::ONE
                } else {
                    F::ZERO
                };

                preprocessed.push(normal_chain_sel);

                // In merkle mode:
                // - When mmcs_bit = 0: limbs 0-1 are chained, limbs 2-3 are private (sibling)
                // - When mmcs_bit = 1: limbs 2-3 are chained, limbs 0-1 are private (sibling)
                let merkle_chain_sel = if !new_start && *merkle_path && !ctl {
                    F::ONE
                } else {
                    F::ZERO
                };
                preprocessed.push(merkle_chain_sel);
            });
        out_ctl
            .iter()
            .zip(output_indices.iter())
            .for_each(|(ctl, idx)| {
                preprocessed.extend(&[F::from_u32(*idx), F::from_bool(*ctl)]);
            });
        preprocessed.push(F::from_u64(*mmcs_index_sum_idx as u64));
        preprocessed.push(F::from_bool(*new_start));
        preprocessed.push(F::from_bool(*merkle_path));
    }

    preprocessed
}

pub fn eval<
    AB: PairBuilder,
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
    //  out_idx[0], out_ctl[0], out_idx[1], out_ctl[1], mmcs_index_sum_ctl_idx, new_start, merkle_path]
    // The following corresponds to the size of the data related to one input limb (in_idx[i], in_ctl[i], normal_chain_sel[i], merkle_chain_sel[i]).
    let preprocessing_limb_data_size = 4;
    let normal_chain_idx = 2;
    let merkle_chain_idx = 3;
    let new_start_idx = 4 * POSEIDON_LIMBS + 2 * POSEIDON_PUBLIC_OUTPUT_LIMBS + 1;
    let merkle_path_idx = new_start_idx + 1;
    // Normal chaining.
    // If new_start_{r+1} = 0 and merkle_path_{r+1} = 0:
    //   in_{r+1}[i] = out_r[i] for i = 0..3
    // BUT: If in_ctl[i] = 1, CTL overrides chaining (limb is not chained).
    // Chaining only applies when in_ctl[limb] = 0.
    for limb in 0..POSEIDON_LIMBS {
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

    // Limb 2: chain from out_r[0] when mmcs_bit = 1 (right), unless in_ctl[2] = 1.
    // When mmcs_bit = 0 (left), limb 2 is private (sibling).
    for d in 0..D {
        let gate_right_2 = next_preprocessed[preprocessing_limb_data_size * 2 + merkle_chain_idx]
            .clone()
            * next_bit.clone();
        builder
            .when_transition()
            .when(gate_right_2)
            .assert_zero(next_in[2 * D + d].clone() - local_out[d].clone());
    }

    // Limb 3: chain from out_r[1] when mmcs_bit = 1 (right), unless in_ctl[3] = 1.
    // When mmcs_bit = 0 (left), limb 3 is private (sibling).
    for d in 0..D {
        let gate_right_3 = next_preprocessed[preprocessing_limb_data_size * 3 + merkle_chain_idx]
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

    // Enforce Poseidon permutation constraint:
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
    AB: PairBuilder,
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
    // SAFETY: Transmute the AIR to match builder's field type
    // Caller guarantees F == AB::F at runtime.
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
    AB: PairBuilder,
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

        let preprocessed = builder.preprocessed();
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
}

impl<
    AB: PermutationAirBuilder + PairBuilder + AirBuilderWithPublicValues,
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
> AirLookupHandler<AB>
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
    fn add_lookup_columns(&mut self) -> Vec<usize> {
        let lookup_column_idx = self.num_lookup_cols;
        self.num_lookup_cols += 1;
        vec![lookup_column_idx]
    }

    fn get_lookups(&mut self) -> Vec<Lookup<<AB>::F>> {
        let symbolic_air_builder = SymbolicAirBuilder::<AB::F>::new(
            0, // TODO: update the permutation width when implemented.
            BaseAir::<AB::F>::width(self),
            0,
            0, // Here, we do not need the permutation trace
            0,
        );
        let symbolic_main = symbolic_air_builder.main();
        let symbolic_main_local = symbolic_main.row_slice(0).expect("The matrix is empty?");
        let symbolic_main_next = symbolic_main
            .row_slice(1)
            .expect("The matrix has only one row?");

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

        let next: &Poseidon2CircuitCols<
            SymbolicVariable<AB::F>,
            Poseidon2Cols<
                SymbolicVariable<AB::F>,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >,
        > = (*symbolic_main_next).borrow();

        // Preprocessing layout:
        // [in_idx[0], in_ctl[0], normal_chain_sel[0], merkle_chain_sel[0], ..., in_idx[3], in_ctl[3], normal_chain_sel[3], merkle_chain_sel[3],
        //  out_idx[0], out_ctl[0], out_idx[1], out_ctl[1], mmcs_index_sum_ctl_idx, new_start, merkle_path]
        // The following corresponds to the size of the data related to one input limb (in_idx[i], in_ctl[i], normal_chain_sel[i], merkle_chain_sel[i]).
        let preprocessing_limb_input_data_size = 4;
        let preprocessing_limb_output_data_size = 4;
        let in_ctl_idx = 1;
        let start_output_idx = preprocessing_limb_input_data_size * POSEIDON_LIMBS;
        let mmcs_index_sum_ctl_idx =
            start_output_idx + preprocessing_limb_output_data_size * POSEIDON_PUBLIC_OUTPUT_LIMBS;
        let new_start_idx = mmcs_index_sum_ctl_idx + 1;
        let merkle_path_idx = new_start_idx + 1;

        let preprocessed = symbolic_air_builder.preprocessed();
        let local_preprocessed = preprocessed
            .row_slice(0)
            .expect("The preprocessed matrix has only one row?");
        let local_preprocessed: &[SymbolicVariable<AB::F>] = (*local_preprocessed).borrow();
        let next_preprocessed = preprocessed
            .row_slice(1)
            .expect("The preprocessed matrix has only one row?");
        let next_preprocessed: &[SymbolicVariable<AB::F>] = (*next_preprocessed).borrow();
        // There are POSEIDON_LIMBS input limbs and POSEIDON_PUBLIC_OUTPUT_LIMBS output limbs to be lookup up in the `Witness` table.
        let mut lookups = Vec::with_capacity(POSEIDON_LIMBS + POSEIDON_PUBLIC_OUTPUT_LIMBS);
        // Each input/output limb is sent with multiplicity `in_ctl/out_ctl`.
        for limb_idx in 0..POSEIDON_LIMBS {
            let in_ctl =
                local_preprocessed[limb_idx * preprocessing_limb_input_data_size + in_ctl_idx];
            let input_idx_limb =
                iter::once(next_preprocessed[limb_idx * preprocessing_limb_input_data_size]) // input witness index
                    .chain(
                        next.poseidon2.inputs[limb_idx * D..(limb_idx + 1) * D]
                            .iter()
                            .cloned(),
                    )
                    .map(SymbolicExpression::from)
                    .collect::<Vec<_>>();

            let lookup_input = vec![(
                input_idx_limb,
                SymbolicExpression::from(in_ctl),
                Direction::Send,
            )];

            lookups.push(AirLookupHandler::<AB>::register_lookup(
                self,
                Kind::Global("WitnessChecks".to_string()),
                &lookup_input,
            ));
        }

        for limb_idx in 0..POSEIDON_PUBLIC_OUTPUT_LIMBS {
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

            lookups.push(AirLookupHandler::<AB>::register_lookup(
                self,
                Kind::Global("WitnessChecks".to_string()),
                &lookup_output,
            ));
        }

        // If next.new_start = 1 and local.merkle_path = 1, then mmcs_index_sum is exposed via CTL.
        let next_new_start = next_preprocessed[new_start_idx];
        let local_merkle_path = local_preprocessed[merkle_path_idx];
        let multiplicity = next_new_start * local_merkle_path;

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
        lookups.push(AirLookupHandler::<AB>::register_lookup(
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
    use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
    use p3_uni_stark::{
        StarkConfig, prove_with_preprocessed, setup_preprocessed, verify_with_preprocessed,
    };
    use rand::rngs::SmallRng;
    use rand::{Rng, SeedableRng};

    use super::*;
    use crate::Poseidon2CircuitAirBabyBearD4Width16;
    use crate::columns::{POSEIDON_LIMBS, POSEIDON_PUBLIC_OUTPUT_LIMBS};

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
        let val_mmcs = ValMmcs::new(field_hash, compress, rng.clone());

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

        let first_state: Vec<Val> = (0..WIDTH).map(|_| rng.random()).collect();
        let zero_state = vec![Val::ZERO; WIDTH];

        let sponge_a: Poseidon2CircuitRow<Val> = Poseidon2CircuitRow {
            new_start: true,
            merkle_path: false,
            mmcs_bit: false,
            mmcs_index_sum: Val::ZERO,
            input_values: first_state,
            in_ctl: [false; POSEIDON_LIMBS],
            input_indices: [0; POSEIDON_LIMBS],
            out_ctl: [false; POSEIDON_PUBLIC_OUTPUT_LIMBS],
            output_indices: [0; POSEIDON_PUBLIC_OUTPUT_LIMBS],
            mmcs_index_sum_idx: 0,
        };

        let sponge_b: Poseidon2CircuitRow<Val> = Poseidon2CircuitRow {
            new_start: false,
            merkle_path: false,
            mmcs_bit: true,
            mmcs_index_sum: Val::ZERO,
            input_values: zero_state.clone(),
            in_ctl: [false; POSEIDON_LIMBS],
            input_indices: [0; POSEIDON_LIMBS],
            out_ctl: [false; POSEIDON_PUBLIC_OUTPUT_LIMBS],
            output_indices: [0; POSEIDON_PUBLIC_OUTPUT_LIMBS],
            mmcs_index_sum_idx: 0,
        };

        let sponge_c: Poseidon2CircuitRow<Val> = Poseidon2CircuitRow {
            new_start: false,
            merkle_path: true,
            mmcs_bit: false,
            mmcs_index_sum: Val::ZERO,
            input_values: zero_state.clone(),
            in_ctl: [false; POSEIDON_LIMBS],
            input_indices: [0; POSEIDON_LIMBS],
            out_ctl: [false; POSEIDON_PUBLIC_OUTPUT_LIMBS],
            output_indices: [0; POSEIDON_PUBLIC_OUTPUT_LIMBS],
            mmcs_index_sum_idx: 0,
        };

        let sponge_d: Poseidon2CircuitRow<Val> = Poseidon2CircuitRow {
            new_start: false,
            merkle_path: false,
            mmcs_bit: false,
            mmcs_index_sum: Val::ZERO,
            input_values: zero_state,
            in_ctl: [false; POSEIDON_LIMBS],
            input_indices: [0; POSEIDON_LIMBS],
            out_ctl: [false; POSEIDON_PUBLIC_OUTPUT_LIMBS],
            output_indices: [0; POSEIDON_PUBLIC_OUTPUT_LIMBS],
            mmcs_index_sum_idx: 0,
        };

        let mut rows = vec![sponge_a, sponge_b, sponge_c, sponge_d];
        let degree_bits = 5;
        let target_rows = 1 << degree_bits;
        if rows.len() < target_rows {
            let filler = rows.last().cloned().unwrap_or_else(|| Poseidon2CircuitRow {
                new_start: true,
                merkle_path: false,
                mmcs_bit: false,
                mmcs_index_sum: Val::ZERO,
                input_values: vec![Val::ZERO; WIDTH],
                in_ctl: [false; POSEIDON_LIMBS],
                input_indices: [0; POSEIDON_LIMBS],
                out_ctl: [false; POSEIDON_PUBLIC_OUTPUT_LIMBS],
                output_indices: [0; POSEIDON_PUBLIC_OUTPUT_LIMBS],
                mmcs_index_sum_idx: 0,
            });
            rows.resize(target_rows, filler);
        }

        let preprocessed = extract_preprocessed_from_operations::<Val, Val>(&rows);
        let air = Poseidon2CircuitAirBabyBearD4Width16::new_with_preprocessed(
            constants.clone(),
            preprocessed,
        );

        let trace = air.generate_trace_rows(&rows, &constants, fri_params.log_blowup, &perm);

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
}
