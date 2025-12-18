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
use p3_field::{PrimeCharacteristicRing, PrimeField};
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
        }
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
                input_indices,
                out_ctl,
                output_indices,
                mmcs_index_sum_idx,
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
            // - Merkle mode (merkle_path = 1): limbs 0-1 are chained from the previous output
            //   (left/right selected by mmcs_bit); limbs 2-3 come from the provided inputs.
            // - If in_ctl[i] = 1, that limb is NOT chained and comes from CTL/witness instead.
            //   The AIR constraints will enforce this (chaining is gated by 1 - in_ctl[i]).
            let mut state = padded_inputs;
            let i = inputs.len();
            if i > 0 && !*new_start {
                if *merkle_path {
                    // Merkle-path mode: the previous digest is always the previous row's out[0..1].
                    // `mmcs_bit` selects whether that digest is the left (0) or right (1) child:
                    // - bit=0: chain into limbs 0..1
                    // - bit=1: chain into limbs 2..3
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

            let normal_chain_sel: [bool; POSEIDON_LIMBS] =
                core::array::from_fn(|j| (!*new_start) && (!*merkle_path) && (!in_ctl[j]));
            let merkle_chain_sel: [bool; POSEIDON_LIMBS] =
                core::array::from_fn(|j| (!*new_start) && *merkle_path && (!in_ctl[j]));

            let (_p2_part, circuit_part) = row.split_at_mut(p2_ncols);

            circuit_part[0].write(F::from_bool(*new_start));
            circuit_part[1].write(F::from_bool(*merkle_path));
            circuit_part[2].write(F::from_bool(*mmcs_bit));
            circuit_part[3].write(acc);

            let mut offset = 4;
            for j in 0..POSEIDON_LIMBS {
                circuit_part[offset + j].write(F::from_bool(normal_chain_sel[j]));
            }
            offset += POSEIDON_LIMBS;
            for j in 0..POSEIDON_LIMBS {
                circuit_part[offset + j].write(F::from_bool(merkle_chain_sel[j]));
            }
            offset += POSEIDON_LIMBS;
            for j in 0..POSEIDON_LIMBS {
                circuit_part[offset + j].write(F::from_bool(in_ctl[j]));
            }
            offset += POSEIDON_LIMBS;
            for j in 0..POSEIDON_LIMBS {
                circuit_part[offset + j].write(F::from_u32(input_indices[j]));
            }
            offset += POSEIDON_LIMBS;
            for j in 0..POSEIDON_PUBLIC_OUTPUT_LIMBS {
                circuit_part[offset + j].write(F::from_bool(out_ctl[j]));
            }
            offset += POSEIDON_PUBLIC_OUTPUT_LIMBS;
            for j in 0..POSEIDON_PUBLIC_OUTPUT_LIMBS {
                circuit_part[offset + j].write(F::from_u32(output_indices[j]));
            }
            offset += POSEIDON_PUBLIC_OUTPUT_LIMBS;
            circuit_part[offset].write(F::from_u32(*mmcs_index_sum_idx));

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
    F: PrimeCharacteristicRing + Sync,
    LinearLayers: Sync,
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
}

fn eval<
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

    // Normal chaining.
    // If new_start_{r+1} = 0 and merkle_path_{r+1} = 0:
    //   in_{r+1}[i] = out_r[i] for i = 0..3
    // BUT: If in_ctl[i] = 1, CTL overrides chaining (limb is not chained).
    // Chaining only applies when in_ctl[limb] = 0.
    for limb in 0..POSEIDON_LIMBS {
        for d in 0..D {
            let idx = limb * D + d;
            let gate = next.normal_chain_sel[limb].clone();
            builder
                .when_transition()
                .when(gate)
                .assert_zero(next_in[idx].clone() - local_out[idx].clone());
        }
    }

    // Merkle-path chaining.
    // If new_start_{r+1} = 0 and merkle_path_{r+1} = 1:
    //   - If mmcs_bit_{r+1} = 0 (left = previous hash): in_{r+1}[0] = out_r[0], in_{r+1}[1] = out_r[1].
    //     Limbs 2-3 are free/private.
    //   - If mmcs_bit_{r+1} = 1 (right = previous hash): in_{r+1}[2] = out_r[0], in_{r+1}[3] = out_r[1].
    //     Limbs 0-1 are free/private.
    // BUT: If in_ctl[i] = 1, CTL overrides chaining (limb is not chained).
    // Chaining only applies when in_ctl[limb] = 0.
    let is_left = AB::Expr::ONE - next_bit.clone();

    // Limb 0: chain from out_r[0] (left), unless in_ctl[0] = 1. Not chained if Right.
    for d in 0..D {
        let gate_left_0 = next.merkle_chain_sel[0].clone() * is_left.clone();
        builder
            .when_transition()
            .when(gate_left_0)
            .assert_zero(next_in[d].clone() - local_out[d].clone());
    }

    // Limb 1: chain from out_r[1] (left), unless in_ctl[1] = 1. Not chained if Right.
    for d in 0..D {
        let gate_left_1 = next.merkle_chain_sel[1].clone() * is_left.clone();
        builder
            .when_transition()
            .when(gate_left_1)
            .assert_zero(next_in[D + d].clone() - local_out[D + d].clone());
    }

    // Limb 2: chain from out_r[0] (right), unless in_ctl[2] = 1. Not chained if Left.
    for d in 0..D {
        let gate_right_2 = next.merkle_chain_sel[2].clone() * next_bit.clone();
        builder
            .when_transition()
            .when(gate_right_2)
            .assert_zero(next_in[2 * D + d].clone() - local_out[d].clone());
    }

    // Limb 3: chain from out_r[1] (right), unless in_ctl[3] = 1. Not chained if Left.
    for d in 0..D {
        let gate_right_3 = next.merkle_chain_sel[3].clone() * next_bit.clone();
        builder
            .when_transition()
            .when(gate_right_3)
            .assert_zero(next_in[3 * D + d].clone() - local_out[D + d].clone());
    }

    // MMCS accumulator update.
    // If merkle_path_{r+1} = 1 and new_start_{r+1} = 0:
    //   mmcs_index_sum_{r+1} = mmcs_index_sum_r * 2 + mmcs_bit_{r+1}
    let two = AB::Expr::ONE + AB::Expr::ONE;
    let not_next_new_start = AB::Expr::ONE - next.new_start.clone();
    builder
        .when_transition()
        .when(not_next_new_start)
        .when(next.merkle_path.clone())
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
{
    #[inline]
    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("The matrix is empty?");
        let local = (*local).borrow();
        let next = main.row_slice(1).expect("The matrix has only one row?");
        let next = (*next).borrow();

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
        >(self, builder, local, next);
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

        // There are POSEIDON_LIMBS input limbs and POSEIDON_PUBLIC_OUTPUT_LIMBS output limbs to be lookup up in the `Witness` table.
        let mut lookups = Vec::with_capacity(POSEIDON_LIMBS + POSEIDON_PUBLIC_OUTPUT_LIMBS);
        // Each input/output limb is sent with multiplicity `in_ctl/out_ctl`.
        for (limb_idx, in_ctl) in local.in_ctl.iter().enumerate() {
            let input_idx_limb = iter::once(next.in_idx[limb_idx])
                .chain(
                    next.poseidon2.inputs[limb_idx * D..(limb_idx + 1) * D]
                        .iter()
                        .cloned(),
                )
                .map(SymbolicExpression::from)
                .collect::<Vec<_>>();

            let lookup_input = vec![(
                input_idx_limb,
                SymbolicExpression::from(*in_ctl),
                Direction::Send,
            )];

            lookups.push(AirLookupHandler::<AB>::register_lookup(
                self,
                Kind::Global("WitnessChecks".to_string()),
                &lookup_input,
            ));
        }

        for (limb_idx, out_ctl) in local.out_ctl.iter().enumerate() {
            let output_idx_limb = iter::once(local.out_idx[limb_idx])
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
                SymbolicExpression::from(*out_ctl),
                Direction::Send,
            )];

            lookups.push(AirLookupHandler::<AB>::register_lookup(
                self,
                Kind::Global("WitnessChecks".to_string()),
                &lookup_output,
            ));
        }

        // If next.new_start = 1 and local.merkle_path = 1, then mmcs_index_sum is exposed via CTL.
        let multiplicity = next.new_start * local.merkle_path;

        let mut mmcs_index_sum_lookup = vec![
            SymbolicExpression::from(local.mmcs_index_sum_idx),
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
    use p3_uni_stark::{StarkConfig, prove, verify};
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

        let air = Poseidon2CircuitAirBabyBearD4Width16::new(constants.clone());

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
        let target_rows = 32;
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

        let trace = air.generate_trace_rows(&rows, &constants, fri_params.log_blowup, &perm);

        type Dft = p3_dft::Radix2Bowers;
        let dft = Dft::default();

        type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
        let pcs = Pcs::new(dft, val_mmcs, fri_params);

        type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
        let config = MyConfig::new(pcs, challenger);

        let proof = prove(&config, &air, trace, &[]);

        verify(&config, &air, &proof, &[])
    }
}
