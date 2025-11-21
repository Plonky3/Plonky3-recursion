use alloc::vec;
use alloc::vec::Vec;
use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_circuit::tables::{Poseidon2CircuitRow, Poseidon2CircuitTrace};
use p3_field::{PrimeCharacteristicRing, PrimeField};
use p3_matrix::Matrix;
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{Poseidon2Air, Poseidon2Cols, RoundConstants, generate_trace_rows};
use p3_symmetric::CryptographicPermutation;

use crate::columns::{POSEIDON_LIMBS, POSEIDON_PUBLIC_OUTPUT_LIMBS};
use crate::sub_builder::SubAirBuilder;
use crate::{Poseidon2CircuitCols, num_cols};

/// Extends the Poseidon2 AIR with recursion circuit-specific columns and constraints.
///
/// This implements the Poseidon Permutation Table specification.
/// See: https://github.com/Plonky3/Plonky3-recursion/discussions/186
///
/// The AIR enforces:
/// - Poseidon permutation constraint: out[0..3] = Poseidon2(in[0..3]) (section 4)
/// - Chaining rules for normal sponge and Merkle-path modes (section 5)
/// - MMCS index accumulator updates (section 6)
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
        }
    }

    pub fn generate_trace_rows<P: CryptographicPermutation<[F; WIDTH]>>(
        &self,
        sponge_ops: Poseidon2CircuitTrace<F>,
        constants: &RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
        extra_capacity_bits: usize,
        perm: P,
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
        let num_circuit_cols = ncols - p2_ncols;

        let mut circuit_trace = vec![F::ZERO; n * num_circuit_cols];
        let mut circuit_trace = RowMajorMatrixViewMut::new(&mut circuit_trace, num_circuit_cols);

        let mut inputs = Vec::with_capacity(n);
        let mut prev_output: Option<[F; WIDTH]> = None;
        let mut prev_mmcs_index_sum = F::ZERO;

        for (i, op) in sponge_ops.iter().enumerate() {
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

            // Apply chaining rules (spec section 5: Chaining Rules).
            let mut state = padded_inputs;
            if i > 0 && !*new_start {
                if *merkle_path {
                    // Merkle-path mode (section 5.3): chain based on previous row's mmcs_bit
                    if let Some(prev_out) = prev_output {
                        let prev_bit = sponge_ops[i - 1].mmcs_bit;
                        if prev_bit {
                            // Case B: mmcs_bit = 1 (right = previous hash)
                            // in_{r+1}[0] = out_r[2], in_{r+1}[1] = out_r[3]
                            state[0..D].copy_from_slice(&prev_out[2 * D..3 * D]);
                            state[D..2 * D].copy_from_slice(&prev_out[3 * D..4 * D]);
                        } else {
                            // Case A: mmcs_bit = 0 (left = previous hash)
                            // in_{r+1}[0] = out_r[0], in_{r+1}[1] = out_r[1]
                            state[0..D].copy_from_slice(&prev_out[0..D]);
                            state[D..2 * D].copy_from_slice(&prev_out[D..2 * D]);
                        }
                        // in_{r+1}[2], in_{r+1}[3] remain free/private (from padded_inputs)
                    }
                } else {
                    // Normal sponge mode (section 5.2): in_{r+1}[i] = out_r[i] for i = 0..3
                    if let Some(prev_out) = prev_output {
                        state = prev_out;
                    }
                }
            }
            // If new_start = 1 (section 5.1): no chaining, input determined solely by CTL

            // Update MMCS index accumulator (spec section 6: MMCS Index Accumulator)
            let acc = if i > 0 && *merkle_path && !*new_start {
                // Section 6.1: mmcs_index_sum_{r+1} = mmcs_index_sum_r * 2 + mmcs_bit_r
                prev_mmcs_index_sum + prev_mmcs_index_sum + F::from_bool(sponge_ops[i - 1].mmcs_bit)
            } else {
                // Section 6.2: Reset behavior - unconstrained (use value from row)
                *mmcs_index_sum
            };
            prev_mmcs_index_sum = acc;

            let row = circuit_trace.row_mut(i);

            row[0] = F::from_bool(*new_start);
            row[1] = F::from_bool(*merkle_path);
            row[2] = F::from_bool(*mmcs_bit);
            row[3] = acc;

            let mut offset = 4;
            for j in 0..POSEIDON_LIMBS {
                row[offset + j] = F::from_bool(in_ctl[j]);
            }
            offset += POSEIDON_LIMBS;
            for j in 0..POSEIDON_LIMBS {
                row[offset + j] = F::from_u32(input_indices[j]);
            }
            offset += POSEIDON_LIMBS;
            for j in 0..POSEIDON_PUBLIC_OUTPUT_LIMBS {
                row[offset + j] = F::from_bool(out_ctl[j]);
            }
            offset += POSEIDON_PUBLIC_OUTPUT_LIMBS;
            for j in 0..POSEIDON_PUBLIC_OUTPUT_LIMBS {
                row[offset + j] = F::from_u32(output_indices[j]);
            }
            offset += POSEIDON_PUBLIC_OUTPUT_LIMBS;
            row[offset] = F::from_u32(*mmcs_index_sum_idx);

            inputs.push(state);
            prev_output = Some(perm.permute(state));
        }

        let p2_trace = generate_trace_rows::<
            F,
            LinearLayers,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >(inputs, constants, extra_capacity_bits);

        let ncols = self.width();

        debug_assert_eq!(ncols, num_circuit_cols + p2_ncols);

        let mut vec = vec![F::ZERO; n * ncols];

        let circuit_trace_view = circuit_trace.as_view();

        // TODO: Remove Poseidon2 air copy, possibly by making `generate_trace_rows_for_perm` public on P3 side
        for ((row, left_part), right_part) in vec
            .chunks_exact_mut(ncols)
            .zip(p2_trace.row_slices())
            .zip(circuit_trace_view.row_slices())
        {
            row[..p2_ncols].copy_from_slice(left_part);
            row[p2_ncols..].copy_from_slice(right_part);
        }

        RowMajorMatrix::new(vec, ncols)
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
    builder.assert_bool(local.new_start.clone());
    builder.assert_bool(next.new_start.clone());
    builder.assert_bool(local.merkle_path.clone());
    builder.assert_bool(next.merkle_path.clone());
    builder.assert_bool(local.mmcs_bit.clone());
    builder.assert_bool(next.mmcs_bit.clone());
    for flag in local.in_ctl.iter() {
        builder.assert_bool(flag.clone());
    }
    for flag in local.out_ctl.iter() {
        builder.assert_bool(flag.clone());
    }

    let continue_chain = AB::Expr::ONE - next.new_start.clone();
    let next_merkle = next.merkle_path.clone();
    let next_not_merkle = AB::Expr::ONE - next_merkle.clone();
    let prev_bit = local.mmcs_bit.clone();
    let local_out = &local.poseidon2.ending_full_rounds[HALF_FULL_ROUNDS - 1].post;
    let next_in = &next.poseidon2.inputs;

    // Normal chaining (section 5.2: Normal Sponge Mode).
    // If new_start_{r+1} = 0 and merkle_path_{r+1} = 0:
    //   in_{r+1}[i] = out_r[i] for i = 0..3
    for idx in 0..WIDTH {
        builder
            .when_transition()
            .when(continue_chain.clone())
            .when(next_not_merkle.clone())
            .assert_zero(next_in[idx].clone() - local_out[idx].clone());
    }

    // Merkle-path chaining (section 5.3: Merkle Path Mode).
    // If new_start_{r+1} = 0 and merkle_path_{r+1} = 1:
    //   - If mmcs_bit_r = 0 (left = previous hash): in_{r+1}[0] = out_r[0], in_{r+1}[1] = out_r[1]
    //   - If mmcs_bit_r = 1 (right = previous hash): in_{r+1}[0] = out_r[2], in_{r+1}[1] = out_r[3]
    //   - in_{r+1}[2], in_{r+1}[3] are free/private
    let is_left = AB::Expr::ONE - prev_bit.clone();
    for limb_offset in 0..D {
        builder
            .when_transition()
            .when(continue_chain.clone())
            .when(next_merkle.clone())
            .when(is_left.clone())
            .assert_zero(next_in[limb_offset].clone() - local_out[limb_offset].clone());
        builder
            .when_transition()
            .when(continue_chain.clone())
            .when(next_merkle.clone())
            .when(is_left.clone())
            .assert_zero(next_in[D + limb_offset].clone() - local_out[D + limb_offset].clone());

        builder
            .when_transition()
            .when(continue_chain.clone())
            .when(next_merkle.clone())
            .when(prev_bit.clone())
            .assert_zero(next_in[limb_offset].clone() - local_out[2 * D + limb_offset].clone());
        builder
            .when_transition()
            .when(continue_chain.clone())
            .when(next_merkle.clone())
            .when(prev_bit.clone())
            .assert_zero(next_in[D + limb_offset].clone() - local_out[3 * D + limb_offset].clone());
    }

    // MMCS accumulator update (section 6.1: Recurrence).
    // If merkle_path_{r+1} = 1 and new_start_{r+1} = 0:
    //   mmcs_index_sum_{r+1} = mmcs_index_sum_r * 2 + mmcs_bit_r
    let two = AB::Expr::ONE + AB::Expr::ONE;
    builder
        .when_transition()
        .when(continue_chain.clone())
        .when(next_merkle.clone())
        .assert_zero(
            next.mmcs_index_sum.clone()
                - (local.mmcs_index_sum.clone() * two + local.mmcs_bit.clone()),
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

    // Enforce Poseidon permutation constraint (spec section 4):
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

#[cfg(test)]
mod test {
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

        let trace = air.generate_trace_rows(rows, &constants, fri_params.log_blowup, perm);

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
