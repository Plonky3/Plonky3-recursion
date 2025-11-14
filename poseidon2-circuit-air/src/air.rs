use alloc::vec;
use alloc::vec::Vec;
use core::array;
use core::borrow::Borrow;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_circuit::tables::{Poseidon2CircuitRow, Poseidon2CircuitTrace};
use p3_field::{PrimeCharacteristicRing, PrimeField};
use p3_matrix::Matrix;
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{Poseidon2Air, Poseidon2Cols, RoundConstants, generate_trace_rows};
use p3_symmetric::CryptographicPermutation;

use crate::sub_builder::SubAirBuilder;
use crate::{Poseidon2CircuitCols, num_cols};

/// Extends the Poseidon2 AIR with recursion circuit-specific columns and constraints.
/// Assumes the field size is at least 16 bits.
///
/// SPECIFIC ASSUMPTIONS:
/// - Memory elements from the witness table are extension elements of degree D.
/// - RATE and CAPACITY are the number of extension elements in the rate/capacity.
/// - WIDTH is the number of field elements in the state, i.e., (RATE + CAPACITY) * D.
/// - `reset` can only be set during an absorb.
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
        assert!(CAPACITY_EXT + RATE_EXT == WIDTH_EXT);
        assert!(WIDTH_EXT * D == WIDTH);

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

        let num_circuit_cols = 3 + 2 * RATE_EXT + WIDTH_EXT;
        let mut circuit_trace = vec![F::ZERO; n * num_circuit_cols];
        let mut circuit_trace = RowMajorMatrixViewMut::new(&mut circuit_trace, num_circuit_cols);

        // TODO: Put trace generation circuit-side.
        let mut state = [F::ZERO; WIDTH];
        let mut inputs = Vec::with_capacity(n);
        for (i, op) in sponge_ops.iter().enumerate() {
            let Poseidon2CircuitRow {
                is_sponge,
                reset,
                absorb_flags,
                input_values,
                input_indices,
                output_indices,
            } = op;

            let row = circuit_trace.row_mut(i);

            row[0] = if *is_sponge { F::ONE } else { F::ZERO };
            row[1] = if *reset { F::ONE } else { F::ZERO };
            row[2] = if *is_sponge && *reset {
                F::ONE
            } else {
                F::ZERO
            };
            for j in 0..RATE_EXT {
                row[3 + j] = if absorb_flags[j] { F::ONE } else { F::ZERO };
            }
            for j in 0..RATE_EXT {
                row[3 + RATE_EXT + j] = F::from_u32(input_indices[j]);
            }
            for j in 0..RATE_EXT {
                row[3 + RATE_EXT + WIDTH_EXT + j] = F::from_u32(output_indices[j]);
            }

            let mut index_absorb = [false; RATE_EXT];
            for (j, flag) in absorb_flags.iter().enumerate() {
                if *flag {
                    for absorb in index_absorb.iter_mut().take(j + 1) {
                        *absorb = true;
                    }
                }
            }

            for (j, absorb) in index_absorb.iter_mut().enumerate() {
                if *absorb {
                    for d in 0..D {
                        let idx = j * D + d;
                        state[idx] = input_values[idx];
                    }
                } else if *reset {
                    // During a reset, non-absorbed rate elements are zeroed.
                    for d in 0..D {
                        let idx = j * D + d;
                        state[idx] = F::ZERO;
                    }
                }
            }

            if *reset || !*is_sponge {
                // Compression or reset: reset capacity
                for j in 0..(CAPACITY_EXT * D) {
                    state[RATE_EXT * D + j] = F::ZERO;
                }
            }

            inputs.push(state);
            state = perm.permute(state);
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

        let p2_ncols = p3_poseidon2_air::num_cols::<
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >();

        let mut vec = vec![F::ZERO; n * ncols];

        let circuit_trace_view = circuit_trace.as_view();

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
            WIDTH_EXT,
            RATE_EXT,
            Poseidon2Cols<u8, WIDTH, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
        >()
    }
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
        WIDTH_EXT,
        RATE_EXT,
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
        WIDTH_EXT,
        RATE_EXT,
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
    // SPONGE CONSTRAINTS
    let next_no_reset = AB::Expr::ONE - next.reset.clone();
    for i in 0..(CAPACITY_EXT * D) {
        // The first row has capacity zeroed.
        builder
            .when(local.is_sponge.clone())
            .when_first_row()
            .assert_zero(local.poseidon2.inputs[RATE_EXT * D + i].clone());

        // When resetting the state, we just have to clear the capacity. The rate will be overwritten by the input.
        builder
            .when(local.is_sponge.clone())
            .when(local.reset.clone())
            .assert_zero(local.poseidon2.inputs[RATE_EXT * D + i].clone());

        // If the next row doesn't reset, propagate the capacity.
        builder
            .when_transition()
            .when(next.is_sponge.clone())
            .when(next_no_reset.clone())
            .assert_zero(
                next.poseidon2.inputs[RATE_EXT * D + i].clone()
                    - local.poseidon2.ending_full_rounds[HALF_FULL_ROUNDS - 1].post
                        [RATE_EXT * D + i]
                        .clone(),
            );
    }

    let mut next_absorb = [AB::Expr::ZERO; RATE_EXT];
    for i in 0..RATE_EXT {
        for col in next_absorb.iter_mut().take(i + 1) {
            *col += next.absorb_flags[i].clone();
        }
    }
    let next_no_absorb =
        array::from_fn::<_, RATE_EXT, _>(|i| AB::Expr::ONE - next_absorb[i].clone());
    // In the next row, each rate element not being absorbed is either:
    // - zeroed if the next row is a reset (handled elsewhere);
    // - copied from the current row if the next row is not a reset.
    // We omit the `is_sponge` check because in a compression all absorb flags are set.
    for index in 0..(RATE_EXT * D) {
        let i = index / D;
        let j = index % D;
        builder
            .when_transition()
            .when(next_no_absorb[i].clone())
            .when(next_no_reset.clone())
            .assert_zero(
                next.poseidon2.inputs[i * D + j].clone()
                    - local.poseidon2.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[i * D + j]
                        .clone(),
            );
    }

    let mut current_absorb = [AB::Expr::ZERO; RATE_EXT];
    for i in 0..RATE_EXT {
        for col in current_absorb.iter_mut().take(i + 1) {
            *col += local.absorb_flags[i].clone();
        }
    }
    let current_no_absorb =
        array::from_fn::<_, RATE_EXT, _>(|i| AB::Expr::ONE - current_absorb[i].clone());
    builder.assert_eq(
        local.is_sponge.clone() * local.reset.clone(),
        local.sponge_reset.clone(),
    );
    // During a reset, the rate elements not being absorbed are zeroed.
    for (i, col) in current_no_absorb.iter().enumerate() {
        let arr = array::from_fn::<_, D, _>(|j| local.poseidon2.inputs[i * D + j].clone().into());
        builder
            .when(local.sponge_reset.clone() * col.clone())
            .assert_zeros(arr);
    }

    let _is_squeeze = AB::Expr::ONE - current_absorb[0].clone();
    // TODO: Add all lookups:
    // - If current_absorb[i] = 1:
    //      * local.rate[i] comes from input lookups.
    // - If is_squeeze = 1:
    //      * local.rate is sent to output lookups.

    // COMPRESSION CONSTRAINTS
    // TODO: Add all lookups:
    // - local input state comes from input lookups.
    // - send local output state to output lookups.

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

    // Eval the Plonky3 Poseidon2 air.
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

    use alloc::vec;

    use p3_baby_bear::{
        BabyBear, GenericPoseidon2LinearLayersBabyBear, Poseidon2ExternalLayerBabyBear,
        Poseidon2InternalLayerBabyBear,
    };
    use p3_challenger::{HashChallenger, SerializingChallenger32};
    use p3_circuit::tables::Poseidon2CircuitRow;
    use p3_commit::ExtensionMmcs;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{TwoAdicFriPcs, create_benchmark_fri_params};
    use p3_keccak::{Keccak256Hash, KeccakF};
    use p3_merkle_tree::MerkleTreeHidingMmcs;
    use p3_poseidon2::{ExternalLayerConstants, Poseidon2};
    use p3_poseidon2_air::RoundConstants;
    use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};
    use p3_uni_stark::{StarkConfig, prove, verify};
    use rand::rngs::SmallRng;
    use rand::{Rng, SeedableRng};
    use tracing_forest::ForestLayer;
    use tracing_forest::util::LevelFilter;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{EnvFilter, Registry};

    use crate::air::Poseidon2CircuitAir;

    const D: usize = 4;
    const WIDTH: usize = 16;
    const WIDTH_EXT: usize = 4;
    const RATE_EXT: usize = 2;
    const CAPACITY_EXT: usize = 2;
    const SBOX_DEGREE: u64 = 7;
    const SBOX_REGISTERS: usize = 1;
    const HALF_FULL_ROUNDS: usize = 4;
    const PARTIAL_ROUNDS: usize = 20;

    fn init_logger() {
        let env_filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();

        Registry::default()
            .with(env_filter)
            .with(ForestLayer::default())
            .init();
    }

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
        init_logger();
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

        let fri_params = create_benchmark_fri_params(challenge_mmcs);

        let beginning_full_constants = rng.random();
        let partial_constants = rng.random();
        let ending_full_constants = rng.random();

        let constants = RoundConstants::new(
            beginning_full_constants,
            partial_constants,
            ending_full_constants,
        );

        let perm = Poseidon2::<
            Val,
            Poseidon2ExternalLayerBabyBear<WIDTH>,
            Poseidon2InternalLayerBabyBear<WIDTH>,
            WIDTH,
            SBOX_DEGREE,
        >::new(
            ExternalLayerConstants::new(
                beginning_full_constants.to_vec(),
                ending_full_constants.to_vec(),
            ),
            partial_constants.to_vec(),
        );

        let air: Poseidon2CircuitAir<
            Val,
            GenericPoseidon2LinearLayersBabyBear,
            D,
            WIDTH,
            WIDTH_EXT,
            RATE_EXT,
            CAPACITY_EXT,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        > = Poseidon2CircuitAir::new(constants.clone());

        // Generate random inputs.
        let mut rng = SmallRng::seed_from_u64(1);

        // Absorb
        let sponge_a: Poseidon2CircuitRow<Val> = Poseidon2CircuitRow {
            is_sponge: true,
            reset: true,
            absorb_flags: vec![false, true],
            input_values: (0..RATE_EXT * D).map(|_| rng.random()).collect(),
            input_indices: vec![0; RATE_EXT],
            output_indices: vec![0; RATE_EXT],
        };

        // Absorb
        let sponge_b: Poseidon2CircuitRow<Val> = Poseidon2CircuitRow {
            is_sponge: true,
            reset: false,
            absorb_flags: vec![false, true],
            input_values: (0..RATE_EXT * D).map(|_| rng.random()).collect(),
            input_indices: vec![0; RATE_EXT],
            output_indices: vec![0; RATE_EXT],
        };

        // Squeeze
        let sponge_c: Poseidon2CircuitRow<Val> = Poseidon2CircuitRow {
            is_sponge: true,
            reset: false,
            absorb_flags: vec![false, false],
            input_values: vec![Val::new(0); RATE_EXT * D],
            input_indices: vec![0; RATE_EXT],
            output_indices: vec![0; RATE_EXT],
        };

        // Absorb one element with reset
        let sponge_d: Poseidon2CircuitRow<Val> = Poseidon2CircuitRow {
            is_sponge: true,
            reset: true,
            absorb_flags: vec![true, false],
            input_values: vec![
                Val::new(42),
                Val::new(43),
                Val::new(44),
                Val::new(45),
                Val::new(0),
                Val::new(0),
                Val::new(0),
                Val::new(0),
            ],
            input_indices: vec![0; RATE_EXT],
            output_indices: vec![0; RATE_EXT],
        };

        let trace = air.generate_trace_rows(
            vec![sponge_a, sponge_b, sponge_c, sponge_d],
            &constants,
            fri_params.log_blowup,
            perm,
        );

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
