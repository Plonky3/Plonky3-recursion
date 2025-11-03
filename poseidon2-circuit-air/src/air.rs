use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::borrow::Borrow;
use core::mem::MaybeUninit;
use core::{array, num};

use itertools::izip;
use p3_air::{Air, AirBuilder, BaseAir};
use p3_circuit::tables::{Poseidon2CircuitRow, Poseidon2CircuitTrace};
use p3_field::{PrimeCharacteristicRing, PrimeField};
use p3_matrix::Matrix;
use p3_matrix::dense::{RowMajorMatrix, RowMajorMatrixViewMut};
use p3_poseidon2::GenericPoseidon2LinearLayers;
use p3_poseidon2_air::{Poseidon2Air, RoundConstants, generate_trace_rows};
use p3_symmetric::CryptographicPermutation;
use tracing::info;

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
    const RATE: usize,
    const CAPACITY: usize,
    const WIDTH: usize,
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
    const RATE: usize,
    const CAPACITY: usize,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>
    Poseidon2CircuitAir<
        F,
        LinearLayers,
        D,
        RATE,
        CAPACITY,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >
{
    pub const fn new(
        constants: RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    ) -> Self {
        assert!((CAPACITY + RATE) * D == WIDTH);
        assert!(WIDTH.is_multiple_of(D));

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

        let num_circuit_cols = 3 + 2 * RATE + WIDTH;
        // let mut circuit_trace = Vec::with_capacity(n * num_circuit_cols);
        let mut circuit_trace = vec![F::ZERO; n * num_circuit_cols];
        let mut circuit_trace = RowMajorMatrixViewMut::new(&mut circuit_trace, num_circuit_cols);

        let mut state = [F::ZERO; WIDTH];
        let mut inputs = Vec::with_capacity(n);
        for (i, op) in sponge_ops.iter().enumerate() {
            info!("i: {i}");
            let Poseidon2CircuitRow {
                is_sponge,
                reset,
                absorb_flags,
                input_values,
                input_indices,
                output_indices,
            } = op;
            info!("hmm");

            let row = circuit_trace.row_mut(i);

            row[0] = if *is_sponge { F::ONE } else { F::ZERO };
            row[1] = if *reset { F::ONE } else { F::ZERO };
            row[2] = if *is_sponge && *reset {
                F::ONE
            } else {
                F::ZERO
            };
            for j in 0..RATE {
                row[3 + j] = if absorb_flags[j] { F::ONE } else { F::ZERO };
            }
            for j in 0..RATE {
                row[3 + RATE + j] = F::from_u32(input_indices[j]);
            }
            for j in 0..RATE {
                row[3 + RATE + WIDTH + j] = F::from_u32(output_indices[j]);
            }

            let mut index_absorb = [false; RATE];
            for j in 0..RATE {
                if absorb_flags[j] {
                    for k in 0..=j {
                        index_absorb[k] = true;
                    }
                }
            }

            for j in 0..RATE {
                if index_absorb[j] {
                    for d in 0..D {
                        let idx = j * D + d;
                        state[idx] = input_values[idx];
                    }
                }
            }

            if *reset || !*is_sponge {
                // Compression or reset: reset capacity
                for j in 0..(CAPACITY * D) {
                    state[RATE * D + j] = F::ZERO;
                }

                inputs.push(state.clone());
                state = perm.permute(state);
            }
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

        let ncols =
            num_cols::<WIDTH, RATE, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>(
            );

        info!("ncols: {}", ncols);

        let p2_ncols = p3_poseidon2_air::num_cols::<
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >();
        info!("p2_ncols: {}", p2_ncols);

        let mut vec = Vec::with_capacity((n * ncols) << extra_capacity_bits);
        let trace = &mut vec.spare_capacity_mut()[..n * ncols];
        let trace = RowMajorMatrixViewMut::new(trace, ncols);

        let (prefix, perms, suffix) = unsafe {
            trace.values.align_to_mut::<Poseidon2CircuitCols<
                MaybeUninit<F>,
                WIDTH,
                RATE,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >>()
        };
        assert!(prefix.is_empty(), "Alignment should match");
        assert!(suffix.is_empty(), "Alignment should match");
        assert_eq!(perms.len(), n);

        for (row, circuit_row, perm_row) in izip!(perms, circuit_trace.rows(), p2_trace.rows()) {
            let left_part = circuit_row.collect::<Vec<_>>();
            let right_part = perm_row.collect::<Vec<_>>();
            // row[..num_circuit_cols].copy_from_slice(&left_part);
            // row[num_circuit_cols..].copy_from_slice(&right_part);
        }

        info!("partial trace: {:?}", vec);

        unsafe {
            vec.set_len(n * ncols);
        }

        RowMajorMatrix::new(vec, ncols)
    }
}

impl<
    F: PrimeCharacteristicRing + Sync,
    LinearLayers: Sync,
    const D: usize,
    const RATE: usize,
    const CAPACITY: usize,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> BaseAir<F>
    for Poseidon2CircuitAir<
        F,
        LinearLayers,
        D,
        RATE,
        CAPACITY,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >
{
    fn width(&self) -> usize {
        num_cols::<WIDTH, RATE, SBOX_DEGREE, SBOX_REGISTERS, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>()
    }
}

pub(crate) fn eval<
    AB: AirBuilder,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
    const D: usize,
    const RATE: usize,
    const CAPACITY: usize,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>(
    air: &Poseidon2CircuitAir<
        AB::F,
        LinearLayers,
        D,
        RATE,
        CAPACITY,
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
    builder: &mut AB,
    local: &Poseidon2CircuitCols<
        AB::Var,
        WIDTH,
        RATE,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
    next: &Poseidon2CircuitCols<
        AB::Var,
        WIDTH,
        RATE,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
) {
    air.p3_poseidon2.eval(builder);

    // SPONGE CONSTRAINTS
    let next_no_reset = AB::Expr::ONE - next.reset.clone();
    for i in 0..(CAPACITY * D) {
        // The first row has capacity zeroed.
        builder
            .when(local.is_sponge.clone())
            .when_first_row()
            .assert_zero(local.poseidon2.inputs[RATE * D + i].clone());

        // When resetting the state, we just have to clear the capacity. The rate will be overwritten by the input.
        builder
            .when(local.is_sponge.clone())
            .when(local.reset.clone())
            .assert_zero(local.poseidon2.inputs[RATE * D + i].clone());

        // If the next row doesn't reset, propagate the capacity.
        builder
            .when(local.is_sponge.clone())
            .when(next_no_reset.clone())
            .assert_zero(
                next.poseidon2.inputs[RATE * D + i].clone()
                    - local.poseidon2.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[RATE * D + i]
                        .clone(),
            );
    }

    let mut next_absorb = [AB::Expr::ZERO; RATE];
    for i in 0..RATE {
        for col in next_absorb.iter_mut().take(RATE).skip(i) {
            *col += next.absorb_flags[i].clone();
        }
    }
    let next_no_absorb = array::from_fn::<_, RATE, _>(|i| AB::Expr::ONE - next_absorb[i].clone());
    // In the next row, each rate element not being absorbed comes from the current row.
    for index in 0..(RATE * D) {
        let i = index / D;
        let j = index % D;
        builder
            .when(local.is_sponge.clone())
            .when(next_no_absorb[i].clone())
            .assert_zero(
                next.poseidon2.inputs[i * D + j].clone()
                    - local.poseidon2.ending_full_rounds[HALF_FULL_ROUNDS - 1].post[i * D + j]
                        .clone(),
            );
    }

    let mut current_absorb = [AB::Expr::ZERO; RATE];
    for i in 0..RATE {
        for col in current_absorb.iter_mut().take(RATE).skip(i) {
            *col += local.absorb_flags[i].clone();
        }
    }
    let current_no_absorb =
        array::from_fn::<_, RATE, _>(|i| AB::Expr::ONE - current_absorb[i].clone());
    builder.assert_eq(
        local.is_sponge.clone() * local.reset.clone(),
        local.sponge_reset.clone(),
    );
    // During a reset, the rate elements not being absorbed are zeroed.
    for (i, col) in current_no_absorb.iter().enumerate().take(RATE) {
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
}

impl<
    AB: AirBuilder,
    LinearLayers: GenericPoseidon2LinearLayers<WIDTH>,
    const D: usize,
    const RATE: usize,
    const CAPACITY: usize,
    const WIDTH: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
> Air<AB>
    for Poseidon2CircuitAir<
        AB::F,
        LinearLayers,
        D,
        RATE,
        CAPACITY,
        WIDTH,
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
            RATE,
            CAPACITY,
            WIDTH,
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
    use core::array;

    use p3_baby_bear::{
        BabyBear, GenericPoseidon2LinearLayersBabyBear, default_babybear_poseidon2_16,
    };
    use p3_challenger::{HashChallenger, SerializingChallenger32};
    use p3_circuit::WitnessId;
    use p3_circuit::ops::MmcsVerifyConfig;
    use p3_circuit::tables::{
        MmcsPrivateData, MmcsTrace, Poseidon2CircuitRow, Poseidon2CircuitTrace,
    };
    use p3_commit::ExtensionMmcs;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{TwoAdicFriPcs, create_benchmark_fri_params};
    use p3_keccak::{Keccak256Hash, KeccakF};
    use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
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

    const WIDTH: usize = 16;
    const D: usize = 4;
    const RATE: usize = 2;
    const CAPACITY: usize = 2;
    const SBOX_DEGREE: u64 = 7;
    const SBOX_REGISTERS: usize = 1;
    const HALF_FULL_ROUNDS: usize = 4;
    const PARTIAL_ROUNDS: usize = 20;

    const P2_NUM_COLS: usize = p3_poseidon2_air::num_cols::<
        WIDTH,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >();

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
        let constants = RoundConstants::from_rng(&mut rng);
        let val_mmcs = ValMmcs::new(field_hash, compress, rng);

        type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

        type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
        let challenger = Challenger::from_hasher(vec![], byte_hash);

        let air: Poseidon2CircuitAir<
            Val,
            GenericPoseidon2LinearLayersBabyBear,
            D,
            RATE,
            CAPACITY,
            WIDTH,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        > = Poseidon2CircuitAir::new(constants.clone());

        // Generate random inputs.
        let mut rng = SmallRng::seed_from_u64(1);

        let a: Poseidon2CircuitRow<Val> = Poseidon2CircuitRow {
            is_sponge: true,
            reset: true,
            absorb_flags: vec![false, true],
            input_values: (0..RATE * D).map(|_| rng.random()).collect(),
            input_indices: vec![0; RATE],
            output_indices: vec![0; RATE],
        };

        let b: Poseidon2CircuitRow<Val> = Poseidon2CircuitRow {
            is_sponge: true,
            reset: true,
            absorb_flags: vec![false, true],
            input_values: (0..RATE * D).map(|_| rng.random()).collect(),
            input_indices: vec![0; RATE],
            output_indices: vec![0; RATE],
        };

        let fri_params = create_benchmark_fri_params(challenge_mmcs);

        let perm = default_babybear_poseidon2_16();
        let trace = air.generate_trace_rows(vec![a, b], &constants, fri_params.log_blowup, perm);

        type Dft = p3_dft::Radix2Bowers;
        let dft = Dft::default();

        type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
        let pcs = Pcs::new(dft, val_mmcs, fri_params);

        type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
        let config = MyConfig::new(pcs, challenger);

        let proof = prove(&config, &air, trace, &vec![]);

        verify(&config, &air, &proof, &vec![])
    }
}
