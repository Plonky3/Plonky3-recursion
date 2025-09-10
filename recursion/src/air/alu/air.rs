use std::borrow::Borrow;
use std::ops::{Add, Mul, Sub};

use itertools::izip;
use p3_air::{Air, AirBuilder};
use p3_field::Field;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use rand::distr::{Distribution, StandardUniform};
use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};

use crate::air::alu::cols::{AluCols, FieldOpEvent};
use crate::circuit_builder::gates::event::AllEvents;

pub trait Operation {
    fn apply<I: Add<Output = O> + Sub<Output = O> + Mul<Output = O>, O>(
        &self,
        left: I,
        right: I,
    ) -> O;
}

pub trait GenerateAluTrace<const R: usize> {
    const TRACE_WIDTH: usize = 6 * R;
    fn build_trace<'a, F: Field, I: Iterator<Item = &'a FieldOpEvent<F>>>(
        events: I,
        events_len: usize,
    ) -> RowMajorMatrix<F> {
        let n_padded = events_len.next_power_of_two();
        let mut trace =
            RowMajorMatrix::new(F::zero_vec(n_padded * Self::TRACE_WIDTH), Self::TRACE_WIDTH);

        let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<AluCols<F, R>>() };
        assert!(prefix.is_empty(), "Alignment should match");
        assert!(suffix.is_empty(), "Alignment should match");
        assert_eq!(rows.len(), events_len);

        for event in events {
            println!("event = {:?}", *event);
            for i in 0..R {
                let row = &mut rows[i];
                row.left_addr[i] = F::from_usize(event.left_addr[i]);
                row.left_val[i] = event.left_val[i];
                row.right_addr[i] = F::from_usize(event.right_addr[i]);
                row.right_val[i] = event.right_val[i];
                row.res_addr[i] = F::from_usize(event.res_addr[i]);
                row.res_val[i] = event.res_val[i];
            }
        }
        trace
    }
}

/*
Asserts a op b = c, where op in {+, -, *}.
(so that the total constraint degree is self.degree).
REPETITIONS counts how many `a * b = c` operations to do per row in the AIR
*/
pub trait AluAir<AB: AirBuilder, const R: usize = 1>:
    Operation + Air<AB> + GenerateAluTrace<R>
{
    fn random_valid_trace<F: Field>(&self, rows: usize, valid: bool) -> RowMajorMatrix<F>
    where
        StandardUniform: Distribution<F>,
    {
        let mut rng = SmallRng::seed_from_u64(1);
        let n_padded = rows.next_power_of_two();
        let mut trace =
            RowMajorMatrix::new(F::zero_vec(n_padded * Self::TRACE_WIDTH), Self::TRACE_WIDTH);

        let (prefix, rows, suffix) = unsafe { trace.values.align_to_mut::<AluCols<F, R>>() };
        assert!(prefix.is_empty(), "Alignment should match");
        assert!(suffix.is_empty(), "Alignment should match");
        assert_eq!(rows.len(), n_padded);

        for (i, row) in rows.iter_mut().enumerate() {
            for (left_addr, left_val, right_addr, right_val, res_addr, res_val) in izip!(
                row.left_addr.iter_mut(),
                row.left_val.iter_mut(),
                row.right_addr.iter_mut(),
                row.right_val.iter_mut(),
                row.res_addr.iter_mut(),
                row.res_val.iter_mut(),
            ) {
                *left_addr = F::from_usize(3 * i);
                *left_val = rng.random();
                *right_addr = F::from_usize(3 * i + 1);
                *right_val = rng.random();
                *res_addr = F::from_usize(3 * i + 2);
                *res_val = self.apply(*left_val, *right_val);
                if !valid {
                    // make it invalid
                    *res_val *= F::TWO;
                }
            }
        }
        trace
    }

    fn width(&self) -> usize {
        Self::TRACE_WIDTH
    }

    fn eval(&self, builder: &mut AB) {
        let main = builder.main();
        let local = main.row_slice(0).expect("Matrix is empty?");
        let local: &AluCols<AB::Var> = (*local).borrow();

        for ((left_val, right_val), res_val) in local
            .left_val
            .iter()
            .zip(local.right_val.iter())
            .zip(local.res_val.iter())
        {
            builder.assert_eq(
                self.apply(left_val.clone(), right_val.clone()),
                res_val.clone(),
            );
        }
    }
}

#[macro_export]
macro_rules! operation_air {
    ($OpAir:ident, $op:tt, $events:ident) => {
        pub struct $OpAir<const REPETITIONS: usize = 1> {
        }

        impl<const REPETITIONS: usize> $OpAir<REPETITIONS> {
            pub const fn new() -> Self {
                Self {  }
            }
        }

        impl<const REPETITIONS: usize> GenerateAluTrace<REPETITIONS> for $OpAir<REPETITIONS> {}

        // your per-op behavior
        impl<const REPETITIONS: usize> $crate::air::alu::air::Operation for $OpAir<REPETITIONS> {
            fn apply<I, O>(&self, left: I, right: I) -> O
            where
                I: core::ops::Add<Output = O>
                 + core::ops::Sub<Output = O>
                 + core::ops::Mul<Output = O>,
            { left $op right }
        }

        impl<F, const REPETITIONS: usize> p3_air::BaseAir<F> for $OpAir<REPETITIONS> {
            #[inline] fn width(&self) -> usize { 6 * REPETITIONS }
        }

        // Implement p3_air::Air for ANY builder AB
        impl<AB, const REPETITIONS: usize> p3_air::Air<AB> for $OpAir<REPETITIONS>
        where
            AB: p3_air::AirBuilder,
        {
            #[inline] fn eval(&self, builder: &mut AB) {
                <Self as $crate::air::alu::air::AluAir<AB, REPETITIONS>>::eval(self, builder)
            }
        }

        // And your AluAir bridge for ANY builder AB
        impl<AB, const REPETITIONS: usize> $crate::air::alu::air::AluAir<AB, REPETITIONS> for $OpAir<REPETITIONS>
        where
            AB: p3_air::AirBuilder,
        {}

        impl<SC: p3_uni_stark::StarkGenericConfig, AB: AirBuilder, const REPETITIONS: usize> $crate::prover::tables::AirWithTraceGenerationFromEvents<SC, AB>
        for $OpAir<REPETITIONS>
        {
            fn generate_trace(&self, all_events: &AllEvents<p3_uni_stark::Val<SC>>) -> RowMajorMatrix<p3_uni_stark::Val<SC>> {
                <Self as GenerateAluTrace<REPETITIONS>>::build_trace(
                    all_events.$events.iter().map(|x| &x.0),
                    all_events.$events.len(),
                )
            }
            fn prove_chip(&self, config: &SC, trace: RowMajorMatrix<p3_uni_stark::Val<SC>>) -> p3_uni_stark::Proof<SC> {
                p3_uni_stark::prove(config, self, trace, &vec![])
            }
            fn verify_chip(&self, config: &SC, proof: &p3_uni_stark::Proof<SC>) -> Result<(), p3_uni_stark::VerificationError<p3_uni_stark::PcsError<SC>>> {
                p3_uni_stark::verify(config, self, proof, &vec![])
            }
        }
    };
}
operation_air!(AddAir, +, add_events);
operation_air!(SubAir, -, sub_events);
operation_air!(MulAir, *, mul_events);

#[cfg(test)]
mod test {
    use core::fmt::Debug;
    use core::marker::PhantomData;

    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::{DuplexChallenger, HashChallenger, SerializingChallenger32};
    use p3_circle::CirclePcs;
    use p3_commit::ExtensionMmcs;
    use p3_commit::testing::TrivialPcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::Field;
    use p3_field::extension::BinomialExtensionField;
    use p3_fri::{FriParameters, HidingFriPcs, TwoAdicFriPcs, create_test_fri_params_zk};
    use p3_keccak::Keccak256Hash;
    use p3_merkle_tree::{MerkleTreeHidingMmcs, MerkleTreeMmcs};
    use p3_mersenne_31::Mersenne31;
    use p3_symmetric::{
        CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher, TruncatedPermutation,
    };
    use p3_uni_stark::{
        DebugConstraintBuilder, ProverConstraintFolder, StarkConfig, StarkGenericConfig,
        SymbolicAirBuilder, Val, VerifierConstraintFolder, prove, verify,
    };
    use rand::SeedableRng;
    use rand::distr::{Distribution, StandardUniform};
    use rand::rngs::SmallRng;

    use crate::air::alu::air::{AddAir, AluAir, SubAir};

    fn do_test<SC: StarkGenericConfig, A: AluAir<SymbolicAirBuilder<Val<SC>>>>(
        config: SC,
        air: A,
        log_height: usize,
    ) -> Result<(), impl Debug>
    where
        SC::Challenger: Clone,
        StandardUniform: Distribution<Val<SC>>,
        // A must implement your ALU AIR for the debug builder (gives you Air<…> too)
        for<'a> A: AluAir<DebugConstraintBuilder<'a, Val<SC>>>,
        // and also be usable by the prover folder
        for<'a> A: AluAir<ProverConstraintFolder<'a, SC>>,
        for<'a> A: AluAir<ProverConstraintFolder<'a, SC>>,
        for<'a> A: AluAir<VerifierConstraintFolder<'a, SC>>,
    {
        let trace = <A as crate::air::alu::air::AluAir<
            DebugConstraintBuilder<'_, Val<SC>>
        >>::random_valid_trace::<Val<SC>>(&air, log_height, true);

        let proof = prove(&config, &air, trace, &vec![]);

        let serialized_proof = postcard::to_allocvec(&proof).expect("unable to serialize proof");
        tracing::debug!("serialized_proof len: {} bytes", serialized_proof.len());

        let deserialized_proof =
            postcard::from_bytes(&serialized_proof).expect("unable to deserialize proof");

        verify(&config, &air, &deserialized_proof, &vec![])
    }

    fn do_test_bb_trivial(log_n: usize) -> Result<(), impl Debug> {
        type Val = BabyBear;
        type Challenge = BinomialExtensionField<Val, 4>;

        type Perm = Poseidon2BabyBear<16>;
        let mut rng = SmallRng::seed_from_u64(1);
        let perm = Perm::new_from_rng_128(&mut rng);

        type Dft = Radix2DitParallel<Val>;
        let dft = Dft::default();

        type Challenger = DuplexChallenger<Val, Perm, 16, 8>;

        type Pcs = TrivialPcs<Val, Radix2DitParallel<Val>>;
        let pcs = TrivialPcs {
            dft,
            log_n,
            _phantom: PhantomData,
        };
        let challenger = Challenger::new(perm);

        type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
        let config = MyConfig::new(pcs, challenger);

        let air = AddAir::new();

        do_test(config, air, 1 << log_n)
    }

    #[test]
    fn prove_bb_trivial_deg2() -> Result<(), impl Debug> {
        do_test_bb_trivial(8)
    }

    #[test]
    fn prove_bb_trivial_deg3() -> Result<(), impl Debug> {
        do_test_bb_trivial(8)
    }

    #[test]
    fn prove_bb_trivial_deg4() -> Result<(), impl Debug> {
        do_test_bb_trivial(8)
    }

    #[cfg(test)]
    fn do_test_bb_twoadic(log_blowup: usize, log_n: usize) -> Result<(), impl Debug> {
        use crate::air::alu::air::MulAir;

        type Val = BabyBear;
        type Challenge = BinomialExtensionField<Val, 4>;

        type Perm = Poseidon2BabyBear<16>;
        let mut rng = SmallRng::seed_from_u64(1);
        let perm = Perm::new_from_rng_128(&mut rng);

        type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
        let hash = MyHash::new(perm.clone());

        type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
        let compress = MyCompress::new(perm.clone());

        type ValMmcs =
            MerkleTreeMmcs<<Val as Field>::Packing, <Val as Field>::Packing, MyHash, MyCompress, 8>;
        let val_mmcs = ValMmcs::new(hash, compress);

        type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

        type Dft = Radix2DitParallel<Val>;
        let dft = Dft::default();

        type Challenger = DuplexChallenger<Val, Perm, 16, 8>;

        let fri_params = FriParameters {
            log_blowup,
            log_final_poly_len: 3,
            num_queries: 40,
            proof_of_work_bits: 8,
            mmcs: challenge_mmcs,
        };
        type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
        let pcs = Pcs::new(dft, val_mmcs, fri_params);
        let challenger = Challenger::new(perm);

        type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
        let config = MyConfig::new(pcs, challenger);

        let air = MulAir::new();

        do_test(config, air, 1 << log_n)
    }

    #[test]
    fn prove_bb_twoadic_deg2() -> Result<(), impl Debug> {
        do_test_bb_twoadic(1, 5)
    }

    #[test]
    fn prove_bb_twoadic_deg2_zk() -> Result<(), impl Debug> {
        type Val = BabyBear;
        type Challenge = BinomialExtensionField<Val, 4>;

        type Perm = Poseidon2BabyBear<16>;
        let mut rng = SmallRng::seed_from_u64(1);
        let perm = Perm::new_from_rng_128(&mut rng);

        type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
        let hash = MyHash::new(perm.clone());

        type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
        let compress = MyCompress::new(perm.clone());

        type ValMmcs = MerkleTreeHidingMmcs<
            <Val as Field>::Packing,
            <Val as Field>::Packing,
            MyHash,
            MyCompress,
            SmallRng,
            8,
            4,
        >;

        let val_mmcs = ValMmcs::new(hash, compress, rng);

        type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

        type Dft = Radix2DitParallel<Val>;
        let dft = Dft::default();

        type Challenger = DuplexChallenger<Val, Perm, 16, 8>;

        let fri_params = create_test_fri_params_zk(challenge_mmcs);
        type HidingPcs = HidingFriPcs<Val, Dft, ValMmcs, ChallengeMmcs, SmallRng>;
        let pcs = HidingPcs::new(dft, val_mmcs, fri_params, 4, SmallRng::seed_from_u64(1));
        type MyConfig = StarkConfig<HidingPcs, Challenge, Challenger>;
        let challenger = Challenger::new(perm);
        let config = MyConfig::new(pcs, challenger);

        let air = SubAir::new();
        do_test(config, air, 1 << 8)
    }

    #[test]
    fn prove_bb_twoadic_deg3() -> Result<(), impl Debug> {
        do_test_bb_twoadic(1, 5)
    }

    #[test]
    fn prove_bb_twoadic_deg4() -> Result<(), impl Debug> {
        do_test_bb_twoadic(2, 4)
    }

    #[test]
    fn prove_bb_twoadic_deg5() -> Result<(), impl Debug> {
        do_test_bb_twoadic(2, 4)
    }

    #[cfg(test)]
    fn do_test_m31_circle(log_blowup: usize, log_n: usize) -> Result<(), impl Debug> {
        use crate::air::alu::air::MulAir;

        type Val = Mersenne31;
        type Challenge = BinomialExtensionField<Val, 3>;

        type ByteHash = Keccak256Hash;
        type FieldHash = SerializingHasher<ByteHash>;
        let byte_hash = ByteHash {};
        let field_hash = FieldHash::new(byte_hash);

        type MyCompress = CompressionFunctionFromHasher<ByteHash, 2, 32>;
        let compress = MyCompress::new(byte_hash);

        type ValMmcs = MerkleTreeMmcs<Val, u8, FieldHash, MyCompress, 32>;
        let val_mmcs = ValMmcs::new(field_hash, compress);

        type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

        type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;

        let fri_params = FriParameters {
            log_blowup,
            log_final_poly_len: 0,
            num_queries: 40,
            proof_of_work_bits: 8,
            mmcs: challenge_mmcs,
        };

        type Pcs = CirclePcs<Val, ValMmcs, ChallengeMmcs>;
        let pcs = Pcs {
            mmcs: val_mmcs,
            fri_params,
            _phantom: PhantomData,
        };
        let challenger = Challenger::from_hasher(vec![], byte_hash);

        type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
        let config = MyConfig::new(pcs, challenger);

        let air = MulAir::new();

        do_test(config, air, 1 << log_n)
    }

    #[test]
    fn prove_m31_circle_deg2() -> Result<(), impl Debug> {
        do_test_m31_circle(1, 6)
    }

    #[test]
    fn prove_m31_circle_deg3() -> Result<(), impl Debug> {
        do_test_m31_circle(1, 7)
    }
}
