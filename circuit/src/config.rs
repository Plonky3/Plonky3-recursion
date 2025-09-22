use p3_field::PrimeCharacteristicRing;
use p3_symmetric::PseudoCompressionFunction;

pub trait CircuitRunnerConfig<const DIGEST_ELEMS: usize> {
    type Field: PrimeCharacteristicRing + Copy;
    type C: PseudoCompressionFunction<[Self::Field; DIGEST_ELEMS], 2> + Sync;

    fn compress(&self) -> &Self::C;
}

pub mod babybear_config {
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
    use p3_symmetric::TruncatedPermutation;

    use crate::config::CircuitRunnerConfig;

    pub struct DefaultBabyBearConfig {
        compress: TruncatedPermutation<Poseidon2BabyBear<16>, 2, 8, 16>,
    }

    impl CircuitRunnerConfig<8> for DefaultBabyBearConfig {
        type Field = BabyBear;
        type C = TruncatedPermutation<Poseidon2BabyBear<16>, 2, 8, 16>;

        fn compress(&self) -> &Self::C {
            &self.compress
        }
    }

    pub fn default_babybear_poseidon2_circuit_runner_config() -> DefaultBabyBearConfig {
        let permutation = default_babybear_poseidon2_16();
        let compress = TruncatedPermutation::<_, 2, 8, 16>::new(permutation);
        DefaultBabyBearConfig { compress }
    }
}

pub mod koalabear_config {
    use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16};
    use p3_symmetric::TruncatedPermutation;

    use crate::config::CircuitRunnerConfig;

    pub struct DefaultKoalaBearConfig {
        compress: TruncatedPermutation<Poseidon2KoalaBear<16>, 2, 8, 16>,
    }

    impl CircuitRunnerConfig<8> for DefaultKoalaBearConfig {
        type Field = KoalaBear;
        type C = TruncatedPermutation<Poseidon2KoalaBear<16>, 2, 8, 16>;

        fn compress(&self) -> &Self::C {
            &self.compress
        }
    }

    pub fn default_koalabear_poseidon2_circuit_runner_config() -> DefaultKoalaBearConfig {
        let permutation = default_koalabear_poseidon2_16();
        let compress = TruncatedPermutation::<_, 2, 8, 16>::new(permutation);
        DefaultKoalaBearConfig { compress }
    }
}

pub mod goldilocks_config {
    use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
    use p3_symmetric::TruncatedPermutation;
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    use crate::config::CircuitRunnerConfig;

    pub struct DefaultGoldilocksConfig {
        compress: TruncatedPermutation<Poseidon2Goldilocks<8>, 2, 4, 8>,
    }

    impl CircuitRunnerConfig<4> for DefaultGoldilocksConfig {
        type Field = Goldilocks;
        type C = TruncatedPermutation<Poseidon2Goldilocks<8>, 2, 4, 8>;

        fn compress(&self) -> &Self::C {
            &self.compress
        }
    }

    pub fn default_goldilocks_poseidon2_circuit_runner_config() -> DefaultGoldilocksConfig {
        type Perm = Poseidon2Goldilocks<8>;
        let mut rng = SmallRng::seed_from_u64(1);
        let perm = Perm::new_from_rng_128(&mut rng);
        type MyCompress = TruncatedPermutation<Perm, 2, 4, 8>;
        let compress = MyCompress::new(perm.clone());

        DefaultGoldilocksConfig { compress }
    }
}
