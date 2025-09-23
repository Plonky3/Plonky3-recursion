use p3_field::PrimeCharacteristicRing;
use p3_symmetric::PseudoCompressionFunction;

pub trait CircuitConfig<const BF_DIGEST_ELEMS: usize, const EF_DIGEST_ELEMS: usize> {
    /// The base field used with this circuit.
    type Field: PrimeCharacteristicRing + Copy;
    /// The comression function used in merkle verify gates.
    type C: PseudoCompressionFunction<[Self::Field; BF_DIGEST_ELEMS], 2> + Sync;
    /// The degree of the extension field.
    const D: usize = BF_DIGEST_ELEMS / EF_DIGEST_ELEMS;

    const MERKLE_GATE_INPUT_SIZE: usize = 2 * EF_DIGEST_ELEMS + 1;

    fn new() -> Self;

    fn compress(&self) -> &Self::C;
}

pub mod babybear_config {
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
    use p3_field::extension::BinomialExtensionField;
    use p3_symmetric::TruncatedPermutation;

    use crate::CircuitBuilder;
    use crate::config::CircuitConfig;

    pub struct DefaultBabyBearConfig<const EF_DIGEST_ELEMS: usize = 8> {
        compress: TruncatedPermutation<Poseidon2BabyBear<16>, 2, 8, 16>,
    }

    pub type DefaultBabyBearQuarticExtensionConfig = DefaultBabyBearConfig<2>;

    pub const DEFAULT_BABY_BEAR_DIGEST_SIZE: usize = 8;

    pub type BabyBearCircuitBuilder = CircuitBuilder<
        BabyBear,
        DefaultBabyBearConfig<DEFAULT_BABY_BEAR_DIGEST_SIZE>,
        DEFAULT_BABY_BEAR_DIGEST_SIZE,
        DEFAULT_BABY_BEAR_DIGEST_SIZE,
    >;

    pub type BabyBearQuarticExtensionCircuitBuilder = CircuitBuilder<
        BinomialExtensionField<BabyBear, 4>,
        DefaultBabyBearQuarticExtensionConfig,
        DEFAULT_BABY_BEAR_DIGEST_SIZE,
        2,
    >;

    impl<const EF_DIGEST_ELEMS: usize> CircuitConfig<DEFAULT_BABY_BEAR_DIGEST_SIZE, EF_DIGEST_ELEMS>
        for DefaultBabyBearConfig<EF_DIGEST_ELEMS>
    {
        type Field = BabyBear;
        type C = TruncatedPermutation<Poseidon2BabyBear<16>, 2, 8, 16>;

        fn new() -> Self {
            default_babybear_poseidon2_circuit_runner_config()
        }

        fn compress(&self) -> &Self::C {
            &self.compress
        }
    }

    pub fn default_babybear_poseidon2_circuit_runner_config<const EF_DIGEST_ELEMS: usize>()
    -> DefaultBabyBearConfig<EF_DIGEST_ELEMS> {
        let permutation = default_babybear_poseidon2_16();
        let compress = TruncatedPermutation::<_, 2, 8, 16>::new(permutation);
        DefaultBabyBearConfig { compress }
    }
}
pub mod koalabear_config {
    use p3_field::extension::BinomialExtensionField;
    use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16};
    use p3_symmetric::TruncatedPermutation;

    use crate::CircuitBuilder;
    use crate::config::CircuitConfig;

    pub struct DefaultKoalaBearConfig<const EF_DIGEST_ELEMS: usize> {
        compress: TruncatedPermutation<Poseidon2KoalaBear<16>, 2, 8, 16>,
    }

    pub type DefaultKoalaBearQuarticExtensionConfig = DefaultKoalaBearConfig<2>;

    pub const DEFAULT_KOALA_BEAR_DIGEST_SIZE: usize = 8;

    pub type KoalaBearCircuitBuilder = CircuitBuilder<
        KoalaBear,
        DefaultKoalaBearConfig<DEFAULT_KOALA_BEAR_DIGEST_SIZE>,
        DEFAULT_KOALA_BEAR_DIGEST_SIZE,
        DEFAULT_KOALA_BEAR_DIGEST_SIZE,
    >;

    pub type KoalaBearQuarticExtensionCircuitBuilder = CircuitBuilder<
        BinomialExtensionField<KoalaBear, 4>,
        DefaultKoalaBearQuarticExtensionConfig,
        DEFAULT_KOALA_BEAR_DIGEST_SIZE,
        2,
    >;

    pub type KoalaBearOcticExtensionCircuitBuilder = CircuitBuilder<
        BinomialExtensionField<KoalaBear, 8>,
        DefaultKoalaBearConfig<1>,
        DEFAULT_KOALA_BEAR_DIGEST_SIZE,
        1,
    >;

    impl<const EF_DIGEST_ELEMS: usize>
        CircuitConfig<DEFAULT_KOALA_BEAR_DIGEST_SIZE, EF_DIGEST_ELEMS>
        for DefaultKoalaBearConfig<EF_DIGEST_ELEMS>
    {
        type Field = KoalaBear;
        type C = TruncatedPermutation<Poseidon2KoalaBear<16>, 2, 8, 16>;

        fn new() -> Self {
            default_koalabear_poseidon2_circuit_runner_config()
        }

        fn compress(&self) -> &Self::C {
            &self.compress
        }
    }

    pub fn default_koalabear_poseidon2_circuit_runner_config<const EF_DIGEST_ELEMS: usize>()
    -> DefaultKoalaBearConfig<EF_DIGEST_ELEMS> {
        let permutation = default_koalabear_poseidon2_16();
        let compress = TruncatedPermutation::<_, 2, 8, 16>::new(permutation);
        DefaultKoalaBearConfig { compress }
    }
}

pub mod goldilocks_config {
    use p3_field::extension::BinomialExtensionField;
    use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
    use p3_symmetric::TruncatedPermutation;
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    use crate::CircuitBuilder;
    use crate::config::CircuitConfig;

    pub struct DefaultGoldilocksConfig<const EF_DIGEST_ELEMS: usize> {
        compress: TruncatedPermutation<Poseidon2Goldilocks<8>, 2, 4, 8>,
    }

    pub type DefaultGoldilocksQuadraticExtensionConfig = DefaultGoldilocksConfig<2>;

    pub const DEFAULT_GOLDILOCKS_DIGEST_SIZE: usize = 4;

    pub type GoldilocksCircuitBuilder = CircuitBuilder<
        Goldilocks,
        DefaultGoldilocksConfig<DEFAULT_GOLDILOCKS_DIGEST_SIZE>,
        DEFAULT_GOLDILOCKS_DIGEST_SIZE,
        DEFAULT_GOLDILOCKS_DIGEST_SIZE,
    >;

    pub type GoldilocksQuadraticExtensionCircuitBuilder = CircuitBuilder<
        BinomialExtensionField<Goldilocks, 2>,
        DefaultGoldilocksQuadraticExtensionConfig,
        DEFAULT_GOLDILOCKS_DIGEST_SIZE,
        2,
    >;

    impl<const EF_DIGEST_ELEMS: usize>
        CircuitConfig<DEFAULT_GOLDILOCKS_DIGEST_SIZE, EF_DIGEST_ELEMS>
        for DefaultGoldilocksConfig<EF_DIGEST_ELEMS>
    {
        type Field = Goldilocks;
        type C = TruncatedPermutation<Poseidon2Goldilocks<8>, 2, 4, 8>;

        fn new() -> Self {
            default_goldilocks_poseidon2_circuit_runner_config()
        }

        fn compress(&self) -> &Self::C {
            &self.compress
        }
    }

    pub fn default_goldilocks_poseidon2_circuit_runner_config<const D: usize>()
    -> DefaultGoldilocksConfig<D> {
        type Perm = Poseidon2Goldilocks<8>;
        let mut rng = SmallRng::seed_from_u64(1);
        let perm = Perm::new_from_rng_128(&mut rng);
        type MyCompress = TruncatedPermutation<Perm, 2, 4, 8>;
        let compress = MyCompress::new(perm.clone());

        DefaultGoldilocksConfig { compress }
    }
}
