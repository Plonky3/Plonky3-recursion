use alloc::vec::Vec;

use p3_symmetric::PseudoCompressionFunction;

pub trait CircuitConfig {
    /// An array of base field elements that corresponds to the output
    /// of the compression function used for this configuration.
    type BaseFieldHash: ArrayHash;
    /// An array of extension field elements that correspond to the output
    /// of the compression function used for this configuration.
    type ExtensionFieldHash: ArrayHash;
    /// The comression function used in merkle verify gates.
    type C: PseudoCompressionFunction<Self::BaseFieldHash, 2> + Sync;

    /// The number of base field element that fit in the output of the compression function.
    const BF_DIGEST_ELEMS: usize;
    /// The number of extension field element that fit in the output of the compression function.
    const EF_DIGEST_ELEMS: usize;
    /// The degree of the extension field.
    const D: usize = Self::BF_DIGEST_ELEMS / Self::EF_DIGEST_ELEMS;

    const MERKLE_GATE_INPUT_SIZE: usize = 2 * Self::EF_DIGEST_ELEMS + 1;

    fn new() -> Self;

    fn compress(&self) -> &Self::C;
}

pub trait ArrayHash: TryFrom<Vec<Self::Field>> + Into<Vec<Self::Field>> + Clone {
    type Field;
    const DIGEST_ELEMS: usize;
}

impl<T: Clone, const N: usize> ArrayHash for [T; N] {
    type Field = T;
    const DIGEST_ELEMS: usize = N;
}

pub mod babybear_config {
    use core::marker::PhantomData;

    use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
    use p3_field::extension::BinomialExtensionField;
    use p3_symmetric::TruncatedPermutation;

    use crate::CircuitBuilder;
    use crate::config::{ArrayHash, CircuitConfig};

    pub struct DefaultBabyBearConfig<ExtensionFieldHash = [BabyBear; DEFAULT_BABY_BEAR_DIGEST_SIZE]> {
        compress: TruncatedPermutation<Poseidon2BabyBear<16>, 2, 8, 16>,
        _phantom: PhantomData<ExtensionFieldHash>,
    }

    pub type DefaultBabyBearQuarticExtensionConfig =
        DefaultBabyBearConfig<[BinomialExtensionField<BabyBear, 4>; 2]>;

    pub const DEFAULT_BABY_BEAR_DIGEST_SIZE: usize = 8;

    pub type BabyBearCircuitBuilder =
        CircuitBuilder<BabyBear, DefaultBabyBearConfig<[BabyBear; DEFAULT_BABY_BEAR_DIGEST_SIZE]>>;

    pub type BabyBearQuarticExtensionCircuitBuilder =
        CircuitBuilder<BinomialExtensionField<BabyBear, 4>, DefaultBabyBearQuarticExtensionConfig>;

    impl<ExtensionFieldHash: ArrayHash> CircuitConfig for DefaultBabyBearConfig<ExtensionFieldHash> {
        type BaseFieldHash = [BabyBear; DEFAULT_BABY_BEAR_DIGEST_SIZE];
        type ExtensionFieldHash = ExtensionFieldHash;

        const BF_DIGEST_ELEMS: usize = DEFAULT_BABY_BEAR_DIGEST_SIZE;

        const EF_DIGEST_ELEMS: usize = ExtensionFieldHash::DIGEST_ELEMS;
        type C = TruncatedPermutation<Poseidon2BabyBear<16>, 2, 8, 16>;

        fn new() -> Self {
            default_babybear_poseidon2_circuit_runner_config()
        }

        fn compress(&self) -> &Self::C {
            &self.compress
        }
    }

    pub fn default_babybear_poseidon2_circuit_runner_config<ExtensionFieldHash: ArrayHash>()
    -> DefaultBabyBearConfig<ExtensionFieldHash> {
        let permutation = default_babybear_poseidon2_16();
        let compress = TruncatedPermutation::<_, 2, 8, 16>::new(permutation);
        DefaultBabyBearConfig {
            compress,
            _phantom: PhantomData,
        }
    }
}
pub mod koalabear_config {
    use core::marker::PhantomData;

    use p3_field::extension::BinomialExtensionField;
    use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16};
    use p3_symmetric::TruncatedPermutation;

    use crate::CircuitBuilder;
    use crate::config::{ArrayHash, CircuitConfig};

    pub struct DefaultKoalaBearConfig<ExtensionFieldHash: ArrayHash> {
        compress: TruncatedPermutation<Poseidon2KoalaBear<16>, 2, 8, 16>,
        _phantom: PhantomData<ExtensionFieldHash>,
    }

    pub type DefaultKoalaBearQuarticExtensionConfig =
        DefaultKoalaBearConfig<[BinomialExtensionField<KoalaBear, 4>; 2]>;

    pub const DEFAULT_KOALA_BEAR_DIGEST_SIZE: usize = 8;

    pub type KoalaBearCircuitBuilder = CircuitBuilder<
        KoalaBear,
        DefaultKoalaBearConfig<[KoalaBear; DEFAULT_KOALA_BEAR_DIGEST_SIZE]>,
    >;

    pub type KoalaBearQuarticExtensionCircuitBuilder = CircuitBuilder<
        BinomialExtensionField<KoalaBear, 4>,
        DefaultKoalaBearQuarticExtensionConfig,
    >;

    pub type KoalaBearOcticExtensionCircuitBuilder = CircuitBuilder<
        BinomialExtensionField<KoalaBear, 8>,
        DefaultKoalaBearConfig<[BinomialExtensionField<KoalaBear, 8>; 1]>,
    >;

    impl<ExtensionFieldHash: ArrayHash> CircuitConfig for DefaultKoalaBearConfig<ExtensionFieldHash> {
        type BaseFieldHash = [KoalaBear; DEFAULT_KOALA_BEAR_DIGEST_SIZE];

        type ExtensionFieldHash = ExtensionFieldHash;

        const BF_DIGEST_ELEMS: usize = DEFAULT_KOALA_BEAR_DIGEST_SIZE;

        const EF_DIGEST_ELEMS: usize = ExtensionFieldHash::DIGEST_ELEMS;

        type C = TruncatedPermutation<Poseidon2KoalaBear<16>, 2, 8, 16>;

        fn new() -> Self {
            default_koalabear_poseidon2_circuit_runner_config()
        }

        fn compress(&self) -> &Self::C {
            &self.compress
        }
    }

    pub fn default_koalabear_poseidon2_circuit_runner_config<ExtensionFieldHash: ArrayHash>()
    -> DefaultKoalaBearConfig<ExtensionFieldHash> {
        let permutation = default_koalabear_poseidon2_16();
        let compress = TruncatedPermutation::<_, 2, 8, 16>::new(permutation);
        DefaultKoalaBearConfig {
            compress,
            _phantom: PhantomData,
        }
    }
}

pub mod goldilocks_config {
    use core::marker::PhantomData;

    use p3_field::extension::BinomialExtensionField;
    use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
    use p3_symmetric::TruncatedPermutation;
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    use crate::CircuitBuilder;
    use crate::config::{ArrayHash, CircuitConfig};

    pub struct DefaultGoldilocksConfig<ExtensionFieldHash> {
        compress: TruncatedPermutation<Poseidon2Goldilocks<8>, 2, 4, 8>,
        _phantom: PhantomData<ExtensionFieldHash>,
    }

    pub type DefaultGoldilocksQuadraticExtensionConfig =
        DefaultGoldilocksConfig<[BinomialExtensionField<Goldilocks, 2>; 2]>;

    pub const DEFAULT_GOLDILOCKS_DIGEST_SIZE: usize = 4;

    pub type GoldilocksCircuitBuilder = CircuitBuilder<
        Goldilocks,
        DefaultGoldilocksConfig<[Goldilocks; DEFAULT_GOLDILOCKS_DIGEST_SIZE]>,
    >;

    pub type GoldilocksQuadraticExtensionCircuitBuilder = CircuitBuilder<
        BinomialExtensionField<Goldilocks, 2>,
        DefaultGoldilocksQuadraticExtensionConfig,
    >;

    impl<ExtensionFieldHash: ArrayHash> CircuitConfig for DefaultGoldilocksConfig<ExtensionFieldHash> {
        type BaseFieldHash = [Goldilocks; DEFAULT_GOLDILOCKS_DIGEST_SIZE];

        type ExtensionFieldHash = ExtensionFieldHash;

        const BF_DIGEST_ELEMS: usize = DEFAULT_GOLDILOCKS_DIGEST_SIZE;

        const EF_DIGEST_ELEMS: usize = ExtensionFieldHash::DIGEST_ELEMS;

        type C = TruncatedPermutation<Poseidon2Goldilocks<8>, 2, 4, 8>;

        fn new() -> Self {
            default_goldilocks_poseidon2_circuit_runner_config()
        }

        fn compress(&self) -> &Self::C {
            &self.compress
        }
    }

    pub fn default_goldilocks_poseidon2_circuit_runner_config<ExtensionFieldHash: ArrayHash>()
    -> DefaultGoldilocksConfig<ExtensionFieldHash> {
        type Perm = Poseidon2Goldilocks<8>;
        let mut rng = SmallRng::seed_from_u64(1);
        let perm = Perm::new_from_rng_128(&mut rng);
        type MyCompress = TruncatedPermutation<Perm, 2, 4, 8>;
        let compress = MyCompress::new(perm.clone());

        DefaultGoldilocksConfig {
            compress,
            _phantom: PhantomData,
        }
    }
}
