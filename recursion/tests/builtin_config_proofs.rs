use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use p3_baby_bear::BabyBear;
use p3_circuit::test_utils::{FibonacciAir, generate_trace_rows};
use p3_field::{Field, PrimeCharacteristicRing};
use p3_goldilocks::Goldilocks;
use p3_koala_bear::KoalaBear;
use p3_recursion::VerifierLimits;
use p3_recursion::builtin_config::{
    FriConfigV1, SuiteIdV1, WhirConfigV1, WhirRateModeV1, WhirSecurityAssumptionV1,
    baby_bear_d4_poseidon1_binary, baby_bear_d4_poseidon1_random_codeword,
    baby_bear_d4_poseidon2_binary, baby_bear_d4_poseidon2_quaternary,
    baby_bear_d4_poseidon2_random_codeword, baby_bear_d4_poseidon2_whir,
    goldilocks_d2_poseidon1_binary, goldilocks_d2_poseidon1_random_codeword,
    goldilocks_d2_poseidon2_binary, goldilocks_d2_poseidon2_quaternary,
    goldilocks_d2_poseidon2_random_codeword, koala_bear_d4_poseidon1_binary,
    koala_bear_d4_poseidon1_random_codeword, koala_bear_d4_poseidon2_binary,
    koala_bear_d4_poseidon2_quaternary, koala_bear_d4_poseidon2_random_codeword,
    koala_bear_d4_poseidon2_salted, koala_bear_d4_poseidon2_whir, koala_bear_d5_poseidon1_binary,
    koala_bear_d5_poseidon2_binary, koala_bear_d5_poseidon2_quaternary,
};
use p3_uni_stark::{prove, verify};
use rand::rngs::StdRng;
use rand::{SeedableRng, TryCryptoRng, TryRng};

#[derive(Debug)]
struct CountingRng {
    inner: StdRng,
    draws: Arc<AtomicUsize>,
}

impl CountingRng {
    fn new(seed: u64, draws: Arc<AtomicUsize>) -> Self {
        Self {
            inner: StdRng::seed_from_u64(seed),
            draws,
        }
    }
}

impl TryRng for CountingRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.draws.fetch_add(1, Ordering::Relaxed);
        self.inner.try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.draws.fetch_add(1, Ordering::Relaxed);
        self.inner.try_next_u64()
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.draws.fetch_add(1, Ordering::Relaxed);
        self.inner.try_fill_bytes(dst)
    }
}

impl TryCryptoRng for CountingRng {}

impl SeedableRng for CountingRng {
    type Seed = <StdRng as SeedableRng>::Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        Self {
            inner: StdRng::from_seed(seed),
            draws: Arc::new(AtomicUsize::new(0)),
        }
    }
}

const fn fri_descriptor(suite: SuiteIdV1) -> FriConfigV1 {
    let spec = suite.spec();
    FriConfigV1::new(
        suite,
        1,
        0,
        2,
        2,
        0,
        0,
        0,
        0,
        if spec.is_hiding() { 4 } else { 0 },
        spec.salt_elements as u32,
    )
}

macro_rules! prove_and_check {
    ($field:ty, $config:expr, $rows:expr) => {{
        let air = FibonacciAir {};
        let trace = generate_trace_rows::<$field>(0, 1, $rows);
        let public_values = [
            <$field>::ZERO,
            <$field>::ONE,
            fibonacci_output::<$field>($rows),
        ];
        let proof = prove(&$config, &air, trace, &public_values).unwrap();
        verify(&$config, &air, &proof, &public_values).expect("native proof must verify");
        let mut wrong = public_values;
        wrong[2] += <$field>::ONE;
        assert!(verify(&$config, &air, &proof, &wrong).is_err());
    }};
}

fn fibonacci_output<F: Field>(n: usize) -> F {
    let (mut a, mut b) = (F::ZERO, F::ONE);
    for _ in 1..n {
        let next = a + b;
        a = b;
        b = next;
    }
    b
}

macro_rules! ordinary_fri_proof_test {
    ($name:ident, $field:ty, $factory:ident, $suite:ident) => {
        #[test]
        fn $name() {
            let descriptor = fri_descriptor(SuiteIdV1::$suite);
            let config = $factory(&descriptor, &VerifierLimits::default()).unwrap();
            prove_and_check!($field, config, 8);
        }
    };
}

ordinary_fri_proof_test!(
    baby_bear_d4_poseidon2_binary_proves,
    BabyBear,
    baby_bear_d4_poseidon2_binary,
    BabyBearD4Poseidon2BinaryFri
);
ordinary_fri_proof_test!(
    baby_bear_d4_poseidon1_binary_proves,
    BabyBear,
    baby_bear_d4_poseidon1_binary,
    BabyBearD4Poseidon1BinaryFri
);
ordinary_fri_proof_test!(
    koala_bear_d4_poseidon2_binary_proves,
    KoalaBear,
    koala_bear_d4_poseidon2_binary,
    KoalaBearD4Poseidon2BinaryFri
);
ordinary_fri_proof_test!(
    koala_bear_d4_poseidon1_binary_proves,
    KoalaBear,
    koala_bear_d4_poseidon1_binary,
    KoalaBearD4Poseidon1BinaryFri
);
ordinary_fri_proof_test!(
    goldilocks_d2_poseidon2_binary_proves,
    Goldilocks,
    goldilocks_d2_poseidon2_binary,
    GoldilocksD2Poseidon2BinaryFri
);
ordinary_fri_proof_test!(
    goldilocks_d2_poseidon1_binary_proves,
    Goldilocks,
    goldilocks_d2_poseidon1_binary,
    GoldilocksD2Poseidon1BinaryFri
);
ordinary_fri_proof_test!(
    koala_bear_d5_poseidon2_binary_proves,
    KoalaBear,
    koala_bear_d5_poseidon2_binary,
    KoalaBearD5Poseidon2BinaryFri
);
ordinary_fri_proof_test!(
    koala_bear_d5_poseidon1_binary_proves,
    KoalaBear,
    koala_bear_d5_poseidon1_binary,
    KoalaBearD5Poseidon1BinaryFri
);
ordinary_fri_proof_test!(
    baby_bear_d4_poseidon2_quaternary_proves,
    BabyBear,
    baby_bear_d4_poseidon2_quaternary,
    BabyBearD4Poseidon2QuaternaryFri
);
ordinary_fri_proof_test!(
    koala_bear_d4_poseidon2_quaternary_proves,
    KoalaBear,
    koala_bear_d4_poseidon2_quaternary,
    KoalaBearD4Poseidon2QuaternaryFri
);
ordinary_fri_proof_test!(
    goldilocks_d2_poseidon2_quaternary_proves,
    Goldilocks,
    goldilocks_d2_poseidon2_quaternary,
    GoldilocksD2Poseidon2QuaternaryFri
);
ordinary_fri_proof_test!(
    koala_bear_d5_poseidon2_quaternary_proves,
    KoalaBear,
    koala_bear_d5_poseidon2_quaternary,
    KoalaBearD5Poseidon2QuaternaryFri
);

macro_rules! random_codeword_fri_proof_test {
    ($name:ident, $field:ty, $factory:ident, $suite:ident) => {
        #[test]
        fn $name() {
            let descriptor = fri_descriptor(SuiteIdV1::$suite);
            let proving_config = $factory(
                &descriptor,
                &VerifierLimits::default(),
                CountingRng::new(1, Arc::new(AtomicUsize::new(0))),
            )
            .unwrap();
            let air = FibonacciAir {};
            // Hiding FRI needs the zero-knowledge mask to cover every disclosed value.
            let trace = generate_trace_rows::<$field>(0, 1, 32);
            let public_values = [
                <$field>::ZERO,
                <$field>::ONE,
                fibonacci_output::<$field>(32),
            ];
            let proof = prove(&proving_config, &air, trace, &public_values).unwrap();

            let draws = Arc::new(AtomicUsize::new(0));
            let verifying_config = $factory(
                &descriptor,
                &VerifierLimits::default(),
                CountingRng::new(91, draws.clone()),
            )
            .unwrap();
            verify(&verifying_config, &air, &proof, &public_values).unwrap();
            assert_eq!(
                draws.load(Ordering::Relaxed),
                0,
                "random-codeword FRI verification must not read its retained RNG"
            );
        }
    };
}

random_codeword_fri_proof_test!(
    baby_bear_d4_poseidon2_random_codeword_proves,
    BabyBear,
    baby_bear_d4_poseidon2_random_codeword,
    BabyBearD4Poseidon2RandomCodewordFri
);
random_codeword_fri_proof_test!(
    baby_bear_d4_poseidon1_random_codeword_proves,
    BabyBear,
    baby_bear_d4_poseidon1_random_codeword,
    BabyBearD4Poseidon1RandomCodewordFri
);
random_codeword_fri_proof_test!(
    koala_bear_d4_poseidon2_random_codeword_proves,
    KoalaBear,
    koala_bear_d4_poseidon2_random_codeword,
    KoalaBearD4Poseidon2RandomCodewordFri
);
random_codeword_fri_proof_test!(
    koala_bear_d4_poseidon1_random_codeword_proves,
    KoalaBear,
    koala_bear_d4_poseidon1_random_codeword,
    KoalaBearD4Poseidon1RandomCodewordFri
);
random_codeword_fri_proof_test!(
    goldilocks_d2_poseidon2_random_codeword_proves,
    Goldilocks,
    goldilocks_d2_poseidon2_random_codeword,
    GoldilocksD2Poseidon2RandomCodewordFri
);
random_codeword_fri_proof_test!(
    goldilocks_d2_poseidon1_random_codeword_proves,
    Goldilocks,
    goldilocks_d2_poseidon1_random_codeword,
    GoldilocksD2Poseidon1RandomCodewordFri
);

#[test]
fn salted_hiding_fri_factory_proves_and_checks() {
    let descriptor = fri_descriptor(SuiteIdV1::KoalaBearD4Poseidon2SaltedFri);
    let proving_config = koala_bear_d4_poseidon2_salted(
        &descriptor,
        &VerifierLimits::default(),
        CountingRng::new(11, Arc::new(AtomicUsize::new(0))),
        CountingRng::new(12, Arc::new(AtomicUsize::new(0))),
        CountingRng::new(13, Arc::new(AtomicUsize::new(0))),
    )
    .unwrap();
    let air = FibonacciAir {};
    // Hiding FRI needs the zero-knowledge mask to cover every disclosed value.
    let trace = generate_trace_rows::<KoalaBear>(0, 1, 32);
    let public_values = [
        KoalaBear::ZERO,
        KoalaBear::ONE,
        fibonacci_output::<KoalaBear>(32),
    ];
    let proof = prove(&proving_config, &air, trace, &public_values).unwrap();

    let input_draws = Arc::new(AtomicUsize::new(0));
    let commit_draws = Arc::new(AtomicUsize::new(0));
    let codeword_draws = Arc::new(AtomicUsize::new(0));
    let verifying_config = koala_bear_d4_poseidon2_salted(
        &descriptor,
        &VerifierLimits::default(),
        CountingRng::new(92, input_draws.clone()),
        CountingRng::new(93, commit_draws.clone()),
        CountingRng::new(94, codeword_draws.clone()),
    )
    .unwrap();
    verify(&verifying_config, &air, &proof, &public_values).unwrap();
    assert_eq!(input_draws.load(Ordering::Relaxed), 0);
    assert_eq!(commit_draws.load(Ordering::Relaxed), 0);
    assert_eq!(codeword_draws.load(Ordering::Relaxed), 0);
}

const fn whir_descriptor(suite: SuiteIdV1) -> WhirConfigV1 {
    WhirConfigV1::new(suite, 1, WhirRateModeV1::Auto, 4, 1, 32, 0, 20, 0)
}

#[test]
fn whir_factories_prove_and_check_both_registered_fields() {
    let limits = VerifierLimits::default();
    let descriptor = whir_descriptor(SuiteIdV1::BabyBearD4Poseidon2Whir);
    let config = baby_bear_d4_poseidon2_whir(&descriptor, &limits).unwrap();
    prove_and_check!(BabyBear, config, 64);

    let descriptor = WhirConfigV1::new(
        SuiteIdV1::KoalaBearD4Poseidon2Whir,
        1,
        WhirRateModeV1::Auto,
        4,
        WhirSecurityAssumptionV1::UniqueDecoding.as_u16(),
        32,
        0,
        20,
        0,
    );
    let config = koala_bear_d4_poseidon2_whir(&descriptor, &limits).unwrap();
    prove_and_check!(KoalaBear, config, 64);
}
