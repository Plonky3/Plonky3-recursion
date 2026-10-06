#[macro_use]
#[path = "common/builtin_fri_lifecycle.rs"]
#[allow(clippy::duplicate_mod)]
mod builtin_fri_lifecycle;

use std::convert::Infallible;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use p3_baby_bear::BabyBear;
use p3_circuit::ops::Poseidon1Config;
use p3_goldilocks::Goldilocks;
use p3_koala_bear::KoalaBear;
use p3_recursion::builtin_config::*;
use p3_recursion::{FriRecursionBackend, Poseidon2Config, VerifierLimits};
use rand::rngs::StdRng;
use rand::{SeedableRng, TryCryptoRng, TryRng};

fri_lifecycle_case!(
    baby_bear_d4_poseidon2_random_codeword_lifecycle,
    field: BabyBear,
    wire_bytes: 4,
    config: BabyBearD4Poseidon2RandomCodewordConfig<StdRng>,
    degree: 4,
    suite: SuiteIdV1::BabyBearD4Poseidon2RandomCodewordFri,
    factory: |d: &FriConfigV1, l: &VerifierLimits| {
        baby_bear_d4_poseidon2_random_codeword(d, l, StdRng::seed_from_u64(100))
    },
    backend: FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::BABY_BEAR_D4_W16)
        .for_extension_degree::<4>()
);

// Source proving RNGs are observed separately from the fresh, verification-only salted MMCS
// instances. The latter are deliberately tagged by the production restoration seed (zero).
static ZERO_SEEDED_INSTANCES: AtomicUsize = AtomicUsize::new(0);
static ZERO_SEEDED_DRAWS: AtomicUsize = AtomicUsize::new(0);

#[derive(Debug)]
struct ObservedRng {
    inner: StdRng,
    draws: Arc<AtomicUsize>,
    zero_seeded: bool,
}

impl ObservedRng {
    fn new(seed: u64, draws: Arc<AtomicUsize>) -> Self {
        Self {
            inner: StdRng::seed_from_u64(seed),
            draws,
            zero_seeded: false,
        }
    }

    fn observe_draw(&self) {
        if self.zero_seeded {
            ZERO_SEEDED_DRAWS.fetch_add(1, Ordering::Relaxed);
        } else {
            self.draws.fetch_add(1, Ordering::Relaxed);
        }
    }
}

impl TryRng for ObservedRng {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        self.observe_draw();
        self.inner.try_next_u32()
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        self.observe_draw();
        self.inner.try_next_u64()
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        self.observe_draw();
        self.inner.try_fill_bytes(dst)
    }
}

impl TryCryptoRng for ObservedRng {}

impl SeedableRng for ObservedRng {
    type Seed = <StdRng as SeedableRng>::Seed;

    fn from_seed(seed: Self::Seed) -> Self {
        Self {
            inner: StdRng::from_seed(seed),
            draws: Arc::new(AtomicUsize::new(0)),
            zero_seeded: false,
        }
    }

    fn seed_from_u64(seed: u64) -> Self {
        let zero_seeded = seed == 0;
        if zero_seeded {
            ZERO_SEEDED_INSTANCES.fetch_add(1, Ordering::Relaxed);
        }
        Self {
            inner: StdRng::seed_from_u64(seed),
            draws: Arc::new(AtomicUsize::new(0)),
            zero_seeded,
        }
    }
}

const fn observed_descriptor(suite: SuiteIdV1) -> FriConfigV1 {
    FriConfigV1::new(
        suite,
        1,
        0,
        2,
        2,
        0,
        0,
        1,
        2,
        4,
        suite.spec().salt_elements as u32,
    )
}

fn observed_statement(start_a: u64, start_b: u64, n: usize) -> Vec<KoalaBear> {
    use p3_field::PrimeCharacteristicRing;

    let mut a = KoalaBear::from_u64(start_a);
    let mut b = KoalaBear::from_u64(start_b);
    for _ in 1..n {
        let next = a + b;
        a = b;
        b = next;
    }
    vec![
        KoalaBear::from_u64(start_a),
        KoalaBear::from_u64(start_b),
        b,
    ]
}

#[test]
fn random_codeword_restoration_does_not_draw_from_source_proving_rng() {
    use p3_recursion::{
        ProveNextLayerParams, TrustedPreparedInput, TrustedPreparedLayer, TrustedPreparedSource,
    };

    const N: usize = 32;
    let descriptor = observed_descriptor(SuiteIdV1::KoalaBearD4Poseidon2RandomCodewordFri);
    let limits = VerifierLimits::default();
    let source_draws = Arc::new(AtomicUsize::new(0));
    let source = koala_bear_d4_poseidon2_random_codeword(
        &descriptor,
        &limits,
        ObservedRng::new(11, source_draws.clone()),
    )
    .unwrap();
    let air = p3_circuit::test_utils::FibonacciAir {};
    let statement = observed_statement(1, 2, N);
    let proof = p3_uni_stark::prove(
        &source,
        &air,
        p3_circuit::test_utils::generate_trace_rows::<KoalaBear>(1, 2, N),
        &statement,
    )
    .unwrap();
    p3_uni_stark::verify(&source, &air, &proof, &statement).unwrap();
    let before = source_draws.load(Ordering::Relaxed);
    assert!(before > 0);
    let output = koala_bear_d4_poseidon2_random_codeword(
        &descriptor,
        &limits,
        ObservedRng::new(12, Arc::new(AtomicUsize::new(0))),
    )
    .unwrap();
    let owner = TrustedPreparedLayer::<
        KoalaBearD4Poseidon2RandomCodewordConfig<ObservedRng>,
        KoalaBearD4Poseidon2RandomCodewordConfig<ObservedRng>,
        _,
        _,
        4,
    >::new(
        TrustedPreparedSource::UniStark {
            config: source,
            air: &air,
            preprocessed_commit: None,
            proof: &proof,
            public_inputs: &statement,
        },
        output,
        FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
            .for_extension_degree::<4>(),
        ProveNextLayerParams {
            table_packing: p3_circuit_prover::TablePacking::new(4, 4).with_min_trace_height(32),
            ..ProveNextLayerParams::default()
        },
    )
    .unwrap();
    let recursive = owner
        .prove(TrustedPreparedInput::UniStark {
            proof: &proof,
            public_inputs: &statement,
        })
        .unwrap();
    owner.verifier().verify(&recursive.0, &statement).unwrap();
    assert_eq!(source_draws.load(Ordering::Relaxed), before);
}

#[test]
fn salted_restoration_draws_neither_source_nor_verification_only_rng() {
    use p3_recursion::{
        ProveNextLayerParams, TrustedPreparedInput, TrustedPreparedLayer, TrustedPreparedSource,
    };

    const N: usize = 32;
    let descriptor = observed_descriptor(SuiteIdV1::KoalaBearD4Poseidon2SaltedFri);
    let limits = VerifierLimits::default();
    let source_draws = [
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
        Arc::new(AtomicUsize::new(0)),
    ];
    let source = koala_bear_d4_poseidon2_salted(
        &descriptor,
        &limits,
        ObservedRng::new(21, source_draws[0].clone()),
        ObservedRng::new(22, source_draws[1].clone()),
        ObservedRng::new(23, source_draws[2].clone()),
    )
    .unwrap();
    let air = p3_circuit::test_utils::FibonacciAir {};
    let statement = observed_statement(1, 2, N);
    let proof = p3_uni_stark::prove(
        &source,
        &air,
        p3_circuit::test_utils::generate_trace_rows::<KoalaBear>(1, 2, N),
        &statement,
    )
    .unwrap();
    p3_uni_stark::verify(&source, &air, &proof, &statement).unwrap();
    let before = source_draws
        .each_ref()
        .map(|counter| counter.load(Ordering::Relaxed));
    assert!(before.iter().all(|draws| *draws > 0));
    let output = koala_bear_d4_poseidon2_salted(
        &descriptor,
        &limits,
        ObservedRng::new(24, Arc::new(AtomicUsize::new(0))),
        ObservedRng::new(25, Arc::new(AtomicUsize::new(0))),
        ObservedRng::new(26, Arc::new(AtomicUsize::new(0))),
    )
    .unwrap();
    let zero_instances_before = ZERO_SEEDED_INSTANCES.load(Ordering::Relaxed);
    let zero_draws_before = ZERO_SEEDED_DRAWS.load(Ordering::Relaxed);
    let owner = TrustedPreparedLayer::<
        KoalaBearD4Poseidon2SaltedConfig<ObservedRng>,
        KoalaBearD4Poseidon2SaltedConfig<ObservedRng>,
        _,
        _,
        4,
    >::new(
        TrustedPreparedSource::UniStark {
            config: source,
            air: &air,
            preprocessed_commit: None,
            proof: &proof,
            public_inputs: &statement,
        },
        output,
        FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
            .for_extension_degree::<4>(),
        ProveNextLayerParams {
            table_packing: p3_circuit_prover::TablePacking::new(4, 4).with_min_trace_height(32),
            ..ProveNextLayerParams::default()
        },
    )
    .unwrap();
    let recursive = owner
        .prove(TrustedPreparedInput::UniStark {
            proof: &proof,
            public_inputs: &statement,
        })
        .unwrap();
    owner.verifier().verify(&recursive.0, &statement).unwrap();
    for (counter, initial) in source_draws.iter().zip(before) {
        assert_eq!(counter.load(Ordering::Relaxed), initial);
    }
    assert!(ZERO_SEEDED_INSTANCES.load(Ordering::Relaxed) > zero_instances_before);
    assert_eq!(ZERO_SEEDED_DRAWS.load(Ordering::Relaxed), zero_draws_before);
}

fri_lifecycle_case!(
    baby_bear_d4_poseidon1_random_codeword_lifecycle,
    field: BabyBear,
    wire_bytes: 4,
    config: BabyBearD4Poseidon1RandomCodewordConfig<StdRng>,
    degree: 4,
    suite: SuiteIdV1::BabyBearD4Poseidon1RandomCodewordFri,
    factory: |d: &FriConfigV1, l: &VerifierLimits| {
        baby_bear_d4_poseidon1_random_codeword(d, l, StdRng::seed_from_u64(101))
    },
    backend: FriRecursionBackend::<16, 8, _>::new(Poseidon1Config::BABY_BEAR_D4_W16)
        .for_extension_degree::<4>()
);

fri_lifecycle_case!(
    koala_bear_d4_poseidon2_random_codeword_lifecycle,
    field: KoalaBear,
    wire_bytes: 4,
    config: KoalaBearD4Poseidon2RandomCodewordConfig<StdRng>,
    degree: 4,
    suite: SuiteIdV1::KoalaBearD4Poseidon2RandomCodewordFri,
    factory: |d: &FriConfigV1, l: &VerifierLimits| {
        koala_bear_d4_poseidon2_random_codeword(d, l, StdRng::seed_from_u64(102))
    },
    backend: FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
        .for_extension_degree::<4>()
);

fri_lifecycle_case!(
    koala_bear_d4_poseidon1_random_codeword_lifecycle,
    field: KoalaBear,
    wire_bytes: 4,
    config: KoalaBearD4Poseidon1RandomCodewordConfig<StdRng>,
    degree: 4,
    suite: SuiteIdV1::KoalaBearD4Poseidon1RandomCodewordFri,
    factory: |d: &FriConfigV1, l: &VerifierLimits| {
        koala_bear_d4_poseidon1_random_codeword(d, l, StdRng::seed_from_u64(103))
    },
    backend: FriRecursionBackend::<16, 8, _>::new(Poseidon1Config::KOALA_BEAR_D4_W16)
        .for_extension_degree::<4>()
);

fri_lifecycle_case!(
    goldilocks_d2_poseidon2_random_codeword_lifecycle,
    field: Goldilocks,
    wire_bytes: 8,
    config: GoldilocksD2Poseidon2RandomCodewordConfig<StdRng>,
    degree: 2,
    suite: SuiteIdV1::GoldilocksD2Poseidon2RandomCodewordFri,
    factory: |d: &FriConfigV1, l: &VerifierLimits| {
        goldilocks_d2_poseidon2_random_codeword(d, l, StdRng::seed_from_u64(104))
    },
    backend: FriRecursionBackend::<8, 4, _>::new(Poseidon2Config::GOLDILOCKS_D2_W8)
        .for_extension_degree::<2>()
);

fri_lifecycle_case!(
    goldilocks_d2_poseidon1_random_codeword_lifecycle,
    field: Goldilocks,
    wire_bytes: 8,
    config: GoldilocksD2Poseidon1RandomCodewordConfig<StdRng>,
    degree: 2,
    suite: SuiteIdV1::GoldilocksD2Poseidon1RandomCodewordFri,
    factory: |d: &FriConfigV1, l: &VerifierLimits| {
        goldilocks_d2_poseidon1_random_codeword(d, l, StdRng::seed_from_u64(105))
    },
    backend: FriRecursionBackend::<8, 4, _>::new(Poseidon1Config::GOLDILOCKS_D2_W8)
        .for_extension_degree::<2>()
);

fri_lifecycle_case!(
    koala_bear_d4_poseidon2_salted_lifecycle,
    field: KoalaBear,
    wire_bytes: 4,
    config: KoalaBearD4Poseidon2SaltedConfig<StdRng>,
    degree: 4,
    suite: SuiteIdV1::KoalaBearD4Poseidon2SaltedFri,
    factory: |d: &FriConfigV1, l: &VerifierLimits| {
        koala_bear_d4_poseidon2_salted(
            d,
            l,
            StdRng::seed_from_u64(106),
            StdRng::seed_from_u64(107),
            StdRng::seed_from_u64(108),
        )
    },
    backend: FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
        .for_extension_degree::<4>()
);
