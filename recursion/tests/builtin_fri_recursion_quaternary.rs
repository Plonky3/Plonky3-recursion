#[macro_use]
#[path = "common/builtin_fri_lifecycle.rs"]
#[allow(clippy::duplicate_mod)]
mod builtin_fri_lifecycle;

use p3_baby_bear::BabyBear;
use p3_goldilocks::Goldilocks;
use p3_koala_bear::KoalaBear;
use p3_recursion::builtin_config::*;
use p3_recursion::{FriRecursionBackend, Poseidon2Config};

fri_lifecycle_case!(
    baby_bear_d4_poseidon2_quaternary_lifecycle,
    field: BabyBear,
    wire_bytes: 4,
    config: BabyBearD4Poseidon2QuaternaryConfig,
    degree: 4,
    suite: SuiteIdV1::BabyBearD4Poseidon2QuaternaryFri,
    factory: baby_bear_d4_poseidon2_quaternary,
    backend: FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::BABY_BEAR_D4_W16)
        .with_extra_poseidon2_table(Poseidon2Config::BABY_BEAR_D4_W32)
        .for_extension_degree::<4>()
);

fri_lifecycle_case!(
    koala_bear_d4_poseidon2_quaternary_lifecycle,
    field: KoalaBear,
    wire_bytes: 4,
    config: KoalaBearD4Poseidon2QuaternaryConfig,
    degree: 4,
    suite: SuiteIdV1::KoalaBearD4Poseidon2QuaternaryFri,
    factory: koala_bear_d4_poseidon2_quaternary,
    backend: FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
        .with_extra_poseidon2_table(Poseidon2Config::KOALA_BEAR_D4_W32)
        .for_extension_degree::<4>()
);

fri_lifecycle_case!(
    goldilocks_d2_poseidon2_quaternary_lifecycle,
    field: Goldilocks,
    wire_bytes: 8,
    config: GoldilocksD2Poseidon2QuaternaryConfig,
    degree: 2,
    suite: SuiteIdV1::GoldilocksD2Poseidon2QuaternaryFri,
    factory: goldilocks_d2_poseidon2_quaternary,
    backend: FriRecursionBackend::<8, 4, _>::new(Poseidon2Config::GOLDILOCKS_D2_W8)
        .with_extra_poseidon2_table(Poseidon2Config::GOLDILOCKS_D2_W16)
        .for_extension_degree::<2>()
);

fri_lifecycle_case!(
    koala_bear_d5_poseidon2_quaternary_lifecycle,
    field: KoalaBear,
    wire_bytes: 4,
    config: KoalaBearD5Poseidon2QuaternaryConfig,
    degree: 5,
    suite: SuiteIdV1::KoalaBearD5Poseidon2QuaternaryFri,
    factory: koala_bear_d5_poseidon2_quaternary,
    backend: FriRecursionBackend::<16, 8, _>::new_d5(Poseidon2Config::KOALA_BEAR_D1_W16)
        .with_extra_poseidon2_table(Poseidon2Config::KOALA_BEAR_D1_W32)
);
