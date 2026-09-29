#[macro_use]
#[path = "common/builtin_fri_lifecycle.rs"]
mod builtin_fri_lifecycle;

use p3_baby_bear::BabyBear;
use p3_circuit::ops::Poseidon1Config;
use p3_goldilocks::Goldilocks;
use p3_koala_bear::KoalaBear;
use p3_recursion::builtin_config::*;
use p3_recursion::{FriRecursionBackend, Poseidon2Config};

fri_lifecycle_case!(
    baby_bear_d4_poseidon2_binary_lifecycle,
    field: BabyBear,
    wire_bytes: 4,
    config: BabyBearD4Poseidon2BinaryConfig,
    degree: 4,
    suite: SuiteIdV1::BabyBearD4Poseidon2BinaryFri,
    factory: baby_bear_d4_poseidon2_binary,
    backend: FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::BABY_BEAR_D4_W16)
        .for_extension_degree::<4>()
);

fri_lifecycle_case!(
    baby_bear_d4_poseidon1_binary_lifecycle,
    field: BabyBear,
    wire_bytes: 4,
    config: BabyBearD4Poseidon1BinaryConfig,
    degree: 4,
    suite: SuiteIdV1::BabyBearD4Poseidon1BinaryFri,
    factory: baby_bear_d4_poseidon1_binary,
    backend: FriRecursionBackend::<16, 8, _>::new(Poseidon1Config::BABY_BEAR_D4_W16)
        .for_extension_degree::<4>()
);

fri_lifecycle_case!(
    koala_bear_d4_poseidon2_binary_lifecycle,
    field: KoalaBear,
    wire_bytes: 4,
    config: KoalaBearD4Poseidon2BinaryConfig,
    degree: 4,
    suite: SuiteIdV1::KoalaBearD4Poseidon2BinaryFri,
    factory: koala_bear_d4_poseidon2_binary,
    backend: FriRecursionBackend::<16, 8, _>::new(Poseidon2Config::KOALA_BEAR_D4_W16)
        .for_extension_degree::<4>()
);

fri_lifecycle_case!(
    koala_bear_d4_poseidon1_binary_lifecycle,
    field: KoalaBear,
    wire_bytes: 4,
    config: KoalaBearD4Poseidon1BinaryConfig,
    degree: 4,
    suite: SuiteIdV1::KoalaBearD4Poseidon1BinaryFri,
    factory: koala_bear_d4_poseidon1_binary,
    backend: FriRecursionBackend::<16, 8, _>::new(Poseidon1Config::KOALA_BEAR_D4_W16)
        .for_extension_degree::<4>()
);

fri_lifecycle_case!(
    goldilocks_d2_poseidon2_binary_lifecycle,
    field: Goldilocks,
    wire_bytes: 8,
    config: GoldilocksD2Poseidon2BinaryConfig,
    degree: 2,
    suite: SuiteIdV1::GoldilocksD2Poseidon2BinaryFri,
    factory: goldilocks_d2_poseidon2_binary,
    backend: FriRecursionBackend::<8, 4, _>::new(Poseidon2Config::GOLDILOCKS_D2_W8)
        .for_extension_degree::<2>(),
    final_poly_log: 1,
    commit_pow_bits: 1
);

fri_lifecycle_case!(
    goldilocks_d2_poseidon1_binary_lifecycle,
    field: Goldilocks,
    wire_bytes: 8,
    config: GoldilocksD2Poseidon1BinaryConfig,
    degree: 2,
    suite: SuiteIdV1::GoldilocksD2Poseidon1BinaryFri,
    factory: goldilocks_d2_poseidon1_binary,
    backend: FriRecursionBackend::<8, 4, _>::new(Poseidon1Config::GOLDILOCKS_D2_W8)
        .for_extension_degree::<2>()
);

fri_lifecycle_case!(
    koala_bear_d5_poseidon2_binary_lifecycle,
    field: KoalaBear,
    wire_bytes: 4,
    config: KoalaBearD5Poseidon2BinaryConfig,
    degree: 5,
    suite: SuiteIdV1::KoalaBearD5Poseidon2BinaryFri,
    factory: koala_bear_d5_poseidon2_binary,
    backend: FriRecursionBackend::<16, 8, _>::new_d5(Poseidon2Config::KOALA_BEAR_D1_W16)
);

fri_lifecycle_case!(
    koala_bear_d5_poseidon1_binary_lifecycle,
    field: KoalaBear,
    wire_bytes: 4,
    config: KoalaBearD5Poseidon1BinaryConfig,
    degree: 5,
    suite: SuiteIdV1::KoalaBearD5Poseidon1BinaryFri,
    factory: koala_bear_d5_poseidon1_binary,
    backend: FriRecursionBackend::<16, 8, _>::new_d5(Poseidon1Config::KOALA_BEAR_D1_W16)
);
