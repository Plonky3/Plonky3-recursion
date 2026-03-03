//! Public types for the Poseidon2 circuit AIR.
//!
//! Defines abstracted field-specific parameters for
//! the Poseidon2 circuit AIR for commonly used configurations.

extern crate alloc;

use alloc::vec::Vec;

use p3_baby_bear::{BabyBear, GenericPoseidon2LinearLayersBabyBear};
use p3_circuit::ops::{GoldilocksD2Width8, Poseidon2Config, Poseidon2Params};
use p3_goldilocks::{GenericPoseidon2LinearLayersGoldilocks, Goldilocks};
use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear};
use p3_poseidon2_air::RoundConstants;
use rand::SeedableRng;
use rand::rngs::SmallRng;

use crate::Poseidon2CircuitAir;

/// Poseidon2 configuration for BabyBear with D=4, WIDTH=16.
pub struct BabyBearD4Width16;

impl Poseidon2Params for BabyBearD4Width16 {
    type BaseField = BabyBear;
    const CONFIG: Poseidon2Config = Poseidon2Config::BabyBearD4Width16;
}

impl BabyBearD4Width16 {
    pub const fn round_constants() -> RoundConstants<BabyBear, 16, 4, 13> {
        RoundConstants::new(
            p3_baby_bear::BABYBEAR_RC16_EXTERNAL_INITIAL,
            p3_baby_bear::BABYBEAR_RC16_INTERNAL,
            p3_baby_bear::BABYBEAR_RC16_EXTERNAL_FINAL,
        )
    }

    pub const fn default_air() -> Poseidon2CircuitAirBabyBearD4Width16 {
        Poseidon2CircuitAirBabyBearD4Width16::new(Self::round_constants())
    }

    pub fn default_air_with_preprocessed(
        preprocessed: Vec<BabyBear>,
        min_height: usize,
    ) -> Poseidon2CircuitAirBabyBearD4Width16 {
        Poseidon2CircuitAirBabyBearD4Width16::new_with_preprocessed(
            Self::round_constants(),
            preprocessed,
        )
        .with_min_height(min_height)
    }
}

/// Poseidon2 configuration for BabyBear with D=4, WIDTH=24.
pub struct BabyBearD4Width24;

impl Poseidon2Params for BabyBearD4Width24 {
    type BaseField = BabyBear;
    const CONFIG: Poseidon2Config = Poseidon2Config::BabyBearD4Width24;
}

impl BabyBearD4Width24 {
    pub const fn round_constants() -> RoundConstants<BabyBear, 24, 4, 21> {
        RoundConstants::new(
            p3_baby_bear::BABYBEAR_RC24_EXTERNAL_INITIAL,
            p3_baby_bear::BABYBEAR_RC24_INTERNAL,
            p3_baby_bear::BABYBEAR_RC24_EXTERNAL_FINAL,
        )
    }

    pub const fn default_air() -> Poseidon2CircuitAirBabyBearD4Width24 {
        Poseidon2CircuitAirBabyBearD4Width24::new(Self::round_constants())
    }

    pub fn default_air_with_preprocessed(
        preprocessed: Vec<BabyBear>,
        min_height: usize,
    ) -> Poseidon2CircuitAirBabyBearD4Width24 {
        Poseidon2CircuitAirBabyBearD4Width24::new_with_preprocessed(
            Self::round_constants(),
            preprocessed,
        )
        .with_min_height(min_height)
    }
}

/// Poseidon2 configuration for KoalaBear with D=4, WIDTH=16.
pub struct KoalaBearD4Width16;

impl Poseidon2Params for KoalaBearD4Width16 {
    type BaseField = KoalaBear;
    const CONFIG: Poseidon2Config = Poseidon2Config::KoalaBearD4Width16;
}

impl KoalaBearD4Width16 {
    pub const fn round_constants() -> RoundConstants<KoalaBear, 16, 4, 20> {
        RoundConstants::new(
            p3_koala_bear::KOALABEAR_RC16_EXTERNAL_INITIAL,
            p3_koala_bear::KOALABEAR_RC16_INTERNAL,
            p3_koala_bear::KOALABEAR_RC16_EXTERNAL_FINAL,
        )
    }

    pub const fn default_air() -> Poseidon2CircuitAirKoalaBearD4Width16 {
        Poseidon2CircuitAirKoalaBearD4Width16::new(Self::round_constants())
    }

    pub fn default_air_with_preprocessed(
        preprocessed: Vec<KoalaBear>,
        min_height: usize,
    ) -> Poseidon2CircuitAirKoalaBearD4Width16 {
        Poseidon2CircuitAirKoalaBearD4Width16::new_with_preprocessed(
            Self::round_constants(),
            preprocessed,
        )
        .with_min_height(min_height)
    }
}

/// Poseidon2 configuration for KoalaBear with D=4, WIDTH=24.
pub struct KoalaBearD4Width24;

impl Poseidon2Params for KoalaBearD4Width24 {
    type BaseField = KoalaBear;
    const CONFIG: Poseidon2Config = Poseidon2Config::KoalaBearD4Width24;
}

impl KoalaBearD4Width24 {
    pub const fn round_constants() -> RoundConstants<KoalaBear, 24, 4, 23> {
        RoundConstants::new(
            p3_koala_bear::KOALABEAR_RC24_EXTERNAL_INITIAL,
            p3_koala_bear::KOALABEAR_RC24_INTERNAL,
            p3_koala_bear::KOALABEAR_RC24_EXTERNAL_FINAL,
        )
    }

    pub const fn default_air() -> Poseidon2CircuitAirKoalaBearD4Width24 {
        Poseidon2CircuitAirKoalaBearD4Width24::new(Self::round_constants())
    }

    pub fn default_air_with_preprocessed(
        preprocessed: Vec<KoalaBear>,
        min_height: usize,
    ) -> Poseidon2CircuitAirKoalaBearD4Width24 {
        Poseidon2CircuitAirKoalaBearD4Width24::new_with_preprocessed(
            Self::round_constants(),
            preprocessed,
        )
        .with_min_height(min_height)
    }
}

/// BabyBear Poseidon2 circuit AIR with D=4, WIDTH=16.
/// Uses constants from `BabyBearD4Width16` configuration.
pub type Poseidon2CircuitAirBabyBearD4Width16 = Poseidon2CircuitAir<
    BabyBear,
    GenericPoseidon2LinearLayersBabyBear,
    { BabyBearD4Width16::D },
    { BabyBearD4Width16::WIDTH },
    { BabyBearD4Width16::WIDTH_EXT },
    { BabyBearD4Width16::RATE_EXT },
    { BabyBearD4Width16::CAPACITY_EXT },
    { BabyBearD4Width16::SBOX_DEGREE },
    { BabyBearD4Width16::SBOX_REGISTERS },
    { BabyBearD4Width16::HALF_FULL_ROUNDS },
    { BabyBearD4Width16::PARTIAL_ROUNDS },
>;

/// BabyBear Poseidon2 circuit AIR with D=4, WIDTH=24.
/// Uses constants from `BabyBearD4Width24` configuration.
pub type Poseidon2CircuitAirBabyBearD4Width24 = Poseidon2CircuitAir<
    BabyBear,
    GenericPoseidon2LinearLayersBabyBear,
    { BabyBearD4Width24::D },
    { BabyBearD4Width24::WIDTH },
    { BabyBearD4Width24::WIDTH_EXT },
    { BabyBearD4Width24::RATE_EXT },
    { BabyBearD4Width24::CAPACITY_EXT },
    { BabyBearD4Width24::SBOX_DEGREE },
    { BabyBearD4Width24::SBOX_REGISTERS },
    { BabyBearD4Width24::HALF_FULL_ROUNDS },
    { BabyBearD4Width24::PARTIAL_ROUNDS },
>;

/// KoalaBear Poseidon2 circuit AIR with D=4, WIDTH=16.
/// Uses constants from `KoalaBearD4Width16` configuration.
pub type Poseidon2CircuitAirKoalaBearD4Width16 = Poseidon2CircuitAir<
    KoalaBear,
    GenericPoseidon2LinearLayersKoalaBear,
    { KoalaBearD4Width16::D },
    { KoalaBearD4Width16::WIDTH },
    { KoalaBearD4Width16::WIDTH_EXT },
    { KoalaBearD4Width16::RATE_EXT },
    { KoalaBearD4Width16::CAPACITY_EXT },
    { KoalaBearD4Width16::SBOX_DEGREE },
    { KoalaBearD4Width16::SBOX_REGISTERS },
    { KoalaBearD4Width16::HALF_FULL_ROUNDS },
    { KoalaBearD4Width16::PARTIAL_ROUNDS },
>;

/// KoalaBear Poseidon2 circuit AIR with D=4, WIDTH=24.
/// Uses constants from `KoalaBearD4Width24` configuration.
pub type Poseidon2CircuitAirKoalaBearD4Width24 = Poseidon2CircuitAir<
    KoalaBear,
    GenericPoseidon2LinearLayersKoalaBear,
    { KoalaBearD4Width24::D },
    { KoalaBearD4Width24::WIDTH },
    { KoalaBearD4Width24::WIDTH_EXT },
    { KoalaBearD4Width24::RATE_EXT },
    { KoalaBearD4Width24::CAPACITY_EXT },
    { KoalaBearD4Width24::SBOX_DEGREE },
    { KoalaBearD4Width24::SBOX_REGISTERS },
    { KoalaBearD4Width24::HALF_FULL_ROUNDS },
    { KoalaBearD4Width24::PARTIAL_ROUNDS },
>;

/// Goldilocks Poseidon2 circuit AIR with D=2, WIDTH=8.
pub type Poseidon2CircuitAirGoldilocksD2Width8 = Poseidon2CircuitAir<
    Goldilocks,
    GenericPoseidon2LinearLayersGoldilocks,
    { GoldilocksD2Width8::D },
    { GoldilocksD2Width8::WIDTH },
    { GoldilocksD2Width8::WIDTH_EXT },
    { GoldilocksD2Width8::RATE_EXT },
    { GoldilocksD2Width8::CAPACITY_EXT },
    { GoldilocksD2Width8::SBOX_DEGREE },
    { GoldilocksD2Width8::SBOX_REGISTERS },
    { GoldilocksD2Width8::HALF_FULL_ROUNDS },
    { GoldilocksD2Width8::PARTIAL_ROUNDS },
>;

pub fn goldilocks_d2_width8_round_constants() -> RoundConstants<Goldilocks, 8, 4, 22> {
    use rand::RngExt;
    use rand::distr::StandardUniform;
    let mut rng = SmallRng::seed_from_u64(1);
    let beginning_full: [[Goldilocks; 8]; 4] =
        core::array::from_fn(|_| rng.sample(StandardUniform));
    let ending_full: [[Goldilocks; 8]; 4] = core::array::from_fn(|_| rng.sample(StandardUniform));
    let partial: [Goldilocks; 22] = core::array::from_fn(|_| rng.sample(StandardUniform));
    RoundConstants::new(beginning_full, partial, ending_full)
}

pub fn goldilocks_d2_width8_default_air() -> Poseidon2CircuitAirGoldilocksD2Width8 {
    Poseidon2CircuitAirGoldilocksD2Width8::new(goldilocks_d2_width8_round_constants())
}

pub fn goldilocks_d2_width8_default_air_with_preprocessed(
    preprocessed: Vec<Goldilocks>,
    min_height: usize,
) -> Poseidon2CircuitAirGoldilocksD2Width8 {
    Poseidon2CircuitAirGoldilocksD2Width8::new_with_preprocessed(
        goldilocks_d2_width8_round_constants(),
        preprocessed,
    )
    .with_min_height(min_height)
}
