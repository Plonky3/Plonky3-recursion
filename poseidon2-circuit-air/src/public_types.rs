//! Public types for the Poseidon2 circuit AIR.
//!
//! Defines abstracted field-specific parameters for
//! the Poseidon2 circuit AIR for commonly used configurations.

use p3_baby_bear::{BabyBear, GenericPoseidon2LinearLayersBabyBear};
use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear};

use p3_circuit::tables::Poseidon2Params;
use crate::Poseidon2CircuitAir;

/// Poseidon2 configuration for BabyBear with D=4, WIDTH=16.
pub struct BabyBearD4Width16;

impl Poseidon2Params for BabyBearD4Width16 {
    const D: usize = 4;
    const WIDTH: usize = 16;
    const RATE_EXT: usize = 2;
    const CAPACITY_EXT: usize = 2;
    const SBOX_DEGREE: u64 = 7;
    const SBOX_REGISTERS: usize = 1;
    const HALF_FULL_ROUNDS: usize = 4;
    const PARTIAL_ROUNDS: usize = 13;
}

/// Poseidon2 configuration for BabyBear with D=4, WIDTH=24.
pub struct BabyBearD4Width24;

impl Poseidon2Params for BabyBearD4Width24 {
    const D: usize = 4;
    const WIDTH: usize = 24;
    const RATE_EXT: usize = 4;
    const CAPACITY_EXT: usize = 2;
    const SBOX_DEGREE: u64 = 7;
    const SBOX_REGISTERS: usize = 1;
    const HALF_FULL_ROUNDS: usize = 4;
    const PARTIAL_ROUNDS: usize = 13;
}

/// Poseidon2 configuration for KoalaBear with D=4, WIDTH=16.
pub struct KoalaBearD4Width16;

impl Poseidon2Params for KoalaBearD4Width16 {
    const D: usize = 4;
    const WIDTH: usize = 16;
    const RATE_EXT: usize = 2;
    const CAPACITY_EXT: usize = 2;
    const SBOX_DEGREE: u64 = 3;
    const SBOX_REGISTERS: usize = 0;
    const HALF_FULL_ROUNDS: usize = 4;
    const PARTIAL_ROUNDS: usize = 20;
}

/// Poseidon2 configuration for KoalaBear with D=4, WIDTH=24.
pub struct KoalaBearD4Width24;

impl Poseidon2Params for KoalaBearD4Width24 {
    const D: usize = 4;
    const WIDTH: usize = 24;
    const RATE_EXT: usize = 4;
    const CAPACITY_EXT: usize = 2;
    const SBOX_DEGREE: u64 = 3;
    const SBOX_REGISTERS: usize = 0;
    const HALF_FULL_ROUNDS: usize = 4;
    const PARTIAL_ROUNDS: usize = 20;
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
