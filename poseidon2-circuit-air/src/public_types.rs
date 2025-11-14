//! Public types for the Poseidon2 circuit AIR.
//!
//! Defines abstracted field-specific parameters for
//! the Poseidon2 circuit AIR for commonly used configurations.

use p3_baby_bear::{BabyBear, GenericPoseidon2LinearLayersBabyBear};
use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear};

use crate::Poseidon2CircuitAir;

/// BabyBear Poseidon2 circuit AIR with D=4, WIDTH=16.
pub type Poseidon2CircuitAirBabyBearD4Width16 = Poseidon2CircuitAir<
    BabyBear,
    GenericPoseidon2LinearLayersBabyBear,
    4,
    16,
    4,
    2,
    2,
    7,
    1,
    4,
    13,
>;

/// BabyBear Poseidon2 circuit AIR with D=4, WIDTH=24.
pub type Poseidon2CircuitAirBabyBearD4Width24 = Poseidon2CircuitAir<
    BabyBear,
    GenericPoseidon2LinearLayersBabyBear,
    4,
    24,
    6,
    4,
    2,
    7,
    1,
    4,
    13,
>;

/// KoalaBear Poseidon2 circuit AIR with D=4, WIDTH=16.
pub type Poseidon2CircuitAirKoalaBearD4Width16 = Poseidon2CircuitAir<
    KoalaBear,
    GenericPoseidon2LinearLayersKoalaBear,
    4,
    16,
    4,
    2,
    2,
    3,
    0,
    4,
    20,
>;

/// KoalaBear Poseidon2 circuit AIR with D=4, WIDTH=24.
pub type Poseidon2CircuitAirKoalaBearD4Width24 = Poseidon2CircuitAir<
    KoalaBear,
    GenericPoseidon2LinearLayersKoalaBear,
    4,
    24,
    6,
    4,
    2,
    3,
    0,
    4,
    20,
>;
