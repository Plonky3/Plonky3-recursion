//! Poseidon2 configuration types and execution closures.

use alloc::sync::Arc;
use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

/// Poseidon2 configuration used as a stable operation key and parameter source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub enum Poseidon2Config {
    /// BabyBear with extension degree D=1 (base field challenges), width 16.
    BabyBearD1Width16,
    BabyBearD4Width16,
    BabyBearD4Width24,
    /// BabyBear with quartic extension, width 32.
    BabyBearD4Width32,
    /// KoalaBear with extension degree D=1 (base field challenges), width 16.
    KoalaBearD1Width16,
    KoalaBearD4Width16,
    KoalaBearD4Width24,
    /// KoalaBear with quartic extension, width 32.
    KoalaBearD4Width32,
    /// Goldilocks with extension degree D=2, width 8 (matches Poseidon2Goldilocks<8>).
    GoldilocksD2Width8,
    /// Goldilocks with quadratic extension, width 16.
    GoldilocksD2Width16,
}

impl Poseidon2Config {
    pub const fn d(self) -> usize {
        match self {
            Self::BabyBearD1Width16 | Self::KoalaBearD1Width16 => 1,
            Self::GoldilocksD2Width8 | Self::GoldilocksD2Width16 => 2,
            Self::BabyBearD4Width16
            | Self::BabyBearD4Width24
            | Self::BabyBearD4Width32
            | Self::KoalaBearD4Width16
            | Self::KoalaBearD4Width24
            | Self::KoalaBearD4Width32 => 4,
        }
    }

    pub const fn width(self) -> usize {
        match self {
            Self::BabyBearD1Width16
            | Self::BabyBearD4Width16
            | Self::KoalaBearD1Width16
            | Self::KoalaBearD4Width16
            | Self::GoldilocksD2Width16 => 16,
            Self::BabyBearD4Width24 | Self::KoalaBearD4Width24 => 24,
            Self::BabyBearD4Width32 | Self::KoalaBearD4Width32 => 32,
            Self::GoldilocksD2Width8 => 8,
        }
    }

    /// Rate in extension field elements (WIDTH / D for D=4, or WIDTH for D=1).
    pub const fn rate_ext(self) -> usize {
        match self {
            Self::BabyBearD1Width16 | Self::KoalaBearD1Width16 => 8,
            Self::BabyBearD4Width16 | Self::KoalaBearD4Width16 => 2,
            Self::BabyBearD4Width24 | Self::KoalaBearD4Width24 => 4,
            // For width 32 with D=4 we have 8 extension limbs; keep capacity_ext=2,
            // so rate_ext=6.
            Self::BabyBearD4Width32 | Self::KoalaBearD4Width32 => 6,
            // For Goldilocks D=2, keep capacity_ext=2 and let rate_ext grow with width.
            Self::GoldilocksD2Width8 => 2,
            Self::GoldilocksD2Width16 => 6,
        }
    }

    pub const fn rate(self) -> usize {
        self.rate_ext() * self.d()
    }

    /// Capacity in extension field elements.
    pub const fn capacity_ext(self) -> usize {
        match self {
            Self::BabyBearD1Width16 | Self::KoalaBearD1Width16 => 8,
            Self::BabyBearD4Width16
            | Self::BabyBearD4Width24
            | Self::BabyBearD4Width32
            | Self::KoalaBearD4Width16
            | Self::KoalaBearD4Width24
            | Self::KoalaBearD4Width32 => 2,
            Self::GoldilocksD2Width8 | Self::GoldilocksD2Width16 => 2,
        }
    }

    pub const fn sbox_degree(self) -> u64 {
        match self {
            Self::BabyBearD1Width16
            | Self::BabyBearD4Width16
            | Self::BabyBearD4Width24
            | Self::BabyBearD4Width32 => 7,
            Self::KoalaBearD1Width16
            | Self::KoalaBearD4Width16
            | Self::KoalaBearD4Width24
            | Self::KoalaBearD4Width32 => 3,
            Self::GoldilocksD2Width8 | Self::GoldilocksD2Width16 => 7,
        }
    }

    pub const fn sbox_registers(self) -> usize {
        match self {
            Self::BabyBearD1Width16
            | Self::BabyBearD4Width16
            | Self::BabyBearD4Width24
            | Self::BabyBearD4Width32
            | Self::GoldilocksD2Width8
            | Self::GoldilocksD2Width16 => 1,
            Self::KoalaBearD1Width16
            | Self::KoalaBearD4Width16
            | Self::KoalaBearD4Width24
            | Self::KoalaBearD4Width32 => 0,
        }
    }

    pub const fn half_full_rounds(self) -> usize {
        match self {
            Self::BabyBearD1Width16
            | Self::BabyBearD4Width16
            | Self::BabyBearD4Width24
            | Self::KoalaBearD1Width16
            | Self::KoalaBearD4Width16
            | Self::KoalaBearD4Width24
            | Self::GoldilocksD2Width8
            | Self::GoldilocksD2Width16
            // Width 32 configs use 8 half-full rounds (see poseidon2::round_numbers).
            | Self::BabyBearD4Width32
            | Self::KoalaBearD4Width32 => 8,
        }
    }

    pub const fn partial_rounds(self) -> usize {
        match self {
            Self::BabyBearD1Width16 | Self::BabyBearD4Width16 => 13,
            Self::BabyBearD4Width24 => 21,
            // BabyBear width 32, s-box degree 7 -> 30 partial rounds.
            Self::BabyBearD4Width32 => 30,
            Self::KoalaBearD1Width16 | Self::KoalaBearD4Width16 => 20,
            Self::KoalaBearD4Width24 => 23,
            // KoalaBear width 32, s-box degree 3 -> 31 partial rounds.
            Self::KoalaBearD4Width32 => 31,
            // Goldilocks: reuse 22 partial rounds for both width 8 and 16,
            // matching upstream Poseidon2Goldilocks configurations.
            Self::GoldilocksD2Width8 | Self::GoldilocksD2Width16 => 22,
        }
    }

    pub const fn width_ext(self) -> usize {
        self.rate_ext() + self.capacity_ext()
    }

    /// Stable string name for this config variant, used to build `NpoTypeId`.
    pub const fn variant_name(self) -> &'static str {
        match self {
            Self::BabyBearD1Width16 => "baby_bear_d1_w16",
            Self::BabyBearD4Width16 => "baby_bear_d4_w16",
            Self::BabyBearD4Width24 => "baby_bear_d4_w24",
            Self::BabyBearD4Width32 => "baby_bear_d4_w32",
            Self::KoalaBearD1Width16 => "koala_bear_d1_w16",
            Self::KoalaBearD4Width16 => "koala_bear_d4_w16",
            Self::KoalaBearD4Width24 => "koala_bear_d4_w24",
            Self::KoalaBearD4Width32 => "koala_bear_d4_w32",
            Self::GoldilocksD2Width8 => "goldilocks_d2_w8",
            Self::GoldilocksD2Width16 => "goldilocks_d2_w16",
        }
    }

    /// Parse a `Poseidon2Config` from a variant name string.
    pub fn from_variant_name(name: &str) -> Option<Self> {
        match name {
            "baby_bear_d1_w16" => Some(Self::BabyBearD1Width16),
            "baby_bear_d4_w16" => Some(Self::BabyBearD4Width16),
            "baby_bear_d4_w24" => Some(Self::BabyBearD4Width24),
            "baby_bear_d4_w32" => Some(Self::BabyBearD4Width32),
            "koala_bear_d1_w16" => Some(Self::KoalaBearD1Width16),
            "koala_bear_d4_w16" => Some(Self::KoalaBearD4Width16),
            "koala_bear_d4_w24" => Some(Self::KoalaBearD4Width24),
            "koala_bear_d4_w32" => Some(Self::KoalaBearD4Width32),
            "goldilocks_d2_w8" => Some(Self::GoldilocksD2Width8),
            "goldilocks_d2_w16" => Some(Self::GoldilocksD2Width16),
            _ => None,
        }
    }
}

/// Poseidon2 permutation execution closure (extension field mode).
///
/// Takes `width_ext` extension field limbs and returns `width_ext` output limbs.
pub type Poseidon2PermExec<F> = Arc<dyn Fn(&[F]) -> Vec<F> + Send + Sync>;

/// Type alias for the Poseidon2 permutation execution closure for D=1 (base field).
///
/// The closure takes 16 base field elements and returns 16 base field elements.
pub type Poseidon2PermExecBase<F> = Arc<dyn Fn(&[F; 16]) -> [F; 16] + Send + Sync>;

/// Config data stored inside `NpoConfig` for Poseidon2 D>=2 (extension field) mode.
#[derive(Clone)]
pub struct Poseidon2PermConfigData<F> {
    /// Poseidon2 parameter set (width, rate, etc.).
    pub config: Poseidon2Config,
    /// Execution closure for the permutation.
    pub exec: Poseidon2PermExec<F>,
    /// Merkle arity used when this permutation is in Merkle-path mode.
    ///
    /// This is a per-table parameter (constant for a given `NpoTypeId`) that
    /// controls how many children a single compression node conceptually has.
    /// For now we only support the binary case `2` and the 4-ary case `4`.
    pub merkle_arity: u8,
}

impl<F> Poseidon2PermConfigData<F> {
    /// Construct a new config payload with an explicit Merkle arity.
    ///
    /// The arity must be a power of two and at least 2. Currently only 2 and 4
    /// are supported.
    pub fn new(config: Poseidon2Config, exec: Poseidon2PermExec<F>, merkle_arity: u8) -> Self {
        // Accept only small, power-of-two arities; this keeps the table ready for
        // 2-ary and 4-ary Merkle trees while preventing accidental misuse.
        assert!(
            matches!(merkle_arity, 2 | 4),
            "Poseidon2PermConfigData::new only supports merkle_arity in {{2, 4}}, got {merkle_arity}"
        );
        Self {
            config,
            exec,
            merkle_arity,
        }
    }
}

/// Config data stored inside `NpoConfig` for Poseidon2 D=1 (base field) mode.
#[derive(Clone)]
pub struct Poseidon2PermBaseConfigData<F> {
    pub config: Poseidon2Config,
    pub exec: Poseidon2PermExecBase<F>,
}
