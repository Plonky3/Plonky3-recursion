use alloc::vec::Vec;

use p3_baby_bear::BabyBear;
use p3_circuit::ops::{PermConfig, Poseidon1Config, Poseidon2Config};
use p3_field::PrimeField64;
use p3_fri::FriParameters;
use p3_goldilocks::Goldilocks;
use p3_koala_bear::KoalaBear;
use p3_sumcheck::strategy::VariableOrder;
use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};
use thiserror::Error;

use crate::pcs::fri::{FriInputError, FriVerifierParams, FriVerifierParamsError, NativeFriParams};
use crate::pcs::whir::uni::WhirUniVerifierParams;
use crate::verifier::VerifierLimits;

/// Stable V1 suite identifier.  Values are part of the artifact protocol.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[repr(u16)]
pub enum SuiteIdV1 {
    BabyBearD4Poseidon2BinaryFri = 0x0101,
    BabyBearD4Poseidon1BinaryFri = 0x0102,
    KoalaBearD4Poseidon2BinaryFri = 0x0103,
    KoalaBearD4Poseidon1BinaryFri = 0x0104,
    GoldilocksD2Poseidon2BinaryFri = 0x0105,
    GoldilocksD2Poseidon1BinaryFri = 0x0106,
    KoalaBearD5Poseidon2BinaryFri = 0x0107,
    KoalaBearD5Poseidon1BinaryFri = 0x0108,
    BabyBearD4Poseidon2QuaternaryFri = 0x0201,
    KoalaBearD4Poseidon2QuaternaryFri = 0x0202,
    GoldilocksD2Poseidon2QuaternaryFri = 0x0203,
    KoalaBearD5Poseidon2QuaternaryFri = 0x0204,
    BabyBearD4Poseidon2RandomCodewordFri = 0x0301,
    BabyBearD4Poseidon1RandomCodewordFri = 0x0302,
    KoalaBearD4Poseidon2RandomCodewordFri = 0x0303,
    KoalaBearD4Poseidon1RandomCodewordFri = 0x0304,
    GoldilocksD2Poseidon2RandomCodewordFri = 0x0305,
    GoldilocksD2Poseidon1RandomCodewordFri = 0x0306,
    KoalaBearD4Poseidon2SaltedFri = 0x0401,
    BabyBearD4Poseidon2Whir = 0x0501,
    KoalaBearD4Poseidon2Whir = 0x0502,
}

impl SuiteIdV1 {
    pub const ALL: [Self; 21] = [
        Self::BabyBearD4Poseidon2BinaryFri,
        Self::BabyBearD4Poseidon1BinaryFri,
        Self::KoalaBearD4Poseidon2BinaryFri,
        Self::KoalaBearD4Poseidon1BinaryFri,
        Self::GoldilocksD2Poseidon2BinaryFri,
        Self::GoldilocksD2Poseidon1BinaryFri,
        Self::KoalaBearD5Poseidon2BinaryFri,
        Self::KoalaBearD5Poseidon1BinaryFri,
        Self::BabyBearD4Poseidon2QuaternaryFri,
        Self::KoalaBearD4Poseidon2QuaternaryFri,
        Self::GoldilocksD2Poseidon2QuaternaryFri,
        Self::KoalaBearD5Poseidon2QuaternaryFri,
        Self::BabyBearD4Poseidon2RandomCodewordFri,
        Self::BabyBearD4Poseidon1RandomCodewordFri,
        Self::KoalaBearD4Poseidon2RandomCodewordFri,
        Self::KoalaBearD4Poseidon1RandomCodewordFri,
        Self::GoldilocksD2Poseidon2RandomCodewordFri,
        Self::GoldilocksD2Poseidon1RandomCodewordFri,
        Self::KoalaBearD4Poseidon2SaltedFri,
        Self::BabyBearD4Poseidon2Whir,
        Self::KoalaBearD4Poseidon2Whir,
    ];

    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    pub const fn from_u16(raw: u16) -> Result<Self, BuiltinConfigError> {
        let suite = match raw {
            0x0101 => Self::BabyBearD4Poseidon2BinaryFri,
            0x0102 => Self::BabyBearD4Poseidon1BinaryFri,
            0x0103 => Self::KoalaBearD4Poseidon2BinaryFri,
            0x0104 => Self::KoalaBearD4Poseidon1BinaryFri,
            0x0105 => Self::GoldilocksD2Poseidon2BinaryFri,
            0x0106 => Self::GoldilocksD2Poseidon1BinaryFri,
            0x0107 => Self::KoalaBearD5Poseidon2BinaryFri,
            0x0108 => Self::KoalaBearD5Poseidon1BinaryFri,
            0x0201 => Self::BabyBearD4Poseidon2QuaternaryFri,
            0x0202 => Self::KoalaBearD4Poseidon2QuaternaryFri,
            0x0203 => Self::GoldilocksD2Poseidon2QuaternaryFri,
            0x0204 => Self::KoalaBearD5Poseidon2QuaternaryFri,
            0x0301 => Self::BabyBearD4Poseidon2RandomCodewordFri,
            0x0302 => Self::BabyBearD4Poseidon1RandomCodewordFri,
            0x0303 => Self::KoalaBearD4Poseidon2RandomCodewordFri,
            0x0304 => Self::KoalaBearD4Poseidon1RandomCodewordFri,
            0x0305 => Self::GoldilocksD2Poseidon2RandomCodewordFri,
            0x0306 => Self::GoldilocksD2Poseidon1RandomCodewordFri,
            0x0401 => Self::KoalaBearD4Poseidon2SaltedFri,
            0x0501 => Self::BabyBearD4Poseidon2Whir,
            0x0502 => Self::KoalaBearD4Poseidon2Whir,
            _ => return Err(BuiltinConfigError::UnsupportedSuite(raw)),
        };
        Ok(suite)
    }

    pub const fn spec(self) -> SuiteSpecV1 {
        use FieldFamilyV1::{BabyBear, Goldilocks, KoalaBear};
        use HashFamilyV1::{Poseidon1, Poseidon2};
        use ProofFamilyV1::{Fri, RandomCodewordFri, SaltedFri, Whir};

        let (
            field,
            extension_degree,
            hash,
            challenger_width,
            challenger_rate,
            mmcs_width,
            mmcs_rate,
            merkle_arity,
            proof_family,
            salt_elements,
        ) = match self {
            Self::BabyBearD4Poseidon2BinaryFri => (BabyBear, 4, Poseidon2, 16, 8, 16, 8, 2, Fri, 0),
            Self::BabyBearD4Poseidon1BinaryFri => (BabyBear, 4, Poseidon1, 16, 8, 16, 8, 2, Fri, 0),
            Self::KoalaBearD4Poseidon2BinaryFri => {
                (KoalaBear, 4, Poseidon2, 16, 8, 16, 8, 2, Fri, 0)
            }
            Self::KoalaBearD4Poseidon1BinaryFri => {
                (KoalaBear, 4, Poseidon1, 16, 8, 16, 8, 2, Fri, 0)
            }
            Self::GoldilocksD2Poseidon2BinaryFri => {
                (Goldilocks, 2, Poseidon2, 8, 4, 8, 4, 2, Fri, 0)
            }
            Self::GoldilocksD2Poseidon1BinaryFri => {
                (Goldilocks, 2, Poseidon1, 8, 4, 8, 4, 2, Fri, 0)
            }
            Self::KoalaBearD5Poseidon2BinaryFri => {
                (KoalaBear, 5, Poseidon2, 16, 8, 16, 8, 2, Fri, 0)
            }
            Self::KoalaBearD5Poseidon1BinaryFri => {
                (KoalaBear, 5, Poseidon1, 16, 8, 16, 8, 2, Fri, 0)
            }
            Self::BabyBearD4Poseidon2QuaternaryFri => {
                (BabyBear, 4, Poseidon2, 16, 8, 32, 24, 4, Fri, 0)
            }
            Self::KoalaBearD4Poseidon2QuaternaryFri => {
                (KoalaBear, 4, Poseidon2, 16, 8, 32, 24, 4, Fri, 0)
            }
            Self::GoldilocksD2Poseidon2QuaternaryFri => {
                (Goldilocks, 2, Poseidon2, 8, 4, 16, 12, 4, Fri, 0)
            }
            Self::KoalaBearD5Poseidon2QuaternaryFri => {
                (KoalaBear, 5, Poseidon2, 16, 8, 32, 24, 4, Fri, 0)
            }
            Self::BabyBearD4Poseidon2RandomCodewordFri => (
                BabyBear,
                4,
                Poseidon2,
                16,
                8,
                16,
                8,
                2,
                RandomCodewordFri,
                0,
            ),
            Self::BabyBearD4Poseidon1RandomCodewordFri => (
                BabyBear,
                4,
                Poseidon1,
                16,
                8,
                16,
                8,
                2,
                RandomCodewordFri,
                0,
            ),
            Self::KoalaBearD4Poseidon2RandomCodewordFri => (
                KoalaBear,
                4,
                Poseidon2,
                16,
                8,
                16,
                8,
                2,
                RandomCodewordFri,
                0,
            ),
            Self::KoalaBearD4Poseidon1RandomCodewordFri => (
                KoalaBear,
                4,
                Poseidon1,
                16,
                8,
                16,
                8,
                2,
                RandomCodewordFri,
                0,
            ),
            Self::GoldilocksD2Poseidon2RandomCodewordFri => (
                Goldilocks,
                2,
                Poseidon2,
                8,
                4,
                8,
                4,
                2,
                RandomCodewordFri,
                0,
            ),
            Self::GoldilocksD2Poseidon1RandomCodewordFri => (
                Goldilocks,
                2,
                Poseidon1,
                8,
                4,
                8,
                4,
                2,
                RandomCodewordFri,
                0,
            ),
            Self::KoalaBearD4Poseidon2SaltedFri => {
                (KoalaBear, 4, Poseidon2, 16, 8, 16, 8, 2, SaltedFri, 4)
            }
            Self::BabyBearD4Poseidon2Whir => (BabyBear, 4, Poseidon2, 16, 8, 16, 8, 2, Whir, 0),
            Self::KoalaBearD4Poseidon2Whir => (KoalaBear, 4, Poseidon2, 16, 8, 16, 8, 2, Whir, 0),
        };
        SuiteSpecV1 {
            field,
            extension_degree,
            quintic_trinomial: extension_degree == 5,
            hash,
            challenger_width,
            challenger_rate,
            mmcs_width,
            mmcs_rate,
            digest_elements: match field {
                Goldilocks => 4,
                BabyBear | KoalaBear => 8,
            },
            merkle_arity,
            proof_family,
            salt_elements,
            protocol_revision: 1,
        }
    }

    pub(crate) const fn mmcs_permutation(self) -> PermConfig {
        use Poseidon1Config as P1;
        use Poseidon2Config as P2;
        match self {
            Self::BabyBearD4Poseidon1BinaryFri | Self::BabyBearD4Poseidon1RandomCodewordFri => {
                PermConfig::poseidon1(P1::BABY_BEAR_D4_W16)
            }
            Self::KoalaBearD4Poseidon1BinaryFri | Self::KoalaBearD4Poseidon1RandomCodewordFri => {
                PermConfig::poseidon1(P1::KOALA_BEAR_D4_W16)
            }
            Self::GoldilocksD2Poseidon1BinaryFri | Self::GoldilocksD2Poseidon1RandomCodewordFri => {
                PermConfig::poseidon1(P1::GOLDILOCKS_D2_W8)
            }
            Self::KoalaBearD5Poseidon1BinaryFri => PermConfig::poseidon1(P1::KOALA_BEAR_D1_W16),
            Self::BabyBearD4Poseidon2QuaternaryFri => PermConfig::poseidon2(P2::BABY_BEAR_D4_W32),
            Self::KoalaBearD4Poseidon2QuaternaryFri => PermConfig::poseidon2(P2::KOALA_BEAR_D4_W32),
            Self::GoldilocksD2Poseidon2QuaternaryFri => {
                PermConfig::poseidon2(P2::GOLDILOCKS_D2_W16)
            }
            Self::KoalaBearD5Poseidon2QuaternaryFri => PermConfig::poseidon2(P2::KOALA_BEAR_D1_W32),
            Self::BabyBearD4Poseidon2BinaryFri
            | Self::BabyBearD4Poseidon2RandomCodewordFri
            | Self::BabyBearD4Poseidon2Whir => PermConfig::poseidon2(P2::BABY_BEAR_D4_W16),
            Self::KoalaBearD4Poseidon2BinaryFri
            | Self::KoalaBearD4Poseidon2RandomCodewordFri
            | Self::KoalaBearD4Poseidon2SaltedFri
            | Self::KoalaBearD4Poseidon2Whir => PermConfig::poseidon2(P2::KOALA_BEAR_D4_W16),
            Self::GoldilocksD2Poseidon2BinaryFri | Self::GoldilocksD2Poseidon2RandomCodewordFri => {
                PermConfig::poseidon2(P2::GOLDILOCKS_D2_W8)
            }
            Self::KoalaBearD5Poseidon2BinaryFri => PermConfig::poseidon2(P2::KOALA_BEAR_D1_W16),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldFamilyV1 {
    BabyBear,
    KoalaBear,
    Goldilocks,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HashFamilyV1 {
    Poseidon1,
    Poseidon2,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProofFamilyV1 {
    Fri,
    RandomCodewordFri,
    SaltedFri,
    Whir,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SuiteSpecV1 {
    pub field: FieldFamilyV1,
    pub extension_degree: u8,
    pub quintic_trinomial: bool,
    pub hash: HashFamilyV1,
    pub challenger_width: u8,
    pub challenger_rate: u8,
    pub mmcs_width: u8,
    pub mmcs_rate: u8,
    pub digest_elements: u8,
    pub merkle_arity: u8,
    pub proof_family: ProofFamilyV1,
    pub salt_elements: u8,
    pub protocol_revision: u16,
}

impl SuiteSpecV1 {
    pub const fn is_poseidon2(self) -> bool {
        matches!(self.hash, HashFamilyV1::Poseidon2)
    }

    pub const fn is_ordinary_fri(self) -> bool {
        matches!(self.proof_family, ProofFamilyV1::Fri)
    }

    pub const fn is_hiding(self) -> bool {
        matches!(
            self.proof_family,
            ProofFamilyV1::RandomCodewordFri | ProofFamilyV1::SaltedFri
        )
    }

    pub const fn is_salted(self) -> bool {
        matches!(self.proof_family, ProofFamilyV1::SaltedFri)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuiltinConfigDescriptorV1 {
    Fri(FriConfigV1),
    Whir(WhirConfigV1),
}

impl BuiltinConfigDescriptorV1 {
    pub const fn suite(&self) -> SuiteIdV1 {
        match self {
            Self::Fri(config) => config.suite(),
            Self::Whir(config) => config.suite(),
        }
    }

    pub fn validate(&self, limits: &VerifierLimits) -> Result<(), BuiltinConfigError> {
        match self {
            Self::Fri(config) => config.validate(limits),
            Self::Whir(config) => config.validate(limits),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FriConfigV1 {
    suite: SuiteIdV1,
    log_blowup: u32,
    log_final_poly_len: u32,
    max_log_arity: u32,
    num_queries: u32,
    commit_pow_bits: u32,
    query_pow_bits: u32,
    input_cap_height: u32,
    commit_cap_height: u32,
    num_random_codewords: u32,
    salt_elements: u32,
}

impl FriConfigV1 {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        suite: SuiteIdV1,
        log_blowup: u32,
        log_final_poly_len: u32,
        max_log_arity: u32,
        num_queries: u32,
        commit_pow_bits: u32,
        query_pow_bits: u32,
        input_cap_height: u32,
        commit_cap_height: u32,
        num_random_codewords: u32,
        salt_elements: u32,
    ) -> Self {
        Self {
            suite,
            log_blowup,
            log_final_poly_len,
            max_log_arity,
            num_queries,
            commit_pow_bits,
            query_pow_bits,
            input_cap_height,
            commit_cap_height,
            num_random_codewords,
            salt_elements,
        }
    }

    pub const fn suite(&self) -> SuiteIdV1 {
        self.suite
    }
    pub const fn log_blowup(&self) -> u32 {
        self.log_blowup
    }
    pub const fn log_final_poly_len(&self) -> u32 {
        self.log_final_poly_len
    }
    pub const fn max_log_arity(&self) -> u32 {
        self.max_log_arity
    }
    pub const fn num_queries(&self) -> u32 {
        self.num_queries
    }
    pub const fn commit_pow_bits(&self) -> u32 {
        self.commit_pow_bits
    }
    pub const fn query_pow_bits(&self) -> u32 {
        self.query_pow_bits
    }
    pub const fn input_cap_height(&self) -> u32 {
        self.input_cap_height
    }
    pub const fn commit_cap_height(&self) -> u32 {
        self.commit_cap_height
    }
    pub const fn num_random_codewords(&self) -> u32 {
        self.num_random_codewords
    }
    pub const fn salt_elements(&self) -> u32 {
        self.salt_elements
    }

    pub fn validate(&self, limits: &VerifierLimits) -> Result<(), BuiltinConfigError> {
        let spec = self.suite.spec();
        if matches!(spec.proof_family, ProofFamilyV1::Whir) {
            return Err(BuiltinConfigError::DescriptorFamilyMismatch {
                suite: self.suite,
                expected: "FRI",
            });
        }
        match spec.proof_family {
            ProofFamilyV1::Fri if self.num_random_codewords != 0 => {
                return Err(BuiltinConfigError::InvalidParameter {
                    component: "num_random_codewords",
                    value: self.num_random_codewords,
                });
            }
            ProofFamilyV1::RandomCodewordFri | ProofFamilyV1::SaltedFri
                if self.num_random_codewords == 0 =>
            {
                return Err(BuiltinConfigError::InvalidParameter {
                    component: "num_random_codewords",
                    value: 0,
                });
            }
            _ => {}
        }
        if self.salt_elements != u32::from(spec.salt_elements) {
            return Err(BuiltinConfigError::InvalidParameter {
                component: "salt_elements",
                value: self.salt_elements,
            });
        }

        check_cap(
            "input cap roots",
            spec.merkle_arity,
            self.input_cap_height,
            limits.max_cap_roots,
        )?;
        check_cap(
            "commit cap roots",
            spec.merkle_arity,
            self.commit_cap_height,
            limits.max_cap_roots,
        )?;
        check_limit(
            "queries per round",
            self.num_queries as usize,
            limits.max_queries_per_round,
        )?;
        check_limit(
            "num_random_codewords",
            self.num_random_codewords as usize,
            limits.max_matrix_width,
        )?;

        let params = FriParameters {
            max_log_arity: self.max_log_arity as usize,
            log_blowup: self.log_blowup as usize,
            log_final_poly_len: self.log_final_poly_len as usize,
            num_queries: self.num_queries as usize,
            batch_proof_of_work_bits: 0,
            commit_proof_of_work_bits: self.commit_pow_bits as usize,
            query_proof_of_work_bits: self.query_pow_bits as usize,
            mmcs: (),
        };
        match spec.field {
            FieldFamilyV1::BabyBear => NativeFriParams::try_from_native::<BabyBear, _>(&params),
            FieldFamilyV1::KoalaBear => NativeFriParams::try_from_native::<KoalaBear, _>(&params),
            FieldFamilyV1::Goldilocks => NativeFriParams::try_from_native::<Goldilocks, _>(&params),
        }
        .map_err(BuiltinConfigError::NativeFri)?;
        FriVerifierParams::try_with_mmcs(
            params.log_blowup,
            params.log_final_poly_len,
            params.max_log_arity,
            params.commit_proof_of_work_bits,
            params.query_proof_of_work_bits,
            params.num_queries,
            self.suite.mmcs_permutation(),
        )
        .map_err(BuiltinConfigError::RecursiveFri)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum WhirRateModeV1 {
    Auto,
    Explicit(Vec<u32>),
}

/// Closed V1 IDs for the WHIR soundness regimes exercised by this repository.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum WhirSecurityAssumptionV1 {
    CapacityBound = 1,
    UniqueDecoding = 2,
}

impl WhirSecurityAssumptionV1 {
    pub const fn as_u16(self) -> u16 {
        self as u16
    }

    pub const fn from_u16(raw: u16) -> Result<Self, BuiltinConfigError> {
        match raw {
            1 => Ok(Self::CapacityBound),
            2 => Ok(Self::UniqueDecoding),
            _ => Err(BuiltinConfigError::UnsupportedSecurityAssumption(raw)),
        }
    }

    const fn native(self) -> SecurityAssumption {
        match self {
            Self::CapacityBound => SecurityAssumption::CapacityBound,
            Self::UniqueDecoding => SecurityAssumption::UniqueDecoding,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WhirConfigV1 {
    suite: SuiteIdV1,
    starting_log_inv_rate: u32,
    round_log_inv_rates: WhirRateModeV1,
    folding_factor: u32,
    security_assumption_id: u16,
    security_level: u32,
    pow_bits: u32,
    log_max_lde_height: u32,
    cap_height: u32,
}

impl WhirConfigV1 {
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        suite: SuiteIdV1,
        starting_log_inv_rate: u32,
        round_log_inv_rates: WhirRateModeV1,
        folding_factor: u32,
        security_assumption_id: u16,
        security_level: u32,
        pow_bits: u32,
        log_max_lde_height: u32,
        cap_height: u32,
    ) -> Self {
        Self {
            suite,
            starting_log_inv_rate,
            round_log_inv_rates,
            folding_factor,
            security_assumption_id,
            security_level,
            pow_bits,
            log_max_lde_height,
            cap_height,
        }
    }

    pub const fn suite(&self) -> SuiteIdV1 {
        self.suite
    }
    pub const fn starting_log_inv_rate(&self) -> u32 {
        self.starting_log_inv_rate
    }
    pub const fn round_log_inv_rates(&self) -> &WhirRateModeV1 {
        &self.round_log_inv_rates
    }
    pub const fn folding_factor(&self) -> u32 {
        self.folding_factor
    }
    pub const fn security_assumption_id(&self) -> u16 {
        self.security_assumption_id
    }
    pub const fn security_level(&self) -> u32 {
        self.security_level
    }
    pub const fn pow_bits(&self) -> u32 {
        self.pow_bits
    }
    pub const fn log_max_lde_height(&self) -> u32 {
        self.log_max_lde_height
    }
    pub const fn cap_height(&self) -> u32 {
        self.cap_height
    }

    pub fn validate(&self, limits: &VerifierLimits) -> Result<(), BuiltinConfigError> {
        let spec = self.suite.spec();
        if !matches!(spec.proof_family, ProofFamilyV1::Whir) {
            return Err(BuiltinConfigError::DescriptorFamilyMismatch {
                suite: self.suite,
                expected: "WHIR",
            });
        }
        if self.folding_factor == 0 {
            return Err(BuiltinConfigError::InvalidParameter {
                component: "folding_factor",
                value: 0,
            });
        }
        if self.starting_log_inv_rate == 0 {
            return Err(BuiltinConfigError::InvalidParameter {
                component: "starting_log_inv_rate",
                value: 0,
            });
        }
        WhirSecurityAssumptionV1::from_u16(self.security_assumption_id)?;
        if self.security_level == 0 {
            return Err(BuiltinConfigError::InvalidParameter {
                component: "security_level",
                value: 0,
            });
        }
        let rates = match &self.round_log_inv_rates {
            WhirRateModeV1::Auto => &[][..],
            WhirRateModeV1::Explicit(rates) if rates.is_empty() => {
                return Err(BuiltinConfigError::InvalidParameter {
                    component: "round_log_inv_rates",
                    value: 0,
                });
            }
            WhirRateModeV1::Explicit(rates) => rates.as_slice(),
        };
        check_limit("WHIR rounds", rates.len(), limits.max_rounds)?;
        for &rate in rates {
            if rate == 0 {
                return Err(BuiltinConfigError::InvalidParameter {
                    component: "round_log_inv_rate",
                    value: 0,
                });
            }
            check_limit(
                "round log inverse rate",
                rate as usize,
                limits.max_log_domain_or_degree,
            )?;
        }
        for (component, value) in [
            ("starting log inverse rate", self.starting_log_inv_rate),
            ("folding factor", self.folding_factor),
            ("log max LDE height", self.log_max_lde_height),
        ] {
            check_limit(component, value as usize, limits.max_log_domain_or_degree)?;
        }
        check_cap(
            "WHIR cap roots",
            spec.merkle_arity,
            self.cap_height,
            limits.max_cap_roots,
        )?;
        check_limit(
            "security level",
            self.security_level as usize,
            limits.max_queries_per_round,
        )?;
        let field_order = match spec.field {
            FieldFamilyV1::BabyBear => BabyBear::ORDER_U64,
            FieldFamilyV1::KoalaBear => KoalaBear::ORDER_U64,
            FieldFamilyV1::Goldilocks => Goldilocks::ORDER_U64,
        };
        if 1u64
            .checked_shl(self.pow_bits)
            .is_none_or(|range| range >= field_order)
        {
            return Err(BuiltinConfigError::InvalidParameter {
                component: "pow_bits",
                value: self.pow_bits,
            });
        }

        let protocol = self.protocol_parameters()?;
        let valid = match spec.field {
            FieldFamilyV1::BabyBear => WhirUniVerifierParams::<BabyBear>::new(
                protocol,
                VariableOrder::Prefix,
                self.suite.mmcs_permutation(),
            )
            .map(|_| ()),
            FieldFamilyV1::KoalaBear => WhirUniVerifierParams::<KoalaBear>::new(
                protocol,
                VariableOrder::Prefix,
                self.suite.mmcs_permutation(),
            )
            .map(|_| ()),
            FieldFamilyV1::Goldilocks => return Err(BuiltinConfigError::InvalidWhirConfiguration),
        };
        valid.map_err(|_| BuiltinConfigError::InvalidWhirConfiguration)?;
        Ok(())
    }

    pub(crate) fn protocol_parameters(&self) -> Result<ProtocolParameters, BuiltinConfigError> {
        Ok(ProtocolParameters {
            starting_log_inv_rate: self.starting_log_inv_rate as usize,
            round_log_inv_rates: match &self.round_log_inv_rates {
                WhirRateModeV1::Auto => Vec::new(),
                WhirRateModeV1::Explicit(rates) => {
                    rates.iter().map(|&rate| rate as usize).collect()
                }
            },
            folding_factor: FoldingFactor::Constant(self.folding_factor as usize),
            soundness_type: WhirSecurityAssumptionV1::from_u16(self.security_assumption_id)?
                .native(),
            security_level: self.security_level as usize,
            pow_bits: self.pow_bits as usize,
        })
    }
}

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub enum BuiltinConfigError {
    #[error("unsupported V1 suite {0:#06x}")]
    UnsupportedSuite(u16),
    #[error("suite {suite:?} is not a {expected} suite")]
    DescriptorFamilyMismatch {
        suite: SuiteIdV1,
        expected: &'static str,
    },
    #[error("factory for {expected:?} cannot construct descriptor for {actual:?}")]
    WrongFactorySuite {
        expected: SuiteIdV1,
        actual: SuiteIdV1,
    },
    #[error("invalid built-in parameter {component}: {value}")]
    InvalidParameter { component: &'static str, value: u32 },
    #[error("unsupported WHIR security-assumption ID {0}")]
    UnsupportedSecurityAssumption(u16),
    #[error("{component} exceeds verifier limit: {actual} > {limit}")]
    LimitExceeded {
        component: &'static str,
        actual: usize,
        limit: usize,
    },
    #[error("integer arithmetic overflow while validating {component}")]
    ArithmeticOverflow { component: &'static str },
    #[error("invalid native FRI parameters: {0}")]
    NativeFri(FriInputError),
    #[error("invalid recursive FRI parameters: {0}")]
    RecursiveFri(FriVerifierParamsError),
    #[error("invalid WHIR protocol parameters")]
    InvalidWhirConfiguration,
}

const fn check_limit(
    component: &'static str,
    actual: usize,
    limit: usize,
) -> Result<(), BuiltinConfigError> {
    if actual > limit {
        Err(BuiltinConfigError::LimitExceeded {
            component,
            actual,
            limit,
        })
    } else {
        Ok(())
    }
}

fn check_cap(
    component: &'static str,
    arity: u8,
    height: u32,
    limit: usize,
) -> Result<(), BuiltinConfigError> {
    let roots = (0..height).try_fold(1usize, |roots, _| {
        roots
            .checked_mul(usize::from(arity))
            .ok_or(BuiltinConfigError::ArithmeticOverflow { component })
    })?;
    check_limit(component, roots, limit)
}
