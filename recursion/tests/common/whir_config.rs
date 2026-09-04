//! A `StarkGenericConfig` whose polynomial commitment scheme is WHIR.

use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
use p3_challenger::DuplexChallenger;
use p3_dft::Radix2DFTSmallBatch;
use p3_field::Field;
use p3_field::extension::BinomialExtensionField;
use p3_merkle_tree::MerkleTreeMmcs;
use p3_recursion::pcs::whir::uni::WhirUniPcs;
use p3_sumcheck::layout::PrefixProver;
use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkGenericConfig;
use p3_whir::parameters::{FoldingFactor, ProtocolParameters, SecurityAssumption};
use rand::SeedableRng;
use rand::rngs::SmallRng;

/// The base field for BabyBear WHIR test configurations.
pub type BbF = BabyBear;
/// The extension field WHIR-backed proofs are challenged and opened over.
pub type BbEF = BinomialExtensionField<BabyBear, 4>;
/// The Poseidon2 permutation shared by the hasher, compressor and challenger.
pub type BbPerm = Poseidon2BabyBear<16>;
/// The leaf hasher for the Merkle commitment scheme WHIR test configurations use.
pub type BbHash = PaddingFreeSponge<BbPerm, 16, 8, 8>;
/// The two-to-one compressor for the Merkle commitment scheme WHIR test configurations use.
pub type BbCompress = TruncatedPermutation<BbPerm, 2, 8, 16>;
/// The base field's packed SIMD representation, as required by [`BbMmcs`].
pub type BbPacked = <BbF as Field>::Packing;
/// The Merkle commitment scheme WHIR test configurations use.
pub type BbMmcs = MerkleTreeMmcs<BbPacked, BbPacked, BbHash, BbCompress, 2, 8>;
/// The FFT engine WHIR test configurations use to encode committed codewords.
pub type BbDft = Radix2DFTSmallBatch<BbF>;
/// The Fiat-Shamir challenger WHIR test configurations use.
pub type BbChallenger = DuplexChallenger<BbF, BbPerm, 16, 8>;
/// The WHIR-backed univariate polynomial commitment scheme under test.
pub type BbWhirPcs = WhirUniPcs<BbEF, BbF, BbDft, BbMmcs, BbChallenger, PrefixProver<BbF, BbEF>>;

/// Number of base-field elements in one Merkle digest.
pub const BB_DIGEST_ELEMS: usize = 8;

/// Deterministic permutation shared by the hasher, compressor and challenger.
pub fn bb_whir_perm() -> BbPerm {
    let mut rng = SmallRng::seed_from_u64(1);
    BbPerm::new_from_rng_128(&mut rng)
}

/// Merkle scheme used by every WHIR commitment in the tests.
pub fn bb_whir_mmcs() -> BbMmcs {
    let perm = bb_whir_perm();
    BbMmcs::new(BbHash::new(perm.clone()), BbCompress::new(perm), 0)
}

/// WHIR protocol parameters; the length of `round_log_inv_rates` fixes the
/// number of intermediate WHIR rounds.
pub const fn bb_whir_protocol_params(round_log_inv_rates: Vec<usize>) -> ProtocolParameters {
    ProtocolParameters {
        security_level: 32,
        pow_bits: 0,
        round_log_inv_rates,
        folding_factor: FoldingFactor::Constant(4),
        soundness_type: SecurityAssumption::CapacityBound,
        starting_log_inv_rate: 1,
    }
}

/// STARK configuration backed by WHIR.
#[derive(Clone)]
pub struct BbWhirConfig {
    pcs: BbWhirPcs,
    challenger: BbChallenger,
}

/// Builds the configuration for the given WHIR round schedule.
pub fn bb_whir_config(round_log_inv_rates: Vec<usize>) -> BbWhirConfig {
    let perm = bb_whir_perm();
    let challenger = BbChallenger::new(perm);
    let pcs = WhirUniPcs::new(
        bb_whir_protocol_params(round_log_inv_rates),
        BbDft::default(),
        bb_whir_mmcs(),
        challenger.clone(),
        20,
    );
    BbWhirConfig { pcs, challenger }
}

impl StarkGenericConfig for BbWhirConfig {
    type Pcs = BbWhirPcs;
    type Challenge = BbEF;
    type Challenger = BbChallenger;

    fn pcs(&self) -> &Self::Pcs {
        &self.pcs
    }

    fn initialise_challenger(&self) -> Self::Challenger {
        self.challenger.clone()
    }
}
