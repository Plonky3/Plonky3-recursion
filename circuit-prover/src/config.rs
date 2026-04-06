//! STARK proving configurations.
//!
//! # Quick Start
//!
//! ```ignore
//! use p3_circuit_prover::config;
//!
//! let config = config::baby_bear();
//! let config = config::koala_bear();
//! let config = config::goldilocks();
//! ```

use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
use p3_challenger::DuplexChallenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_fri::{TwoAdicFriPcs, create_benchmark_fri_params_high_arity};
use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};
use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{CryptographicPermutation, PaddingFreeSponge, TruncatedPermutation};
use p3_uni_stark::StarkConfig;

/// Standard Poseidon2-based STARK configuration.
///
/// Hasher and compressor permutations are kept as separate type parameters so
/// that callers can opt into a dual setup (e.g. width-24 hasher with a
/// narrower width-16 compressor).
pub type Poseidon2StarkConfig<
    F,
    PermHash,
    PermCompress,
    const HASH_WIDTH: usize,
    const COMPRESS_WIDTH: usize,
    const RATE: usize,
    const OUT: usize,
    const D: usize,
> = StarkConfig<
    TwoAdicFriPcs<
        F,
        Radix2DitParallel<F>,
        MerkleTreeMmcs<
            F,
            F,
            PaddingFreeSponge<PermHash, HASH_WIDTH, RATE, OUT>,
            TruncatedPermutation<PermCompress, 2, OUT, COMPRESS_WIDTH>,
            2,
            OUT,
        >,
        ExtensionMmcs<
            F,
            BinomialExtensionField<F, D>,
            MerkleTreeMmcs<
                F,
                F,
                PaddingFreeSponge<PermHash, HASH_WIDTH, RATE, OUT>,
                TruncatedPermutation<PermCompress, 2, OUT, COMPRESS_WIDTH>,
                2,
                OUT,
            >,
        >,
    >,
    BinomialExtensionField<F, D>,
    DuplexChallenger<F, PermHash, HASH_WIDTH, RATE>,
>;

/// Build a [`Poseidon2StarkConfig`] from separate hasher and compressor permutations.
///
/// ```ignore
/// let perm = default_babybear_poseidon2_16();
/// let config = build_poseidon2_stark_config(perm.clone(), perm);
/// ```
pub fn build_poseidon2_stark_config<
    F: Field,
    PermHash: Clone + CryptographicPermutation<[F; HASH_WIDTH]>,
    PermCompress: Clone + CryptographicPermutation<[F; COMPRESS_WIDTH]>,
    const HASH_WIDTH: usize,
    const COMPRESS_WIDTH: usize,
    const RATE: usize,
    const OUT: usize,
    const D: usize,
>(
    perm_hash: PermHash,
    perm_compress: PermCompress,
) -> Poseidon2StarkConfig<F, PermHash, PermCompress, HASH_WIDTH, COMPRESS_WIDTH, RATE, OUT, D> {
    let hash = PaddingFreeSponge::new(perm_hash.clone());
    let compress = TruncatedPermutation::new(perm_compress);
    let val_mmcs = MerkleTreeMmcs::new(hash, compress, 3);
    let challenge_mmcs = ExtensionMmcs::new(val_mmcs.clone());
    let dft = Radix2DitParallel::default();
    let fri_params = create_benchmark_fri_params_high_arity(challenge_mmcs);
    let pcs = TwoAdicFriPcs::new(dft, val_mmcs, fri_params);
    let challenger = DuplexChallenger::new(perm_hash);
    StarkConfig::new(pcs, challenger)
}

pub type BabyBearConfig =
    Poseidon2StarkConfig<BabyBear, Poseidon2BabyBear<16>, Poseidon2BabyBear<16>, 16, 16, 8, 8, 4>;
pub type KoalaBearConfig = Poseidon2StarkConfig<
    KoalaBear,
    Poseidon2KoalaBear<16>,
    Poseidon2KoalaBear<16>,
    16,
    16,
    8,
    8,
    4,
>;
pub type GoldilocksConfig =
    Poseidon2StarkConfig<Goldilocks, Poseidon2Goldilocks<8>, Poseidon2Goldilocks<8>, 8, 8, 4, 4, 2>;

/// Standard BabyBear STARK config (D=4, width=16).
pub fn baby_bear() -> BabyBearConfig {
    let perm = default_babybear_poseidon2_16();
    build_poseidon2_stark_config(perm.clone(), perm)
}

/// Standard KoalaBear STARK config (D=4, width=16).
pub fn koala_bear() -> KoalaBearConfig {
    let perm = default_koalabear_poseidon2_16();
    build_poseidon2_stark_config(perm.clone(), perm)
}

/// Standard Goldilocks STARK config (D=2, width=8).
pub fn goldilocks() -> GoldilocksConfig {
    let perm = default_goldilocks_poseidon2_8();
    build_poseidon2_stark_config(perm.clone(), perm)
}

fn default_goldilocks_poseidon2_8() -> Poseidon2Goldilocks<8> {
    let mut rng = <rand::rngs::SmallRng as rand::SeedableRng>::seed_from_u64(1);
    Poseidon2Goldilocks::<8>::new_from_rng_128(&mut rng)
}

/// Trait bounds for STARK-compatible fields.
pub trait StarkField: Field + PrimeCharacteristicRing + TwoAdicField + PrimeField64 {}

impl<F> StarkField for F where F: Field + PrimeCharacteristicRing + TwoAdicField + PrimeField64 {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_fields_configs_compile() {
        let _bb: BabyBearConfig = baby_bear();
        let _kb: KoalaBearConfig = koala_bear();
        let _gl: GoldilocksConfig = goldilocks();
    }
}
