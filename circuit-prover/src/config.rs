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
/// All Poseidon2 setups use the same permutation for hashing and compression,
/// so the only free parameters are the field `F`, the permutation `Perm`,
/// the sponge dimensions (`WIDTH`, `RATE`, `OUT`), and the challenge degree `D`.
pub type Poseidon2StarkConfig<
    F,
    Perm,
    const WIDTH: usize,
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
            PaddingFreeSponge<Perm, WIDTH, RATE, OUT>,
            TruncatedPermutation<Perm, 2, OUT, WIDTH>,
            2,
            OUT,
        >,
        ExtensionMmcs<
            F,
            BinomialExtensionField<F, D>,
            MerkleTreeMmcs<
                F,
                F,
                PaddingFreeSponge<Perm, WIDTH, RATE, OUT>,
                TruncatedPermutation<Perm, 2, OUT, WIDTH>,
                2,
                OUT,
            >,
        >,
    >,
    BinomialExtensionField<F, D>,
    DuplexChallenger<F, Perm, WIDTH, RATE>,
>;

/// Build a [`Poseidon2StarkConfig`] from a permutation instance.
///
/// This is the only way to construct a config — no separate builder type needed.
///
/// ```ignore
/// let config = build_poseidon2_stark_config(default_babybear_poseidon2_16());
/// ```
pub fn build_poseidon2_stark_config<
    F: Field,
    Perm: Clone + CryptographicPermutation<[F; WIDTH]>,
    const WIDTH: usize,
    const RATE: usize,
    const OUT: usize,
    const D: usize,
>(
    perm: Perm,
) -> Poseidon2StarkConfig<F, Perm, WIDTH, RATE, OUT, D> {
    let hash = PaddingFreeSponge::new(perm.clone());
    let compress = TruncatedPermutation::new(perm.clone());
    let val_mmcs = MerkleTreeMmcs::new(hash, compress, 3);
    let challenge_mmcs = ExtensionMmcs::new(val_mmcs.clone());
    let dft = Radix2DitParallel::default();
    let fri_params = create_benchmark_fri_params_high_arity(challenge_mmcs);
    let pcs = TwoAdicFriPcs::new(dft, val_mmcs, fri_params);
    let challenger = DuplexChallenger::new(perm);
    StarkConfig::new(pcs, challenger)
}

pub type BabyBearConfig = Poseidon2StarkConfig<BabyBear, Poseidon2BabyBear<16>, 16, 8, 8, 4>;
pub type KoalaBearConfig = Poseidon2StarkConfig<KoalaBear, Poseidon2KoalaBear<16>, 16, 8, 8, 4>;
pub type GoldilocksConfig = Poseidon2StarkConfig<Goldilocks, Poseidon2Goldilocks<8>, 8, 4, 4, 2>;

/// Standard BabyBear STARK config (D=4, width=16).
pub fn baby_bear() -> BabyBearConfig {
    build_poseidon2_stark_config(default_babybear_poseidon2_16())
}

/// Standard KoalaBear STARK config (D=4, width=16).
pub fn koala_bear() -> KoalaBearConfig {
    build_poseidon2_stark_config(default_koalabear_poseidon2_16())
}

/// Standard Goldilocks STARK config (D=2, width=8).
pub fn goldilocks() -> GoldilocksConfig {
    build_poseidon2_stark_config(default_goldilocks_poseidon2_8())
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
