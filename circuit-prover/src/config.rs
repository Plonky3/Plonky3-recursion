//! STARK config, generic over base field `F` and permutation `P`.
//! Provides convenience builders for BabyBear and KoalaBear.

use p3_challenger::DuplexChallenger as Challenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel as Dft;
use p3_field::extension::{BinomialExtensionField, BinomiallyExtendable};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_fri::{TwoAdicFriPcs as Pcs, create_test_fri_params};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{
    CryptographicPermutation, PaddingFreeSponge as MyHash, TruncatedPermutation as MyCompress,
};
use p3_uni_stark::StarkConfig;

/// Simplified trait alias for STARK-compatible fields.
pub trait StarkField:
    Field + PrimeCharacteristicRing + TwoAdicField + PrimeField64 + BinomiallyExtendable<4>
{
}

/// Simplified trait alias for STARK-compatible permutations.
pub trait StarkPermutation<F: StarkField>:
    Clone + CryptographicPermutation<[F; 16]> + CryptographicPermutation<[<F as Field>::Packing; 16]>
{
}

// Blanket implementations
impl<F> StarkField for F where
    F: Field + PrimeCharacteristicRing + TwoAdicField + PrimeField64 + BinomiallyExtendable<4>
{
}
impl<F, P> StarkPermutation<F> for P
where
    F: StarkField,
    P: Clone
        + CryptographicPermutation<[F; 16]>
        + CryptographicPermutation<[<F as Field>::Packing; 16]>,
{
}

/// FRI challenge field: D4 binomial extension over base field `F`.
pub type Challenge<F> = BinomialExtensionField<F, 4>;

/// Merkle tree MMCS over the base field `F` with permutation `P` (width 16).
pub type ValMmcs<F, P> = MerkleTreeMmcs<
    <F as Field>::Packing,
    <F as Field>::Packing,
    MyHash<P, 16, 8, 8>,
    MyCompress<P, 2, 8, 16>,
    8,
>;

/// MMCS wrapper for the challenge extension.
pub type ChallengeMmcs<F, P> = ExtensionMmcs<F, Challenge<F>, ValMmcs<F, P>>;

/// The complete STARK configuration type.
pub type ProverConfig<F, P> = StarkConfig<
    Pcs<F, Dft<F>, ValMmcs<F, P>, ChallengeMmcs<F, P>>,
    Challenge<F>,
    Challenger<F, P, 16, 8>,
>;

/// Build a standard STARK configuration for any supported field and permutation.
///
/// This creates a FRI-based STARK configuration with:
/// - Two-adic FRI PCS for polynomial commitments
/// - Merkle tree MMCS for vector commitments  
/// - Duplex challenger for Fiat-Shamir
pub fn build_standard_config_generic<F: StarkField, P: StarkPermutation<F>>(
    perm: P,
) -> ProverConfig<F, P> {
    let hash = MyHash::<P, 16, 8, 8>::new(perm.clone());
    let compress = MyCompress::<P, 2, 8, 16>::new(perm.clone());
    let val_mmcs = ValMmcs::<F, P>::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::<F, P>::new(val_mmcs.clone());

    let dft = Dft::<F>::default();
    let fri_params = create_test_fri_params::<ChallengeMmcs<F, P>>(challenge_mmcs, 0);
    let pcs = Pcs::<F, _, _, _>::new(dft, val_mmcs, fri_params);

    let challenger = Challenger::<F, P, 16, 8>::new(perm);

    StarkConfig::new(pcs, challenger)
}

// Field-specific configuration builders

pub mod babybear_config {
    use p3_baby_bear::{BabyBear as BB, Poseidon2BabyBear as Poseidon2BB};
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    use super::*;

    pub type BabyBearConfig = ProverConfig<BB, Poseidon2BB<16>>;

    pub fn build_standard_config_babybear() -> BabyBearConfig {
        let mut rng = SmallRng::seed_from_u64(1);
        let perm = Poseidon2BB::<16>::new_from_rng_128(&mut rng);
        build_standard_config_generic::<BB, _>(perm)
    }
}

pub mod koalabear_config {
    use p3_koala_bear::{KoalaBear as KB, Poseidon2KoalaBear as Poseidon2KB};
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    use super::*;

    pub type KoalaBearConfig = ProverConfig<KB, Poseidon2KB<16>>;

    pub fn build_standard_config_koalabear() -> KoalaBearConfig {
        let mut rng = SmallRng::seed_from_u64(1);
        let perm = Poseidon2KB::<16>::new_from_rng_128(&mut rng);
        build_standard_config_generic::<KB, _>(perm)
    }
}
