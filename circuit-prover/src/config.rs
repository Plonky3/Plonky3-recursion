//! STARK config, generic over base field `F`, permutation `P`, and challenge degree `CD`.
//!
//! Generics glossary:
//! - `F`: Base field for values, FFTs and commitments (BabyBear/KoalaBear/Goldilocks).
//! - `P`: Cryptographic permutation over `F` used by hash/compress and the challenger.
//! - `CD`: Degree of the binomial extension used for the FRI challenge field.
//!
//! Notes:
//! - `CD` is independent from the circuit element-field degree `D` used by AIRs; the circuit can use
//!   element fields `EF = BinomialExtensionField<F, D>` while the FRI challenge field is `BinomialExtensionField<F, CD>`.
//!
//! Provides convenience builders for BabyBear, KoalaBear, and Goldilocks.

use p3_challenger::DuplexChallenger as Challenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel as Dft;
use p3_field::extension::{BinomialExtensionField, BinomiallyExtendable};
use p3_field::{Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_fri::{TwoAdicFriPcs as Pcs, create_benchmark_fri_params};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{
    CryptographicPermutation, PaddingFreeSponge as MyHash, PseudoCompressionFunction,
    TruncatedPermutation as MyCompress,
};
use p3_uni_stark::StarkConfig;

/// Simplified trait alias for STARK-compatible fields.
pub trait StarkField: Field + PrimeCharacteristicRing + TwoAdicField + PrimeField64 {}

/// Simplified trait alias for STARK-compatible permutations.
pub trait StarkPermutation<F: StarkField>:
    Clone + CryptographicPermutation<[F; 16]> + CryptographicPermutation<[<F as Field>::Packing; 16]>
{
}

// Blanket implementations
impl<F> StarkField for F where F: Field + PrimeCharacteristicRing + TwoAdicField + PrimeField64 {}
impl<F, P> StarkPermutation<F> for P
where
    F: StarkField,
    P: Clone
        + CryptographicPermutation<[F; 16]>
        + CryptographicPermutation<[<F as Field>::Packing; 16]>,
{
}

/// FRI challenge field: degree-`CD` binomial extension over base field `F`.
/// `CD` is independent of the circuit element extension degree used in AIRs; they may differ.
pub type Challenge<F, const CD: usize> = BinomialExtensionField<F, CD>;

/// Merkle tree MMCS over the base field `F` with permutation `P` (width 16).
pub type ValMmcs<F, P> = MerkleTreeMmcs<
    <F as Field>::Packing,
    <F as Field>::Packing,
    MyHash<P, 16, 8, 8>,
    MyCompress<P, 2, 8, 16>,
    8,
>;

/// MMCS wrapper for the challenge extension of degree `CD`.
pub type ChallengeMmcs<F, P, const CD: usize> = ExtensionMmcs<F, Challenge<F, CD>, ValMmcs<F, P>>;

/// The complete STARK configuration type.
///
/// - `F`: Base field for trace/PCS.
/// - `P`: Permutation over `F` used by hash/challenger.
/// - `CD`: Challenge field degree (binomial extension over `F`).
pub type ProverConfig<F, P, const CD: usize> = StarkConfig<
    Pcs<F, Dft<F>, ValMmcs<F, P>, ChallengeMmcs<F, P, CD>>,
    Challenge<F, CD>,
    Challenger<F, P, 16, 8>,
>;

/// Build a standard STARK configuration for any supported field and permutation.
/// `CD` here is the challenge extension degree, independent from the circuit element degree.
/// This creates a FRI-based STARK configuration with:
/// - Two-adic FRI PCS for polynomial commitments
/// - Merkle tree MMCS for vector commitments  
/// - Duplex challenger for Fiat-Shamir
pub fn build_standard_config_generic<F, P, const CD: usize>(perm: P) -> ProverConfig<F, P, CD>
where
    F: StarkField + BinomiallyExtendable<CD>,
    P: StarkPermutation<F>,
{
    let hash = MyHash::<P, 16, 8, 8>::new(perm.clone());
    let compress = MyCompress::<P, 2, 8, 16>::new(perm.clone());
    let val_mmcs = ValMmcs::<F, P>::new(hash, compress);
    let challenge_mmcs = ChallengeMmcs::<F, P, CD>::new(val_mmcs.clone());

    let dft = Dft::<F>::default();
    let fri_params = create_benchmark_fri_params::<ChallengeMmcs<F, P, CD>>(challenge_mmcs);
    let pcs = Pcs::<F, _, _, _>::new(dft, val_mmcs, fri_params);

    let challenger = Challenger::<F, P, 16, 8>::new(perm);

    StarkConfig::new(pcs, challenger)
}

/// Build a standard 2-to-1 compression function for any supported field and permutation.
pub fn standard_compression_function_generic<F, P>(perm: P) -> MyCompress<P, 2, 8, 16>
where
    F: StarkField,
    P: StarkPermutation<F> + Clone + 'static,
{
    MyCompress::new(perm)
}

// Field-specific configuration builders

pub mod babybear_config {
    use p3_baby_bear::{
        BabyBear as BB, Poseidon2BabyBear as Poseidon2BB, default_babybear_poseidon2_16,
    };

    use super::*;

    pub type BabyBearConfig = ProverConfig<BB, Poseidon2BB<16>, 4>;

    pub fn build_standard_config_babybear() -> BabyBearConfig {
        let perm = default_babybear_poseidon2_16();
        build_standard_config_generic::<BB, _, 4>(perm)
    }

    // TODO: For now we are not considering packed inputs for BabyBear
    pub fn baby_bear_standard_compression_function() -> impl PseudoCompressionFunction<[BB; 8], 2> {
        let perm = default_babybear_poseidon2_16();
        standard_compression_function_generic::<BB, _>(perm)
    }
}

pub mod koalabear_config {
    use p3_koala_bear::{
        KoalaBear as KB, Poseidon2KoalaBear as Poseidon2KB, default_koalabear_poseidon2_16,
    };

    use super::*;

    pub type KoalaBearConfig = ProverConfig<KB, Poseidon2KB<16>, 4>;

    pub fn build_standard_config_koalabear() -> KoalaBearConfig {
        let perm = default_koalabear_poseidon2_16();
        build_standard_config_generic::<KB, _, 4>(perm)
    }

    // TODO:For now we are not considering packed inputs for KoalaBear
    pub fn koala_bear_standard_compression_function() -> impl PseudoCompressionFunction<[KB; 8], 2>
    {
        let perm = default_koalabear_poseidon2_16();
        standard_compression_function_generic::<KB, _>(perm)
    }
}

pub mod goldilocks_config {
    use p3_goldilocks::{Goldilocks as GL, Poseidon2Goldilocks as Poseidon2GL};
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    use super::*;

    pub type GoldilocksConfig = ProverConfig<GL, Poseidon2GL<16>, 2>;

    pub fn build_standard_config_goldilocks() -> GoldilocksConfig {
        let mut rng = SmallRng::seed_from_u64(1);
        let perm = Poseidon2GL::<16>::new_from_rng_128(&mut rng);
        build_standard_config_generic::<GL, _, 2>(perm)
    }

    // TODO: For now we are considering packed inputs for Goldilocks
    pub fn goldilocks_standard_compression_function() -> impl PseudoCompressionFunction<[GL; 8], 2>
    {
        let mut rng = SmallRng::seed_from_u64(1);
        let perm = Poseidon2GL::<16>::new_from_rng_128(&mut rng);
        standard_compression_function_generic::<GL, _>(perm)
    }
}
