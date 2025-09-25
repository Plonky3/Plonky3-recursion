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

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_challenger::DuplexChallenger as Challenger;
use p3_circuit::op::MerkleVerifyConfig;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel as Dft;
use p3_field::extension::{BinomialExtensionField, BinomiallyExtendable};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField64, TwoAdicField};
use p3_fri::{TwoAdicFriPcs as Pcs, create_test_fri_params};
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
pub fn build_standard_config_generic<EF, F, P, const CD: usize>(
    perm: P,
) -> (ProverConfig<F, P, CD>, MerkleVerifyConfig<EF>)
where
    F: StarkField + BinomiallyExtendable<CD>,
    P: StarkPermutation<F> + Clone + 'static,
    EF: BasedVectorSpace<F>,
{
    let hash = MyHash::<P, 16, 8, 8>::new(perm.clone());
    let compress = MyCompress::<P, 2, 8, 16>::new(perm.clone());
    let val_mmcs = ValMmcs::<F, P>::new(hash, compress.clone());
    let challenge_mmcs = ChallengeMmcs::<F, P, CD>::new(val_mmcs.clone());

    let dft = Dft::<F>::default();
    let fri_params = create_test_fri_params::<ChallengeMmcs<F, P, CD>>(challenge_mmcs, 0);
    let pcs = Pcs::<F, _, _, _>::new(dft, val_mmcs, fri_params);

    let challenger = Challenger::<F, P, 16, 8>::new(perm);

    let config = StarkConfig::new(pcs, challenger);

    let compress = move |[left, right]: [&[EF]; 2]| -> Vec<EF> {
        let left: [F; 8] = left
            .iter()
            .flat_map(|x| x.as_basis_coefficients_slice())
            .copied()
            .collect::<Vec<F>>()
            .try_into()
            .expect("Incorrect size of the compression function input");
        let right: [F; 8] = right
            .iter()
            .flat_map(|x| x.as_basis_coefficients_slice())
            .copied()
            .collect::<Vec<F>>()
            .try_into()
            .expect("Incorrect size of the compression function input");
        let output = compress.compress([left, right]);
        output
            .chunks(EF::DIMENSION)
            .map(|xs| {
                EF::from_basis_coefficients_slice(xs).expect("Chunks are of size EF::DIMENSION")
            })
            .collect::<Vec<EF>>()
    };
    let merkle_config = MerkleVerifyConfig {
        base_field_digest_elems: 8,
        ext_field_digest_elems: 8 / EF::DIMENSION,
        max_tree_height: 32,
        compress: Arc::new(compress),
    };
    (config, merkle_config)
}

// Field-specific configuration builders

pub mod babybear_config {
    use p3_baby_bear::{
        BabyBear as BB, Poseidon2BabyBear as Poseidon2BB, default_babybear_poseidon2_16,
    };
    use p3_field::BasedVectorSpace;

    use super::*;

    pub type BabyBearConfig<F> = (ProverConfig<BB, Poseidon2BB<16>, 4>, MerkleVerifyConfig<F>);

    pub fn build_standard_config_babybear<F>() -> BabyBearConfig<F>
    where
        F: BasedVectorSpace<BB>,
    {
        let perm = default_babybear_poseidon2_16();
        build_standard_config_generic::<F, BB, _, 4>(perm)
    }
}

pub mod koalabear_config {
    use p3_koala_bear::{
        KoalaBear as KB, Poseidon2KoalaBear as Poseidon2KB, default_koalabear_poseidon2_16,
    };

    use super::*;

    pub type KoalaBearConfig<F> = (ProverConfig<KB, Poseidon2KB<16>, 4>, MerkleVerifyConfig<F>);

    pub fn build_standard_config_koalabear<F>() -> KoalaBearConfig<F>
    where
        F: BasedVectorSpace<KB>,
    {
        let perm = default_koalabear_poseidon2_16();
        build_standard_config_generic::<F, KB, _, 4>(perm)
    }
}

pub mod goldilocks_config {
    use p3_goldilocks::{Goldilocks as GL, Poseidon2Goldilocks as Poseidon2GL};
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    use super::*;

    pub type GoldilocksConfig<F> = (ProverConfig<GL, Poseidon2GL<16>, 2>, MerkleVerifyConfig<F>);

    pub fn build_standard_config_goldilocks<F>() -> GoldilocksConfig<F>
    where
        F: BasedVectorSpace<GL>,
    {
        let mut rng = SmallRng::seed_from_u64(1);
        let perm = Poseidon2GL::<16>::new_from_rng_128(&mut rng);
        build_standard_config_generic::<F, GL, _, 2>(perm)
    }
}
