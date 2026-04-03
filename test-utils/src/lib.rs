//! Test utilities for Plonky3 recursion crates.

#![no_std]

/// Maximum allowed constraint degree for AIR constraints.
pub const MAX_TEST_CONSTRAINT_DEGREE: usize = 3;

pub use p3_challenger::DuplexChallenger;
pub use p3_commit::ExtensionMmcs;
pub use p3_dft::Radix2DitParallel;
pub use p3_field::extension::BinomialExtensionField;
pub use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
pub use p3_fri::TwoAdicFriPcs;
pub use p3_lookup::LookupAir;
pub use p3_merkle_tree::MerkleTreeMmcs;
pub use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
pub use p3_uni_stark::StarkConfig;

/// Macro to generate a constraint degree test for an AIR.
///
/// Usage: `assert_air_constraint_degree!(air, "AirName");`
#[macro_export]
macro_rules! assert_air_constraint_degree {
    ($air:expr, $air_name:expr) => {{
        use p3_air::{AirLayout, BaseAir};
        use p3_batch_stark::symbolic::get_symbolic_constraints;
        use p3_lookup::LookupAir;
        use p3_lookup::logup::LogUpGadget;

        type F = p3_baby_bear::BabyBear;
        type EF = p3_field::extension::BinomialExtensionField<F, 4>;
        let mut air = $air;

        let preprocessed_width = air.preprocessed_trace().map(|m| m.width()).unwrap_or(0);
        let lookups = LookupAir::get_lookups(&mut air);
        let lookup_gadget = LogUpGadget::new();
        let layout = AirLayout {
            preprocessed_width,
            main_width: BaseAir::<F>::width(&air),
            num_public_values: BaseAir::<F>::num_public_values(&air),
            permutation_width: 0,
            num_permutation_challenges: 0,
            num_permutation_values: 0,
            num_periodic_columns: 0,
        };

        let (base_constraints, extension_constraints) =
            get_symbolic_constraints::<F, EF, _, _>(&air, layout, &lookups, &lookup_gadget);

        for (i, constraint) in base_constraints.iter().enumerate() {
            let degree = constraint.degree_multiple();
            assert!(
                degree <= $crate::MAX_TEST_CONSTRAINT_DEGREE,
                "{} base constraint {} has degree {} which exceeds maximum of {}",
                $air_name,
                i,
                degree,
                $crate::MAX_TEST_CONSTRAINT_DEGREE
            );
        }

        for (i, constraint) in extension_constraints.iter().enumerate() {
            let degree = constraint.degree_multiple();
            assert!(
                degree <= $crate::MAX_TEST_CONSTRAINT_DEGREE,
                "{} extension constraint {} has degree {} which exceeds maximum of {}",
                $air_name,
                i,
                degree,
                $crate::MAX_TEST_CONSTRAINT_DEGREE
            );
        }
    }};
}

/// Common parameters for the BabyBear field.
pub mod baby_bear_params {
    pub use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};

    pub use super::*;

    pub type F = BabyBear;
    pub const D: usize = 4;
    pub const WIDTH: usize = 16;
    pub const RATE: usize = 8;
    pub const DIGEST_ELEMS: usize = 8;
    pub type Challenge = BinomialExtensionField<F, D>;
    pub type Dft = Radix2DitParallel<F>;
    pub type Perm = Poseidon2BabyBear<WIDTH>;
    pub type MyHash = PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST_ELEMS>;
    pub type MyCompress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, WIDTH>;
    pub type MyMmcs = MerkleTreeMmcs<
        <F as Field>::Packing,
        <F as Field>::Packing,
        MyHash,
        MyCompress,
        2,
        DIGEST_ELEMS,
    >;
    pub type ChallengeMmcs = ExtensionMmcs<F, Challenge, MyMmcs>;
    pub type Challenger = DuplexChallenger<F, Perm, WIDTH, RATE>;
    pub type MyPcs = TwoAdicFriPcs<F, Dft, MyMmcs, ChallengeMmcs>;
    pub type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;
}

/// Common parameters for the KoalaBear field.
pub mod koala_bear_params {
    pub use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16};

    pub use super::*;

    pub type F = KoalaBear;
    pub const D: usize = 4;
    pub const WIDTH: usize = 16;
    pub const RATE: usize = 8;
    pub const DIGEST_ELEMS: usize = 8;

    pub type Challenge = BinomialExtensionField<F, D>;
    pub type Dft = Radix2DitParallel<F>;
    pub type Perm = Poseidon2KoalaBear<WIDTH>;
    pub type MyHash = PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST_ELEMS>;
    pub type MyCompress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, WIDTH>;
    pub type MyMmcs = MerkleTreeMmcs<
        <F as Field>::Packing,
        <F as Field>::Packing,
        MyHash,
        MyCompress,
        2,
        DIGEST_ELEMS,
    >;
    pub type ChallengeMmcs = ExtensionMmcs<F, Challenge, MyMmcs>;
    pub type Challenger = DuplexChallenger<F, Perm, WIDTH, RATE>;
    pub type MyPcs = TwoAdicFriPcs<F, Dft, MyMmcs, ChallengeMmcs>;
    pub type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;
}

/// KoalaBear with quintic trinomial challenge field (`D = 5`).
pub mod koala_bear_quintic_params {
    pub use p3_field::extension::QuinticTrinomialExtensionField;
    pub use p3_koala_bear::{KoalaBear, Poseidon2KoalaBear, default_koalabear_poseidon2_16};

    pub use super::*;

    pub type F = KoalaBear;
    pub const D: usize = 5;
    pub const WIDTH: usize = 16;
    pub const RATE: usize = 8;
    pub const DIGEST_ELEMS: usize = 8;

    pub type Challenge = QuinticTrinomialExtensionField<F>;
    pub type Dft = Radix2DitParallel<F>;
    pub type Perm = Poseidon2KoalaBear<WIDTH>;
    pub type MyHash = PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST_ELEMS>;
    pub type MyCompress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, WIDTH>;
    pub type MyMmcs = MerkleTreeMmcs<
        <F as Field>::Packing,
        <F as Field>::Packing,
        MyHash,
        MyCompress,
        2,
        DIGEST_ELEMS,
    >;
    pub type ChallengeMmcs = ExtensionMmcs<F, Challenge, MyMmcs>;
    pub type Challenger = DuplexChallenger<F, Perm, WIDTH, RATE>;
    pub type MyPcs = TwoAdicFriPcs<F, Dft, MyMmcs, ChallengeMmcs>;
    pub type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;
}

/// Common parameters for the Goldilocks field.
pub mod goldilocks_params {
    pub use p3_goldilocks::{Goldilocks, Poseidon2Goldilocks};

    pub use super::*;

    pub type F = Goldilocks;
    pub const D: usize = 2;
    pub const WIDTH: usize = 8;
    pub const RATE: usize = 4;
    pub const DIGEST_ELEMS: usize = 4;

    pub type Challenge = BinomialExtensionField<F, D>;
    pub type Dft = Radix2DitParallel<F>;
    pub type Perm = Poseidon2Goldilocks<WIDTH>;
    pub type MyHash = PaddingFreeSponge<Perm, WIDTH, RATE, DIGEST_ELEMS>;
    pub type MyCompress = TruncatedPermutation<Perm, 2, DIGEST_ELEMS, WIDTH>;
    pub type MyMmcs = MerkleTreeMmcs<
        <F as Field>::Packing,
        <F as Field>::Packing,
        MyHash,
        MyCompress,
        2,
        DIGEST_ELEMS,
    >;
    pub type ChallengeMmcs = ExtensionMmcs<F, Challenge, MyMmcs>;
    pub type Challenger = DuplexChallenger<F, Perm, WIDTH, RATE>;
    pub type MyPcs = TwoAdicFriPcs<F, Dft, MyMmcs, ChallengeMmcs>;
    pub type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;
}
