#![allow(clippy::type_complexity)]

use p3_baby_bear::{BabyBear as Val, Poseidon2BabyBear as Perm};
use p3_challenger::DuplexChallenger as Challenger;
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel as Dft;
use p3_field::extension::BinomialExtensionField;
use p3_fri::{TwoAdicFriPcs as Pcs, create_test_fri_params};
use p3_merkle_tree::MerkleTreeMmcs;
use p3_symmetric::{PaddingFreeSponge as MyHash, TruncatedPermutation as MyCompress};
use p3_uni_stark::StarkConfig;

pub type Challenge = BinomialExtensionField<Val, 4>;
pub type ValMmcs = MerkleTreeMmcs<
    <Val as p3_field::Field>::Packing,
    <Val as p3_field::Field>::Packing,
    MyHash<Perm<16>, 16, 8, 8>,
    MyCompress<Perm<16>, 2, 8, 16>,
    8,
>;
pub type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;

/// Build a test STARK config following the standard pattern from Plonky3 examples
pub fn build_test_config() -> StarkConfig<
    Pcs<Val, Dft<Val>, ValMmcs, ChallengeMmcs>,
    Challenge,
    Challenger<Val, Perm<16>, 16, 8>,
> {
    use rand::SeedableRng;
    use rand::rngs::SmallRng;

    let mut rng = SmallRng::seed_from_u64(1);
    let perm = Perm::<16>::new_from_rng_128(&mut rng);
    let hash = MyHash::<Perm<16>, 16, 8, 8>::new(perm.clone());
    let compress = MyCompress::<Perm<16>, 2, 8, 16>::new(perm.clone());
    let val_mmcs = ValMmcs::new(hash, compress, 0);
    let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());
    let dft = Dft::<Val>::default();
    let fri_params = create_test_fri_params::<ChallengeMmcs>(challenge_mmcs, 0);
    let pcs = Pcs::new(dft, val_mmcs, fri_params);
    let challenger = Challenger::<Val, Perm<16>, 16, 8>::new(perm);

    StarkConfig::new(pcs, challenger)
}
