// Match the standard BabyBear/D4 hashing, expansion, folding and caps.
// Functional roundtrips use two FRI queries without grinding.
pub(crate) fn proof_config() -> p3_circuit_prover::config::BabyBearConfig {
    use p3_baby_bear::{BabyBear, default_babybear_poseidon2_16};
    use p3_challenger::DuplexChallenger;
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_fri::{FriParameters, TwoAdicFriPcs};
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use p3_uni_stark::StarkConfig;

    let permutation = default_babybear_poseidon2_16();
    let hash = PaddingFreeSponge::<_, 16, 8, 8>::new(permutation.clone());
    let compress = TruncatedPermutation::<_, 2, 8, 16>::new(permutation.clone());
    let val_mmcs = MerkleTreeMmcs::<BabyBear, BabyBear, _, _, 2, 8>::new(hash, compress, 3);
    let mut fri_params =
        FriParameters::new_benchmark_high_arity(ExtensionMmcs::new(val_mmcs.clone()));
    fri_params.num_queries = 2;
    fri_params.batch_proof_of_work_bits = 0;
    fri_params.query_proof_of_work_bits = 0;
    let pcs = TwoAdicFriPcs::new(Radix2DitParallel::default(), val_mmcs, fri_params);
    StarkConfig::new(pcs, DuplexChallenger::new(permutation))
}
