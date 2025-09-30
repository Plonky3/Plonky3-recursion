/// Definition of the AIR to verify Merkle tree authentication paths.
/// Re-exported from Plonky3.
pub use p3_merkle_tree_air::air::MerkleVerifyAir;

#[cfg(test)]
mod test {

    use alloc::vec;

    use p3_circuit::WitnessId;
    use p3_circuit::tables::{MerklePrivateData, MerkleTrace};
    use p3_keccak::{Keccak256Hash, KeccakF};
    use p3_merkle_tree_air::air::MerkleVerifyAir;
    use p3_symmetric::{CompressionFunctionFromHasher, PaddingFreeSponge, SerializingHasher};

    use crate::config::babybear_config::build_standard_config_babybear;

    #[test]
    fn prove_mmcs_verify_poseidon() -> Result<
        (),
        p3_uni_stark::VerificationError<
            p3_fri::verifier::FriError<
                p3_merkle_tree::MerkleTreeError,
                p3_merkle_tree::MerkleTreeError,
            >,
        >,
    > {
        use core::array;

        use p3_baby_bear::BabyBear;
        use p3_challenger::{HashChallenger, SerializingChallenger32};
        use p3_commit::ExtensionMmcs;
        use p3_field::extension::BinomialExtensionField;
        use p3_fri::{TwoAdicFriPcs, create_benchmark_fri_params};
        use p3_merkle_tree::MerkleTreeMmcs;
        use p3_uni_stark::{StarkConfig, prove, verify};
        use rand::rngs::SmallRng;
        use rand::{Rng, SeedableRng};

        type Val = BabyBear;

        type FieldHash = SerializingHasher<U64Hash>;

        type ByteHash = Keccak256Hash;
        let byte_hash = ByteHash {};

        type U64Hash = PaddingFreeSponge<KeccakF, 25, 17, 4>;
        let u64_hash = U64Hash::new(KeccakF {});

        let field_hash = FieldHash::new(u64_hash);

        type MyCompress = CompressionFunctionFromHasher<U64Hash, 2, 4>;
        let compress = MyCompress::new(u64_hash);

        const NUM_INPUTS: usize = 4;
        const HEIGHT: usize = 8;
        const DIGEST_ELEMS: usize = 8;

        // Generate random inputs.

        let mut rng = SmallRng::seed_from_u64(1);
        let private_data: [MerklePrivateData<Val>; NUM_INPUTS] = array::from_fn(|i| {
            let path_siblings = if i % 2 == 0 {
                (0..HEIGHT)
                    .map(|j| {
                        if j == HEIGHT / 2 {
                            (
                                vec![rng.random::<Val>(); DIGEST_ELEMS],
                                Some(vec![rng.random::<Val>(); DIGEST_ELEMS]),
                            )
                        } else {
                            (vec![rng.random::<Val>(); DIGEST_ELEMS], None)
                        }
                    })
                    .collect()
            } else {
                vec![(vec![rng.random::<Val>(); DIGEST_ELEMS], None); HEIGHT]
            };
            MerklePrivateData { path_siblings }
        });

        let public_data = [[rng.random::<Val>(); DIGEST_ELEMS]; NUM_INPUTS];
        let indices = [rng.random::<u32>(); NUM_INPUTS];

        let (_, merkle_config) = build_standard_config_babybear();

        let trace = MerkleTrace {
            merkle_paths: private_data
                .iter()
                .zip(public_data)
                .zip(indices)
                .map(|((data, leaf), index)| {
                    data.to_trace(
                        &merkle_config,
                        vec![WitnessId(0); DIGEST_ELEMS],
                        &leaf,
                        index,
                    )
                    .unwrap()
                })
                .collect(),
        };

        // Create the AIR.
        let merkle_table_config = merkle_config.into();
        let air = MerkleVerifyAir::<Val>::new(merkle_table_config);

        // Generate trace for Merkle tree table.
        let trace = MerkleVerifyAir::<Val>::trace_to_matrix(&merkle_table_config, &trace);

        // Prove with Keccak.
        type Challenge = BinomialExtensionField<Val, 4>;

        type ValMmcs = MerkleTreeMmcs<
            [Val; p3_keccak::VECTOR_LEN],
            [u64; p3_keccak::VECTOR_LEN],
            FieldHash,
            MyCompress,
            4,
        >;

        let val_mmcs = ValMmcs::new(field_hash, compress);

        type ChallengeMmcs = ExtensionMmcs<Val, Challenge, ValMmcs>;
        let challenge_mmcs = ChallengeMmcs::new(val_mmcs.clone());

        type Challenger = SerializingChallenger32<Val, HashChallenger<u8, ByteHash, 32>>;
        let challenger = Challenger::from_hasher(vec![], byte_hash);

        let fri_params = create_benchmark_fri_params(challenge_mmcs);

        type Dft = p3_dft::Radix2Bowers;
        let dft = Dft::default();

        type Pcs = TwoAdicFriPcs<Val, Dft, ValMmcs, ChallengeMmcs>;
        let pcs = Pcs::new(dft, val_mmcs, fri_params);

        type MyConfig = StarkConfig<Pcs, Challenge, Challenger>;
        let config = MyConfig::new(pcs, challenger);

        let proof = prove(&config, &air, trace, &vec![]);

        // Verify the proof.
        verify(&config, &air, &proof, &vec![])
    }
}
