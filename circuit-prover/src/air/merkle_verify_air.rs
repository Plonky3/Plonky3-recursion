/// Definition of the AIR to verify Merkle tree authentication paths.
/// Re-exported from Plonky3.
pub use p3_merkle_tree_air::air::MerkleVerifyAir;

#[cfg(test)]
mod test {

    use alloc::vec;

    use p3_circuit::WitnessId;
    use p3_circuit::op::MerkleVerifyConfig;
    use p3_circuit::tables::{MerklePrivateData, MerkleTrace};
    use p3_merkle_tree_air::air::MerkleVerifyAir;

    use crate::config::babybear_config::{
        baby_bear_standard_compression_function, build_standard_config_babybear,
    };

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
        use p3_uni_stark::{prove, verify};
        use rand::rngs::SmallRng;
        use rand::{Rng, SeedableRng};

        type Val = BabyBear;

        const NUM_INPUTS: usize = 4;
        const HEIGHT: usize = 8;
        const DIGEST_ELEMS: usize = 8;

        // Generate random inputs.

        let mut rng = SmallRng::seed_from_u64(1);

        let compress = baby_bear_standard_compression_function();
        let merkle_config = MerkleVerifyConfig::babybear_default();

        let leafs = [[rng.random::<Val>(); DIGEST_ELEMS]; NUM_INPUTS];
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
            let directions: [bool; HEIGHT] = array::from_fn(|_| rng.random::<bool>());
            MerklePrivateData::new(
                &compress,
                &merkle_config,
                &leafs[i],
                &path_siblings,
                &directions,
            )
            .expect("The size of all digests is DIGEST_ELEMS")
        });

        let indices = [rng.random::<u32>(); NUM_INPUTS];

        let trace = MerkleTrace {
            merkle_paths: private_data
                .iter()
                .zip(indices)
                .map(|(data, index)| {
                    data.to_trace(&merkle_config, &[WitnessId(0); DIGEST_ELEMS], index)
                        .unwrap()
                })
                .collect(),
        };

        // Create the AIR.
        let merkle_table_config = merkle_config.into();
        let air = MerkleVerifyAir::<Val>::new(merkle_table_config);

        // Generate trace for Merkle tree table.
        let trace = MerkleVerifyAir::<Val>::trace_to_matrix(&merkle_table_config, &trace);

        let config = build_standard_config_babybear();

        let proof = prove(&config, &air, trace, &vec![]);

        // Verify the proof.
        verify(&config, &air, &proof, &vec![])
    }
}
