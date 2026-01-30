use alloc::vec::Vec;

use p3_circuit::op::{NonPrimitiveOpType, Poseidon2Config};
use p3_circuit::ops::hash::add_hash_slice;
use p3_circuit::ops::mmcs::{add_mmcs_verify, format_openings};
use p3_circuit::{CircuitBuilder, CircuitBuilderError, NonPrimitiveOpId};
use p3_field::{ExtensionField, Field, TwoAdicField};
use p3_matrix::Dimensions;

use crate::Target;

/// Recursive verison of `MerkleTreeMmcs::verify_batch`. Adds a circuit that verifies an opened batch of rows with respect to a given commitment.
///
/// - `circuit`: The circuit builder to which we add the verify_batch circuit
/// - `commit`: The merkle root of the tree.
/// - `dimensions`: A vector of the dimensions of the matrices committed to.
/// - `directions`: The little-endian binary decomposition of the index of a leaf in the tree.
/// - `opened_values`: A vector of matrix rows. Assume that the tallest matrix committed
///   to has height `2^n >= M_tall.height() > 2^{n - 1}` and the `j`th matrix has height
///   `2^m >= Mj.height() > 2^{m - 1}`. Then `j`'th value of opened values must be the row `Mj[index >> (m - n)]`.
/// - `proof`: A vector of sibling nodes. The `i`th element should be the node at level `i`
///   with index `(index << i) ^ 1`.
///
/// Returns the list of permutations operations requiring private data, otherwise returns an error.
pub fn verify_batch_circuit<F, EF>(
    circuit: &mut CircuitBuilder<EF>,
    permutation_config: Poseidon2Config,
    commitment: &[Target],
    dimensions: &[Dimensions],
    index_bits: &[Target],
    opened_values: &[Vec<Target>],
) -> Result<Vec<NonPrimitiveOpId>, CircuitBuilderError>
where
    F: Field + TwoAdicField,
    EF: ExtensionField<F>,
{
    // Check that the openings have the correct shape.
    if dimensions.len() != opened_values.len() {
        panic!("Wrong batch size"); // TODO: Add errors
    }

    // TODO: Disabled for now since TwoAdicFriPcs and CirclePcs currently pass 0 for width.
    // for (dims, opened_vals) in zip_eq(dimensions.iter(), opened_values) {
    //     if opened_vals.len() != dims.width {
    //         return Err(WrongWidth);
    //     }
    // }

    let formatted_op_vals = format_openings(
        opened_values,
        dimensions,
        index_bits.len(),
        permutation_config,
    )
    .map_err(
        |_| CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
            // TODO: I this the error we want?
            op: NonPrimitiveOpType::Poseidon2Perm(permutation_config),
        },
    )?;

    // Hash the opened values while keeping the format.
    let op_vals_digests = formatted_op_vals
        .into_iter()
        .map(|leaf| {
            if !leaf.is_empty() {
                add_hash_slice(circuit, &permutation_config, &leaf, true)
            } else {
                Ok(leaf)
            }
        })
        .collect::<Result<Vec<Vec<Target>>, _>>()?;

    add_mmcs_verify(
        circuit,
        permutation_config,
        &op_vals_digests,
        index_bits,
        commitment,
    )
}

#[cfg(test)]
mod test {
    use alloc::vec;
    use alloc::vec::Vec;
    use core::cmp::Reverse;

    use itertools::Itertools;
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear, default_babybear_poseidon2_16};
    use p3_circuit::op::Poseidon2Config;
    use p3_circuit::ops::mmcs::{add_mmcs_verify, format_openings};
    use p3_circuit::ops::{Poseidon2PermPrivateData, generate_poseidon2_trace};
    use p3_circuit::{CircuitBuilder, CircuitError, NonPrimitiveOpPrivateData};
    use p3_commit::Mmcs;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
    use p3_matrix::dense::{DenseMatrix, RowMajorMatrix};
    use p3_matrix::{Dimensions, Matrix};
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_poseidon2_circuit_air::BabyBearD4Width16;
    use p3_symmetric::{CryptographicHasher, PaddingFreeSponge, TruncatedPermutation};
    use p3_util::log2_ceil_usize;
    use rand::SeedableRng;
    use rand::rngs::SmallRng;
    use tracing_forest::ForestLayer;
    use tracing_forest::util::LevelFilter;
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;
    use tracing_subscriber::{EnvFilter, Registry};

    use crate::pcs::verify_batch_circuit;

    type F = BabyBear;
    type CF = BinomialExtensionField<F, 4>;

    type Perm = Poseidon2BabyBear<16>;
    type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
    type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    type MyMmcs =
        MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, MyHash, MyCompress, 8>;

    fn base_digest_to_ext(digest: &[F], permutation_config: Poseidon2Config) -> Vec<CF> {
        assert_eq!(
            digest.len(),
            permutation_config.rate(),
            "unexpected base digest length"
        );
        digest
            .chunks(<CF as BasedVectorSpace<F>>::DIMENSION)
            .map(|chunk| {
                let mut coeffs = [F::ZERO; 4];
                for (i, &val) in chunk.iter().enumerate() {
                    coeffs[i] = val;
                }
                CF::from_basis_coefficients_slice(&coeffs).expect("packed base digest")
            })
            .collect()
    }

    fn test_all_openings(mats: Vec<RowMajorMatrix<F>>) {
        let perm = default_babybear_poseidon2_16();
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm.clone());
        let mmcs = MyMmcs::new(hash, compress);

        let dimensions = mats.iter().map(DenseMatrix::dimensions).collect_vec();

        let mut heights_tallest_first = dimensions
            .iter()
            .enumerate()
            .sorted_by_key(|(_, dims)| Reverse(dims.height))
            .peekable();

        let max_height = heights_tallest_first.peek().unwrap().1.height;

        let (commit, prover_data) = mmcs.commit(mats);

        let path_depth = log2_ceil_usize(max_height);
        for index in 0..max_height {
            let mut builder = CircuitBuilder::<CF>::new();
            let permutation_config = Poseidon2Config::BabyBearD4Width16;
            builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
                generate_poseidon2_trace::<CF, BabyBearD4Width16>,
                perm.clone(),
            );

            let batch_opening = mmcs.open_batch(index, &prover_data);

            let directions = (0..path_depth).map(|k| index >> k & 1 == 1).collect_vec();

            let openings = batch_opening
                .opened_values
                .iter()
                .map(|opening| {
                    opening
                        .chunks(<CF as BasedVectorSpace<F>>::DIMENSION)
                        .map(|_| builder.add_public_input())
                        .collect_vec()
                })
                .collect_vec();

            let directions_expr = builder.alloc_public_inputs(path_depth, "directions");
            let root = builder.alloc_public_inputs(permutation_config.rate_ext(), "root");

            let permutation_mmcs_ops = verify_batch_circuit::<F, CF>(
                &mut builder,
                permutation_config,
                &root,
                &dimensions,
                &directions_expr,
                &openings,
            )
            .unwrap();

            let circuit = builder.build().unwrap();
            let mut runner = circuit.runner();

            let directions_expr_vals = directions
                .iter()
                .map(|&bit| CF::from_bool(bit))
                .collect_vec();

            let mut public_inputs = vec![];
            public_inputs.extend(
                batch_opening
                    .opened_values
                    .iter()
                    .flat_map(|openings| {
                        openings
                            .chunks(<CF as BasedVectorSpace<F>>::DIMENSION)
                            .map(|chunk| {
                                let mut coeffs = [F::ZERO; 4];
                                for (i, &val) in chunk.iter().enumerate() {
                                    coeffs[i] = val;
                                }
                                CF::from_basis_coefficients_slice(&coeffs).expect("packed opening")
                            })
                    })
                    .collect_vec(),
            );
            public_inputs.extend(directions_expr_vals.iter());
            let commit_base = commit.into_iter().collect_vec();
            let commit_ext = base_digest_to_ext(&commit_base, permutation_config);
            debug_assert_eq!(permutation_config.rate_ext(), commit_ext.len());
            public_inputs.extend(commit_ext);

            runner.set_public_inputs(&public_inputs).unwrap();

            let siblings = batch_opening
                .opening_proof
                .iter()
                .map(|digest| {
                    digest
                        .chunks(4)
                        .map(CF::from_basis_coefficients_slice)
                        .collect::<Option<Vec<_>>>()
                        .unwrap()
                })
                .collect_vec();

            for (&op_id, sibling) in permutation_mmcs_ops.iter().zip(siblings) {
                runner
                    .set_private_data(
                        op_id,
                        NonPrimitiveOpPrivateData::Poseidon2Perm(Poseidon2PermPrivateData {
                            sibling: sibling.try_into().unwrap(),
                        }),
                    )
                    .unwrap();
            }

            // Whe then we run the runner and the MMCS trace is generated, it will be checked that
            // the root computed by the MmcsVerify gate matches that given as input.
            let _ = runner.run().unwrap();
        }
    }

    fn init_logger() {
        let env_filter = EnvFilter::builder()
            .with_default_directive(LevelFilter::INFO.into())
            .from_env_lossy();

        Registry::default()
            .with(env_filter)
            .with(ForestLayer::default())
            .init();
    }

    #[test]
    fn commit_single_1x8() {
        init_logger();
        // v = [0, 1, 2, 3, 4, 5, 6, 7]
        let v = vec![
            F::from_u32(0),
            F::from_u32(1),
            F::from_u32(2),
            F::from_u32(3),
            F::from_u32(4),
            F::from_u32(5),
            F::from_u32(6),
            F::from_u32(7),
        ];

        test_all_openings(vec![RowMajorMatrix::new_col(v)]);
    }

    #[test]
    fn commit_single_2x2() {
        let mat = RowMajorMatrix::new(vec![F::ZERO, F::ONE, F::TWO, F::ONE], 2);
        test_all_openings(vec![mat]);
    }

    #[test]
    fn commit_single_2x3() {
        // mat = [
        //   0 1
        //   2 1
        //   2 2
        // ]
        let mat = RowMajorMatrix::new(vec![F::ZERO, F::ONE, F::TWO, F::ONE, F::TWO, F::TWO], 2);
        test_all_openings(vec![mat]);
    }

    #[test]
    fn commit_mixed() {
        // mat_1 = [
        //   0 1
        //   2 3
        //   4 5
        //   6 7
        //   8 9
        // ]
        let mat_1 = RowMajorMatrix::new(
            vec![
                F::from_usize(0),
                F::from_usize(1),
                F::from_usize(2),
                F::from_usize(3),
                F::from_usize(4),
                F::from_usize(5),
                F::from_usize(6),
                F::from_usize(7),
                F::from_usize(8),
                F::from_usize(9),
            ],
            2,
        );
        // mat_2 = [
        //   10 11 12
        //   13 14 15
        //   16 17 18
        // ]
        let mat_2 = RowMajorMatrix::new(
            vec![
                F::from_usize(10),
                F::from_usize(11),
                F::from_usize(12),
                F::from_usize(13),
                F::from_usize(14),
                F::from_usize(15),
                F::from_usize(16),
                F::from_usize(17),
                F::from_usize(18),
            ],
            3,
        );
        test_all_openings(vec![mat_1, mat_2]);
    }

    #[test]
    fn commit_either_order() {
        let mut rng = SmallRng::seed_from_u64(1);
        let input_1 = RowMajorMatrix::<F>::rand(&mut rng, 5, 8);
        let input_2 = RowMajorMatrix::<F>::rand(&mut rng, 3, 16);

        test_all_openings(vec![input_1.clone(), input_2.clone()]);
        test_all_openings(vec![input_2, input_1]);
    }

    #[test]
    fn verify_tampered_proof_fails() {
        let mut rng = SmallRng::seed_from_u64(1);
        let perm = Perm::new_from_rng_128(&mut rng);
        let hash = MyHash::new(perm.clone());
        let compress = MyCompress::new(perm);
        let mmcs = MyMmcs::new(hash.clone(), compress);

        // 4 8x1 matrixes, 4 8x2 matrixes
        let mut mats = (0..4)
            .map(|_| RowMajorMatrix::<F>::rand(&mut rng, 8, 1))
            .collect_vec();
        let large_mat_dims = (0..4).map(|_| Dimensions {
            height: 8,
            width: 1,
        });
        mats.extend((0..4).map(|_| RowMajorMatrix::<F>::rand(&mut rng, 8, 2)));
        let small_mat_dims = (0..4).map(|_| Dimensions {
            height: 8,
            width: 2,
        });
        let dimensions = &large_mat_dims.chain(small_mat_dims).collect_vec();

        let (commit, prover_data) = mmcs.commit(mats);

        let mut builder = CircuitBuilder::<CF>::new();
        let permutation_config = Poseidon2Config::BabyBearD4Width16;
        let perm = default_babybear_poseidon2_16();
        builder.enable_poseidon2_perm::<BabyBearD4Width16, _>(
            generate_poseidon2_trace::<CF, BabyBearD4Width16>,
            perm,
        );

        // open the 3rd row of each matrix, mess with proof, and verify
        let index = 3;
        let path_depth = 3;
        let mut batch_opening = mmcs.open_batch(index, &prover_data);
        batch_opening.opening_proof[0][0] += F::ONE;

        let openings_digests = batch_opening
            .opened_values
            .iter()
            .zip(dimensions)
            .chunk_by(|(_, dimensions)| dimensions.height)
            .into_iter()
            .map(|(_, group)| hash.hash_iter(group.flat_map(|(x, _)| x.clone())))
            .collect_vec();
        let dimensions = dimensions
            .iter()
            .chunk_by(|dimensions| dimensions.height)
            .into_iter()
            .map(|(height, _)| Dimensions { width: 0, height })
            .collect_vec();

        let openings = openings_digests
            .iter()
            .map(|mat_hash| {
                mat_hash
                    .iter()
                    .map(|_| builder.add_public_input())
                    .collect_vec()
            })
            .collect_vec();
        let openings =
            format_openings(&openings, &dimensions, path_depth, permutation_config).unwrap();
        let directions_expr = builder.alloc_public_inputs(path_depth, "directions");
        let root_exprs = builder.alloc_public_inputs(permutation_config.rate_ext(), "root");

        let permutation_mmcs_ops = add_mmcs_verify(
            &mut builder,
            permutation_config,
            &openings,
            &directions_expr,
            &root_exprs,
        )
        .unwrap();
        let circuit = builder.build().unwrap();
        let root_widx0 = circuit.expr_to_widx[&root_exprs[0]];
        let mut runner = circuit.runner();

        let directions = (0..path_depth)
            .map(|k| CF::from_bool(index >> k & 1 == 1))
            .collect_vec();

        let mut public_inputs = vec![];
        public_inputs.extend(
            openings_digests
                .iter()
                .flat_map(|digest| digest.map(CF::from)),
        );
        public_inputs.extend(directions.iter());
        let commit_base = commit.into_iter().collect_vec();
        let commit_ext = base_digest_to_ext(&commit_base, permutation_config);
        debug_assert_eq!(permutation_config.rate_ext(), commit_ext.len());
        public_inputs.extend(commit_ext);

        runner.set_public_inputs(&public_inputs).unwrap();

        let siblings = batch_opening
            .opening_proof
            .iter()
            .map(|digest| {
                digest
                    .chunks(4)
                    .map(CF::from_basis_coefficients_slice)
                    .collect::<Option<Vec<_>>>()
                    .unwrap()
            })
            .collect_vec();

        for (&op_id, sibling) in permutation_mmcs_ops.iter().zip(siblings) {
            let sibling: [CF; 2] = sibling.try_into().unwrap();
            runner
                .set_private_data(
                    op_id,
                    NonPrimitiveOpPrivateData::Poseidon2Perm(Poseidon2PermPrivateData { sibling }),
                )
                .unwrap();
        }

        // When the we run the runner and the MMCS trace is generated, it will be checked that
        // the root computed by the MmcsVerify gate does not match the one given as input.
        let result = runner.run();

        match result {
            Err(CircuitError::WitnessConflict { witness_id, .. }) => {
                assert_eq!(witness_id, root_widx0, "expected root witness mismatch");
            }
            _ => panic!("The test was suppose to fail with a root mismatch!"),
        }
    }
}
