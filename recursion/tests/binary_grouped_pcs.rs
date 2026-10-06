//! Full grouped-codeword openings retain the native symbol query relation.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryChallenger, BinaryField8, BinaryField128, TowerLevel};
use p3_binary_pcs::{BinaryPcs, BinaryPcsConfig, BinaryPcsParams, GroupedCodewordMmcs};
use p3_challenger::{CanObserve, CanSampleBits, FieldChallenger};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{ByteHash, bytes_to_limbs};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::PrunedMerklePaths;
use p3_multilinear_util::point::Point;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{BinaryCodewordGrouping, BinaryGroupedPcsVerifier};
use p3_sumcheck::layout::{Layout, SuffixProver, Table};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
use p3_test_utils::binary_field_params::{blake3, keccak};

#[derive(serde::Serialize, serde::Deserialize)]
struct GroupedBaseWire {
    inner: PrunedMerklePaths<u8, 32>,
    missing_symbols: Vec<BinaryField8>,
}

macro_rules! grouped {
    (with_group_size, $tree:expr, $config:expr, $group:expr) => {
        GroupedCodewordMmcs::with_group_size($tree, $config, $group)
    };
    (codeword, $tree:expr, $config:expr, $group:expr) => {
        GroupedCodewordMmcs::new($tree, $group)
    };
    (folding, $tree:expr, $config:expr, $group:expr) => {
        GroupedCodewordMmcs::for_folding($tree, $config)
    };
}

macro_rules! check {
    ($params:ident, $hash:expr, $grouping:expr, $native:ident, $group:expr, $cap:expr) => {{
        check!(
            $params, $hash, $grouping, $native, $group, $grouping, $native, $group, $cap
        )
    }};
    ($params:ident, $hash:expr, $base_grouping:expr, $base_native:ident, $base_group:expr, $round_grouping:expr, $round_native:ident, $round_group:expr, $cap:expr) => {{
        type F = BinaryField8;
        type E = BinaryField128;
        let config = BinaryPcsConfig::try_new::<F, E>(
            5,
            BinaryPcsParams {
                log_inv_rate: 2,
                pow_bits: 0,
                security_level: 16,
            },
        )
        .unwrap()
        .try_with_folding(2)
        .unwrap();
        let base = $params::LevelMmcs::<F>::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            $cap,
        );
        let round = $params::LevelMmcs::<E>::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            $cap,
        );
        let gb = grouped!($base_native, base.clone(), &config, $base_group);
        let gr = grouped!($round_native, round.clone(), &config, $round_group);
        let pcs = BinaryPcs::<F, E, _, _>::new(config, gb, gr).unwrap();
        let protocol = OpeningProtocol::new(vec![TableSpec::new(
            TableShape::new(5, 1),
            vec![OpeningBatch::new(vec![0], vec![0])],
        )]);
        let verifier = BinaryGroupedPcsVerifier::<F, E>::new(
            config,
            protocol.clone(),
            $hash,
            $cap,
            256,
            $base_grouping,
            $round_grouping,
        )
        .unwrap();
        let shape = verifier.input_shape();
        let mut b = CircuitBuilder::<BabyBear>::new();
        match $hash {
            ByteHash::Keccak256 => b.enable_keccak_f1600::<BabyBear>(),
            ByteHash::Blake3 => b.enable_blake3_compress::<BabyBear>(),
        }
        let cap = (0..1usize << $cap)
            .map(|_| b.alloc_private_input_array::<16>("cap").to_vec())
            .collect::<Vec<_>>();
        let targets = shape
            .allocate_targets::<BabyBear, BabyBear>(&mut b)
            .unwrap();
        let grouped_inputs = targets
            .oracles
            .iter()
            .map(|o| {
                o.leaves.iter().map(|row| row.len() * 8).sum::<usize>()
                    + o.paths.iter().map(|p| p.len() * 16).sum::<usize>()
            })
            .sum::<usize>();
        let grouped_start = b.private_input_count() - grouped_inputs;
        let first_path = grouped_start
            + targets.oracles[0]
                .leaves
                .iter()
                .map(|r| r.len() * 8)
                .sum::<usize>();
        let first_path_present = !targets.oracles[0].paths[0].is_empty();
        assert_eq!(
            verifier.input_resource_usage().scalar_elements,
            b.private_input_count() + 5 * 8
        );
        let initial = vec![b.define_const(BabyBear::from_u8(7)); 7];
        let mut ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
            &mut b, $hash, &initial,
        )
        .unwrap();
        verifier
            .observe_commitment::<BabyBear, BabyBear>(&mut b, &mut ch, &cap)
            .unwrap();
        let points = vec![
            (0..5)
                .map(|_| {
                    verifier
                        .sample_challenge::<BabyBear, BabyBear>(&mut b, &mut ch)
                        .unwrap()
                })
                .collect(),
        ];
        let continuation = verifier
            .verify_at_with_continuation::<BabyBear, BabyBear>(&mut b, ch, &cap, &points, &targets)
            .unwrap();
        let marker = b.define_const(BabyBear::from_u8(9));
        let mut tail = continuation
            .resume_with_observation::<BabyBear, BabyBear>(&mut b, &[marker])
            .unwrap();
        let sampled = tail.sample_bits::<BabyBear, BabyBear>(&mut b, 7).unwrap();
        let expected = b.alloc_private_input_array::<7>("tail bits");
        for (&bit, want) in sampled.iter().zip(expected) {
            let d = b.sub(bit, want);
            b.assert_zero(d);
        }
        let circuit = b.build().unwrap();
        let mut last = Vec::new();
        for seed in [7u8, 53] {
            let make = || BinaryChallenger::<F, _>::from_hasher(vec![7; 7], $params::byte_hash());
            let mut pc = make();
            let table = Table::new(RowMajorMatrix::new(
                (0..32).map(|i| F::from_repr(i ^ seed)).collect(),
                32,
            ));
            let (commitment, data) = pcs
                .commit(SuffixProver::<F, E>::new_witness(vec![table], 0), &mut pc)
                .unwrap();
            let points = vec![Point::new(
                (0..5).map(|_| pc.sample_algebra_element()).collect(),
            )];
            let proof = pcs.try_open_at(data, &protocol, &points, &mut pc).unwrap();
            let mut vc = make();
            pcs.observe_commitment(&commitment, &mut vc);
            let verify_points = vec![Point::new(
                (0..5).map(|_| vc.sample_algebra_element()).collect(),
            )];
            let mut imported_ch = vc.clone();
            let entry = vc.clone();
            pcs.verify_at(&commitment, &proof, &protocol, &verify_points, &mut vc)
                .unwrap();
            let imported = verifier
                .import_native(
                    &base,
                    &round,
                    &commitment,
                    &verify_points,
                    &proof,
                    &mut imported_ch,
                )
                .unwrap();
            for kind in 0..2 {
                let mut malformed = proof.clone();
                let mut wire: GroupedBaseWire =
                    postcard::from_bytes(&postcard::to_allocvec(&proof.base_multi_proof).unwrap())
                        .unwrap();
                if kind == 0 {
                    wire.inner
                        .sibling_hashes
                        .resize(proof.base_opened_values.len() * 7 + 1, [0; 32]);
                } else if wire.missing_symbols.pop().is_none() {
                    wire.missing_symbols.push(F::from_repr(1));
                }
                malformed.base_multi_proof =
                    postcard::from_bytes(&postcard::to_allocvec(&wire).unwrap()).unwrap();
                let mut retry = entry.clone();
                assert!(
                    verifier
                        .import_native(
                            &base,
                            &round,
                            &commitment,
                            &verify_points,
                            &malformed,
                            &mut retry
                        )
                        .is_err()
                );
                assert_eq!(retry.sample_bits(31), entry.clone().sample_bits(31));
            }
            vc.observe(F::from_repr(9));
            imported_ch.observe(F::from_repr(9));
            let native_tail = vc.sample_bits(7);
            assert_eq!(native_tail, imported_ch.sample_bits(7));
            let mut values = commitment
                .roots()
                .iter()
                .flat_map(|d| bytes_to_limbs(d).into_iter().map(BabyBear::from_u16))
                .collect::<Vec<_>>();
            values.extend(imported.private_values::<BabyBear>(&shape).unwrap());
            values.extend((0..7).map(|i| BabyBear::from_bool(native_tail >> i & 1 != 0)));
            let mut runner = circuit.runner();
            runner.set_private_inputs(&values).unwrap();
            runner.run().unwrap();
            let mut corrupt_offsets = vec![
                0,
                16 * (1usize << $cap),
                values.len() - 1,
                grouped_start,
                grouped_start + 8 * (targets.oracles[0].leaves[0].len() - 1),
            ];
            if first_path_present {
                corrupt_offsets.push(first_path);
            }
            for offset in corrupt_offsets {
                let mut bad = values.clone();
                bad[offset] += BabyBear::ONE;
                let mut runner = circuit.runner();
                runner.set_private_inputs(&bad).unwrap();
                assert!(runner.run().is_err());
            }
            // A shape with a different grouping policy cannot pack this witness.
            let foreign = BinaryGroupedPcsVerifier::<F, E>::new(
                config,
                protocol.clone(),
                $hash,
                $cap,
                256,
                BinaryCodewordGrouping::Codeword(2),
                BinaryCodewordGrouping::Codeword(2),
            )
            .unwrap();
            if foreign.input_shape() != shape {
                assert!(
                    imported
                        .private_values::<BabyBear>(&foreign.input_shape())
                        .is_err()
                );
            }
            last = values;
        }
        (circuit, last)
    }};
}

#[test]
fn grouped_pcs_native_openings_reuse_one_circuit_and_preserve_transcript() {
    check!(
        keccak,
        ByteHash::Keccak256,
        BinaryCodewordGrouping::Message(16),
        with_group_size,
        16,
        1
    );
    check!(
        blake3,
        ByteHash::Blake3,
        BinaryCodewordGrouping::Message(2),
        with_group_size,
        2,
        1
    );
}

#[test]
fn grouped_pcs_opening_proves_in_a_prime_field() {
    use p3_circuit_prover::ConstraintProfile;
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, Blake3CompressAirBuilder, Blake3CompressPreprocessor,
        Blake3CompressProver,
    };
    let (circuit, values) = check!(
        blake3,
        ByteHash::Blake3,
        BinaryCodewordGrouping::Message(4),
        with_group_size,
        4,
        1
    );
    let mut prover = BatchStarkProver::new(crate::proof_config());
    prover.register_table_prover(Box::new(Blake3CompressProver::<1>));
    let prepared = prover
        .prepare_circuit::<BabyBear, 1>(
            &circuit,
            &[Box::new(Blake3CompressPreprocessor)],
            &[Box::new(Blake3CompressAirBuilder::<1>)],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let mut runner = circuit.runner();
    runner.set_private_inputs(&values).unwrap();
    let proof = prepared.prove(&runner.run().unwrap()).unwrap();
    prepared.verifier().verify(&proof, &[]).unwrap();
}

#[test]
fn grouped_pcs_codeword_cap_and_fold_policy_cover_zero_depth_and_short_last_batch() {
    check!(
        blake3,
        ByteHash::Blake3,
        BinaryCodewordGrouping::Codeword(128),
        codeword,
        128,
        0
    );
    check!(
        keccak,
        ByteHash::Keccak256,
        BinaryCodewordGrouping::Folding,
        folding,
        4,
        1
    );
    check!(
        blake3,
        ByteHash::Blake3,
        BinaryCodewordGrouping::Codeword(16),
        codeword,
        16,
        BinaryCodewordGrouping::Folding,
        folding,
        4,
        0
    );
}

#[test]
fn grouped_pcs_prices_complete_leaves_and_rejects_invalid_geometry() {
    use p3_recursion::verifier::{VerificationError, VerifierLimits};
    let config = BinaryPcsConfig::try_new::<BinaryField8, BinaryField128>(
        5,
        BinaryPcsParams {
            log_inv_rate: 2,
            pow_bits: 0,
            security_level: 16,
        },
    )
    .unwrap()
    .try_with_folding(2)
    .unwrap();
    let protocol = OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(5, 1),
        vec![OpeningBatch::new(vec![0], vec![0])],
    )]);
    let make = |base, rounds, cap, limits: &VerifierLimits| {
        BinaryGroupedPcsVerifier::<BinaryField8, BinaryField128>::with_limits(
            config,
            protocol.clone(),
            ByteHash::Blake3,
            cap,
            256,
            base,
            rounds,
            limits,
        )
    };
    for policy in [
        BinaryCodewordGrouping::Codeword(0),
        BinaryCodewordGrouping::Message(3),
    ] {
        assert!(
            make(
                policy,
                BinaryCodewordGrouping::Folding,
                0,
                &VerifierLimits::default()
            )
            .is_err()
        );
        assert!(
            make(
                BinaryCodewordGrouping::Folding,
                policy,
                0,
                &VerifierLimits::default()
            )
            .is_err()
        );
    }
    assert!(
        make(
            BinaryCodewordGrouping::Codeword(128),
            BinaryCodewordGrouping::Folding,
            1,
            &VerifierLimits::default()
        )
        .is_err()
    );
    let plan = make(
        BinaryCodewordGrouping::Codeword(128),
        BinaryCodewordGrouping::Codeword(128),
        0,
        &VerifierLimits::default(),
    )
    .unwrap();
    assert_eq!(
        plan.input_resource_usage()
            .restored_authentication_path_hashes,
        0
    );
    let limits = VerifierLimits {
        max_total_scalar_elements: plan.input_resource_usage().scalar_elements - 1,
        ..VerifierLimits::default()
    };
    assert!(matches!(
        make(
            BinaryCodewordGrouping::Codeword(128),
            BinaryCodewordGrouping::Codeword(128),
            0,
            &limits
        ),
        Err(VerificationError::ResourceLimitExceeded {
            component: "scalar elements",
            ..
        })
    ));
}
