//! Boolean bit readings are closed against complete grouped-codeword leaves.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField64, BinaryField128, PackedGf2x64, TowerLevel};
use p3_binary_pcs::{
    BinaryPcsConfig, BinaryPcsParams, BitOpening, BooleanMultilinearPcs, BooleanPcs,
    GroupedCodewordMmcs,
};
use p3_challenger::FieldChallenger;
use p3_circuit::ops::{ByteHash, bytes_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::point::Point;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{
    BinaryCodewordGrouping, BinaryGroupedBooleanPcsVerifier, BinaryRingClaimSpec,
    RecursiveBinaryTowerField,
};
use p3_test_utils::binary_field_params::{blake3, keccak};

fn run(circuit: &Circuit<BabyBear>, values: &[BabyBear]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(values).unwrap();
    runner.run().is_ok()
}

#[derive(serde::Serialize, serde::Deserialize)]
struct GroupedView<E> {
    inner: p3_merkle_tree::PrunedMerklePaths<u8, 32>,
    missing_symbols: Vec<E>,
}

macro_rules! fixture {
    ($native:ty, $params:ident, $hash:expr, $specs:expr, $prefix:expr, $seed:expr) => {{
        type E = $native;
        let absorbed = E::RAW_BITS.ilog2() as usize;
        let n = absorbed + 3;
        let prefix: usize = $prefix;
        let config = BinaryPcsConfig::try_new::<E, E>(
            3,
            BinaryPcsParams {
                log_inv_rate: 3,
                pow_bits: 0,
                security_level: 8,
            },
        )
        .unwrap();
        let tree = $params::LevelMmcs::<E>::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            0,
        );
        let mmcs = GroupedCodewordMmcs::new(tree.clone(), 8);
        let pcs = BooleanPcs::<E, _, _>::new(config, mmcs.clone(), mmcs.clone(), n).unwrap();
        let verifier = BinaryGroupedBooleanPcsVerifier::<E>::new(
            config,
            $specs.to_vec(),
            $hash,
            0,
            64,
            BinaryCodewordGrouping::Codeword(8),
            BinaryCodewordGrouping::Codeword(8),
        )
        .unwrap();
        let make = || $params::LevelChallenger::<E>::from_hasher(vec![9; 3], $params::byte_hash());
        let bits = (0..1usize << (n - 6))
            .map(|i| PackedGf2x64::new(0xb273ca07846def19u64.wrapping_mul(i as u64 + $seed)))
            .collect::<Vec<_>>();
        let mut prover = make();
        let (cap, data) = pcs.commit_bits(&bits, &mut prover).unwrap();
        let openings = $specs
            .iter()
            .enumerate()
            .map(|(i, spec)| BitOpening {
                point: Point::new(
                    (0..n)
                        .map(|j| {
                            if j < prefix {
                                E::ONE
                            } else {
                                E::from_le_byte_iter(
                                    (0x1428961abcc37f2a5df697141047def3u128
                                        .wrapping_mul(1 + j as u128 + i as u128))
                                    .to_le_bytes()
                                    .into_iter(),
                                )
                            }
                        })
                        .collect(),
                ),
                row_variables: spec.next_rows.unwrap_or(n),
                current: spec.current,
                next: spec.next_rows.is_some(),
            })
            .collect::<Vec<_>>();
        let (readings, proof) = pcs.open_readings(data, &openings, &mut prover).unwrap();
        let mut native_ch = make();
        pcs.observe_commitment(&cap, &mut native_ch);
        pcs.verify_readings(&cap, &openings, &readings, &proof, &mut native_ch)
            .unwrap();
        let points = openings.iter().map(|o| o.point.clone()).collect::<Vec<_>>();
        let readings = readings
            .iter()
            .map(|r| (r.current, r.next))
            .collect::<Vec<_>>();
        let mut entry = make();
        pcs.observe_commitment(&cap, &mut entry);
        let mut imported_ch = entry.clone();
        let imported = verifier
            .import_native(
                &tree,
                &tree,
                &cap,
                &points,
                &readings,
                &proof,
                &mut imported_ch,
            )
            .unwrap();
        assert_eq!(
            imported_ch.sample_algebra_element::<E>(),
            native_ch.sample_algebra_element::<E>()
        );
        let shape = verifier.input_shape();
        let other = BinaryGroupedBooleanPcsVerifier::<E>::new(
            config,
            $specs.to_vec(),
            $hash,
            0,
            65,
            BinaryCodewordGrouping::Codeword(8),
            BinaryCodewordGrouping::Codeword(8),
        )
        .unwrap()
        .input_shape();
        assert!(imported.private_values::<BabyBear>(&other).is_err());
        let mut values = bytes_to_limbs(&cap.roots()[0])
            .into_iter()
            .map(BabyBear::from_u16)
            .collect::<Vec<_>>();
        values.extend(imported.private_values::<BabyBear>(&shape).unwrap());
        let mut builder = CircuitBuilder::<BabyBear>::new();
        match $hash {
            ByteHash::Keccak256 => builder.enable_keccak_f1600::<BabyBear>(),
            ByteHash::Blake3 => builder.enable_blake3_compress::<BabyBear>(),
        }
        let cap_target = vec![
            builder
                .alloc_private_input_array::<16>("Boolean cap")
                .to_vec(),
        ];
        let targets = shape
            .allocate_targets::<BabyBear, BabyBear>(&mut builder)
            .unwrap();
        let initial = (0..3)
            .map(|_| builder.define_const(BabyBear::from_u8(9)))
            .collect::<Vec<_>>();
        let mut ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
            &mut builder,
            $hash,
            &initial,
        )
        .unwrap();
        verifier
            .observe_commitment::<BabyBear, BabyBear>(&mut builder, &mut ch, &cap_target)
            .unwrap();
        verifier
            .verify_readings::<BabyBear, BabyBear>(&mut builder, ch, &cap_target, &targets)
            .unwrap();
        let grouped_len = targets
            .opening
            .oracles
            .iter()
            .map(|o| {
                o.leaves.iter().map(|leaf| leaf.len() * 8).sum::<usize>()
                    + o.paths.iter().map(|path| path.len() * 16).sum::<usize>()
            })
            .sum::<usize>();
        let first_leaf = values.len() - grouped_len;
        // A coset starts at an even index; lane seven is never this row's symbol.
        let mut changed_lane = values.clone();
        changed_lane[first_leaf + 7 * 8] += BabyBear::ONE;
        let circuit = builder.build().unwrap();
        assert!(
            !run(&circuit, &changed_lane),
            "accepted an altered unselected grouped lane"
        );
        assert!(run(&circuit, &values));
        // Each public part of the opening relation remains constrained.
        for index in [0, 16, 16 + 8 * n] {
            let mut bad = values.clone();
            bad[index] += BabyBear::ONE;
            assert!(
                !run(&circuit, &bad),
                "accepted altered cap, point, or reading at {index}"
            );
        }
        let mut detached = proof.clone();
        detached.opening.evals[0] = p3_sumcheck::OpeningBatch::new(vec![E::ZERO], vec![]);
        assert!(
            verifier
                .import_native(
                    &tree,
                    &tree,
                    &cap,
                    &points,
                    &readings,
                    &detached,
                    &mut entry.clone()
                )
                .is_err()
        );
        let mut malformed = proof.clone();
        malformed.opening.sumcheck.polynomial_evaluations.pop();
        let mut unchanged = entry.clone();
        assert!(
            verifier
                .import_native(
                    &tree,
                    &tree,
                    &cap,
                    &points,
                    &readings,
                    &malformed,
                    &mut unchanged
                )
                .is_err()
        );
        assert_eq!(
            unchanged.sample_algebra_element::<E>(),
            entry.clone().sample_algebra_element::<E>()
        );
        // A malformed opaque supplement is discovered after ring replay. The
        // complete wrapper must still leave the caller's challenger unchanged.
        let mut malformed = proof.clone();
        let bytes = postcard::to_allocvec(&malformed.opening.base_multi_proof).unwrap();
        let mut view: GroupedView<E> = postcard::from_bytes(&bytes).unwrap();
        assert!(view.missing_symbols.pop().is_some());
        malformed.opening.base_multi_proof =
            postcard::from_bytes(&postcard::to_allocvec(&view).unwrap()).unwrap();
        let mut unchanged = entry.clone();
        let mut before = unchanged.clone();
        assert!(
            verifier
                .import_native(
                    &tree,
                    &tree,
                    &cap,
                    &points,
                    &readings,
                    &malformed,
                    &mut unchanged
                )
                .is_err()
        );
        assert_eq!(
            unchanged.sample_algebra_element::<E>(),
            before.sample_algebra_element::<E>()
        );
        (circuit, values, shape)
    }};
}

#[test]
fn grouped_boolean128_prefixes_reuse_one_checked_input_shape() {
    let specs = [BinaryRingClaimSpec {
        current: true,
        next_rows: None,
    }];
    let (circuit, _, shape) = fixture!(BinaryField128, keccak, ByteHash::Keccak256, specs, 0, 2);
    for prefix in [1, 2] {
        let (_, values, other) = fixture!(
            BinaryField128,
            keccak,
            ByteHash::Keccak256,
            specs,
            prefix,
            7 + prefix as u64
        );
        assert_eq!(shape, other);
        assert!(run(&circuit, &values));
    }
}

#[test]
fn grouped_boolean64_blake3_binds_batched_current_and_successor_readings() {
    let specs = [
        BinaryRingClaimSpec {
            current: true,
            next_rows: Some(7),
        },
        BinaryRingClaimSpec {
            current: false,
            next_rows: Some(3),
        },
    ];
    fixture!(BinaryField64, blake3, ByteHash::Blake3, specs, 1, 19);
}

#[test]
fn grouped_boolean_opening_proves_in_a_prime_field() {
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, Blake3CompressAirBuilder, Blake3CompressPreprocessor,
        Blake3CompressProver,
    };
    use p3_circuit_prover::{ConstraintProfile, config};
    let specs = [BinaryRingClaimSpec {
        current: true,
        next_rows: None,
    }];
    let (circuit, values, _) = fixture!(BinaryField64, blake3, ByteHash::Blake3, specs, 1, 13);
    let mut prover = BatchStarkProver::new(config::baby_bear());
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
fn grouped_boolean_budget_covers_ring_and_complete_leaf_inputs_together() {
    use p3_recursion::pcs::binary::{BinaryBitRingVerifier, BinaryGroupedPcsVerifier};
    use p3_recursion::verifier::{VerificationError, VerifierLimits};
    use p3_sumcheck::{OpeningBatch, OpeningProtocol, TableShape, TableSpec};
    type E = BinaryField128;
    let config = BinaryPcsConfig::try_new::<E, E>(
        2,
        BinaryPcsParams {
            log_inv_rate: 1,
            pow_bits: 0,
            security_level: 8,
        },
    )
    .unwrap();
    let specs = vec![BinaryRingClaimSpec {
        current: true,
        next_rows: None,
    }];
    let limits = VerifierLimits {
        max_total_scalar_elements: 1300,
        ..VerifierLimits::default()
    };
    BinaryBitRingVerifier::<E>::with_limits(9, specs.clone(), &limits).unwrap();
    BinaryGroupedPcsVerifier::<E, E>::with_limits(
        config,
        OpeningProtocol::new(vec![TableSpec::new(
            TableShape::new(2, 1),
            vec![OpeningBatch::new(vec![0], vec![])],
        )]),
        ByteHash::Keccak256,
        0,
        64,
        BinaryCodewordGrouping::Codeword(4),
        BinaryCodewordGrouping::Codeword(4),
        &limits,
    )
    .unwrap();
    assert!(matches!(
        BinaryGroupedBooleanPcsVerifier::<E>::with_limits(
            config,
            specs,
            ByteHash::Keccak256,
            0,
            64,
            BinaryCodewordGrouping::Codeword(4),
            BinaryCodewordGrouping::Codeword(4),
            &limits,
        ),
        Err(VerificationError::ResourceLimitExceeded {
            component: "scalar elements",
            ..
        })
    ));
}
