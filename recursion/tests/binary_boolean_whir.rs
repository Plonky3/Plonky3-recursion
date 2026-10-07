//! Released Boolean ring-switch proofs closed against additive WHIR.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField128, PackedGf2x64, TowerLevel};
use p3_binary_pcs::whir::{BinaryWhirDomain, BooleanWhirPcs};
use p3_binary_pcs::{BitOpening, BooleanMultilinearPcs};
use p3_challenger::{CanSampleUniformBits, FieldChallenger};
use p3_circuit::ops::{ByteHash, bytes_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::point::Point;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{
    BinaryBooleanWhirVerifier, BinaryRingClaimSpec, verify_binary_query_indices_with_continuation,
};
use p3_sumcheck::layout::SuffixProver;
use p3_test_utils::binary_field_params::{blake3, keccak};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};

fn run(circuit: &Circuit<BabyBear>, values: &[BabyBear]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(values).unwrap();
    runner.run().is_ok()
}

macro_rules! fixture {
    ($params:ident, $hash:expr, $specs:expr, $prefix:expr, $seed:expr) => {{ fixture!($params, $hash, $specs, $prefix, $seed, false) }};
    ($params:ident, $hash:expr, $specs:expr, $prefix:expr, $seed:expr, $after_queries:expr) => {{ fixture!($params, $hash, $specs, $prefix, $seed, $after_queries, 2) }};
    ($params:ident, $hash:expr, $specs:expr, $prefix:expr, $seed:expr, $after_queries:expr, $packed:expr) => {{
        type E = BinaryField128;
        type Ch = $params::LevelChallenger<E>;
        let n = 7 + $packed;
        let prefix: usize = $prefix;
        let domain = BinaryWhirDomain::<E>::default();
        let config = WhirConfig::<E, E, Ch>::new_with_domain(
            $packed,
            ProtocolParameters {
                security_level: 8,
                pow_bits: 0,
                round_log_inv_rates: vec![],
                folding_factor: FoldingFactor::Constant(1),
                soundness_type: SecurityAssumption::JohnsonBound,
                starting_log_inv_rate: 1,
            },
            &domain,
        )
        .unwrap();
        let mmcs = $params::LevelMmcs::<E>::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            0,
        );
        let inner = WhirProver::<E, E, _, _, Ch, SuffixProver<E, E>>::new(
            config.clone(),
            domain,
            mmcs.clone(),
        );
        let pcs = BooleanWhirPcs::new(inner, n).unwrap();
        let recursive = BinaryBooleanWhirVerifier::new(&config, $specs.to_vec(), $hash, 0).unwrap();
        let make = || Ch::from_hasher(vec![9; 3], $params::byte_hash());
        let bits = (0..1usize << (n - 6))
            .map(|i| PackedGf2x64::new(0xb273ca07846def19u64.wrapping_mul(i as u64 + $seed)))
            .collect::<Vec<_>>();
        let mut prover = make();
        let (cap, data) = pcs.commit_bits(&bits, &mut prover).unwrap();
        let queries = |ch: &mut Ch| {
            let mut indices = vec![];
            if $after_queries {
                while indices.len() < 2 {
                    let index = ch.sample_uniform_bits::<true>(3).unwrap();
                    if !indices.contains(&index) {
                        indices.push(index);
                    }
                }
                indices.sort_unstable();
            }
            indices
        };
        let indices = queries(&mut prover);
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
                                E::from_repr(
                                    0x1428961abcc37f2a5df697141047def3u128
                                        .wrapping_mul(1 + j as u128 + i as u128),
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
        let mut native = make();
        pcs.observe_commitment(&cap, &mut native);
        assert_eq!(queries(&mut native), indices);
        pcs.verify_readings(&cap, &openings, &readings, &proof, &mut native)
            .unwrap();
        let points = openings.iter().map(|o| o.point.clone()).collect::<Vec<_>>();
        let readings = readings
            .iter()
            .map(|r| (r.current, r.next))
            .collect::<Vec<_>>();
        let mut entry = make();
        pcs.observe_commitment(&cap, &mut entry);
        assert_eq!(queries(&mut entry), indices);
        let mut imported_ch = entry.clone();
        let imported = recursive
            .import_native(
                &config,
                &mmcs,
                &cap,
                &points,
                &readings,
                &proof,
                &mut imported_ch,
            )
            .unwrap();
        let expected = native.sample_algebra_element::<E>().to_repr();
        assert_eq!(
            imported_ch.sample_algebra_element::<E>().to_repr(),
            expected
        );
        let shape = recursive.input_shape();
        let other_hash = match $hash {
            ByteHash::Keccak256 => ByteHash::Blake3,
            ByteHash::Blake3 => ByteHash::Keccak256,
        };
        let other =
            BinaryBooleanWhirVerifier::new(&config, $specs.to_vec(), other_hash, 0).unwrap();
        assert!(
            imported
                .private_values::<BabyBear>(&other.input_shape())
                .is_err()
        );
        let mut values = bytes_to_limbs(&cap.roots()[0])
            .into_iter()
            .map(BabyBear::from_u16)
            .collect::<Vec<_>>();
        values.extend(imported.private_values::<BabyBear>(&shape).unwrap());
        values.extend((0..8).map(|i| BabyBear::from_u16((expected >> (16 * i)) as u16)));
        let mut b = CircuitBuilder::<BabyBear>::new();
        match $hash {
            ByteHash::Keccak256 => b.enable_keccak_f1600::<BabyBear>(),
            ByteHash::Blake3 => b.enable_blake3_compress::<BabyBear>(),
        }
        let cap_target = vec![
            b.alloc_private_input_array::<16>("Boolean WHIR cap")
                .to_vec(),
        ];
        let targets = shape
            .allocate_targets::<BabyBear, BabyBear>(&mut b)
            .unwrap();
        let initial = (0..3)
            .map(|_| b.define_const(BabyBear::from_u8(9)))
            .collect::<Vec<_>>();
        let mut ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
            &mut b, $hash, &initial,
        )
        .unwrap();
        recursive
            .observe_commitment::<BabyBear, BabyBear>(&mut b, &mut ch, &cap_target)
            .unwrap();
        let mut ch =
            if $after_queries {
                let index_bits = indices
                    .iter()
                    .map(|&index| {
                        (0..3)
                            .map(|j| b.define_const(BabyBear::from_bool(index >> j & 1 != 0)))
                            .collect::<Vec<_>>()
                    })
                    .collect::<Vec<_>>();
                let continuation = verify_binary_query_indices_with_continuation::<
                    BabyBear,
                    BabyBear,
                >(&mut b, ch, 3, &index_bits, 32)
                .unwrap();
                recursive
                    .verify_readings_after_queries::<BabyBear, BabyBear>(
                        &mut b,
                        continuation,
                        &cap_target,
                        &targets,
                    )
                    .unwrap()
            } else {
                recursive
                    .verify_readings::<BabyBear, BabyBear>(&mut b, ch, &cap_target, &targets)
                    .unwrap()
            };
        let actual = ch.sample::<BabyBear, BabyBear>(&mut b).unwrap();
        let expected_target = b.alloc_private_input_array::<8>("Boolean WHIR continuation");
        let expected_target = b.binary128_from_limbs::<BabyBear>(expected_target).unwrap();
        for (&a, &e) in actual.bits().iter().zip(expected_target.bits()) {
            let difference = b.sub(a, e);
            b.assert_zero(difference);
        }
        let circuit = b.build().unwrap();
        assert!(run(&circuit, &values));
        for index in [0, 16, 16 + 8 * n, values.len() - 8] {
            let mut wrong = values.clone();
            wrong[index] += BabyBear::ONE;
            assert!(!run(&circuit, &wrong));
        }
        let mut detached = proof.clone();
        detached.opening.evals[0] = p3_sumcheck::OpeningBatch::new(vec![E::ZERO], vec![]);
        let mut unchanged = entry.clone();
        assert!(
            recursive
                .import_native(
                    &config,
                    &mmcs,
                    &cap,
                    &points,
                    &readings,
                    &detached,
                    &mut unchanged,
                )
                .is_err()
        );
        let mut before = entry.clone();
        assert_eq!(
            unchanged.sample_algebra_element::<E>(),
            before.sample_algebra_element::<E>()
        );
        let mut malformed = proof.clone();
        malformed.opening.whir.final_poly = None;
        let mut unchanged = entry.clone();
        assert!(
            recursive
                .import_native(
                    &config,
                    &mmcs,
                    &cap,
                    &points,
                    &readings,
                    &malformed,
                    &mut unchanged,
                )
                .is_err()
        );
        assert_eq!(
            unchanged.sample_algebra_element::<E>(),
            entry.sample_algebra_element::<E>()
        );
        (circuit, values, shape)
    }};
}

#[test]
fn native_boolean_whir_prefixes_share_one_checked_circuit() {
    let specs = [BinaryRingClaimSpec {
        current: true,
        next_rows: None,
    }];
    let (circuit, _, shape) = fixture!(keccak, ByteHash::Keccak256, specs, 0, 2);
    for prefix in [1, 2] {
        let (_, values, other) = fixture!(
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
fn native_blake3_whir_closes_batched_current_and_successor_readings() {
    let specs = [
        BinaryRingClaimSpec {
            current: true,
            next_rows: Some(8),
        },
        BinaryRingClaimSpec {
            current: false,
            next_rows: Some(3),
        },
    ];
    fixture!(blake3, ByteHash::Blake3, specs, 1, 19);
}

#[test]
fn preceding_bounded_queries_resume_through_the_ring_seed_once() {
    let specs = [BinaryRingClaimSpec {
        current: true,
        next_rows: Some(8),
    }];
    fixture!(keccak, ByteHash::Keccak256, specs, 1, 5, true);
}

#[test]
fn combined_resource_limit_accounts_for_both_the_ring_and_whir() {
    use p3_recursion::pcs::binary::{BinaryBitRingVerifier, BinaryWhirVerifier};
    use p3_recursion::verifier::{VerificationError, VerifierLimits};
    use p3_sumcheck::strategy::VariableOrder;
    use p3_sumcheck::{OpeningBatch, OpeningProtocol, TableShape, TableSpec};
    type E = BinaryField128;
    let domain = BinaryWhirDomain::<E>::default();
    let config = WhirConfig::<E, E, keccak::LevelChallenger<E>>::new_with_domain(
        2,
        ProtocolParameters {
            security_level: 8,
            pow_bits: 0,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(1),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: 1,
        },
        &domain,
    )
    .unwrap();
    let specs = vec![BinaryRingClaimSpec {
        current: true,
        next_rows: None,
    }];
    let verifier =
        BinaryBooleanWhirVerifier::new(&config, specs.clone(), ByteHash::Keccak256, 0).unwrap();
    let limits = VerifierLimits {
        max_total_scalar_elements: verifier.input_resource_usage().scalar_elements - 1,
        ..VerifierLimits::default()
    };
    BinaryBitRingVerifier::<E>::with_limits(9, specs.clone(), &limits).unwrap();
    let protocol = OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(2, 1),
        vec![OpeningBatch::new(vec![0], vec![])],
    )]);
    BinaryWhirVerifier::<E>::with_limits(
        &config,
        protocol,
        VariableOrder::Suffix,
        ByteHash::Keccak256,
        0,
        &limits,
    )
    .unwrap();
    assert!(matches!(
        BinaryBooleanWhirVerifier::with_limits(&config, specs, ByteHash::Keccak256, 0, &limits),
        Err(VerificationError::ResourceLimitExceeded {
            component: "scalar elements",
            ..
        })
    ));
}

#[test]
fn complete_boolean_whir_readings_prove_in_a_prime_field_circuit() {
    use p3_circuit_prover::ConstraintProfile;
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover,
    };
    let specs = [BinaryRingClaimSpec {
        current: true,
        next_rows: None,
    }];
    let (circuit, values, _) = fixture!(keccak, ByteHash::Keccak256, specs, 1, 11, false, 1);
    let mut prover = BatchStarkProver::new(crate::proof_config());
    prover.register_table_prover(Box::new(KeccakF1600Prover::<1>));
    let prepared = prover
        .prepare_circuit::<BabyBear, 1>(
            &circuit,
            &[Box::new(KeccakF1600Preprocessor)],
            &[Box::new(KeccakF1600AirBuilder::<1>)],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let mut runner = circuit.runner();
    runner.set_private_inputs(&values).unwrap();
    let proof = prepared.prove(&runner.run().unwrap()).unwrap();
    prepared.verifier().verify(&proof, &[]).unwrap();
}
