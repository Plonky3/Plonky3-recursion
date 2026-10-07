//! Released Boolean trace routing composed with additive WHIR.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_binary_pcs::BooleanTraceCommitment;
use p3_binary_pcs::whir::{BinaryWhirDomain, BooleanWhirPcs};
use p3_challenger::{CanSampleUniformBits, FieldChallenger};
use p3_circuit::ops::{ByteHash, bytes_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::point::Point;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{
    BinaryBooleanWhirTraceVerifier, RecursiveBinaryTowerField,
    verify_binary_query_indices_with_continuation,
};
use p3_sumcheck::layout::{SuffixProver, Table};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
use p3_test_utils::binary_field_params::{blake3, keccak};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};

fn run(circuit: &Circuit<BabyBear>, values: &[BabyBear]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(values).unwrap();
    runner.run().is_ok()
}

macro_rules! check {
    ($params:ident, $hash:expr, $protocol:expr) => {{ check!($params, $hash, $protocol, false) }};
    ($params:ident, $hash:expr, $protocol:expr, $after_queries:expr) => {{
        type E = BinaryField128;
        type Ch = $params::LevelChallenger<E>;
        let protocol = $protocol;
        let n = p3_sumcheck::layout::plan_stacked_layout(&protocol.table_shapes()).0;
        let domain = BinaryWhirDomain::<E>::default();
        let config = WhirConfig::<E, E, Ch>::new_with_domain(
            n - 7,
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
        let pcs = BooleanTraceCommitment::from_commitment(BooleanWhirPcs::new(inner, n).unwrap());
        let recursive =
            BinaryBooleanWhirTraceVerifier::new(&config, protocol.clone(), $hash, 0).unwrap();
        let shape = recursive.input_shape();
        let mut builder = CircuitBuilder::<BabyBear>::new();
        match $hash {
            ByteHash::Keccak256 => builder.enable_keccak_f1600::<BabyBear>(),
            ByteHash::Blake3 => builder.enable_blake3_compress::<BabyBear>(),
        }
        let cap = vec![
            builder
                .alloc_private_input_array::<16>("trace cap")
                .to_vec(),
        ];
        let points = protocol
            .iter_openings()
            .map(|(table, _)| {
                (0..protocol.table_shapes()[table].num_variables())
                    .map(|_| {
                        let limbs = builder.alloc_private_input_array::<8>("trace row coordinate");
                        builder.binary128_from_limbs::<BabyBear>(limbs).unwrap()
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let proof = shape
            .allocate_targets::<BabyBear, BabyBear>(&mut builder)
            .unwrap();
        let query_targets = if $after_queries {
            (0..2)
                .map(|_| {
                    (0..3)
                        .map(|_| builder.alloc_private_input("preceding query bit"))
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>()
        } else {
            vec![]
        };
        let initial = (0..3)
            .map(|_| builder.define_const(BabyBear::from_u8(9)))
            .collect::<Vec<_>>();
        let mut ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
            &mut builder,
            $hash,
            &initial,
        )
        .unwrap();
        recursive
            .observe_commitment::<BabyBear, BabyBear>(&mut builder, &mut ch, &cap)
            .unwrap();
        let (evals, mut ch) = if $after_queries {
            let token = verify_binary_query_indices_with_continuation::<BabyBear, BabyBear>(
                &mut builder,
                ch,
                3,
                &query_targets,
                32,
            )
            .unwrap();
            recursive
                .verify_at_after_queries::<BabyBear, BabyBear>(
                    &mut builder,
                    token,
                    &cap,
                    &points,
                    &proof,
                )
                .unwrap()
        } else {
            recursive
                .verify_at::<BabyBear, BabyBear>(&mut builder, ch, &cap, &points, &proof)
                .unwrap()
        };
        let actual = ch.sample::<BabyBear, BabyBear>(&mut builder).unwrap();
        let expected = builder.alloc_private_input_array::<8>("trace WHIR continuation");
        let expected = builder.binary128_from_limbs::<BabyBear>(expected).unwrap();
        for (&a, &e) in actual.bits().iter().zip(expected.bits()) {
            let difference = builder.sub(a, e);
            builder.assert_zero(difference);
        }
        assert_eq!(evals.len(), protocol.num_openings());
        for (evals, (_, request)) in evals.iter().zip(protocol.iter_openings()) {
            assert!(request.has_same_shape(evals));
        }
        let circuit = builder.build().unwrap();
        let mut last_values = vec![];
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
        for seed in [2u128, 19] {
            let make =
                || $params::LevelChallenger::<E>::from_hasher(vec![9; 3], $params::byte_hash());
            let tables = protocol
                .table_shapes()
                .iter()
                .enumerate()
                .map(|(table, shape)| {
                    Table::new(RowMajorMatrix::new(
                        (0..shape.width() * (1 << shape.num_variables()))
                            .map(|i| {
                                if (seed + i as u128 + 31 * table as u128).count_ones() & 1 == 0 {
                                    E::ZERO
                                } else {
                                    E::ONE
                                }
                            })
                            .collect(),
                        1 << shape.num_variables(),
                    ))
                })
                .collect::<Vec<_>>();
            let native_points = protocol
                .iter_openings()
                .enumerate()
                .map(|(opening, (table, _))| {
                    Point::new(
                        (0..protocol.table_shapes()[table].num_variables())
                            .map(|j| {
                                E::from_le_byte_iter(
                                    (0x6b9731a08be41d27659931cad03ef712u128
                                        .wrapping_mul(seed + 1 + j as u128 + 13 * opening as u128))
                                    .to_le_bytes()
                                    .into_iter(),
                                )
                            })
                            .collect(),
                    )
                })
                .collect::<Vec<_>>();
            let mut prover = make();
            let (commitment, data) = pcs.commit(tables, &mut prover).unwrap();
            let indices = queries(&mut prover);
            let native_proof = pcs
                .open_at(data, &protocol, &native_points, &mut prover)
                .unwrap();
            let mut verifier = make();
            pcs.observe_commitment(&commitment, &mut verifier);
            assert_eq!(queries(&mut verifier), indices);
            pcs.verify_at(
                &commitment,
                &native_proof,
                &protocol,
                &native_points,
                &mut verifier,
            )
            .unwrap();
            let mut entry = make();
            pcs.observe_commitment(&commitment, &mut entry);
            assert_eq!(queries(&mut entry), indices);
            let imported = recursive
                .import_native(
                    &config,
                    &mmcs,
                    &commitment,
                    &native_points,
                    &native_proof,
                    &mut entry,
                )
                .unwrap();
            assert_eq!(imported.shape(), &shape);
            let other_protocol = OpeningProtocol::new(
                protocol
                    .table_shapes()
                    .into_iter()
                    .enumerate()
                    .map(|(table, shape)| {
                        TableSpec::new(
                            shape,
                            protocol
                                .iter_openings()
                                .filter(|(owner, _)| *owner == table)
                                .map(|(_, batch)| {
                                    OpeningBatch::new(
                                        batch.current().iter().rev().copied().collect(),
                                        batch.next().to_vec(),
                                    )
                                })
                                .collect(),
                        )
                    })
                    .collect(),
            );
            if other_protocol != protocol {
                let other = BinaryBooleanWhirTraceVerifier::new(&config, other_protocol, $hash, 0)
                    .unwrap()
                    .input_shape();
                assert!(imported.private_values::<BabyBear>(&other).is_err());
            }
            let mut values = bytes_to_limbs(&commitment.roots()[0])
                .into_iter()
                .map(BabyBear::from_u16)
                .collect::<Vec<_>>();
            let pack =
                |raw: u128| (0..8).map(move |i| BabyBear::from_u16((raw >> (16 * i)) as u16));
            values.extend(
                native_points
                    .iter()
                    .flat_map(|p| p.as_slice())
                    .flat_map(|&v| pack(v.raw_coordinates())),
            );
            let outer_start = values.len();
            values.extend(imported.private_values::<BabyBear>(&shape).unwrap());
            let expected = verifier.sample_algebra_element::<E>();
            assert_eq!(entry.sample_algebra_element::<E>(), expected);
            values.extend(
                indices.iter().flat_map(|&index| {
                    (0..3).map(move |j| BabyBear::from_bool(index >> j & 1 != 0))
                }),
            );
            values.extend(pack(expected.to_repr()));
            assert!(run(&circuit, &values));
            last_values = values.clone();
            let child_start = outer_start + 8 * native_proof.values.len();
            for index in [
                0,
                16,
                outer_start,
                child_start,
                child_start + 8 * n,
                values.len() - 8,
            ] {
                let mut wrong = values.clone();
                wrong[index] += BabyBear::ONE;
                assert!(!run(&circuit, &wrong));
            }
            let mut wrong = native_proof.clone();
            wrong.values.pop();
            let mut unchanged = make();
            pcs.observe_commitment(&commitment, &mut unchanged);
            let mut before = unchanged.clone();
            assert!(
                recursive
                    .import_native(
                        &config,
                        &mmcs,
                        &commitment,
                        &native_points,
                        &wrong,
                        &mut unchanged
                    )
                    .is_err()
            );
            assert_eq!(
                unchanged.sample_algebra_element::<E>(),
                before.sample_algebra_element::<E>()
            );
            let mut wrong = native_proof.clone();
            wrong.opening.opening.whir.final_poly = None;
            let mut unchanged = make();
            pcs.observe_commitment(&commitment, &mut unchanged);
            let mut before = unchanged.clone();
            assert!(
                recursive
                    .import_native(
                        &config,
                        &mmcs,
                        &commitment,
                        &native_points,
                        &wrong,
                        &mut unchanged
                    )
                    .is_err()
            );
            assert_eq!(
                unchanged.sample_algebra_element::<E>(),
                before.sample_algebra_element::<E>()
            );
        }
        (circuit, last_values, shape)
    }};
}

fn batched(width: usize, rows: usize, next: bool) -> OpeningProtocol {
    OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(rows, width),
        vec![
            OpeningBatch::new(
                (0..width).collect(),
                if next { (0..width).collect() } else { vec![] },
            ),
            OpeningBatch::new(
                (0..width).collect(),
                if next { (0..width).collect() } else { vec![] },
            ),
        ],
    )])
}

#[test]
fn column_batched_whir_routes_match_native_nonpower_width_and_width_one() {
    check!(blake3, ByteHash::Blake3, batched(3, 7, true));
    check!(keccak, ByteHash::Keccak256, batched(1, 8, true));
}

#[test]
fn generic_whir_columns_bind_varied_heights_and_unopened_table_placement() {
    let protocol = OpeningProtocol::new(vec![
        TableSpec::new(
            TableShape::new(7, 2),
            vec![OpeningBatch::new(vec![1, 0], vec![0])],
        ),
        TableSpec::new(
            TableShape::new(5, 3),
            vec![OpeningBatch::new(vec![2], vec![1, 2])],
        ),
        TableSpec::new(TableShape::new(6, 1), vec![]),
    ]);
    check!(keccak, ByteHash::Keccak256, protocol);
}

#[test]
fn preceding_queries_resume_through_both_native_trace_entry_routes() {
    check!(keccak, ByteHash::Keccak256, batched(1, 8, false), true);
    let generic = OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(7, 2),
        vec![OpeningBatch::new(vec![1], vec![])],
    )]);
    check!(blake3, ByteHash::Blake3, generic, true);
}

#[test]
fn trusted_trace_geometry_and_combined_limits_reject_before_allocation() {
    use p3_recursion::pcs::binary::{BinaryBooleanWhirVerifier, BinaryRingClaimSpec};
    use p3_recursion::verifier::{VerificationError, VerifierLimits};
    type E = BinaryField128;
    let domain = BinaryWhirDomain::<E>::default();
    let config = WhirConfig::<E, E, keccak::LevelChallenger<E>>::new_with_domain(
        1,
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
    let protocol = OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(8, 1),
        vec![OpeningBatch::new(vec![0], vec![])],
    )]);
    let verifier =
        BinaryBooleanWhirTraceVerifier::new(&config, protocol.clone(), ByteHash::Keccak256, 0)
            .unwrap();
    let limits = VerifierLimits {
        max_total_scalar_elements: verifier.input_resource_usage().scalar_elements - 1,
        ..VerifierLimits::default()
    };
    BinaryBooleanWhirVerifier::with_limits(
        &config,
        vec![BinaryRingClaimSpec {
            current: true,
            next_rows: None,
        }],
        ByteHash::Keccak256,
        0,
        &limits,
    )
    .unwrap();
    assert!(matches!(
        BinaryBooleanWhirTraceVerifier::with_limits(
            &config,
            protocol,
            ByteHash::Keccak256,
            0,
            &limits,
        ),
        Err(VerificationError::ResourceLimitExceeded {
            component: "scalar elements",
            ..
        })
    ));
    for protocol in [
        OpeningProtocol::new(vec![TableSpec::new(TableShape::new(8, 1), vec![])]),
        OpeningProtocol::new(vec![TableSpec::new(
            TableShape::new(7, 1),
            vec![OpeningBatch::new(vec![0], vec![])],
        )]),
        OpeningProtocol::new(vec![TableSpec::new(
            TableShape::new(9, 1),
            vec![OpeningBatch::new(vec![0], vec![])],
        )]),
    ] {
        assert!(
            BinaryBooleanWhirTraceVerifier::new(&config, protocol, ByteHash::Keccak256, 0).is_err()
        );
    }
}

#[test]
fn whir_trace_opening_proves_in_a_prime_field_circuit() {
    use p3_circuit_prover::ConstraintProfile;
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover,
    };
    let protocol = OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(8, 1),
        vec![OpeningBatch::new(vec![0], vec![])],
    )]);
    let (circuit, values, _) = check!(keccak, ByteHash::Keccak256, protocol);
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
