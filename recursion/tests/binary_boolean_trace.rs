//! Native Boolean trace column routes and their packed opening relation.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField64, BinaryField128, TowerLevel};
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsParams, BooleanTracePcs};
use p3_circuit::ops::{ByteHash, bytes_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::point::Point;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{BinaryBooleanTraceVerifier, RecursiveBinaryTowerField};
use p3_sumcheck::layout::Table;
use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
use p3_test_utils::binary_field_params::{blake3, keccak};

fn run(circuit: &Circuit<BabyBear>, values: &[BabyBear]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(values).unwrap();
    runner.run().is_ok()
}

macro_rules! check {
    ($e:ty, $params:ident, $hash:expr, $protocol:expr) => {{
        type E = $e;
        let protocol = $protocol;
        let n = p3_sumcheck::layout::plan_stacked_layout(&protocol.table_shapes()).0;
        let config = BinaryPcsConfig::try_new::<E, E>(
            n - E::RAW_BITS.ilog2() as usize,
            BinaryPcsParams { log_inv_rate: 1, pow_bits: 0, security_level: 8 },
        ).unwrap();
        let mmcs = $params::LevelMmcs::<E>::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()), 0,
        );
        let pcs = BooleanTracePcs::<E, _, _>::new(config, mmcs.clone(), mmcs.clone(), n).unwrap();
        let recursive = BinaryBooleanTraceVerifier::<E>::new(config, protocol.clone(), $hash, 0, 64).unwrap();
        let shape = recursive.input_shape();
        let mut builder = CircuitBuilder::<BabyBear>::new();
        match $hash {
            ByteHash::Keccak256 => builder.enable_keccak_f1600::<BabyBear>(),
            ByteHash::Blake3 => builder.enable_blake3_compress::<BabyBear>(),
        }
        let cap = vec![builder.alloc_private_input_array::<16>("trace cap").to_vec()];
        let points = protocol.iter_openings().map(|(table, _)| {
            (0..protocol.table_shapes()[table].num_variables()).map(|_| {
                let limbs = builder.alloc_private_input_array::<8>("trace row coordinate");
                builder.binary128_from_limbs::<BabyBear>(limbs).unwrap()
            }).collect::<Vec<_>>()
        }).collect::<Vec<_>>();
        let proof = shape.allocate_targets::<BabyBear, BabyBear>(&mut builder).unwrap();
        let initial = (0..3).map(|_| builder.define_const(BabyBear::from_u8(9))).collect::<Vec<_>>();
        let mut ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
            &mut builder, $hash, &initial,
        ).unwrap();
        recursive.observe_commitment::<BabyBear, BabyBear>(&mut builder, &mut ch, &cap).unwrap();
        let evals = recursive.verify_at::<BabyBear, BabyBear>(&mut builder, ch, &cap, &points, &proof).unwrap();
        assert_eq!(evals.len(), protocol.num_openings());
        for (evals, (_, request)) in evals.iter().zip(protocol.iter_openings()) {
            assert!(request.has_same_shape(evals));
        }
        let circuit = builder.build().unwrap();
        let mut last_values = vec![];
        for seed in [2u128, 19] {
            let make = || $params::LevelChallenger::<E>::from_hasher(vec![9; 3], $params::byte_hash());
            let tables = protocol.table_shapes().iter().enumerate().map(|(table, shape)| {
                Table::new(RowMajorMatrix::new(
                    (0..shape.width() * (1 << shape.num_variables())).map(|i| {
                        if (seed + i as u128 + 31 * table as u128).count_ones() & 1 == 0 { E::ZERO } else { E::ONE }
                    }).collect(), 1 << shape.num_variables(),
                ))
            }).collect::<Vec<_>>();
            let native_points = protocol.iter_openings().enumerate().map(|(opening, (table, _))| {
                Point::new((0..protocol.table_shapes()[table].num_variables()).map(|j| {
                    E::from_le_byte_iter((0x6b9731a08be41d27659931cad03ef712u128.wrapping_mul(seed + 1 + j as u128 + 13 * opening as u128)).to_le_bytes().into_iter())
                }).collect())
            }).collect::<Vec<_>>();
            let mut prover = make();
            let (commitment, data) = pcs.commit(tables, &mut prover).unwrap();
            let native_proof = pcs.open_at(data, &protocol, &native_points, &mut prover).unwrap();
            let mut verifier = make();
            pcs.observe_commitment(&commitment, &mut verifier);
            pcs.verify_at(&commitment, &native_proof, &protocol, &native_points, &mut verifier).unwrap();
            let mut entry = make();
            pcs.observe_commitment(&commitment, &mut entry);
            let imported = recursive.import_native(&mmcs, &mmcs, &commitment, &native_points, &native_proof, &mut entry).unwrap();
            assert_eq!(imported.shape(), &shape);
            let other_protocol = OpeningProtocol::new(protocol.table_shapes().into_iter().enumerate().map(|(table, shape)| {
                TableSpec::new(shape, protocol.iter_openings().filter(|(owner, _)| *owner == table).map(|(_, batch)| {
                    OpeningBatch::new(batch.current().iter().rev().copied().collect(), batch.next().to_vec())
                }).collect())
            }).collect());
            if other_protocol != protocol {
                let other = BinaryBooleanTraceVerifier::<E>::new(config, other_protocol, $hash, 0, 64).unwrap().input_shape();
                assert!(imported.private_values::<BabyBear>(&other).is_err());
            }
            let mut values = bytes_to_limbs(&commitment.roots()[0]).into_iter().map(BabyBear::from_u16).collect::<Vec<_>>();
            let pack = |raw: u128| (0..8).map(move |i| BabyBear::from_u16((raw >> (16 * i)) as u16));
            values.extend(native_points.iter().flat_map(|p| p.as_slice()).flat_map(|&v| pack(v.raw_coordinates())));
            let outer_start = values.len();
            values.extend(imported.private_values::<BabyBear>(&shape).unwrap());
            assert!(run(&circuit, &values));
            last_values = values.clone();
            let child_start = outer_start + 8 * native_proof.values.len();
            for index in [0, 16, outer_start, child_start, child_start + 8 * n] {
                let mut wrong = values.clone();
                wrong[index] += BabyBear::ONE;
                assert!(!run(&circuit, &wrong));
            }
            if E::RAW_BITS == 64 {
                for index in [16 + 4, outer_start + 4] {
                    let mut wrong = values.clone();
                    wrong[index] = BabyBear::ONE;
                    assert!(!run(&circuit, &wrong));
                }
            }
            let mut wrong = native_proof.clone();
            wrong.values.pop();
            let mut unchanged = make();
            pcs.observe_commitment(&commitment, &mut unchanged);
            let mut before = unchanged.clone();
            assert!(recursive.import_native(&mmcs, &mmcs, &commitment, &native_points, &wrong, &mut unchanged).is_err());
            use p3_challenger::FieldChallenger;
            assert_eq!(unchanged.sample_algebra_element::<E>(), before.sample_algebra_element::<E>());
            let mut wrong = native_proof.clone();
            wrong.opening.opening.sumcheck.polynomial_evaluations.pop();
            let mut unchanged = make();
            pcs.observe_commitment(&commitment, &mut unchanged);
            let mut before = unchanged.clone();
            assert!(recursive.import_native(&mmcs, &mmcs, &commitment, &native_points, &wrong, &mut unchanged).is_err());
            assert_eq!(unchanged.sample_algebra_element::<E>(), before.sample_algebra_element::<E>());
            assert_eq!(entry.sample_algebra_element::<E>(), verifier.sample_algebra_element::<E>());
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
fn column_batched_routes_match_native_for_nonpower_width_and_width_one() {
    check!(BinaryField64, blake3, ByteHash::Blake3, batched(3, 6, true));
    check!(
        BinaryField128,
        keccak,
        ByteHash::Keccak256,
        batched(1, 8, true)
    );
}

#[test]
fn generic_columns_bind_varied_heights_and_unopened_table_placement() {
    let protocol = OpeningProtocol::new(vec![
        TableSpec::new(
            TableShape::new(6, 2),
            vec![OpeningBatch::new(vec![1, 0], vec![0])],
        ),
        TableSpec::new(
            TableShape::new(4, 3),
            vec![OpeningBatch::new(vec![2], vec![1, 2])],
        ),
        TableSpec::new(TableShape::new(5, 1), vec![]),
    ]);
    check!(BinaryField64, keccak, ByteHash::Keccak256, protocol);
}

#[test]
fn trace_opening_proves_in_a_prime_field_circuit() {
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover,
    };
    use p3_circuit_prover::{ConstraintProfile, config};

    let protocol = OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(7, 1),
        vec![OpeningBatch::new(vec![0], vec![])],
    )]);
    let (circuit, values, _) = check!(BinaryField64, keccak, ByteHash::Keccak256, protocol);
    let mut prover = BatchStarkProver::new(config::baby_bear());
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

#[test]
fn trace_metadata_is_bounded_before_native_planning() {
    use p3_recursion::verifier::{VerificationError, VerifierLimits};
    let config = BinaryPcsConfig::try_new::<BinaryField64, BinaryField64>(
        1,
        BinaryPcsParams {
            log_inv_rate: 1,
            pow_bits: 0,
            security_level: 8,
        },
    )
    .unwrap();
    let make = |protocol, limits: &VerifierLimits| {
        BinaryBooleanTraceVerifier::<BinaryField64>::with_limits(
            config,
            protocol,
            ByteHash::Keccak256,
            0,
            32,
            limits,
        )
    };
    let defaults = VerifierLimits::default();
    assert!(
        make(
            OpeningProtocol::new(vec![TableSpec::new(TableShape::new(7, 1), vec![])]),
            &defaults
        )
        .is_err()
    );
    assert!(
        make(
            OpeningProtocol::new(vec![TableSpec::new(
                TableShape::new(6, 1),
                vec![OpeningBatch::new(vec![0], vec![])]
            )]),
            &defaults
        )
        .is_err()
    );
    assert!(matches!(
        make(
            OpeningProtocol::new(vec![TableSpec::new(
                TableShape::new(63, usize::MAX),
                vec![]
            )]),
            &defaults
        ),
        Err(VerificationError::ResourceArithmeticOverflow { .. })
    ));
    let limits = VerifierLimits {
        max_total_scalar_elements: 64,
        ..defaults
    };
    assert!(matches!(
        make(batched(1, 7, false), &limits),
        Err(VerificationError::ResourceLimitExceeded { .. })
    ));
}

#[test]
fn consecutive_trace_openings_resume_both_column_routes() {
    use p3_challenger::{CanObserve, FieldChallenger};
    type E = BinaryField64;
    let config = BinaryPcsConfig::try_new::<E, E>(
        1,
        BinaryPcsParams {
            log_inv_rate: 1,
            pow_bits: 0,
            security_level: 8,
        },
    )
    .unwrap();
    let mmcs = keccak::LevelMmcs::<E>::new(
        keccak::FieldHash::new(keccak::byte_hash()),
        keccak::Compress::new(keccak::byte_hash()),
        0,
    );
    let pcs = BooleanTracePcs::<E, _, _>::new(config, mmcs.clone(), mmcs.clone(), 7).unwrap();
    let protocols = [vec![1, 0], vec![0, 1], vec![1, 0]].map(|columns| {
        OpeningProtocol::new(vec![TableSpec::new(
            TableShape::new(6, 2),
            vec![OpeningBatch::new(columns, vec![])],
        )])
    });
    let verifiers = protocols.each_ref().map(|protocol| {
        BinaryBooleanTraceVerifier::<E>::new(config, protocol.clone(), ByteHash::Keccak256, 0, 32)
            .unwrap()
    });
    let shapes = verifiers.each_ref().map(|v| v.input_shape());
    let mut builder = CircuitBuilder::<BabyBear>::new();
    builder.enable_keccak_f1600::<BabyBear>();
    let caps = (0..3)
        .map(|_| {
            vec![
                builder
                    .alloc_private_input_array::<16>("trace cap")
                    .to_vec(),
            ]
        })
        .collect::<Vec<_>>();
    let mut row_points = Vec::new();
    let mut proofs = Vec::new();
    for shape in &shapes {
        row_points.push(vec![
            (0..6)
                .map(|_| {
                    let limbs = builder.alloc_private_input_array::<8>("trace row point");
                    builder.binary128_from_limbs::<BabyBear>(limbs).unwrap()
                })
                .collect::<Vec<_>>(),
        ]);
        proofs.push(
            shape
                .allocate_targets::<BabyBear, BabyBear>(&mut builder)
                .unwrap(),
        );
    }
    let expected = builder.alloc_private_input_array::<8>("continued trace challenge");
    let expected = builder.binary128_from_limbs::<BabyBear>(expected).unwrap();
    let initial = (0..3)
        .map(|_| builder.define_const(BabyBear::from_u8(9)))
        .collect::<Vec<_>>();
    let mut ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
        &mut builder,
        ByteHash::Keccak256,
        &initial,
    )
    .unwrap();
    for (v, cap) in verifiers.iter().zip(&caps) {
        v.observe_commitment::<BabyBear, BabyBear>(&mut builder, &mut ch, cap)
            .unwrap();
    }
    let (_, mut token) = verifiers[0]
        .verify_at_with_continuation::<BabyBear, BabyBear>(
            &mut builder,
            ch,
            &caps[0],
            &row_points[0],
            &proofs[0],
        )
        .unwrap();
    for i in 1..3 {
        (_, token) = verifiers[i]
            .verify_at_after_queries::<BabyBear, BabyBear>(
                &mut builder,
                token,
                &caps[i],
                &row_points[i],
                &proofs[i],
            )
            .unwrap();
    }
    let observation = 43u64
        .to_le_bytes()
        .map(|b| builder.define_const(BabyBear::from_u8(b)));
    let mut ch = token
        .resume_with_observation::<BabyBear, BabyBear>(&mut builder, &observation)
        .unwrap();
    let bytes = ch
        .sample_bytes::<BabyBear, BabyBear>(&mut builder, 8)
        .unwrap();
    let mut bits = [p3_circuit::ExprId::ZERO; 128];
    for (i, byte) in bytes.into_iter().enumerate() {
        bits[8 * i..8 * i + 8]
            .copy_from_slice(&builder.decompose_to_bits::<BabyBear>(byte, 8).unwrap());
    }
    let actual = builder.binary128_from_bits(bits).unwrap();
    for (&a, &b) in actual.bits().iter().zip(expected.bits()) {
        let difference = if b == p3_circuit::ExprId::ZERO {
            builder.sub(b, a)
        } else {
            builder.sub(a, b)
        };
        builder.assert_zero(difference);
    }
    let circuit = builder.build().unwrap();
    for seed in [2u64, 19] {
        let make = || keccak::LevelChallenger::<E>::from_hasher(vec![9; 3], keccak::byte_hash());
        let mut prover = make();
        let mut caps = Vec::new();
        let mut retained = Vec::new();
        for i in 0..3 {
            let table = Table::new(RowMajorMatrix::new(
                (0..128)
                    .map(|j| {
                        if (seed + 7 * i + j).count_ones() & 1 == 0 {
                            E::ZERO
                        } else {
                            E::ONE
                        }
                    })
                    .collect(),
                64,
            ));
            let (cap, data) = pcs.commit(vec![table], &mut prover).unwrap();
            caps.push(cap);
            retained.push(data);
        }
        let points = (0..3)
            .map(|i| {
                vec![Point::new(
                    (0..6)
                        .map(|j| {
                            E::from_repr(0x4365978214af97bdu64.wrapping_mul(seed + 13 * i + j + 1))
                        })
                        .collect(),
                )]
            })
            .collect::<Vec<_>>();
        let proofs = retained
            .into_iter()
            .enumerate()
            .map(|(i, data)| {
                pcs.open_at(data, &protocols[i], &points[i], &mut prover)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let mut entry = make();
        for cap in &caps {
            pcs.observe_commitment(cap, &mut entry);
        }
        let mut verifier = entry.clone();
        let mut inputs = Vec::new();
        for i in 0..3 {
            pcs.verify_at(
                &caps[i],
                &proofs[i],
                &protocols[i],
                &points[i],
                &mut verifier,
            )
            .unwrap();
            inputs.push(
                verifiers[i]
                    .import_native(&mmcs, &mmcs, &caps[i], &points[i], &proofs[i], &mut entry)
                    .unwrap(),
            );
        }
        entry.observe(E::from_repr(43));
        verifier.observe(E::from_repr(43));
        let expected = verifier.sample_algebra_element::<E>().to_repr() as u128;
        assert_eq!(
            entry.sample_algebra_element::<E>().to_repr() as u128,
            expected
        );
        let pack = |raw: u128| (0..8).map(move |j| BabyBear::from_u16((raw >> (16 * j)) as u16));
        let mut values = caps
            .iter()
            .flat_map(|c| {
                bytes_to_limbs(&c.roots()[0])
                    .into_iter()
                    .map(BabyBear::from_u16)
            })
            .collect::<Vec<_>>();
        for i in 0..3 {
            values.extend(
                points[i][0]
                    .as_slice()
                    .iter()
                    .flat_map(|&v| pack(v.to_repr() as u128)),
            );
            values.extend(inputs[i].private_values::<BabyBear>(&shapes[i]).unwrap());
        }
        values.extend(pack(expected));
        assert!(run(&circuit, &values));
        let last = values.len() - 8;
        values[last] += BabyBear::ONE;
        assert!(!run(&circuit, &values));
    }
}
