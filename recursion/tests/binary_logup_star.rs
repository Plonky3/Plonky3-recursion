//! Indexed-lookup reductions with independently closed position and column claims.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField8, BinaryField64, BinaryField128};
use p3_challenger::{CanObserve, CanSample, CanSampleBits, FieldChallenger, GrindingChallenger};
use p3_circuit::ops::{BinaryTower128Target, ByteHash};
use p3_circuit::{Circuit, CircuitBuilder, ExprId};
use p3_field::{ExtensionField, PrimeCharacteristicRing};
use p3_multi_stark::fractional_gkr::{FractionGkrLayerProof, FractionGkrProof, SplitFraction};
use p3_multi_stark::logup_star::transcript::LogupStarTableShape;
use p3_multi_stark::logup_star::{
    LogupStarProof, Reader, ReaderWitness, TableLookup, TableWitness,
};
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{
    RecursiveBinaryChallengeField, RecursiveBinaryTowerField, binary128_eval_multilinear,
};
use p3_recursion::verifier::{
    BinaryLogupStarReaderTargets, BinaryLogupStarVerifier, VerificationError, VerifierLimits,
};
use p3_sumcheck::generic_degree::GenericDegreeProof;
use p3_test_utils::binary_field_params::{blake3, keccak};

fn equal(b: &mut CircuitBuilder<BabyBear>, a: &BinaryTower128Target, c: &BinaryTower128Target) {
    for (&a, &c) in a.bits().iter().zip(c.bits()) {
        let difference = if c == ExprId::ZERO {
            b.sub(c, a)
        } else {
            b.sub(a, c)
        };
        b.assert_zero(difference);
    }
}

fn closed_fixture<F, E, Ch>(
    hash: ByteHash,
    make: impl Fn() -> Ch,
    multiple: bool,
) -> (Circuit<BabyBear>, Vec<BabyBear>)
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
    Ch: FieldChallenger<F> + GrindingChallenger<Witness = F> + Clone,
{
    let mut tables = vec![LogupStarTableShape {
        num_variables: 1,
        width: 2,
        readers: vec![2, 1],
    }];
    if multiple {
        tables.push(LogupStarTableShape {
            num_variables: 2,
            width: 1,
            readers: vec![1],
        });
    }
    let verifier = BinaryLogupStarVerifier::<F, E>::new(&tables, 4).unwrap();
    let shape = verifier.input_shape();
    let mut raw_columns = vec![vec![vec![3u8, 7], vec![5, 11]]];
    let mut positions = vec![vec![vec![1usize, 0, 1, 1], vec![0, 1]]];
    if multiple {
        raw_columns.push(vec![vec![0, 5, 10, 19]]);
        positions.push(vec![vec![0, 3]]);
    }
    let columns: Vec<Vec<Vec<F>>> = raw_columns
        .into_iter()
        .map(|columns| {
            columns
                .into_iter()
                .map(|column| {
                    column
                        .into_iter()
                        .map(|byte| {
                            F::from_le_byte_iter(
                                core::iter::once(byte).chain(core::iter::repeat(0)),
                            )
                        })
                        .collect()
                })
                .collect()
        })
        .collect();
    let mut before = make();
    let points: Vec<Vec<_>> = tables
        .iter()
        .map(|table| {
            table
                .readers
                .iter()
                .map(|&height| {
                    Point::<E>::new(
                        (0..height)
                            .map(|_| before.sample_algebra_element::<E>())
                            .collect(),
                    )
                })
                .collect()
        })
        .collect();
    let claims: Vec<Vec<Vec<E>>> = positions
        .iter()
        .zip(&points)
        .zip(&columns)
        .map(|((positions, points), columns)| {
            positions
                .iter()
                .zip(points)
                .map(|(positions, point)| {
                    columns
                        .iter()
                        .map(|column| {
                            Poly::new(
                                positions
                                    .iter()
                                    .map(|&position| E::from(column[position]))
                                    .collect::<Vec<_>>(),
                            )
                            .eval_ext::<F>(point)
                        })
                        .collect()
                })
                .collect()
        })
        .collect();
    let readers: Vec<Vec<_>> = points
        .iter()
        .zip(&claims)
        .map(|(points, claims)| {
            points
                .iter()
                .zip(claims)
                .map(|(point, claims)| Reader { point, claims })
                .collect()
        })
        .collect();
    let lookups: Vec<_> = tables
        .iter()
        .zip(&readers)
        .map(|(table, readers)| TableLookup {
            num_variables: table.num_variables,
            readers,
        })
        .collect();
    let column_views: Vec<Vec<_>> = columns
        .iter()
        .map(|columns| columns.iter().map(Vec::as_slice).collect())
        .collect();
    let reader_witnesses: Vec<Vec<_>> = positions
        .iter()
        .map(|positions| {
            positions
                .iter()
                .map(|positions| ReaderWitness { positions })
                .collect()
        })
        .collect();
    let witness: Vec<_> = column_views
        .iter()
        .zip(&reader_witnesses)
        .map(|(columns, readers)| TableWitness { columns, readers })
        .collect();
    let (proof, proved) = LogupStarProof::<F, E>::prove(&lookups, &witness, &mut before.clone());
    let mut native = before.clone();
    assert_eq!(proof.verify(&lookups, &mut native).unwrap(), proved);
    let mut imported_ch = before.clone();
    let imported = verifier
        .import_native(&lookups, &proof, &mut imported_ch)
        .unwrap();
    let next = native.sample_algebra_element::<E>();
    assert_eq!(imported_ch.sample_algebra_element::<E>(), next);

    let mut b = CircuitBuilder::<BabyBear>::new();
    match hash {
        ByteHash::Keccak256 => b.enable_keccak_f1600::<BabyBear>(),
        ByteHash::Blake3 => b.enable_blake3_compress::<BabyBear>(),
    }
    let targets = shape
        .allocate_targets::<BabyBear, BabyBear>(&mut b)
        .unwrap();
    let initial = b.alloc_private_input_array::<3>("LogupStar initial transcript");
    let mut ch =
        BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(&mut b, hash, &initial)
            .unwrap();
    let mut reader_targets = Vec::new();
    for ((positions, table), columns) in positions.iter().zip(&tables).zip(&columns) {
        let mut table_targets = Vec::new();
        for (positions, &height) in positions.iter().zip(&table.readers) {
            let mut point = Vec::new();
            for _ in 0..height {
                let bytes = ch
                    .sample_bytes::<BabyBear, BabyBear>(&mut b, E::RAW_BITS / 8)
                    .unwrap();
                let mut bits = [ExprId::ZERO; 128];
                for (i, byte) in bytes.into_iter().enumerate() {
                    bits[8 * i..8 * i + 8]
                        .copy_from_slice(&b.decompose_to_bits::<BabyBear>(byte, 8).unwrap());
                }
                point.push(b.binary128_from_bits(bits).unwrap());
            }
            let claims = columns
                .iter()
                .map(|column| {
                    let pulled = positions
                        .iter()
                        .map(|&position| {
                            b.binary128_constant(column[position].raw_coordinates())
                                .unwrap()
                        })
                        .collect::<Vec<_>>();
                    binary128_eval_multilinear(&mut b, &pulled, &point).unwrap()
                })
                .collect();
            table_targets.push(BinaryLogupStarReaderTargets { point, claims });
        }
        reader_targets.push(table_targets);
    }
    let output = verifier
        .verify_reduction::<BabyBear, BabyBear>(&mut b, ch, &reader_targets, &targets)
        .unwrap();
    for (table_index, ((columns, positions), table)) in
        columns.iter().zip(&positions).zip(&tables).enumerate()
    {
        for (column, actual) in columns
            .iter()
            .zip(&output.tables[table_index].column_claims)
        {
            let values = column
                .iter()
                .map(|&value| b.binary128_constant(value.raw_coordinates()).unwrap())
                .collect::<Vec<_>>();
            let own = &output.table_point[output.table_point.len() - table.num_variables..];
            let expected = binary128_eval_multilinear(&mut b, &values, own).unwrap();
            equal(&mut b, actual, &expected);
        }
        for ((positions, &height), actual) in positions
            .iter()
            .zip(&table.readers)
            .zip(&output.tables[table_index].position_claims)
        {
            let values = positions
                .iter()
                .map(|&position| b.binary128_constant(position as u128).unwrap())
                .collect::<Vec<_>>();
            let own = &output.position_point[output.position_point.len() - height..];
            let expected = binary128_eval_multilinear(&mut b, &values, own).unwrap();
            equal(&mut b, actual, &expected);
        }
    }
    let mut ch = output.challenger;
    let bytes = ch
        .sample_bytes::<BabyBear, BabyBear>(&mut b, E::RAW_BITS / 8)
        .unwrap();
    let mut bits = [ExprId::ZERO; 128];
    for (i, byte) in bytes.into_iter().enumerate() {
        bits[8 * i..8 * i + 8].copy_from_slice(&b.decompose_to_bits::<BabyBear>(byte, 8).unwrap());
    }
    let actual = b.binary128_from_bits(bits).unwrap();
    let limbs = b.alloc_private_input_array::<8>("LogupStar native continuation");
    let expected = b.binary128_from_limbs::<BabyBear>(limbs).unwrap();
    equal(&mut b, &actual, &expected);
    let circuit = b.build().unwrap();
    let mut values = imported.private_values::<BabyBear>(&shape).unwrap();
    values.extend([7, 19, 13].map(BabyBear::from_u8));
    let raw = next.raw_coordinates();
    values.extend((0..8).map(|i| BabyBear::from_u16((raw >> (16 * i)) as u16)));
    let run = |values: &[BabyBear]| {
        let mut runner = circuit.runner();
        runner.set_private_inputs(values).unwrap();
        runner.run().is_ok()
    };
    let mut runner = circuit.runner();
    runner.set_private_inputs(&values).unwrap();
    runner
        .run()
        .expect("closed native LogUpStar reduction must verify");
    let root_index: usize = tables
        .iter()
        .map(|table| (1usize << table.num_variables) * 8)
        .sum();
    for index in [0, root_index, values.len() - 8] {
        let mut wrong = values.clone();
        wrong[index] += BabyBear::ONE;
        assert!(!run(&wrong));
    }
    if E::RAW_BITS == 64 {
        let mut wrong = values.clone();
        wrong[4] = BabyBear::ONE;
        assert!(!run(&wrong));
    }
    let unchanged = |bad| {
        let mut ch = before.clone();
        assert!(verifier.import_native(&lookups, &bad, &mut ch).is_err());
        assert_eq!(
            ch.sample_algebra_element::<E>(),
            before.clone().sample_algebra_element::<E>()
        );
    };
    let mut bad = proof.clone();
    bad.pushforwards[0].pop();
    unchanged(bad);
    let mut bad = proof.clone();
    bad.position_claims.pop();
    unchanged(bad);
    let mut bad = proof.clone();
    bad.column_claims[0].pop();
    unchanged(bad);
    let mut bad = proof.clone();
    bad.fraction_gkr.layers.pop();
    unchanged(bad);
    let mut bad = proof.clone();
    bad.pushforwards[0][0] += E::ONE;
    unchanged(bad);
    let mut bad = proof.clone();
    bad.position_claims[0] += E::ONE;
    unchanged(bad);
    let mut bad = proof.clone();
    bad.column_claims[0][0] += E::ONE;
    unchanged(bad);
    let mut bad = proof.clone();
    bad.product.pow_witnesses.push(F::ZERO);
    unchanged(bad);
    let foreign = BinaryLogupStarVerifier::<F, E>::new(&tables, 5).unwrap();
    assert!(
        imported
            .private_values::<BabyBear>(&foreign.input_shape())
            .is_err()
    );
    let mut bad_targets = targets.clone();
    bad_targets.pushforwards[0].pop();
    assert!(
        verifier
            .verify_reduction::<BabyBear, BabyBear>(
                &mut CircuitBuilder::new(),
                BinaryTower128Challenger::new(hash),
                &reader_targets,
                &bad_targets
            )
            .is_err()
    );
    (circuit, values)
}

#[test]
fn native_logup_star_binds_multiple_readers_and_unequal_points() {
    closed_fixture::<BinaryField8, BinaryField64, _>(
        ByteHash::Blake3,
        || blake3::LevelChallenger::from_hasher(vec![7, 19, 13], blake3::byte_hash()),
        true,
    );
}

#[test]
fn both_hashes_and_tower_widths_bind_padded_fraction_and_product_claims() {
    closed_fixture::<BinaryField8, BinaryField64, _>(
        ByteHash::Keccak256,
        || keccak::LevelChallenger::from_hasher(vec![7, 19, 13], keccak::byte_hash()),
        true,
    );
    closed_fixture::<BinaryField8, BinaryField128, _>(
        ByteHash::Keccak256,
        || keccak::LevelChallenger::from_hasher(vec![7, 19, 13], keccak::byte_hash()),
        true,
    );
    closed_fixture::<BinaryField8, BinaryField128, _>(
        ByteHash::Blake3,
        || blake3::LevelChallenger::from_hasher(vec![7, 19, 13], blake3::byte_hash()),
        true,
    );
    closed_fixture::<BinaryField128, BinaryField128, _>(
        ByteHash::Keccak256,
        || keccak::LevelChallenger::from_hasher(vec![7, 19, 13], keccak::byte_hash()),
        false,
    );
}

#[test]
fn a_closed_indexed_reduction_proves_in_a_prime_field_circuit() {
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, Blake3CompressAirBuilder, Blake3CompressPreprocessor,
        Blake3CompressProver,
    };
    use p3_circuit_prover::{ConstraintProfile, config};
    let (circuit, values) = closed_fixture::<BinaryField8, BinaryField64, _>(
        ByteHash::Blake3,
        || blake3::LevelChallenger::from_hasher(vec![7, 19, 13], blake3::byte_hash()),
        false,
    );
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

#[derive(Clone)]
struct ZeroChallenger {
    draws: usize,
}
impl CanObserve<BinaryField128> for ZeroChallenger {
    fn observe(&mut self, _: BinaryField128) {}
}
impl CanSample<BinaryField128> for ZeroChallenger {
    fn sample(&mut self) -> BinaryField128 {
        self.draws += 1;
        BinaryField128::ZERO
    }
}
impl CanSampleBits<usize> for ZeroChallenger {
    fn sample_bits(&mut self, _: usize) -> usize {
        panic!("indexed reduction has no bit samples")
    }
}
impl FieldChallenger<BinaryField128> for ZeroChallenger {}
impl GrindingChallenger for ZeroChallenger {
    type Witness = BinaryField128;
    fn grind(&mut self, _: usize) -> BinaryField128 {
        panic!("indexed reduction has no grinding")
    }
}

#[test]
fn zero_entry_draws_exhaust_a_finite_budget_without_advancing_the_caller() {
    type E = BinaryField128;
    let verifier = BinaryLogupStarVerifier::<E, E>::new(
        &[LogupStarTableShape {
            num_variables: 1,
            width: 1,
            readers: vec![1],
        }],
        2,
    )
    .unwrap();
    let point = Point::new(vec![E::ONE]);
    let claims = [E::ONE];
    let readers = [Reader {
        point: &point,
        claims: &claims,
    }];
    let lookups = [TableLookup {
        num_variables: 1,
        readers: &readers,
    }];
    let proof = LogupStarProof {
        pushforwards: vec![vec![E::ONE, E::ZERO]],
        fraction_gkr: FractionGkrProof {
            root_denominator: E::ONE,
            layers: (0..2)
                .map(|layer| FractionGkrLayerProof {
                    round_polys: vec![[E::ZERO; 3]; layer],
                    claims: SplitFraction {
                        n0: E::ZERO,
                        n1: E::ZERO,
                        d0: E::ONE,
                        d1: E::ONE,
                    },
                })
                .collect(),
        },
        position_claims: vec![E::ZERO],
        product: GenericDegreeProof {
            claimed_sum: E::ZERO,
            round_polys: vec![vec![E::ZERO; 2]],
            pow_witnesses: vec![],
        },
        column_claims: vec![vec![E::ONE]],
    };
    let mut ch = ZeroChallenger { draws: 0 };
    let error = verifier
        .import_native(&lookups, &proof, &mut ch)
        .unwrap_err();
    assert!(
        matches!(error, VerificationError::InvalidProofShape(message) if message.contains("draw budget exhausted"))
    );
    assert_eq!(ch.draws, 0);
}

#[test]
fn indexed_geometry_and_aggregate_work_are_checked_before_allocation() {
    let table = LogupStarTableShape {
        num_variables: 1,
        width: 2,
        readers: vec![2, 1],
    };
    let prepare = |tables: &[LogupStarTableShape], limits: &VerifierLimits| {
        BinaryLogupStarVerifier::<BinaryField8, BinaryField128>::with_limits(tables, 4, limits)
    };
    assert!(prepare(&[], &VerifierLimits::default()).is_err());
    for bad in [
        LogupStarTableShape {
            num_variables: 0,
            ..table.clone()
        },
        LogupStarTableShape {
            num_variables: 8,
            ..table.clone()
        },
        LogupStarTableShape {
            width: 0,
            ..table.clone()
        },
        LogupStarTableShape {
            readers: vec![],
            ..table.clone()
        },
        LogupStarTableShape {
            readers: vec![usize::MAX],
            ..table.clone()
        },
    ] {
        assert!(prepare(&[bad], &VerifierLimits::default()).is_err());
    }
    let usage = prepare(core::slice::from_ref(&table), &VerifierLimits::default())
        .unwrap()
        .input_resource_usage();
    for limits in [
        VerifierLimits {
            max_instances: usage.instances - 1,
            ..VerifierLimits::default()
        },
        VerifierLimits {
            max_rounds: usage.rounds - 1,
            ..VerifierLimits::default()
        },
        VerifierLimits {
            max_queries_per_round: 4,
            ..VerifierLimits::default()
        },
        VerifierLimits {
            max_total_scalar_elements: usage.scalar_elements - 1,
            ..VerifierLimits::default()
        },
        VerifierLimits {
            max_metadata_entries: usage.metadata_entries - 1,
            ..VerifierLimits::default()
        },
        VerifierLimits {
            max_final_poly_evaluations: 1,
            ..VerifierLimits::default()
        },
    ] {
        assert!(prepare(core::slice::from_ref(&table), &limits).is_err());
    }
    assert!(
        prepare(
            &[table],
            &VerifierLimits {
                max_metadata_entries: usage.metadata_entries,
                ..VerifierLimits::default()
            }
        )
        .is_ok()
    );
}

#[test]
fn repeated_reader_widths_cannot_overflow_native_coordinate_lengths() {
    let limits = VerifierLimits {
        max_instances: usize::MAX,
        max_rounds: usize::MAX,
        max_queries_per_round: usize::MAX,
        max_log_domain_or_degree: usize::BITS as usize - 1,
        max_matrix_width: usize::MAX,
        max_final_poly_evaluations: usize::MAX,
        max_cap_roots: usize::MAX,
        max_total_scalar_elements: usize::MAX,
        max_metadata_entries: usize::MAX,
        max_metadata_string_bytes: usize::MAX,
        max_compressed_frontier_hashes: usize::MAX,
        max_restored_authentication_path_hashes: usize::MAX,
    };
    let tables = [LogupStarTableShape {
        num_variables: 1,
        width: usize::MAX / 64,
        readers: vec![1; 16],
    }];
    assert!(matches!(
        BinaryLogupStarVerifier::<BinaryField8, BinaryField128>::with_limits(&tables, 32, &limits),
        Err(VerificationError::ResourceArithmeticOverflow {
            component: "binary indexed native statement coordinates"
        })
    ));
}
