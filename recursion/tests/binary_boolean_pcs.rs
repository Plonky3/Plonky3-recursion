//! Released Boolean PCS proofs close their bit readings against a byte-tree commitment.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField64, BinaryField128, PackedGf2x64, TowerLevel};
use p3_binary_pcs::{
    BinaryPcsConfig, BinaryPcsParams, BitOpening, BooleanMultilinearPcs, BooleanPcs,
};
use p3_challenger::FieldChallenger;
use p3_circuit::ops::{ByteHash, bytes_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_field::PrimeCharacteristicRing;
use p3_multilinear_util::point::Point;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{
    BinaryBitRingVerifier, BinaryBooleanPcsVerifier, BinaryPcs128Verifier, BinaryRingClaimSpec,
    RecursiveBinaryTowerField,
};
use p3_recursion::verifier::{VerificationError, VerifierLimits};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, TableShape, TableSpec};
use p3_test_utils::binary_field_params::{blake3, keccak};

fn run(circuit: &Circuit<BabyBear>, values: &[BabyBear]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(values).unwrap();
    runner.run().is_ok()
}

macro_rules! fixture {
    ($native:ty, $params:ident, $hash:expr, $specs:expr, $prefix:expr, $seed:expr) => {{
        type E = $native;
        let absorbed = E::RAW_BITS.ilog2() as usize;
        let n = absorbed + 2;
        let prefix: usize = $prefix;
        let config = BinaryPcsConfig::try_new::<E, E>(
            2,
            BinaryPcsParams {
                log_inv_rate: 1,
                pow_bits: 0,
                security_level: 8,
            },
        )
        .unwrap();
        let mmcs = $params::LevelMmcs::<E>::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            0,
        );
        let pcs = BooleanPcs::<E, _, _>::new(config, mmcs.clone(), mmcs.clone(), n).unwrap();
        let verifier =
            BinaryBooleanPcsVerifier::<E>::new(config, $specs.to_vec(), $hash, 0, 64).unwrap();
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
        let imported = verifier
            .import_native(
                &mmcs,
                &mmcs,
                &cap,
                &points,
                &readings,
                &proof,
                entry.clone(),
            )
            .unwrap();
        let shape = verifier.input_shape();
        let other = BinaryBooleanPcsVerifier::<E>::new(config, $specs.to_vec(), $hash, 0, 65)
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
        let circuit = builder.build().unwrap();
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
                    &mmcs,
                    &mmcs,
                    &cap,
                    &points,
                    &readings,
                    &detached,
                    entry.clone()
                )
                .is_err()
        );
        let mut malformed = proof.clone();
        malformed.opening.sumcheck.polynomial_evaluations.pop();
        let mut unchanged = entry.clone();
        assert!(
            verifier
                .import_native(
                    &mmcs,
                    &mmcs,
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
            entry.sample_algebra_element::<E>()
        );
        (circuit, values, shape)
    }};
}

#[test]
fn boolean128_prefixes_reuse_one_checked_input_shape() {
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
fn boolean64_blake3_binds_batched_current_and_successor_readings() {
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
fn combined_resource_limit_covers_both_stages() {
    let config = BinaryPcsConfig::try_new::<BinaryField128, BinaryField128>(
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
    BinaryBitRingVerifier::<BinaryField128>::with_limits(9, specs.clone(), &limits).unwrap();
    BinaryPcs128Verifier::with_limits(
        config,
        OpeningProtocol::new(vec![TableSpec::new(
            TableShape::new(2, 1),
            vec![OpeningBatch::new(vec![0], vec![])],
        )]),
        ByteHash::Keccak256,
        0,
        64,
        &limits,
    )
    .unwrap();
    assert!(matches!(
        BinaryBooleanPcsVerifier::<BinaryField128>::with_limits(
            config,
            specs,
            ByteHash::Keccak256,
            0,
            64,
            &limits,
        ),
        Err(VerificationError::ResourceLimitExceeded {
            component: "scalar elements",
            ..
        })
    ));
}

#[test]
fn composed_boolean_opening_proves_in_a_prime_field_circuit() {
    use p3_circuit_prover::ConstraintProfile;
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover,
    };

    let specs = [BinaryRingClaimSpec {
        current: true,
        next_rows: None,
    }];
    let (circuit, values, _) = fixture!(BinaryField64, keccak, ByteHash::Keccak256, specs, 1, 31);
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

#[test]
#[ignore]
fn consecutive_boolean_openings_reuse_the_native_ring_entry() {
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
    let pcs = BooleanPcs::<E, _, _>::new(config, mmcs.clone(), mmcs.clone(), 7).unwrap();
    let verifier = BinaryBooleanPcsVerifier::<E>::new(
        config,
        vec![BinaryRingClaimSpec {
            current: true,
            next_rows: None,
        }],
        ByteHash::Keccak256,
        0,
        32,
    )
    .unwrap();
    let shape = verifier.input_shape();
    let mut builder = CircuitBuilder::<BabyBear>::new();
    builder.enable_keccak_f1600::<BabyBear>();
    let caps = (0..2)
        .map(|_| {
            vec![
                builder
                    .alloc_private_input_array::<16>("Boolean cap")
                    .to_vec(),
            ]
        })
        .collect::<Vec<_>>();
    let first = shape
        .allocate_targets::<BabyBear, BabyBear>(&mut builder)
        .unwrap();
    let second = shape
        .allocate_targets::<BabyBear, BabyBear>(&mut builder)
        .unwrap();
    let expected = builder.alloc_private_input_array::<8>("continued Boolean challenge");
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
    for cap in &caps {
        verifier
            .observe_commitment::<BabyBear, BabyBear>(&mut builder, &mut ch, cap)
            .unwrap();
    }
    let continuation = verifier
        .verify_readings_with_continuation::<BabyBear, BabyBear>(&mut builder, ch, &caps[0], &first)
        .unwrap();
    let continuation = verifier
        .verify_readings_after_queries::<BabyBear, BabyBear>(
            &mut builder,
            continuation,
            &caps[1],
            &second,
        )
        .unwrap();
    let observation = 29u64
        .to_le_bytes()
        .map(|b| builder.define_const(BabyBear::from_u8(b)));
    let mut ch = continuation
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
    for (seed, prefixes) in [(2u64, [0, 1]), (19, [1, 0])] {
        let make = || keccak::LevelChallenger::<E>::from_hasher(vec![9; 3], keccak::byte_hash());
        let mut prover = make();
        let mut native_caps = Vec::new();
        let mut data = Vec::new();
        for i in 0..2u64 {
            let bits = [
                PackedGf2x64::new(0x39244dfadb79d227u64.wrapping_mul(seed + i)),
                PackedGf2x64::new(0x9731364faf895fc7u64.wrapping_mul(seed + i)),
            ];
            let (cap, retained) = pcs.commit_bits(&bits, &mut prover).unwrap();
            native_caps.push(cap);
            data.push(retained);
        }
        let openings = prefixes.map(|prefix| {
            vec![BitOpening {
                point: Point::new(
                    (0..7)
                        .map(|j| {
                            if j < prefix {
                                E::ONE
                            } else {
                                E::from_repr(
                                    0x63914fcd278be173u64.wrapping_mul(1 + j as u64 + seed),
                                )
                            }
                        })
                        .collect(),
                ),
                row_variables: 7,
                current: true,
                next: false,
            }]
        });
        let mut proofs = Vec::new();
        let mut readings = Vec::new();
        for (retained, opening) in data.into_iter().zip(&openings) {
            let (values, proof) = pcs.open_readings(retained, opening, &mut prover).unwrap();
            readings.push(values);
            proofs.push(proof);
        }
        let mut entry = make();
        for cap in &native_caps {
            pcs.observe_commitment(cap, &mut entry);
        }
        let mut native_verifier = entry.clone();
        let mut inputs = Vec::new();
        for i in 0..2 {
            pcs.verify_readings(
                &native_caps[i],
                &openings[i],
                &readings[i],
                &proofs[i],
                &mut native_verifier,
            )
            .unwrap();
            inputs.push(
                verifier
                    .import_native(
                        &mmcs,
                        &mmcs,
                        &native_caps[i],
                        &[openings[i][0].point.clone()],
                        &[(readings[i][0].current, readings[i][0].next)],
                        &proofs[i],
                        &mut entry,
                    )
                    .unwrap(),
            );
        }
        use p3_challenger::CanObserve;
        native_verifier.observe(E::from_repr(29));
        entry.observe(E::from_repr(29));
        let expected = native_verifier.sample_algebra_element::<E>().to_repr() as u128;
        assert_eq!(
            entry.sample_algebra_element::<E>().to_repr() as u128,
            expected
        );
        let mut values = native_caps
            .iter()
            .flat_map(|cap| {
                bytes_to_limbs(&cap.roots()[0])
                    .into_iter()
                    .map(BabyBear::from_u16)
            })
            .collect::<Vec<_>>();
        for input in inputs {
            values.extend(input.private_values::<BabyBear>(&shape).unwrap());
        }
        values.extend((0..8).map(|i| BabyBear::from_u16((expected >> (16 * i)) as u16)));
        assert!(run(&circuit, &values));
        let mut wrong = values.clone();
        let last = wrong.len() - 8;
        wrong[last] += BabyBear::ONE;
        assert!(!run(&circuit, &wrong));
        if seed == 2 {
            use p3_circuit_prover::ConstraintProfile;
            use p3_circuit_prover::batch_stark_prover::{
                BatchStarkProver, KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover,
            };
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
    }
}
