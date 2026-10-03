//! Released Poly64→Poly192 WHIR proofs verified in prime-field circuits.

use p3_baby_bear::BabyBear;
use p3_binary_field::{Poly64, Poly192};
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_challenger::FieldChallenger;
use p3_circuit::ops::{ByteHash, bytes_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::point::Point;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::BinaryPolyWhirVerifier;
use p3_recursion::verifier::{VerificationError, VerifierLimits};
use p3_sumcheck::layout::{Layout, PrefixProver, SuffixProver, Table};
use p3_sumcheck::strategy::VariableOrder;
use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
use p3_test_utils::binary_field_params::{blake3, keccak};
use p3_whir::pcs::proof::QueryOpenings;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};

fn pack(value: Poly192) -> impl Iterator<Item = BabyBear> {
    value.coefficients().into_iter().flat_map(|coefficient| {
        (0..4).map(move |i| BabyBear::from_u16((coefficient.to_bits() >> (16 * i)) as u16))
    })
}

fn run(circuit: &Circuit<BabyBear>, values: &[BabyBear]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(values).unwrap();
    runner.run().is_ok()
}

fn protocol(height: usize, mixed: bool) -> OpeningProtocol {
    let mut specs = vec![TableSpec::new(
        TableShape::new(height, 1),
        vec![OpeningBatch::new(vec![0], vec![0])],
    )];
    if mixed {
        specs.push(TableSpec::new(
            TableShape::new(height - 2, 2),
            vec![OpeningBatch::new(vec![1, 0], vec![0])],
        ));
        specs.push(TableSpec::new(TableShape::new(height - 3, 1), vec![]));
    }
    OpeningProtocol::new(specs)
}

fn parameters(folding: FoldingFactor) -> ProtocolParameters {
    ProtocolParameters {
        security_level: 8,
        pow_bits: 0,
        round_log_inv_rates: vec![],
        folding_factor: folding,
        soundness_type: SecurityAssumption::JohnsonBound,
        starting_log_inv_rate: 1,
    }
}

macro_rules! check {
    ($params:ident, $hash:expr, $layout:ident, $protocol:expr, $parameters:expr, $cap:expr, $rounds:expr) => {{
        type Ch = $params::LevelChallenger<Poly64>;
        type L = $layout<Poly64, Poly192>;
        let protocol = $protocol;
        let n = p3_sumcheck::layout::plan_stacked_layout(&protocol.table_shapes()).0;
        let domain = BinaryWhirDomain::<Poly64>::default();
        let config =
            WhirConfig::<Poly192, Poly64, Ch>::new_with_domain(n, $parameters, &domain).unwrap();
        assert_eq!(config.n_rounds(), $rounds);
        if config.params().security_level >= 178 {
            assert!(config.starting_folding_pow_bits() > 0);
            assert!(config.terminal().pow_bits > 0);
        }
        if config.params().security_level == 192 {
            assert!(config.final_folding_pow_bits() > 0);
        }
        let mmcs = $params::LevelMmcs::<Poly64>::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            $cap,
        );
        let pcs =
            WhirProver::<Poly192, Poly64, _, _, Ch, L>::new(config.clone(), domain, mmcs.clone());
        let recursive = BinaryPolyWhirVerifier::new(
            &config,
            protocol.clone(),
            L::variable_order(),
            $hash,
            $cap,
        )
        .unwrap();
        let shape = recursive.input_shape();
        let mut b = CircuitBuilder::<BabyBear>::new();
        match $hash {
            ByteHash::Keccak256 => b.enable_keccak_f1600::<BabyBear>(),
            ByteHash::Blake3 => b.enable_blake3_compress::<BabyBear>(),
        }
        let cap = (0..1usize << $cap)
            .map(|_| b.alloc_private_input_array::<16>("Poly WHIR cap").to_vec())
            .collect::<Vec<_>>();
        let points = protocol
            .iter_openings()
            .map(|(table, _)| {
                (0..protocol.table_shapes()[table].num_variables())
                    .map(|_| {
                        let limbs = b.alloc_private_input_array::<12>("Poly WHIR point");
                        b.binary_poly192_from_limbs::<BabyBear>(limbs).unwrap()
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let proof = shape
            .allocate_targets::<BabyBear, BabyBear>(&mut b)
            .unwrap();
        // The resource plan accounts for the cap, prescribed points and proof.
        assert!(recursive.input_resource_usage().scalar_elements >= b.private_input_count());
        let initial = [9, 17, 221].map(|byte| b.define_const(BabyBear::from_u8(byte)));
        let mut ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
            &mut b, $hash, &initial,
        )
        .unwrap();
        recursive
            .observe_commitment::<BabyBear, BabyBear>(&mut b, &mut ch, &cap)
            .unwrap();
        let (_, mut ch) = recursive
            .verify_at::<BabyBear, BabyBear>(&mut b, ch, &cap, &points, &proof)
            .unwrap();
        let actual = ch.sample_poly192::<BabyBear, BabyBear>(&mut b).unwrap();
        let expected = b.alloc_private_input_array::<12>("Poly WHIR continuation");
        let expected = b.binary_poly192_from_limbs::<BabyBear>(expected).unwrap();
        for (actual, expected) in actual.coefficients().iter().zip(expected.coefficients()) {
            for (&a, &e) in actual.bits().iter().zip(expected.bits()) {
                let difference = b.sub(a, e);
                b.assert_zero(difference);
            }
        }
        let circuit = b.build().unwrap();
        let mut last = vec![];
        for seed in [2u64, 19] {
            let make = || Ch::from_hasher(vec![9, 17, 221], $params::byte_hash());
            let tables = protocol
                .table_shapes()
                .iter()
                .enumerate()
                .map(|(table, shape)| {
                    Table::new(RowMajorMatrix::new(
                        (0..shape.width() * (1 << shape.num_variables()))
                            .map(|i| {
                                Poly64::new(
                                    0x492f307c9bfa3e51u64
                                        .wrapping_mul(seed + i as u64 + 17 * table as u64),
                                )
                            })
                            .collect(),
                        1 << shape.num_variables(),
                    ))
                })
                .collect();
            let witness = L::new_witness(tables, config.round_folding_factor(0));
            let points = protocol
                .iter_openings()
                .enumerate()
                .map(|(opening, (table, _))| {
                    Point::new(
                        (0..protocol.table_shapes()[table].num_variables())
                            .map(|j| {
                                Poly192::new(core::array::from_fn(|k| {
                                    Poly64::new(0x693acef7331531cdu64.wrapping_mul(
                                        seed + j as u64 + 23 * opening as u64 + 91 * k as u64,
                                    ))
                                }))
                            })
                            .collect(),
                    )
                })
                .collect::<Vec<_>>();
            let mut prover = make();
            let (commitment, data) = pcs.commit(witness, &mut prover).unwrap();
            let native_proof = pcs.open_at(data, &protocol, &points, &mut prover).unwrap();
            let mut verifier = make();
            pcs.observe_commitment(&commitment, &mut verifier);
            pcs.verify_at(
                &commitment,
                &native_proof,
                &protocol,
                &points,
                &mut verifier,
            )
            .unwrap();
            let mut entry = make();
            pcs.observe_commitment(&commitment, &mut entry);
            let imported = recursive
                .import_native(
                    &config,
                    &mmcs,
                    &commitment,
                    &points,
                    &native_proof,
                    &mut entry,
                )
                .unwrap();
            let expected = verifier.sample_algebra_element::<Poly192>();
            assert_eq!(entry.sample_algebra_element::<Poly192>(), expected);
            let mut values = commitment
                .roots()
                .iter()
                .flat_map(|root| bytes_to_limbs(root).into_iter().map(BabyBear::from_u16))
                .collect::<Vec<_>>();
            values.extend(
                points
                    .iter()
                    .flat_map(|point| point.iter())
                    .flat_map(|&value| pack(value)),
            );
            let proof_start = values.len();
            values.extend(imported.private_values::<BabyBear>(&shape).unwrap());
            let proof_end = values.len();
            values.extend(pack(expected));
            assert!(run(&circuit, &values));
            let mut corrupt = vec![0, commitment.roots().len() * 16, proof_start, proof_end];
            let mut offset = proof_start
                + 12 * (protocol.checked_num_claims().unwrap()
                    + native_proof.whir.initial_ood_answers.len());
            corrupt.push(offset);
            offset += 24
                * native_proof
                    .whir
                    .initial_sumcheck
                    .polynomial_evaluations
                    .len()
                + 4 * native_proof.whir.initial_sumcheck.pow_witnesses.len();
            let mut saw_extension = false;
            for i in 0..=native_proof.whir.rounds.len() {
                let (openings, sumcheck) = if let Some(round) = native_proof.whir.rounds.get(i) {
                    offset += 16 * round.commitment.as_ref().unwrap().roots().len()
                        + 12 * round.ood_answers.len()
                        + 4;
                    (&round.openings, Some(&round.sumcheck))
                } else {
                    corrupt.push(offset);
                    offset += 12
                        * native_proof
                            .whir
                            .final_poly
                            .as_ref()
                            .unwrap()
                            .as_slice()
                            .len()
                        + 4;
                    (
                        &native_proof.whir.final_openings,
                        native_proof.whir.final_sumcheck.as_ref(),
                    )
                };
                let (queries, width) = match openings {
                    QueryOpenings::Base(opening) => {
                        assert_eq!(i, 0);
                        corrupt.push(offset + 3);
                        (opening.rows.len(), opening.rows[0].len() * 4)
                    }
                    QueryOpenings::Extension(opening) => {
                        assert!(i > 0);
                        assert!(
                            opening
                                .rows
                                .iter()
                                .flatten()
                                .any(|v| v.coefficients()[1] != Poly64::ZERO
                                    && v.coefficients()[2] != Poly64::ZERO)
                        );
                        saw_extension = true;
                        corrupt.extend([offset, offset + 4, offset + 8]);
                        (opening.rows.len(), opening.rows[0].len() * 12)
                    }
                };
                offset += queries * width;
                let site = config
                    .round_parameters()
                    .get(i)
                    .cloned()
                    .unwrap_or_else(|| config.final_round_config());
                let path_len = site.log_folded_domain_size - $cap;
                if path_len > 0 {
                    corrupt.push(offset);
                }
                offset += queries * path_len * 16;
                if let Some(sumcheck) = sumcheck {
                    offset += 24 * sumcheck.polynomial_evaluations.len()
                        + 4 * sumcheck.pow_witnesses.len();
                }
            }
            assert_eq!(offset, proof_end);
            assert_eq!(saw_extension, $rounds > 0);
            for at in corrupt {
                let mut wrong = values.clone();
                wrong[at] += BabyBear::ONE;
                assert!(!run(&circuit, &wrong), "accepted corrupt limb {at}");
            }
            let mut malformed = native_proof.clone();
            malformed.whir.final_poly = None;
            let mut unchanged = make();
            pcs.observe_commitment(&commitment, &mut unchanged);
            let mut before = unchanged.clone();
            assert!(
                recursive
                    .import_native(
                        &config,
                        &mmcs,
                        &commitment,
                        &points,
                        &malformed,
                        &mut unchanged
                    )
                    .is_err()
            );
            assert_eq!(
                unchanged.sample_algebra_element::<Poly192>(),
                before.sample_algebra_element::<Poly192>()
            );
            let mut malformed = native_proof.clone();
            let (rows, frontier) = match &mut malformed.whir.final_openings {
                QueryOpenings::Base(opening) => (opening.rows.len(), &mut opening.proof),
                QueryOpenings::Extension(opening) => (opening.rows.len(), &mut opening.proof),
            };
            let depth = config.final_round_config().log_folded_domain_size - $cap;
            frontier.sibling_hashes.resize(rows * depth + 1, [0; 32]);
            let mut unchanged = make();
            pcs.observe_commitment(&commitment, &mut unchanged);
            let mut before = unchanged.clone();
            assert!(matches!(
                recursive.import_native(
                    &config,
                    &mmcs,
                    &commitment,
                    &points,
                    &malformed,
                    &mut unchanged
                ),
                Err(VerificationError::ResourceLimitExceeded {
                    component: "binary Poly WHIR frontier",
                    ..
                })
            ));
            assert_eq!(
                unchanged.sample_algebra_element::<Poly192>(),
                before.sample_algebra_element::<Poly192>()
            );
            let mut malformed = native_proof.clone();
            let frontier = match &mut malformed.whir.final_openings {
                QueryOpenings::Base(opening) => &mut opening.proof,
                QueryOpenings::Extension(opening) => &mut opening.proof,
            };
            if frontier.sibling_hashes.pop().is_some() {
                let mut unchanged = make();
                pcs.observe_commitment(&commitment, &mut unchanged);
                let mut before = unchanged.clone();
                assert!(
                    recursive
                        .import_native(
                            &config,
                            &mmcs,
                            &commitment,
                            &points,
                            &malformed,
                            &mut unchanged
                        )
                        .is_err()
                );
                assert_eq!(
                    unchanged.sample_algebra_element::<Poly192>(),
                    before.sample_algebra_element::<Poly192>()
                );
            }
            let other_order = if L::variable_order() == VariableOrder::Prefix {
                VariableOrder::Suffix
            } else {
                VariableOrder::Prefix
            };
            let other =
                BinaryPolyWhirVerifier::new(&config, protocol.clone(), other_order, $hash, $cap)
                    .unwrap();
            assert!(
                imported
                    .private_values::<BabyBear>(&other.input_shape())
                    .is_err()
            );
            last = values;
        }
        (circuit, last)
    }};
}

#[test]
fn polynomial_prefix_whir_verifies_and_proves_in_a_prime_field() {
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover,
    };
    use p3_circuit_prover::{ConstraintProfile, config};
    let (circuit, values) = check!(
        keccak,
        ByteHash::Keccak256,
        PrefixProver,
        protocol(3, false),
        parameters(FoldingFactor::Constant(2)),
        0,
        0
    );
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
fn polynomial_suffix_mixed_folds_authenticate_every_extension_coefficient() {
    let mut params = parameters(FoldingFactor::PerRound(vec![1, 1, 3]));
    params.security_level = 12;
    params.pow_bits = 4;
    params.round_log_inv_rates = vec![2, 1];
    check!(
        blake3,
        ByteHash::Blake3,
        SuffixProver,
        protocol(9, false),
        params,
        0,
        2
    );
}

#[test]
fn polynomial_leaf_caps_and_absent_closing_fold_follow_native() {
    check!(
        blake3,
        ByteHash::Blake3,
        SuffixProver,
        protocol(2, false),
        parameters(FoldingFactor::Constant(2)),
        1,
        0
    );
}

#[test]
fn polynomial_positive_initial_fold_and_query_pow_use_poly64_witnesses() {
    let mut params = parameters(FoldingFactor::Constant(2));
    params.security_level = 178;
    params.pow_bits = 8;
    check!(
        keccak,
        ByteHash::Keccak256,
        SuffixProver,
        protocol(3, false),
        params,
        0,
        0
    );
}

#[test]
fn polynomial_positive_closing_pow_uses_the_native_base_witness_width() {
    let mut params = parameters(FoldingFactor::Constant(1));
    params.security_level = 192;
    params.pow_bits = 4;
    params.soundness_type = SecurityAssumption::UniqueDecoding;
    // At full field-width security, initial batching has room for one claim.
    let protocol = OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(2, 1),
        vec![OpeningBatch::new(vec![0], vec![])],
    )]);
    check!(
        blake3,
        ByteHash::Blake3,
        PrefixProver,
        protocol,
        params,
        0,
        0
    );
}

#[test]
fn polynomial_varied_tables_and_opening_order_follow_native_layout() {
    check!(
        keccak,
        ByteHash::Keccak256,
        PrefixProver,
        protocol(5, true),
        parameters(FoldingFactor::Constant(2)),
        0,
        0
    );
}

#[test]
fn polynomial_whir_bounds_price_cubic_extension_rows_and_192_bit_challenges() {
    let config = WhirConfig::<Poly192, Poly64, keccak::LevelChallenger<Poly64>>::new_with_domain(
        9,
        parameters(FoldingFactor::Constant(1)),
        &BinaryWhirDomain::<Poly64>::default(),
    )
    .unwrap();
    let make = |limits: &VerifierLimits| {
        BinaryPolyWhirVerifier::with_limits(
            &config,
            protocol(9, false),
            VariableOrder::Prefix,
            ByteHash::Keccak256,
            0,
            limits,
        )
    };
    let defaults = VerifierLimits::default();
    let plan = make(&defaults).unwrap();
    let limits = VerifierLimits {
        max_matrix_width: 4,
        ..defaults
    };
    assert!(matches!(
        make(&limits),
        Err(VerificationError::ResourceLimitExceeded {
            component: "binary WHIR native row width",
            ..
        })
    ));
    let limits = VerifierLimits {
        max_total_scalar_elements: plan.input_resource_usage().scalar_elements - 1,
        ..defaults
    };
    assert!(matches!(
        make(&limits),
        Err(VerificationError::ResourceLimitExceeded {
            component: "scalar elements",
            ..
        })
    ));
}

#[test]
fn polynomial_whir_rejects_pow_that_native_grinding_cannot_produce() {
    let mut params = parameters(FoldingFactor::Constant(1));
    params.security_level = 248;
    params.pow_bits = 64;
    params.soundness_type = SecurityAssumption::UniqueDecoding;
    let config = WhirConfig::<Poly192, Poly64, keccak::LevelChallenger<Poly64>>::new_with_domain(
        2,
        params,
        &BinaryWhirDomain::<Poly64>::default(),
    )
    .unwrap();
    assert!(config.max_pow_bits() > 56 && config.max_pow_bits() <= 64);
    let protocol = OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(2, 1),
        vec![OpeningBatch::new(vec![0], vec![])],
    )]);
    assert!(matches!(
        BinaryPolyWhirVerifier::new(
            &config,
            protocol,
            VariableOrder::Prefix,
            ByteHash::Keccak256,
            0
        ),
        Err(VerificationError::ResourceLimitExceeded {
            component: "binary WHIR native grinding bits",
            limit: 56,
            ..
        })
    ));
}
