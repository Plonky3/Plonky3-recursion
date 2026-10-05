//! Complete released additive WHIR tower proofs in prime-field circuits.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField32, BinaryField128, TowerLevel};
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_challenger::FieldChallenger;
use p3_circuit::ops::{ByteHash, bytes_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::point::Point;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{BinaryWhirVerifier, RecursiveBinaryTowerField};
use p3_sumcheck::layout::{Layout, PrefixProver, SuffixProver, Table};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
use p3_test_utils::binary_field_params::{blake3, keccak};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};

fn run(circuit: &Circuit<BabyBear>, values: &[BabyBear]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(values).unwrap();
    runner.run().is_ok()
}

macro_rules! check {
    ($f:ty, $params:ident, $hash:expr, $layout:ident, $protocol:expr, $folding:expr) => {
        check!(
            $f,
            $params,
            $hash,
            $layout,
            $protocol,
            ProtocolParameters {
                security_level: 8,
                pow_bits: 0,
                round_log_inv_rates: vec![],
                folding_factor: $folding,
                soundness_type: SecurityAssumption::JohnsonBound,
                starting_log_inv_rate: 1,
            },
            0
        )
    };
    ($f:ty, $params:ident, $hash:expr, $layout:ident, $protocol:expr, $parameters:expr, $cap_height:expr) => {{
        type F = $f;
        type E = BinaryField128;
        type Ch = $params::LevelChallenger<F>;
        type L = $layout<F, E>;
        let protocol = $protocol;
        let n = p3_sumcheck::layout::plan_stacked_layout(&protocol.table_shapes()).0;
        let domain = BinaryWhirDomain::<F>::default();
        let config = WhirConfig::<E, F, Ch>::new_with_domain(n, $parameters, &domain).unwrap();
        let mmcs = $params::LevelMmcs::<F>::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            $cap_height,
        );
        let pcs = WhirProver::<E, F, _, _, Ch, L>::new(config.clone(), domain, mmcs.clone());
        let recursive = BinaryWhirVerifier::<F>::new(
            &config,
            protocol.clone(),
            L::variable_order(),
            $hash,
            $cap_height,
        )
        .unwrap();
        let shape = recursive.input_shape();
        let mut b = CircuitBuilder::<BabyBear>::new();
        match $hash {
            ByteHash::Keccak256 => b.enable_keccak_f1600::<BabyBear>(),
            ByteHash::Blake3 => b.enable_blake3_compress::<BabyBear>(),
        }
        let cap = (0..1usize << $cap_height)
            .map(|_| b.alloc_private_input_array::<16>("WHIR cap").to_vec())
            .collect::<Vec<_>>();
        let points = protocol
            .iter_openings()
            .map(|(table, _)| {
                (0..protocol.table_shapes()[table].num_variables())
                    .map(|_| {
                        let limbs = b.alloc_private_input_array::<8>("WHIR point coordinate");
                        b.binary128_from_limbs::<BabyBear>(limbs).unwrap()
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        let proof = shape
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
            .observe_commitment::<BabyBear, BabyBear>(&mut b, &mut ch, &cap)
            .unwrap();
        let (_, mut ch) = recursive
            .verify_at::<BabyBear, BabyBear>(&mut b, ch, &cap, &points, &proof)
            .unwrap();
        let actual = ch.sample::<BabyBear, BabyBear>(&mut b).unwrap();
        let expected = b.alloc_private_input_array::<8>("native WHIR continuation");
        let expected = b.binary128_from_limbs::<BabyBear>(expected).unwrap();
        for (&a, &e) in actual.bits().iter().zip(expected.bits()) {
            let difference = b.sub(a, e);
            b.assert_zero(difference);
        }
        let circuit = b.build().unwrap();
        let mut last_values = vec![];
        for seed in [2u128, 19] {
            let make = || Ch::from_hasher(vec![9; 3], $params::byte_hash());
            let tables = protocol
                .table_shapes()
                .iter()
                .enumerate()
                .map(|(table, shape)| {
                    Table::new(RowMajorMatrix::new(
                        (0..shape.width() * (1 << shape.num_variables()))
                            .map(|i| {
                                F::from_le_byte_iter(
                                    0x492f307c9bfa3e514379dc5a1b279591u128
                                        .wrapping_mul(seed + i as u128 + 17 * table as u128)
                                        .to_le_bytes()
                                        .into_iter(),
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
                                E::from_repr(
                                    0x693acef7331531cd976110953785aecdu128
                                        .wrapping_mul(seed + j as u128 + 23 * opening as u128),
                                )
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
            let expected = verifier.sample_algebra_element::<E>().to_repr();
            assert_eq!(entry.sample_algebra_element::<E>().to_repr(), expected);
            let other_order = if L::variable_order() == p3_sumcheck::strategy::VariableOrder::Prefix
            {
                p3_sumcheck::strategy::VariableOrder::Suffix
            } else {
                p3_sumcheck::strategy::VariableOrder::Prefix
            };
            let other = BinaryWhirVerifier::<F>::new(
                &config,
                protocol.clone(),
                other_order,
                $hash,
                $cap_height,
            )
            .unwrap();
            assert!(
                imported
                    .private_values::<BabyBear>(&other.input_shape())
                    .is_err()
            );
            let pack =
                |raw: u128| (0..8).map(move |i| BabyBear::from_u16((raw >> (16 * i)) as u16));
            let mut values = commitment
                .roots()
                .iter()
                .flat_map(|root| bytes_to_limbs(root).into_iter().map(BabyBear::from_u16))
                .collect::<Vec<_>>();
            values.extend(
                points
                    .iter()
                    .flat_map(|p| p.iter())
                    .flat_map(|&v| pack(v.to_repr())),
            );
            let proof_start = values.len();
            values.extend(imported.private_values::<BabyBear>(&shape).unwrap());
            values.extend(pack(expected));
            assert!(run(&circuit, &values));
            let cap_limbs = commitment.roots().len() * 16;
            let sc_start = proof_start
                + 8 * (protocol.checked_num_claims().unwrap()
                    + native_proof.whir.initial_ood_answers.len());
            let first_tail = sc_start
                + 8 * (2 * native_proof
                    .whir
                    .initial_sumcheck
                    .polynomial_evaluations
                    .len()
                    + native_proof.whir.initial_sumcheck.pow_witnesses.len());
            let row_start = first_tail
                + if let Some(round) = native_proof.whir.rounds.first() {
                    16 * round.commitment.as_ref().unwrap().roots().len()
                        + 8 * (round.ood_answers.len() + 1)
                } else {
                    8 * (native_proof
                        .whir
                        .final_poly
                        .as_ref()
                        .unwrap()
                        .as_slice()
                        .len()
                        + 1)
                };
            for at in [
                0,
                cap_limbs,
                proof_start,
                sc_start,
                row_start,
                values.len() - 8,
            ] {
                let mut wrong = values.clone();
                wrong[at] += BabyBear::ONE;
                assert!(!run(&circuit, &wrong));
            }
            if F::RAW_BITS == 32 {
                let mut wrong = values.clone();
                wrong[row_start + 2] = BabyBear::ONE;
                assert!(!run(&circuit, &wrong));
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
                unchanged.sample_algebra_element::<E>(),
                before.sample_algebra_element::<E>()
            );
            let mut malformed = native_proof.clone();
            malformed.whir.initial_sumcheck.polynomial_evaluations.pop();
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
                unchanged.sample_algebra_element::<E>(),
                before.sample_algebra_element::<E>()
            );
            last_values = values;
        }
        (circuit, last_values)
    }};
}

fn protocol(rows: usize, width: usize, next: bool) -> OpeningProtocol {
    OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(rows, width),
        vec![OpeningBatch::new(
            (0..width).collect(),
            if next { vec![width - 1] } else { vec![] },
        )],
    )])
}

#[test]
fn initial_and_closing_folds_match_native_tower128_prefix() {
    check!(
        BinaryField128,
        keccak,
        ByteHash::Keccak256,
        PrefixProver,
        protocol(3, 1, false),
        FoldingFactor::Constant(2)
    );
}

#[test]
fn narrow_tower32_rows_match_native_suffix_extension_openings() {
    check!(
        BinaryField32,
        keccak,
        ByteHash::Keccak256,
        SuffixProver,
        protocol(8, 2, true),
        FoldingFactor::Constant(2)
    );
}

#[test]
fn intermediate_rounds_match_native_blake3_prefix() {
    check!(
        BinaryField128,
        blake3,
        ByteHash::Blake3,
        PrefixProver,
        protocol(9, 1, true),
        FoldingFactor::Constant(2)
    );
}

#[test]
fn zero_closing_rounds_match_native_with_leaf_level_caps() {
    check!(
        BinaryField128,
        keccak,
        ByteHash::Keccak256,
        SuffixProver,
        protocol(2, 1, true),
        ProtocolParameters {
            security_level: 8,
            pow_bits: 0,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(2),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: 1,
        },
        1
    );
}

#[test]
fn varied_table_heights_and_mixed_openings_follow_native_batching_order() {
    let protocol = OpeningProtocol::new(vec![
        TableSpec::new(
            TableShape::new(4, 2),
            vec![
                OpeningBatch::new(vec![1], vec![0, 1]),
                OpeningBatch::new(vec![1, 0], vec![]),
            ],
        ),
        TableSpec::new(
            TableShape::new(6, 1),
            vec![OpeningBatch::new(vec![0], vec![])],
        ),
        TableSpec::new(TableShape::new(3, 1), vec![]),
    ]);
    let keccak_protocol = protocol.clone();
    check!(
        BinaryField128,
        keccak,
        ByteHash::Keccak256,
        SuffixProver,
        keccak_protocol,
        FoldingFactor::Constant(2)
    );
    check!(
        BinaryField32,
        blake3,
        ByteHash::Blake3,
        PrefixProver,
        protocol,
        FoldingFactor::Constant(2)
    );
}

#[test]
fn full_additive_whir_opening_proves_in_a_prime_field_circuit() {
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover,
    };
    use p3_circuit_prover::{ConstraintProfile, config};
    let (circuit, values) = check!(
        BinaryField128,
        keccak,
        ByteHash::Keccak256,
        PrefixProver,
        protocol(3, 1, false),
        FoldingFactor::Constant(2)
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
fn native_positive_pow_uses_narrow_base_witnesses_in_both_fold_and_query_phases() {
    check!(
        BinaryField32,
        keccak,
        ByteHash::Keccak256,
        SuffixProver,
        protocol(3, 1, false),
        ProtocolParameters {
            security_level: 114,
            pow_bits: 8,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(2),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: 1,
        },
        0
    );
}

#[test]
fn positive_closing_pow_matches_the_native_narrow_witness_transcript() {
    check!(
        BinaryField32,
        keccak,
        ByteHash::Keccak256,
        PrefixProver,
        protocol(2, 1, false),
        ProtocolParameters {
            security_level: 128,
            pow_bits: 4,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(1),
            soundness_type: SecurityAssumption::UniqueDecoding,
            starting_log_inv_rate: 1,
        },
        0
    );
}

#[test]
fn two_intermediate_rounds_preserve_repeated_stratified_query_rows() {
    check!(
        BinaryField128,
        keccak,
        ByteHash::Keccak256,
        SuffixProver,
        protocol(9, 1, false),
        ProtocolParameters {
            security_level: 12,
            pow_bits: 4,
            round_log_inv_rates: vec![2, 1],
            folding_factor: FoldingFactor::PerRound(vec![1, 1, 3]),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: 1,
        },
        0
    );
}

#[test]
fn trusted_whir_geometry_and_aggregate_limits_reject_before_allocation() {
    use p3_recursion::verifier::{VerificationError, VerifierLimits};
    use p3_sumcheck::strategy::VariableOrder;
    type F = BinaryField32;
    let domain = BinaryWhirDomain::<F>::default();
    let config = WhirConfig::<BinaryField128, F, keccak::LevelChallenger<F>>::new_with_domain(
        11,
        ProtocolParameters {
            security_level: 8,
            pow_bits: 0,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(4),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: 1,
        },
        &domain,
    )
    .unwrap();
    assert_eq!(config.n_rounds(), 1);
    let make = |protocol, cap, limits: &VerifierLimits| {
        BinaryWhirVerifier::<F>::with_limits(
            &config,
            protocol,
            VariableOrder::Prefix,
            ByteHash::Keccak256,
            cap,
            limits,
        )
    };
    let defaults = VerifierLimits::default();
    assert!(make(protocol(10, 1, false), 0, &defaults).is_err());
    assert!(make(protocol(11, 1, false), 8, &defaults).is_err());
    let limits = VerifierLimits {
        max_total_scalar_elements: 128,
        ..defaults
    };
    assert!(matches!(
        make(protocol(11, 1, false), 0, &limits),
        Err(VerificationError::ResourceLimitExceeded {
            component: "scalar elements",
            ..
        })
    ));
    let limits = VerifierLimits {
        max_matrix_width: 16,
        ..defaults
    };
    assert!(matches!(
        make(protocol(11, 1, false), 0, &limits),
        Err(VerificationError::ResourceLimitExceeded {
            component: "binary WHIR native row width",
            ..
        })
    ));
}
