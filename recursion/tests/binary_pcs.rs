//! Full native binary PCS openings verified by a prime-field circuit.

use p3_baby_bear::BabyBear;
use p3_binary_field::{
    BinaryChallenger, BinaryField8, BinaryField16, BinaryField32, BinaryField64, BinaryField128,
    TowerLevel,
};
use p3_binary_pcs::transcript::{BinaryPcsShape, BinaryPcsVerifierTranscript};
use p3_binary_pcs::{BinaryPcs, BinaryPcsConfig, BinaryPcsParams};
use p3_challenger::FieldChallenger;
use p3_circuit::ops::{BinaryTower128Target, ByteHash, bytes_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder, ExprId};
use p3_commit::MultilinearPcs;
use p3_field::extension::BinomialExtensionField;
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing};
use p3_matrix::Dimensions;
use p3_matrix::dense::RowMajorMatrix;
use p3_multilinear_util::point::Point;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{
    BinaryOracleOpeningTargets, BinaryPcs128ProofTargets, BinaryPcs128Verifier, BinaryPcsVerifier,
    RecursiveBinaryChallengeField, RecursiveBinaryTowerField,
};
use p3_sumcheck::layout::{Layout, SuffixProver, Table, Verifier};
use p3_sumcheck::strategy::Basis;
use p3_sumcheck::{
    OpeningBatch, OpeningProtocol, PrescribedPointPcs, SumcheckData, TableShape, TableSpec,
};
use p3_test_utils::binary_field_params::{blake3, keccak};

type Host = BinomialExtensionField<BabyBear, 4>;
type Native = BinaryField128;

fn batches(config: &BinaryPcsConfig) -> impl Iterator<Item = (usize, usize)> + '_ {
    (0..config.num_variables())
        .step_by(config.log_folding_factor())
        .map(|start| {
            (
                start,
                config
                    .log_folding_factor()
                    .min(config.num_variables() - start),
            )
        })
}

struct Fixture {
    config: BinaryPcsConfig,
    protocol: OpeningProtocol,
    cap: Vec<[u8; 32]>,
    sumcheck: Vec<[Native; 2]>,
    evals: Vec<OpeningBatch<Native>>,
    rounds: Vec<(Vec<[u8; 32]>, Vec<Native>, Vec<Vec<[u8; 32]>>)>,
    base_rows: Vec<Native>,
    base_paths: Vec<Vec<[u8; 32]>>,
    final_word: Vec<Native>,
    pow_witness: Native,
    queries: Vec<usize>,
}

macro_rules! fixture {
    ($params:ident, $seed:expr, $n:expr, $k:expr, $cap_height:expr) => {
        fixture!($params, $seed, $n, $k, $cap_height, vec![($n, 1)])
    };
    ($params:ident, $seed:expr, $n:expr, $k:expr, $cap_height:expr, $shapes:expr) => {{ fixture!($params, $seed, $n, $k, $cap_height, $shapes, 0) }};
    ($params:ident, $seed:expr, $n:expr, $k:expr, $cap_height:expr, $shapes:expr, $pow:expr) => {{
        let config = BinaryPcsConfig::try_new::<Native, Native>(
            $n,
            BinaryPcsParams {
                log_inv_rate: 1,
                pow_bits: $pow,
                security_level: 40,
            },
        )
        .unwrap()
        .try_with_folding($k)
        .unwrap();
        let mmcs = $params::LevelMmcs::<Native>::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            $cap_height,
        );
        let pcs =
            BinaryPcs::<Native, Native, _, _>::new(config, mmcs.clone(), mmcs.clone()).unwrap();
        let shapes = $shapes;
        let tables: Vec<_> = shapes
            .iter()
            .enumerate()
            .map(|(table, &(arity, width))| {
                Table::new(RowMajorMatrix::new(
                    (0..width * (1 << arity))
                        .map(|i| {
                            Native::from_repr(
                                0x21bade026a6ae768f2ed66ffdcc99396u128.wrapping_mul(
                                    1 + i as u128 + $seed as u128 + 97 * table as u128,
                                ),
                            )
                        })
                        .collect(),
                    1 << arity,
                ))
            })
            .collect();
        let protocol = OpeningProtocol::new(
            shapes
                .iter()
                .map(|&(arity, width)| {
                    TableSpec::new(
                        TableShape::new(arity, width),
                        vec![OpeningBatch::new(
                            (0..width).rev().collect(),
                            (0..width).collect(),
                        )],
                    )
                })
                .collect(),
        );
        let make_challenger =
            || BinaryChallenger::<Native, _>::from_hasher(vec![7; 7], $params::byte_hash());
        let mut pc = make_challenger();
        let (cap, data) = pcs
            .commit(
                SuffixProver::<Native, Native>::new_witness(tables, 0),
                &mut pc,
            )
            .unwrap();
        let points: Vec<_> = protocol
            .iter_openings()
            .map(|(table, _)| {
                Point::new(
                    (0..shapes[table].0)
                        .map(|_| pc.sample_algebra_element())
                        .collect(),
                )
            })
            .collect();
        let proof = pcs.try_open_at(data, &protocol, &points, &mut pc).unwrap();
        let mut vc = make_challenger();
        pcs.observe_commitment(&cap, &mut vc);
        let verifier_points: Vec<_> = protocol
            .iter_openings()
            .map(|(table, _)| {
                Point::new(
                    (0..shapes[table].0)
                        .map(|_| vc.sample_algebra_element())
                        .collect(),
                )
            })
            .collect();
        pcs.verify_at(&cap, &proof, &protocol, &verifier_points, &mut vc)
            .unwrap();

        // Restore paths from an independently replayed native transcript.
        let mut replay = make_challenger();
        pcs.observe_commitment(&cap, &mut replay);
        let points: Vec<_> = protocol
            .iter_openings()
            .map(|(table, _)| {
                Point::new(
                    (0..shapes[table].0)
                        .map(|_| replay.sample_algebra_element())
                        .collect(),
                )
            })
            .collect();
        let mut layout = Verifier::<Native, Native>::new(
            &protocol.table_shapes(),
            SuffixProver::<Native, Native>::strategy(),
        );
        for (i, (table, batch)) in protocol.iter_openings().enumerate() {
            layout
                .add_claim_at(table, batch, &points[i], &proof.evals[i], &mut replay)
                .unwrap();
        }
        let mut transcript = BinaryPcsVerifierTranscript::<Native, Native, _>::new(
            &mut replay,
            BinaryPcsShape::new(&config),
        );
        let alpha = transcript.fold_batch(|ch| layout.batching_challenge(ch));
        let mut claim = layout.sum(alpha);
        for (batch, (start, arity)) in batches(&config).enumerate() {
            for r in start..start + arity {
                let message = SumcheckData {
                    polynomial_evaluations: vec![proof.sumcheck.polynomial_evaluations[r]],
                    pow_witnesses: vec![],
                };
                let _ = transcript
                    .fold_batch(|ch| message.verify_rounds(ch, &mut claim, 1, 0, Basis::Evaluation))
                    .unwrap();
            }
            if batch + 1 < config.num_fold_batches() {
                transcript.oracle_commitment(proof.rounds[batch].commitment.clone());
            }
        }
        transcript
            .final_codeword(proof.final_codeword.as_slice())
            .unwrap();
        transcript.query_pow(proof.pow_witness).unwrap();
        // Native returns low symbol positions (candidate << 1); our circuit
        // witnesses the underlying sampled pair indices.
        let queries: Vec<_> = transcript
            .query_pairs()
            .into_iter()
            .map(|position| position >> 1)
            .collect();
        transcript.finish();
        let indices: Vec<_> = queries
            .iter()
            .map(|&q| q << config.log_folding_factor())
            .collect();
        let restore = |start: usize, arity: usize, rows: &[Vec<Native>], multi_proof: &_| {
            let size = 1usize << arity;
            let indices: Vec<_> = indices
                .iter()
                .flat_map(|&index| {
                    let first = (index >> start) & !(size - 1);
                    first..first + size
                })
                .collect();
            let wrapped: Vec<_> = rows.iter().map(|r| vec![r.as_slice()]).collect();
            mmcs.restore_and_recompute_paths(
                &[Dimensions {
                    width: 1,
                    height: (1 << ($n + 1)) >> start,
                }],
                &indices,
                &wrapped,
                multi_proof,
            )
            .unwrap()
            .into_iter()
            .map(|p| p.siblings)
            .collect()
        };
        let base_paths = restore(0, $k, &proof.base_opened_values, &proof.base_multi_proof);
        let rounds = batches(&config)
            .skip(1)
            .zip(&proof.rounds)
            .map(|((start, arity), round)| {
                (
                    round.commitment.roots().to_vec(),
                    round.opened_values.iter().map(|r| r[0]).collect(),
                    restore(start, arity, &round.opened_values, &round.multi_proof),
                )
            })
            .collect();
        Fixture {
            config,
            protocol,
            cap: cap.roots().to_vec(),
            sumcheck: proof.sumcheck.polynomial_evaluations,
            evals: proof.evals,
            rounds,
            base_rows: proof.base_opened_values.iter().map(|r| r[0]).collect(),
            base_paths,
            final_word: proof.final_codeword.as_slice().to_vec(),
            pow_witness: proof.pow_witness,
            queries,
        }
    }};
}

fn field(
    builder: &mut CircuitBuilder<Host>,
    values: &mut Vec<Host>,
    value: Native,
) -> BinaryTower128Target {
    let limbs = builder.alloc_private_input_array::<8>("binary PCS field");
    values.extend((0..8).map(|i| Host::from_u16((value.to_repr() >> (16 * i)) as u16)));
    builder.binary128_from_limbs::<BabyBear>(limbs).unwrap()
}

fn digest(
    builder: &mut CircuitBuilder<Host>,
    values: &mut Vec<Host>,
    value: &[u8; 32],
) -> Vec<ExprId> {
    let limbs = builder.alloc_private_input_array::<16>("binary PCS digest");
    values.extend(bytes_to_limbs(value).into_iter().map(Host::from_u16));
    limbs.to_vec()
}

fn build(
    hash: ByteHash,
    cap_height: usize,
    fixture: &Fixture,
) -> (Circuit<Host>, Vec<Host>, Vec<Host>) {
    build_as::<Native, Native>(hash, cap_height, fixture)
}

fn build_as<F, E>(
    hash: ByteHash,
    cap_height: usize,
    fixture: &Fixture,
) -> (Circuit<Host>, Vec<Host>, Vec<Host>)
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
{
    let verifier = BinaryPcsVerifier::<F, E>::new(
        fixture.config,
        fixture.protocol.clone(),
        hash,
        cap_height,
        64,
    )
    .unwrap();
    let mut builder = CircuitBuilder::<Host>::new();
    match hash {
        ByteHash::Keccak256 => builder.enable_keccak_f1600::<BabyBear>(),
        ByteHash::Blake3 => builder.enable_blake3_compress::<BabyBear>(),
    }
    let public: Vec<_> = fixture
        .cap
        .iter()
        .flat_map(|d| bytes_to_limbs(d).into_iter().map(Host::from_u16))
        .collect();
    let root: Vec<Vec<_>> = fixture
        .cap
        .iter()
        .map(|_| (0..16).map(|_| builder.public_input()).collect())
        .collect();
    let initial: Vec<_> = [Host::from_u8(7); 7]
        .into_iter()
        .map(|x| builder.define_const(x))
        .collect();
    let mut challenger = BinaryTower128Challenger::with_initial_bytes::<BabyBear, Host>(
        &mut builder,
        hash,
        &initial,
    )
    .unwrap();
    verifier
        .observe_commitment::<BabyBear, Host>(&mut builder, &mut challenger, &root)
        .unwrap();
    let points: Vec<Vec<_>> = fixture
        .protocol
        .iter_openings()
        .map(|(table, _)| {
            (0..fixture.protocol.table_shapes()[table].num_variables())
                .map(|_| {
                    verifier
                        .sample_challenge::<BabyBear, Host>(&mut builder, &mut challenger)
                        .unwrap()
                })
                .collect()
        })
        .collect();
    let mut values = Vec::new();
    let sumcheck = fixture
        .sumcheck
        .iter()
        .map(|message| message.map(|x| field(&mut builder, &mut values, x)))
        .collect();
    let evals = fixture
        .evals
        .iter()
        .map(|e| {
            OpeningBatch::new(
                e.current()
                    .iter()
                    .map(|&x| field(&mut builder, &mut values, x))
                    .collect(),
                e.next()
                    .iter()
                    .map(|&x| field(&mut builder, &mut values, x))
                    .collect(),
            )
        })
        .collect();
    let rounds = fixture
        .rounds
        .iter()
        .map(|(cap, rows, paths)| BinaryOracleOpeningTargets {
            cap: cap
                .iter()
                .map(|d| digest(&mut builder, &mut values, d))
                .collect(),
            rows: rows
                .iter()
                .map(|&x| field(&mut builder, &mut values, x))
                .collect(),
            paths: paths
                .iter()
                .map(|p| {
                    p.iter()
                        .map(|d| digest(&mut builder, &mut values, d))
                        .collect()
                })
                .collect(),
        })
        .collect();
    let base_rows = fixture
        .base_rows
        .iter()
        .map(|&x| field(&mut builder, &mut values, x))
        .collect();
    let base_paths = fixture
        .base_paths
        .iter()
        .map(|p| {
            p.iter()
                .map(|d| digest(&mut builder, &mut values, d))
                .collect()
        })
        .collect();
    let final_codeword = fixture
        .final_word
        .iter()
        .map(|&x| field(&mut builder, &mut values, x))
        .collect();
    let pow_witness = field(&mut builder, &mut values, fixture.pow_witness);
    let shape = BinaryPcsShape::new(&fixture.config);
    let query_indices = fixture
        .queries
        .iter()
        .map(|&index| {
            (0..shape.pair_bits)
                .map(|b| {
                    values.push(Host::from_bool(index >> b & 1 == 1));
                    builder.alloc_private_input("binary PCS query bit")
                })
                .collect()
        })
        .collect();
    let proof = BinaryPcs128ProofTargets {
        sumcheck,
        evals,
        rounds,
        base_rows,
        base_paths,
        final_codeword,
        pow_witness,
        query_indices,
    };
    verifier
        .verify_at::<BabyBear, Host>(&mut builder, challenger, &root, &points, &proof)
        .unwrap();
    (builder.build().unwrap(), public, values)
}

fn runs(circuit: &Circuit<Host>, public: &[Host], private: &[Host]) -> bool {
    let mut runner = circuit.runner();
    runner.set_public_inputs(public).is_ok()
        && runner.set_private_inputs(private).is_ok()
        && runner.run().is_ok()
}

#[test]
fn native_openings_authenticate_and_fold_through_both_hashes() {
    for (n, k, cap) in [(1, 1, 0), (3, 2, 1)] {
        for hash in [ByteHash::Keccak256, ByteHash::Blake3] {
            let fixture = match hash {
                ByteHash::Keccak256 => fixture!(keccak, 7, n, k, cap),
                ByteHash::Blake3 => fixture!(blake3, 7, n, k, cap),
            };
            let (circuit, public, private) = build(hash, cap, &fixture);
            assert!(runs(&circuit, &public, &private), "{hash:?}, n={n}, k={k}");
            for i in [0, 8 * n, private.len() / 2, private.len() - 1] {
                let mut wrong = private.clone();
                wrong[i] += Host::ONE;
                assert!(!runs(&circuit, &public, &wrong), "private input {i}");
            }
            let query_bits = fixture.queries.len() * BinaryPcsShape::new(&fixture.config).pair_bits;
            let pow_start = private.len() - query_bits - 8;
            for i in pow_start..pow_start + 8 {
                let mut wrong = private.clone();
                wrong[i] += Host::ONE;
                assert!(!runs(&circuit, &public, &wrong), "zero-PoW limb {i}");
            }
            let mut wrong = public.clone();
            wrong[0] += Host::ONE;
            assert!(!runs(&circuit, &wrong, &private));
        }
    }
}

#[test]
fn native_selectors_and_varied_table_arities_reuse_one_circuit() {
    for shapes in [vec![(1, 2)], vec![(0, 1), (1, 2)]] {
        let n = if shapes.len() == 1 { 2 } else { 3 };
        let first = fixture!(blake3, 7, n, 2, 1, shapes.clone());
        let (circuit, public, private) = build(ByteHash::Blake3, 1, &first);
        assert!(runs(&circuit, &public, &private));
        let second = fixture!(blake3, 91, n, 2, 1, shapes);
        let (_, public, private) = build(ByteHash::Blake3, 1, &second);
        assert!(runs(&circuit, &public, &private));
    }
}

#[test]
fn native_query_grinding_is_replayed() {
    let fixture = fixture!(keccak, 7, 1, 1, 0, vec![(1, 1)], 3);
    let (circuit, public, private) = build(ByteHash::Keccak256, 0, &fixture);
    assert!(runs(&circuit, &public, &private));
    let mut wrong = private.clone();
    // The witness precedes the query bits in this fixed input layout.
    wrong[private.len() - 8 - fixture.queries.len()] += Host::ONE;
    assert!(!runs(&circuit, &public, &wrong));
}

#[test]
fn malformed_geometry_and_target_shapes_return_errors() {
    let fixture = fixture!(keccak, 7, 1, 1, 0);
    assert!(
        BinaryPcs128Verifier::new(
            fixture.config,
            fixture.protocol.clone(),
            ByteHash::Keccak256,
            0,
            1
        )
        .is_err()
    );
    let wrong_protocol = OpeningProtocol::new(vec![TableSpec::new(TableShape::new(2, 1), vec![])]);
    assert!(
        BinaryPcs128Verifier::new(fixture.config, wrong_protocol, ByteHash::Keccak256, 0, 64)
            .is_err()
    );
    let verifier = BinaryPcs128Verifier::new(
        fixture.config,
        fixture.protocol.clone(),
        ByteHash::Keccak256,
        0,
        64,
    )
    .unwrap();
    let mut builder = CircuitBuilder::<Host>::new();
    let zero = builder.binary128_constant(0).unwrap();
    let cap = vec![vec![ExprId::ZERO; 16]];
    let points = vec![vec![zero.clone()]];
    let proof = BinaryPcs128ProofTargets {
        sumcheck: vec![[zero.clone(), zero.clone()]],
        evals: vec![OpeningBatch::new(vec![zero.clone()], vec![zero.clone()])],
        rounds: vec![],
        base_rows: vec![zero.clone(); 4],
        base_paths: vec![vec![vec![ExprId::ZERO; 16]; 2]; 4],
        final_codeword: vec![zero.clone(); 2],
        pow_witness: zero,
        query_indices: vec![vec![ExprId::ZERO]; 2],
    };
    let mut bad = vec![proof.clone(); 5];
    bad[0].sumcheck.clear();
    bad[1].evals.clear();
    bad[2].base_paths[0].pop();
    bad[3].base_paths[0][0].pop();
    bad[4].query_indices[0].clear();
    for proof in bad {
        let error = verifier
            .verify_at::<BabyBear, Host>(
                &mut builder,
                BinaryTower128Challenger::new(ByteHash::Keccak256),
                &cap,
                &points,
                &proof,
            )
            .unwrap_err();
        assert!(matches!(
            error,
            p3_recursion::verifier::VerificationError::InvalidProofShape(_)
        ));
    }
}

#[test]
fn empty_deserialized_requests_and_tight_resource_limits_are_rejected() {
    use p3_recursion::verifier::{VerificationError, VerifierLimits};
    let fixture = fixture!(blake3, 7, 1, 1, 0);
    let empty: OpeningBatch<usize> = postcard::from_bytes(&[0, 0]).unwrap();
    let protocol = OpeningProtocol::new(vec![TableSpec::new(TableShape::new(1, 1), vec![empty])]);
    assert!(matches!(
        BinaryPcs128Verifier::new(fixture.config, protocol, ByteHash::Blake3, 0, 64),
        Err(VerificationError::InvalidProofShape(_))
    ));
    // 32 row limbs + 128 path limbs fit this budget, but the complete input
    // also carries messages, evaluations, final word, points, PoW, queries, cap.
    let limits = VerifierLimits {
        max_total_scalar_elements: 160,
        ..VerifierLimits::default()
    };
    assert!(matches!(
        BinaryPcs128Verifier::with_limits(
            fixture.config,
            fixture.protocol,
            ByteHash::Blake3,
            0,
            64,
            &limits
        ),
        Err(VerificationError::ResourceLimitExceeded {
            component: "scalar elements",
            ..
        })
    ));
}

#[test]
fn a_complete_binary_opening_proves_in_a_prime_field_circuit() {
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover,
    };
    use p3_circuit_prover::{ConstraintProfile, config};
    let fixture = fixture!(keccak, 7, 1, 1, 0);
    let (circuit, public, private) = build(ByteHash::Keccak256, 0, &fixture);
    let mut prover = BatchStarkProver::new(config::baby_bear());
    prover.register_table_prover(Box::new(KeccakF1600Prover::<4>));
    let prepared = prover
        .prepare_circuit::<Host, 4>(
            &circuit,
            &[Box::new(KeccakF1600Preprocessor)],
            &[Box::new(KeccakF1600AirBuilder::<4>)],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    runner.set_private_inputs(&private).unwrap();
    let proof = prepared.prove(&runner.run().unwrap()).unwrap();
    prepared.verifier().verify(&proof, &[]).unwrap();
}

macro_rules! narrow_fixture {
    ($f:ty, $e:ty, $params:ident) => {
        narrow_fixture!($f, $e, $params, 0)
    };
    ($f:ty, $e:ty, $params:ident, $pow:expr) => {{ narrow_fixture!($f, $e, $params, $pow, 1) }};
    ($f:ty, $e:ty, $params:ident, $pow:expr, $n:expr) => {{
        type F = $f;
        type E = $e;
        let config = BinaryPcsConfig::try_new::<F, E>(
            $n,
            BinaryPcsParams {
                log_inv_rate: 1,
                pow_bits: $pow,
                security_level: 40,
            },
        )
        .unwrap();
        let base = $params::LevelMmcs::<F>::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            0,
        );
        let rounds = $params::LevelMmcs::<E>::new(
            $params::FieldHash::new($params::byte_hash()),
            $params::Compress::new($params::byte_hash()),
            0,
        );
        let pcs = BinaryPcs::<F, E, _, _>::new(config, base.clone(), rounds.clone()).unwrap();
        let protocol = OpeningProtocol::new(vec![TableSpec::new(
            TableShape::new($n, 1),
            vec![OpeningBatch::new(vec![0], vec![0])],
        )]);
        let make = || BinaryChallenger::<F, _>::from_hasher(vec![7; 7], $params::byte_hash());
        let mut pc = make();
        let table = Table::new(RowMajorMatrix::new(
            (0..1 << $n)
                .map(|i| F::from_repr((0x93u128 + 0x54 * i as u128) as _))
                .collect(),
            1 << $n,
        ));
        let (root, data) = pcs
            .commit(SuffixProver::<F, E>::new_witness(vec![table], 0), &mut pc)
            .unwrap();
        let point = Point::new((0..$n).map(|_| pc.sample_algebra_element::<E>()).collect());
        let proof = pcs
            .try_open_at(data, &protocol, core::slice::from_ref(&point), &mut pc)
            .unwrap();
        let mut vc = make();
        pcs.observe_commitment(&root, &mut vc);
        let point = Point::new((0..$n).map(|_| vc.sample_algebra_element::<E>()).collect());
        pcs.verify_at(
            &root,
            &proof,
            &protocol,
            core::slice::from_ref(&point),
            &mut vc,
        )
        .unwrap();

        let mut replay = make();
        pcs.observe_commitment(&root, &mut replay);
        let point = Point::new(
            (0..$n)
                .map(|_| replay.sample_algebra_element::<E>())
                .collect(),
        );
        let mut layout =
            Verifier::<F, E>::new(&protocol.table_shapes(), SuffixProver::<F, E>::strategy());
        layout
            .add_claim_at(
                0,
                &protocol.iter_openings().next().unwrap().1,
                &point,
                &proof.evals[0],
                &mut replay,
            )
            .unwrap();
        let mut transcript =
            BinaryPcsVerifierTranscript::<F, E, _>::new(&mut replay, BinaryPcsShape::new(&config));
        let alpha = transcript.fold_batch(|ch| layout.batching_challenge(ch));
        let mut claim = layout.sum(alpha);
        for r in 0..$n {
            let message = SumcheckData {
                polynomial_evaluations: vec![proof.sumcheck.polynomial_evaluations[r]],
                pow_witnesses: vec![],
            };
            let _ = transcript
                .fold_batch(|ch| message.verify_rounds(ch, &mut claim, 1, 0, Basis::Evaluation))
                .unwrap();
            if r + 1 < $n {
                transcript.oracle_commitment(proof.rounds[r].commitment.clone());
            }
        }
        transcript
            .final_codeword(proof.final_codeword.as_slice())
            .unwrap();
        transcript.query_pow(proof.pow_witness).unwrap();
        let pair_positions = transcript.query_pairs();
        transcript.finish();
        let queries: Vec<_> = pair_positions
            .iter()
            .map(|&position| position >> 1)
            .collect();
        let indices: Vec<_> = pair_positions
            .iter()
            .flat_map(|&position| [position, position + 1])
            .collect();
        let rows: Vec<_> = proof
            .base_opened_values
            .iter()
            .map(|r| vec![r.as_slice()])
            .collect();
        let paths = base
            .restore_and_recompute_paths(
                &[Dimensions {
                    width: 1,
                    height: 1 << ($n + 1),
                }],
                &indices,
                &rows,
                &proof.base_multi_proof,
            )
            .unwrap();
        let round_inputs = proof
            .rounds
            .iter()
            .enumerate()
            .map(|(r, round)| {
                let indices: Vec<_> = pair_positions
                    .iter()
                    .flat_map(|&position| {
                        let first = (position >> (r + 1)) & !1;
                        [first, first + 1]
                    })
                    .collect();
                let rows: Vec<_> = round
                    .opened_values
                    .iter()
                    .map(|r| vec![r.as_slice()])
                    .collect();
                let paths = rounds
                    .restore_and_recompute_paths(
                        &[Dimensions {
                            width: 1,
                            height: (1 << ($n + 1)) >> (r + 1),
                        }],
                        &indices,
                        &rows,
                        &round.multi_proof,
                    )
                    .unwrap();
                (
                    round.commitment.roots().to_vec(),
                    round
                        .opened_values
                        .iter()
                        .map(|r| Native::from_repr(r[0].to_repr() as u128))
                        .collect(),
                    paths.into_iter().map(|p| p.siblings).collect(),
                )
            })
            .collect();
        Fixture {
            config,
            protocol,
            cap: root.roots().to_vec(),
            sumcheck: proof
                .sumcheck
                .polynomial_evaluations
                .iter()
                .map(|pair| pair.map(|x| Native::from_repr(x.to_repr() as u128)))
                .collect(),
            evals: proof
                .evals
                .iter()
                .map(|e| {
                    OpeningBatch::new(
                        e.current()
                            .iter()
                            .map(|x| Native::from_repr(x.to_repr() as u128))
                            .collect(),
                        e.next()
                            .iter()
                            .map(|x| Native::from_repr(x.to_repr() as u128))
                            .collect(),
                    )
                })
                .collect(),
            rounds: round_inputs,
            base_rows: proof
                .base_opened_values
                .iter()
                .map(|r| Native::from_repr(r[0].to_repr() as u128))
                .collect(),
            base_paths: paths.into_iter().map(|p| p.siblings).collect(),
            final_word: proof
                .final_codeword
                .as_slice()
                .iter()
                .map(|x| Native::from_repr(x.to_repr() as u128))
                .collect(),
            pow_witness: Native::from_repr(proof.pow_witness.to_repr() as u128),
            queries,
        }
    }};
}

#[test]
fn narrow_tower_alphabets_and_challenge_widths_match_native() {
    macro_rules! check {
        ($f:ty, $e:ty) => {{
            for hash in [ByteHash::Blake3, ByteHash::Keccak256] {
                let fixture = match hash {
                    ByteHash::Blake3 => narrow_fixture!($f, $e, blake3),
                    ByteHash::Keccak256 => narrow_fixture!($f, $e, keccak),
                };
                let (circuit, public, private) = build_as::<$f, $e>(hash, 0, &fixture);
                assert!(
                    runs(&circuit, &public, &private),
                    "{hash:?}, {} -> {}",
                    stringify!($f),
                    stringify!($e)
                );
                // An unused upper coordinate is forbidden by the native field width.
                if <$e>::bits() < 128 {
                    let mut wrong = private.clone();
                    wrong[4] = Host::ONE;
                    assert!(!runs(&circuit, &public, &wrong));
                }
                if <$f>::bits() < 128 {
                    let mut wrong = private;
                    wrong[32 + <$f>::bits() / 16] +=
                        Host::from_u16(if <$f>::bits() == 8 { 256 } else { 1 });
                    assert!(!runs(&circuit, &public, &wrong));
                }
            }
        }};
    }
    check!(BinaryField8, BinaryField64);
    check!(BinaryField16, BinaryField64);
    check!(BinaryField32, BinaryField64);
    check!(BinaryField64, BinaryField64);
    check!(BinaryField8, BinaryField128);
    check!(BinaryField16, BinaryField128);
    check!(BinaryField32, BinaryField128);
    check!(BinaryField64, BinaryField128);
}

#[test]
fn narrow_pow_witness_uses_its_native_byte_width() {
    let fixture = narrow_fixture!(BinaryField16, BinaryField64, blake3, 1);
    let (circuit, public, private) =
        build_as::<BinaryField16, BinaryField64>(ByteHash::Blake3, 0, &fixture);
    assert!(runs(&circuit, &public, &private));
    let mut wrong = private;
    let pow_start = wrong.len() - fixture.queries.len() - 8;
    wrong[pow_start + 1] += Host::ONE;
    assert!(!runs(&circuit, &public, &wrong));
}

#[test]
fn narrow_folded_oracles_hash_eight_byte_challenge_symbols() {
    for hash in [ByteHash::Blake3, ByteHash::Keccak256] {
        let fixture = match hash {
            ByteHash::Blake3 => narrow_fixture!(BinaryField8, BinaryField64, blake3, 0, 2),
            ByteHash::Keccak256 => narrow_fixture!(BinaryField8, BinaryField64, keccak, 0, 2),
        };
        assert_eq!(fixture.rounds.len(), 1);
        let (circuit, public, private) = build_as::<BinaryField8, BinaryField64>(hash, 0, &fixture);
        assert!(runs(&circuit, &public, &private));
    }
}

#[test]
fn a_narrow_binary_opening_proves_with_exact_one_byte_leaves() {
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover,
    };
    use p3_circuit_prover::{ConstraintProfile, config};
    let fixture = narrow_fixture!(BinaryField8, BinaryField64, keccak);
    let (circuit, public, private) =
        build_as::<BinaryField8, BinaryField64>(ByteHash::Keccak256, 0, &fixture);
    let mut prover = BatchStarkProver::new(config::baby_bear());
    prover.register_table_prover(Box::new(KeccakF1600Prover::<4>));
    let prepared = prover
        .prepare_circuit::<Host, 4>(
            &circuit,
            &[Box::new(KeccakF1600Preprocessor)],
            &[Box::new(KeccakF1600AirBuilder::<4>)],
            ConstraintProfile::Standard,
        )
        .unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&public).unwrap();
    runner.set_private_inputs(&private).unwrap();
    let proof = prepared.prove(&runner.run().unwrap()).unwrap();
    prepared.verifier().verify(&proof, &[]).unwrap();
}

#[test]
fn binary_pcs_configuration_must_match_both_native_field_types() {
    let fixture = narrow_fixture!(BinaryField8, BinaryField64, blake3);
    assert!(
        BinaryPcsVerifier::<BinaryField16, BinaryField64>::new(
            fixture.config,
            fixture.protocol.clone(),
            ByteHash::Blake3,
            0,
            64
        )
        .is_err()
    );
    assert!(
        BinaryPcsVerifier::<BinaryField8, BinaryField128>::new(
            fixture.config,
            fixture.protocol,
            ByteHash::Blake3,
            0,
            64
        )
        .is_err()
    );
}
