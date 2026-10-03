//! Native proof import remains bounded and its allocation is proof-independent.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_binary_pcs::{BinaryPcs, BinaryPcsConfig, BinaryPcsParams, BinaryPcsProof};
use p3_challenger::{
    CanObserve, CanSample, CanSampleBits, CanSampleUniformBits, FieldChallenger,
    GrindingChallenger, ResamplingError,
};
use p3_circuit::CircuitBuilder;
use p3_circuit::ops::{ByteHash, bytes_to_limbs};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_field::extension::BinomialExtensionField;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleCap;
use p3_multilinear_util::point::Point;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::BinaryPcs128Verifier;
use p3_recursion::verifier::{VerificationError, VerifierLimits};
use p3_sumcheck::layout::{Layout, SuffixProver, Table};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
use p3_test_utils::binary_field_params::keccak;

type Native = BinaryField128;
type Host = BinomialExtensionField<BabyBear, 4>;
type Mmcs = keccak::LevelMmcs<Native>;
type Ch = keccak::LevelChallenger<Native>;
type Proof = BinaryPcsProof<Native, Native, Mmcs, Mmcs>;

fn config() -> BinaryPcsConfig {
    BinaryPcsConfig::try_new::<Native, Native>(
        5,
        BinaryPcsParams {
            log_inv_rate: 2,
            pow_bits: 0,
            security_level: 8,
        },
    )
    .unwrap()
    .try_with_folding(2)
    .unwrap()
}

fn protocol() -> OpeningProtocol {
    OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(5, 1),
        vec![OpeningBatch::new(vec![0], vec![0])],
    )])
}

fn mmcs() -> Mmcs {
    Mmcs::new(
        keccak::FieldHash::new(keccak::byte_hash()),
        keccak::Compress::new(keccak::byte_hash()),
        1,
    )
}

fn native(seed: u128) -> (MerkleCap<Native, [u8; 32]>, Vec<Point<Native>>, Proof, Ch) {
    let mmcs = mmcs();
    let pcs = BinaryPcs::<Native, Native, _, _>::new(config(), mmcs.clone(), mmcs).unwrap();
    let table = Table::new(RowMajorMatrix::new(
        (0..32).map(|i| Native::from_repr(seed + 19 * i)).collect(),
        32,
    ));
    let make = || Ch::from_hasher(vec![13; 5], keccak::byte_hash());
    let mut prover = make();
    let (cap, data) = pcs
        .commit(
            SuffixProver::<Native, Native>::new_witness(vec![table], 0),
            &mut prover,
        )
        .unwrap();
    let point = Point::new((0..5).map(|_| prover.sample_algebra_element()).collect());
    let proof = pcs
        .try_open_at(
            data,
            &protocol(),
            core::slice::from_ref(&point),
            &mut prover,
        )
        .unwrap();
    let mut verifier = make();
    pcs.observe_commitment(&cap, &mut verifier);
    let verifier_point = Point::new((0..5).map(|_| verifier.sample_algebra_element()).collect());
    pcs.verify_at(
        &cap,
        &proof,
        &protocol(),
        core::slice::from_ref(&verifier_point),
        &mut verifier,
    )
    .unwrap();
    let mut entry = make();
    pcs.observe_commitment(&cap, &mut entry);
    let point = Point::new((0..5).map(|_| entry.sample_algebra_element()).collect());
    (cap, vec![point], proof, entry)
}

struct ConstantQueries {
    inner: Ch,
    draws: Arc<AtomicUsize>,
    observations: Arc<AtomicUsize>,
}

impl<T> CanObserve<T> for ConstantQueries
where
    Ch: CanObserve<T>,
{
    fn observe(&mut self, value: T) {
        self.observations.fetch_add(1, Ordering::Relaxed);
        self.inner.observe(value);
    }
}
impl<T> CanSample<T> for ConstantQueries
where
    Ch: CanSample<T>,
{
    fn sample(&mut self) -> T {
        self.inner.sample()
    }
}
impl CanSampleBits<usize> for ConstantQueries {
    fn sample_bits(&mut self, bits: usize) -> usize {
        self.inner.sample_bits(bits)
    }
}
impl FieldChallenger<Native> for ConstantQueries {}
impl GrindingChallenger for ConstantQueries {
    type Witness = Native;
    fn grind(&mut self, bits: usize) -> Native {
        self.inner.grind(bits)
    }
}
impl CanSampleUniformBits<Native> for ConstantQueries {
    fn sample_uniform_bits<const RESAMPLE: bool>(
        &mut self,
        _: usize,
    ) -> Result<usize, ResamplingError> {
        self.draws.fetch_add(1, Ordering::Relaxed);
        Ok(0)
    }
}

#[test]
fn malformed_imports_reject_before_transcript_and_queries_stop_at_the_bound() {
    let (cap, points, proof, ch) = native(7);
    let verifier =
        BinaryPcs128Verifier::new(config(), protocol(), ByteHash::Keccak256, 1, 128).unwrap();
    let mmcs = mmcs();
    let mut malformed = vec![proof.clone(); 5];
    malformed[0].sumcheck.pow_witnesses.push(Native::ZERO);
    malformed[1].sumcheck.polynomial_evaluations.pop();
    malformed[2].base_opened_values[0].push(Native::ZERO);
    malformed[3].rounds.pop();
    malformed[4].evals.clear();
    for proof in malformed {
        let draws = Arc::new(AtomicUsize::new(0));
        let observations = Arc::new(AtomicUsize::new(0));
        let challenger = ConstantQueries {
            inner: ch.clone(),
            draws: draws.clone(),
            observations: observations.clone(),
        };
        assert!(
            verifier
                .import_native(&mmcs, &mmcs, &cap, &points, &proof, challenger)
                .is_err()
        );
        assert_eq!(draws.load(Ordering::Relaxed), 0);
        assert_eq!(observations.load(Ordering::Relaxed), 0);
    }
    let draws = Arc::new(AtomicUsize::new(0));
    let challenger = ConstantQueries {
        inner: ch.clone(),
        draws: draws.clone(),
        observations: Arc::new(AtomicUsize::new(0)),
    };
    let error = verifier
        .import_native(&mmcs, &mmcs, &cap, &points, &proof, challenger)
        .unwrap_err();
    assert!(matches!(error, VerificationError::InvalidProofShape(_)));
    assert_eq!(draws.load(Ordering::Relaxed), 128);

    let mut extra = proof.clone();
    extra.base_multi_proof.sibling_hashes.push([0; 32]);
    assert!(
        verifier
            .import_native(&mmcs, &mmcs, &cap, &points, &extra, ch.clone())
            .is_err()
    );
    assert!(!proof.base_multi_proof.sibling_hashes.is_empty());
    let limits = VerifierLimits {
        max_compressed_frontier_hashes: 0,
        ..VerifierLimits::default()
    };
    let tight = BinaryPcs128Verifier::with_limits(
        config(),
        protocol(),
        ByteHash::Keccak256,
        1,
        128,
        &limits,
    )
    .unwrap();
    assert!(matches!(
        tight.import_native(&mmcs, &mmcs, &cap, &points, &proof, ch),
        Err(VerificationError::ResourceLimitExceeded { .. })
    ));
}

#[test]
fn allocated_native_inputs_authenticate_and_reuse_one_circuit() {
    let verifier =
        BinaryPcs128Verifier::new(config(), protocol(), ByteHash::Keccak256, 1, 128).unwrap();
    let shape = verifier.input_shape();
    let mmcs = mmcs();
    let (cap, points, proof, ch) = native(7);
    let imported = verifier
        .import_native(&mmcs, &mmcs, &cap, &points, &proof, ch)
        .unwrap();
    let different =
        BinaryPcs128Verifier::new(config(), protocol(), ByteHash::Blake3, 1, 128).unwrap();
    assert!(
        imported
            .private_values::<Host>(&different.input_shape())
            .is_err()
    );
    let mut builder = CircuitBuilder::<Host>::new();
    builder.enable_keccak_f1600::<BabyBear>();
    let roots: Vec<Vec<_>> = (0..2)
        .map(|_| (0..16).map(|_| builder.public_input()).collect())
        .collect();
    let initial = (0..5)
        .map(|_| builder.define_const(Host::from_u8(13)))
        .collect::<Vec<_>>();
    let mut challenger = BinaryTower128Challenger::with_initial_bytes::<BabyBear, Host>(
        &mut builder,
        ByteHash::Keccak256,
        &initial,
    )
    .unwrap();
    verifier
        .observe_commitment::<BabyBear, Host>(&mut builder, &mut challenger, &roots)
        .unwrap();
    let points = vec![
        (0..5)
            .map(|_| {
                verifier
                    .sample_challenge::<BabyBear, Host>(&mut builder, &mut challenger)
                    .unwrap()
            })
            .collect(),
    ];
    let targets = shape
        .allocate_targets::<BabyBear, Host>(&mut builder)
        .unwrap();
    verifier
        .verify_at::<BabyBear, Host>(&mut builder, challenger, &roots, &points, &targets)
        .unwrap();
    let circuit = builder.build().unwrap();
    let public = |cap: &MerkleCap<Native, [u8; 32]>| {
        cap.roots()
            .iter()
            .flat_map(|d| bytes_to_limbs(d).into_iter().map(Host::from_u16))
            .collect::<Vec<_>>()
    };
    let run = |public: &[Host], private: &[Host]| {
        let mut runner = circuit.runner();
        runner.set_public_inputs(public).unwrap();
        runner.set_private_inputs(private).unwrap();
        runner.run().is_ok()
    };
    let private = imported.private_values(&shape).unwrap();
    assert!(run(&public(&cap), &private));
    let mut wrong = private.clone();
    wrong[0] += Host::ONE;
    assert!(!run(&public(&cap), &wrong));
    let (second_cap, second_points, second_proof, second_ch) = native(97);
    let second = verifier
        .import_native(
            &mmcs,
            &mmcs,
            &second_cap,
            &second_points,
            &second_proof,
            second_ch,
        )
        .unwrap();
    assert_eq!(second.shape(), &shape);
    assert!(run(
        &public(&second_cap),
        &second.private_values(&shape).unwrap()
    ));
    assert!(!run(&public(&cap), &second.private_values(&shape).unwrap()));
}

#[test]
fn consecutive_openings_preserve_native_transcript_for_both_entry_seeds() {
    use p3_circuit_prover::batch_stark_prover::{
        BatchStarkProver, KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover,
    };
    use p3_circuit_prover::{ConstraintProfile, config as host_config};

    for (num_variables, cap_height, prove) in [(5usize, 1usize, false), (1, 0, true)] {
        let config = || {
            BinaryPcsConfig::try_new::<Native, Native>(
                num_variables,
                BinaryPcsParams {
                    log_inv_rate: 2,
                    pow_bits: 0,
                    security_level: 8,
                },
            )
            .unwrap()
            .try_with_folding(num_variables.min(2))
            .unwrap()
        };
        let protocol = || {
            OpeningProtocol::new(vec![TableSpec::new(
                TableShape::new(num_variables, 1),
                vec![OpeningBatch::new(vec![0], vec![0])],
            )])
        };
        let mmcs = || {
            Mmcs::new(
                keccak::FieldHash::new(keccak::byte_hash()),
                keccak::Compress::new(keccak::byte_hash()),
                cap_height,
            )
        };
        for second_empty in [false, true] {
            let second_protocol = if second_empty {
                OpeningProtocol::new(vec![TableSpec::new(
                    TableShape::new(num_variables, 1),
                    vec![],
                )])
            } else {
                protocol()
            };
            let first = BinaryPcs128Verifier::new(
                config(),
                protocol(),
                ByteHash::Keccak256,
                cap_height,
                128,
            )
            .unwrap();
            let second = BinaryPcs128Verifier::new(
                config(),
                second_protocol.clone(),
                ByteHash::Keccak256,
                cap_height,
                128,
            )
            .unwrap();
            let first_shape = first.input_shape();
            let second_shape = second.input_shape();
            let mmcs = mmcs();
            let pcs = BinaryPcs::<Native, Native, _, _>::new(config(), mmcs.clone(), mmcs.clone())
                .unwrap();
            let mut builder = CircuitBuilder::<Host>::new();
            builder.enable_keccak_f1600::<BabyBear>();
            let caps = (0..2)
                .map(|_| {
                    (0..1usize << cap_height)
                        .map(|_| {
                            builder
                                .alloc_public_input_array::<16>("consecutive PCS cap")
                                .to_vec()
                        })
                        .collect::<Vec<_>>()
                })
                .collect::<Vec<_>>();
            let expected = builder.alloc_public_input_array::<8>("continued PCS challenge");
            let expected = builder.binary128_from_limbs::<BabyBear>(expected).unwrap();
            let initial = (0..5)
                .map(|_| builder.define_const(Host::from_u8(13)))
                .collect::<Vec<_>>();
            let mut ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, Host>(
                &mut builder,
                ByteHash::Keccak256,
                &initial,
            )
            .unwrap();
            first
                .observe_commitment::<BabyBear, Host>(&mut builder, &mut ch, &caps[0])
                .unwrap();
            second
                .observe_commitment::<BabyBear, Host>(&mut builder, &mut ch, &caps[1])
                .unwrap();
            let points = vec![
                (0..num_variables)
                    .map(|_| {
                        first
                            .sample_challenge::<BabyBear, Host>(&mut builder, &mut ch)
                            .unwrap()
                    })
                    .collect::<Vec<_>>(),
            ];
            let first_targets = first_shape
                .allocate_targets::<BabyBear, Host>(&mut builder)
                .unwrap();
            let second_targets = second_shape
                .allocate_targets::<BabyBear, Host>(&mut builder)
                .unwrap();
            let continuation = first
                .verify_at_with_continuation::<BabyBear, Host>(
                    &mut builder,
                    ch,
                    &caps[0],
                    &points,
                    &first_targets,
                )
                .unwrap();
            let second_points = if second_empty { vec![] } else { points.clone() };
            let continuation = second
                .verify_at_after_queries::<BabyBear, Host>(
                    &mut builder,
                    continuation,
                    &caps[1],
                    &second_points,
                    &second_targets,
                )
                .unwrap();
            let observation = 41u128
                .to_le_bytes()
                .map(|b| builder.define_const(Host::from_u8(b)));
            let mut ch = continuation
                .resume_with_observation::<BabyBear, Host>(&mut builder, &observation)
                .unwrap();
            let actual = first
                .sample_challenge::<BabyBear, Host>(&mut builder, &mut ch)
                .unwrap();
            for (&a, &b) in actual.bits().iter().zip(expected.bits()) {
                let difference = builder.sub(a, b);
                builder.assert_zero(difference);
            }
            let circuit = builder.build().unwrap();
            for seed in [7u128, 97] {
                let make = || Ch::from_hasher(vec![13; 5], keccak::byte_hash());
                let table = |offset: u128| {
                    Table::new(RowMajorMatrix::new(
                        (0..1u128 << num_variables)
                            .map(|i| Native::from_repr(seed + offset + 19 * i))
                            .collect(),
                        1usize << num_variables,
                    ))
                };
                let mut prover = make();
                let (first_cap, first_data) = pcs
                    .commit(
                        SuffixProver::<Native, Native>::new_witness(vec![table(0)], 0),
                        &mut prover,
                    )
                    .unwrap();
                let (second_cap, second_data) = pcs
                    .commit(
                        SuffixProver::<Native, Native>::new_witness(vec![table(313)], 0),
                        &mut prover,
                    )
                    .unwrap();
                let point = Point::new(
                    (0..num_variables)
                        .map(|_| prover.sample_algebra_element())
                        .collect(),
                );
                let first_points = vec![point];
                let second_points = if second_empty {
                    vec![]
                } else {
                    first_points.clone()
                };
                let first_proof = pcs
                    .try_open_at(first_data, &protocol(), &first_points, &mut prover)
                    .unwrap();
                let second_proof = pcs
                    .try_open_at(second_data, &second_protocol, &second_points, &mut prover)
                    .unwrap();
                let mut entry = make();
                pcs.observe_commitment(&first_cap, &mut entry);
                pcs.observe_commitment(&second_cap, &mut entry);
                let replayed = Point::new(
                    (0..num_variables)
                        .map(|_| entry.sample_algebra_element())
                        .collect(),
                );
                assert_eq!(replayed, first_points[0]);
                let mut native_verifier = entry.clone();
                pcs.verify_at(
                    &first_cap,
                    &first_proof,
                    &protocol(),
                    &first_points,
                    &mut native_verifier,
                )
                .unwrap();
                pcs.verify_at(
                    &second_cap,
                    &second_proof,
                    &second_protocol,
                    &second_points,
                    &mut native_verifier,
                )
                .unwrap();
                let first_input = first
                    .import_native(
                        &mmcs,
                        &mmcs,
                        &first_cap,
                        &first_points,
                        &first_proof,
                        &mut entry,
                    )
                    .unwrap();
                let second_input = second
                    .import_native(
                        &mmcs,
                        &mmcs,
                        &second_cap,
                        &second_points,
                        &second_proof,
                        &mut entry,
                    )
                    .unwrap();
                native_verifier.observe(Native::from_repr(41));
                entry.observe(Native::from_repr(41));
                let expected = native_verifier.sample_algebra_element::<Native>();
                assert_eq!(entry.sample_algebra_element::<Native>(), expected);
                let mut public = first_cap
                    .roots()
                    .iter()
                    .chain(second_cap.roots())
                    .flat_map(|d| bytes_to_limbs(d).into_iter().map(Host::from_u16))
                    .collect::<Vec<_>>();
                public.extend(
                    (0..8).map(|i| Host::from_u16((expected.to_repr() >> (16 * i)) as u16)),
                );
                let mut private = first_input.private_values::<Host>(&first_shape).unwrap();
                private.extend(second_input.private_values::<Host>(&second_shape).unwrap());
                let run = |public: &[Host], private: &[Host]| {
                    let mut runner = circuit.runner();
                    runner.set_public_inputs(public).unwrap();
                    runner.set_private_inputs(private).unwrap();
                    runner.run().is_ok()
                };
                assert!(run(&public, &private));
                let last = public.len() - 8;
                let mut wrong = public.clone();
                wrong[last] += Host::ONE;
                assert!(!run(&wrong, &private));
                if prove && seed == 7 {
                    let mut prover = BatchStarkProver::new(host_config::baby_bear());
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
            }
        }
    }
}
