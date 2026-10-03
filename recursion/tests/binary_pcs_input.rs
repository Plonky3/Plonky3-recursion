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
