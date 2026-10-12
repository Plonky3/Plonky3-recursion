//! Packed-bit trace openings over Poly64 values and Poly192 challenges verified in the native
//! Poly64 carrier: column batching, the bit ring switch with every sumcheck round, and the
//! packed WHIR opening, checked against the released Boolean trace commitment.

use p3_binary_field::{Poly64, Poly192};
use p3_binary_pcs::whir::{BinaryWhirDomain, BooleanWhirPcs, BooleanWhirProof};
use p3_binary_pcs::{BooleanTraceCommitment, BooleanTraceCommitmentProof};
use p3_challenger::FieldChallenger;
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::{ByteHash, NativePoly192Target, bytes_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_commit::MultilinearPcs;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::{MerkleCap, MerkleTreeMmcs};
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_recursion::pcs::binary::{
    BinaryPolyBitRingVerifier, BinaryPolyBooleanWhirTraceVerifier, BinaryPolyBooleanWhirVerifier,
    BinaryPolyWhirVerifier, BinaryRingClaimSpec, ByteDigestMmcs, MerkleArity,
    NativeBinaryPolyBooleanWhirTraceInput, NativePolyBitRingReading,
};
use p3_recursion::{BinaryTower128Challenger, VerifierLimits};
use p3_sumcheck::layout::{Layout, SuffixProver, Table, plan_stacked_layout};
use p3_sumcheck::ring_switch::bits::{BitPacking, BitRingSwitch, BitRingSwitchClaims};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
use p3_symmetric::CompressionFunctionFromHasher;
use p3_test_utils::binary_field_params::keccak;
use p3_whir::pcs::proof::QueryOpenings;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};

type F = Poly64;
type E = Poly192;
type H = NativeBinaryEncoding;
type Ch = keccak::LevelChallenger<F>;
/// Trees whose nodes compress two digests.
type PairMmcs = keccak::LevelMmcs<F>;
/// Trees whose nodes compress four digests.
type QuadMmcs = MerkleTreeMmcs<
    F,
    u8,
    keccak::FieldHash,
    CompressionFunctionFromHasher<keccak::ByteHash, 4, 32>,
    4,
    32,
>;
type Pcs<M> = BooleanTraceCommitment<E, BooleanWhirPcs<F, E, BinaryWhirDomain<F>, M, Ch>>;
type Proof<M> = BooleanTraceCommitmentProof<E, BooleanWhirProof<F, E, M>>;

/// Bit variables one packed Poly64 element absorbs.
const ABSORBED: usize = 6;
/// Rows of a sent tensor, one Poly64 cell per Poly192 coordinate.
const ROWS: usize = 192;
/// Poly64 cells of one Poly192 value.
const LIMBS: usize = 3;
/// Bytes every transcript here starts from, natively and in each circuit.
const INITIAL: [u8; 4] = [7, 19, 13, 29];

/// Deterministic SplitMix64 stream of words and full-width field elements.
struct Sampler(u64);

impl Sampler {
    const fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    const fn base(&mut self) -> F {
        F::new(self.next_u64())
    }

    fn bases(&mut self, count: usize) -> Vec<F> {
        (0..count).map(|_| self.base()).collect()
    }

    const fn ext(&mut self) -> E {
        E::new([self.base(), self.base(), self.base()])
    }

    fn point(&mut self, variables: usize) -> Point<E> {
        Point::new((0..variables).map(|_| self.ext()).collect())
    }
}

fn challenger() -> Ch {
    Ch::from_hasher(INITIAL.to_vec(), keccak::byte_hash())
}

const fn pair_mmcs(cap_height: usize) -> PairMmcs {
    PairMmcs::new(
        keccak::FieldHash::new(keccak::byte_hash()),
        keccak::Compress::new(keccak::byte_hash()),
        cap_height,
    )
}

const fn quad_mmcs(cap_height: usize) -> QuadMmcs {
    QuadMmcs::new(
        keccak::FieldHash::new(keccak::byte_hash()),
        CompressionFunctionFromHasher::new(keccak::byte_hash()),
        cap_height,
    )
}

/// The packed WHIR configuration the tests open with: small security, so the circuits stay
/// small, and folds of two once the packing has that many variables.
fn packed_config(variables: usize) -> WhirConfig<E, F, Ch> {
    whir_config(variables, 8, 2, if variables >= 4 { 2 } else { 1 })
}

fn whir_config(
    variables: usize,
    security: usize,
    rate: usize,
    fold: usize,
) -> WhirConfig<E, F, Ch> {
    WhirConfig::new_with_domain(
        variables,
        ProtocolParameters {
            security_level: security,
            pow_bits: 0,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(fold),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: rate,
        },
        &BinaryWhirDomain::<F>::default(),
    )
    .unwrap()
}

/// One table of `2^rows` rows and `width` columns, opened `openings` times as a complete
/// batch: every column at the current row and, with `next`, every column one row ahead.
#[derive(Clone, Copy, Debug)]
struct Case {
    rows: usize,
    width: usize,
    next: bool,
    openings: usize,
    cap_height: usize,
}

impl Case {
    const fn new(rows: usize, width: usize, next: bool, openings: usize) -> Self {
        Self {
            rows,
            width,
            next,
            openings,
            cap_height: 0,
        }
    }

    const fn with_cap(self, cap_height: usize) -> Self {
        Self { cap_height, ..self }
    }

    fn protocol(&self) -> OpeningProtocol {
        let all: Vec<usize> = (0..self.width).collect();
        let batch = OpeningBatch::new(all.clone(), if self.next { all } else { vec![] });
        OpeningProtocol::new(vec![TableSpec::new(
            TableShape::new(self.rows, self.width),
            vec![batch; self.openings],
        )])
    }

    fn bit_variables(&self) -> usize {
        plan_stacked_layout(&self.protocol().table_shapes()).0
    }
}

/// A released opening of random bits at random row points, verified natively, with the
/// recursive verifier over the same geometry and tree arity.
struct Opened<M: ByteDigestMmcs<F>> {
    case: Case,
    config: WhirConfig<E, F, Ch>,
    mmcs: M,
    pcs: Pcs<M>,
    verifier: BinaryPolyBooleanWhirTraceVerifier,
    commitment: MerkleCap<F, [u8; 32]>,
    points: Vec<Point<E>>,
    proof: Proof<M>,
    /// The released verifier's next challenge after the opening.
    next: E,
}

impl<M: ByteDigestMmcs<F> + Clone> Opened<M> {
    fn new(case: Case, arity: MerkleArity, mmcs: M, seed: u64) -> Self {
        let protocol = case.protocol();
        let config = packed_config(case.bit_variables() - ABSORBED);
        let inner = WhirProver::<E, F, _, _, Ch, SuffixProver<F, E>>::new(
            config.clone(),
            BinaryWhirDomain::<F>::default(),
            mmcs.clone(),
        );
        let pcs = BooleanTraceCommitment::from_commitment(
            BooleanWhirPcs::new(inner, case.bit_variables()).unwrap(),
        );
        let verifier = BinaryPolyBooleanWhirTraceVerifier::with_limits(
            &config,
            protocol.clone(),
            ByteHash::Keccak256,
            arity,
            case.cap_height,
            &VerifierLimits::default(),
        )
        .unwrap();
        let mut sampler = Sampler(seed);
        let blocks = (1usize << case.rows).div_ceil(64);
        let mut words: Vec<u64> = (0..case.width * blocks)
            .map(|_| sampler.next_u64())
            .collect();
        // Every column's last row is set, so the repeated last row a successor reads is never
        // zero. Rows are a whole number of 64-row blocks here.
        assert!(case.rows >= ABSORBED);
        for word in &mut words[(blocks - 1) * case.width..] {
            *word |= 1 << 63;
        }
        let table = Table::from_packed_bits(RowMajorMatrix::new(words, case.width), case.rows);
        let points: Vec<_> = (0..case.openings)
            .map(|_| sampler.point(case.rows))
            .collect();
        let mut prover = challenger();
        let (commitment, data) = pcs.commit(vec![table], &mut prover).unwrap();
        let proof = pcs.open_at(data, &protocol, &points, &mut prover).unwrap();
        let mut released = challenger();
        pcs.observe_commitment(&commitment, &mut released);
        let evals = pcs
            .verify_at(&commitment, &proof, &protocol, &points, &mut released)
            .unwrap();
        assert_eq!(evals.len(), case.openings);
        let next = released.sample_algebra_element::<E>();
        Self {
            case,
            config,
            mmcs,
            pcs,
            verifier,
            commitment,
            points,
            proof,
            next,
        }
    }

    fn high(&self) -> usize {
        self.case.bit_variables() - ABSORBED
    }

    /// Imports `proof` on a transcript that has observed the commitment, returning the
    /// import's result and the challenger it left behind.
    fn import(
        &self,
        proof: &Proof<M>,
    ) -> (Result<NativeBinaryPolyBooleanWhirTraceInput, String>, Ch) {
        let mut entry = challenger();
        self.pcs.observe_commitment(&self.commitment, &mut entry);
        let result = self
            .verifier
            .import_native(
                &self.config,
                &self.mmcs,
                &self.commitment,
                &self.points,
                proof,
                &mut entry,
            )
            .map_err(|error| error.to_string());
        (result, entry)
    }

    /// The native circuit's private inputs for the honest proof. The import leaves the
    /// transcript where the released verifier leaves it.
    fn native_private(&self) -> Vec<F> {
        let (imported, mut entry) = self.import(&self.proof);
        let imported = imported.unwrap();
        assert_eq!(entry.sample_algebra_element::<E>(), self.next);
        imported
            .private_native_values(&self.verifier.input_shape())
            .unwrap()
    }

    /// Public inputs: the cap words and the row points, then, for a bound circuit, the
    /// opened values in protocol order and the next challenge.
    fn native_public(&self, bound: bool) -> Vec<F> {
        let mut public: Vec<F> = self
            .commitment
            .roots()
            .iter()
            .flat_map(|root| {
                bytes_to_limbs(root)
                    .into_iter()
                    .map(|word| H::encode_u16(word).unwrap())
            })
            .collect();
        let points = self.points.iter().flat_map(|point| point.iter().copied());
        let opened = bound.then(|| self.proof.values.iter().copied().chain([self.next]));
        public.extend(
            points
                .chain(opened.into_iter().flatten())
                .flat_map(E::coefficients),
        );
        public
    }

    /// The native verifier circuit. A bound circuit also constrains the returned values to
    /// the opened values and its next challenge to the released one; an unbound circuit
    /// holds the verifier's own constraints only.
    fn native_circuit(&self, bound: bool) -> Circuit<F> {
        let mut b = CircuitBuilder::<F>::new();
        b.enable_native_keccak_f1600().unwrap();
        let cap: Vec<_> = self
            .commitment
            .roots()
            .iter()
            .map(|_| {
                b.alloc_public_input_array::<16>("packed commitment root")
                    .to_vec()
            })
            .collect();
        let points: Vec<Vec<_>> = self
            .points
            .iter()
            .map(|point| point.iter().map(|_| public_value(&mut b)).collect())
            .collect();
        let proof = self
            .verifier
            .input_shape()
            .allocate_native_targets(&mut b)
            .unwrap();
        let mut ch = native_challenger(&mut b);
        self.verifier
            .observe_commitment_native(&mut b, &mut ch, &cap)
            .unwrap();
        let (evals, mut ch) = self
            .verifier
            .verify_at_native(&mut b, ch, &cap, &points, &proof)
            .unwrap();
        assert_eq!(evals.len(), self.case.openings);
        if bound {
            for value in evals
                .iter()
                .flat_map(|e| e.current().iter().chain(e.next()))
            {
                bind(&mut b, value);
            }
            let next = native_sample(&mut b, &mut ch);
            bind(&mut b, &next);
        }
        b.build().unwrap()
    }

    /// The honest witness is accepted, and so is the transcript: changing the last opened
    /// value or the next challenge drawn after the opening is refused.
    fn check_honest(&self) {
        let circuit = self.native_circuit(true);
        let public = self.native_public(true);
        let private = self.native_private();
        assert!(accepts(&circuit, &public, &private), "{:?}", self.case);
        for index in [public.len() - LIMBS - 1, public.len() - 1] {
            let mut wrong = public.clone();
            wrong[index] += F::ONE;
            assert!(
                !accepts(&circuit, &wrong, &private),
                "{:?} public {index}",
                self.case
            );
        }
    }

    /// A verifier over `arity` and `cap_height`, a tree other than this opening's, refuses the
    /// import as a configuration mismatch and leaves the transcript where the commitment left
    /// it.
    fn check_foreign_tree(&self, arity: MerkleArity, cap_height: usize) {
        let foreign = BinaryPolyBooleanWhirTraceVerifier::with_limits(
            &self.config,
            self.case.protocol(),
            ByteHash::Keccak256,
            arity,
            cap_height,
            &VerifierLimits::default(),
        )
        .unwrap();
        let mut entry = challenger();
        self.pcs.observe_commitment(&self.commitment, &mut entry);
        let mut untouched = entry.clone();
        let error = foreign
            .import_native(
                &self.config,
                &self.mmcs,
                &self.commitment,
                &self.points,
                &self.proof,
                &mut entry,
            )
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("configuration shape mismatch"),
            "{arity:?} cap {cap_height}: {error}"
        );
        assert_eq!(
            entry.sample_algebra_element::<E>(),
            untouched.sample_algebra_element::<E>()
        );
    }
}

fn public_value(b: &mut CircuitBuilder<F>) -> NativePoly192Target {
    let coefficients = core::array::from_fn(|_| b.public_input());
    b.native_poly192_from_coefficients(coefficients)
}

/// Constrains `actual` to the next three public limbs.
fn bind(b: &mut CircuitBuilder<F>, actual: &NativePoly192Target) {
    let expected = public_value(b);
    for (&actual, &expected) in actual.coefficients().iter().zip(expected.coefficients()) {
        let difference = b.sub(actual, expected);
        b.assert_zero(difference);
    }
}

fn native_challenger(b: &mut CircuitBuilder<F>) -> BinaryTower128Challenger {
    let initial = INITIAL.map(|byte| b.define_const(H::encode_u16(u16::from(byte)).unwrap()));
    BinaryTower128Challenger::with_initial_bytes_with_host::<H, F>(b, ByteHash::Keccak256, &initial)
        .unwrap()
}

/// The circuit transcript's next Poly192 draw, as the native transcript reads it.
fn native_sample(
    b: &mut CircuitBuilder<F>,
    ch: &mut BinaryTower128Challenger,
) -> NativePoly192Target {
    let bits = ch.sample_poly192_with_host::<H, F>(b).unwrap();
    b.native_poly192_from_bits(core::array::from_fn(|i| {
        bits.coefficients()[i / 64].bits()[i % 64]
    }))
    .unwrap()
}

fn accepts(circuit: &Circuit<F>, public: &[F], private: &[F]) -> bool {
    let mut runner = circuit.runner();
    runner
        .set_public_inputs(public)
        .and_then(|()| runner.set_private_inputs(private))
        .and_then(|()| runner.run())
        .is_ok()
}

/// The first index at or after `from` at which `needle` occurs in `haystack`.
fn locate(haystack: &[F], needle: &[F], from: usize) -> usize {
    (from..=haystack.len() - needle.len())
        .find(|&i| haystack[i..i + needle.len()] == *needle)
        .expect("the witness holds the proof value")
}

/// Witness generation accepts the released opening, returns exactly the opened values, and
/// leaves the in-circuit transcript where the released verifier leaves it: across widths that
/// pad the column batch, a successor spanning elements and one inside one element, two
/// openings batched under lambda, a single column, a cap of one level, and trees whose nodes
/// compress four digests.
#[test]
fn native_poly_packed_openings_replay_the_released_commitment() {
    let pairwise = [
        Case::new(7, 3, true, 2),
        Case::new(6, 2, true, 1),
        Case::new(8, 1, false, 1).with_cap(1),
    ];
    for (i, case) in pairwise.into_iter().enumerate() {
        Opened::new(
            case,
            MerkleArity::Two,
            pair_mmcs(case.cap_height),
            0x5eed + i as u64,
        )
        .check_honest();
    }
    let case = Case::new(8, 3, true, 1).with_cap(1);
    Opened::new(case, MerkleArity::Four, quad_mmcs(case.cap_height), 0x4a4a).check_honest();
}

/// The Keccak table's shape at the native fixed point: 1,625 columns over 2^17 rows, every
/// column read one row ahead, so the reduction sends carry and last and runs all 22 rounds.
#[test]
fn native_poly_packed_opening_replays_the_keccak_shape() {
    let case = Case::new(17, 1625, true, 1);
    let opened = Opened::new(case, MerkleArity::Two, pair_mmcs(0), 0x4ecc);
    assert!(opened.proof.opening.reduction.claims[0].successor.is_some());
    assert_eq!(
        opened
            .proof
            .opening
            .reduction
            .sumcheck
            .polynomial_evaluations
            .len(),
        opened.high()
    );
    opened.check_honest();
}

/// Expression nodes of the native packed opening at the Keccak table's shape, 1,625 columns
/// over 2^17 rows with every column read one row ahead: the column batch with the ring switch,
/// and the packed WHIR opening at security 32, rate 3 and folds of four, without grinding.
/// The bounds are 1.2 times the counts measured on the native transcript and WHIR kernel
/// these circuits are built from, and are updatable when either changes.
#[test]
fn node_counts_at_the_keccak_shape() {
    const MEASURED_RING: usize = 398_229;
    const MEASURED_WHIR: usize = 205_987;
    let case = Case::new(17, 1625, true, 1);
    let variables = case.bit_variables() - ABSORBED;
    let config = whir_config(variables, 32, 3, 4);
    let verifier =
        BinaryPolyBooleanWhirTraceVerifier::new(&config, case.protocol(), ByteHash::Keccak256, 0)
            .unwrap();
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let cap = vec![
        b.alloc_public_input_array::<16>("packed commitment root")
            .to_vec(),
    ];
    let points = vec![
        (0..case.rows)
            .map(|_| public_value(&mut b))
            .collect::<Vec<_>>(),
    ];
    let proof = verifier
        .input_shape()
        .allocate_native_targets(&mut b)
        .unwrap();
    let ch = native_challenger(&mut b);
    let before = b.construction_usage().unwrap().expression_nodes;
    verifier
        .verify_at_native(&mut b, ch, &cap, &points, &proof)
        .unwrap();
    let total = b.construction_usage().unwrap().expression_nodes - before;

    let packed = OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(variables, 1),
        vec![OpeningBatch::new(vec![0], vec![])],
    )]);
    let whir = BinaryPolyWhirVerifier::new(
        &config,
        packed,
        SuffixProver::<F, E>::variable_order(),
        ByteHash::Keccak256,
        0,
    )
    .unwrap();
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let cap = vec![
        b.alloc_public_input_array::<16>("packed commitment root")
            .to_vec(),
    ];
    let point = vec![
        (0..variables)
            .map(|_| public_value(&mut b))
            .collect::<Vec<_>>(),
    ];
    let opening = whir.input_shape().allocate_native_targets(&mut b).unwrap();
    let ch = native_challenger(&mut b);
    let before = b.construction_usage().unwrap().expression_nodes;
    whir.verify_at_native(&mut b, ch, &cap, &point, &opening)
        .unwrap();
    let packed_whir = b.construction_usage().unwrap().expression_nodes - before;
    let ring = total - packed_whir;

    println!(
        "native Poly64 packed opening at (17, 1625): {total} nodes; column batch and ring \
         switch {ring}, packed WHIR {packed_whir}"
    );
    assert!(
        ring * 5 <= MEASURED_RING * 6,
        "{ring} column batch and ring switch nodes"
    );
    assert!(
        packed_whir * 5 <= MEASURED_WHIR * 6,
        "{packed_whir} packed WHIR nodes"
    );
}

/// A verifier of the other tree arity, in either direction, or of another cap height, higher
/// or lower, refuses the import at its configuration check before the transcript moves. The
/// arity cases use single-root caps, so the cap's root count cannot tell the trees apart.
#[test]
fn a_foreign_tree_is_refused_at_import() {
    let case = Case::new(8, 3, true, 1);
    let pair = Opened::new(case, MerkleArity::Two, pair_mmcs(0), 0xa2);
    let quad = Opened::new(case, MerkleArity::Four, quad_mmcs(0), 0xa4);
    let capped = case.with_cap(1);
    let quad_capped = Opened::new(capped, MerkleArity::Four, quad_mmcs(1), 0xa41);
    pair.check_foreign_tree(MerkleArity::Four, 0);
    quad.check_foreign_tree(MerkleArity::Two, 0);
    pair.check_foreign_tree(MerkleArity::Two, 1);
    quad_capped.check_foreign_tree(MerkleArity::Four, 0);
    // Four roots on both sides: a pairwise cap two levels high.
    quad_capped.check_foreign_tree(MerkleArity::Two, 2);
}

/// Every committed class of the native witness is bound: changing an opened value, a tensor,
/// carry or last row, a round message, the surviving value, or any part of the packed
/// opening fails witness generation in a circuit holding only the verifier's constraints.
#[test]
fn every_private_class_is_bound() {
    let opened = Opened::new(
        Case::new(7, 3, true, 1),
        MerkleArity::Two,
        pair_mmcs(0),
        0x7a3e,
    );
    let circuit = opened.native_circuit(false);
    let public = opened.native_public(false);
    let private = opened.native_private();
    assert!(accepts(&circuit, &public, &private));
    let width = opened.case.width;
    let tensors = LIMBS * opened.proof.values.len();
    let sumcheck = tensors + 3 * ROWS;
    let survivor = sumcheck + 2 * LIMBS * opened.high();
    let whir = survivor + LIMBS;
    let packed = &opened.proof.opening.opening;
    assert_eq!(
        private[whir..whir + LIMBS],
        packed.evals[0].current()[0].coefficients()
    );
    let ood = packed
        .whir
        .initial_ood_answers
        .first()
        .or_else(|| {
            packed
                .whir
                .rounds
                .first()
                .and_then(|r| r.ood_answers.first())
        })
        .copied()
        .expect("the packed opening samples out of domain");
    let (leaf, sibling) = match &packed.whir.final_openings {
        QueryOpenings::Base(o) => (o.rows[0][0], o.proof.sibling_hashes[0]),
        QueryOpenings::Extension(o) => (o.rows[0][0].coefficients()[0], o.proof.sibling_hashes[0]),
    };
    let sibling: Vec<F> = bytes_to_limbs(&sibling)
        .into_iter()
        .map(|word| F::new(u64::from(word)))
        .collect();
    for (class, index) in [
        ("current value", 0),
        ("successor value", LIMBS * width + 2),
        ("tensor row", tensors + 5),
        ("carry row", tensors + ROWS + 5),
        ("last row", tensors + 2 * ROWS + 191),
        ("round message", sumcheck + 4),
        ("surviving value", survivor + 1),
        ("WHIR evaluation", whir + 2),
        (
            "OOD answer",
            locate(&private, &ood.coefficients(), whir + LIMBS),
        ),
        ("Merkle sibling", locate(&private, &sibling, whir + LIMBS)),
        ("leaf cell", locate(&private, &[leaf], whir + LIMBS)),
    ] {
        let mut wrong = private.clone();
        wrong[index] += F::ONE;
        assert!(!accepts(&circuit, &public, &wrong), "{class} at {index}");
    }
}

/// The import refuses a changed opened value, which the released ring switch replay rejects,
/// and a surviving value other than the packed opening's evaluation, and leaves the caller's
/// transcript untouched.
#[test]
fn tampered_proofs_are_refused_at_import() {
    let opened = Opened::new(
        Case::new(7, 3, true, 1),
        MerkleArity::Two,
        pair_mmcs(0),
        0x0d0f,
    );
    let mut value = opened.proof.clone();
    value.values[1] += E::ONE;
    let mut survivor = opened.proof.clone();
    survivor.opening.reduction.final_eval += E::ONE;
    for (proof, expected) in [
        (value, "replay failed"),
        (survivor, "surviving value differs"),
    ] {
        let (imported, mut entry) = opened.import(&proof);
        let error = imported.err().unwrap();
        assert!(error.contains(expected), "{expected}: {error}");
        let mut untouched = challenger();
        opened
            .pcs
            .observe_commitment(&opened.commitment, &mut untouched);
        assert_eq!(
            entry.sample_algebra_element::<E>(),
            untouched.sample_algebra_element::<E>()
        );
    }
}

/// Generic column routes and batched routes over several tables are refused before any
/// constraint is added.
#[test]
fn unsupported_routes_are_refused() {
    let generic = OpeningProtocol::new(vec![
        TableSpec::new(
            TableShape::new(7, 2),
            vec![OpeningBatch::new(vec![1, 0], vec![0])],
        ),
        TableSpec::new(
            TableShape::new(6, 3),
            vec![OpeningBatch::new(vec![2], vec![1, 2])],
        ),
    ]);
    // Every batch is complete, so each table is one batched run with its own transcript.
    let several_tables = OpeningProtocol::new(vec![
        TableSpec::new(
            TableShape::new(7, 2),
            vec![OpeningBatch::new(vec![0, 1], vec![0, 1])],
        ),
        TableSpec::new(
            TableShape::new(6, 3),
            vec![OpeningBatch::new(vec![0, 1, 2], vec![])],
        ),
    ]);
    for protocol in [generic, several_tables] {
        let n = plan_stacked_layout(&protocol.table_shapes()).0;
        let verifier = BinaryPolyBooleanWhirTraceVerifier::new(
            &packed_config(n - ABSORBED),
            protocol.clone(),
            ByteHash::Keccak256,
            0,
        )
        .unwrap();
        let mut b = CircuitBuilder::<F>::new();
        let cap = vec![
            b.alloc_public_input_array::<16>("packed commitment root")
                .to_vec(),
        ];
        let points: Vec<Vec<_>> = protocol
            .iter_openings()
            .map(|(table, _)| {
                (0..protocol.table_shapes()[table].num_variables())
                    .map(|_| public_value(&mut b))
                    .collect()
            })
            .collect();
        let proof = verifier
            .input_shape()
            .allocate_native_targets(&mut b)
            .unwrap();
        let ch = native_challenger(&mut b);
        let before = b.construction_usage().unwrap();
        let error = verifier
            .verify_at_native(&mut b, ch, &cap, &points, &proof)
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("column-batched route of one table"),
            "{error}"
        );
        let after = b.construction_usage().unwrap();
        assert_eq!(after.expression_nodes, before.expression_nodes);
        assert_eq!(after.pending_connects, before.pending_connects);
    }
}

/// The surviving value of the ring switch is constrained equal to the packed opening's
/// evaluation, the one link from the readings to the commitment. A ring switch run on another
/// packing, closed at its own surviving value, followed by the committed packing's opening at
/// that surviving point, passes every other check: each part imports on its own, the whole
/// proof does not, and the circuit refuses it.
#[test]
fn the_surviving_value_is_the_packed_evaluation() {
    let variables = 9;
    let high = variables - ABSORBED;
    let config = packed_config(high);
    let mmcs = pair_mmcs(0);
    let inner = WhirProver::<E, F, _, _, Ch, SuffixProver<F, E>>::new(
        config.clone(),
        BinaryWhirDomain::<F>::default(),
        mmcs.clone(),
    );
    let specs = vec![BinaryRingClaimSpec {
        current: true,
        next_rows: None,
    }];
    let verifier =
        BinaryPolyBooleanWhirVerifier::new(&config, specs.clone(), ByteHash::Keccak256, 0).unwrap();
    let ring = BinaryPolyBitRingVerifier::new(variables, specs).unwrap();
    let protocol = OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(high, 1),
        vec![OpeningBatch::new(vec![0], vec![])],
    )]);
    let whir = BinaryPolyWhirVerifier::new(
        &config,
        protocol.clone(),
        SuffixProver::<F, E>::variable_order(),
        ByteHash::Keccak256,
        0,
    )
    .unwrap();

    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let cap = vec![
        b.alloc_public_input_array::<16>("packed commitment root")
            .to_vec(),
    ];
    let reading = NativePolyBitRingReading {
        point: (0..variables).map(|_| public_value(&mut b)).collect(),
        current: Some(public_value(&mut b)),
        next: None,
    };
    let targets = verifier
        .input_shape()
        .allocate_native_targets(&mut b)
        .unwrap();
    let mut ch = native_challenger(&mut b);
    verifier
        .observe_commitment_native(&mut b, &mut ch, &cap)
        .unwrap();
    verifier
        .verify_readings_native(&mut b, ch, &cap, core::slice::from_ref(&reading), &targets)
        .unwrap();
    let circuit = b.build().unwrap();

    let mut sampler = Sampler(0x5e1f);
    let point = sampler.point(variables);
    let committed = sampler.bases(1 << high);
    let mut other = committed.clone();
    other[0] += F::ONE;
    for (switched, honest) in [(&committed, true), (&other, false)] {
        let mut prover = challenger();
        let table = Table::new(RowMajorMatrix::new(committed.clone(), committed.len()));
        let witness =
            SuffixProver::<F, E>::new_witness(vec![table], config.round_folding_factor(0));
        let (commitment, data) = inner.commit(witness, &mut prover).unwrap();
        let entry = prover.clone();
        let claims =
            BitRingSwitchClaims::new(vec![BitRingSwitch::<F, E>::new(&point).unwrap()]).unwrap();
        let packing = BitPacking::from_packed(Poly::new(switched.clone())).unwrap();
        let (reduction, survivor, value) = claims.prove::<E, _, _>(&packing, &mut prover);
        let current = claims.reductions()[0].incoming_claim(&reduction.claims[0].tensor);
        let opening = inner
            .open_at(
                data,
                &protocol,
                core::slice::from_ref(&survivor),
                &mut prover,
            )
            .unwrap();
        assert_eq!(opening.evals[0].current()[0] == value, honest);

        let readings = [(Some(current), None)];
        let (ring_input, imported, mut rest) = ring
            .import_native(
                core::slice::from_ref(&point),
                &readings,
                &reduction,
                entry.clone(),
            )
            .unwrap();
        assert_eq!(imported, survivor);
        let whir_input = whir
            .import_native(
                &config,
                &mmcs,
                &commitment,
                &[survivor],
                &opening,
                &mut rest,
            )
            .unwrap();
        let mut private = ring_input
            .private_native_values(&ring.input_shape())
            .unwrap();
        private.extend(
            whir_input
                .private_native_values(&whir.input_shape())
                .unwrap(),
        );
        let whole = verifier.import_native(
            &config,
            &mmcs,
            &commitment,
            core::slice::from_ref(&point),
            &readings,
            &BooleanWhirProof { reduction, opening },
            &mut entry.clone(),
        );
        if honest {
            let whole = whole
                .unwrap()
                .private_native_values(&verifier.input_shape())
                .unwrap();
            assert_eq!(whole, private);
        } else {
            assert!(whole.is_err());
        }

        let mut public: Vec<F> = bytes_to_limbs(&commitment.roots()[0])
            .into_iter()
            .map(|word| H::encode_u16(word).unwrap())
            .collect();
        public.extend(point.iter().flat_map(|x| x.coefficients()));
        public.extend(current.coefficients());
        assert_eq!(accepts(&circuit, &public, &private), honest);
    }
}
