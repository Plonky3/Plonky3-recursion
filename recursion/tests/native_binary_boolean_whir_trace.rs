//! Packed-bit trace openings verified in the native Tower128 carrier: column batching, the
//! bit ring switch with every sumcheck round, and the packed WHIR opening, checked against
//! the released Boolean trace commitment and the prime-host verifier.

use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_binary_pcs::whir::{BinaryWhirDomain, BooleanWhirPcs, BooleanWhirProof};
use p3_binary_pcs::{BooleanTraceCommitment, BooleanTraceCommitmentProof};
use p3_challenger::FieldChallenger;
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::{ByteHash, NativeTower128Target, bytes_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_commit::MultilinearPcs;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_merkle_tree::MerkleCap;
use p3_multilinear_util::point::Point;
use p3_multilinear_util::poly::Poly;
use p3_recursion::BinaryTower128Challenger;
use p3_recursion::pcs::binary::{
    BinaryBitRingVerifier, BinaryBooleanWhirTraceVerifier, BinaryBooleanWhirVerifier,
    BinaryRingClaimSpec, BinaryWhirVerifier, NativeBitRingReading,
};
use p3_sumcheck::layout::{Layout, SuffixProver, Table, plan_stacked_layout};
use p3_sumcheck::ring_switch::bits::{BitPacking, BitRingSwitch, BitRingSwitchClaims};
use p3_sumcheck::{OpeningBatch, OpeningProtocol, PrescribedPointPcs, TableShape, TableSpec};
use p3_test_utils::binary_field_params::keccak;
use p3_whir::pcs::proof::QueryOpenings;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirConfig, WhirProver};

type F = BinaryField128;
type H = NativeBinaryEncoding;
type Ch = keccak::LevelChallenger<F>;
type Mmcs = keccak::LevelMmcs<F>;
type Pcs = BooleanTraceCommitment<F, BooleanWhirPcs<F, F, BinaryWhirDomain<F>, Mmcs, Ch>>;
type Proof = BooleanTraceCommitmentProof<F, BooleanWhirProof<F, F, Mmcs>>;

/// Coordinates one packed Tower128 element absorbs.
const ABSORBED: usize = 7;
/// Bytes every transcript here starts from, natively and in each circuit. An even count keeps
/// the circuit transcript's later sixteen-bit words aligned, as they are inside a proof.
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

    fn field(&mut self) -> F {
        F::from_repr(u128::from(self.next_u64()) << 64 | u128::from(self.next_u64()))
    }

    fn fields(&mut self, count: usize) -> Vec<F> {
        (0..count).map(|_| self.field()).collect()
    }
}

fn challenger() -> Ch {
    Ch::from_hasher(INITIAL.to_vec(), keccak::byte_hash())
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

    /// The packed WHIR configuration the tests open with: small security, so the circuits
    /// stay small, and folds of four once the packing has that many variables.
    fn config(&self) -> WhirConfig<F, F, Ch> {
        packed_config(self.bit_variables() - ABSORBED, 8, 1)
    }
}

fn packed_config(variables: usize, security: usize, rate: usize) -> WhirConfig<F, F, Ch> {
    WhirConfig::new_with_domain(
        variables,
        ProtocolParameters {
            security_level: security,
            pow_bits: 0,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(if variables >= 4 { 4 } else { 1 }),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: rate,
        },
        &BinaryWhirDomain::<F>::default(),
    )
    .unwrap()
}

const fn mmcs(cap_height: usize) -> Mmcs {
    Mmcs::new(
        keccak::FieldHash::new(keccak::byte_hash()),
        keccak::Compress::new(keccak::byte_hash()),
        cap_height,
    )
}

/// A released opening of random bits at random row points, verified natively, with the
/// recursive verifier over the same geometry.
struct Opened {
    case: Case,
    protocol: OpeningProtocol,
    config: WhirConfig<F, F, Ch>,
    mmcs: Mmcs,
    pcs: Pcs,
    verifier: BinaryBooleanWhirTraceVerifier,
    commitment: MerkleCap<F, [u8; 32]>,
    points: Vec<Point<F>>,
    proof: Proof,
    /// The released verifier's next challenge after the opening.
    next: F,
}

impl Opened {
    /// `first` replaces every row point's first coordinate.
    fn new(case: Case, seed: u64, first: Option<F>) -> Self {
        let protocol = case.protocol();
        let config = case.config();
        let mmcs = mmcs(case.cap_height);
        let inner = WhirProver::<F, F, _, _, Ch, SuffixProver<F, F>>::new(
            config.clone(),
            BinaryWhirDomain::<F>::default(),
            mmcs.clone(),
        );
        let pcs = BooleanTraceCommitment::from_commitment(
            BooleanWhirPcs::new(inner, case.bit_variables()).unwrap(),
        );
        let verifier = BinaryBooleanWhirTraceVerifier::new(
            &config,
            protocol.clone(),
            ByteHash::Keccak256,
            case.cap_height,
        )
        .unwrap();
        let mut sampler = Sampler(seed);
        let blocks = (1usize << case.rows).div_ceil(64);
        let mut words: Vec<u64> = (0..case.width * blocks)
            .map(|_| sampler.next_u64())
            .collect();
        // Every column's last row is set, so the repeated last row a successor reads is never
        // zero. Rows are a whole number of 64-row blocks here.
        assert!(case.rows >= 6);
        for word in &mut words[(blocks - 1) * case.width..] {
            *word |= 1 << 63;
        }
        let table = Table::from_packed_bits(RowMajorMatrix::new(words, case.width), case.rows);
        let points: Vec<_> = (0..case.openings)
            .map(|_| {
                let mut point = sampler.fields(case.rows);
                if let Some(first) = first {
                    point[0] = first;
                }
                Point::new(point)
            })
            .collect();
        let mut prover = challenger();
        let (commitment, data) = pcs.commit(vec![table], &mut prover).unwrap();
        let proof = pcs.open_at(data, &protocol, &points, &mut prover).unwrap();
        let mut released = challenger();
        pcs.observe_commitment(&commitment, &mut released);
        pcs.verify_at(&commitment, &proof, &protocol, &points, &mut released)
            .unwrap();
        let next = released.sample_algebra_element::<F>();
        Self {
            case,
            protocol,
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
        proof: &Proof,
    ) -> (
        Result<p3_recursion::pcs::binary::NativeBinaryBooleanWhirTraceInput, String>,
        Ch,
    ) {
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
            .map_err(|error| format!("{error:?}"));
        (result, entry)
    }

    /// The native circuit's private inputs for the honest proof.
    fn native_private(&self) -> Vec<F> {
        let (imported, mut entry) = self.import(&self.proof);
        let imported = imported.unwrap();
        assert_eq!(entry.sample_algebra_element::<F>(), self.next);
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
        public.extend(self.points.iter().flat_map(|point| point.iter().copied()));
        if bound {
            public.extend(&self.proof.values);
            public.push(self.next);
        }
        public
    }

    /// The native verifier circuit. A bound circuit also constrains the returned values to
    /// the opened values and its next challenge to the released one; an unbound circuit
    /// holds the verifier's own constraints only.
    fn native_circuit(&self, bound: bool) -> Circuit<F> {
        let mut b = CircuitBuilder::<F>::new();
        b.enable_native_keccak_f1600().unwrap();
        let cap: Vec<_> = (0..1usize << self.case.cap_height)
            .map(|_| {
                b.alloc_public_input_array::<16>("packed commitment root")
                    .to_vec()
            })
            .collect();
        let points: Vec<Vec<_>> = self
            .points
            .iter()
            .map(|point| point.iter().map(|_| public_scalar(&mut b)).collect())
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
        assert_eq!(evals.len(), self.protocol.num_openings());
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
}

fn public_scalar(b: &mut CircuitBuilder<F>) -> NativeTower128Target {
    let expression = b.public_input();
    b.native_tower128_from_expr(expression)
}

/// Constrains `actual` to the next public input.
fn bind(b: &mut CircuitBuilder<F>, actual: &NativeTower128Target) {
    let expected = public_scalar(b);
    let difference = b.sub(actual.as_expr(), expected.as_expr());
    b.assert_zero(difference);
}

fn native_challenger(b: &mut CircuitBuilder<F>) -> BinaryTower128Challenger {
    let initial = INITIAL.map(|byte| b.define_const(H::encode_u16(u16::from(byte)).unwrap()));
    BinaryTower128Challenger::with_initial_bytes_with_host::<H, F>(b, ByteHash::Keccak256, &initial)
        .unwrap()
}

fn native_sample(
    b: &mut CircuitBuilder<F>,
    ch: &mut BinaryTower128Challenger,
) -> NativeTower128Target {
    let bits = ch.sample_with_host::<H, F>(b).unwrap();
    b.native_tower128_from_bits(*bits.bits()).unwrap()
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
/// leaves the transcript where the released verifier leaves it: across widths that pad the
/// column batch, a successor inside one element and one spanning elements, two openings
/// batched under lambda, and a cap of two levels.
#[test]
fn native_packed_openings_replay_the_released_commitment() {
    let cases = [
        Case::new(7, 3, true, 2),
        Case::new(8, 1, true, 2),
        Case::new(8, 1, false, 2),
        Case::new(10, 1625, true, 1),
        Case::new(10, 1625, true, 1).with_cap(2),
        Case::new(10, 1625, false, 1).with_cap(2),
    ];
    for (i, case) in cases.into_iter().enumerate() {
        let opened = Opened::new(case, 0x5eed + i as u64, None);
        let circuit = opened.native_circuit(true);
        let public = opened.native_public(true);
        let private = opened.native_private();
        assert!(accepts(&circuit, &public, &private), "{case:?}");
        // The returned values and the continuation are bound: changing the last opened value
        // or the next challenge is refused.
        for index in [public.len() - 2, public.len() - 1] {
            let mut wrong = public.clone();
            wrong[index] += F::ONE;
            assert!(
                !accepts(&circuit, &wrong, &private),
                "{case:?} public {index}"
            );
        }
    }
}

/// The Keccak table's shape at the native fixed point: 1,625 columns over 2^17 rows, every
/// column read one row ahead.
#[test]
fn native_packed_opening_replays_the_keccak_shape() {
    let opened = Opened::new(Case::new(17, 1625, true, 1), 0x4ecc, None);
    let circuit = opened.native_circuit(true);
    assert!(accepts(
        &circuit,
        &opened.native_public(true),
        &opened.native_private()
    ));
}

/// Every committed class of the native witness is bound: changing any one value fails
/// witness generation in a circuit holding only the verifier's constraints.
#[test]
fn every_private_class_is_bound() {
    let opened = Opened::new(Case::new(10, 1625, true, 1), 0x7a3e, None);
    let circuit = opened.native_circuit(false);
    let public = opened.native_public(false);
    let private = opened.native_private();
    assert!(accepts(&circuit, &public, &private));
    let width = opened.case.width;
    let values = opened.proof.values.len();
    let tensors = values;
    let sumcheck = tensors + 3 * 128;
    let survivor = sumcheck + 2 * opened.high();
    let whir = survivor + 1;
    let packed = &opened.proof.opening.opening.whir;
    let ood = packed
        .initial_ood_answers
        .first()
        .or_else(|| packed.rounds.first().and_then(|r| r.ood_answers.first()))
        .copied()
        .expect("the packed opening samples out of domain");
    let (leaf, sibling) = match &packed.final_openings {
        QueryOpenings::Base(o) => (o.rows[0][0], o.proof.sibling_hashes[0]),
        QueryOpenings::Extension(o) => (o.rows[0][0], o.proof.sibling_hashes[0]),
    };
    let sibling: Vec<F> = bytes_to_limbs(&sibling)
        .into_iter()
        .map(|word| F::from_repr(u128::from(word)))
        .collect();
    assert_eq!(
        private[whir],
        opened.proof.opening.opening.evals[0].current()[0]
    );
    for (class, index) in [
        ("current value", 0),
        ("successor value", width),
        ("tensor row", tensors + 5),
        ("carry row", tensors + 128 + 5),
        ("last row", tensors + 256 + 5),
        ("sumcheck coefficient", sumcheck + 3),
        ("survivor", survivor),
        ("WHIR evaluation", whir),
        ("OOD answer", locate(&private, &[ood], whir)),
        ("Merkle sibling", locate(&private, &sibling, whir)),
        ("leaf cell", locate(&private, &[leaf], whir)),
    ] {
        let mut wrong = private.clone();
        wrong[index] += F::ONE;
        assert!(!accepts(&circuit, &public, &wrong), "{class} at {index}");
    }
}

/// The prime-host verifier and the native one accept the same imported proof, and both
/// refuse it with an opened value or a tensor row changed.
#[test]
fn prime_and_native_verifiers_agree() {
    check_prime_agreement(Case::new(8, 1, false, 1), 0x9a17);
}

/// As [`prime_and_native_verifiers_agree`], with the successor reading and its carry and last
/// elements in both verifiers.
#[test]
#[ignore = "the prime-host circuit with successor elements takes about two minutes and 6 GB in a debug build"]
fn prime_and_native_verifiers_agree_with_successor_elements() {
    check_prime_agreement(Case::new(8, 1, true, 1), 0x9a18);
}

fn check_prime_agreement(case: Case, seed: u64) {
    let opened = Opened::new(case, seed, None);
    let native = opened.native_circuit(false);
    let native_public = opened.native_public(false);
    let native_private = opened.native_private();

    let shape = opened.verifier.input_shape();
    let mut b = CircuitBuilder::<BabyBear>::new();
    b.enable_keccak_f1600::<BabyBear>();
    let cap = vec![
        b.alloc_private_input_array::<16>("packed commitment")
            .to_vec(),
    ];
    let points: Vec<Vec<_>> = opened
        .points
        .iter()
        .map(|point| {
            point
                .iter()
                .map(|_| {
                    let limbs = b.alloc_private_input_array::<8>("row coordinate");
                    b.binary128_from_limbs::<BabyBear>(limbs).unwrap()
                })
                .collect()
        })
        .collect();
    let proof = shape
        .allocate_targets::<BabyBear, BabyBear>(&mut b)
        .unwrap();
    let initial = INITIAL.map(|byte| b.define_const(BabyBear::from_u8(byte)));
    let mut ch = BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(
        &mut b,
        ByteHash::Keccak256,
        &initial,
    )
    .unwrap();
    opened
        .verifier
        .observe_commitment::<BabyBear, BabyBear>(&mut b, &mut ch, &cap)
        .unwrap();
    opened
        .verifier
        .verify_at::<BabyBear, BabyBear>(&mut b, ch, &cap, &points, &proof)
        .unwrap();
    let prime = b.build().unwrap();
    let pack = |raw: u128| (0..8).map(move |i| BabyBear::from_u16((raw >> (16 * i)) as u16));
    let mut prime_private: Vec<BabyBear> = bytes_to_limbs(&opened.commitment.roots()[0])
        .into_iter()
        .map(BabyBear::from_u16)
        .collect();
    prime_private.extend(
        opened
            .points
            .iter()
            .flat_map(|point| point.iter().flat_map(|&x| pack(x.to_repr()))),
    );
    let values_start = prime_private.len();
    let (imported, _) = opened.import(&opened.proof);
    prime_private.extend(
        imported
            .unwrap()
            .private_values::<BabyBear>(&shape)
            .unwrap(),
    );
    let prime_accepts = |private: &[BabyBear]| {
        let mut runner = prime.runner();
        runner
            .set_private_inputs(private)
            .and_then(|()| runner.run())
            .is_ok()
    };
    assert!(prime_accepts(&prime_private));
    assert!(accepts(&native, &native_public, &native_private));

    // The prime ring input repeats the lifted point and the readings before the tensor.
    let values = opened.proof.values.len();
    let readings = 1 + usize::from(case.next);
    let prime_tensor = values_start + 8 * (values + case.bit_variables() + readings);
    for (class, native_index, prime_index) in [
        ("opened value", 0, values_start),
        ("tensor row", values + 5, prime_tensor + 8 * 5),
    ] {
        let mut wrong = native_private.clone();
        wrong[native_index] += F::ONE;
        assert!(!accepts(&native, &native_public, &wrong), "native {class}");
        let mut wrong = prime_private.clone();
        wrong[prime_index] = BabyBear::from_u64(wrong[prime_index].as_canonical_u64() ^ 1);
        assert!(!prime_accepts(&wrong), "prime {class}");
    }
}

/// A dropped ring-switch round is refused at import, before the transcript moves. Points
/// whose first coordinate is one common bit let the released reduction skip a round; the
/// prime host imports that proof, while the native witness, which runs every round, refuses
/// it.
#[test]
fn round_counts_other_than_every_round_are_refused() {
    let opened = Opened::new(Case::new(10, 1625, true, 1), 0x0d0f, None);
    let mut wrong = opened.proof.clone();
    let rounds = &mut wrong.opening.reduction.sumcheck.polynomial_evaluations;
    rounds.truncate(rounds.len() - 1);
    let (imported, mut entry) = opened.import(&wrong);
    assert!(imported.is_err());
    let mut untouched = challenger();
    opened
        .pcs
        .observe_commitment(&opened.commitment, &mut untouched);
    assert_eq!(
        entry.sample_algebra_element::<F>(),
        untouched.sample_algebra_element::<F>()
    );

    let opened = Opened::new(Case::new(8, 1, false, 1), 0x0b17, Some(F::ONE));
    assert_eq!(
        opened
            .proof
            .opening
            .reduction
            .sumcheck
            .polynomial_evaluations
            .len(),
        opened.high() - 1
    );
    let (imported, _) = opened.import(&opened.proof);
    let imported = imported.unwrap();
    let shape = opened.verifier.input_shape();
    assert!(imported.private_values::<BabyBear>(&shape).is_ok());
    assert!(imported.private_native_values(&shape).is_err());
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
            TableShape::new(5, 3),
            vec![OpeningBatch::new(vec![2], vec![1, 2])],
        ),
        TableSpec::new(TableShape::new(6, 1), vec![]),
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
        let config = packed_config(n - ABSORBED, 8, 1);
        let verifier =
            BinaryBooleanWhirTraceVerifier::new(&config, protocol.clone(), ByteHash::Keccak256, 0)
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
                    .map(|_| public_scalar(&mut b))
                    .collect()
            })
            .collect();
        let proof = verifier
            .input_shape()
            .allocate_native_targets(&mut b)
            .unwrap();
        let ch = native_challenger(&mut b);
        let before = b.construction_usage().unwrap();
        assert!(
            verifier
                .verify_at_native(&mut b, ch, &cap, &points, &proof)
                .is_err()
        );
        let after = b.construction_usage().unwrap();
        assert_eq!(after.expression_nodes, before.expression_nodes);
        assert_eq!(after.pending_connects, before.pending_connects);
    }
}

/// The ring switch alone, with the readings and its surviving point and value as public
/// inputs. The ring switch absorbs neither the readings nor anything after the surviving
/// value, so changing the current or the successor reading alone fails only its column check,
/// and changing the surviving value together with the witness's copy of it fails only the
/// closing check. Covers a successor spanning elements, one inside an element, and none.
#[test]
fn ring_switch_readings_and_survivor_are_checked() {
    let variables = 10;
    let mut sampler = Sampler(0x41c3);
    for rows in [Some(9), Some(5), None] {
        let point = Point::new(sampler.fields(variables));
        let reduction = rows
            .map_or_else(
                || BitRingSwitch::new(&point),
                |rows| BitRingSwitch::with_successor(&point, rows),
            )
            .unwrap();
        let claims = BitRingSwitchClaims::new(vec![reduction]).unwrap();
        let packing =
            BitPacking::from_packed(Poly::new(sampler.fields(1 << (variables - ABSORBED))))
                .unwrap();
        let (proof, survivor, value) = claims.prove::<F, _, _>(&packing, &mut challenger());
        let reduction = &claims.reductions()[0];
        let current = reduction.incoming_claim(&proof.claims[0].tensor);
        let next = rows.map(|_| {
            reduction
                .successor_claim(&proof.claims[0].tensor, proof.claims[0].successor.as_ref())
                .unwrap()
        });
        let verifier = BinaryBitRingVerifier::<F>::new(
            variables,
            vec![BinaryRingClaimSpec {
                current: true,
                next_rows: rows,
            }],
        )
        .unwrap();
        let (input, imported_point, _) = verifier
            .import_native(
                core::slice::from_ref(&point),
                &[(Some(current), next)],
                &proof,
                challenger(),
            )
            .unwrap();
        assert_eq!(imported_point, survivor);

        let mut b = CircuitBuilder::<F>::new();
        b.enable_native_keccak_f1600().unwrap();
        let reading = NativeBitRingReading {
            point: (0..variables).map(|_| public_scalar(&mut b)).collect(),
            current: Some(public_scalar(&mut b)),
            next: rows.map(|_| public_scalar(&mut b)),
        };
        let targets = verifier
            .input_shape()
            .allocate_native_targets(&mut b)
            .unwrap();
        let ch = native_challenger(&mut b);
        let output = verifier
            .verify_native(&mut b, ch, core::slice::from_ref(&reading), &targets)
            .unwrap();
        for coordinate in &output.point {
            bind(&mut b, coordinate);
        }
        bind(&mut b, &output.value);
        let circuit = b.build().unwrap();

        let mut public = point.as_slice().to_vec();
        public.push(current);
        public.extend(next);
        let readings = public.len();
        public.extend(survivor.as_slice());
        public.push(value);
        let private = input
            .private_native_values(&verifier.input_shape())
            .unwrap();
        assert!(accepts(&circuit, &public, &private), "{rows:?}");
        for (reading, index) in [("current", variables), ("successor", variables + 1)]
            .into_iter()
            .filter(|&(_, index)| index < readings)
        {
            let mut wrong = public.clone();
            wrong[index] += F::ONE;
            assert!(!accepts(&circuit, &wrong, &private), "{rows:?} {reading}");
        }
        let (mut wrong_public, mut wrong_private) = (public.clone(), private.clone());
        *wrong_public.last_mut().unwrap() += F::ONE;
        *wrong_private.last_mut().unwrap() += F::ONE;
        assert!(
            !accepts(&circuit, &wrong_public, &wrong_private),
            "{rows:?} survivor"
        );
    }
}

/// The surviving value of the ring switch is constrained equal to the packed opening's
/// evaluation, the one link from the readings to the commitment. A ring switch run on another
/// packing, closed at its own surviving value, followed by the committed packing's opening at
/// that surviving point, passes every other check: each part imports on its own, the whole
/// proof does not, and the circuit refuses it.
#[test]
fn the_surviving_value_is_the_packed_evaluation() {
    let variables = 10;
    let high = variables - ABSORBED;
    let config = packed_config(high, 8, 1);
    let mmcs = mmcs(0);
    let inner = WhirProver::<F, F, _, _, Ch, SuffixProver<F, F>>::new(
        config.clone(),
        BinaryWhirDomain::<F>::default(),
        mmcs.clone(),
    );
    let specs = vec![BinaryRingClaimSpec {
        current: true,
        next_rows: None,
    }];
    let verifier =
        BinaryBooleanWhirVerifier::new(&config, specs.clone(), ByteHash::Keccak256, 0).unwrap();
    let ring = BinaryBitRingVerifier::<F>::new(variables, specs).unwrap();
    let protocol = OpeningProtocol::new(vec![TableSpec::new(
        TableShape::new(high, 1),
        vec![OpeningBatch::new(vec![0], vec![])],
    )]);
    let whir = BinaryWhirVerifier::<F>::new(
        &config,
        protocol.clone(),
        SuffixProver::<F, F>::variable_order(),
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
    let reading = NativeBitRingReading {
        point: (0..variables).map(|_| public_scalar(&mut b)).collect(),
        current: Some(public_scalar(&mut b)),
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
    let point = Point::new(sampler.fields(variables));
    let committed = sampler.fields(1 << high);
    let mut other = committed.clone();
    other[0] += F::ONE;
    for (switched, honest) in [(&committed, true), (&other, false)] {
        let mut prover = challenger();
        let table = Table::new(RowMajorMatrix::new(committed.clone(), committed.len()));
        let witness =
            SuffixProver::<F, F>::new_witness(vec![table], config.round_folding_factor(0));
        let (commitment, data) = inner.commit(witness, &mut prover).unwrap();
        let mut entry = prover.clone();
        let claims = BitRingSwitchClaims::new(vec![BitRingSwitch::new(&point).unwrap()]).unwrap();
        let packing = BitPacking::from_packed(Poly::new(switched.clone())).unwrap();
        let (reduction, survivor, value) = claims.prove::<F, _, _>(&packing, &mut prover);
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
            &mut entry,
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
        public.extend(point.iter().copied());
        public.push(current);
        assert_eq!(accepts(&circuit, &public, &private), honest);
    }
}

/// Expression nodes of the native packed opening at the Keccak table's shape, 1,625 columns
/// over 2^17 rows with every column read one row ahead: the column batch with the ring switch,
/// and the packed WHIR opening at security 32, rate 3 and folds of four, without grinding.
/// The bounds are 1.2 times the counts measured on the native transcript and WHIR kernel
/// these circuits are built from, and are updatable when either changes.
#[test]
fn node_counts_at_the_keccak_shape() {
    const MEASURED_RING: usize = 381_562;
    const MEASURED_WHIR: usize = 234_936;
    let case = Case::new(17, 1625, true, 1);
    let protocol = case.protocol();
    let variables = case.bit_variables() - ABSORBED;
    let config = packed_config(variables, 32, 3);
    let verifier =
        BinaryBooleanWhirTraceVerifier::new(&config, protocol, ByteHash::Keccak256, 0).unwrap();
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let cap = vec![
        b.alloc_public_input_array::<16>("packed commitment root")
            .to_vec(),
    ];
    let points = vec![
        (0..case.rows)
            .map(|_| public_scalar(&mut b))
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
    let whir = BinaryWhirVerifier::<F>::new(
        &config,
        packed,
        SuffixProver::<F, F>::variable_order(),
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
            .map(|_| public_scalar(&mut b))
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
        "native packed opening at (17, 1625): {total} nodes; column batch and ring switch \
         {ring}, packed WHIR {packed_whir}"
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
