//! A dense recurrence beside a Boolean-assuming Keccak-f table, proven through the composite.

use alloc::vec;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_pcs::BooleanTraceCommitment;
use p3_binary_pcs::whir::{BinaryWhirDomain, BooleanWhirPcs};
use p3_challenger::CanSample;
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::{KeccakBinaryAir, NUM_KECCAK_BINARY_COLS, generate_binary_trace_packed};
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::{
    MultiStarkProof, ProverInstance, ProverInstances, ProvingKey, VerifierInstance,
    VerifierInstances, VerifyingKey, prove_with_security, security_report, setup,
    verify_with_security,
};
use p3_sumcheck::{OpeningBatch, TableShape};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption, WhirProver};
use rand::rngs::SmallRng;
use rand::{RngExt, SeedableRng};

use super::*;

const HASH: ByteHash = ByteHash::Keccak256;
/// Two roots per part, so a swapped or truncated cap is still a well-formed cap.
const CAP_HEIGHT: usize = 1;
const FOLDING: usize = 2;
const DENSE_VARIABLES: usize = 4;
const DENSE_WIDTH: usize = 2;
/// Three permutations fill 75 rows, padded to 128.
const PERMUTATIONS: usize = 3;
const KECCAK_VARIABLES: usize = 7;
/// Instance order: dense, Keccak, dense, so dense tables sit on both sides of the packed one.
const KECCAK: usize = 1;
const POW_BITS: usize = 0;
const TARGET_BITS: usize = 20;

type Config = BinaryNativeMixedWhirConfig;

/// A degree-two recurrence reading the next row and one preprocessed weight column.
///
/// ```text
///     first row    (a, b) = public values
///     transition   a' = b,   b' = a·b + w
/// ```
fn eval_dense<AB: AirBuilder<F = E>>(b: &mut AB) {
    let main = b.main();
    let (cur, next) = (main.current_slice(), main.next_slice());
    let w = b.preprocessed().current_slice()[0];
    let (first, second) = (b.public_values()[0], b.public_values()[1]);
    b.when_first_row().assert_eq(cur[0], first);
    b.when_first_row().assert_eq(cur[1], second);
    b.when_transition().assert_eq(next[0], cur[1]);
    b.when_transition().assert_eq(next[1], cur[0] * cur[1] + w);
}

fn weights() -> Vec<E> {
    (0..1 << DENSE_VARIABLES)
        .map(|row| E::from_bool(row % 3 == 0))
        .collect()
}

enum TestAir {
    Dense,
    Keccak(KeccakBinaryAir),
}

impl BaseAir<E> for TestAir {
    fn width(&self) -> usize {
        match self {
            Self::Dense => DENSE_WIDTH,
            Self::Keccak(air) => BaseAir::<E>::width(air),
        }
    }
    fn num_public_values(&self) -> usize {
        match self {
            Self::Dense => 2,
            Self::Keccak(_) => 0,
        }
    }
    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Dense => 1,
            Self::Keccak(_) => 0,
        }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<E>> {
        match self {
            Self::Dense => Some(RowMajorMatrix::new(weights(), 1)),
            Self::Keccak(_) => None,
        }
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        match self {
            Self::Dense => (0..DENSE_WIDTH).collect(),
            Self::Keccak(air) => BaseAir::<E>::main_next_row_columns(air),
        }
    }
    fn max_constraint_degree(&self) -> Option<usize> {
        match self {
            Self::Dense => None,
            Self::Keccak(air) => BaseAir::<E>::max_constraint_degree(air),
        }
    }
    fn num_constraints(&self) -> Option<usize> {
        match self {
            Self::Dense => None,
            Self::Keccak(air) => BaseAir::<E>::num_constraints(air),
        }
    }
    fn assumes_boolean_trace(&self) -> bool {
        match self {
            Self::Dense => false,
            Self::Keccak(air) => BaseAir::<E>::assumes_boolean_trace(air),
        }
    }
}

impl<AB: AirBuilder<F = E>> Air<AB> for TestAir {
    fn eval(&self, b: &mut AB) {
        match self {
            Self::Dense => eval_dense(b),
            Self::Keccak(air) => air.eval(b),
        }
    }
}

/// The dense recurrence from `(first, second)`, as one column-major table.
fn dense_table(first: E, second: E) -> Table<E> {
    let rows = 1 << DENSE_VARIABLES;
    let (mut a, mut b) = (vec![first], vec![second]);
    for (row, w) in weights().into_iter().enumerate().take(rows - 1) {
        a.push(b[row]);
        b.push(a[row] * b[row] + w);
    }
    Table::new(RowMajorMatrix::new([a, b].concat(), rows))
}

fn keccak_table() -> Table<E> {
    let mut rng = SmallRng::seed_from_u64(11);
    let inputs = (0..PERMUTATIONS)
        .map(|_| core::array::from_fn(|_| rng.random()))
        .collect();
    Table::from_packed_bits(generate_binary_trace_packed::<E>(inputs), KECCAK_VARIABLES)
}

/// The packed Keccak table rewritten with dense field cells, one per bit.
fn dense_keccak_cells() -> Vec<E> {
    keccak_table()
        .into_dense()
        .iter_polys()
        .flatten()
        .copied()
        .collect()
}

fn challenger() -> Challenger {
    BinaryNativeChallenger::fresh(vec![5, 0, 9], HASH)
}

fn parameters() -> ProtocolParameters {
    ProtocolParameters {
        security_level: 32,
        pow_bits: POW_BITS,
        round_log_inv_rates: vec![],
        folding_factor: FoldingFactor::Constant(FOLDING),
        soundness_type: SecurityAssumption::JohnsonBound,
        starting_log_inv_rate: 1,
    }
}

fn whir(num_variables: usize) -> DensePcs {
    let parameters =
        BinaryNativeWhirPcsParameters::<E>::new(num_variables, parameters(), HASH, CAP_HEIGHT)
            .unwrap();
    WhirProver::new(
        parameters.config,
        BinaryWhirDomain::<E>::default(),
        tree(HASH, CAP_HEIGHT),
    )
}

fn arity(shapes: &[TableShape]) -> usize {
    plan_stacked_layout(shapes).0
}

fn dense_shape() -> TableShape {
    TableShape::new(DENSE_VARIABLES, DENSE_WIDTH)
}

fn keccak_shape() -> TableShape {
    TableShape::new(KECCAK_VARIABLES, NUM_KECCAK_BINARY_COLS)
}

fn packed_pcs() -> NativeBooleanWhirTracePcs {
    let bits = arity(&[keccak_shape()]);
    let inner = whir(bits - 7);
    BooleanTraceCommitment::from_commitment(BooleanWhirPcs::new(inner, bits).unwrap())
}

fn dense_main_pcs() -> DensePcs {
    whir(arity(&[dense_shape(), dense_shape()]))
}

fn mixed_pcs(packed_table: usize) -> MixedWhirPcs {
    MixedWhirPcs::new(
        dense_main_pcs(),
        Some((packed_pcs(), packed_table)),
        CAP_HEIGHT,
    )
    .unwrap()
}

/// One batch opening every column at the current row and every column one row ahead.
fn full_spec(shape: TableShape) -> TableSpec {
    let all = (0..shape.width()).collect::<Vec<_>>();
    TableSpec::new(shape, vec![OpeningBatch::new(all.clone(), all)])
}

fn main_protocol(keccak: TableSpec) -> OpeningProtocol {
    OpeningProtocol::new(vec![
        full_spec(dense_shape()),
        keccak,
        full_spec(dense_shape()),
    ])
}

struct Fixture {
    airs: Vec<TestAir>,
    heights: Vec<usize>,
    public: Vec<Vec<E>>,
    config: Config,
    proving: ProvingKey<Config>,
    verifying: VerifyingKey<Config>,
}

impl Fixture {
    fn new() -> Self {
        let airs = vec![
            TestAir::Dense,
            TestAir::Keccak(KeccakBinaryAir::assuming_boolean_trace()),
            TestAir::Dense,
        ];
        let preprocessed = MixedWhirPcs::new(
            whir(arity(&[
                TableShape::new(DENSE_VARIABLES, 1),
                TableShape::new(DENSE_VARIABLES, 1),
            ])),
            None,
            CAP_HEIGHT,
        )
        .unwrap();
        let config = Config::new(mixed_pcs(KECCAK), Some(preprocessed)).unwrap();
        let refs = airs.iter().collect::<Vec<_>>();
        let (proving, verifying) = setup(&config, &refs, &mut challenger()).unwrap();
        Self {
            airs,
            heights: vec![DENSE_VARIABLES, KECCAK_VARIABLES, DENSE_VARIABLES],
            public: vec![
                vec![E::ONE, E::ONE + E::ONE + E::ONE],
                vec![],
                vec![E::ZERO, E::ONE],
            ],
            config,
            proving,
            verifying,
        }
    }

    fn tables(&self) -> Vec<Table<E>> {
        vec![
            dense_table(self.public[0][0], self.public[0][1]),
            keccak_table(),
            dense_table(self.public[2][0], self.public[2][1]),
        ]
    }

    fn verifier_instances(&self) -> VerifierInstances<'_, Config, TestAir> {
        VerifierInstances::new(
            self.airs
                .iter()
                .zip(&self.heights)
                .zip(&self.public)
                .map(|((air, &height), public)| {
                    VerifierInstance::new(air, &self.verifying, height, public)
                })
                .collect(),
        )
    }

    fn prove(&self) -> MultiStarkProof<Config> {
        let instances = ProverInstances::new(
            self.airs
                .iter()
                .zip(self.tables())
                .zip(&self.public)
                .map(|((air, table), public)| {
                    ProverInstance::new(air, table, &self.proving, public)
                })
                .collect(),
        );
        prove_with_security(
            &self.config,
            instances,
            POW_BITS,
            TARGET_BITS,
            &mut challenger(),
        )
        .unwrap()
    }

    fn verify(&self, proof: &MultiStarkProof<Config>) -> bool {
        verify_with_security(
            &self.config,
            self.verifier_instances(),
            proof,
            POW_BITS,
            TARGET_BITS,
            &mut challenger(),
        )
        .is_ok()
    }
}

fn cap_halves(cap: &Cap) -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
    let (dense, packed) = cap.roots().split_at(1 << CAP_HEIGHT);
    (dense.to_vec(), packed.to_vec())
}

#[test]
fn mixed_round_trip_with_security() {
    let fixture = Fixture::new();
    security_report(&fixture.config, &fixture.verifier_instances())
        .unwrap()
        .require_security(TARGET_BITS)
        .unwrap();

    let proof = fixture.prove();
    assert_eq!(proof.commitment.num_roots(), 2 << CAP_HEIGHT);
    assert!(proof.opening.packed.is_some());
    // The dense opening carries the two dense tables only; the Keccak values travel packed.
    assert_eq!(proof.opening.dense.evals.len(), 2);
    assert!(fixture.verify(&proof));
}

#[test]
fn mixed_security_is_union_of_parts() {
    let pcs = mixed_pcs(KECCAK);
    let composite = pcs
        .prescribed_security(&main_protocol(full_spec(keccak_shape())))
        .unwrap();

    let dense_protocol =
        OpeningProtocol::new(vec![full_spec(dense_shape()), full_spec(dense_shape())]);
    let packed_protocol = OpeningProtocol::new(vec![full_spec(keccak_shape())]);
    let dense = dense_main_pcs()
        .prescribed_security(&dense_protocol)
        .unwrap();
    let packed =
        PrescribedPointPcs::<E, Challenger>::prescribed_security(&packed_pcs(), &packed_protocol)
            .unwrap();
    // Both lists are larger than one, so a maximum would differ from the product.
    assert!(dense.log2_max_candidates > 0.0 && packed.log2_max_candidates > 0.0);

    assert_eq!(composite.terms, [dense.terms, packed.terms].concat());
    assert_eq!(
        composite.log2_max_candidates,
        dense.log2_max_candidates + packed.log2_max_candidates
    );
}

#[test]
fn mixed_transcript_order_pin() {
    let fixture = Fixture::new();
    let pcs = &fixture.config.main;

    let mut prover = challenger();
    let (cap, _) = pcs.commit(fixture.tables(), &mut prover).unwrap();
    let after_commit: E = prover.sample();

    let mut verifier = challenger();
    pcs.observe_commitment(&cap, &mut verifier);
    let after_observe: E = verifier.sample();

    let (dense, packed) = cap_halves(&cap);
    let replay = |order: [&Vec<[u8; 32]>; 2]| -> E {
        let mut challenger = challenger();
        dense_main_pcs().observe_commitment(&MerkleCap::new(order[0].clone()), &mut challenger);
        packed_pcs().observe_commitment(&MerkleCap::new(order[1].clone()), &mut challenger);
        challenger.sample()
    };

    assert_eq!(after_observe, replay([&dense, &packed]));
    assert_ne!(after_observe, replay([&packed, &dense]));
    assert_eq!(after_commit, after_observe);
}

#[test]
fn dense_only_observation_matches_dense_pcs() {
    let composite = MixedWhirPcs::new(dense_main_pcs(), None, CAP_HEIGHT).unwrap();
    let bare = dense_main_pcs();
    let tables = || vec![dense_table(E::ONE, E::ZERO), dense_table(E::ZERO, E::ONE)];

    let mut composite_prover = challenger();
    let (cap, _) = composite.commit(tables(), &mut composite_prover).unwrap();
    let mut bare_prover = challenger();
    let (bare_cap, _) = bare
        .commit(
            SuffixProver::<E, E>::new_witness(tables(), FOLDING),
            &mut bare_prover,
        )
        .unwrap();
    assert_eq!(cap.roots(), bare_cap.roots());
    assert_eq!(
        CanSample::<E>::sample(&mut composite_prover),
        CanSample::<E>::sample(&mut bare_prover)
    );

    let mut composite_verifier = challenger();
    composite.observe_commitment(&cap, &mut composite_verifier);
    let mut bare_verifier = challenger();
    bare.observe_commitment(&cap, &mut bare_verifier);
    assert_eq!(
        CanSample::<E>::sample(&mut composite_verifier),
        CanSample::<E>::sample(&mut bare_verifier)
    );

    let protocol = OpeningProtocol::new(vec![full_spec(dense_shape()), full_spec(dense_shape())]);
    let composite = composite.prescribed_security(&protocol).unwrap();
    let bare = bare.prescribed_security(&protocol).unwrap();
    assert_eq!(composite.terms, bare.terms);
    assert_eq!(composite.log2_max_candidates, bare.log2_max_candidates);
}

#[test]
fn tampered_mixed_proofs_are_rejected() {
    let fixture = Fixture::new();
    let proof = fixture.prove();
    assert!(fixture.verify(&proof));
    // The configuration is not `Clone`, so each tamper starts from a decoded copy.
    let bytes = postcard::to_allocvec(&proof).unwrap();
    let rejects = |tamper: &dyn Fn(&mut MultiStarkProof<Config>)| {
        let mut tampered: MultiStarkProof<Config> = postcard::from_bytes(&bytes).unwrap();
        assert!(fixture.verify(&tampered));
        tamper(&mut tampered);
        !fixture.verify(&tampered)
    };

    assert!(rejects(&|proof| {
        proof.opening.packed.as_mut().unwrap().values[0] += E::ONE;
    }));
    assert!(rejects(&|proof| {
        proof
            .opening
            .packed
            .as_mut()
            .unwrap()
            .opening
            .reduction
            .claims[0]
            .tensor
            .add_exterior_product(E::ONE, E::ONE);
    }));
    assert!(rejects(&|proof| {
        let batch = &proof.opening.dense.evals[0];
        let mut current = batch.current().to_vec();
        current[0] += E::ONE;
        proof.opening.dense.evals[0] = OpeningBatch::new(current, batch.next().to_vec());
    }));
    assert!(rejects(&|proof| {
        let (dense, packed) = cap_halves(&proof.commitment);
        proof.commitment = MerkleCap::new([packed, dense].concat());
    }));
    assert!(rejects(&|proof| {
        let (dense, _) = cap_halves(&proof.commitment);
        proof.commitment = MerkleCap::new(dense);
    }));
}

#[test]
fn non_bit_cell_refused_before_transcript() {
    let fixture = Fixture::new();
    let pcs = &fixture.config.main;
    let rows = 1 << KECCAK_VARIABLES;
    let with_keccak = |cells: Vec<E>| {
        let mut tables = fixture.tables();
        tables[KECCAK] = Table::new(RowMajorMatrix::new(cells, rows));
        tables
    };

    // Dense storage holding only bits commits exactly as the packed storage does.
    let (packed_cap, _) = pcs.commit(fixture.tables(), &mut challenger()).unwrap();
    let (dense_cap, _) = pcs
        .commit(with_keccak(dense_keccak_cells()), &mut challenger())
        .unwrap();
    assert_eq!(packed_cap.roots(), dense_cap.roots());

    const COLUMN: usize = 17;
    let non_bit: E = SmallRng::seed_from_u64(3).random();
    assert!(non_bit != E::ZERO && non_bit != E::ONE);
    let mut cells = dense_keccak_cells();
    cells[COLUMN * rows + 5] = non_bit;

    let mut moved = challenger();
    let mut untouched = moved.clone();
    let refused = pcs.commit(with_keccak(cells), &mut moved);
    assert!(matches!(
        refused,
        Err(MixedWhirError::Packed(
            BooleanTraceCommitmentError::NonBooleanCell {
                table: KECCAK,
                column: COLUMN,
            }
        ))
    ));
    assert_eq!(
        CanSample::<E>::sample(&mut moved),
        CanSample::<E>::sample(&mut untouched)
    );
}

#[test]
fn prescribed_security_fails_closed() {
    let pcs = mixed_pcs(KECCAK);
    let all = (0..NUM_KECCAK_BINARY_COLS).collect::<Vec<_>>();
    let partial = all[..NUM_KECCAK_BINARY_COLS - 1].to_vec();
    let batched =
        |batches: Vec<OpeningBatch<usize>>| main_protocol(TableSpec::new(keccak_shape(), batches));

    assert!(
        pcs.prescribed_security(&batched(vec![OpeningBatch::new(all.clone(), all.clone())]))
            .is_some()
    );
    assert!(
        pcs.prescribed_security(&batched(vec![OpeningBatch::new(all.clone(), vec![])]))
            .is_some()
    );
    for batches in [
        vec![OpeningBatch::new(partial.clone(), all.clone())],
        vec![OpeningBatch::new(all.clone(), partial)],
        vec![
            OpeningBatch::new(all.clone(), all.clone()),
            OpeningBatch::new(all.clone(), all),
        ],
    ] {
        assert!(pcs.prescribed_security(&batched(batches)).is_none());
    }

    let missing = mixed_pcs(3);
    assert!(
        missing
            .prescribed_security(&main_protocol(full_spec(keccak_shape())))
            .is_none()
    );
}

/// The multi-STARK prover and verifier admit an AIR that leaves its booleanity to the
/// commitment only inside the region reported here, so it must be the packed table alone.
#[test]
fn bit_region_is_the_packed_table_alone() {
    let pcs = mixed_pcs(KECCAK);
    assert_eq!(
        pcs.bit_region(KECCAK, NUM_KECCAK_BINARY_COLS),
        NUM_KECCAK_BINARY_COLS
    );
    for table in [0, KECCAK + 1] {
        assert_eq!(pcs.bit_region(table, NUM_KECCAK_BINARY_COLS), 0);
    }
    let dense_only = MixedWhirPcs::new(dense_main_pcs(), None, CAP_HEIGHT).unwrap();
    for table in [0, KECCAK] {
        assert_eq!(dense_only.bit_region(table, NUM_KECCAK_BINARY_COLS), 0);
    }
}
