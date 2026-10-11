//! Mixed dense and packed-bit proofs, imported natively and verified in a prime-field circuit.
//!
//! Proofs come from `p3_multi_stark` over the composite commitment. Each statement's AIRs are
//! one [`TestAir`] list: native bus tables, or small dense and Boolean tables.

mod forged_limb;
mod forged_swapped;
mod keccak_chain;
mod small;
mod transcript;

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;

use p3_air::{AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::TowerLevel;
use p3_bus::BusInteractionBuilder;
use p3_circuit::ops::NativeTower128Target;
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::{Circuit, CircuitBuilder};
use p3_circuit_prover::native_bus::NativeBusCircuitAir;
use p3_commit::MultilinearPcs;
use p3_matrix::dense::RowMajorMatrix;
use p3_multi_stark::{
    ProverInstance, ProverInstances, VerifierInstance, VerifierInstances, prove, setup, verify,
};
use p3_sumcheck::TableShape;
use p3_sumcheck::layout::{Table, plan_stacked_layout};
use p3_whir::pcs::proof::{QueryOpenings, WhirProof};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

use super::*;
use crate::artifact::binary_native::{
    BinaryNativeChallenger, BinaryNativeWhirPcsParameters, MixedWhirPcs, tree,
};

type Config = BinaryNativeMixedWhirConfig;
type BooleanTraceProof = p3_binary_pcs::BooleanTraceCommitmentProof<
    F,
    p3_binary_pcs::whir::BooleanWhirProof<F, F, NativeMmcs<F>>,
>;

const HASH: ByteHash = ByteHash::Keccak256;
/// Two roots per part, so a swapped or truncated cap is still a well-formed cap.
const CAP_HEIGHT: usize = 1;
const FOLDING: usize = 2;
const MAX_TAU_DRAWS: usize = 32;
const INITIAL: [u8; 3] = [5, 0, 9];

fn challenger() -> BinaryNativeChallenger<F> {
    BinaryNativeChallenger::fresh(INITIAL.to_vec(), HASH)
}

fn whir_parameters(num_variables: usize) -> BinaryNativeWhirPcsParameters<F> {
    BinaryNativeWhirPcsParameters::<F>::new(
        num_variables,
        ProtocolParameters {
            security_level: 8,
            pow_bits: 0,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(FOLDING),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: 2,
        },
        HASH,
        CAP_HEIGHT,
    )
    .unwrap()
}

fn limits() -> VerifierLimits {
    VerifierLimits {
        max_rounds: 256,
        max_metadata_entries: 1 << 20,
        ..VerifierLimits::default()
    }
}

fn arity(shapes: &[TableShape]) -> usize {
    plan_stacked_layout(shapes).0
}

/// A cap of the configured height whose roots are not yet known.
fn placeholder_cap() -> MerkleCap<F, [u8; 32]> {
    MerkleCap::new(vec![[0; 32]; 1 << CAP_HEIGHT])
}

fn limbs(value: F) -> impl Iterator<Item = BabyBear> {
    let raw = value.to_raw_coordinates();
    (0..8).map(move |i| BabyBear::from_u16((raw >> (16 * i)) as u16))
}

/// Parameters of the composite commitment over these AIRs, with `packed_table` bit-committed
/// when given: the packed parameters, the table and its bit arity. Preprocessing parameters
/// exist when some AIR has preprocessed columns.
struct Parameters {
    dense: BinaryNativeWhirPcsParameters<F>,
    packed: Option<(BinaryNativeWhirPcsParameters<F>, usize, usize)>,
    preprocessed: Option<BinaryNativeWhirPcsParameters<F>>,
}

impl Parameters {
    fn new<A: BaseAir<F>>(airs: &[A], heights: &[usize], packed_table: Option<usize>) -> Self {
        let shapes: Vec<_> = airs
            .iter()
            .zip(heights)
            .map(|(air, &height)| TableShape::new(height, air.width()))
            .collect();
        let dense: Vec<_> = (0..shapes.len())
            .filter(|&i| Some(i) != packed_table)
            .map(|i| shapes[i])
            .collect();
        let preprocessed: Vec<_> = airs
            .iter()
            .zip(heights)
            .filter(|(air, _)| air.preprocessed_width() != 0)
            .map(|(air, &height)| TableShape::new(height, air.preprocessed_width()))
            .collect();
        let packed = packed_table.map(|table| {
            let bits = arity(&[shapes[table]]);
            (whir_parameters(bits - 7), table, bits)
        });
        Self {
            dense: whir_parameters(arity(&dense)),
            packed,
            preprocessed: (!preprocessed.is_empty()).then(|| whir_parameters(arity(&preprocessed))),
        }
    }

    fn packed(&self) -> &BinaryNativeWhirPcsParameters<F> {
        &self.packed.as_ref().unwrap().0
    }

    fn config(&self) -> Config {
        let packed = self
            .packed
            .as_ref()
            .map(|(parameters, table, bits)| (parameters, *table, *bits));
        Config::new(
            MixedWhirPcs::from_parameters(&self.dense, packed).unwrap(),
            self.preprocessed
                .as_ref()
                .map(|pp| MixedWhirPcs::from_parameters(pp, None).unwrap()),
        )
        .unwrap()
    }

    /// The commitment of the AIRs' preprocessed traces, when they have any.
    fn preprocessed_cap<A: BaseAir<F>>(&self, airs: &[A]) -> Option<MerkleCap<F, [u8; 32]>> {
        let pcs = MixedWhirPcs::from_parameters(self.preprocessed.as_ref()?, None).unwrap();
        let tables = airs
            .iter()
            .filter(|air| air.preprocessed_width() != 0)
            .map(|air| Table::new(air.preprocessed_trace().unwrap().transpose()))
            .collect();
        Some(pcs.commit(tables, &mut challenger()).unwrap().0)
    }

    /// The mixed verifier over these parameters, retaining `preprocessed_cap` when the AIRs
    /// have preprocessed columns.
    fn verifier<A>(
        &self,
        airs: &[A],
        heights: &[usize],
        packed_table: usize,
        preprocessed_cap: Option<MerkleCap<F, [u8; 32]>>,
    ) -> Result<BinaryMixedWhirMultiStarkVerifier, VerificationError>
    where
        A: Air<InteractionSymbolicBuilder<F, F>> + Air<BusSymbolicBuilder<F, F>>,
    {
        let airs = airs.iter().collect::<Vec<_>>();
        let (dense, packed) = (self.dense.configuration(), self.packed().configuration());
        match (&self.preprocessed, preprocessed_cap) {
            (Some(pp), Some(commitment)) => BinaryMixedWhirMultiStarkVerifier::with_preprocessing(
                &airs,
                heights,
                packed_table,
                dense,
                packed,
                HASH,
                MerkleArity::Two,
                CAP_HEIGHT,
                0,
                MAX_TAU_DRAWS,
                BinaryMixedWhirMultiStarkPreprocessing {
                    config: pp.configuration().clone(),
                    hash: HASH,
                    arity: MerkleArity::Two,
                    cap_height: CAP_HEIGHT,
                    commitment,
                },
                &limits(),
            ),
            (None, None) => BinaryMixedWhirMultiStarkVerifier::with_limits(
                &airs,
                heights,
                packed_table,
                dense,
                packed,
                HASH,
                MerkleArity::Two,
                CAP_HEIGHT,
                0,
                MAX_TAU_DRAWS,
                &limits(),
            ),
            _ => panic!("a preprocessing cap is given exactly with preprocessing parameters"),
        }
    }
}

/// A proven mixed statement, with every parameter its verifiers need.
struct Mixed {
    airs: Vec<TestAir>,
    heights: Vec<usize>,
    public: Vec<Vec<F>>,
    packed_table: usize,
    parameters: Parameters,
    config: Config,
    preprocessed_cap: Option<MerkleCap<F, [u8; 32]>>,
    proof: MultiStarkProof<Config>,
}

impl Mixed {
    fn prove(
        airs: Vec<TestAir>,
        heights: Vec<usize>,
        public: Vec<Vec<F>>,
        packed_table: usize,
        tables: Vec<Table<F>>,
    ) -> Self {
        let parameters = Parameters::new(&airs, &heights, Some(packed_table));
        let config = parameters.config();
        let refs = airs.iter().collect::<Vec<_>>();
        let (proving, _) = setup(&config, &refs, &mut challenger()).unwrap();
        // Setup commits these tables too, but its key keeps the cap private.
        let preprocessed_cap = parameters.preprocessed_cap(&airs);
        let proof = prove(
            &config,
            ProverInstances::new(
                refs.iter()
                    .zip(tables)
                    .zip(&public)
                    .map(|((air, table), public)| {
                        ProverInstance::new(*air, table, &proving, public)
                    })
                    .collect(),
            ),
            0,
            &mut challenger(),
        )
        .unwrap();
        Self {
            airs,
            heights,
            public,
            packed_table,
            parameters,
            config,
            preprocessed_cap,
            proof,
        }
    }

    /// The multi-stark verifier's transcript after the proof, one observation and one sample.
    fn continued_challenge(&self) -> F {
        let refs = self.airs.iter().collect::<Vec<_>>();
        let (_, verifying) = setup(&self.config, &refs, &mut challenger()).unwrap();
        let mut ch = challenger();
        verify(
            &self.config,
            VerifierInstances::new(
                refs.iter()
                    .zip(&self.heights)
                    .zip(&self.public)
                    .map(|((air, &height), public)| {
                        VerifierInstance::new(*air, &verifying, height, public)
                    })
                    .collect(),
            ),
            &self.proof,
            0,
            &mut ch,
        )
        .unwrap();
        ch.observe(F::from_repr(29));
        ch.sample_algebra_element()
    }

    fn verifier(&self) -> BinaryMixedWhirMultiStarkVerifier {
        self.parameters
            .verifier(
                &self.airs,
                &self.heights,
                self.packed_table,
                self.preprocessed_cap.clone(),
            )
            .unwrap()
    }

    fn import(
        &self,
        verifier: &BinaryMixedWhirMultiStarkVerifier,
        proof: &MultiStarkProof<Config>,
        ch: &mut BinaryNativeChallenger<F>,
    ) -> Result<NativeBinaryMixedWhirMultiStarkInput, VerificationError> {
        let mmcs = tree::<F>(HASH, CAP_HEIGHT);
        verifier.import_native(
            self.parameters.dense.configuration(),
            self.parameters.packed().configuration(),
            &mmcs,
            self.parameters
                .preprocessed
                .as_ref()
                .map(|pp| (pp.configuration(), &mmcs)),
            &self.public,
            proof,
            ch,
        )
    }

    /// Imports the honest proof and checks the native continuation against the multi-stark
    /// verifier's. Returns the input and the continued challenge both circuits pin.
    fn honest_import(
        &self,
        verifier: &BinaryMixedWhirMultiStarkVerifier,
    ) -> (NativeBinaryMixedWhirMultiStarkInput, F) {
        let mut ch = challenger();
        let input = self.import(verifier, &self.proof, &mut ch).unwrap();
        ch.observe(F::from_repr(29));
        let continued = ch.sample_algebra_element::<F>();
        assert_eq!(continued, self.continued_challenge());
        (input, continued)
    }

    /// The honest import and the private inputs of `H`'s circuit.
    fn honest_private_values<H: Host>(
        &self,
        verifier: &BinaryMixedWhirMultiStarkVerifier,
    ) -> (NativeBinaryMixedWhirMultiStarkInput, Vec<H::CF>) {
        let (input, continued) = self.honest_import(verifier);
        let private = private_inputs::<H>(&input, &verifier.input_shape(), continued);
        (input, private)
    }

    /// Every tamper class but a Merkle sibling is refused by the native import, which leaves
    /// the caller's transcript as it was. A tampered sibling is restored into a different path
    /// witness, which only the circuit's path authentication refuses; those witnesses are
    /// returned in [`SIBLINGS`] order.
    fn assert_tampers_refused_by_import(
        &self,
        verifier: &BinaryMixedWhirMultiStarkVerifier,
    ) -> Vec<NativeBinaryMixedWhirMultiStarkInput> {
        for (name, tamper) in TAMPERS {
            let mut proof = self.proof_copy();
            tamper(&mut proof);
            let mut ch = challenger();
            let mut before = ch.clone();
            assert!(
                self.import(verifier, &proof, &mut ch).is_err(),
                "import accepted a tampered {name}"
            );
            assert_eq!(
                ch.sample_algebra_element::<F>(),
                before.sample_algebra_element::<F>(),
                "a refused {name} moved the transcript"
            );
        }
        let shape = verifier.input_shape();
        let honest = self
            .import(verifier, &self.proof, &mut challenger())
            .unwrap()
            .private_values::<BabyBear>(&shape)
            .unwrap();
        SIBLINGS
            .iter()
            .map(|(name, tamper)| {
                let mut proof = self.proof_copy();
                tamper(&mut proof);
                let tampered = self.import(verifier, &proof, &mut challenger()).unwrap();
                assert_ne!(
                    tampered.private_values::<BabyBear>(&shape).unwrap(),
                    honest,
                    "a tampered {name} left the witness as it was"
                );
                tampered
            })
            .collect()
    }

    /// The configuration is not `Clone`, so a proof copy goes through its encoding.
    fn proof_copy(&self) -> MultiStarkProof<Config> {
        postcard::from_bytes(&postcard::to_allocvec(&self.proof).unwrap()).unwrap()
    }

    /// The public inputs of `H`'s circuit.
    fn public_values<H: Host>(&self) -> Vec<H::CF> {
        self.public
            .iter()
            .flatten()
            .flat_map(|&v| H::encode(v))
            .collect()
    }
}

fn packed_opening(proof: &mut MultiStarkProof<Config>) -> &mut BooleanTraceProof {
    proof.opening.packed.as_mut().unwrap()
}

/// The first sibling digest of a WHIR opening's first query round, which authenticates rows
/// against the committed cap.
fn first_sibling(whir: &mut WhirProof<F, F, NativeMmcs<F>>) -> &mut [u8; 32] {
    let openings = whir
        .rounds
        .first_mut()
        .map_or(&mut whir.final_openings, |round| &mut round.openings);
    let siblings = match openings {
        QueryOpenings::Base(o) => &mut o.proof.sibling_hashes,
        QueryOpenings::Extension(o) => &mut o.proof.sibling_hashes,
    };
    siblings
        .first_mut()
        .expect("the queries leave a sibling digest to send")
}

type Tamper = fn(&mut MultiStarkProof<Config>);

/// Tampers of one Merkle sibling digest in the dense and in the packed WHIR opening.
const SIBLINGS: [(&str, Tamper); 2] = [
    ("dense WHIR Merkle sibling", |proof| {
        first_sibling(&mut proof.opening.dense.whir)[0] ^= 1;
    }),
    ("packed WHIR Merkle sibling", |proof| {
        first_sibling(&mut packed_opening(proof).opening.opening.whir)[0] ^= 1;
    }),
];

/// Tampers that change what the transcript or the opening checks read.
const TAMPERS: [(&str, Tamper); 4] = [
    ("packed opened value", |proof| {
        packed_opening(proof).values[0] += F::ONE;
    }),
    ("dense opened value", |proof| {
        let batch = &proof.opening.dense.evals[0];
        let mut current = batch.current().to_vec();
        current[0] += F::ONE;
        proof.opening.dense.evals[0] = OpeningBatch::new(current, batch.next().to_vec());
    }),
    ("ring-switch tensor row", |proof| {
        packed_opening(proof).opening.reduction.claims[0]
            .tensor
            .add_exterior_product(F::ONE, F::ONE);
    }),
    ("cap with swapped halves", |proof| {
        let (dense, packed) = proof.commitment.roots().split_at(1 << CAP_HEIGHT);
        proof.commitment = MerkleCap::new([packed, dense].concat());
    }),
];

/// The prime-field verifier circuit. It also observes a fixed value after the verifier,
/// samples one challenge and requires it to equal a private input appended after the proof's
/// witnesses, so the circuit's transcript continuation is pinned to the native one.
fn prime_circuit(verifier: &BinaryMixedWhirMultiStarkVerifier) -> Circuit<BabyBear> {
    let shape = verifier.input_shape();
    let mut b = CircuitBuilder::<BabyBear>::new();
    b.enable_keccak_f1600::<BabyBear>();
    let public: Vec<Vec<_>> = shape
        .public_value_counts()
        .map(|count| {
            (0..count)
                .map(|_| {
                    let inputs = core::array::from_fn(|_| b.public_input());
                    b.binary128_from_limbs::<BabyBear>(inputs).unwrap()
                })
                .collect()
        })
        .collect();
    let targets = shape
        .allocate_targets::<BabyBear, BabyBear>(&mut b)
        .unwrap();
    let initial = INITIAL.map(|v| b.define_const(BabyBear::from_u8(v)));
    let ch =
        BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(&mut b, HASH, &initial)
            .unwrap();
    let mut ch = verifier
        .verify::<BabyBear, BabyBear>(&mut b, ch, &public, &targets)
        .unwrap();
    let observation = 29u128
        .to_le_bytes()
        .map(|v| b.define_const(BabyBear::from_u8(v)));
    ch.observe_bytes::<BabyBear, BabyBear>(&mut b, &observation)
        .unwrap();
    let actual = ch.sample::<BabyBear, BabyBear>(&mut b).unwrap();
    let expected = b.alloc_private_input_array::<8>("continued challenge");
    let expected = b.binary128_from_limbs::<BabyBear>(expected).unwrap();
    for (&actual, &expected) in actual.bits().iter().zip(expected.bits()) {
        let difference = b.sub(actual, expected);
        b.assert_zero(difference);
    }
    b.build().unwrap()
}

/// A native circuit with Keccak enabled and one public scalar per statement value, for
/// statements of `counts` values per AIR.
fn native_builder(
    counts: impl Iterator<Item = usize>,
) -> (CircuitBuilder<F>, Vec<Vec<NativeTower128Target>>) {
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let public = counts
        .map(|count| {
            (0..count)
                .map(|_| {
                    let value = b.public_input();
                    b.native_tower128_from_expr(value)
                })
                .collect()
        })
        .collect();
    (b, public)
}

fn native_challenger(b: &mut CircuitBuilder<F>) -> BinaryTower128Challenger {
    let initial =
        INITIAL.map(|v| b.define_const(NativeBinaryEncoding::encode_u16(v.into()).unwrap()));
    BinaryTower128Challenger::with_initial_bytes_with_host::<NativeBinaryEncoding, F>(
        b, HASH, &initial,
    )
    .unwrap()
}

/// The native Tower128 verifier circuit, with the continuation pin of [`prime_circuit`], and
/// the expression nodes the verifier itself adds.
fn native_circuit(verifier: &BinaryMixedWhirMultiStarkVerifier) -> (Circuit<F>, usize) {
    let shape = verifier.input_shape();
    let (mut b, public) = native_builder(shape.public_value_counts());
    let targets = shape.allocate_native_targets(&mut b).unwrap();
    let ch = native_challenger(&mut b);
    let before = b.construction_usage().unwrap().expression_nodes;
    let mut ch = verifier
        .verify_native(&mut b, ch, &public, &targets)
        .unwrap();
    let nodes = b.construction_usage().unwrap().expression_nodes - before;
    let observation = 29u128
        .to_le_bytes()
        .map(|v| b.define_const(NativeBinaryEncoding::encode_u16(v.into()).unwrap()));
    ch.observe_bytes_with_host::<NativeBinaryEncoding, F>(&mut b, &observation)
        .unwrap();
    let actual = ch
        .sample_with_host::<NativeBinaryEncoding, F>(&mut b)
        .unwrap();
    let actual = b.native_tower128_from_bits(*actual.bits()).unwrap();
    let expected = b.alloc_private_input("continued challenge");
    let difference = b.sub(actual.as_expr(), expected);
    b.assert_zero(difference);
    (b.build().unwrap(), nodes)
}

fn accepts<CF: Field>(circuit: &Circuit<CF>, private: &[CF], public: &[CF]) -> bool {
    let mut runner = circuit.runner();
    runner.set_private_inputs(private).unwrap();
    runner.set_public_inputs(public).unwrap();
    runner.run().is_ok()
}

/// A verifier circuit's field and its encoding of the mixed verifier's inputs.
trait Host {
    type CF: Field;
    /// Names the circuit in assertion messages.
    const NAME: &'static str;

    /// The verifier circuit, with its continuation pin.
    fn circuit(verifier: &BinaryMixedWhirMultiStarkVerifier) -> Circuit<Self::CF>;

    /// The scalars of one field value.
    fn encode(value: F) -> Vec<Self::CF>;

    /// The scalars of an import's witnesses, in allocation order.
    fn witnesses(
        input: &NativeBinaryMixedWhirMultiStarkInput,
        shape: &BinaryMixedWhirMultiStarkInputShape,
    ) -> Vec<Self::CF>;

    /// The scalar counts of the relation's bus and sumcheck witnesses, which follow the cap,
    /// and of the dense opening's witnesses, which follow them.
    fn relation_and_dense_scalars(
        input: &NativeBinaryMixedWhirMultiStarkInput,
        shape: &BinaryMixedWhirMultiStarkInputShape,
    ) -> (usize, usize);

    /// Flips the lowest bit of a scalar, which keeps it within its encoding's range.
    fn flip(value: &mut Self::CF);
}

/// The prime-field circuit: eight sixteen-bit BabyBear limbs per field value.
struct Prime;

impl Host for Prime {
    type CF = BabyBear;
    const NAME: &'static str = "prime";

    fn circuit(verifier: &BinaryMixedWhirMultiStarkVerifier) -> Circuit<BabyBear> {
        prime_circuit(verifier)
    }

    fn encode(value: F) -> Vec<BabyBear> {
        limbs(value).collect()
    }

    fn witnesses(
        input: &NativeBinaryMixedWhirMultiStarkInput,
        shape: &BinaryMixedWhirMultiStarkInputShape,
    ) -> Vec<BabyBear> {
        input.private_values(shape).unwrap()
    }

    fn relation_and_dense_scalars(
        input: &NativeBinaryMixedWhirMultiStarkInput,
        shape: &BinaryMixedWhirMultiStarkInputShape,
    ) -> (usize, usize) {
        let bus = input
            .bus
            .as_ref()
            .zip(shape.relation.bus.as_ref())
            .map_or(0, |(bus, shape)| {
                bus.private_values::<BabyBear>(&shape.product)
                    .unwrap()
                    .len()
            });
        let sumcheck = input
            .sumcheck
            .private_values::<BabyBear>(&shape.relation.sumcheck)
            .unwrap()
            .len();
        let dense = input
            .dense
            .private_values::<BabyBear>(&shape.dense)
            .unwrap()
            .len();
        (bus + sumcheck, dense)
    }

    fn flip(value: &mut BabyBear) {
        *value = BabyBear::from_u64(value.as_canonical_u64() ^ 1);
    }
}

/// The native Tower128 circuit: one scalar per field value.
struct Native;

impl Host for Native {
    type CF = F;
    const NAME: &'static str = "native";

    fn circuit(verifier: &BinaryMixedWhirMultiStarkVerifier) -> Circuit<F> {
        native_circuit(verifier).0
    }

    fn encode(value: F) -> Vec<F> {
        vec![value]
    }

    fn witnesses(
        input: &NativeBinaryMixedWhirMultiStarkInput,
        shape: &BinaryMixedWhirMultiStarkInputShape,
    ) -> Vec<F> {
        input.private_native_values(shape).unwrap()
    }

    fn relation_and_dense_scalars(
        input: &NativeBinaryMixedWhirMultiStarkInput,
        shape: &BinaryMixedWhirMultiStarkInputShape,
    ) -> (usize, usize) {
        let bus = input
            .bus
            .as_ref()
            .zip(shape.relation.bus.as_ref())
            .map_or(0, |(bus, shape)| {
                bus.private_native_values(&shape.product).unwrap().len()
            });
        let sumcheck = input
            .sumcheck
            .private_native_values(&shape.relation.sumcheck)
            .unwrap()
            .len();
        let dense = input
            .dense
            .private_native_values(&shape.dense)
            .unwrap()
            .len();
        (bus + sumcheck, dense)
    }

    /// Characteristic two: adding one flips the lowest coordinate.
    fn flip(value: &mut F) {
        *value += F::ONE;
    }
}

/// The private inputs of `H`'s circuit: the import's witnesses, then the continued challenge.
fn private_inputs<H: Host>(
    input: &NativeBinaryMixedWhirMultiStarkInput,
    shape: &BinaryMixedWhirMultiStarkInputShape,
    continued: F,
) -> Vec<H::CF> {
    let mut private = H::witnesses(input, shape);
    private.extend(H::encode(continued));
    private
}

/// Offsets of the dense and the packed opening's witnesses within the private inputs of `H`'s
/// circuit, after the cap's two halves of sixteen limbs per root and the relation's witnesses.
fn opening_offsets<H: Host>(
    input: &NativeBinaryMixedWhirMultiStarkInput,
    shape: &BinaryMixedWhirMultiStarkInputShape,
) -> (usize, usize) {
    assert!(input.indexed.is_none());
    let (relation, dense) = H::relation_and_dense_scalars(input, shape);
    let dense_offset = (2 << CAP_HEIGHT) * 16 + relation;
    (dense_offset, dense_offset + dense)
}

const DENSE_VARIABLES: usize = 4;
const DENSE_WIDTH: usize = 2;
const BIT_WIDTH: usize = 8;

/// A native bus table, or a small dense or Boolean table.
///
/// ```text
///     dense    first row (a, b) = public values;   a' = b,   b' = a·b + w,   w preprocessed
///     square   first row a = public value;   b = a·a + 1
///     bits     c = a·b;   a' = b,   b' = a + b + a·b,   x'_j = x_(j-1) for j ≥ 4
/// ```
///
/// The Boolean table reads only its declared columns one row ahead.
#[derive(Clone)]
enum TestAir {
    Bus(Box<NativeBusCircuitAir<F>>),
    Dense,
    Square,
    Bits { next: Vec<usize> },
}

fn weights() -> Vec<F> {
    (0..1 << DENSE_VARIABLES)
        .map(|row| F::from_bool(row % 3 == 0))
        .collect()
}

impl BaseAir<F> for TestAir {
    fn width(&self) -> usize {
        match self {
            Self::Bus(air) => air.width(),
            Self::Dense | Self::Square => DENSE_WIDTH,
            Self::Bits { .. } => BIT_WIDTH,
        }
    }
    fn num_public_values(&self) -> usize {
        match self {
            Self::Bus(air) => air.num_public_values(),
            Self::Dense => 2,
            Self::Square => 1,
            Self::Bits { .. } => 0,
        }
    }
    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Bus(air) => air.preprocessed_width(),
            Self::Dense => 1,
            Self::Square | Self::Bits { .. } => 0,
        }
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        match self {
            Self::Bus(air) => air.preprocessed_trace(),
            Self::Dense => Some(RowMajorMatrix::new(weights(), 1)),
            Self::Square | Self::Bits { .. } => None,
        }
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        match self {
            Self::Bus(air) => air.main_next_row_columns(),
            Self::Dense => (0..DENSE_WIDTH).collect(),
            Self::Square => Vec::new(),
            Self::Bits { next } => next.clone(),
        }
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        match self {
            Self::Bus(air) => air.preprocessed_next_row_columns(),
            Self::Dense | Self::Square | Self::Bits { .. } => Vec::new(),
        }
    }
    fn assumes_boolean_trace(&self) -> bool {
        match self {
            Self::Bus(air) => air.assumes_boolean_trace(),
            Self::Dense | Self::Square => false,
            Self::Bits { .. } => true,
        }
    }
}

impl<AB: AirBuilder<F = F> + BusInteractionBuilder> Air<AB> for TestAir {
    fn eval(&self, b: &mut AB) {
        if let Self::Bus(air) = self {
            return air.eval(b);
        }
        let main = b.main();
        let (cur, next) = (main.current_slice().to_vec(), main.next_slice().to_vec());
        match self {
            Self::Bus(_) => unreachable!("evaluated above"),
            Self::Dense => {
                let w = b.preprocessed().current_slice()[0];
                let (first, second) = (b.public_values()[0], b.public_values()[1]);
                b.when_first_row().assert_eq(cur[0], first);
                b.when_first_row().assert_eq(cur[1], second);
                b.when_transition().assert_eq(next[0], cur[1]);
                b.when_transition().assert_eq(next[1], cur[0] * cur[1] + w);
            }
            Self::Square => {
                let first = b.public_values()[0];
                b.when_first_row().assert_eq(cur[0], first);
                b.assert_eq(cur[1], cur[0] * cur[0] + AB::Expr::ONE);
            }
            Self::Bits { next: declared } => {
                b.assert_eq(cur[2], cur[0] * cur[1]);
                if declared.contains(&0) {
                    b.when_transition().assert_eq(next[0], cur[1]);
                }
                if declared.contains(&1) {
                    b.when_transition()
                        .assert_eq(next[1], cur[0] + cur[1] + cur[0] * cur[1]);
                }
                for j in (4..BIT_WIDTH).filter(|j| declared.contains(j)) {
                    b.when_transition().assert_eq(next[j], cur[j - 1]);
                }
            }
        }
    }
}
