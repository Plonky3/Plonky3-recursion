//! A native bus of chained Keccak-f calls whose Keccak table is committed as bits, sixty-four
//! per Poly64 element, beside dense Poly64 tables: proven by `p3_multi_stark` over the composite
//! commitment, imported natively, and verified in the native Poly64 carrier at both tree
//! arities.

use alloc::vec;
use alloc::vec::Vec;

use p3_air::BaseAir;
use p3_baby_bear::BabyBear;
use p3_circuit::Circuit;
use p3_circuit::ops::binary_encoding::{BinaryCircuitEncoding, NativeBinaryEncoding};
use p3_circuit::ops::{NativePoly192Target, keccak_state_to_limbs};
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::native_bus::{
    KeccakCommitment, NativeBusCircuit, NativeBusCircuitAir, NativeBusTrace,
};
use p3_commit::MultilinearPcs;
use p3_keccak::KeccakF;
use p3_multi_stark::{
    ProverInstance, ProverInstances, VerifierInstance, VerifierInstances, prove, setup, verify,
};
use p3_sumcheck::OpeningBatch;
use p3_sumcheck::layout::Table;
use p3_symmetric::Permutation;
use p3_whir::pcs::proof::{QueryOpenings, WhirProof};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

use super::*;
use crate::artifact::binary_native::{
    BinaryNativeChallenger, BinaryNativePolyMixedWhirPcsParameters,
    BinaryNativePolyWhirPcsParameters, NativeMixedWhirPcs,
};

type F = Poly64;
type E = Poly192;
type H = NativeBinaryEncoding;
type Config = BinaryNativePolyMixedWhirConfig;
type BooleanTraceProof = p3_binary_pcs::BooleanTraceCommitmentProof<
    E,
    p3_binary_pcs::whir::BooleanWhirProof<F, E, NativeWhirMmcs<F>>,
>;

const HASH: ByteHash = ByteHash::Keccak256;
/// One level of cap, so each part's cap holds several roots and the two arities' caps differ
/// in length.
const CAP_HEIGHT: usize = 1;
/// Folds of two, and the least table height.
const FOLDING: usize = 2;
const MAX_TAU_DRAWS: usize = 32;
const INITIAL: [u8; 3] = [5, 0, 9];
/// Three permutations fill 75 Keccak rows, padded to 128: two Poly64 elements of rows per
/// column, so the next row crosses an element and the ring switch sends carry and last.
const CALLS: usize = 3;
const ARITIES: [MerkleArity; 2] = [MerkleArity::Two, MerkleArity::Four];

fn challenger() -> BinaryNativeChallenger<F> {
    BinaryNativeChallenger::fresh(INITIAL.to_vec(), HASH)
}

fn limits() -> VerifierLimits {
    VerifierLimits {
        max_rounds: 256,
        max_metadata_entries: 1 << 20,
        ..VerifierLimits::default()
    }
}

/// Small security, so the circuits stay small.
fn whir(num_variables: usize, arity: MerkleArity) -> BinaryNativePolyWhirPcsParameters {
    BinaryNativePolyWhirPcsParameters::with_limits(
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
        arity,
        CAP_HEIGHT,
        &limits(),
    )
    .unwrap()
}

/// `CALLS` chained Keccak-f calls from a public input state to a public output state, and the
/// statement of a fixed input.
fn keccak_chain() -> (Circuit<F>, Vec<F>) {
    let mut builder = CircuitBuilder::<F>::new();
    builder.enable_native_keccak_f1600().unwrap();
    let mut state = builder.alloc_public_input_array::<100>("input").to_vec();
    for _ in 0..CALLS {
        state = builder.add_native_keccak_f1600(&state).unwrap().to_vec();
    }
    let expected = builder.alloc_public_input_array::<100>("output");
    for (actual, expected) in state.iter().zip(expected) {
        builder.connect(*actual, expected);
    }
    let circuit = builder.build().unwrap();

    let input: [u64; 25] =
        core::array::from_fn(|i| 0x8123456789abcdefu64.rotate_left(3 * i as u32));
    let mut output = input;
    for _ in 0..CALLS {
        KeccakF.permute_mut(&mut output);
    }
    let statement = [input, output]
        .iter()
        .flat_map(keccak_state_to_limbs)
        .map(|limb| F::new(u64::from(limb)))
        .collect();
    (circuit, statement)
}

fn native_bus(circuit: &Circuit<F>, keccak: KeccakCommitment) -> NativeBusCircuit<F> {
    NativeBusCircuit::with_options(
        circuit,
        "poly-mixed",
        FOLDING,
        DirectCircuitLimits::default(),
        keccak,
    )
    .unwrap()
}

/// Every table as proven: dense tables as Poly64 cells, the bit-committed one as packed bits.
fn tables(traces: Vec<NativeBusTrace<F>>) -> Vec<Table<F>> {
    traces
        .into_iter()
        .map(|trace| match trace {
            NativeBusTrace::Dense(matrix) => Table::new(matrix.transpose()),
            NativeBusTrace::PackedBits { words, log_height } => {
                Table::from_packed_bits(words, log_height)
            }
        })
        .collect()
}

/// A preprocessing cap of the right length whose roots are not known.
fn placeholder_cap(arity: MerkleArity) -> MerkleCap<F, [u8; 32]> {
    MerkleCap::new(vec![[0; 32]; arity.cap_roots(CAP_HEIGHT).unwrap()])
}

/// Parameters of the bus's composite commitment on trees of `arity`, its Keccak table
/// bit-committed, and of its dense preprocessing commitment.
struct Parameters {
    arity: MerkleArity,
    dense: BinaryNativePolyWhirPcsParameters,
    packed: BinaryNativePolyWhirPcsParameters,
    table: usize,
    bit_variables: usize,
    preprocessed: BinaryNativePolyWhirPcsParameters,
}

impl Parameters {
    fn new(bus: &NativeBusCircuit<F>, arity: MerkleArity) -> Self {
        let bit_variables = bus.packed_bit_variables().unwrap();
        let absorbed = BinaryNativePolyMixedWhirPcsParameters::ABSORBED_VARIABLES;
        Self {
            arity,
            dense: whir(bus.main_variables(), arity),
            packed: whir(bit_variables - absorbed, arity),
            table: bus.keccak_table_index().unwrap(),
            bit_variables,
            preprocessed: whir(bus.preprocessed_variables().unwrap(), arity),
        }
    }

    fn mmcs(&self) -> NativeWhirMmcs<F> {
        NativeWhirMmcs::new(HASH, self.arity, CAP_HEIGHT)
    }

    fn config(&self) -> Config {
        Config::new(
            NativeMixedWhirPcs::from_parameters(
                &self.dense,
                Some((&self.packed, self.table, self.bit_variables)),
            )
            .unwrap(),
            Some(NativeMixedWhirPcs::from_parameters(&self.preprocessed, None).unwrap()),
        )
        .unwrap()
    }

    /// The commitment of the AIRs' preprocessed traces.
    fn preprocessed_cap(&self, airs: &[NativeBusCircuitAir<F>]) -> MerkleCap<F, [u8; 32]> {
        let pcs = NativeMixedWhirPcs::from_parameters(&self.preprocessed, None).unwrap();
        let tables = airs
            .iter()
            .filter(|air| air.preprocessed_width() != 0)
            .map(|air| Table::new(air.preprocessed_trace().unwrap().transpose()))
            .collect();
        pcs.commit(tables, &mut challenger()).unwrap().0
    }

    /// The mixed verifier of `airs` with `table` bit-committed, retaining `commitment` as its
    /// preprocessing authority.
    fn verifier(
        &self,
        airs: &[NativeBusCircuitAir<F>],
        heights: &[usize],
        table: usize,
        commitment: MerkleCap<F, [u8; 32]>,
    ) -> Result<BinaryPolyMixedWhirMultiStarkVerifier, VerificationError> {
        BinaryPolyMixedWhirMultiStarkVerifier::with_preprocessing(
            &airs.iter().collect::<Vec<_>>(),
            heights,
            table,
            self.dense.configuration(),
            self.packed.configuration(),
            HASH,
            self.arity,
            CAP_HEIGHT,
            0,
            MAX_TAU_DRAWS,
            BinaryPolyMixedWhirMultiStarkPreprocessing {
                config: self.preprocessed.configuration().clone(),
                hash: HASH,
                arity: self.arity,
                cap_height: CAP_HEIGHT,
                commitment,
            },
            &limits(),
        )
    }
}

/// The chain proven on trees of one arity, with every parameter its verifiers need.
struct Chain {
    bus: NativeBusCircuit<F>,
    public: Vec<Vec<F>>,
    parameters: Parameters,
    config: Config,
    preprocessed_cap: MerkleCap<F, [u8; 32]>,
    proof: MultiStarkProof<Config>,
}

impl Chain {
    fn prove(arity: MerkleArity) -> Self {
        let (circuit, statement) = keccak_chain();
        let bus = native_bus(&circuit, KeccakCommitment::Bits);
        let mut runner = circuit.runner();
        runner.set_public_inputs(&statement).unwrap();
        let witness = runner.run().unwrap().witness_trace;
        let public = bus.public_values(&statement).unwrap();
        let tables = tables(bus.trace_tables(&witness).unwrap());
        let parameters = Parameters::new(&bus, arity);
        let config = parameters.config();
        let airs = bus.airs().iter().collect::<Vec<_>>();
        let (proving, _) = setup(&config, &airs, &mut challenger()).unwrap();
        let proof = prove(
            &config,
            ProverInstances::new(
                airs.iter()
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
        // Setup commits the preprocessed tables too, but its key keeps the cap private.
        let preprocessed_cap = parameters.preprocessed_cap(bus.airs());
        Self {
            bus,
            public,
            parameters,
            config,
            preprocessed_cap,
            proof,
        }
    }

    fn verifier(&self) -> BinaryPolyMixedWhirMultiStarkVerifier {
        self.parameters
            .verifier(
                self.bus.airs(),
                self.bus.log_heights(),
                self.parameters.table,
                self.preprocessed_cap.clone(),
            )
            .unwrap()
    }

    /// The multi-stark verifier's next Poly192 draw after the proof.
    fn continued_challenge(&self) -> E {
        let airs = self.bus.airs().iter().collect::<Vec<_>>();
        let (_, verifying) = setup(&self.config, &airs, &mut challenger()).unwrap();
        let mut ch = challenger();
        verify(
            &self.config,
            VerifierInstances::new(
                airs.iter()
                    .zip(self.bus.log_heights())
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
        ch.sample_algebra_element()
    }

    fn import(
        &self,
        verifier: &BinaryPolyMixedWhirMultiStarkVerifier,
        proof: &MultiStarkProof<Config>,
        ch: &mut BinaryNativeChallenger<F>,
    ) -> Result<NativeBinaryPolyMixedWhirMultiStarkInput, VerificationError> {
        let mmcs = self.parameters.mmcs();
        verifier.import_native(
            self.parameters.dense.configuration(),
            self.parameters.packed.configuration(),
            &mmcs,
            Some((self.parameters.preprocessed.configuration(), &mmcs)),
            &self.public,
            proof,
            ch,
        )
    }

    /// Imports the honest proof and checks the native continuation against the multi-stark
    /// verifier's. Returns the input and the circuit's private inputs: its witnesses, then the
    /// continued challenge the circuit pins.
    fn honest_private_values(
        &self,
        verifier: &BinaryPolyMixedWhirMultiStarkVerifier,
    ) -> (NativeBinaryPolyMixedWhirMultiStarkInput, Vec<F>) {
        let mut ch = challenger();
        let input = self.import(verifier, &self.proof, &mut ch).unwrap();
        let continued = ch.sample_algebra_element::<E>();
        assert_eq!(continued, self.continued_challenge());
        let mut private = input
            .private_native_values(&verifier.input_shape())
            .unwrap();
        private.extend(continued.coefficients());
        (input, private)
    }

    /// Every tamper class but a Merkle sibling is refused by the native import, which leaves
    /// the caller's transcript as it was. A tampered sibling is restored into a different path
    /// witness, which only the circuit's path authentication refuses; those inputs are returned
    /// in [`SIBLINGS`] order.
    fn assert_tampers_refused_by_import(
        &self,
        verifier: &BinaryPolyMixedWhirMultiStarkVerifier,
    ) -> Vec<NativeBinaryPolyMixedWhirMultiStarkInput> {
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
                ch.sample_algebra_element::<E>(),
                before.sample_algebra_element::<E>(),
                "a refused {name} moved the transcript"
            );
        }
        SIBLINGS
            .iter()
            .map(|(_, tamper)| {
                let mut proof = self.proof_copy();
                tamper(&mut proof);
                self.import(verifier, &proof, &mut challenger()).unwrap()
            })
            .collect()
    }

    /// The configuration is not `Clone`, so a proof copy goes through its encoding.
    fn proof_copy(&self) -> MultiStarkProof<Config> {
        postcard::from_bytes(&postcard::to_allocvec(&self.proof).unwrap()).unwrap()
    }
}

fn packed_opening(proof: &mut MultiStarkProof<Config>) -> &mut BooleanTraceProof {
    proof.opening.packed.as_mut().unwrap()
}

/// The first sibling digest of a WHIR opening's first query round, which authenticates rows
/// against the committed cap.
fn first_sibling(whir: &mut WhirProof<F, E, NativeWhirMmcs<F>>) -> &mut [u8; 32] {
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
        packed_opening(proof).values[0] += E::ONE;
    }),
    ("dense opened value", |proof| {
        let batch = &proof.opening.dense.evals[0];
        let mut current = batch.current().to_vec();
        current[0] += E::ONE;
        proof.opening.dense.evals[0] = OpeningBatch::new(current, batch.next().to_vec());
    }),
    ("ring-switch tensor row", |proof| {
        packed_opening(proof).opening.reduction.claims[0]
            .tensor
            .add_exterior_product(E::ONE, F::ONE);
    }),
    ("cap with swapped halves", |proof| {
        let roots = proof.commitment.num_roots() / 2;
        let (dense, packed) = proof.commitment.roots().split_at(roots);
        proof.commitment = MerkleCap::new([packed, dense].concat());
    }),
];

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

/// The native verifier circuit with one public cell per statement value. After the verifier it
/// draws one Poly192 challenge and requires it to equal the last three private inputs, so the
/// circuit's transcript continuation is pinned to the native one. Also returns the expression
/// nodes the verifier itself adds.
fn native_circuit(verifier: &BinaryPolyMixedWhirMultiStarkVerifier) -> (Circuit<F>, usize) {
    let shape = verifier.input_shape();
    let mut b = CircuitBuilder::<F>::new();
    b.enable_native_keccak_f1600().unwrap();
    let public: Vec<Vec<_>> = shape
        .public_value_counts()
        .map(|count| (0..count).map(|_| b.public_input()).collect())
        .collect();
    let targets = shape.allocate_native_targets(&mut b).unwrap();
    let initial = INITIAL.map(|byte| b.define_const(H::encode_u16(u16::from(byte)).unwrap()));
    let ch = BinaryTower128Challenger::with_initial_bytes_with_host::<H, F>(&mut b, HASH, &initial)
        .unwrap();
    let before = b.construction_usage().unwrap().expression_nodes;
    let mut ch = verifier
        .verify_native(&mut b, ch, &public, &targets)
        .unwrap();
    let nodes = b.construction_usage().unwrap().expression_nodes - before;
    let actual = native_sample(&mut b, &mut ch);
    let expected = b.alloc_private_input_array::<3>("continued challenge");
    for (&actual, expected) in actual.coefficients().iter().zip(expected) {
        let difference = b.sub(actual, expected);
        b.assert_zero(difference);
    }
    (b.build().unwrap(), nodes)
}

fn accepts(circuit: &Circuit<F>, private: &[F], public: &[F]) -> bool {
    let mut runner = circuit.runner();
    runner
        .set_private_inputs(private)
        .and_then(|()| runner.set_public_inputs(public))
        .and_then(|()| runner.run())
        .is_ok()
}

/// Offsets of the dense and the packed opening's witnesses within the private inputs, after
/// the cap's two halves of sixteen limbs per root and the relation's witnesses.
fn opening_offsets(
    input: &NativeBinaryPolyMixedWhirMultiStarkInput,
    shape: &BinaryPolyMixedWhirMultiStarkInputShape,
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
    let dense_offset = 2 * shape.cap_roots * 16 + bus + sumcheck;
    (dense_offset, dense_offset + dense)
}

/// A named change to the circuit's private inputs.
type WitnessTamper<'a> = (&'static str, &'a dyn Fn(&mut Vec<F>));

/// Expression nodes of the native verifier of the chain with its Keccak table bit-committed,
/// on trees of arity two, as measured. Either arity's bound is 1.2 times this count, updatable
/// when the native transcript, the WHIR kernel or the Keccak AIR change.
const MEASURED_POLY_MIXED_NODES: usize = 845_488;

/// At either tree arity, the native import of the honest chain ends where the multi-stark
/// verifier does, and the native circuit accepts it with that continuation, within the measured
/// node bound. Each tamper class is refused: by the import before it moves the transcript, and
/// in the circuit applied to the one witness it names.
#[test]
fn keccak_chain_satisfies_the_native_circuit_and_refuses_tampers() {
    for arity in ARITIES {
        let chain = Chain::prove(arity);
        assert_eq!(
            chain.proof.commitment.num_roots(),
            2 * arity.cap_roots(CAP_HEIGHT).unwrap()
        );
        let verifier = chain.verifier();
        let shape = verifier.input_shape();
        let (input, private) = chain.honest_private_values(&verifier);
        let siblings = chain.assert_tampers_refused_by_import(&verifier);
        let (circuit, nodes) = native_circuit(&verifier);
        std::println!(
            "native Poly64 mixed verifier of {CALLS} Keccak-f calls, {arity:?}: {nodes} nodes"
        );
        assert!(
            nodes * 5 <= MEASURED_POLY_MIXED_NODES * 6,
            "{arity:?}: {nodes} mixed native verifier nodes"
        );
        let public: Vec<F> = chain.public.iter().flatten().copied().collect();
        assert!(
            accepts(&circuit, &private, &public),
            "{arity:?}: the native circuit refused the honest witness"
        );

        let (dense, packed) = opening_offsets(&input, &shape);
        // The packed opening's witnesses start with the opened Keccak values.
        let values = &chain.proof.opening.packed.as_ref().unwrap().values;
        let cells: Vec<F> = values.iter().flat_map(|v| v.coefficients()).collect();
        assert!(private[packed..].starts_with(&cells));
        // Tensor rows can repeat; a row whose value occurs once names its witness alone.
        let tensor_row = chain
            .proof
            .opening
            .packed
            .as_ref()
            .unwrap()
            .opening
            .reduction
            .claims[0]
            .tensor
            .rows()
            .iter()
            .find_map(|&row| {
                let positions: Vec<_> = (packed..private.len())
                    .filter(|&i| private[i] == row)
                    .collect();
                (positions.len() == 1).then(|| positions[0])
            })
            .unwrap();
        // A Merkle sibling enters the transcript nowhere, so the continuation is unchanged.
        let [dense_sibling, packed_sibling] = [0, 1].map(|i| {
            let mut values = siblings[i].private_native_values(&shape).unwrap();
            values.extend_from_slice(&private[values.len()..]);
            values
        });
        // Each sibling tamper changes only the witnesses of the opening it names.
        assert_eq!(dense_sibling[..dense], private[..dense]);
        assert_eq!(dense_sibling[packed..], private[packed..]);
        assert_eq!(packed_sibling[..packed], private[..packed]);
        let roots = 16 * shape.cap_roots;
        let tampers: [WitnessTamper<'_>; 6] = [
            ("packed opened value", &|private| private[packed] += F::ONE),
            ("dense opened value", &|private| private[dense] += F::ONE),
            ("ring-switch tensor row", &|private| {
                private[tensor_row] += F::ONE;
            }),
            ("cap with swapped halves", &|private| {
                private[..2 * roots].rotate_left(roots);
            }),
            ("dense WHIR Merkle sibling", &|private| {
                private.clone_from(&dense_sibling);
            }),
            ("packed WHIR Merkle sibling", &|private| {
                private.clone_from(&packed_sibling);
            }),
        ];
        for (name, tamper) in tampers {
            let mut tampered = private.clone();
            tamper(&mut tampered);
            assert_ne!(tampered, private, "{arity:?}: {name}");
            assert!(
                !accepts(&circuit, &tampered, &public),
                "{arity:?}: the native circuit accepted a tampered {name}"
            );
        }
        let mut statement = public.clone();
        statement[0] += F::ONE;
        assert!(
            !accepts(&circuit, &private, &statement),
            "{arity:?}: the native circuit accepted another statement"
        );
    }
}

/// A proof on trees of one arity carries caps of that arity's length, which a verifier on trees
/// of the other arity refuses before replaying any transcript.
#[test]
fn a_proof_on_trees_of_another_arity_is_refused_at_import() {
    let [pairwise, quaternary] = ARITIES.map(Chain::prove);
    for (verifying, proven) in [(&pairwise, &quaternary), (&quaternary, &pairwise)] {
        let verifier = verifying.verifier();
        let mut ch = challenger();
        let mut before = ch.clone();
        assert!(matches!(
            verifying.import(&verifier, &proven.proof, &mut ch),
            Err(VerificationError::InvalidProofShape(message))
                if message == "binary mixed WHIR MultiStark cap does not hold one cap per part"
        ));
        assert_eq!(
            ch.sample_algebra_element::<E>(),
            before.sample_algebra_element::<E>()
        );
    }
}

/// The native verifier checks the packed opening's target shapes with the dense opening's,
/// before the transcript: refusing a malformed packed opening builds no more nodes than
/// refusing a malformed dense one.
#[test]
fn native_verifier_refuses_a_malformed_packed_opening_before_the_transcript() {
    let (circuit, _) = keccak_chain();
    let bus = native_bus(&circuit, KeccakCommitment::Bits);
    let parameters = Parameters::new(&bus, MerkleArity::Four);
    let verifier = parameters
        .verifier(
            bus.airs(),
            bus.log_heights(),
            parameters.table,
            placeholder_cap(MerkleArity::Four),
        )
        .unwrap();
    let shape = verifier.input_shape();
    let refusal = |malform: &dyn Fn(&mut BinaryPolyMixedWhirMultiStarkProofTargets)| {
        let mut b = CircuitBuilder::<F>::new();
        b.enable_native_keccak_f1600().unwrap();
        let public: Vec<Vec<_>> = shape
            .public_value_counts()
            .map(|count| (0..count).map(|_| b.public_input()).collect())
            .collect();
        let mut targets = shape.allocate_native_targets(&mut b).unwrap();
        malform(&mut targets);
        let initial = INITIAL.map(|byte| b.define_const(H::encode_u16(u16::from(byte)).unwrap()));
        let ch =
            BinaryTower128Challenger::with_initial_bytes_with_host::<H, F>(&mut b, HASH, &initial)
                .unwrap();
        let before = b.construction_usage().unwrap().expression_nodes;
        let Err(VerificationError::InvalidProofShape(message)) =
            verifier.verify_native(&mut b, ch, &public, &targets)
        else {
            panic!("the native verifier did not refuse malformed targets by their shape");
        };
        let nodes = b.construction_usage().unwrap().expression_nodes - before;
        (message, nodes)
    };
    let (dense, dense_nodes) = refusal(&|targets| {
        targets.dense.final_poly.pop();
    });
    let (packed, packed_nodes) = refusal(&|targets| {
        targets.packed.values.pop();
    });
    assert_eq!(dense, "binary WHIR target opening or proof shape mismatch");
    assert_eq!(packed, "binary trace row point or value count mismatch");
    assert_eq!(packed_nodes, dense_nodes);
}

#[test]
fn bit_committed_table_must_be_exactly_the_boolean_assuming_air() {
    let (circuit, _) = keccak_chain();
    let bits = native_bus(&circuit, KeccakCommitment::Bits);
    let parameters = Parameters::new(&bits, MerkleArity::Two);
    let keccak = parameters.table;
    let build = |airs: &[NativeBusCircuitAir<F>], heights: &[usize], table: usize| {
        parameters.verifier(airs, heights, table, placeholder_cap(MerkleArity::Two))
    };
    let refused = |result: Result<_, VerificationError>, expected: &str| {
        assert!(
            matches!(&result, Err(VerificationError::InvalidProofShape(message)) if message == expected),
            "{expected}"
        );
    };
    let mismatch = "polynomial mixed WHIR MultiStark bit-committed table is not exactly the Boolean-assuming AIR";

    build(bits.airs(), bits.log_heights(), keccak).unwrap();
    // The configured table's AIR keeps its booleanity constraints, so no AIR assumes bits.
    let dense = native_bus(&circuit, KeccakCommitment::Dense);
    refused(build(dense.airs(), dense.log_heights(), keccak), mismatch);
    // The configured table is a dense one, while the Keccak AIR assumes bits.
    refused(build(bits.airs(), bits.log_heights(), 0), mismatch);
    // A second Boolean-assuming AIR outside the configured table.
    let mut airs = bits.airs().to_vec();
    airs.push(airs[keccak].clone());
    let mut heights = bits.log_heights().to_vec();
    heights.push(heights[keccak]);
    refused(build(&airs, &heights, keccak), mismatch);
    refused(
        build(bits.airs(), bits.log_heights(), bits.airs().len()),
        "polynomial mixed WHIR MultiStark packed table index exceeds the AIRs",
    );
}

/// The native first fold bounds every table's height: the bit-committed table's preprocessed
/// columns lie in the dense preprocessing layout alongside the dense tables'.
#[test]
fn first_fold_bounds_the_dense_and_the_bit_committed_tables() {
    let (circuit, _) = keccak_chain();
    let bus = native_bus(&circuit, KeccakCommitment::Bits);
    let parameters = Parameters::new(&bus, MerkleArity::Two);
    let keccak = parameters.table;
    let refusal = |table: usize| {
        let mut heights = bus.log_heights().to_vec();
        heights[table] = FOLDING - 1;
        match parameters.verifier(
            bus.airs(),
            &heights,
            keccak,
            placeholder_cap(MerkleArity::Two),
        ) {
            Err(VerificationError::InvalidProofShape(message)) => message,
            _ => panic!("table {table} below the first fold was not refused by its shape"),
        }
    };
    let dense = usize::from(keccak == 0);
    assert_eq!(
        refusal(dense),
        "polynomial WHIR trace height is below the native first fold"
    );
    assert_eq!(
        refusal(keccak),
        "polynomial WHIR trace height is below the native first fold"
    );
}

fn identity(shape: &BinaryPolyMixedWhirMultiStarkInputShape) -> Vec<u8> {
    let mut w = crate::artifact::wire::Writer::new(1 << 24);
    shape.write_identity(&mut w).unwrap();
    w.finish().unwrap()
}

/// The identity is a function of the verifier alone, and binds the bit-committed table, the
/// variables of its bit stack and the trees' arity. The decode shape reads one cap per part
/// and a ring-switch message for every round.
#[test]
fn identity_binds_the_packed_table_bit_variables_and_tree_arity() {
    let (circuit, _) = keccak_chain();
    let bus = native_bus(&circuit, KeccakCommitment::Bits);
    let shape = |arity| {
        let parameters = Parameters::new(&bus, arity);
        parameters
            .verifier(
                bus.airs(),
                bus.log_heights(),
                parameters.table,
                placeholder_cap(arity),
            )
            .unwrap()
            .input_shape()
    };
    let [pairwise, quaternary] = ARITIES.map(shape);
    assert_eq!(identity(&pairwise), identity(&shape(MerkleArity::Two)));
    assert_ne!(identity(&pairwise), identity(&quaternary));
    let mut moved = pairwise.clone();
    moved.packed_table = 0;
    assert_ne!(identity(&pairwise), identity(&moved));
    let mut widened = pairwise.clone();
    widened.bit_variables += 1;
    assert_ne!(identity(&pairwise), identity(&widened));
    let mut rearranged = pairwise.clone();
    rearranged.arity = MerkleArity::Four;
    assert_ne!(identity(&pairwise), identity(&rearranged));

    let bits = bus.packed_bit_variables().unwrap();
    for (shape, arity) in [
        (&pairwise, MerkleArity::Two),
        (&quaternary, MerkleArity::Four),
    ] {
        assert_eq!(shape.bit_variables, bits);
        let decode = shape.native_decode_shape();
        assert_eq!(decode.cap_roots, 2 * arity.cap_roots(CAP_HEIGHT).unwrap());
        assert!(decode.indexed.is_none());
        let ring = &decode.opening.packed.as_ref().unwrap().ring;
        assert_eq!(ring.successor, [true]);
        assert_eq!((ring.min_rounds, ring.max_rounds), (bits - 6, bits - 6));
        assert!(decode.preprocessed.unwrap().packed.is_none());
    }
}

/// The relation has no prime-field circuit: its verification is refused before it adds a node.
#[test]
fn prime_field_verification_is_refused() {
    let (circuit, _) = keccak_chain();
    let bus = native_bus(&circuit, KeccakCommitment::Bits);
    let parameters = Parameters::new(&bus, MerkleArity::Two);
    let verifier = parameters
        .verifier(
            bus.airs(),
            bus.log_heights(),
            parameters.table,
            placeholder_cap(MerkleArity::Two),
        )
        .unwrap();
    let mut b = CircuitBuilder::<BabyBear>::new();
    b.enable_keccak_f1600::<BabyBear>();
    let initial = INITIAL.map(|v| b.define_const(BabyBear::from_u8(v)));
    let ch =
        BinaryTower128Challenger::with_initial_bytes::<BabyBear, BabyBear>(&mut b, HASH, &initial)
            .unwrap();
    let public: Vec<Vec<BinaryPoly64Target>> = Vec::new();
    let before = b.construction_usage().unwrap().expression_nodes;
    assert!(matches!(
        verifier.verify::<BabyBear, BabyBear>(&mut b, ch, &public),
        Err(VerificationError::InvalidProofShape(message))
            if message == "polynomial mixed WHIR MultiStark relation has no prime-field circuit; verify it in the native Poly64 carrier"
    ));
    assert_eq!(b.construction_usage().unwrap().expression_nodes, before);
}
