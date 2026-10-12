//! Checked native owners of a Poly64 native bus statement whose Keccak table is committed as
//! bits packed sixty-four per element, beside a dense WHIR commitment of every other table.

use p3_binary_field::{Poly64, Poly192};
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::{ByteHash, keccak_state_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::native_bus::{
    KeccakCommitment, NativeBusCircuit, NativeBusCircuitAir, NativeBusTrace,
};
use p3_keccak::KeccakF;
use p3_multi_stark::MultiStarkProof;
use p3_recursion::artifact::{
    ArtifactError, BinaryNativePolyMixedWhirAuthority, BinaryNativePolyMixedWhirConfig,
    BinaryNativePolyMixedWhirPcsParameters, BinaryNativePolyWhirAuthority,
    BinaryNativePolyWhirPcsParameters, BinaryNativeVerifierSpec, CanonicalBinaryStatement,
    ExpectedVerifierArtifact,
};
use p3_recursion::pcs::binary::MerkleArity;
use p3_recursion::verifier::{VerificationError, VerifierLimits};
use p3_sumcheck::layout::Table;
use p3_symmetric::Permutation;
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

type F = Poly64;
type Authority = BinaryNativePolyMixedWhirAuthority<NativeBusCircuitAir<F>>;
type Proof = MultiStarkProof<BinaryNativePolyMixedWhirConfig>;

/// Three permutations fill 75 rows, padded to 128: two elements of rows per column, so the
/// next row crosses an element.
const CALLS: usize = 3;
const MIN_VARIABLES: usize = 7;
const FOLDING: usize = 2;
const HASH: ByteHash = ByteHash::Keccak256;
/// Two roots per part on pairwise trees, four on arity-4 trees.
const CAP_HEIGHT: usize = 1;
/// Magic, version, kind, suite and body length.
const HEADER_BYTES: usize = 17;
const FIELD_BYTES: usize = 8;
const DIGEST_BYTES: usize = 32;
/// The row variables one Poly64 element of the packed commitment absorbs.
const ABSORBED_VARIABLES: usize = 6;

/// Three chained Keccak-f calls from a public input state to a public output state, and the
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
        .map(|limb| F::from_raw_coordinates(u128::from(limb)).unwrap())
        .collect();
    (circuit, statement)
}

fn native_bus(circuit: &Circuit<F>, keccak: KeccakCommitment) -> NativeBusCircuit<F> {
    NativeBusCircuit::with_options(
        circuit,
        "poly-mixed",
        MIN_VARIABLES,
        DirectCircuitLimits::default(),
        keccak,
    )
    .unwrap()
}

fn whir(
    num_variables: usize,
    rate: usize,
    arity: MerkleArity,
) -> BinaryNativePolyWhirPcsParameters {
    BinaryNativePolyWhirPcsParameters::with_limits(
        num_variables,
        ProtocolParameters {
            security_level: 32,
            pow_bits: 0,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(FOLDING),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: rate,
        },
        HASH,
        arity,
        CAP_HEIGHT,
        &limits(),
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

fn spec<P>(main: P, preprocessed: P) -> BinaryNativeVerifierSpec<P> {
    BinaryNativeVerifierSpec {
        main,
        preprocessed: Some(preprocessed),
        transcript_hash: HASH,
        initial_bytes: b"poly-mixed-native".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 32,
        security_bits: 16,
    }
}

/// Rates of the packed and the preprocessing commitment; the dense main rate stays 1.
#[derive(Clone, Copy)]
struct Rates {
    packed: usize,
    preprocessed: usize,
}

const RATES: Rates = Rates {
    packed: 1,
    preprocessed: 1,
};

/// The mixed specification for a Bits-mode native bus on trees of `arity`, bit-committing
/// table `table`.
fn mixed_spec(
    prepared: &NativeBusCircuit<F>,
    table: usize,
    rates: Rates,
    arity: MerkleArity,
) -> BinaryNativeVerifierSpec<BinaryNativePolyMixedWhirPcsParameters> {
    let bits = prepared.packed_bit_variables().unwrap();
    spec(
        BinaryNativePolyMixedWhirPcsParameters::with_packed_table(
            whir(prepared.main_variables(), 1, arity),
            whir(bits - ABSORBED_VARIABLES, rates.packed, arity),
            table,
            bits,
        )
        .unwrap(),
        BinaryNativePolyMixedWhirPcsParameters::dense(whir(
            prepared.preprocessed_variables().unwrap(),
            rates.preprocessed,
            arity,
        )),
    )
}

fn mixed_setup(
    airs: Vec<NativeBusCircuitAir<F>>,
    heights: Vec<usize>,
    spec: BinaryNativeVerifierSpec<BinaryNativePolyMixedWhirPcsParameters>,
) -> Result<Authority, VerificationError> {
    Authority::setup(airs, heights, spec, &limits()).map(|(_, authority)| authority)
}

/// Every table as proven: dense tables as field cells, the bit-committed one as packed bits.
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

/// The Keccak chain proven in Bits mode under the mixed authority on trees of `arity`, and its
/// public values.
fn mixed_proof(arity: MerkleArity) -> (Authority, Proof, Vec<Vec<F>>) {
    let (circuit, statement) = keccak_chain();
    let prepared = native_bus(&circuit, KeccakCommitment::Bits);
    let (prover, authority) = Authority::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        mixed_spec(
            &prepared,
            prepared.keccak_table_index().unwrap(),
            RATES,
            arity,
        ),
        &limits(),
    )
    .unwrap();
    let public = prepared.public_values(&statement).unwrap();
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    let witness = runner.run().unwrap().witness_trace;
    let proof = prover
        .prove_tables(&public, tables(prepared.trace_tables(&witness).unwrap()))
        .unwrap();
    (authority, proof, public)
}

fn statement_count(public: &[Vec<F>]) -> usize {
    public.iter().map(Vec::len).sum()
}

fn decode(
    authority: &Authority,
    bytes: &[u8],
    statement: &[u8],
    count: usize,
) -> Result<(), ArtifactError> {
    let identity = authority.canonical_verifier_bytes();
    authority
        .decode_and_verify(
            identity,
            ExpectedVerifierArtifact::from_trusted_bytes(identity),
            bytes,
            CanonicalBinaryStatement::new(statement, count),
        )
        .map(|_| ())
}

fn suite(bytes: &[u8]) -> u16 {
    u16::from_le_bytes(bytes[11..13].try_into().unwrap())
}

/// The Keccak table travels as packed bits at either tree arity: it encodes deterministically,
/// decodes to the statement it was proven for, and feeds the native recursion input.
#[test]
fn bits_mode_round_trips_at_both_arities() {
    for arity in [MerkleArity::Two, MerkleArity::Four] {
        let (authority, proof, public) = mixed_proof(arity);
        assert!(proof.opening.packed.is_some(), "{arity:?}");
        let token = authority.verify_native(&proof, &public).unwrap();
        assert_eq!(token.public_values(), public);
        let encoded = authority.encode_native_proof(&proof, &public).unwrap();
        assert_eq!(
            encoded,
            authority.encode_native_proof(&proof, &public).unwrap()
        );
        let statement = authority.encode_statement(&public).unwrap();
        assert_eq!(statement.len(), statement_count(&public) * FIELD_BYTES);
        let identity = authority.canonical_verifier_bytes();
        let token = authority
            .decode_and_verify(
                identity,
                ExpectedVerifierArtifact::from_trusted_bytes(identity),
                &encoded,
                CanonicalBinaryStatement::new(&statement, statement_count(&public)),
            )
            .unwrap();
        assert_eq!(token.public_values(), public);
        assert_eq!(token.canonical_verifier_bytes(), identity);
        token
            .native_input()
            .private_native_values(&authority.recursive_verifier().input_shape())
            .unwrap();
    }
}

/// The identity binds the packed table, the tree arity and both parts' rates.
#[test]
fn identity_binds_the_packed_table_arity_and_rates() {
    let (circuit, _) = keccak_chain();
    let bits = native_bus(&circuit, KeccakCommitment::Bits);
    let keccak = bits.keccak_table_index().unwrap();
    let identity = |airs: Vec<_>, heights: Vec<_>, table, rates, arity| {
        mixed_setup(airs, heights, mixed_spec(&bits, table, rates, arity))
            .unwrap()
            .canonical_verifier_bytes()
            .to_vec()
    };
    let (airs, heights) = (bits.airs().to_vec(), bits.log_heights().to_vec());
    let two = MerkleArity::Two;
    let base = identity(airs.clone(), heights.clone(), keccak, RATES, two);
    // The Keccak table moved to the front of the instance order.
    let (mut moved_airs, mut moved_heights) = (airs.clone(), heights.clone());
    moved_airs.swap(0, keccak);
    moved_heights.swap(0, keccak);
    assert_ne!(base, identity(moved_airs, moved_heights, 0, RATES, two));
    let packed = Rates { packed: 2, ..RATES };
    let preprocessed = Rates {
        preprocessed: 2,
        ..RATES
    };
    for (rates, arity) in [
        (packed, two),
        (preprocessed, two),
        (RATES, MerkleArity::Four),
    ] {
        assert_ne!(
            base,
            identity(airs.clone(), heights.clone(), keccak, rates, arity)
        );
    }

    // The configured table of a Dense-mode bus keeps its booleanity constraints.
    let dense = native_bus(&circuit, KeccakCommitment::Dense);
    assert!(matches!(
        mixed_setup(
            dense.airs().to_vec(),
            dense.log_heights().to_vec(),
            mixed_spec(&bits, keccak, RATES, two),
        ),
        Err(VerificationError::InvalidProofShape(message)) if message
            == "polynomial mixed WHIR MultiStark bit-committed table is not exactly the Boolean-assuming AIR"
    ));
    // The packed table's bit stack must be the table's own.
    let mut shifted = mixed_spec(&bits, keccak, RATES, two);
    shifted.main = BinaryNativePolyMixedWhirPcsParameters::with_packed_table(
        whir(bits.main_variables(), 1, two),
        whir(
            bits.packed_bit_variables().unwrap() - ABSORBED_VARIABLES + 1,
            1,
            two,
        ),
        keccak,
        bits.packed_bit_variables().unwrap() + 1,
    )
    .unwrap();
    assert!(matches!(
        mixed_setup(airs.clone(), heights.clone(), shifted),
        Err(VerificationError::InvalidProofShape(message)) if message
            == "binary native mixed WHIR bit variables do not match the packed table"
    ));
    // A dense family refuses the Bits-mode AIRs before planning a relation.
    let refused = BinaryNativePolyWhirAuthority::<_>::setup(
        airs,
        heights,
        spec(
            whir(bits.main_variables(), 1, two),
            whir(bits.preprocessed_variables().unwrap(), 1, two),
        ),
        &limits(),
    );
    assert!(matches!(
        refused,
        Err(VerificationError::InvalidProofShape(message)) if message
            == "binary native AIR declares bit columns its commitment does not store as bits"
    ));
}

/// A mixed authority and a dense one, or a mixed one on other trees, accept no one another's
/// proofs, identities or suites.
#[test]
fn foreign_authorities_refuse_the_proof_bytes() {
    let (mixed, proof, public) = mixed_proof(MerkleArity::Two);
    let mixed_bytes = mixed.encode_native_proof(&proof, &public).unwrap();
    let count = statement_count(&public);
    let statement = mixed.encode_statement(&public).unwrap();
    decode(&mixed, &mixed_bytes, &statement, count).unwrap();

    // Dense family: another suite in both directions.
    let (circuit, statement_values) = keccak_chain();
    let prepared = native_bus(&circuit, KeccakCommitment::Dense);
    let (prover, dense) = BinaryNativePolyWhirAuthority::<_>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec(
            whir(prepared.main_variables(), 1, MerkleArity::Two),
            whir(
                prepared.preprocessed_variables().unwrap(),
                1,
                MerkleArity::Two,
            ),
        ),
        &limits(),
    )
    .unwrap();
    assert_eq!(prepared.public_values(&statement_values).unwrap(), public);
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement_values).unwrap();
    let traces = prepared
        .traces(&runner.run().unwrap().witness_trace)
        .unwrap();
    let dense_bytes = dense
        .encode_native_proof(&prover.prove(&public, traces).unwrap(), &public)
        .unwrap();
    assert_ne!(suite(&dense_bytes), suite(&mixed_bytes));
    assert_eq!(
        decode(&mixed, &dense_bytes, &statement, count),
        Err(ArtifactError::UnsupportedSuite(suite(&dense_bytes)))
    );
    let dense_statement = dense.encode_statement(&public).unwrap();
    let dense_identity = dense.canonical_verifier_bytes();
    assert_eq!(
        dense
            .decode_and_verify(
                dense_identity,
                ExpectedVerifierArtifact::from_trusted_bytes(dense_identity),
                &mixed_bytes,
                CanonicalBinaryStatement::new(&dense_statement, count),
            )
            .err(),
        Some(ArtifactError::UnsupportedSuite(suite(&mixed_bytes)))
    );

    // Trees of the other arity: their identity is not this authority's, and their proof bytes
    // carry caps of another length.
    let (four, four_proof, _) = mixed_proof(MerkleArity::Four);
    let four_bytes = four.encode_native_proof(&four_proof, &public).unwrap();
    assert_ne!(
        mixed.canonical_verifier_bytes(),
        four.canonical_verifier_bytes()
    );
    let four_identity = four.canonical_verifier_bytes();
    assert_eq!(
        mixed
            .decode_and_verify(
                four_identity,
                ExpectedVerifierArtifact::from_trusted_bytes(four_identity),
                &four_bytes,
                CanonicalBinaryStatement::new(&statement, count),
            )
            .err(),
        Some(ArtifactError::TrustedArtifactMismatch)
    );
    assert!(decode(&mixed, &four_bytes, &statement, count).is_err());
    assert!(decode(&four, &mixed_bytes, &statement, count).is_err());

    // A statement of another value is no statement of this proof.
    let mut wrong = public;
    let row = wrong.iter().position(|row| !row.is_empty()).unwrap();
    wrong[row][0] += F::new(1);
    let wrong = mixed.encode_statement(&wrong).unwrap();
    assert!(decode(&mixed, &mixed_bytes, &wrong, count).is_err());
}

/// Bytes cut short or extended past the encoding, and bytes flipped in each part, are refused.
#[test]
fn truncated_oversized_and_tampered_proofs_are_refused() {
    let (authority, proof, public) = mixed_proof(MerkleArity::Two);
    let encoded = authority.encode_native_proof(&proof, &public).unwrap();
    let statement = authority.encode_statement(&public).unwrap();
    let count = statement_count(&public);
    decode(&authority, &encoded, &statement, count).unwrap();

    // The cut lengths walk the whole encoding in steps that land in every part.
    let step = encoded.len() / 61 + 1;
    for length in (0..encoded.len()).step_by(step).chain([encoded.len() - 1]) {
        assert!(
            decode(&authority, &encoded[..length], &statement, count).is_err(),
            "a proof cut to {length} bytes was accepted"
        );
    }

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(decode(&authority, &trailing, &statement, count).is_err());
    let body = u32::try_from(trailing.len() - HEADER_BYTES).unwrap();
    trailing[13..HEADER_BYTES].copy_from_slice(&body.to_le_bytes());
    assert!(decode(&authority, &trailing, &statement, count).is_err());

    // The main cap carries the dense roots, then the packed roots.
    let half = (1 << CAP_HEIGHT) * DIGEST_BYTES;
    let cap = HEADER_BYTES + 2 + count * FIELD_BYTES;
    assert_eq!(
        encoded[cap..cap + 2 * half],
        proof.commitment.roots().concat()
    );
    let flip = |offset: usize| {
        let mut bytes = encoded.clone();
        bytes[offset] ^= 1;
        bytes
    };
    let mut swapped = encoded.clone();
    swapped[cap..cap + 2 * half].rotate_left(half);
    let last = encoded.len() - 1;
    let tampers = [
        ("dense cap half", flip(cap)),
        ("packed cap half", flip(cap + half)),
        ("swapped cap halves", swapped),
        ("final byte", flip(last)),
        ("middle byte", flip(encoded.len() / 2)),
    ];
    for (name, bytes) in tampers {
        assert!(
            decode(&authority, &bytes, &statement, count).is_err(),
            "a tampered {name} was accepted"
        );
    }
}

/// The packed opening's values are the proof's own: one changed value leaves a proof the
/// authority refuses to encode.
#[test]
fn a_forged_packed_value_is_not_encoded() {
    let (authority, proof, public) = mixed_proof(MerkleArity::Two);
    let mut forged: Proof = postcard::from_bytes(&postcard::to_allocvec(&proof).unwrap()).unwrap();
    forged.opening.packed.as_mut().unwrap().values[0] += Poly192::new([F::new(1); 3]);
    assert!(authority.verify_native(&forged, &public).is_err());
    assert_eq!(
        authority.encode_native_proof(&forged, &public),
        Err(ArtifactError::VerificationRejected)
    );
}
