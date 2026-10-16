//! Checked native owners of a native bus statement whose Keccak table is committed as bits,
//! beside a dense WHIR commitment of every other table.

use p3_baby_bear::BabyBear;
use p3_binary_field::BinaryField128;
use p3_circuit::ops::binary_native::BinaryCoordinateField;
use p3_circuit::ops::{ByteHash, keccak_state_to_limbs};
use p3_circuit::{Circuit, CircuitBuilder};
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_circuit_prover::native_bus::{
    KeccakCommitment, NativeBusCircuit, NativeBusCircuitAir, NativeBusTrace,
};
use p3_commit::Mmcs;
use p3_keccak::KeccakF;
use p3_merkle_tree::PrunedMerklePaths;
use p3_multi_stark::{MultiStarkProof, MultiStarkSecurityReport};
use p3_recursion::artifact::{
    ArtifactError, BinaryNativeMixedWhirAuthority, BinaryNativeMixedWhirConfig,
    BinaryNativeMixedWhirPcsParameters, BinaryNativeVerifierSpec, BinaryNativeWhirAuthority,
    BinaryNativeWhirPcsParameters, CanonicalBinaryStatement, ExpectedVerifierArtifact,
};
use p3_recursion::pcs::binary::RecursiveBinaryTowerField;
use p3_recursion::verifier::{VerificationError, VerifierLimits};
use p3_sumcheck::layout::Table;
use p3_symmetric::Permutation;
use p3_whir::pcs::proof::{QueryOpenings, WhirProof};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

type F = BinaryField128;
type Authority = BinaryNativeMixedWhirAuthority<NativeBusCircuitAir<F>>;
type Proof = MultiStarkProof<BinaryNativeMixedWhirConfig>;

const CALLS: usize = 3;
const FOLDING: usize = 2;
const HASH: ByteHash = ByteHash::Keccak256;
/// Two roots per part, so swapping the halves of the main cap changes every root position.
const CAP_HEIGHT: usize = 1;
/// Magic, version, kind, suite and body length.
const HEADER_BYTES: usize = 17;
/// The proof revision leading the body.
const REVISION_BYTES: usize = 2;
const FIELD_BYTES: usize = 16;
/// The row variables one field element of the packed commitment absorbs.
const ABSORBED_VARIABLES: usize = 7;
const DIGEST_BYTES: usize = 32;

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
        .map(|limb| F::from_raw_coordinates(limb as u128).unwrap())
        .collect();
    (circuit, statement)
}

fn native_bus(circuit: &Circuit<F>, keccak: KeccakCommitment) -> NativeBusCircuit<F> {
    NativeBusCircuit::with_options(
        circuit,
        "mixed",
        FOLDING,
        DirectCircuitLimits::default(),
        keccak,
    )
    .unwrap()
}

fn whir(num_variables: usize, rate: usize) -> BinaryNativeWhirPcsParameters<F> {
    whir_folding(num_variables, rate, FOLDING)
}

/// WHIR parameters folding `folding` variables in every round.
fn whir_folding(
    num_variables: usize,
    rate: usize,
    folding: usize,
) -> BinaryNativeWhirPcsParameters<F> {
    BinaryNativeWhirPcsParameters::new(
        num_variables,
        ProtocolParameters {
            security_level: 32,
            pow_bits: 0,
            round_log_inv_rates: vec![],
            folding_factor: FoldingFactor::Constant(folding),
            soundness_type: SecurityAssumption::JohnsonBound,
            starting_log_inv_rate: rate,
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

fn spec<P>(main: P, preprocessed: P) -> BinaryNativeVerifierSpec<P> {
    BinaryNativeVerifierSpec {
        main,
        preprocessed: Some(preprocessed),
        transcript_hash: HASH,
        initial_bytes: b"mixed-native".to_vec(),
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

/// The mixed specification for a Bits-mode native bus, bit-committing table `table`.
fn mixed_spec(
    prepared: &NativeBusCircuit<F>,
    table: usize,
    rates: Rates,
) -> BinaryNativeVerifierSpec<BinaryNativeMixedWhirPcsParameters> {
    let bits = prepared.packed_bit_variables().unwrap();
    spec(
        BinaryNativeMixedWhirPcsParameters::with_packed_table(
            whir(prepared.main_variables(), 1),
            whir(bits - ABSORBED_VARIABLES, rates.packed),
            table,
            bits,
        )
        .unwrap(),
        BinaryNativeMixedWhirPcsParameters::dense(whir(
            prepared.preprocessed_variables().unwrap(),
            rates.preprocessed,
        )),
    )
}

fn mixed_setup(
    airs: Vec<NativeBusCircuitAir<F>>,
    heights: Vec<usize>,
    spec: BinaryNativeVerifierSpec<BinaryNativeMixedWhirPcsParameters>,
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

/// The Keccak chain proven in Bits mode under the mixed authority, and its public values.
fn mixed_proof() -> (Authority, Proof, Vec<Vec<F>>) {
    let (circuit, statement) = keccak_chain();
    let prepared = native_bus(&circuit, KeccakCommitment::Bits);
    let (prover, authority) = Authority::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        mixed_spec(&prepared, prepared.keccak_table_index().unwrap(), RATES),
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

fn field_bytes(values: &[F]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|value| value.raw_coordinates().to_le_bytes())
        .collect()
}

/// Where `needle` sits in `bytes`, which must hold it exactly once.
fn position(bytes: &[u8], needle: &[u8]) -> usize {
    let mut found = bytes
        .windows(needle.len())
        .enumerate()
        .filter(|(_, window)| *window == needle)
        .map(|(offset, _)| offset);
    let offset = found.next().expect("the encoding holds the value");
    assert!(found.next().is_none(), "the encoding holds the value once");
    offset
}

/// The first sibling digest of a WHIR opening's first query round.
fn first_sibling<M>(whir: &WhirProof<F, F, M>) -> [u8; 32]
where
    M: Mmcs<F, MultiProof = PrunedMerklePaths<u8, 32>>,
{
    let openings = whir
        .rounds
        .first()
        .map_or(&whir.final_openings, |round| &round.openings);
    let siblings = match openings {
        QueryOpenings::Base(o) => &o.proof.sibling_hashes,
        QueryOpenings::Extension(o) => &o.proof.sibling_hashes,
    };
    *siblings
        .first()
        .expect("the queries leave a sibling digest to send")
}

#[test]
fn bits_mode_round_trip_decodes_and_verifies() {
    let (authority, proof, public) = mixed_proof();
    assert!(proof.opening.packed.is_some());
    let token = authority.verify_native(&proof, &public).unwrap();
    assert_eq!(token.public_values(), public);
    let encoded = authority.encode_native_proof(&proof, &public).unwrap();
    assert_eq!(
        encoded,
        authority.encode_native_proof(&proof, &public).unwrap()
    );
    let statement = authority.encode_statement(&public).unwrap();
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
        .private_values::<BabyBear>(&authority.recursive_verifier().input_shape())
        .unwrap();
}

#[test]
fn identity_binds_the_packed_table_rate_and_preprocessing() {
    let (circuit, _) = keccak_chain();
    let bits = native_bus(&circuit, KeccakCommitment::Bits);
    let keccak = bits.keccak_table_index().unwrap();
    let identity = |airs: Vec<_>, heights: Vec<_>, table, rates| {
        mixed_setup(airs, heights, mixed_spec(&bits, table, rates))
            .unwrap()
            .canonical_verifier_bytes()
            .to_vec()
    };
    let (airs, heights) = (bits.airs().to_vec(), bits.log_heights().to_vec());
    let base = identity(airs.clone(), heights.clone(), keccak, RATES);
    // The Keccak table moved to the front of the instance order.
    let (mut moved_airs, mut moved_heights) = (airs.clone(), heights.clone());
    moved_airs.swap(0, keccak);
    moved_heights.swap(0, keccak);
    assert_ne!(base, identity(moved_airs, moved_heights, 0, RATES));
    let packed = Rates { packed: 2, ..RATES };
    assert_ne!(
        base,
        identity(airs.clone(), heights.clone(), keccak, packed)
    );
    let preprocessed = Rates {
        preprocessed: 2,
        ..RATES
    };
    assert_ne!(
        base,
        identity(airs.clone(), heights.clone(), keccak, preprocessed)
    );
    // The preprocessing commitment folds its first round by the main commitment's factor.
    let mut refolded = mixed_spec(&bits, keccak, RATES);
    refolded.preprocessed = Some(BinaryNativeMixedWhirPcsParameters::dense(whir_folding(
        bits.preprocessed_variables().unwrap(),
        1,
        FOLDING + 1,
    )));
    assert!(matches!(
        mixed_setup(airs.clone(), heights.clone(), refolded),
        Err(VerificationError::InvalidProofShape(message)) if message
            == "binary native mixed WHIR main and preprocessing initial folding factors differ"
    ));

    // The configured table of a Dense-mode bus keeps its booleanity constraints.
    let dense = native_bus(&circuit, KeccakCommitment::Dense);
    assert!(matches!(
        mixed_setup(
            dense.airs().to_vec(),
            dense.log_heights().to_vec(),
            mixed_spec(&bits, keccak, RATES),
        ),
        Err(VerificationError::InvalidProofShape(message)) if message
            == "binary mixed WHIR MultiStark bit-committed table is not exactly the Boolean-assuming AIR"
    ));
    // A dense family refuses the Bits-mode AIRs before planning a relation.
    let refused = BinaryNativeWhirAuthority::<F, _>::setup(
        airs,
        heights,
        spec(
            whir(bits.main_variables(), 1),
            whir(bits.preprocessed_variables().unwrap(), 1),
        ),
        &limits(),
    );
    assert!(matches!(
        refused,
        Err(VerificationError::InvalidProofShape(message)) if message
            == "binary native AIR declares bit columns its commitment does not store as bits"
    ));
}

/// The security report an authority exposes is the one its setup enforced: a target at the
/// report's whole composed bits is accepted and the next bit is refused. Both main openings and
/// the preprocessing opening are terms of the mixed report; the dense report has one main
/// opening.
#[test]
fn setup_enforces_the_security_report_it_exposes() {
    let (circuit, _) = keccak_chain();
    let bits = native_bus(&circuit, KeccakCommitment::Bits);
    let keccak = bits.keccak_table_index().unwrap();
    let mixed = |security_bits| {
        let mut spec = mixed_spec(&bits, keccak, RATES);
        spec.security_bits = security_bits;
        mixed_setup(bits.airs().to_vec(), bits.log_heights().to_vec(), spec)
    };
    let report = mixed(1).unwrap().security_report().clone();
    let openings = |report: &MultiStarkSecurityReport| {
        report
            .terms()
            .iter()
            .filter(|term| term.label == "whir-opening")
            .count()
    };
    assert_eq!(openings(&report), 3);
    let floor = report.security_bits().unwrap().floor() as usize;
    assert!(floor >= 16, "composed security {floor} bits");
    assert_eq!(
        mixed(floor).unwrap().security_report().terms(),
        report.terms()
    );
    assert!(matches!(
        mixed(floor + 1),
        Err(VerificationError::InvalidProofShape(message))
            if message.starts_with("binary native statement security target is not met")
    ));

    let dense = native_bus(&circuit, KeccakCommitment::Dense);
    let dense_spec = spec(
        whir(dense.main_variables(), 1),
        whir(dense.preprocessed_variables().unwrap(), 1),
    );
    let authority = BinaryNativeWhirAuthority::<F, _>::setup(
        dense.airs().to_vec(),
        dense.log_heights().to_vec(),
        dense_spec,
        &limits(),
    )
    .map(|(_, authority)| authority)
    .unwrap();
    assert_eq!(openings(authority.security_report()), 2);
    assert!(authority.security_report().security_bits().unwrap() >= 16.0);
}

#[test]
fn proof_bytes_of_the_dense_and_mixed_families_are_not_interchangeable() {
    let (mixed, proof, public) = mixed_proof();
    let mixed_bytes = mixed.encode_native_proof(&proof, &public).unwrap();

    let (circuit, statement) = keccak_chain();
    let prepared = native_bus(&circuit, KeccakCommitment::Dense);
    let (prover, dense) = BinaryNativeWhirAuthority::<F, _>::setup(
        prepared.airs().to_vec(),
        prepared.log_heights().to_vec(),
        spec(
            whir(prepared.main_variables(), 1),
            whir(prepared.preprocessed_variables().unwrap(), 1),
        ),
        &limits(),
    )
    .unwrap();
    assert_eq!(prepared.public_values(&statement).unwrap(), public);
    let mut runner = circuit.runner();
    runner.set_public_inputs(&statement).unwrap();
    let traces = prepared
        .traces(&runner.run().unwrap().witness_trace)
        .unwrap();
    let dense_bytes = dense
        .encode_native_proof(&prover.prove(&public, traces).unwrap(), &public)
        .unwrap();

    let suite = |bytes: &[u8]| u16::from_le_bytes(bytes[11..13].try_into().unwrap());
    let count = statement_count(&public);
    let mixed_statement = mixed.encode_statement(&public).unwrap();
    assert_eq!(
        decode(&mixed, &dense_bytes, &mixed_statement, count),
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
}

#[test]
fn byte_tampers_of_mixed_proofs_are_rejected() {
    let (authority, proof, public) = mixed_proof();
    let encoded = authority.encode_native_proof(&proof, &public).unwrap();
    let statement = authority.encode_statement(&public).unwrap();
    let count = statement_count(&public);
    decode(&authority, &encoded, &statement, count).unwrap();

    let half = (1 << CAP_HEIGHT) * DIGEST_BYTES;
    let cap = HEADER_BYTES + REVISION_BYTES + count * FIELD_BYTES;
    assert_eq!(
        encoded[cap..cap + 2 * half],
        proof.commitment.roots().concat()
    );
    // Whole blocks locate the values: a round flag's evaluation one row ahead equals the
    // previous flag's, so short runs of opened values repeat.
    let packed = proof.opening.packed.as_ref().unwrap();
    let value = position(&encoded, &field_bytes(&packed.values));
    let tensor = position(
        &encoded,
        &field_bytes(packed.opening.reduction.claims[0].tensor.rows()),
    );
    let packed_path = position(&encoded, &first_sibling(&packed.opening.opening.whir));
    let dense_path = position(&encoded, &first_sibling(&proof.opening.dense.whir));

    let flip = |offset: usize| {
        let mut bytes = encoded.clone();
        bytes[offset] ^= 1;
        bytes
    };
    let mut swapped = encoded.clone();
    swapped[cap..cap + 2 * half].rotate_left(half);
    let tampers = [
        ("dense cap half", flip(cap)),
        ("packed cap half", flip(cap + half)),
        ("swapped cap halves", swapped),
        ("packed opened value", flip(value)),
        ("ring-switch tensor row", flip(tensor)),
        ("packed WHIR path", flip(packed_path)),
        ("dense WHIR path", flip(dense_path)),
    ];
    for (name, bytes) in tampers {
        assert_eq!(
            decode(&authority, &bytes, &statement, count),
            Err(ArtifactError::VerificationRejected),
            "a tampered {name} was accepted"
        );
    }

    let mut trailing = encoded.clone();
    trailing.push(0);
    assert!(decode(&authority, &trailing, &statement, count).is_err());
    let body = u32::try_from(trailing.len() - HEADER_BYTES).unwrap();
    trailing[13..HEADER_BYTES].copy_from_slice(&body.to_le_bytes());
    assert!(decode(&authority, &trailing, &statement, count).is_err());
}
