//! Closed byte-hash AIRs remain verifiable after portable artifact import.

use p3_baby_bear::BabyBear;
use p3_blake3::Blake3;
use p3_circuit::ops::ByteHash;
use p3_circuit::{CircuitBuilder, StatementExport};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::{
    BatchStarkProver, Blake3CompressAirBuilder, Blake3CompressPreprocessor, Blake3CompressProver,
    ConstraintProfile, KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover,
    StatementAirBuilder, StatementPreprocessor, StatementProver, TablePacking,
};
use p3_field::PrimeCharacteristicRing;
use p3_keccak::Keccak256Hash;
use p3_recursion::artifact::{
    ArtifactError, ArtifactLimits, CanonicalStatement, ExpectedVerifierArtifact,
    PortableArtifactExport, PortableArtifactImport, PortableVerifier, TypedArtifactVerifier,
};
use p3_recursion::builtin_config::{
    BabyBearD4Poseidon2BinaryConfig, FriConfigV1, SuiteIdV1, baby_bear_d4_poseidon2_binary,
};
use p3_symmetric::CryptographicHasher;

fn roundtrip(hash: ByteHash) {
    let limits = ArtifactLimits::default();
    let descriptor = FriConfigV1::new(
        SuiteIdV1::BabyBearD4Poseidon2BinaryFri,
        1,
        0,
        2,
        2,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    let config = || baby_bear_d4_poseidon2_binary(&descriptor, &limits.verifier).unwrap();
    let mut b = CircuitBuilder::<BabyBear>::new();
    b.enable_keccak_f1600::<BabyBear>();
    b.enable_blake3_compress::<BabyBear>();
    let raw = [
        b.alloc_private_input("message limb"),
        b.alloc_private_input("message limb"),
    ];
    let one = b.define_const(BabyBear::ONE);
    let message = raw.map(|input| b.add(input, one));
    let digest = b.byte_hash_limbs::<BabyBear>(hash, &message).unwrap();
    let public: Vec<_> = digest.iter().map(|_| b.public_input()).collect();
    for (&computed, &expected) in digest.iter().zip(&public) {
        b.connect(computed, expected);
    }
    let schema = b
        .set_statement_exports::<BabyBear>(
            &public
                .iter()
                .copied()
                .map(StatementExport::Base)
                .collect::<Vec<_>>(),
        )
        .unwrap();
    let circuit = b.build().unwrap();
    let preprocessors: Vec<Box<dyn NpoPreprocessor<BabyBear>>> = vec![
        Box::new(KeccakF1600Preprocessor),
        Box::new(Blake3CompressPreprocessor),
        Box::new(StatementPreprocessor::new(schema.clone())),
    ];
    let builders: Vec<Box<dyn NpoAirBuilder<BabyBearD4Poseidon2BinaryConfig, 1>>> = vec![
        Box::new(KeccakF1600AirBuilder::<1>),
        Box::new(Blake3CompressAirBuilder::<1>),
        Box::new(StatementAirBuilder::<1>::new(schema.clone())),
    ];
    let mut prover = BatchStarkProver::new(config())
        .with_table_packing(TablePacking::new(4, 4).with_min_trace_height(32));
    prover.register_table_prover(Box::new(KeccakF1600Prover::<1>));
    prover.register_table_prover(Box::new(Blake3CompressProver::<1>));
    prover.register_table_prover(Box::new(StatementProver::<1>::new(schema)));
    let prepared = prover
        .prepare_circuit::<BabyBear, 1>(
            &circuit,
            &preprocessors,
            &builders,
            ConstraintProfile::Standard,
        )
        .unwrap();
    let verifier = prepared.verifier();
    let identity = verifier.encode_verifier_artifact(limits).unwrap();
    let imported = PortableVerifier::decode(
        &identity,
        ExpectedVerifierArtifact::from_trusted_bytes(&identity),
        limits,
    )
    .unwrap();
    let typed = TypedArtifactVerifier::decode_with_config(
        config(),
        &identity,
        ExpectedVerifierArtifact::from_trusted_bytes(&identity),
        limits,
    )
    .unwrap();
    for message in [[0x1357u16, 0x2468], [0xdead, 0xbeef]] {
        let bytes: Vec<_> = message.iter().flat_map(|x| x.to_le_bytes()).collect();
        let digest: [u8; 32] = match hash {
            ByteHash::Keccak256 => Keccak256Hash.hash_slice(&bytes),
            ByteHash::Blake3 => Blake3.hash_slice(&bytes),
        };
        let public: Vec<_> = digest
            .chunks_exact(2)
            .map(|chunk| BabyBear::from_u16(u16::from_le_bytes(chunk.try_into().unwrap())))
            .collect();
        let canonical: Vec<_> = digest
            .chunks_exact(2)
            .flat_map(|chunk| {
                u32::from(u16::from_le_bytes(chunk.try_into().unwrap())).to_le_bytes()
            })
            .collect();
        let mut runner = circuit.runner();
        runner
            .set_private_inputs(&message.map(|limb| BabyBear::from_u16(limb) - BabyBear::ONE))
            .unwrap();
        runner.set_public_inputs(&public).unwrap();
        let proof = prepared.prove(&runner.run().unwrap()).unwrap();
        verifier.verify(&proof, &public).unwrap();
        let encoded = verifier.encode_proof_artifact(&proof, limits).unwrap();
        imported
            .verify_encoded(&encoded, CanonicalStatement::new(&canonical, 16))
            .unwrap();
        let checked = typed
            .import_proof(&encoded, CanonicalStatement::new(&canonical, 16))
            .unwrap();
        assert_eq!(checked.statement(), public);
        assert_eq!(checked.trusted_identity_bytes(), identity);
        let mut wrong = canonical.clone();
        wrong[0] ^= 1;
        assert!(
            typed
                .import_proof(&encoded, CanonicalStatement::new(&wrong, 16))
                .is_err()
        );
        let mut trailing = encoded;
        trailing.push(0);
        assert!(
            typed
                .import_proof(&trailing, CanonicalStatement::new(&canonical, 16))
                .is_err()
        );
    }
    let width = match hash {
        ByteHash::Keccak256 => p3_keccak_air::NUM_KECCAK_COLS,
        ByteHash::Blake3 => p3_circuit_prover::air::blake3_air::BLAKE3_COMPRESS_WIDTH,
    };
    let mut tight = limits;
    tight.verifier.max_matrix_width = width - 1;
    assert!(matches!(
        PortableVerifier::decode(
            &identity,
            ExpectedVerifierArtifact::from_trusted_bytes(&identity),
            tight,
        ),
        Err(ArtifactError::DecodeLimitExceeded {
            component: "NPO matrix width",
            ..
        })
    ));
}

#[test]
fn keccak_air_has_a_closed_portable_identity() {
    roundtrip(ByteHash::Keccak256);
}

#[test]
fn blake3_air_has_a_closed_portable_identity() {
    roundtrip(ByteHash::Blake3);
}
