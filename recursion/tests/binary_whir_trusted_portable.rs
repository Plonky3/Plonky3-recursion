//! Checked binary tokens remain bound through portable prime recursion layers.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField32, TowerLevel};
use p3_circuit::ops::ByteHash;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::artifact::{
    ArtifactLimits, BinaryNativeVerifierSpec, BinaryNativeWhirAuthority,
    BinaryNativeWhirPcsParameters, CanonicalBinaryStatement, CanonicalStatement,
    ExpectedVerifierArtifact, PortableArtifactExport, PortableArtifactImport, PortableVerifier,
    TypedArtifactVerifier,
};
use p3_recursion::backend::fri::FriRecursionBackend;
use p3_recursion::builtin_config::{
    BabyBearD4Poseidon2BinaryConfig, FriConfigV1, SuiteIdV1, baby_bear_d4_poseidon2_binary,
};
use p3_recursion::prepared::PreparedBinaryWhirMultiStarkLayer;
use p3_recursion::{BatchOnly, Poseidon2Config, ProveNextLayerParams, TrustedPreparedLayer};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

type F = BinaryField32;

type C = BabyBearD4Poseidon2BinaryConfig;
struct ConstantAir;
impl BaseAir<F> for ConstantAir {
    fn width(&self) -> usize {
        1
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
    fn num_public_values(&self) -> usize {
        1
    }
}
impl<AB: AirBuilder<F = F>> Air<AB> for ConstantAir {
    fn eval(&self, b: &mut AB) {
        b.assert_eq(b.main().current_slice()[0], b.public_values()[0]);
    }
}
fn spec(
    prefix: Vec<u8>,
    hash: ByteHash,
) -> BinaryNativeVerifierSpec<BinaryNativeWhirPcsParameters<F>> {
    BinaryNativeVerifierSpec {
        main: BinaryNativeWhirPcsParameters::new(
            3,
            ProtocolParameters {
                starting_log_inv_rate: 2,
                round_log_inv_rates: vec![],
                folding_factor: FoldingFactor::Constant(1),
                soundness_type: SecurityAssumption::JohnsonBound,
                security_level: 24,
                pow_bits: 0,
            },
            hash,
            0,
        )
        .unwrap(),
        preprocessed: None,
        transcript_hash: hash,
        initial_bytes: prefix,
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 16,
    }
}
fn config(limits: &ArtifactLimits) -> C {
    baby_bear_d4_poseidon2_binary(
        &FriConfigV1::new(
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
        ),
        &limits.verifier,
    )
    .unwrap()
}
fn canonical(values: &[BabyBear]) -> Vec<u8> {
    values
        .iter()
        .flat_map(|v| (v.as_canonical_u64() as u32).to_le_bytes())
        .collect()
}

fn checked_whir_chain(hash: ByteHash) {
    let limits = ArtifactLimits::default();
    let native_spec = spec(vec![7, 19, 13], hash);
    let (prover, authority) = BinaryNativeWhirAuthority::<F, _>::setup_with_artifact_limits(
        vec![ConstantAir],
        vec![3],
        native_spec.clone(),
        limits,
    )
    .unwrap();
    let output_config = config(&limits);
    let params = ProveNextLayerParams::default();
    let layer = PreparedBinaryWhirMultiStarkLayer::<F, C, 4>::from_native_authority(
        &authority,
        output_config.clone(),
        params.clone(),
    )
    .unwrap();
    assert_eq!(
        layer.native_verifier_identity(),
        Some(authority.canonical_verifier_bytes())
    );
    let mut encoded_outputs = Vec::new();
    for raw in [0u8, 1] {
        let value = F::from_repr(raw.into());
        let public = vec![vec![value]];
        let proof = prover
            .prove(&public, vec![RowMajorMatrix::new(vec![value; 8], 1)])
            .unwrap();
        let encoded = authority.encode_native_proof(&proof, &public).unwrap();
        let statement = authority.encode_statement(&public).unwrap();
        let identity = authority.canonical_verifier_bytes();
        let checked = authority
            .decode_and_verify(
                identity,
                ExpectedVerifierArtifact::from_trusted_bytes(identity),
                &encoded,
                CanonicalBinaryStatement::new(&statement, 1),
            )
            .unwrap();
        assert_eq!(checked.public_values(), public);
        assert_eq!(
            checked.canonical_verifier_bytes(),
            authority.canonical_verifier_bytes()
        );
        let mut wrong = public.clone();
        wrong[0][0] += F::ONE;
        assert!(authority.verify_native(&proof, &wrong).is_err());
        let mut changed = proof;
        changed.commitment = p3_merkle_tree::MerkleCap::new(vec![[0; 32]]);
        assert!(authority.verify_native(&changed, &public).is_err());
        let output = layer.prove_verified(&checked).unwrap();
        let statement = layer.statement_layout().pack::<BabyBear>(&public).unwrap();
        assert_eq!(
            statement,
            [
                BabyBear::from_u8(raw),
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO,
                BabyBear::ZERO
            ]
        );
        layer.verifier().verify(&output.0, &statement).unwrap();
        encoded_outputs.push((
            layer
                .verifier()
                .encode_proof_artifact(&output.0, limits)
                .unwrap(),
            statement,
        ));
    }
    let verifier_bytes = layer.verifier().encode_verifier_artifact(limits).unwrap();
    let (foreign_prover, foreign) = BinaryNativeWhirAuthority::<F, _>::setup_with_artifact_limits(
        vec![ConstantAir],
        vec![3],
        spec(vec![7, 19, 13, 0], hash),
        limits,
    )
    .unwrap();
    let value = F::ONE;
    let public = vec![vec![value]];
    let proof = foreign_prover
        .prove(&public, vec![RowMajorMatrix::new(vec![value; 8], 1)])
        .unwrap();
    let token = foreign.verify_native(&proof, &public).unwrap();
    assert!(matches!(layer.prove_verified(&token),
        Err(p3_recursion::VerificationError::InvalidProofShape(message))
            if message == "binary verified input belongs to another native authority"));
    drop(layer);
    drop(prover);
    drop(authority);
    drop(foreign);
    drop(foreign_prover);
    let imported = TypedArtifactVerifier::<C>::decode_with_config(
        output_config.clone(),
        &verifier_bytes,
        ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
        limits,
    )
    .unwrap();
    let portable = PortableVerifier::decode(
        &verifier_bytes,
        ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
        limits,
    )
    .unwrap();
    for (bytes, statement) in &encoded_outputs {
        portable
            .verify_encoded(bytes, CanonicalStatement::new(&canonical(statement), 8))
            .unwrap();
    }
    assert!(
        portable
            .verify_encoded(
                &encoded_outputs[0].0,
                CanonicalStatement::new(&canonical(&encoded_outputs[1].1), 8)
            )
            .is_err()
    );
    let (bytes, statement) = &encoded_outputs[0];
    let child = imported
        .import_proof(bytes, CanonicalStatement::new(&canonical(statement), 8))
        .unwrap();
    let backend = FriRecursionBackend::<16, 8>::new(Poseidon2Config::BABY_BEAR_D4_W16)
        .for_extension_degree::<4>();
    let outer = TrustedPreparedLayer::<C, C, BatchOnly, _, 4>::new(
        child.as_source(),
        output_config,
        backend,
        params,
    )
    .unwrap();
    let output = outer.prove(child.as_input()).unwrap();
    outer.verifier().verify(&output.0, statement).unwrap();
    let outer_verifier = outer.verifier().encode_verifier_artifact(limits).unwrap();
    let outer_bytes = outer
        .verifier()
        .encode_proof_artifact(&output.0, limits)
        .unwrap();
    drop(output);
    drop(outer);
    drop(child);
    drop(imported);
    drop(portable);
    let portable = PortableVerifier::decode(
        &outer_verifier,
        ExpectedVerifierArtifact::from_trusted_bytes(&outer_verifier),
        limits,
    )
    .unwrap();
    portable
        .verify_encoded(
            &outer_bytes,
            CanonicalStatement::new(&canonical(statement), 8),
        )
        .unwrap();
    assert!(
        portable
            .verify_encoded(
                &outer_bytes,
                CanonicalStatement::new(&canonical(&encoded_outputs[1].1), 8)
            )
            .is_err()
    );
}

#[test]
fn checked_whir_native_bytes_survive_two_portable_recursion_layers() {
    checked_whir_chain(ByteHash::Blake3);
}
