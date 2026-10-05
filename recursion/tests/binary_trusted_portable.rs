//! Checked binary tokens remain bound through portable prime recursion layers.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::{BinaryField8, BinaryField64, TowerLevel};
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsParams};
use p3_circuit::ops::ByteHash;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::artifact::{
    ArtifactLimits, BinaryNativeAuthority, BinaryNativePcsParameters, BinaryNativeVerifierSpec,
    CanonicalBinaryStatement, CanonicalStatement, ExpectedVerifierArtifact, PortableArtifactExport,
    PortableArtifactImport, PortableVerifier, TypedArtifactVerifier,
};
use p3_recursion::backend::fri::FriRecursionBackend;
use p3_recursion::builtin_config::{
    BabyBearD4Poseidon2BinaryConfig, FriConfigV1, SuiteIdV1, baby_bear_d4_poseidon2_binary,
};
use p3_recursion::prepared::PreparedBinaryMultiStarkLayer;
use p3_recursion::{BatchOnly, Poseidon2Config, ProveNextLayerParams, TrustedPreparedLayer};

type F = BinaryField8;
type E = BinaryField64;
type C = BabyBearD4Poseidon2BinaryConfig;
struct ConstantAir;
impl BaseAir<F> for ConstantAir {
    fn width(&self) -> usize {
        1
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
fn spec(prefix: Vec<u8>) -> BinaryNativeVerifierSpec {
    BinaryNativeVerifierSpec {
        main: BinaryNativePcsParameters {
            config: BinaryPcsConfig::try_new::<F, E>(
                1,
                BinaryPcsParams {
                    log_inv_rate: 2,
                    pow_bits: 0,
                    security_level: 24,
                },
            )
            .unwrap(),
            hash: ByteHash::Blake3,
            cap_height: 0,
            max_query_draws: 128,
        },
        preprocessed: None,
        transcript_hash: ByteHash::Blake3,
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

#[test]
fn checked_binary_native_tokens_cross_portable_and_second_trusted_layer() {
    let limits = ArtifactLimits::default();
    let native_spec = spec(vec![7, 19, 13]);
    let (prover, authority) = BinaryNativeAuthority::<F, E, _>::setup_with_artifact_limits(
        vec![ConstantAir],
        vec![1],
        native_spec,
        limits,
    )
    .unwrap();
    let output_config = config(&limits);
    let params = ProveNextLayerParams::default();
    let layer = PreparedBinaryMultiStarkLayer::<F, E, C, 4>::from_native_authority(
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
    for raw in [137u8, 53] {
        let value = F::from_repr(raw);
        let public = vec![vec![value]];
        let proof = prover
            .prove(&public, vec![RowMajorMatrix::new(vec![value; 2], 1)])
            .unwrap();
        let native_bytes = authority.encode_native_proof(&proof, &public).unwrap();
        let native_statement = authority.encode_statement(&public).unwrap();
        let identity = authority.canonical_verifier_bytes();
        let checked = authority
            .decode_and_verify(
                identity,
                ExpectedVerifierArtifact::from_trusted_bytes(identity),
                &native_bytes,
                CanonicalBinaryStatement::new(&native_statement, 1),
            )
            .unwrap();
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
    let (foreign_prover, foreign) = BinaryNativeAuthority::<F, E, _>::setup_with_artifact_limits(
        vec![ConstantAir],
        vec![1],
        spec(vec![7, 19, 13, 0]),
        limits,
    )
    .unwrap();
    let value = F::from_repr(137);
    let public = vec![vec![value]];
    let proof = foreign_prover
        .prove(&public, vec![RowMajorMatrix::new(vec![value; 2], 1)])
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

struct PreprocessedPublicAir {
    offset: u8,
}
impl BaseAir<F> for PreprocessedPublicAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn preprocessed_width(&self) -> usize {
        1
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        Some(RowMajorMatrix::new(
            vec![
                F::from_repr(7 ^ self.offset),
                F::from_repr(11 ^ self.offset),
            ],
            1,
        ))
    }
}
impl<AB: AirBuilder<F = F>> Air<AB> for PreprocessedPublicAir {
    fn eval(&self, b: &mut AB) {
        let public: AB::Expr = b.public_values()[0].into();
        b.assert_eq(
            b.main().current_slice()[0],
            public + b.preprocessed().current_slice()[0],
        );
    }
}

#[test]
fn prepared_native_authority_binds_captured_preprocessing_and_both_hashes() {
    let limits = ArtifactLimits::default();
    let mut native = spec(vec![7, 19, 13]);
    native.preprocessed = Some(BinaryNativePcsParameters {
        hash: ByteHash::Keccak256,
        cap_height: 1,
        ..native.main
    });
    let make = |offset| {
        BinaryNativeAuthority::<F, E, _>::setup_with_artifact_limits(
            vec![PreprocessedPublicAir { offset }],
            vec![1],
            native.clone(),
            limits,
        )
        .unwrap()
    };
    let (prover, authority) = make(0);
    let layer = PreparedBinaryMultiStarkLayer::<F, E, C, 4>::from_native_authority(
        &authority,
        config(&limits),
        ProveNextLayerParams::default(),
    )
    .unwrap();
    let public = vec![vec![F::from_repr(137)]];
    let prove =
        |prover: &p3_recursion::artifact::BinaryNativeProver<F, E, PreprocessedPublicAir>,
         offset| {
            prover
                .prove(
                    &public,
                    vec![RowMajorMatrix::new(
                        [7u8, 11]
                            .into_iter()
                            .map(|raw| public[0][0] + F::from_repr(raw ^ offset))
                            .collect(),
                        1,
                    )],
                )
                .unwrap()
        };
    let proof = prove(&prover, 0);
    let token = authority.verify_native(&proof, &public).unwrap();
    let output = layer.prove_verified(&token).unwrap();
    let statement = layer.statement_layout().pack::<BabyBear>(&public).unwrap();
    layer.verifier().verify(&output.0, &statement).unwrap();
    let verifier_bytes = layer.verifier().encode_verifier_artifact(limits).unwrap();
    let proof_bytes = layer
        .verifier()
        .encode_proof_artifact(&output.0, limits)
        .unwrap();
    PortableVerifier::decode(
        &verifier_bytes,
        ExpectedVerifierArtifact::from_trusted_bytes(&verifier_bytes),
        limits,
    )
    .unwrap()
    .verify_encoded(
        &proof_bytes,
        CanonicalStatement::new(&canonical(&statement), 8),
    )
    .unwrap();
    let (foreign_prover, foreign) = make(1);
    let token = foreign
        .verify_native(&prove(&foreign_prover, 1), &public)
        .unwrap();
    assert!(matches!(layer.prove_verified(&token),
        Err(p3_recursion::VerificationError::InvalidProofShape(message))
            if message == "binary verified input belongs to another native authority"));
}
