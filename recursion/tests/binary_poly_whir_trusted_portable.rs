//! Checked binary tokens remain bound through portable prime recursion layers.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_binary_field::Poly64;
use p3_circuit::ops::ByteHash;
use p3_field::{PrimeCharacteristicRing, PrimeField64};
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::artifact::{
    ArtifactLimits, BinaryNativePolyWhirAuthority, BinaryNativePolyWhirPcsParameters,
    BinaryNativeVerifierSpec, CanonicalBinaryStatement, CanonicalStatement,
    ExpectedVerifierArtifact, PortableArtifactExport, PortableArtifactImport, PortableVerifier,
    TypedArtifactVerifier,
};
use p3_recursion::backend::fri::FriRecursionBackend;
use p3_recursion::builtin_config::{
    BabyBearD4Poseidon2BinaryConfig, FriConfigV1, SuiteIdV1, baby_bear_d4_poseidon2_binary,
};
use p3_recursion::prepared::PreparedBinaryPolyWhirMultiStarkLayer;
use p3_recursion::{BatchOnly, Poseidon2Config, ProveNextLayerParams, TrustedPreparedLayer};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

type F = Poly64;

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
) -> BinaryNativeVerifierSpec<BinaryNativePolyWhirPcsParameters> {
    BinaryNativeVerifierSpec {
        main: BinaryNativePolyWhirPcsParameters::new(
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

fn checked_poly_whir_chain(hash: ByteHash) {
    let limits = ArtifactLimits::default();
    let native_spec = spec(vec![7, 19, 13], hash);
    let (prover, authority) = BinaryNativePolyWhirAuthority::<_>::setup_with_artifact_limits(
        vec![ConstantAir],
        vec![3],
        native_spec,
        limits,
    )
    .unwrap();
    let output_config = config(&limits);
    let params = ProveNextLayerParams::default();
    let layer = PreparedBinaryPolyWhirMultiStarkLayer::<C, 4>::from_native_authority(
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
    for raw in [0u64, 0xfedc_ba98_7654_3210] {
        let value = F::new(raw);
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
            (0..4)
                .map(|i| BabyBear::from_u16((raw >> (16 * i)) as u16))
                .collect::<Vec<_>>()
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
    let (foreign_prover, foreign) = BinaryNativePolyWhirAuthority::<_>::setup_with_artifact_limits(
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
            .verify_encoded(bytes, CanonicalStatement::new(&canonical(statement), 4))
            .unwrap();
    }
    assert!(
        portable
            .verify_encoded(
                &encoded_outputs[0].0,
                CanonicalStatement::new(&canonical(&encoded_outputs[1].1), 4)
            )
            .is_err()
    );
    let (bytes, statement) = &encoded_outputs[0];
    let child = imported
        .import_proof(bytes, CanonicalStatement::new(&canonical(statement), 4))
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
            CanonicalStatement::new(&canonical(statement), 4),
        )
        .unwrap();
    assert!(
        portable
            .verify_encoded(
                &outer_bytes,
                CanonicalStatement::new(&canonical(&encoded_outputs[1].1), 4)
            )
            .is_err()
    );
}

#[test]
fn checked_poly_whir_native_bytes_survive_two_portable_recursion_layers() {
    checked_poly_whir_chain(ByteHash::Blake3);
}

#[test]
fn polynomial_statement_layout_encodes_all_four_limbs_in_air_order() {
    use p3_recursion::VerifierLimits;
    use p3_recursion::prepared::BinaryPolyStatementLayout;
    let layout =
        BinaryPolyStatementLayout::with_limits(&[2, 0, 1], &VerifierLimits::default()).unwrap();
    let values = [
        F::new(0x0123_4567_89ab_cdef),
        F::new(u64::MAX),
        F::new(0x8765_4321_dead_beef),
    ];
    let public = vec![vec![values[0], values[1]], vec![], vec![values[2]]];
    let packed = layout.pack::<BabyBear>(&public).unwrap();
    assert_eq!(layout.field_bits(), 64);
    assert_eq!(layout.public_value_counts(), &[2, 0, 1]);
    assert_eq!(layout.schema().base_len(), 12);
    assert!(
        layout
            .schema()
            .fields()
            .iter()
            .all(|field| *field == p3_circuit::StatementField::Base)
    );
    let expected: Vec<_> = [0x0123_4567_89ab_cdefu64, u64::MAX, 0x8765_4321_dead_beef]
        .into_iter()
        .flat_map(|raw| (0..4).map(move |i| BabyBear::from_u16((raw >> (16 * i)) as u16)))
        .collect();
    assert_eq!(packed, expected);
    let mut wrong = public.clone();
    wrong[1].push(values[0]);
    assert!(layout.pack::<BabyBear>(&wrong).is_err());
    assert!(layout.pack::<BabyBear>(&public[..2]).is_err());
}

#[test]
fn polynomial_statement_geometry_checks_limits_before_allocation() {
    use p3_recursion::prepared::BinaryPolyStatementLayout;
    use p3_recursion::{VerificationError, VerifierLimits};
    let defaults = VerifierLimits::default();
    for limits in [
        VerifierLimits {
            max_instances: 2,
            ..defaults
        },
        VerifierLimits {
            max_total_scalar_elements: 11,
            ..defaults
        },
        VerifierLimits {
            max_metadata_entries: 14,
            ..defaults
        },
        VerifierLimits {
            max_matrix_width: 12,
            ..defaults
        },
    ] {
        assert!(matches!(
            BinaryPolyStatementLayout::with_limits(&[2, 0, 1], &limits),
            Err(VerificationError::ResourceLimitExceeded { .. })
        ));
    }
    let exact = VerifierLimits {
        max_instances: 3,
        max_total_scalar_elements: 12,
        max_metadata_entries: 15,
        max_matrix_width: 13,
        ..defaults
    };
    assert!(BinaryPolyStatementLayout::with_limits(&[2, 0, 1], &exact).is_ok());
    let wide = VerifierLimits {
        max_total_scalar_elements: usize::MAX,
        max_metadata_entries: usize::MAX,
        ..defaults
    };
    for counts in [vec![usize::MAX, 1], vec![usize::MAX / 4 + 1]] {
        assert!(matches!(
            BinaryPolyStatementLayout::with_limits(&counts, &wide),
            Err(VerificationError::ResourceArithmeticOverflow { .. })
        ));
    }
    let empty = BinaryPolyStatementLayout::with_limits(&[0, 0], &defaults).unwrap();
    assert!(
        empty
            .pack::<BabyBear>(&[vec![], vec![]])
            .unwrap()
            .is_empty()
    );
}
