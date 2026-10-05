//! Native binary imports use retained geometry and an independent raw statement.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::{BinaryField8, BinaryField64, BinaryField128, TowerLevel};
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsParams};
use p3_bus::{BusActivation, BusDirection, BusInteractionBuilder, BusName};
use p3_circuit::ops::ByteHash;
use p3_lookup::IndexedLookupBuilder;
use p3_lookup::indexed::TraceWindow;
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::artifact::{
    ArtifactError, ArtifactLimits, BinaryNativeAuthority, BinaryNativePcsParameters,
    BinaryNativeVerifierSpec, CanonicalBinaryStatement, ExpectedVerifierArtifact,
};
use p3_recursion::pcs::binary::RecursiveBinaryTowerField;
use p3_recursion::verifier::VerifierLimits;

struct ConstantAir;
impl<F> BaseAir<F> for ConstantAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        1
    }
}
impl<AB: AirBuilder> Air<AB> for ConstantAir {
    fn eval(&self, b: &mut AB) {
        b.assert_eq(b.main().current_slice()[0], b.public_values()[0]);
    }
}

macro_rules! check {
    ($f:ty, $e:ty, $security:expr, $target:expr) => {{
        type F = $f;
        type E = $e;
        for hash in [ByteHash::Keccak256, ByteHash::Blake3] {
            let main = BinaryNativePcsParameters {
                config: BinaryPcsConfig::try_new::<F, E>(
                    1,
                    BinaryPcsParams {
                        log_inv_rate: 2,
                        pow_bits: 0,
                        security_level: $security,
                    },
                )
                .unwrap(),
                hash,
                cap_height: 0,
                max_query_draws: 128,
            };
            let (prover, authority) = BinaryNativeAuthority::<F, E, _>::setup(
                vec![ConstantAir],
                vec![1],
                BinaryNativeVerifierSpec {
                    main,
                    preprocessed: None,
                    transcript_hash: hash,
                    initial_bytes: vec![0, 19, 255],
                    sumcheck_pow_bits: 0,
                    max_tau_draws: 8,
                    security_bits: $target,
                },
                &VerifierLimits::default(),
            )
            .unwrap();
            let identity = authority.canonical_verifier_bytes();
            let anchor = ExpectedVerifierArtifact::from_trusted_bytes(identity);
            for raw in [0xabu128, 0x47] {
                let value =
                    F::from_le_byte_iter(raw.to_le_bytes().into_iter().take(F::RAW_BITS / 8));
                let public = vec![vec![value]];
                let proof = prover
                    .prove(&public, vec![RowMajorMatrix::new(vec![value; 2], 1)])
                    .unwrap();
                let encoded = authority.encode_native_proof(&proof, &public).unwrap();
                let statement = authority.encode_statement(&public).unwrap();
                assert_eq!(statement, raw.to_le_bytes()[..F::RAW_BITS / 8]);
                let expected = CanonicalBinaryStatement::new(&statement, 1);
                let verified = authority
                    .decode_and_verify(identity, anchor, &encoded, expected)
                    .unwrap();
                assert_eq!(verified.public_values(), public);
                assert_eq!(verified.canonical_verifier_bytes(), identity);
                let mut wrong_statement = statement.clone();
                wrong_statement[0] ^= 1;
                assert_eq!(
                    authority
                        .decode_and_verify(
                            identity,
                            anchor,
                            &encoded,
                            CanonicalBinaryStatement::new(&wrong_statement, 1)
                        )
                        .err(),
                    Some(ArtifactError::VerificationRejected)
                );
                assert!(
                    authority
                        .decode_and_verify(
                            identity,
                            anchor,
                            &encoded,
                            CanonicalBinaryStatement::new(&statement, 2)
                        )
                        .is_err()
                );
                let mut foreign = identity.to_vec();
                foreign[17] ^= 1;
                assert_eq!(
                    authority
                        .decode_and_verify(&foreign, anchor, &[], expected)
                        .err(),
                    Some(ArtifactError::TrustedArtifactMismatch)
                );
                assert_eq!(
                    authority
                        .decode_and_verify(
                            &foreign,
                            ExpectedVerifierArtifact::from_trusted_bytes(&foreign),
                            &[],
                            expected
                        )
                        .err(),
                    Some(ArtifactError::TrustedArtifactMismatch)
                );
                for len in 0..encoded.len() {
                    assert!(
                        authority
                            .decode_and_verify(identity, anchor, &encoded[..len], expected)
                        .is_err()
                    );
                    if len >= 17 {
                        let mut inner_truncation = encoded[..len].to_vec();
                        inner_truncation[13..17].copy_from_slice(&((len - 17) as u32).to_le_bytes());
                        assert!(authority.decode_and_verify(identity, anchor, &inner_truncation, expected).is_err());
                    }
                }
                assert!(proof.opening.rounds.is_empty());
                let frontier_offset = 19 + F::RAW_BITS / 8 + proof.commitment.roots().len() * 32
                    + E::RAW_BITS / 8 * (1 + proof.sumcheck.round_polys.iter().map(Vec::len).sum::<usize>())
                    + F::RAW_BITS / 8 * proof.sumcheck.pow_witnesses.len()
                    + E::RAW_BITS / 8 * (2 * proof.opening.sumcheck.polynomial_evaluations.len()
                        + proof.opening.evals.iter().map(|e| e.current().len() + e.next().len()).sum::<usize>())
                    + F::RAW_BITS / 8 * proof.opening.base_opened_values.len();
                let mut oversized = encoded.clone();
                oversized[frontier_offset..frontier_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
                assert!(matches!(authority.decode_and_verify(identity, anchor, &oversized, expected),
                    Err(ArtifactError::DecodeLimitExceeded { component: "binary compressed frontier", .. })));
                let mut trailing = encoded.clone();
                trailing.push(0);
                assert!(
                    authority
                        .decode_and_verify(identity, anchor, &trailing, expected)
                        .is_err()
                );
                let mut changed = encoded.clone();
                *changed.last_mut().unwrap() ^= 1;
                assert!(
                    authority
                        .decode_and_verify(identity, anchor, &changed, expected)
                        .is_err()
                );
            }
        }
    }};
}

#[test]
fn bounded_native_artifacts_roundtrip_narrow_and_wide_fields() {
    check!(BinaryField8, BinaryField64, 24, 16);
    check!(BinaryField128, BinaryField128, 8, 4);
}

struct CoupledAir {
    provider: bool,
}
impl BaseAir<BinaryField8> for CoupledAir {
    fn width(&self) -> usize {
        3
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn preprocessed_width(&self) -> usize {
        usize::from(self.provider)
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<BinaryField8>> {
        self.provider
            .then(|| RowMajorMatrix::new((7u8..15).map(BinaryField8::from_repr).collect(), 1))
    }
}
impl<AB: AirBuilder<F = BinaryField8> + IndexedLookupBuilder + BusInteractionBuilder> Air<AB>
    for CoupledAir
{
    fn eval(&self, b: &mut AB) {
        b.assert_eq(b.main().current_slice()[2], b.public_values()[0]);
        let (payload, direction) = if self.provider {
            b.push_indexed_table("payload", TraceWindow::Preprocessed, [0]);
            (b.preprocessed().current_slice()[0], BusDirection::Pull)
        } else {
            b.push_indexed_read("payload", 0, [1]);
            (b.main().current_slice()[1], BusDirection::Push)
        };
        b.push_bus_interaction(
            BusName::new("payload"),
            direction,
            [payload],
            BusActivation::Always,
        );
    }
}

#[test]
fn native_artifact_authenticates_combined_bus_indexed_and_preprocessed_parts() {
    type F = BinaryField8;
    type E = BinaryField64;
    let pcs = |n, hash, cap_height| BinaryNativePcsParameters {
        config: BinaryPcsConfig::try_new::<F, E>(
            n,
            BinaryPcsParams {
                log_inv_rate: if n == 3 { 4 } else { 2 },
                pow_bits: 0,
                security_level: 24,
            },
        )
        .unwrap()
        .try_with_folding(2)
        .unwrap(),
        hash,
        cap_height,
        max_query_draws: 512,
    };
    let spec = BinaryNativeVerifierSpec {
        main: pcs(6, ByteHash::Keccak256, 1),
        preprocessed: Some(pcs(3, ByteHash::Blake3, 1)),
        transcript_hash: ByteHash::Blake3,
        initial_bytes: vec![7, 19, 13],
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 16,
    };
    let (prover, authority) = BinaryNativeAuthority::<F, E, _>::setup(
        vec![
            CoupledAir { provider: false },
            CoupledAir { provider: true },
        ],
        vec![3, 3],
        spec.clone(),
        &VerifierLimits::default(),
    )
    .unwrap();
    let public = vec![vec![F::from_repr(0x53)], vec![F::from_repr(0x97)]];
    let reader = (0u8..8)
        .flat_map(|i| [F::from_repr(i), F::from_repr(i + 7), public[0][0]])
        .collect();
    let provider = (0u8..8)
        .flat_map(|i| [F::from_repr(i), F::from_repr(27), public[1][0]])
        .collect();
    let proof = prover
        .prove(
            &public,
            vec![
                RowMajorMatrix::new(reader, 3),
                RowMajorMatrix::new(provider, 3),
            ],
        )
        .unwrap();
    assert!(proof.bus.is_some() && proof.indexed.is_some() && proof.preprocessed_opening.is_some());
    let count =
        |p: &p3_multi_stark::config::PcsProof<p3_recursion::artifact::BinaryNativeConfig<F, E>>| {
            p.base_multi_proof.sibling_hashes.len()
                + p.rounds
                    .iter()
                    .map(|r| r.multi_proof.sibling_hashes.len())
                    .sum::<usize>()
        };
    let (main_frontiers, pp_frontiers) = (
        count(&proof.opening),
        count(proof.preprocessed_opening.as_ref().unwrap()),
    );
    assert!(main_frontiers > 0 && pp_frontiers > 0);
    let limits = VerifierLimits {
        max_compressed_frontier_hashes: main_frontiers + pp_frontiers - 1,
        ..VerifierLimits::default()
    };
    let (_, bounded) = BinaryNativeAuthority::<F, E, _>::setup(
        vec![
            CoupledAir { provider: false },
            CoupledAir { provider: true },
        ],
        vec![3, 3],
        spec,
        &limits,
    )
    .unwrap();
    assert!(matches!(
        bounded.verify_native(&proof, &public),
        Err(
            p3_recursion::verifier::VerificationError::ResourceLimitExceeded {
                component: "compressed frontier hashes",
                ..
            }
        )
    ));
    let identity = authority.canonical_verifier_bytes();
    let statement = authority.encode_statement(&public).unwrap();
    let expected = CanonicalBinaryStatement::new(&statement, 2);
    let encoded = authority.encode_native_proof(&proof, &public).unwrap();
    let anchor = ExpectedVerifierArtifact::from_trusted_bytes(identity);
    assert_eq!(
        authority
            .decode_and_verify(identity, anchor, &encoded, expected)
            .unwrap()
            .public_values(),
        public
    );
    let mut changed = encoded;
    // Revision, two raw public values and two main cap roots precede bus roots.
    changed[17 + 2 + 2 + 64] ^= 1;
    assert!(
        authority
            .decode_and_verify(identity, anchor, &changed, expected)
            .is_err()
    );
}

#[test]
fn native_decode_charges_independent_and_attached_statements_together() {
    type F = BinaryField8;
    type E = BinaryField64;
    let make = |limits| {
        BinaryNativeAuthority::<F, E, _>::setup_with_artifact_limits(
            vec![ConstantAir],
            vec![1],
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
                initial_bytes: vec![0, 19, 255],
                sumcheck_pow_bits: 0,
                max_tau_draws: 8,
                security_bits: 16,
            },
            limits,
        )
        .unwrap()
    };
    let (prover, authority) = make(ArtifactLimits::default());
    let value = F::from_repr(137);
    let public = vec![vec![value]];
    let proof = prover
        .prove(&public, vec![RowMajorMatrix::new(vec![value; 2], 1)])
        .unwrap();
    let bytes = authority.encode_native_proof(&proof, &public).unwrap();
    let statement = authority.encode_statement(&public).unwrap();
    let identity = authority.canonical_verifier_bytes();
    for (limits, component) in [
        (
            ArtifactLimits {
                max_decoded_bytes: 128,
                ..ArtifactLimits::default()
            },
            "decoded allocation bytes",
        ),
        (
            ArtifactLimits {
                max_container_entries: 7,
                ..ArtifactLimits::default()
            },
            "container entries",
        ),
        (
            ArtifactLimits {
                max_proof_bytes: 16,
                ..ArtifactLimits::default()
            },
            "artifact bytes",
        ),
    ] {
        let (_, tight) = make(limits);
        assert_eq!(tight.canonical_verifier_bytes(), identity);
        assert!(matches!(tight.decode_and_verify(identity,
            ExpectedVerifierArtifact::from_trusted_bytes(identity), &bytes,
            CanonicalBinaryStatement::new(&statement, 1)),
            Err(ArtifactError::DecodeLimitExceeded { component: actual, .. }) if actual == component));
    }
}

struct LargeProgramAir;
impl BaseAir<BinaryField128> for LargeProgramAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        1
    }
}
impl<AB: AirBuilder<F = BinaryField128>> Air<AB> for LargeProgramAir {
    fn eval(&self, b: &mut AB) {
        let mut expression: AB::Expr = b.main().current_slice()[0].into();
        let mut constant = BinaryField128::from_repr(0);
        for raw in 1..1024u128 {
            let term = BinaryField128::from_repr(raw << 41);
            expression += term;
            constant += term;
        }
        let public: AB::Expr = b.public_values()[0].into();
        b.assert_eq(expression, public + constant);
    }
}

#[test]
fn native_decode_accounts_for_retained_large_air_program() {
    type F = BinaryField128;
    let spec = BinaryNativeVerifierSpec {
        main: BinaryNativePcsParameters {
            config: BinaryPcsConfig::try_new::<F, F>(
                1,
                BinaryPcsParams {
                    log_inv_rate: 2,
                    pow_bits: 0,
                    security_level: 8,
                },
            )
            .unwrap(),
            hash: ByteHash::Blake3,
            cap_height: 0,
            max_query_draws: 128,
        },
        preprocessed: None,
        transcript_hash: ByteHash::Blake3,
        initial_bytes: vec![],
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    };
    let (prover, authority) = BinaryNativeAuthority::<F, F, _>::setup(
        vec![LargeProgramAir],
        vec![1],
        spec.clone(),
        &VerifierLimits::default(),
    )
    .unwrap();
    let usage = authority.recursive_verifier().input_resource_usage();
    assert!(usage.metadata_entries > usage.scalar_elements);
    let public = vec![vec![F::from_repr(137)]];
    let proof = prover
        .prove(&public, vec![RowMajorMatrix::new(vec![public[0][0]; 2], 1)])
        .unwrap();
    let bytes = authority.encode_native_proof(&proof, &public).unwrap();
    let statement = authority.encode_statement(&public).unwrap();
    let (_, tight) = BinaryNativeAuthority::<F, F, _>::setup_with_artifact_limits(
        vec![LargeProgramAir],
        vec![1],
        spec,
        ArtifactLimits {
            // Enough for both statements and the conservative scalar copy;
            // the retained AIR program must be charged separately.
            max_decoded_bytes: usage.scalar_elements * 16 + 4096,
            ..ArtifactLimits::default()
        },
    )
    .unwrap();
    let identity = authority.canonical_verifier_bytes();
    assert_eq!(tight.canonical_verifier_bytes(), identity);
    assert!(matches!(
        tight.decode_and_verify(
            identity,
            ExpectedVerifierArtifact::from_trusted_bytes(identity),
            &bytes,
            CanonicalBinaryStatement::new(&statement, 1)
        ),
        Err(ArtifactError::DecodeLimitExceeded {
            component: "decoded allocation bytes",
            ..
        })
    ));
}
