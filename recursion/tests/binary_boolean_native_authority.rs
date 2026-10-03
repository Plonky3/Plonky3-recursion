//! Checked native Boolean trace owners retain the ring and ordinary PCS geometry.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::{BinaryField64, BinaryField128};
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsParams};
use p3_circuit::ops::ByteHash;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::artifact::{
    ArtifactError, BinaryNativeBooleanTraceAuthority, BinaryNativePcsParameters,
    BinaryNativeVerifierSpec, CanonicalBinaryStatement, ExpectedVerifierArtifact,
};
use p3_recursion::pcs::binary::RecursiveBinaryTowerField;
use p3_recursion::verifier::VerifierLimits;

fn frontier_count<F, E, M, MX>(proof: &p3_binary_pcs::BinaryPcsProof<F, E, M, MX>) -> usize
where
    F: p3_field::Field,
    E: p3_field::Field,
    M: p3_commit::Mmcs<F, MultiProof = p3_merkle_tree::PrunedMerklePaths<u8, 32>>,
    MX: p3_commit::Mmcs<E, MultiProof = p3_merkle_tree::PrunedMerklePaths<u8, 32>>,
{
    proof.base_multi_proof.sibling_hashes.len()
        + proof
            .rounds
            .iter()
            .map(|round| round.multi_proof.sibling_hashes.len())
            .sum::<usize>()
}

struct ConstantAir;
impl<F> BaseAir<F> for ConstantAir {
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
impl<AB: AirBuilder> Air<AB> for ConstantAir {
    fn eval(&self, b: &mut AB) {
        b.assert_eq(b.main().current_slice()[0], b.public_values()[0]);
    }
}

macro_rules! check_owner {
    ($e:ty) => {{
        type E = $e;
        for hash in [ByteHash::Keccak256, ByteHash::Blake3] {
            let (prover, authority) = BinaryNativeBooleanTraceAuthority::<E, _>::setup(
                vec![ConstantAir],
                vec![E::RAW_BITS.ilog2() as usize + 1],
                BinaryNativeVerifierSpec {
                    main: BinaryNativePcsParameters {
                            config: BinaryPcsConfig::try_new::<E, E>(1, BinaryPcsParams {
                                log_inv_rate: 5, pow_bits: 0, security_level: 8,
                            }).unwrap(),
                            hash, cap_height: 0, max_query_draws: 64,
                        },
                    preprocessed: None, transcript_hash: hash,
                    initial_bytes: vec![0, 19, 255], sumcheck_pow_bits: 0,
                    max_tau_draws: 8, security_bits: 4,
                },
                &VerifierLimits::default(),
            ).unwrap();
            for value in [E::ZERO, E::ONE] {
                let public = vec![vec![value]];
                let proof = prover.prove(&public, vec![RowMajorMatrix::new(
                    vec![value; E::RAW_BITS * 2], 1,
                )]).unwrap();
                let encoded = authority.encode_native_proof(&proof, &public).unwrap();
                let statement = authority.encode_statement(&public).unwrap();
                let identity = authority.canonical_verifier_bytes();
                let anchor = ExpectedVerifierArtifact::from_trusted_bytes(identity);
                let expected = CanonicalBinaryStatement::new(&statement, 1);
                let token = authority.decode_and_verify(identity, anchor, &encoded, expected).unwrap();
                assert_eq!(token.public_values(), public);
                token.native_input().private_values::<p3_baby_bear::BabyBear>(
                    &authority.recursive_verifier().input_shape(),
                ).unwrap();
                assert_eq!(encoded, authority.encode_native_proof(&proof, &public).unwrap());
                for len in 0..encoded.len() {
                    assert!(authority.decode_and_verify(identity, anchor, &encoded[..len], expected).is_err());
                    if len >= 17 {
                        let mut short = encoded[..len].to_vec();
                        short[13..17].copy_from_slice(&((len - 17) as u32).to_le_bytes());
                        assert!(authority.decode_and_verify(identity, anchor, &short, expected).is_err());
                    }
                }
                assert_eq!(authority.decode_and_verify(&[], anchor, &[], expected).err(),
                    Some(ArtifactError::TrustedArtifactMismatch));
                let mut wrong = statement.clone();
                wrong[0] ^= 1;
                assert_eq!(authority.decode_and_verify(identity, anchor, &encoded,
                    CanonicalBinaryStatement::new(&wrong, 1)).err(),
                    Some(ArtifactError::VerificationRejected));

                let reduction = &proof.opening.opening.reduction;
                let round_offset = 19 + E::RAW_BITS / 8
                    + proof.commitment.roots().len() * 32
                    + E::RAW_BITS / 8 * (1 + proof.sumcheck.round_polys.iter().map(Vec::len).sum::<usize>()
                        + proof.sumcheck.pow_witnesses.len() + proof.opening.values.len()
                        + reduction.claims.iter().map(|c| c.tensor.rows().len()
                            + c.successor.as_ref().map_or(0, |s| s.carry.rows().len() + s.last.rows().len()))
                            .sum::<usize>());
                let rounds = reduction.sumcheck.polynomial_evaluations.len();
                assert_eq!(rounds, 1);
                let mut oversized = encoded.clone();
                oversized[round_offset..round_offset + 4].copy_from_slice(&u32::MAX.to_le_bytes());
                assert!(matches!(authority.decode_and_verify(identity, anchor, &oversized, expected),
                    Err(ArtifactError::DecodeLimitExceeded { component: "binary ring rounds", .. })));
                // Zero rounds fit the trusted prefix bound, but the exact routed
                // point still requires one round. Complete native replay rejects it.
                let mut wrong_rounds = encoded.clone();
                wrong_rounds[round_offset..round_offset + 4].copy_from_slice(&0u32.to_le_bytes());
                wrong_rounds.drain(round_offset + 4..round_offset + 4 + E::RAW_BITS / 4);
                let len = (wrong_rounds.len() - 17) as u32;
                wrong_rounds[13..17].copy_from_slice(&len.to_le_bytes());
                assert_eq!(authority.decode_and_verify(identity, anchor, &wrong_rounds, expected).err(),
                    Some(ArtifactError::VerificationRejected));
                let mut changed = proof;
                changed.opening.values[0] += E::ONE;
                assert!(authority.verify_native(&changed, &public).is_err());
            }
        }
    }};
}

#[test]
fn checked_boolean_trace_owners_decode_both_fields_and_hashes() {
    check_owner!(BinaryField64);
    check_owner!(BinaryField128);
}

#[test]
fn ordinary_trace_authority_rejects_grouped_proof_bytes_before_decoding() {
    use p3_recursion::artifact::{
        BinaryNativeGroupedBooleanTraceAuthority, BinaryNativeGroupedPcsParameters,
        BinaryNativeGroupedVerifierSpec,
    };
    use p3_recursion::pcs::binary::BinaryCodewordGrouping;
    type E = BinaryField64;
    let main = BinaryNativePcsParameters {
        config: BinaryPcsConfig::try_new::<E, E>(
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
        max_query_draws: 64,
    };
    let spec = BinaryNativeVerifierSpec {
        main,
        preprocessed: None,
        transcript_hash: ByteHash::Blake3,
        initial_bytes: vec![0, 19, 255],
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    };
    let (_, ordinary) = BinaryNativeBooleanTraceAuthority::<E, _>::setup(
        vec![ConstantAir],
        vec![7],
        spec.clone(),
        &VerifierLimits::default(),
    )
    .unwrap();
    let (prover, grouped) = BinaryNativeGroupedBooleanTraceAuthority::<E, _>::setup(
        vec![ConstantAir],
        vec![7],
        BinaryNativeGroupedVerifierSpec {
            main: BinaryNativeGroupedPcsParameters {
                pcs: main,
                base_grouping: BinaryCodewordGrouping::Folding,
                round_grouping: BinaryCodewordGrouping::Folding,
            },
            preprocessed: None,
            transcript_hash: spec.transcript_hash,
            initial_bytes: spec.initial_bytes,
            sumcheck_pow_bits: 0,
            max_tau_draws: 8,
            security_bits: 4,
        },
        &VerifierLimits::default(),
    )
    .unwrap();
    assert_ne!(
        ordinary.canonical_verifier_bytes(),
        grouped.canonical_verifier_bytes()
    );
    let public = vec![vec![E::ONE]];
    let proof = prover
        .prove(&public, vec![RowMajorMatrix::new(vec![E::ONE; 128], 1)])
        .unwrap();
    let bytes = grouped.encode_native_proof(&proof, &public).unwrap();
    let statement = ordinary.encode_statement(&public).unwrap();
    let identity = ordinary.canonical_verifier_bytes();
    let suite = u16::from_le_bytes(bytes[11..13].try_into().unwrap());
    assert_eq!(
        ordinary
            .decode_and_verify(
                identity,
                ExpectedVerifierArtifact::from_trusted_bytes(identity),
                &bytes,
                CanonicalBinaryStatement::new(&statement, 1)
            )
            .err(),
        Some(ArtifactError::UnsupportedSuite(suite))
    );
}

struct PreprocessedAir {
    flip: bool,
}
impl BaseAir<BinaryField64> for PreprocessedAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn preprocessed_width(&self) -> usize {
        1
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<BinaryField64>> {
        Some(RowMajorMatrix::new(
            (0..128)
                .map(|row| BinaryField64::from_bool((row % 2 == 1) ^ self.flip))
                .collect(),
            1,
        ))
    }
}
impl<AB: AirBuilder<F = BinaryField64>> Air<AB> for PreprocessedAir {
    fn eval(&self, b: &mut AB) {
        let public: AB::Expr = b.public_values()[0].into();
        b.assert_eq(b.main().current_slice()[0], public.clone());
        b.assert_eq(
            b.main().current_slice()[1],
            b.preprocessed().current_slice()[0],
        );
        let next = b.main().next_slice()[0];
        b.when_transition().assert_eq(next, public);
        let parity: AB::Expr = b.main().current_slice()[1].into();
        let next_parity = b.preprocessed().next_slice()[0];
        b.when_transition()
            .assert_eq(next_parity, AB::Expr::ONE + parity);
    }
}

#[test]
fn checked_trace_codec_closes_successors_preprocessing_and_shared_frontier_budget() {
    use p3_recursion::artifact::ArtifactLimits;
    type E = BinaryField64;
    let make_pcs = |variables, hash, cap_height| BinaryNativePcsParameters {
        config: BinaryPcsConfig::try_new::<E, E>(
            variables,
            BinaryPcsParams {
                log_inv_rate: 5,
                pow_bits: 0,
                security_level: 8,
            },
        )
        .unwrap(),
        hash,
        cap_height,
        max_query_draws: 64,
    };
    let spec = BinaryNativeVerifierSpec {
        main: make_pcs(2, ByteHash::Keccak256, 0),
        preprocessed: Some(make_pcs(1, ByteHash::Blake3, 1)),
        transcript_hash: ByteHash::Blake3,
        initial_bytes: vec![11, 3, 19],
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    };
    let make = |flip, limits| {
        BinaryNativeBooleanTraceAuthority::<E, _>::setup_with_artifact_limits(
            vec![PreprocessedAir { flip }],
            vec![7],
            spec.clone(),
            limits,
        )
        .unwrap()
    };
    let (prover, authority) = make(false, ArtifactLimits::default());
    let public = vec![vec![E::ONE]];
    let trace = RowMajorMatrix::new(
        (0..128)
            .flat_map(|row| [E::ONE, E::from_bool(row % 2 == 1)])
            .collect(),
        2,
    );
    let proof = prover.prove(&public, vec![trace]).unwrap();
    let main = &proof.opening.opening;
    let pp = &proof.preprocessed_opening.as_ref().unwrap().opening;
    assert!(main.reduction.claims.iter().any(|c| c.successor.is_some()));
    assert!(pp.reduction.claims.iter().any(|c| c.successor.is_some()));
    let main_counts = frontier_count(&main.opening);
    let pp_counts = frontier_count(&pp.opening);
    assert!(main_counts > 0 && pp_counts > 0);
    let encoded = authority.encode_native_proof(&proof, &public).unwrap();
    let statement = authority.encode_statement(&public).unwrap();
    let decode =
        |a: &p3_recursion::artifact::BinaryNativeBooleanTraceAuthority<E, PreprocessedAir>| {
            let identity = a.canonical_verifier_bytes();
            a.decode_and_verify(
                identity,
                ExpectedVerifierArtifact::from_trusted_bytes(identity),
                &encoded,
                CanonicalBinaryStatement::new(&statement, 1),
            )
        };
    let token = decode(&authority).unwrap();
    token
        .native_input()
        .private_values::<p3_baby_bear::BabyBear>(&authority.recursive_verifier().input_shape())
        .unwrap();
    let limit = main_counts + pp_counts - 1;
    assert!(main_counts <= limit && pp_counts <= limit);
    let (_, bounded) = make(
        false,
        ArtifactLimits {
            verifier: VerifierLimits {
                max_compressed_frontier_hashes: limit,
                ..VerifierLimits::default()
            },
            ..ArtifactLimits::default()
        },
    );
    assert!(matches!(
        decode(&bounded),
        Err(ArtifactError::DecodeLimitExceeded {
            component: "binary compressed frontier",
            ..
        })
    ));
    let (_, other) = make(true, ArtifactLimits::default());
    assert_ne!(
        authority.canonical_verifier_bytes(),
        other.canonical_verifier_bytes()
    );
    assert!(other.verify_native(&proof, &public).is_err());
    let mut malformed = proof;
    malformed
        .preprocessed_opening
        .as_mut()
        .unwrap()
        .opening
        .reduction
        .claims[0]
        .successor = None;
    assert!(authority.encode_native_proof(&malformed, &public).is_err());
}
