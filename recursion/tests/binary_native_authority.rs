//! A closed factory owns matched native and recursive binary proof authority.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::{BinaryField128, TowerLevel};
use p3_binary_pcs::{BinaryPcsConfig, BinaryPcsParams};
use p3_circuit::ops::ByteHash;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::artifact::{
    BinaryNativeAuthority, BinaryNativePcsParameters, BinaryNativeVerifierSpec,
};
use p3_recursion::verifier::VerifierLimits;

type F = BinaryField128;

struct PinnedAir {
    preprocessed: bool,
    fixed: F,
}
impl BaseAir<F> for PinnedAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn preprocessed_width(&self) -> usize {
        usize::from(self.preprocessed)
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<F>> {
        self.preprocessed
            .then(|| RowMajorMatrix::new(vec![self.fixed; 4], 1))
    }
}
impl<AB: AirBuilder<F = F>> Air<AB> for PinnedAir {
    fn eval(&self, b: &mut AB) {
        let main = b.main().current_slice()[0];
        let public: AB::Expr = b.public_values()[0].into();
        if self.preprocessed {
            b.assert_eq(main, public + b.preprocessed().current_slice()[0]);
        } else {
            b.assert_eq(main, public + self.fixed);
        }
    }
}

fn spec(hash: ByteHash, preprocessed: bool) -> BinaryNativeVerifierSpec {
    let config = BinaryPcsConfig::try_new::<F, F>(
        2,
        BinaryPcsParams {
            log_inv_rate: 2,
            pow_bits: 0,
            security_level: 8,
        },
    )
    .unwrap();
    let main = BinaryNativePcsParameters {
        config,
        hash,
        cap_height: 0,
        max_query_draws: 128,
    };
    BinaryNativeVerifierSpec {
        main,
        preprocessed: preprocessed.then_some(BinaryNativePcsParameters {
            hash: ByteHash::Blake3,
            cap_height: 1,
            ..main
        }),
        transcript_hash: ByteHash::Blake3,
        initial_bytes: vec![7, 19, 13],
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    }
}

#[test]
fn owned_native_authority_verifies_all_caps_and_independent_statements() {
    for hash in [ByteHash::Keccak256, ByteHash::Blake3] {
        for preprocessed in [false, true] {
            let fixed = F::from_repr(0xf381239bca71);
            let (prover, authority) = BinaryNativeAuthority::<F, F, _>::setup(
                vec![PinnedAir {
                    preprocessed,
                    fixed,
                }],
                vec![2],
                spec(hash, preprocessed),
                &VerifierLimits::default(),
            )
            .unwrap();
            let retained = authority.canonical_verifier_bytes().to_vec();
            for raw in [0x982713u128, 0x8261de71] {
                let public = vec![vec![F::from_repr(raw)]];
                let proof = prover
                    .prove(
                        &public,
                        vec![RowMajorMatrix::new(vec![public[0][0] + fixed; 4], 1)],
                    )
                    .unwrap();
                let verified = authority.verify_native(&proof, &public).unwrap();
                assert_eq!(verified.public_values(), public);
                assert_eq!(authority.canonical_verifier_bytes(), retained);
                let mut wrong_statement = public.clone();
                wrong_statement[0][0] += F::ONE;
                assert!(authority.verify_native(&proof, &wrong_statement).is_err());
                let mut wrong_rows: p3_multi_stark::MultiStarkProof<
                    p3_recursion::artifact::BinaryNativeConfig<F, F>,
                > = postcard::from_bytes(&postcard::to_allocvec(&proof).unwrap()).unwrap();
                wrong_rows.opening.base_opened_values[0][0] += F::ONE;
                assert!(
                    matches!(authority.verify_native(&wrong_rows, &public), Err(p3_recursion::verifier::VerificationError::InvalidProofShape(message)) if message == "binary native proof verification rejected")
                );
                let mut oversized: p3_multi_stark::MultiStarkProof<
                    p3_recursion::artifact::BinaryNativeConfig<F, F>,
                > = postcard::from_bytes(&postcard::to_allocvec(&proof).unwrap()).unwrap();
                oversized
                    .opening
                    .base_multi_proof
                    .sibling_hashes
                    .resize(4096, [0; 32]);
                assert!(authority.verify_native(&oversized, &public).is_err());
            }
        }
    }
}

#[test]
fn native_authority_identity_pins_air_prefix_hash_and_preprocessed_values() {
    let make = |fixed, preprocessed, spec| {
        BinaryNativeAuthority::<F, F, _>::setup(
            vec![PinnedAir {
                preprocessed,
                fixed,
            }],
            vec![2],
            spec,
            &VerifierLimits::default(),
        )
        .unwrap()
        .1
    };
    let reference = make(F::from_repr(3), false, spec(ByteHash::Blake3, false));
    let same = make(F::from_repr(3), false, spec(ByteHash::Blake3, false));
    assert_eq!(
        reference.canonical_verifier_bytes(),
        same.canonical_verifier_bytes()
    );
    let different_air = make(F::from_repr(4), false, spec(ByteHash::Blake3, false));
    assert_ne!(
        reference.canonical_verifier_bytes(),
        different_air.canonical_verifier_bytes()
    );
    let mut prefix = spec(ByteHash::Blake3, false);
    prefix.initial_bytes.push(0);
    assert_ne!(
        reference.canonical_verifier_bytes(),
        make(F::from_repr(3), false, prefix).canonical_verifier_bytes()
    );
    let mut hash = spec(ByteHash::Blake3, false);
    hash.transcript_hash = ByteHash::Keccak256;
    assert_ne!(
        reference.canonical_verifier_bytes(),
        make(F::from_repr(3), false, hash).canonical_verifier_bytes()
    );
    let pp1 = make(F::from_repr(3), true, spec(ByteHash::Blake3, true));
    let pp2 = make(F::from_repr(4), true, spec(ByteHash::Blake3, true));
    assert_ne!(
        pp1.canonical_verifier_bytes(),
        pp2.canonical_verifier_bytes()
    );
}

#[test]
fn native_authority_rejects_aggregate_prefix_and_unsupported_grinding() {
    let make_air = || PinnedAir {
        preprocessed: false,
        fixed: F::ONE,
    };
    let (_, authority) = BinaryNativeAuthority::<F, F, _>::setup(
        vec![make_air()],
        vec![2],
        spec(ByteHash::Blake3, false),
        &VerifierLimits::default(),
    )
    .unwrap();
    let limits = VerifierLimits {
        max_metadata_entries: authority
            .recursive_verifier()
            .input_resource_usage()
            .metadata_entries,
        ..VerifierLimits::default()
    };
    assert!(matches!(
        BinaryNativeAuthority::<F, F, _>::setup(
            vec![make_air()],
            vec![2],
            spec(ByteHash::Blake3, false),
            &limits,
        ),
        Err(
            p3_recursion::verifier::VerificationError::ResourceLimitExceeded {
                component: "metadata entries",
                ..
            }
        )
    ));
    let mut grinding = spec(ByteHash::Blake3, false);
    grinding.sumcheck_pow_bits = 57;
    assert!(matches!(
        BinaryNativeAuthority::<F, F, _>::setup(
            vec![make_air()],
            vec![2],
            grinding,
            &VerifierLimits::default(),
        ),
        Err(
            p3_recursion::verifier::VerificationError::ResourceLimitExceeded {
                component: "binary native grinding bits",
                actual: 57,
                limit: 56
            }
        )
    ));
    let mut insecure = spec(ByteHash::Blake3, false);
    insecure.security_bits = 128;
    assert!(
        BinaryNativeAuthority::<F, F, _>::setup(
            vec![make_air()],
            vec![2],
            insecure,
            &VerifierLimits::default(),
        )
        .is_err()
    );
}
