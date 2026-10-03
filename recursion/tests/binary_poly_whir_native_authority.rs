//! Checked polynomial WHIR authority preserves all three challenge coefficients.
use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::{Poly64, Poly192};
use p3_circuit::ops::ByteHash;
use p3_field::PrimeCharacteristicRing;
use p3_matrix::dense::RowMajorMatrix;
use p3_recursion::artifact::{
    ArtifactError, BinaryNativePolyWhirAuthority, BinaryNativePolyWhirPcsParameters,
    BinaryNativeVerifierSpec, CanonicalBinaryStatement, ExpectedVerifierArtifact,
};
use p3_recursion::verifier::VerifierLimits;
use p3_sumcheck::layout::{PrefixProver, SuffixProver};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

struct ConstantAir;
impl<F> BaseAir<F> for ConstantAir {
    fn width(&self) -> usize {
        1
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![]
    }
}
impl<AB: AirBuilder> Air<AB> for ConstantAir {
    fn eval(&self, b: &mut AB) {
        b.assert_eq(b.main().current_slice()[0], b.public_values()[0]);
    }
}
fn parameters() -> ProtocolParameters {
    ProtocolParameters {
        security_level: 24,
        pow_bits: 0,
        round_log_inv_rates: vec![],
        folding_factor: FoldingFactor::Constant(1),
        soundness_type: SecurityAssumption::JohnsonBound,
        starting_log_inv_rate: 2,
    }
}
macro_rules! check {
    ($f:ty, $layout:ident) => {{
        type F = Poly64;
        type L = $layout<F, Poly192>;
        for hash in [ByteHash::Keccak256, ByteHash::Blake3] {
            let main = BinaryNativePolyWhirPcsParameters::with_limits(
                3,
                parameters(),
                hash,
                0,
                &VerifierLimits::default(),
            )
            .unwrap();
            let spec = BinaryNativeVerifierSpec {
                main,
                preprocessed: None,
                transcript_hash: hash,
                initial_bytes: vec![0, 19, 255],
                sumcheck_pow_bits: 0,
                max_tau_draws: 8,
                security_bits: 16,
            };
            let (prover, authority) = BinaryNativePolyWhirAuthority::<_, L>::setup(
                vec![ConstantAir],
                vec![3],
                spec,
                &VerifierLimits::default(),
            )
            .unwrap();
            let public = vec![vec![F::new(0xfedc_ba98_7654_3210)]];
            let mut proof = prover
                .prove(
                    &public,
                    vec![RowMajorMatrix::new(
                        vec![F::new(0xfedc_ba98_7654_3210); 8],
                        1,
                    )],
                )
                .unwrap();
            let original = proof.sumcheck.round_polys[0][0];
            let mut coefficients = original.coefficients();
            coefficients[2] += Poly64::ONE;
            proof.sumcheck.round_polys[0][0] = Poly192::new(coefficients);
            assert!(authority.verify_native(&proof, &public).is_err());
            proof.sumcheck.round_polys[0][0] = original;
            let bytes = authority.encode_native_proof(&proof, &public).unwrap();
            let statement = authority.encode_statement(&public).unwrap();
            assert_eq!(statement, 0xfedc_ba98_7654_3210u64.to_le_bytes());
            let identity = authority.canonical_verifier_bytes();
            let decode = |bytes: &[u8]| {
                authority.decode_and_verify(
                    identity,
                    ExpectedVerifierArtifact::from_trusted_bytes(identity),
                    bytes,
                    CanonicalBinaryStatement::new(&statement, 1),
                )
            };
            let token = decode(&bytes).unwrap();
            assert_eq!(token.public_values(), public);
            token
                .native_input()
                .private_values::<p3_baby_bear::BabyBear>(
                    &authority.recursive_verifier().input_shape(),
                )
                .unwrap();
            for length in 0..bytes.len() {
                assert!(decode(&bytes[..length]).is_err());
            }
            let mut wrong = public.clone();
            wrong[0][0] += F::ONE;
            let wrong = authority.encode_statement(&wrong).unwrap();
            assert!(
                authority
                    .decode_and_verify(
                        identity,
                        ExpectedVerifierArtifact::from_trusted_bytes(identity),
                        &bytes,
                        CanonicalBinaryStatement::new(&wrong, 1)
                    )
                    .is_err()
            );
            let mut changed = identity.to_vec();
            let last = changed.len() - 1;
            changed[last] ^= 1;
            assert_eq!(
                authority
                    .decode_and_verify(
                        &changed,
                        ExpectedVerifierArtifact::from_trusted_bytes(identity),
                        &bytes,
                        CanonicalBinaryStatement::new(&statement, 1)
                    )
                    .err(),
                Some(ArtifactError::TrustedArtifactMismatch)
            );
        }
    }};
}
#[test]
fn checked_poly_whir_owners_decode_both_layouts_and_hashes() {
    check!(Poly64, PrefixProver);
    check!(Poly64, SuffixProver);
}
#[test]
fn poly_whir_parameters_reject_unbounded_constructor_work_before_native_derivation() {
    let limits = VerifierLimits::default();
    let make = |n, params| {
        BinaryNativePolyWhirPcsParameters::with_limits(n, params, ByteHash::Blake3, 0, &limits)
    };
    assert!(make(usize::MAX, parameters()).is_err());
    let mut params = parameters();
    params.starting_log_inv_rate = usize::MAX;
    assert!(make(3, params).is_err());
    let mut params = parameters();
    params.round_log_inv_rates = vec![1; 4];
    assert!(make(3, params).is_err());
    let mut params = parameters();
    params.folding_factor = FoldingFactor::PerRound(vec![1; 4]);
    assert!(make(3, params).is_err());
    let mut params = parameters();
    params.security_level = usize::MAX;
    assert!(make(3, params).is_err());
    let mut params = parameters();
    params.pow_bits = params.security_level;
    assert!(make(3, params).is_err());
    // The nominal PoW ceiling may exceed the challenger limit while actual
    // required work fits it; the owner prices actual native difficulties.
    let mut params = parameters();
    params.security_level = 26;
    params.pow_bits = 25;
    params.starting_log_inv_rate = 6;
    assert_eq!(
        make(3, params.clone())
            .unwrap()
            .configuration()
            .max_pow_bits(),
        24
    );
    params.starting_log_inv_rate = 61;
    params.soundness_type = SecurityAssumption::UniqueDecoding;
    assert!(make(3, params).is_err());
}

struct PreprocessedAir {
    flip: bool,
}
impl BaseAir<Poly64> for PreprocessedAir {
    fn width(&self) -> usize {
        2
    }
    fn num_public_values(&self) -> usize {
        1
    }
    fn preprocessed_width(&self) -> usize {
        1
    }
    fn main_next_row_columns(&self) -> Vec<usize> {
        vec![0]
    }
    fn preprocessed_next_row_columns(&self) -> Vec<usize> {
        vec![0]
    }
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Poly64>> {
        Some(RowMajorMatrix::new(
            (0..8)
                .map(|row| Poly64::from_bool((row % 2 == 1) ^ self.flip))
                .collect(),
            1,
        ))
    }
}
impl<AB: AirBuilder<F = Poly64>> Air<AB> for PreprocessedAir {
    fn eval(&self, b: &mut AB) {
        let public: AB::Expr = b.public_values()[0].into();
        let main = b.main();
        let cur = main.current_slice();
        let next = main.next_slice()[0];
        let pp = b.preprocessed();
        let pp_cur = pp.current_slice()[0];
        let pp_next = pp.next_slice()[0];
        b.assert_eq(cur[0], public.clone());
        b.assert_eq(cur[1], pp_cur);
        b.when_transition().assert_eq(next, public);
        b.when_transition()
            .assert_eq(pp_next, AB::Expr::ONE + cur[1]);
    }
}
#[test]
fn checked_poly_whir_owner_retains_preprocessing_with_independent_hashes_and_caps() {
    type F = Poly64;
    let spec = || {
        let p = |n, rate, hash, cap| {
            let mut params = parameters();
            params.folding_factor = FoldingFactor::Constant(2);
            params.starting_log_inv_rate = rate;
            BinaryNativePolyWhirPcsParameters::new(n, params, hash, cap).unwrap()
        };
        BinaryNativeVerifierSpec {
            main: p(4, 2, ByteHash::Keccak256, 0),
            preprocessed: Some(p(3, 2, ByteHash::Blake3, 1)),
            transcript_hash: ByteHash::Blake3,
            initial_bytes: vec![0, 19, 255],
            sumcheck_pow_bits: 0,
            max_tau_draws: 8,
            security_bits: 8,
        }
    };
    let (prover, authority) = BinaryNativePolyWhirAuthority::<_>::setup(
        vec![PreprocessedAir { flip: false }],
        vec![3],
        spec(),
        &VerifierLimits::default(),
    )
    .unwrap();
    let public = vec![vec![F::ONE]];
    let trace = RowMajorMatrix::new(
        (0..8)
            .flat_map(|row| [F::ONE, F::from_bool(row % 2 == 1)])
            .collect(),
        2,
    );
    let proof = prover.prove(&public, vec![trace]).unwrap();
    let bytes = authority.encode_native_proof(&proof, &public).unwrap();
    let statement = authority.encode_statement(&public).unwrap();
    let identity = authority.canonical_verifier_bytes();
    authority
        .decode_and_verify(
            identity,
            ExpectedVerifierArtifact::from_trusted_bytes(identity),
            &bytes,
            CanonicalBinaryStatement::new(&statement, 1),
        )
        .unwrap();
    let (_, different) = BinaryNativePolyWhirAuthority::<_>::setup(
        vec![PreprocessedAir { flip: true }],
        vec![3],
        spec(),
        &VerifierLimits::default(),
    )
    .unwrap();
    assert_ne!(identity, different.canonical_verifier_bytes());
    assert!(different.verify_native(&proof, &public).is_err());
    let mut bad = spec();
    let mut params = parameters();
    params.folding_factor = FoldingFactor::Constant(1);
    bad.preprocessed =
        Some(BinaryNativePolyWhirPcsParameters::new(3, params, ByteHash::Blake3, 1).unwrap());
    assert!(
        matches!(BinaryNativePolyWhirAuthority::<_>::setup(vec![PreprocessedAir { flip: false }], vec![3], bad, &VerifierLimits::default()), Err(p3_recursion::VerificationError::InvalidProofShape(message)) if message == "binary native WHIR main and preprocessing initial folding factors differ")
    );
    let mut params = parameters();
    params.folding_factor = FoldingFactor::Constant(2);
    let spec = BinaryNativeVerifierSpec {
        main: BinaryNativePolyWhirPcsParameters::new(3, params, ByteHash::Blake3, 0).unwrap(),
        preprocessed: None,
        transcript_hash: ByteHash::Blake3,
        initial_bytes: vec![],
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    };
    assert!(
        matches!(BinaryNativePolyWhirAuthority::<_>::setup(vec![ConstantAir], vec![1], spec, &VerifierLimits::default()), Err(p3_recursion::VerificationError::InvalidProofShape(message)) if message == "binary native WHIR trace height is below its initial folding factor")
    );
}
