//! Prepared native recursion refuses allocation policies before key generation.

use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
use p3_binary_field::BinaryField128;
use p3_circuit::ops::ByteHash;
use p3_circuit_prover::direct::DirectCircuitLimits;
use p3_recursion::artifact::{
    ArtifactLimits, BinaryNativeVerifierSpec, BinaryNativeWhirAuthority,
    BinaryNativeWhirPcsParameters,
};
use p3_recursion::prepared::{NativeBinaryRecursionOptions, PreparedNativeBinaryWhirLayer};
use p3_recursion::verifier::{VerificationError, VerifierLimits};
use p3_whir::{FoldingFactor, ProtocolParameters, SecurityAssumption};

type F = BinaryField128;
#[derive(Clone)]
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
        let main = b.main();
        b.assert_eq(main.current_slice()[0], b.public_values()[0]);
    }
}
const fn protocol() -> ProtocolParameters {
    ProtocolParameters {
        security_level: 8,
        pow_bits: 0,
        round_log_inv_rates: vec![],
        folding_factor: FoldingFactor::Constant(1),
        soundness_type: SecurityAssumption::JohnsonBound,
        starting_log_inv_rate: 1,
    }
}
fn authority(hash: ByteHash) -> BinaryNativeWhirAuthority<F, ConstantAir> {
    let spec = BinaryNativeVerifierSpec {
        main: BinaryNativeWhirPcsParameters::<F>::new(1, protocol(), hash, 0).unwrap(),
        preprocessed: None,
        transcript_hash: hash,
        initial_bytes: b"native-recursion-limit-test".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 8,
        security_bits: 4,
    };
    BinaryNativeWhirAuthority::setup(vec![ConstantAir], vec![1], spec, &VerifierLimits::default())
        .unwrap()
        .1
}
fn options() -> NativeBinaryRecursionOptions {
    NativeBinaryRecursionOptions {
        main: protocol(),
        preprocessed: protocol(),
        cap_height: 0,
        initial_bytes: b"native-output-limit-test".to_vec(),
        sumcheck_pow_bits: 0,
        max_tau_draws: 32,
        security_bits: 4,
        max_pcs_codeword_cells: 0,
        artifact_limits: ArtifactLimits::default(),
    }
}
#[test]
fn native_preparation_checks_host_graph_and_codeword_limits() {
    assert!(matches!(
        PreparedNativeBinaryWhirLayer::from_native_authority(
            &authority(ByteHash::Blake3),
            options(),
            &DirectCircuitLimits::default()
        ),
        Err(VerificationError::CircuitBuilder(_))
    ));
    let authority = authority(ByteHash::Keccak256);
    for folding in [
        FoldingFactor::PerRound(vec![]),
        FoldingFactor::Constant(0),
        FoldingFactor::Constant(usize::MAX),
    ] {
        let mut invalid = options();
        invalid.main.folding_factor = folding;
        assert!(matches!(
            PreparedNativeBinaryWhirLayer::from_native_authority(
                &authority,
                invalid,
                &DirectCircuitLimits::default()
            ),
            Err(VerificationError::InvalidProofShape(_))
        ));
    }
    let mut invalid = options();
    invalid.preprocessed.folding_factor = FoldingFactor::Constant(2);
    assert!(matches!(
        PreparedNativeBinaryWhirLayer::from_native_authority(
            &authority,
            invalid,
            &DirectCircuitLimits::default()
        ),
        Err(VerificationError::InvalidProofShape(_))
    ));
    let graph_limits = DirectCircuitLimits {
        max_witnesses: 0,
        ..Default::default()
    };
    assert!(matches!(
        PreparedNativeBinaryWhirLayer::from_native_authority(&authority, options(), &graph_limits),
        Err(VerificationError::NativeBusCircuit(_))
    ));
    let trace_limits = DirectCircuitLimits {
        max_trace_cells: 1 << 27,
        ..Default::default()
    };
    assert!(
        matches!(PreparedNativeBinaryWhirLayer::from_native_authority(&authority, options(), &trace_limits), Err(VerificationError::ResourceLimitExceeded { component: "native recursive PCS codeword cells", limit: 0, actual }) if actual > 0)
    );
}
