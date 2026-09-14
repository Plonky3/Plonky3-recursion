mod assembly;
mod descriptor;
pub(crate) mod native;
pub(crate) mod wire;

use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::vec::Vec;

use p3_circuit::{StatementError, StatementSchema};
use p3_circuit_prover::BatchStarkProof;
use p3_uni_stark::StarkGenericConfig;

use crate::VerifierLimits;
use crate::builtin_config::BuiltinConfigError;

/// Application-provisioned exact trust anchor for one canonical verifier artifact.
#[derive(Clone, Copy, Debug)]
pub struct ExpectedVerifierArtifact<'a> {
    canonical_bytes: &'a [u8],
}

impl<'a> ExpectedVerifierArtifact<'a> {
    /// Assert that `bytes` came from an independently trusted provisioning channel.
    pub const fn from_trusted_bytes(bytes: &'a [u8]) -> Self {
        Self {
            canonical_bytes: bytes,
        }
    }
}

/// Canonical base-field statement bytes interpreted under a retained verifier schema.
#[derive(Clone, Copy, Debug)]
pub struct CanonicalStatement<'a> {
    canonical_bytes: &'a [u8],
    element_count: usize,
}

impl<'a> CanonicalStatement<'a> {
    pub const fn new(canonical_bytes: &'a [u8], element_count: usize) -> Self {
        Self {
            canonical_bytes,
            element_count,
        }
    }
}

pub(crate) trait PortableVerifierInner {
    fn schema(&self) -> &StatementSchema;
    fn verify_encoded(
        &self,
        bytes: &[u8],
        expected: CanonicalStatement<'_>,
    ) -> Result<(), ArtifactError>;
}

/// Opaque verification-only handle reconstructed from a pinned canonical artifact.
///
/// The selected suite and native verifier/config stay private to the handle.
///
/// ```compile_fail
/// use p3_recursion::artifact::PortableVerifier;
///
/// fn suite_escape(verifier: &PortableVerifier) {
///     let _ = verifier.suite();
/// }
/// ```
#[derive(Clone)]
pub struct PortableVerifier {
    state: Rc<PortableVerifierState>,
}

struct PortableVerifierState {
    inner: Box<dyn PortableVerifierInner>,
    canonical_bytes: Vec<u8>,
}

impl PortableVerifier {
    fn from_parts(inner: Box<dyn PortableVerifierInner>, canonical_bytes: Vec<u8>) -> Self {
        Self {
            state: Rc::new(PortableVerifierState {
                inner,
                canonical_bytes,
            }),
        }
    }

    pub fn decode(
        candidate: &[u8],
        expected: ExpectedVerifierArtifact<'_>,
        limits: ArtifactLimits,
    ) -> Result<Self, ArtifactError> {
        check_expected_verifier_candidate(candidate, expected, &limits)?;
        assembly::decode_portable_verifier(candidate, limits)
    }

    pub fn verify_encoded(
        &self,
        proof: &[u8],
        expected_statement: CanonicalStatement<'_>,
    ) -> Result<(), ArtifactError> {
        self.state.inner.verify_encoded(proof, expected_statement)
    }

    pub fn schema(&self) -> &StatementSchema {
        self.state.inner.schema()
    }

    pub fn trusted_identity_bytes(&self) -> &[u8] {
        &self.state.canonical_bytes
    }
}

/// Export operations implemented only for library-created built-in verifier config wrappers.
pub trait PortableArtifactExport {
    type Config: StarkGenericConfig;

    fn encode_verifier_artifact(&self, limits: ArtifactLimits) -> Result<Vec<u8>, ArtifactError>;
    fn encode_proof_artifact(
        &self,
        proof: &BatchStarkProof<Self::Config>,
        limits: ArtifactLimits,
    ) -> Result<Vec<u8>, ArtifactError>;
}

fn check_expected_verifier_candidate(
    candidate: &[u8],
    expected: ExpectedVerifierArtifact<'_>,
    limits: &ArtifactLimits,
) -> Result<(), ArtifactError> {
    // Parse only the non-selecting frame envelope first. Suite/config dispatch is forbidden until
    // the exact independently provisioned byte identity has matched.
    wire::validate_frame_envelope(candidate, ArtifactKind::Verifier, limits.max_verifier_bytes)?;
    if candidate != expected.canonical_bytes {
        return Err(ArtifactError::TrustedArtifactMismatch);
    }
    Ok(())
}

/// The physical artifact carried by a V1 frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum ArtifactKind {
    /// A trusted verifier descriptor.
    Verifier = 1,
    /// A proof decoded under a trusted verifier descriptor.
    Proof = 2,
}

/// Finite limits applied while importing artifact bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArtifactLimits {
    pub max_verifier_bytes: usize,
    pub max_proof_bytes: usize,
    pub max_decoded_bytes: usize,
    pub max_container_entries: usize,
    pub verifier: VerifierLimits,
}

impl Default for ArtifactLimits {
    fn default() -> Self {
        Self {
            max_verifier_bytes: 16 << 20,
            max_proof_bytes: 64 << 20,
            max_decoded_bytes: 128 << 20,
            max_container_entries: 1 << 20,
            verifier: VerifierLimits::default(),
        }
    }
}

/// Typed failures from the stable artifact format.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ArtifactError {
    #[error("artifact magic is not P3RCART\\0")]
    BadMagic,
    #[error("artifact has the wrong kind")]
    WrongArtifactKind,
    #[error("artifact format version {0} is unsupported")]
    UnsupportedVersion(u16),
    #[error("artifact suite {0} is unsupported")]
    UnsupportedSuite(u16),
    #[error("artifact built-in AIR tag {0} is unsupported")]
    UnsupportedBuiltinAir(u16),
    #[error("candidate verifier artifact does not match the independently trusted bytes")]
    TrustedArtifactMismatch,
    #[error("artifact is truncated")]
    Truncated,
    #[error("artifact has trailing bytes")]
    TrailingBytes,
    #[error("artifact contains invalid tag {tag} for {component}")]
    InvalidTag { component: &'static str, tag: u8 },
    #[error("artifact contains a non-canonical field element")]
    NonCanonicalField,
    #[error("artifact contains non-canonical metadata")]
    NonCanonicalMetadata,
    #[error("artifact contains malformed proof data for {component}")]
    MalformedProof { component: &'static str },
    #[error("artifact length arithmetic overflowed")]
    LengthOverflow,
    #[error("artifact decode limit exceeded for {component}: {actual} > {limit}")]
    DecodeLimitExceeded {
        component: &'static str,
        actual: usize,
        limit: usize,
    },
    #[error("artifact allocation failed for {component}")]
    AllocationFailed { component: &'static str },
    #[error("artifact contains an invalid built-in configuration: {0}")]
    BuiltinConfig(#[from] BuiltinConfigError),
    #[error("artifact statement does not match the retained schema: {0}")]
    Statement(#[from] StatementError),
    #[error("artifact proof verification was rejected")]
    VerificationRejected,
}

#[cfg(test)]
mod identity_tests {
    use super::{
        ArtifactError, ArtifactKind, ArtifactLimits, ExpectedVerifierArtifact,
        check_expected_verifier_candidate,
    };
    use crate::artifact::wire::encode_framed;

    #[test]
    fn exact_trust_anchor_match_precedes_suite_or_body_instantiation() {
        let limits = ArtifactLimits::default();
        let candidate = encode_framed(ArtifactKind::Verifier, 0xffff, 128, |writer| {
            writer.write_u8(0xff)
        })
        .unwrap();
        let expected = encode_framed(ArtifactKind::Verifier, 1, 128, |_| Ok(())).unwrap();
        assert_eq!(
            check_expected_verifier_candidate(
                &candidate,
                ExpectedVerifierArtifact::from_trusted_bytes(&expected),
                &limits,
            ),
            Err(ArtifactError::TrustedArtifactMismatch)
        );
    }

    #[test]
    fn malformed_frame_rejects_before_identity_comparison() {
        let limits = ArtifactLimits::default();
        assert_eq!(
            check_expected_verifier_candidate(
                b"not-artifact",
                ExpectedVerifierArtifact::from_trusted_bytes(&[0; 17]),
                &limits,
            ),
            Err(ArtifactError::BadMagic)
        );
    }
}
