pub(crate) mod native;
pub(crate) mod wire;

use crate::VerifierLimits;

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
}
