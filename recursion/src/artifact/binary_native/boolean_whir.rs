//! Factory-owned native Boolean WHIR trace proofs and checked recursion input.
use p3_air::Air;
use p3_binary_field::BinaryField128;
use p3_multi_stark::folder::{InteractionMultilinearFolder, MultilinearFolder};
use p3_multi_stark::packed_ext::PackedExt;

use super::config::{BinaryNativeBooleanWhirTraceConfig, BinaryNativeWhirPcsParameters};
use super::family::BooleanWhirTraceFamily;
use super::*;
use crate::verifier::{
    BinaryBooleanWhirTraceMultiStarkVerifier, NativeBinaryBooleanWhirTraceMultiStarkInput,
};
type E = BinaryField128;

/// Trusted AIRs, matched native key and exact bit/packed commitment relation.
pub struct BinaryNativeBooleanWhirTraceAuthority<A> {
    pub(super) state: Arc<State<E, E, A, BooleanWhirTraceFamily>>,
}
impl<A> Clone for BinaryNativeBooleanWhirTraceAuthority<A> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}
pub struct BinaryNativeBooleanWhirTraceProver<A> {
    state: Arc<State<E, E, A, BooleanWhirTraceFamily>>,
    key: ProvingKey<BinaryNativeBooleanWhirTraceConfig>,
}
/// Minted only after bounded replay and complete retained native verification.
pub struct VerifiedBinaryNativeBooleanWhirTraceProof {
    pub(crate) identity: Arc<[u8]>,
    pub(crate) input: NativeBinaryBooleanWhirTraceMultiStarkInput,
    pub(crate) public: Vec<Vec<E>>,
}
impl VerifiedBinaryNativeBooleanWhirTraceProof {
    pub fn canonical_verifier_bytes(&self) -> &[u8] {
        &self.identity
    }
    pub fn native_input(&self) -> &NativeBinaryBooleanWhirTraceMultiStarkInput {
        &self.input
    }
    pub fn public_values(&self) -> &[Vec<E>] {
        &self.public
    }
}
impl<A: VerifierAir<E, E>> BinaryNativeBooleanWhirTraceAuthority<A> {
    pub fn setup(
        airs: Vec<A>,
        heights: Vec<usize>,
        spec: BinaryNativeVerifierSpec<BinaryNativeWhirPcsParameters<E>>,
        limits: &VerifierLimits,
    ) -> Result<(BinaryNativeBooleanWhirTraceProver<A>, Self), VerificationError> {
        Self::setup_with_artifact_limits(
            airs,
            heights,
            spec,
            ArtifactLimits {
                verifier: *limits,
                ..ArtifactLimits::default()
            },
        )
    }
    pub fn setup_with_artifact_limits(
        airs: Vec<A>,
        heights: Vec<usize>,
        spec: BinaryNativeVerifierSpec<BinaryNativeWhirPcsParameters<E>>,
        limits: ArtifactLimits,
    ) -> Result<(BinaryNativeBooleanWhirTraceProver<A>, Self), VerificationError> {
        let (state, key) =
            lifecycle::setup::<E, E, A, BooleanWhirTraceFamily>(airs, heights, spec, limits)?;
        Ok((
            BinaryNativeBooleanWhirTraceProver {
                state: state.clone(),
                key,
            },
            Self { state },
        ))
    }
    pub fn canonical_verifier_bytes(&self) -> &[u8] {
        &self.state.identity
    }
    pub(crate) fn shared_identity(&self) -> Arc<[u8]> {
        self.state.identity.clone()
    }
    pub fn artifact_limits(&self) -> &ArtifactLimits {
        &self.state.limits
    }
    pub fn recursive_verifier(&self) -> &BinaryBooleanWhirTraceMultiStarkVerifier {
        &self.state.binary
    }
    pub fn transcript_hash(&self) -> ByteHash {
        self.state.spec.transcript_hash
    }
    pub fn initial_bytes(&self) -> &[u8] {
        &self.state.spec.initial_bytes
    }
    pub fn verify_native(
        &self,
        proof: &MultiStarkProof<BinaryNativeBooleanWhirTraceConfig>,
        expected: &[Vec<E>],
    ) -> Result<VerifiedBinaryNativeBooleanWhirTraceProof, VerificationError> {
        let input = self.state.verify_native(proof, expected)?;
        Ok(VerifiedBinaryNativeBooleanWhirTraceProof {
            identity: self.state.identity.clone(),
            input,
            public: expected.to_vec(),
        })
    }
}
impl<A> BinaryNativeBooleanWhirTraceProver<A>
where
    A: VerifierAir<E, E>
        + for<'a> Air<MultilinearFolder<'a, E, PackedExt<E, E>, PackedExt<E, E>>>
        + for<'a> Air<InteractionMultilinearFolder<'a, E, PackedExt<E, E>, PackedExt<E, E>>>,
{
    /// Ordinary row-major AIR traces. Trusted shapes are checked before
    /// commitment or any native transcript mutation.
    pub fn prove(
        &self,
        public: &[Vec<E>],
        traces: Vec<RowMajorMatrix<E>>,
    ) -> Result<MultiStarkProof<BinaryNativeBooleanWhirTraceConfig>, VerificationError> {
        self.state.prove(&self.key, public, traces)
    }
}
