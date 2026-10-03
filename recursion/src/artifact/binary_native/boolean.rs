//! Factory-owned native ordinary Boolean trace proofs and checked recursion input.

use super::config::BinaryNativeBooleanTraceConfig;
use super::family::BooleanTraceFamily;
use super::*;
use crate::verifier::{
    BinaryBooleanTraceMultiStarkVerifier, NativeBinaryBooleanTraceMultiStarkInput,
};

/// Trusted AIRs, matched native key and exact bit/packed commitment relation.
pub struct BinaryNativeBooleanTraceAuthority<E, A>
where
    E: RecursiveBinaryChallengeField
        + EncodableLevel
        + ExtensionField<E>
        + ChallengeField<E>
        + FoldAlphabet<E>
        + p3_binary_pcs::Coordinates
        + PackedValue<Value = E>
        + serde::Serialize
        + serde::de::DeserializeOwned,
{
    pub(super) state: Arc<State<E, E, A, BooleanTraceFamily>>,
}
impl<E, A> Clone for BinaryNativeBooleanTraceAuthority<E, A>
where
    E: RecursiveBinaryChallengeField
        + EncodableLevel
        + ExtensionField<E>
        + ChallengeField<E>
        + FoldAlphabet<E>
        + p3_binary_pcs::Coordinates
        + PackedValue<Value = E>
        + serde::Serialize
        + serde::de::DeserializeOwned,
{
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

pub struct BinaryNativeBooleanTraceProver<E, A>
where
    E: RecursiveBinaryChallengeField
        + EncodableLevel
        + ExtensionField<E>
        + ChallengeField<E>
        + FoldAlphabet<E>
        + p3_binary_pcs::Coordinates
        + PackedValue<Value = E>
        + serde::Serialize
        + serde::de::DeserializeOwned,
{
    state: Arc<State<E, E, A, BooleanTraceFamily>>,
    key: ProvingKey<BinaryNativeBooleanTraceConfig<E>>,
}

/// Minted only after bounded replay and complete retained native verification.
pub struct VerifiedBinaryNativeBooleanTraceProof<E>
where
    E: RecursiveBinaryChallengeField + ExtensionField<E>,
{
    pub(crate) identity: Arc<[u8]>,
    pub(crate) input: NativeBinaryBooleanTraceMultiStarkInput<E>,
    pub(crate) public: Vec<Vec<E>>,
}
impl<E: RecursiveBinaryChallengeField + ExtensionField<E>>
    VerifiedBinaryNativeBooleanTraceProof<E>
{
    pub fn canonical_verifier_bytes(&self) -> &[u8] {
        &self.identity
    }
    pub fn native_input(&self) -> &NativeBinaryBooleanTraceMultiStarkInput<E> {
        &self.input
    }
    pub fn public_values(&self) -> &[Vec<E>] {
        &self.public
    }
}

impl<E, A> BinaryNativeBooleanTraceAuthority<E, A>
where
    E: RecursiveBinaryChallengeField
        + EncodableLevel
        + ExtensionField<E>
        + ChallengeField<E>
        + FoldAlphabet<E>
        + p3_binary_pcs::Coordinates
        + PackedValue<Value = E>
        + serde::Serialize
        + serde::de::DeserializeOwned,
    A: VerifierAir<E, E>,
{
    pub fn setup(
        airs: Vec<A>,
        heights: Vec<usize>,
        spec: BinaryNativeVerifierSpec,
        limits: &VerifierLimits,
    ) -> Result<(BinaryNativeBooleanTraceProver<E, A>, Self), VerificationError> {
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
        spec: BinaryNativeVerifierSpec,
        limits: ArtifactLimits,
    ) -> Result<(BinaryNativeBooleanTraceProver<E, A>, Self), VerificationError> {
        let (state, proving) =
            lifecycle::setup::<E, E, A, BooleanTraceFamily>(airs, heights, spec, limits)?;
        Ok((
            BinaryNativeBooleanTraceProver {
                state: state.clone(),
                key: proving,
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
    pub fn recursive_verifier(&self) -> &BinaryBooleanTraceMultiStarkVerifier<E> {
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
        proof: &MultiStarkProof<BinaryNativeBooleanTraceConfig<E>>,
        expected: &[Vec<E>],
    ) -> Result<VerifiedBinaryNativeBooleanTraceProof<E>, VerificationError> {
        let input = self.state.verify_native(proof, expected)?;
        Ok(VerifiedBinaryNativeBooleanTraceProof {
            identity: self.state.identity.clone(),
            input,
            public: expected.to_vec(),
        })
    }
}
impl<E, A> BinaryNativeBooleanTraceProver<E, A>
where
    E: RecursiveBinaryChallengeField
        + EncodableLevel
        + ExtensionField<E>
        + ChallengeField<E>
        + FoldAlphabet<E>
        + p3_binary_pcs::Coordinates
        + PackedValue<Value = E>
        + serde::Serialize
        + serde::de::DeserializeOwned,
    A: ProverAir<E, E>,
    E::ExtensionPacking: From<E> + From<E::Packing>,
{
    /// Ordinary row-major AIR traces. Trusted shapes are checked before
    /// commitment or any native transcript mutation.
    pub fn prove(
        &self,
        public: &[Vec<E>],
        traces: Vec<RowMajorMatrix<E>>,
    ) -> Result<MultiStarkProof<BinaryNativeBooleanTraceConfig<E>>, VerificationError> {
        self.state.prove(&self.key, public, traces)
    }
}
