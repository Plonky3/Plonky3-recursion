//! Factory-owned native grouped Boolean trace proofs and checked recursion input.

use super::config::BinaryNativeGroupedBooleanTraceConfig;
use super::family::GroupedBooleanTraceFamily;
use super::*;
use crate::verifier::{
    BinaryGroupedBooleanTraceMultiStarkVerifier, NativeBinaryGroupedBooleanTraceMultiStarkInput,
};

/// Trusted AIRs, matched native key and exact bit/packed commitment relation.
pub struct BinaryNativeGroupedBooleanTraceAuthority<E, A>
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
    pub(super) state: Arc<State<E, E, A, GroupedBooleanTraceFamily>>,
}
impl<E, A> Clone for BinaryNativeGroupedBooleanTraceAuthority<E, A>
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

pub struct BinaryNativeGroupedBooleanTraceProver<E, A>
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
    state: Arc<State<E, E, A, GroupedBooleanTraceFamily>>,
    key: ProvingKey<BinaryNativeGroupedBooleanTraceConfig<E>>,
}

/// Minted only after bounded replay and complete retained native verification.
pub struct VerifiedBinaryNativeGroupedBooleanTraceProof<E>
where
    E: RecursiveBinaryChallengeField + ExtensionField<E>,
{
    pub(crate) identity: Arc<[u8]>,
    pub(crate) input: NativeBinaryGroupedBooleanTraceMultiStarkInput<E>,
    pub(crate) public: Vec<Vec<E>>,
}
impl<E: RecursiveBinaryChallengeField + ExtensionField<E>>
    VerifiedBinaryNativeGroupedBooleanTraceProof<E>
{
    pub fn canonical_verifier_bytes(&self) -> &[u8] {
        &self.identity
    }
    pub const fn native_input(&self) -> &NativeBinaryGroupedBooleanTraceMultiStarkInput<E> {
        &self.input
    }
    pub fn public_values(&self) -> &[Vec<E>] {
        &self.public
    }
}

impl<E, A> BinaryNativeGroupedBooleanTraceAuthority<E, A>
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
        spec: BinaryNativeGroupedVerifierSpec,
        limits: &VerifierLimits,
    ) -> Result<(BinaryNativeGroupedBooleanTraceProver<E, A>, Self), VerificationError> {
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
        spec: BinaryNativeGroupedVerifierSpec,
        limits: ArtifactLimits,
    ) -> Result<(BinaryNativeGroupedBooleanTraceProver<E, A>, Self), VerificationError> {
        let (state, proving) =
            lifecycle::setup::<E, E, A, GroupedBooleanTraceFamily>(airs, heights, spec, limits)?;
        Ok((
            BinaryNativeGroupedBooleanTraceProver {
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
    pub fn recursive_verifier(&self) -> &BinaryGroupedBooleanTraceMultiStarkVerifier<E> {
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
        proof: &MultiStarkProof<BinaryNativeGroupedBooleanTraceConfig<E>>,
        expected: &[Vec<E>],
    ) -> Result<VerifiedBinaryNativeGroupedBooleanTraceProof<E>, VerificationError> {
        let input = self.state.verify_native(proof, expected)?;
        Ok(VerifiedBinaryNativeGroupedBooleanTraceProof {
            identity: self.state.identity.clone(),
            input,
            public: expected.to_vec(),
        })
    }
}
impl<E, A> BinaryNativeGroupedBooleanTraceProver<E, A>
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
    ) -> Result<MultiStarkProof<BinaryNativeGroupedBooleanTraceConfig<E>>, VerificationError> {
        self.state.prove(&self.key, public, traces)
    }
}
