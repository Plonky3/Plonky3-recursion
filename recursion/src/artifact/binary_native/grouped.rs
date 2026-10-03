//! Factory-owned native grouped binary proofs with a frozen recursive relation.

use super::config::BinaryNativeGroupedConfig;
use super::family::GroupedFamily;
use super::*;
use crate::pcs::binary::BinaryCodewordGrouping;
use crate::verifier::{BinaryGroupedMultiStarkVerifier, NativeBinaryGroupedMultiStarkInput};

/// Exact native grouping constructors, independently fixed at each PCS site.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BinaryNativeGroupedPcsParameters {
    pub pcs: BinaryNativePcsParameters,
    pub base_grouping: BinaryCodewordGrouping,
    pub round_grouping: BinaryCodewordGrouping,
}

pub type BinaryNativeGroupedVerifierSpec =
    BinaryNativeVerifierSpec<BinaryNativeGroupedPcsParameters>;

/// Owned trusted AIRs, matched native verifying key, closed cryptography and
/// frozen recursive plan. Construction receives no representative proof.
pub struct BinaryNativeGroupedAuthority<F, E, A>
where
    F: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField
        + ExtensionField<F>
        + ChallengeField<F>
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
{
    state: Arc<State<F, E, A, GroupedFamily>>,
}

impl<F, E, A> Clone for BinaryNativeGroupedAuthority<F, E, A>
where
    F: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField
        + ExtensionField<F>
        + ChallengeField<F>
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
{
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

pub struct BinaryNativeGroupedProver<F, E, A>
where
    F: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField
        + ExtensionField<F>
        + ChallengeField<F>
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
{
    state: Arc<State<F, E, A, GroupedFamily>>,
    key: ProvingKey<BinaryNativeGroupedConfig<F, E>>,
}

/// Created only after bounded replay and complete native verification under
/// retained authority. Its statement is the independently supplied statement.
pub struct VerifiedBinaryNativeGroupedProof<F, E>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField,
{
    pub(crate) identity: Arc<[u8]>,
    pub(crate) input: NativeBinaryGroupedMultiStarkInput<F, E>,
    pub(crate) public: Vec<Vec<F>>,
}

impl<F: RecursiveBinaryTowerField, E: RecursiveBinaryChallengeField>
    VerifiedBinaryNativeGroupedProof<F, E>
{
    pub fn canonical_verifier_bytes(&self) -> &[u8] {
        &self.identity
    }
    pub fn native_input(&self) -> &NativeBinaryGroupedMultiStarkInput<F, E> {
        &self.input
    }
    pub fn public_values(&self) -> &[Vec<F>] {
        &self.public
    }
}

impl<F, E, A> BinaryNativeGroupedAuthority<F, E, A>
where
    F: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField
        + ExtensionField<F>
        + ChallengeField<F>
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
    A: VerifierAir<F, E>,
{
    pub fn setup(
        airs: Vec<A>,
        heights: Vec<usize>,
        spec: BinaryNativeGroupedVerifierSpec,
        limits: &VerifierLimits,
    ) -> Result<(BinaryNativeGroupedProver<F, E, A>, Self), VerificationError> {
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
    ) -> Result<(BinaryNativeGroupedProver<F, E, A>, Self), VerificationError> {
        let (state, proving) =
            lifecycle::setup::<F, E, A, GroupedFamily>(airs, heights, spec, limits)?;
        Ok((
            BinaryNativeGroupedProver {
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
    pub fn recursive_verifier(&self) -> &BinaryGroupedMultiStarkVerifier<F, E> {
        &self.state.binary
    }
    pub fn transcript_hash(&self) -> ByteHash {
        self.state.spec.transcript_hash
    }
    pub fn initial_bytes(&self) -> &[u8] {
        &self.state.spec.initial_bytes
    }

    /// The independent statement is checked before bounded replay. Only after
    /// replay succeeds can the full native verifier invoke its unbounded query
    /// sampler; identical transcript state has already fit the retained budget.
    pub fn verify_native(
        &self,
        proof: &MultiStarkProof<BinaryNativeGroupedConfig<F, E>>,
        expected: &[Vec<F>],
    ) -> Result<VerifiedBinaryNativeGroupedProof<F, E>, VerificationError> {
        let input = self.state.verify_native(proof, expected)?;
        Ok(VerifiedBinaryNativeGroupedProof {
            identity: self.state.identity.clone(),
            input,
            public: expected.to_vec(),
        })
    }
}

impl<F, E, A> BinaryNativeGroupedProver<F, E, A>
where
    F: RecursiveBinaryTowerField + EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField
        + ExtensionField<F>
        + ChallengeField<F>
        + FoldAlphabet<E>
        + PackedValue<Value = E>,
    A: ProverAir<F, E>,
    E::ExtensionPacking: From<E> + From<F::Packing>,
{
    /// Trace matrices have ordinary row-major AIR order. Shape checks precede
    /// transpose, commitment, grinding or any transcript mutation.
    pub fn prove(
        &self,
        public: &[Vec<F>],
        traces: Vec<RowMajorMatrix<F>>,
    ) -> Result<MultiStarkProof<BinaryNativeGroupedConfig<F, E>>, VerificationError> {
        self.state.prove(&self.key, public, traces)
    }
}
