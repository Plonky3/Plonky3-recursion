//! Factory-owned native additive WHIR proofs and checked recursion input.

use p3_binary_field::BinaryField128;
use p3_binary_pcs::whir::BinaryWhirDomain;
use p3_sumcheck::layout::SuffixProver;
use p3_whir::WhirDomain;

use super::config::{
    BinaryNativeWhirConfig, BinaryNativeWhirLayout, BinaryNativeWhirPcsParameters,
};
use super::family::WhirFamily;
use super::*;
use crate::pcs::binary::RecursiveBinaryWhirTowerField;
use crate::verifier::{BinaryWhirMultiStarkVerifier, NativeBinaryWhirMultiStarkInput};

/// Trusted AIRs, matched native key and exact additive domain and layout.
pub struct BinaryNativeWhirAuthority<F, A, L = SuffixProver<F, BinaryField128>>
where
    F: RecursiveBinaryWhirTowerField
        + EncodableLevel
        + FoldAlphabet<BinaryField128>
        + PackedValue<Value = F>
        + Ord,
    BinaryField128: ExtensionField<F> + ChallengeField<F>,
    BinaryWhirDomain<F>: WhirDomain<F, BinaryField128>,
    L: BinaryNativeWhirLayout<F>,
{
    pub(super) state: Arc<State<F, BinaryField128, A, WhirFamily<L>>>,
}
impl<F, A, L> Clone for BinaryNativeWhirAuthority<F, A, L>
where
    F: RecursiveBinaryWhirTowerField
        + EncodableLevel
        + FoldAlphabet<BinaryField128>
        + PackedValue<Value = F>
        + Ord,
    BinaryField128: ExtensionField<F> + ChallengeField<F>,
    BinaryWhirDomain<F>: WhirDomain<F, BinaryField128>,
    L: BinaryNativeWhirLayout<F>,
{
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

pub struct BinaryNativeWhirProver<F, A, L = SuffixProver<F, BinaryField128>>
where
    F: RecursiveBinaryWhirTowerField
        + EncodableLevel
        + FoldAlphabet<BinaryField128>
        + PackedValue<Value = F>
        + Ord,
    BinaryField128: ExtensionField<F> + ChallengeField<F>,
    BinaryWhirDomain<F>: WhirDomain<F, BinaryField128>,
    L: BinaryNativeWhirLayout<F>,
{
    state: Arc<State<F, BinaryField128, A, WhirFamily<L>>>,
    key: ProvingKey<BinaryNativeWhirConfig<F, L>>,
}

/// Minted only after bounded replay and complete retained native verification.
pub struct VerifiedBinaryNativeWhirProof<F>
where
    F: RecursiveBinaryWhirTowerField,
{
    pub(crate) identity: Arc<[u8]>,
    pub(crate) input: NativeBinaryWhirMultiStarkInput<F>,
    pub(crate) public: Vec<Vec<F>>,
}
impl<F: RecursiveBinaryWhirTowerField> VerifiedBinaryNativeWhirProof<F> {
    pub fn canonical_verifier_bytes(&self) -> &[u8] {
        &self.identity
    }
    pub const fn native_input(&self) -> &NativeBinaryWhirMultiStarkInput<F> {
        &self.input
    }
    pub fn public_values(&self) -> &[Vec<F>] {
        &self.public
    }
}

impl<F, A, L> BinaryNativeWhirAuthority<F, A, L>
where
    F: RecursiveBinaryWhirTowerField
        + EncodableLevel
        + FoldAlphabet<BinaryField128>
        + PackedValue<Value = F>
        + Ord,
    BinaryField128: ExtensionField<F> + ChallengeField<F>,
    BinaryWhirDomain<F>: WhirDomain<F, BinaryField128>,
    L: BinaryNativeWhirLayout<F>,
    A: VerifierAir<F, BinaryField128>,
{
    pub fn setup(
        airs: Vec<A>,
        heights: Vec<usize>,
        spec: BinaryNativeVerifierSpec<BinaryNativeWhirPcsParameters<F>>,
        limits: &VerifierLimits,
    ) -> Result<(BinaryNativeWhirProver<F, A, L>, Self), VerificationError> {
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
        spec: BinaryNativeVerifierSpec<BinaryNativeWhirPcsParameters<F>>,
        limits: ArtifactLimits,
    ) -> Result<(BinaryNativeWhirProver<F, A, L>, Self), VerificationError> {
        let (state, proving) =
            lifecycle::setup::<F, BinaryField128, A, WhirFamily<L>>(airs, heights, spec, limits)?;
        Ok((
            BinaryNativeWhirProver {
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
    pub fn recursive_verifier(&self) -> &BinaryWhirMultiStarkVerifier<F> {
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
        proof: &MultiStarkProof<BinaryNativeWhirConfig<F, L>>,
        expected: &[Vec<F>],
    ) -> Result<VerifiedBinaryNativeWhirProof<F>, VerificationError> {
        let input = self.state.verify_native(proof, expected)?;
        Ok(VerifiedBinaryNativeWhirProof {
            identity: self.state.identity.clone(),
            input,
            public: expected.to_vec(),
        })
    }
}
impl<F, A, L> BinaryNativeWhirProver<F, A, L>
where
    F: RecursiveBinaryWhirTowerField
        + EncodableLevel
        + FoldAlphabet<BinaryField128>
        + PackedValue<Value = F>
        + Ord,
    BinaryField128: ExtensionField<F> + ChallengeField<F>,
    BinaryWhirDomain<F>: WhirDomain<F, BinaryField128>,
    L: BinaryNativeWhirLayout<F>,
    A: ProverAir<F, BinaryField128>,
    <BinaryField128 as ExtensionField<F>>::ExtensionPacking:
        From<BinaryField128> + From<F::Packing>,
{
    /// Ordinary row-major AIR traces. Trusted shapes are checked before
    /// commitment or any native transcript mutation.
    pub fn prove(
        &self,
        public: &[Vec<F>],
        traces: Vec<RowMajorMatrix<F>>,
    ) -> Result<MultiStarkProof<BinaryNativeWhirConfig<F, L>>, VerificationError> {
        self.state.prove(&self.key, public, traces)
    }
}
