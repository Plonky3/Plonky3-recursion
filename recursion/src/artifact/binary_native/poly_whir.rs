//! Factory-owned native additive WHIR proofs and checked recursion input.

use p3_binary_field::{Poly64, Poly192};
use p3_sumcheck::layout::SuffixProver;

use super::config::{
    BinaryNativePolyWhirConfig, BinaryNativePolyWhirLayout, BinaryNativePolyWhirPcsParameters,
};
use super::family::PolyWhirFamily;
use super::*;
use crate::verifier::{BinaryPolyWhirMultiStarkVerifier, NativeBinaryPolyWhirMultiStarkInput};

/// Trusted AIRs, matched native key and exact additive domain and layout.
pub struct BinaryNativePolyWhirAuthority<A, L = SuffixProver<Poly64, Poly192>>
where
    L: BinaryNativePolyWhirLayout,
{
    pub(super) state: Arc<State<Poly64, Poly192, A, PolyWhirFamily<L>>>,
}
impl<A, L> Clone for BinaryNativePolyWhirAuthority<A, L>
where
    L: BinaryNativePolyWhirLayout,
{
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}

pub struct BinaryNativePolyWhirProver<A, L = SuffixProver<Poly64, Poly192>>
where
    L: BinaryNativePolyWhirLayout,
{
    state: Arc<State<Poly64, Poly192, A, PolyWhirFamily<L>>>,
    key: ProvingKey<BinaryNativePolyWhirConfig<L>>,
}

/// Minted only after bounded replay and complete retained native verification.
pub struct VerifiedBinaryNativePolyWhirProof {
    pub(crate) identity: Arc<[u8]>,
    pub(crate) input: NativeBinaryPolyWhirMultiStarkInput,
    pub(crate) public: Vec<Vec<Poly64>>,
}
impl VerifiedBinaryNativePolyWhirProof {
    pub fn canonical_verifier_bytes(&self) -> &[u8] {
        &self.identity
    }
    pub const fn native_input(&self) -> &NativeBinaryPolyWhirMultiStarkInput {
        &self.input
    }
    pub fn public_values(&self) -> &[Vec<Poly64>] {
        &self.public
    }
}

impl<A, L> BinaryNativePolyWhirAuthority<A, L>
where
    L: BinaryNativePolyWhirLayout,
    A: VerifierAir<Poly64, Poly192>,
{
    pub fn setup(
        airs: Vec<A>,
        heights: Vec<usize>,
        spec: BinaryNativeVerifierSpec<BinaryNativePolyWhirPcsParameters>,
        limits: &VerifierLimits,
    ) -> Result<(BinaryNativePolyWhirProver<A, L>, Self), VerificationError> {
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
        spec: BinaryNativeVerifierSpec<BinaryNativePolyWhirPcsParameters>,
        limits: ArtifactLimits,
    ) -> Result<(BinaryNativePolyWhirProver<A, L>, Self), VerificationError> {
        let (state, proving) =
            lifecycle::setup::<Poly64, Poly192, A, PolyWhirFamily<L>>(airs, heights, spec, limits)?;
        Ok((
            BinaryNativePolyWhirProver {
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
    pub fn recursive_verifier(&self) -> &BinaryPolyWhirMultiStarkVerifier {
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
        proof: &MultiStarkProof<BinaryNativePolyWhirConfig<L>>,
        expected: &[Vec<Poly64>],
    ) -> Result<VerifiedBinaryNativePolyWhirProof, VerificationError> {
        let input = self.state.verify_native(proof, expected)?;
        Ok(VerifiedBinaryNativePolyWhirProof {
            identity: self.state.identity.clone(),
            input,
            public: expected.to_vec(),
        })
    }
}
impl<A, L> BinaryNativePolyWhirProver<A, L>
where
    L: BinaryNativePolyWhirLayout,
    A: VerifierAir<Poly64, Poly192>
        + for<'a> p3_air::Air<p3_multi_stark::folder::MultilinearFolder<'a, Poly64, Poly64, Poly192>>
        + for<'a> p3_air::Air<
            p3_multi_stark::folder::MultilinearFolder<
                'a,
                Poly64,
                p3_multi_stark::packed_ext::PackedExt<Poly64, Poly192>,
                p3_multi_stark::packed_ext::PackedExt<Poly64, Poly192>,
            >,
        > + for<'a> p3_air::Air<
            p3_multi_stark::folder::InteractionMultilinearFolder<'a, Poly64, Poly64, Poly192>,
        > + for<'a> p3_air::Air<
            p3_multi_stark::folder::InteractionMultilinearFolder<
                'a,
                Poly64,
                p3_multi_stark::packed_ext::PackedExt<Poly64, Poly192>,
                p3_multi_stark::packed_ext::PackedExt<Poly64, Poly192>,
            >,
        >,
{
    /// Ordinary row-major AIR traces. Trusted shapes are checked before
    /// commitment or any native transcript mutation.
    pub fn prove(
        &self,
        public: &[Vec<Poly64>],
        traces: Vec<RowMajorMatrix<Poly64>>,
    ) -> Result<MultiStarkProof<BinaryNativePolyWhirConfig<L>>, VerificationError> {
        self.state.prove(&self.key, public, traces)
    }
}
