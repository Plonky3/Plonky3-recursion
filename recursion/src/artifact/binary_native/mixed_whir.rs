//! Factory-owned native proofs over a dense WHIR commitment and one packed-bit table
//! commitment, and checked recursion input.
use p3_air::Air;
use p3_binary_field::BinaryField128;
use p3_multi_stark::folder::{InteractionMultilinearFolder, MultilinearFolder};
use p3_multi_stark::packed_ext::PackedExt;
use p3_sumcheck::layout::Table;

use super::config::{BinaryNativeMixedWhirConfig, BinaryNativeMixedWhirPcsParameters};
use super::family::MixedWhirFamily;
use super::*;
use crate::verifier::{BinaryMixedWhirMultiStarkVerifier, NativeBinaryMixedWhirMultiStarkInput};
type E = BinaryField128;

/// Trusted AIRs, matched native key, and the exact dense and packed-bit commitment relation.
///
/// The one AIR that assumes a Boolean trace is the table the main commitment stores as bits;
/// setup refuses any other pairing of AIRs and commitment.
pub struct BinaryNativeMixedWhirAuthority<A> {
    pub(super) state: Arc<State<E, E, A, MixedWhirFamily>>,
}
impl<A> Clone for BinaryNativeMixedWhirAuthority<A> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}
pub struct BinaryNativeMixedWhirProver<A> {
    state: Arc<State<E, E, A, MixedWhirFamily>>,
    key: ProvingKey<BinaryNativeMixedWhirConfig>,
}
/// Minted only after bounded replay and complete retained native verification.
pub struct VerifiedBinaryNativeMixedWhirProof {
    pub(crate) identity: Arc<[u8]>,
    pub(crate) input: NativeBinaryMixedWhirMultiStarkInput,
    pub(crate) public: Vec<Vec<E>>,
}
impl VerifiedBinaryNativeMixedWhirProof {
    pub fn canonical_verifier_bytes(&self) -> &[u8] {
        &self.identity
    }
    pub const fn native_input(&self) -> &NativeBinaryMixedWhirMultiStarkInput {
        &self.input
    }
    pub fn public_values(&self) -> &[Vec<E>] {
        &self.public
    }
}
impl<A: VerifierAir<E, E>> BinaryNativeMixedWhirAuthority<A> {
    pub fn setup(
        airs: Vec<A>,
        heights: Vec<usize>,
        spec: BinaryNativeVerifierSpec<BinaryNativeMixedWhirPcsParameters>,
        limits: &VerifierLimits,
    ) -> Result<(BinaryNativeMixedWhirProver<A>, Self), VerificationError> {
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
        spec: BinaryNativeVerifierSpec<BinaryNativeMixedWhirPcsParameters>,
        limits: ArtifactLimits,
    ) -> Result<(BinaryNativeMixedWhirProver<A>, Self), VerificationError> {
        let (state, key) =
            lifecycle::setup::<E, E, A, MixedWhirFamily>(airs, heights, spec, limits)?;
        Ok((
            BinaryNativeMixedWhirProver {
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
    pub fn recursive_verifier(&self) -> &BinaryMixedWhirMultiStarkVerifier {
        &self.state.binary.verifier
    }
    pub fn transcript_hash(&self) -> ByteHash {
        self.state.spec.transcript_hash
    }
    pub fn initial_bytes(&self) -> &[u8] {
        &self.state.spec.initial_bytes
    }
    pub fn verify_native(
        &self,
        proof: &MultiStarkProof<BinaryNativeMixedWhirConfig>,
        expected: &[Vec<E>],
    ) -> Result<VerifiedBinaryNativeMixedWhirProof, VerificationError> {
        let input = self.state.verify_native(proof, expected)?;
        Ok(VerifiedBinaryNativeMixedWhirProof {
            identity: self.state.identity.clone(),
            input,
            public: expected.to_vec(),
        })
    }
}
impl<A> BinaryNativeMixedWhirProver<A>
where
    A: VerifierAir<E, E>
        + for<'a> Air<MultilinearFolder<'a, E, PackedExt<E, E>, PackedExt<E, E>>>
        + for<'a> Air<InteractionMultilinearFolder<'a, E, PackedExt<E, E>, PackedExt<E, E>>>,
{
    /// Main tables in AIR order: field cells, or packed bits for the bit-committed table.
    /// Trusted shapes are checked before commitment or any native transcript mutation, and the
    /// commitment refuses a non-bit cell of the bit-committed table before it binds anything.
    pub fn prove_tables(
        &self,
        public: &[Vec<E>],
        tables: Vec<Table<E>>,
    ) -> Result<MultiStarkProof<BinaryNativeMixedWhirConfig>, VerificationError> {
        self.state.prove_tables(&self.key, public, tables)
    }
}
