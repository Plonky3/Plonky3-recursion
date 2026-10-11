//! Factory-owned native proofs over a dense Poly64 WHIR commitment and one packed-bit table
//! commitment, and checked recursion input.
use p3_binary_field::{Poly64, Poly192};
use p3_sumcheck::layout::Table;

use super::config::{BinaryNativePolyMixedWhirConfig, BinaryNativePolyMixedWhirPcsParameters};
use super::family::PolyMixedWhirFamily;
use super::*;
use crate::verifier::{
    BinaryPolyMixedWhirMultiStarkVerifier, NativeBinaryPolyMixedWhirMultiStarkInput,
};

/// Trusted AIRs, matched native key, and the exact dense and packed-bit commitment relation.
///
/// The one AIR that assumes a Boolean trace is the table the main commitment stores as bits;
/// setup refuses any other pairing of AIRs and commitment.
pub struct BinaryNativePolyMixedWhirAuthority<A> {
    pub(super) state: Arc<State<Poly64, Poly192, A, PolyMixedWhirFamily>>,
}
impl<A> Clone for BinaryNativePolyMixedWhirAuthority<A> {
    fn clone(&self) -> Self {
        Self {
            state: self.state.clone(),
        }
    }
}
pub struct BinaryNativePolyMixedWhirProver<A> {
    state: Arc<State<Poly64, Poly192, A, PolyMixedWhirFamily>>,
    key: ProvingKey<BinaryNativePolyMixedWhirConfig>,
}
/// Minted only after bounded replay and complete retained native verification.
pub struct VerifiedBinaryNativePolyMixedWhirProof {
    pub(crate) identity: Arc<[u8]>,
    pub(crate) input: NativeBinaryPolyMixedWhirMultiStarkInput,
    pub(crate) public: Vec<Vec<Poly64>>,
}
impl VerifiedBinaryNativePolyMixedWhirProof {
    pub fn canonical_verifier_bytes(&self) -> &[u8] {
        &self.identity
    }
    pub const fn native_input(&self) -> &NativeBinaryPolyMixedWhirMultiStarkInput {
        &self.input
    }
    pub fn public_values(&self) -> &[Vec<Poly64>] {
        &self.public
    }
}
impl<A: VerifierAir<Poly64, Poly192>> BinaryNativePolyMixedWhirAuthority<A> {
    pub fn setup(
        airs: Vec<A>,
        heights: Vec<usize>,
        spec: BinaryNativeVerifierSpec<BinaryNativePolyMixedWhirPcsParameters>,
        limits: &VerifierLimits,
    ) -> Result<(BinaryNativePolyMixedWhirProver<A>, Self), VerificationError> {
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
        spec: BinaryNativeVerifierSpec<BinaryNativePolyMixedWhirPcsParameters>,
        limits: ArtifactLimits,
    ) -> Result<(BinaryNativePolyMixedWhirProver<A>, Self), VerificationError> {
        let (state, key) = lifecycle::setup::<Poly64, Poly192, A, PolyMixedWhirFamily>(
            airs, heights, spec, limits,
        )?;
        Ok((
            BinaryNativePolyMixedWhirProver {
                state: state.clone(),
                key,
            },
            Self { state },
        ))
    }
    pub fn canonical_verifier_bytes(&self) -> &[u8] {
        &self.state.identity
    }
    pub fn artifact_limits(&self) -> &ArtifactLimits {
        &self.state.limits
    }
    /// Every assessed security term of the trusted statement, as setup checked it against the
    /// spec's `security_bits`.
    pub fn security_report(&self) -> &MultiStarkSecurityReport {
        &self.state.security
    }
    pub fn recursive_verifier(&self) -> &BinaryPolyMixedWhirMultiStarkVerifier {
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
        proof: &MultiStarkProof<BinaryNativePolyMixedWhirConfig>,
        expected: &[Vec<Poly64>],
    ) -> Result<VerifiedBinaryNativePolyMixedWhirProof, VerificationError> {
        let input = self.state.verify_native(proof, expected)?;
        Ok(VerifiedBinaryNativePolyMixedWhirProof {
            identity: self.state.identity.clone(),
            input,
            public: expected.to_vec(),
        })
    }
}
impl<A: ProverAir<Poly64, Poly192>> BinaryNativePolyMixedWhirProver<A> {
    /// Main tables in AIR order: field cells, or packed bits for the bit-committed table.
    /// Trusted shapes are checked before commitment or any native transcript mutation, and the
    /// commitment refuses a non-bit cell of the bit-committed table before it binds anything.
    /// A statement with indexed lookups reads every table as field cells, so it refuses packed
    /// bits.
    pub fn prove_tables(
        &self,
        public: &[Vec<Poly64>],
        tables: Vec<Table<Poly64>>,
    ) -> Result<MultiStarkProof<BinaryNativePolyMixedWhirConfig>, VerificationError> {
        if self.state.decode.indexed.is_some()
            && tables.iter().any(|table| table.packed_bits().is_some())
        {
            return Err(invalid(
                "binary native mixed WHIR indexed lookups read no packed-bit table",
            ));
        }
        self.state.prove_tables(&self.key, public, tables)
    }
}
