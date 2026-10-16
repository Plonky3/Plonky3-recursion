//! Trusted-shape bounded dense and packed-bit Poly64 WHIR proof bytes.
use p3_binary_field::{Poly64, Poly192};

use super::super::family::PolyMixedWhirFamily;
use super::super::{
    BinaryNativePolyMixedWhirAuthority, BinaryNativePolyMixedWhirConfig,
    VerifiedBinaryNativePolyMixedWhirProof,
};
use super::*;
use crate::artifact::binary_native::family::NativeFamily;

fn suite() -> u16 {
    <PolyMixedWhirFamily as NativeFamily<Poly64, Poly192>>::suite()
}

impl<A: VerifierAir<Poly64, Poly192>> BinaryNativePolyMixedWhirAuthority<A> {
    pub fn encode_statement(&self, public: &[Vec<Poly64>]) -> Result<Vec<u8>, ArtifactError> {
        self.state
            .check_public(public)
            .map_err(|_| ArtifactError::VerificationRejected)?;
        let mut writer = Writer::new(self.state.limits.max_proof_bytes);
        write_public(&mut writer, public)?;
        writer.finish()
    }
    /// Full retained native verification precedes encoding. The main cap carries the dense
    /// roots, then the packed roots, at the exact count the decoder reads back.
    pub fn encode_native_proof(
        &self,
        proof: &MultiStarkProof<BinaryNativePolyMixedWhirConfig>,
        public: &[Vec<Poly64>],
    ) -> Result<Vec<u8>, ArtifactError> {
        self.verify_native(proof, public)
            .map_err(|_| ArtifactError::VerificationRejected)?;
        encode_multi::<BinaryNativePolyMixedWhirConfig>(
            proof,
            public,
            suite(),
            &self.state.limits,
            mixed_whir::write_mixed_with::<Poly64, Poly192>,
        )
    }
    /// Trust anchors and the independent statement are checked before proof decoding. Main and
    /// preprocessing openings share one allocation and frontier budget.
    pub fn decode_and_verify(
        &self,
        candidate: &[u8],
        expected: ExpectedVerifierArtifact<'_>,
        proof_bytes: &[u8],
        statement: CanonicalBinaryStatement<'_>,
    ) -> Result<VerifiedBinaryNativePolyMixedWhirProof, ArtifactError> {
        let authority = DecodeAuthority {
            identity: &self.state.identity,
            shape: &self.state.decode,
            limits: &self.state.limits,
            usage: self.state.binary.verifier.input_resource_usage(),
            suite: suite(),
        };
        let (proof, public) = authority.decode::<BinaryNativePolyMixedWhirConfig>(
            candidate,
            expected,
            proof_bytes,
            statement,
            mixed_whir::read_mixed_with::<Poly64, Poly192>,
        )?;
        self.verify_native(&proof, &public)
            .map_err(|_| ArtifactError::VerificationRejected)
    }
}
