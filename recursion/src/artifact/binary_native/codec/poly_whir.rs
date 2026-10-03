//! Retained polynomial WHIR proof authority and coefficient wire encoding.
use super::super::{
    BinaryNativePolyWhirAuthority, BinaryNativePolyWhirConfig, BinaryNativePolyWhirLayout,
    VerifiedBinaryNativePolyWhirProof,
};
use super::*;
use p3_binary_field::{Poly64, Poly192};

impl<A, L> BinaryNativePolyWhirAuthority<A, L>
where
    L: BinaryNativePolyWhirLayout,
    A: VerifierAir<Poly64, Poly192>,
{
    pub fn encode_statement(&self, public: &[Vec<Poly64>]) -> Result<Vec<u8>, ArtifactError> {
        self.state
            .check_public(public)
            .map_err(|_| ArtifactError::VerificationRejected)?;
        let mut writer = Writer::new(self.state.limits.max_proof_bytes);
        write_public(&mut writer, public)?;
        writer.finish()
    }
    pub fn encode_native_proof(
        &self,
        proof: &MultiStarkProof<BinaryNativePolyWhirConfig<L>>,
        public: &[Vec<Poly64>],
    ) -> Result<Vec<u8>, ArtifactError> {
        self.verify_native(proof, public)
            .map_err(|_| ArtifactError::VerificationRejected)?;
        encode_multi::<BinaryNativePolyWhirConfig<L>>(
            proof,
            public,
            0xba01,
            &self.state.limits,
            super::whir::write_whir_with::<Poly64, Poly192>,
        )
    }
    /// Match the application's independent identity and statement before bounded
    /// decoding, then perform complete verification under retained native keys.
    pub fn decode_and_verify(
        &self,
        candidate: &[u8],
        expected: ExpectedVerifierArtifact<'_>,
        proof_bytes: &[u8],
        statement: CanonicalBinaryStatement<'_>,
    ) -> Result<VerifiedBinaryNativePolyWhirProof, ArtifactError> {
        let authority = DecodeAuthority {
            identity: &self.state.identity,
            shape: &self.state.decode,
            limits: &self.state.limits,
            usage: self.state.binary.input_resource_usage(),
            suite: 0xba01,
        };
        let (proof, public) = authority.decode::<BinaryNativePolyWhirConfig<L>>(
            candidate,
            expected,
            proof_bytes,
            statement,
            super::whir::read_whir_with::<Poly64, Poly192>,
        )?;
        self.verify_native(&proof, &public)
            .map_err(|_| ArtifactError::VerificationRejected)
    }
}
