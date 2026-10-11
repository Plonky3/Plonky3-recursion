//! Trusted-shape bounded dense and packed-bit WHIR proof bytes.
use p3_binary_field::{BinaryField128, BitCoordinates};
use p3_challenger::fs::TranscriptField;

use super::super::config::{MixedWhirProof, NativeMixedWhirProof};
use super::super::{
    BinaryNativeMixedWhirAuthority, BinaryNativeMixedWhirConfig, VerifiedBinaryNativeMixedWhirProof,
};
use super::*;
type E = BinaryField128;

impl<A: VerifierAir<E, E>> BinaryNativeMixedWhirAuthority<A> {
    pub fn encode_statement(&self, public: &[Vec<E>]) -> Result<Vec<u8>, ArtifactError> {
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
        proof: &MultiStarkProof<BinaryNativeMixedWhirConfig>,
        public: &[Vec<E>],
    ) -> Result<Vec<u8>, ArtifactError> {
        self.verify_native(proof, public)
            .map_err(|_| ArtifactError::VerificationRejected)?;
        encode_multi::<BinaryNativeMixedWhirConfig>(
            proof,
            public,
            suite::<E, E>() | 0x600,
            &self.state.limits,
            write_mixed,
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
    ) -> Result<VerifiedBinaryNativeMixedWhirProof, ArtifactError> {
        let authority = DecodeAuthority {
            identity: &self.state.identity,
            shape: &self.state.decode,
            limits: &self.state.limits,
            usage: self.state.binary.verifier.input_resource_usage(),
            suite: suite::<E, E>() | 0x600,
        };
        let (proof, public) = authority.decode::<BinaryNativeMixedWhirConfig>(
            candidate,
            expected,
            proof_bytes,
            statement,
            read_mixed,
        )?;
        self.verify_native(&proof, &public)
            .map_err(|_| ArtifactError::VerificationRejected)
    }
}

fn write_mixed(w: &mut Writer, p: &MixedWhirProof) -> Result<(), ArtifactError> {
    write_mixed_with::<E, E>(w, p)
}
fn read_mixed(
    r: &mut Reader<'_>,
    s: &MixedWhirDecode,
    total: &mut usize,
) -> Result<MixedWhirProof, ArtifactError> {
    read_mixed_with::<E, E>(r, s, total)
}
pub(super) fn write_mixed_with<F, E>(
    w: &mut Writer,
    p: &NativeMixedWhirProof<F, E>,
) -> Result<(), ArtifactError>
where
    F: ScalarWire + BitCoordinates + PackedValue<Value = F> + TranscriptField,
    E: ScalarWire + BitCoordinates + ExtensionField<F>,
{
    whir::write_whir_with(w, &p.dense)?;
    if let Some(packed) = &p.packed {
        boolean_whir::write_trace_with(w, packed)?;
    }
    Ok(())
}
pub(super) fn read_mixed_with<F, E>(
    r: &mut Reader<'_>,
    s: &MixedWhirDecode,
    total: &mut usize,
) -> Result<NativeMixedWhirProof<F, E>, ArtifactError>
where
    F: ScalarWire + BitCoordinates + PackedValue<Value = F> + TranscriptField,
    E: ScalarWire + BitCoordinates + ExtensionField<F>,
{
    Ok(NativeMixedWhirProof {
        dense: whir::read_whir_with(r, &s.dense, total)?,
        packed: s
            .packed
            .as_ref()
            .map(|packed| boolean_whir::read_trace_with(r, packed, total))
            .transpose()?,
    })
}
