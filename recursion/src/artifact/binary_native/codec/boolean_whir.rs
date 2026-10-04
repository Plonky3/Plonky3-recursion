//! Trusted-shape bounded trace and bit-ring WHIR proof bytes.
use p3_binary_field::BinaryField128;
use p3_binary_pcs::BooleanTraceCommitmentProof;
use p3_binary_pcs::whir::BooleanWhirProof;

use super::super::{
    BinaryNativeBooleanWhirTraceAuthority, BinaryNativeBooleanWhirTraceConfig,
    VerifiedBinaryNativeBooleanWhirTraceProof,
};
use super::*;
type E = BinaryField128;

type TraceProof = BooleanTraceCommitmentProof<E, BooleanWhirProof<E, NativeMmcs<E>>>;

impl<A: VerifierAir<E, E>> BinaryNativeBooleanWhirTraceAuthority<A> {
    pub fn encode_statement(&self, public: &[Vec<E>]) -> Result<Vec<u8>, ArtifactError> {
        self.state
            .check_public(public)
            .map_err(|_| ArtifactError::VerificationRejected)?;
        let mut writer = Writer::new(self.state.limits.max_proof_bytes);
        write_public(&mut writer, public)?;
        writer.finish()
    }
    /// Full retained native verification precedes encoding, including the
    /// exact routed ring round count and its required empty grinding vector.
    pub fn encode_native_proof(
        &self,
        proof: &MultiStarkProof<BinaryNativeBooleanWhirTraceConfig>,
        public: &[Vec<E>],
    ) -> Result<Vec<u8>, ArtifactError> {
        self.verify_native(proof, public)
            .map_err(|_| ArtifactError::VerificationRejected)?;
        encode_multi::<BinaryNativeBooleanWhirTraceConfig>(
            proof,
            public,
            suite::<E, E>() | 0x500,
            &self.state.limits,
            write_trace,
        )
    }
    /// Trust anchors and the independent statement are checked before proof
    /// decoding. Main and preprocessing share one allocation/frontier budget.
    pub fn decode_and_verify(
        &self,
        candidate: &[u8],
        expected: ExpectedVerifierArtifact<'_>,
        proof_bytes: &[u8],
        statement: CanonicalBinaryStatement<'_>,
    ) -> Result<VerifiedBinaryNativeBooleanWhirTraceProof, ArtifactError> {
        let authority = DecodeAuthority {
            identity: &self.state.identity,
            shape: &self.state.decode,
            limits: &self.state.limits,
            usage: self.state.binary.input_resource_usage(),
            suite: suite::<E, E>() | 0x500,
        };
        let (proof, public) = authority.decode::<BinaryNativeBooleanWhirTraceConfig>(
            candidate,
            expected,
            proof_bytes,
            statement,
            read_trace,
        )?;
        self.verify_native(&proof, &public)
            .map_err(|_| ArtifactError::VerificationRejected)
    }
}

fn write_trace(w: &mut Writer, p: &TraceProof) -> Result<(), ArtifactError> {
    write_fields(w, &p.values)?;
    grouped_boolean::write_ring(w, &p.opening.reduction)?;
    whir::write_whir(w, &p.opening.opening)
}
fn read_trace(
    r: &mut Reader<'_>,
    s: &BooleanTraceDecode<WhirDecode>,
    total: &mut usize,
) -> Result<TraceProof, ArtifactError> {
    Ok(BooleanTraceCommitmentProof {
        values: read_fields(r, s.value_count)?,
        opening: BooleanWhirProof {
            reduction: grouped_boolean::read_ring(r, &s.ring)?,
            opening: whir::read_whir(r, &s.packed, total)?,
        },
    })
}
