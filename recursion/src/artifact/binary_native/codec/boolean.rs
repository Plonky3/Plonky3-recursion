//! Trusted-shape bounded trace and bit-ring proof bytes.
use p3_binary_pcs::{BooleanProof, BooleanTraceCommitmentProof, BooleanTraceProof};

use super::super::{
    BinaryNativeBooleanTraceAuthority, BinaryNativeBooleanTraceConfig,
    VerifiedBinaryNativeBooleanTraceProof,
};
use super::*;

type TraceProof<E> = BooleanTraceProof<E, NativeMmcs<E>, NativeMmcs<E>>;

impl<E, A> BinaryNativeBooleanTraceAuthority<E, A>
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
        proof: &MultiStarkProof<BinaryNativeBooleanTraceConfig<E>>,
        public: &[Vec<E>],
    ) -> Result<Vec<u8>, ArtifactError> {
        self.verify_native(proof, public)
            .map_err(|_| ArtifactError::VerificationRejected)?;
        encode_multi::<BinaryNativeBooleanTraceConfig<E>>(
            proof,
            public,
            suite::<E, E>() | 0x300,
            &self.state.limits,
            write_trace::<E>,
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
    ) -> Result<VerifiedBinaryNativeBooleanTraceProof<E>, ArtifactError> {
        let authority = DecodeAuthority {
            identity: &self.state.identity,
            shape: &self.state.decode,
            limits: &self.state.limits,
            usage: self.state.binary.input_resource_usage(),
            suite: suite::<E, E>() | 0x300,
        };
        let (proof, public) = authority.decode::<BinaryNativeBooleanTraceConfig<E>>(
            candidate,
            expected,
            proof_bytes,
            statement,
            read_trace::<E>,
        )?;
        self.verify_native(&proof, &public)
            .map_err(|_| ArtifactError::VerificationRejected)
    }
}

fn write_trace<E>(w: &mut Writer, p: &TraceProof<E>) -> Result<(), ArtifactError>
where
    E: RecursiveBinaryChallengeField + PackedValue<Value = E>,
{
    write_fields(w, &p.values)?;
    grouped_boolean::write_ring(w, &p.opening.reduction)?;
    write_pcs(w, &p.opening.opening)
}
fn read_trace<E>(
    r: &mut Reader<'_>,
    s: &BooleanTraceDecode<PcsDecode<OracleDecode>>,
    total: &mut usize,
) -> Result<TraceProof<E>, ArtifactError>
where
    E: RecursiveBinaryChallengeField + PackedValue<Value = E>,
{
    Ok(BooleanTraceCommitmentProof {
        values: read_fields(r, s.value_count)?,
        opening: BooleanProof {
            reduction: grouped_boolean::read_ring(r, &s.ring)?,
            opening: read_pcs(r, &s.packed, total)?,
        },
    })
}
