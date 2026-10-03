//! Bounded grouped proof bytes, authenticated under retained native authority.
use super::super::{
    BinaryNativeGroupedAuthority, BinaryNativeGroupedConfig, VerifiedBinaryNativeGroupedProof,
};
use super::*;
use p3_binary_pcs::GroupedCodewordMmcs;

type GroupedTree<F> = GroupedCodewordMmcs<NativeMmcs<F>>;
type GroupedPcsProof<F, E> = BinaryPcsProof<F, E, GroupedTree<F>, GroupedTree<E>>;

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
    pub fn encode_statement(&self, public: &[Vec<F>]) -> Result<Vec<u8>, ArtifactError> {
        self.state
            .check_public(public)
            .map_err(|_| ArtifactError::VerificationRejected)?;
        let mut writer = Writer::new(self.state.limits.max_proof_bytes);
        write_public(&mut writer, public)?;
        writer.finish()
    }

    /// Encoding accepts a proof only after the same complete native checks used
    /// for imports. Its geometry cannot silently alter the fixed wire layout.
    pub fn encode_native_proof(
        &self,
        proof: &MultiStarkProof<BinaryNativeGroupedConfig<F, E>>,
        public: &[Vec<F>],
    ) -> Result<Vec<u8>, ArtifactError> {
        self.verify_native(proof, public)
            .map_err(|_| ArtifactError::VerificationRejected)?;
        encode_multi::<BinaryNativeGroupedConfig<F, E>>(
            proof,
            public,
            suite::<F, E>() | 0x100,
            &self.state.limits,
            write_grouped_pcs::<F, E>,
        )
    }

    /// Match both the application trust anchor and this factory's retained
    /// identity before decoding any statement or proof-dependent allocation.
    /// Attached public values are compared to the independent statement, then
    /// bounded transcript replay and full native authentication mint the token.
    pub fn decode_and_verify(
        &self,
        candidate: &[u8],
        expected: ExpectedVerifierArtifact<'_>,
        proof_bytes: &[u8],
        statement: CanonicalBinaryStatement<'_>,
    ) -> Result<VerifiedBinaryNativeGroupedProof<F, E>, ArtifactError> {
        let authority = DecodeAuthority {
            identity: &self.state.identity,
            shape: &self.state.decode,
            limits: &self.state.limits,
            usage: self.state.binary.input_resource_usage(),
            suite: (suite::<F, E>() | 0x100),
        };
        let (proof, public) = authority.decode::<BinaryNativeGroupedConfig<F, E>>(
            candidate,
            expected,
            proof_bytes,
            statement,
            read_grouped_pcs::<F, E>,
        )?;
        self.verify_native(&proof, &public)
            .map_err(|_| ArtifactError::VerificationRejected)
    }
}

fn write_grouped_pcs<F, E>(w: &mut Writer, p: &GroupedPcsProof<F, E>) -> Result<(), ArtifactError>
where
    F: RecursiveBinaryTowerField + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField + PackedValue<Value = E>,
{
    write_pcs_with(w, p, grouped_shell::write::<F>, grouped_shell::write::<E>)
}
fn read_grouped_pcs<F, E>(
    r: &mut Reader<'_>,
    s: &PcsDecode<GroupedOracleDecode>,
    total: &mut usize,
) -> Result<GroupedPcsProof<F, E>, ArtifactError>
where
    F: RecursiveBinaryTowerField + PackedValue<Value = F>,
    E: RecursiveBinaryChallengeField + PackedValue<Value = E>,
{
    read_pcs_with::<F, E, GroupedTree<F>, GroupedTree<E>, _>(
        r,
        s,
        total,
        grouped_shell::read::<F>,
        grouped_shell::read::<E>,
    )
}
