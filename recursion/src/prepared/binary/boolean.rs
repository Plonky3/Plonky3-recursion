//! Prepared prover for the complete ordinary Boolean trace MultiStark relation.

use core::hash::Hash;

use p3_circuit::ops::BinaryTower128Target;

use super::lifecycle::ClosedBinaryCircuit;
use super::*;
use crate::artifact::{BinaryNativeBooleanTraceAuthority, VerifiedBinaryNativeBooleanTraceProof};
use crate::verifier::{
    BinaryBooleanTraceMultiStarkInputShape, BinaryBooleanTraceMultiStarkProofTargets,
    BinaryBooleanTraceMultiStarkVerifier, NativeBinaryBooleanTraceMultiStarkInput,
};

impl<E> ClosedBinaryCircuit<E, E> for BinaryBooleanTraceMultiStarkVerifier<E>
where
    E: RecursiveBinaryChallengeField
        + ExtensionField<E>
        + p3_binary_pcs::ChallengeField<E>
        + p3_binary_pcs::FoldAlphabet<E>
        + p3_binary_pcs::Coordinates
        + serde::Serialize
        + serde::de::DeserializeOwned,
{
    type Statement = BinaryStatementLayout<E>;
    type Shape = BinaryBooleanTraceMultiStarkInputShape<E>;
    type Targets = BinaryBooleanTraceMultiStarkProofTargets<E>;
    type Input = NativeBinaryBooleanTraceMultiStarkInput<E>;
    fn usage(&self) -> InputResourceUsage {
        self.input_resource_usage()
    }
    fn shape(&self) -> Self::Shape {
        self.input_shape()
    }
    fn public_counts(shape: &Self::Shape) -> Vec<usize> {
        shape.public_value_counts().collect()
    }
    fn allocate_targets<BF, EF>(
        shape: &Self::Shape,
        b: &mut CircuitBuilder<EF>,
    ) -> Result<Self::Targets, VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        shape.allocate_targets::<BF, EF>(b)
    }
    fn verify_circuit<BF, EF>(
        &self,
        b: &mut CircuitBuilder<EF>,
        ch: BinaryTower128Challenger,
        public: &[Vec<BinaryTower128Target>],
        targets: &Self::Targets,
    ) -> Result<(), VerificationError>
    where
        BF: PrimeField64,
        EF: ExtensionField<BF> + Eq + Hash,
    {
        self.verify::<BF, EF>(b, ch, public, targets).map(|_| ())
    }
    fn private_values<EF: p3_field::Field>(
        input: &Self::Input,
        shape: &Self::Shape,
    ) -> Result<Vec<EF>, VerificationError> {
        input.private_values::<EF>(shape)
    }
}

/// Owns one trusted binary relation and its prepared prime-field prover.
/// Construction uses only the trusted plan and transcript configuration;
/// proving accepts bounded witness material and the original binary statement.
pub struct PreparedBinaryBooleanTraceMultiStarkLayer<
    E,
    SC: StarkGenericConfig + 'static,
    const D: usize,
> {
    core: BinaryPreparedCore<
        E,
        E,
        SC,
        D,
        BinaryBooleanTraceMultiStarkVerifier<E>,
        BinaryBooleanTraceMultiStarkInputShape<E>,
    >,
}

impl<E, SC, const D: usize> PreparedBinaryBooleanTraceMultiStarkLayer<E, SC, D>
where
    E: RecursiveBinaryChallengeField
        + ExtensionField<E>
        + p3_binary_pcs::ChallengeField<E>
        + p3_binary_pcs::FoldAlphabet<E>
        + p3_binary_pcs::Coordinates
        + serde::Serialize
        + serde::de::DeserializeOwned,
    SC: StarkGenericConfig + Send + Sync + Clone + 'static,
    Val<SC>: PrimeField64 + StarkField,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + ExtractBinomialW<Val<SC>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    SC::Challenger: p3_challenger::GrindingChallenger<Witness = Val<SC>>,
    p3_uni_stark::PcsProverError<SC>: Send,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain: Send + Sync,
    SC::Pcs: Sync,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::ProverData: Sync,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment: Sync,
    StatementPreprocessor: NpoPreprocessor<Val<SC>>,
    KeccakF1600Preprocessor: NpoPreprocessor<Val<SC>>,
    Blake3CompressPreprocessor: NpoPreprocessor<Val<SC>>,
{
    /// Retain the factory's exact ordinary relation identity and transcript for
    /// proving with independently verified native tokens.
    pub fn from_native_authority<A>(
        authority: &BinaryNativeBooleanTraceAuthority<E, A>,
        output_config: SC,
        params: ProveNextLayerParams,
    ) -> Result<Self, VerificationError>
    where
        E: EncodableLevel + PackedValue<Value = E>,
        A: VerifierAir<E, E>,
    {
        let mut layer = Self::with_limits(
            authority.recursive_verifier().clone(),
            authority.transcript_hash(),
            authority.initial_bytes(),
            output_config,
            params,
            &authority.artifact_limits().verifier,
        )?;
        layer.core.native_identity = Some(authority.shared_identity());
        Ok(layer)
    }

    pub fn new(
        binary: BinaryBooleanTraceMultiStarkVerifier<E>,
        hash: ByteHash,
        initial_bytes: &[u8],
        output_config: SC,
        params: ProveNextLayerParams,
    ) -> Result<Self, VerificationError> {
        Self::with_limits(
            binary,
            hash,
            initial_bytes,
            output_config,
            params,
            &VerifierLimits::default(),
        )
    }

    pub fn with_limits(
        binary: BinaryBooleanTraceMultiStarkVerifier<E>,
        hash: ByteHash,
        initial_bytes: &[u8],
        output_config: SC,
        params: ProveNextLayerParams,
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        Ok(Self {
            core: BinaryPreparedCore::with_limits(
                binary,
                hash,
                initial_bytes,
                output_config,
                params,
                limits,
            )?,
        })
    }

    pub fn binary_verifier(&self) -> &BinaryBooleanTraceMultiStarkVerifier<E> {
        &self.core.binary
    }
    pub fn native_verifier_identity(&self) -> Option<&[u8]> {
        self.core.native_identity.as_deref()
    }
    pub fn statement_layout(&self) -> &BinaryStatementLayout<E> {
        &self.core.layout
    }
    pub fn params(&self) -> &ProveNextLayerParams {
        &self.core.params
    }
    pub fn verifier(&self) -> CircuitVerifier<SC> {
        self.core.prepared.verifier()
    }

    pub fn prove(
        &self,
        input: &NativeBinaryBooleanTraceMultiStarkInput<E>,
        public: &[Vec<E>],
    ) -> Result<RecursionOutput<SC>, VerificationError>
    where
        p3_batch_stark::BatchProof<SC>: ProvingMaybeSend,
    {
        self.core.prove(input, public)
    }

    /// Check identity before statement packing or witness allocation, then use
    /// only the token's independently verified statement and retained input.
    pub fn prove_verified(
        &self,
        proof: &VerifiedBinaryNativeBooleanTraceProof<E>,
    ) -> Result<RecursionOutput<SC>, VerificationError>
    where
        p3_batch_stark::BatchProof<SC>: ProvingMaybeSend,
    {
        if self.core.native_identity.as_deref() != Some(&*proof.identity) {
            return Err(invalid(
                "binary verified input belongs to another native authority",
            ));
        }
        self.prove(&proof.input, &proof.public)
    }
}
