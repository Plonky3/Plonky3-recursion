//! Prepared prover for complete released additive WHIR MultiStark relations.

use super::lifecycle::ClosedBinaryCircuit;
use super::*;
use crate::artifact::{
    BinaryNativeWhirAuthority, BinaryNativeWhirLayout, VerifiedBinaryNativeWhirProof,
};
use crate::verifier::{
    BinaryWhirMultiStarkInputShape, BinaryWhirMultiStarkProofTargets, BinaryWhirMultiStarkVerifier,
    NativeBinaryWhirMultiStarkInput,
};
use core::hash::Hash;
use p3_circuit::ops::BinaryTower128Target;

impl<F> ClosedBinaryCircuit<F, BinaryField128> for BinaryWhirMultiStarkVerifier<F>
where
    F: crate::pcs::binary::RecursiveBinaryWhirTowerField,
    BinaryField128: ExtensionField<F>,
{
    type Shape = BinaryWhirMultiStarkInputShape<F>;
    type Targets = BinaryWhirMultiStarkProofTargets;
    type Input = NativeBinaryWhirMultiStarkInput<F>;
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
pub struct PreparedBinaryWhirMultiStarkLayer<F, SC: StarkGenericConfig + 'static, const D: usize> {
    core: BinaryPreparedCore<
        F,
        BinaryField128,
        SC,
        D,
        BinaryWhirMultiStarkVerifier<F>,
        BinaryWhirMultiStarkInputShape<F>,
    >,
}

impl<F, SC, const D: usize> PreparedBinaryWhirMultiStarkLayer<F, SC, D>
where
    F: crate::pcs::binary::RecursiveBinaryWhirTowerField,
    BinaryField128: ExtensionField<F>,
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
    /// Retain the factory's exact relation identity and transcript for proving
    /// with independently verified native tokens.
    pub fn from_native_authority<A, L>(
        authority: &BinaryNativeWhirAuthority<F, A, L>,
        output_config: SC,
        params: ProveNextLayerParams,
    ) -> Result<Self, VerificationError>
    where
        F: EncodableLevel + FoldAlphabet<BinaryField128> + PackedValue<Value = F> + Ord,
        BinaryField128: ChallengeField<F>,
        p3_binary_pcs::whir::BinaryWhirDomain<F>: p3_whir::WhirDomain<F, BinaryField128>,
        L: BinaryNativeWhirLayout<F>,
        A: VerifierAir<F, BinaryField128>,
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
        binary: BinaryWhirMultiStarkVerifier<F>,
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
        binary: BinaryWhirMultiStarkVerifier<F>,
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

    pub fn binary_verifier(&self) -> &BinaryWhirMultiStarkVerifier<F> {
        &self.core.binary
    }
    pub fn native_verifier_identity(&self) -> Option<&[u8]> {
        self.core.native_identity.as_deref()
    }
    pub fn statement_layout(&self) -> &BinaryStatementLayout<F> {
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
        input: &NativeBinaryWhirMultiStarkInput<F>,
        public: &[Vec<F>],
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
        proof: &VerifiedBinaryNativeWhirProof<F>,
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
