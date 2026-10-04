//! Prepared binary MultiStark circuits with an independent prime output field.

mod boolean;
mod boolean_whir;
pub use boolean_whir::PreparedBinaryBooleanWhirTraceMultiStarkLayer;
mod grouped_boolean;
mod lifecycle;
mod statement;
pub use statement::BinaryPolyStatementLayout;
mod poly_whir;
pub use poly_whir::PreparedBinaryPolyWhirMultiStarkLayer;
mod whir;
use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

pub use boolean::PreparedBinaryBooleanTraceMultiStarkLayer;
pub use grouped_boolean::PreparedBinaryGroupedBooleanTraceMultiStarkLayer;
use lifecycle::BinaryPreparedCore;
use p3_air::{SymbolicExpression, SymbolicExpressionExt};
use p3_binary_dft::EncodableLevel;
use p3_binary_field::BinaryField128;
use p3_binary_pcs::{ChallengeField, FoldAlphabet};
use p3_circuit::ops::ByteHash;
use p3_circuit::{
    Circuit, CircuitBuilder, StatementField, StatementSchema, VerifiedStatementTargets,
};
use p3_circuit_prover::CircuitVerifier;
use p3_circuit_prover::batch_stark_prover::{
    Blake3CompressAirBuilder, Blake3CompressPreprocessor, Blake3CompressProver,
    KeccakF1600AirBuilder, KeccakF1600Preprocessor, KeccakF1600Prover, ProvingMaybeSend,
    StatementAirBuilder, StatementPreprocessor, StatementProver, TableProver,
};
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::config::StarkField;
use p3_circuit_prover::field_params::ExtractBinomialW;
use p3_commit::Pcs;
use p3_field::{
    Algebra, BasedVectorSpace, ExtensionField, PackedValue, PrimeCharacteristicRing, PrimeField64,
};
use p3_multi_stark::folder::VerifierAir;
use p3_uni_stark::{StarkGenericConfig, Val};
pub use whir::PreparedBinaryWhirMultiStarkLayer;

use super::prover::{PreparedProver, prepare_prover_from_parts};
use crate::artifact::{
    BinaryNativeAuthority, BinaryNativeGroupedAuthority, VerifiedBinaryNativeGroupedProof,
    VerifiedBinaryNativeProof,
};
use crate::pcs::binary::{RecursiveBinaryChallengeField, RecursiveBinaryTowerField};
use crate::verifier::{
    BinaryGroupedMultiStarkInputShape, BinaryGroupedMultiStarkVerifier, BinaryMultiStarkInputShape,
    BinaryMultiStarkVerifier, InputResourceUsage, NativeBinaryGroupedMultiStarkInput,
    NativeBinaryMultiStarkInput, VerificationError, VerifierLimits,
};
use crate::{BinaryTower128Challenger, ProveNextLayerParams, RecursionOutput};

/// AIR order, then public-value order, then eight little-endian u16 limbs.
/// Native values in narrower tower fields are zero-extended to this encoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BinaryStatementLayout<F = BinaryField128> {
    counts: Vec<usize>,
    schema: StatementSchema,
    field: PhantomData<F>,
}

impl<F: RecursiveBinaryTowerField> BinaryStatementLayout<F> {
    pub fn with_limits(
        counts: &[usize],
        limits: &VerifierLimits,
    ) -> Result<Self, VerificationError> {
        let mut usage = InputResourceUsage::default();
        usage.add_instances(limits, counts.len())?;
        usage.add_metadata_entries(limits, counts.len())?;
        let fields = counts
            .iter()
            .try_fold(0usize, |total, &count| total.checked_add(count))
            .ok_or(VerificationError::ResourceArithmeticOverflow {
                component: "binary statement fields",
            })?;
        let limbs = fields
            .checked_mul(8)
            .ok_or(VerificationError::ResourceArithmeticOverflow {
                component: "binary statement limbs",
            })?;
        usage.add_scalar_elements(limits, limbs)?;
        usage.add_metadata_entries(limits, limbs)?;
        if limbs != 0 {
            usage.check_matrix_width(
                limits,
                limbs
                    .checked_add(1)
                    .ok_or(VerificationError::ResourceArithmeticOverflow {
                        component: "binary statement table width",
                    })?,
            )?;
        }
        let schema = StatementSchema::try_new(vec![StatementField::Base; limbs])
            .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
        Ok(Self {
            counts: counts.to_vec(),
            schema,
            field: PhantomData,
        })
    }

    pub fn public_value_counts(&self) -> &[usize] {
        &self.counts
    }
    pub fn schema(&self) -> &StatementSchema {
        &self.schema
    }
    pub const fn field_bits(&self) -> usize {
        F::RAW_BITS
    }

    pub fn pack<OF: PrimeField64>(&self, public: &[Vec<F>]) -> Result<Vec<OF>, VerificationError> {
        if public.len() != self.counts.len()
            || public
                .iter()
                .zip(&self.counts)
                .any(|(values, &count)| values.len() != count)
        {
            return Err(invalid("binary prepared public value shape mismatch"));
        }
        if OF::ORDER_U64 <= u16::MAX as u64 {
            return Err(invalid(
                "binary statement host field cannot encode u16 limbs",
            ));
        }
        Ok(public
            .iter()
            .flatten()
            .flat_map(|value| {
                let raw = value.raw_coordinates();
                (0..8).map(move |i| OF::from_u16((raw >> (16 * i)) as u16))
            })
            .collect())
    }
}

/// Owns one trusted binary relation and its prepared prime-field prover.
/// Construction uses only the trusted plan and transcript configuration;
/// proving accepts bounded witness material and the original binary statement.
pub struct PreparedBinaryMultiStarkLayer<F, E, SC: StarkGenericConfig + 'static, const D: usize> {
    core: BinaryPreparedCore<
        F,
        E,
        SC,
        D,
        BinaryMultiStarkVerifier<F, E>,
        BinaryMultiStarkInputShape<F, E>,
    >,
}

impl<F, E, SC, const D: usize> PreparedBinaryMultiStarkLayer<F, E, SC, D>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
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
    /// Prepare directly from factory-owned native authority. The exact native
    /// relation identity and transcript configuration are retained independently
    /// of every proof, enabling checked token reuse through `prove_verified`.
    pub fn from_native_authority<A>(
        authority: &BinaryNativeAuthority<F, E, A>,
        output_config: SC,
        params: ProveNextLayerParams,
    ) -> Result<Self, VerificationError>
    where
        F: EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
        E: ChallengeField<F> + FoldAlphabet<E> + PackedValue<Value = E>,
        A: VerifierAir<F, E>,
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
        binary: BinaryMultiStarkVerifier<F, E>,
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
        binary: BinaryMultiStarkVerifier<F, E>,
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

    pub fn binary_verifier(&self) -> &BinaryMultiStarkVerifier<F, E> {
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
        input: &NativeBinaryMultiStarkInput<F, E>,
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
        proof: &VerifiedBinaryNativeProof<F, E>,
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

/// Owns one trusted binary relation and its prepared prime-field prover.
/// Construction uses only the trusted plan and transcript configuration;
/// proving accepts bounded witness material and the original binary statement.
pub struct PreparedBinaryGroupedMultiStarkLayer<
    F,
    E,
    SC: StarkGenericConfig + 'static,
    const D: usize,
> {
    core: BinaryPreparedCore<
        F,
        E,
        SC,
        D,
        BinaryGroupedMultiStarkVerifier<F, E>,
        BinaryGroupedMultiStarkInputShape<F, E>,
    >,
}

impl<F, E, SC, const D: usize> PreparedBinaryGroupedMultiStarkLayer<F, E, SC, D>
where
    F: RecursiveBinaryTowerField,
    E: RecursiveBinaryChallengeField + ExtensionField<F>,
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
    /// Retain the factory's exact grouped relation identity and transcript for
    /// proving with independently verified native tokens.
    pub fn from_native_authority<A>(
        authority: &BinaryNativeGroupedAuthority<F, E, A>,
        output_config: SC,
        params: ProveNextLayerParams,
    ) -> Result<Self, VerificationError>
    where
        F: EncodableLevel + FoldAlphabet<E> + PackedValue<Value = F>,
        E: ChallengeField<F> + FoldAlphabet<E> + PackedValue<Value = E>,
        A: VerifierAir<F, E>,
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
        binary: BinaryGroupedMultiStarkVerifier<F, E>,
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
        binary: BinaryGroupedMultiStarkVerifier<F, E>,
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

    pub fn binary_verifier(&self) -> &BinaryGroupedMultiStarkVerifier<F, E> {
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
        input: &NativeBinaryGroupedMultiStarkInput<F, E>,
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
        proof: &VerifiedBinaryNativeGroupedProof<F, E>,
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

fn invalid(message: &'static str) -> VerificationError {
    VerificationError::InvalidProofShape(message.into())
}
