//! Prepared binary MultiStark circuits with an independent prime output field.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

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

use super::prover::{PreparedProver, prepare_prover_from_parts};
use crate::artifact::{BinaryNativeAuthority, VerifiedBinaryNativeProof};
use crate::pcs::binary::{RecursiveBinaryChallengeField, RecursiveBinaryTowerField};
use crate::verifier::{
    BinaryMultiStarkInputShape, BinaryMultiStarkVerifier, InputResourceUsage,
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
    binary: BinaryMultiStarkVerifier<F, E>,
    shape: BinaryMultiStarkInputShape<F, E>,
    layout: BinaryStatementLayout<F>,
    circuit: Circuit<SC::Challenge>,
    prepared: PreparedProver<SC>,
    params: ProveNextLayerParams,
    native_identity: Option<Arc<[u8]>>,
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
        layer.native_identity = Some(authority.shared_identity());
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
        if D != <SC::Challenge as BasedVectorSpace<Val<SC>>>::DIMENSION {
            return Err(invalid("binary prepared circuit extension degree mismatch"));
        }
        let mut usage = binary.input_resource_usage();
        usage.check(limits)?;
        usage.add_metadata_entries(limits, initial_bytes.len())?;
        let shape = binary.input_shape();
        let counts: Vec<_> = shape.public_value_counts().collect();
        let layout = BinaryStatementLayout::<F>::with_limits(&counts, limits)?;
        usage.add_metadata_entries(limits, layout.schema.base_len())?;
        let mut b = CircuitBuilder::<SC::Challenge>::new();
        // Main PCS, preprocessing PCS and transcript hashes are independently
        // configured. Register both closed byte-hash implementations.
        b.enable_keccak_f1600::<Val<SC>>();
        b.enable_blake3_compress::<Val<SC>>();
        let mut original_limbs = Vec::with_capacity(layout.schema.base_len());
        let public = counts
            .iter()
            .map(|&count| {
                (0..count)
                    .map(|_| {
                        let limbs = core::array::from_fn(|_| b.public_input());
                        original_limbs.extend(limbs);
                        b.binary128_from_limbs::<Val<SC>>(limbs)
                            .map_err(VerificationError::from)
                    })
                    .collect::<Result<Vec<_>, _>>()
            })
            .collect::<Result<Vec<_>, _>>()?;
        let targets = shape.allocate_targets::<Val<SC>, SC::Challenge>(&mut b)?;
        let initial = initial_bytes
            .iter()
            .map(|&byte| b.define_const(SC::Challenge::from_u8(byte)))
            .collect::<Vec<_>>();
        let ch = BinaryTower128Challenger::with_initial_bytes::<Val<SC>, SC::Challenge>(
            &mut b, hash, &initial,
        )?;
        let _completion = binary.verify::<Val<SC>, SC::Challenge>(&mut b, ch, &public, &targets)?;
        // SAFETY: These are the exact original limb IDs used above to build
        // each AIR public value consumed by the complete binary verifier.
        // The layout fixes their instance/value/limb order and Base encoding.
        unsafe {
            VerifiedStatementTargets::new_unchecked(&b, layout.schema.clone(), original_limbs)
        }?
        .install::<Val<SC>>(&mut b)?;
        let circuit = b.build()?;
        let mut preprocessors: Vec<Box<dyn NpoPreprocessor<Val<SC>>>> = vec![
            Box::new(KeccakF1600Preprocessor),
            Box::new(Blake3CompressPreprocessor),
        ];
        let mut builders: Vec<Box<dyn NpoAirBuilder<SC, D>>> = vec![
            Box::new(KeccakF1600AirBuilder::<D>),
            Box::new(Blake3CompressAirBuilder::<D>),
        ];
        let mut provers: Vec<Box<dyn TableProver<SC>>> = vec![
            Box::new(KeccakF1600Prover::<D>),
            Box::new(Blake3CompressProver::<D>),
        ];
        if layout.schema.base_len() != 0 {
            preprocessors.push(Box::new(StatementPreprocessor::new(layout.schema.clone())));
            builders.push(Box::new(StatementAirBuilder::<D>::new(
                layout.schema.clone(),
            )));
            provers.push(Box::new(StatementProver::<D>::new(layout.schema.clone())));
        }
        let prepared = prepare_prover_from_parts::<SC, D>(
            &circuit,
            &output_config,
            &params,
            &preprocessors,
            &builders,
            provers,
        )?;
        Ok(Self {
            binary,
            shape,
            layout,
            circuit,
            prepared,
            params,
            native_identity: None,
        })
    }

    pub fn binary_verifier(&self) -> &BinaryMultiStarkVerifier<F, E> {
        &self.binary
    }
    pub fn native_verifier_identity(&self) -> Option<&[u8]> {
        self.native_identity.as_deref()
    }
    pub fn statement_layout(&self) -> &BinaryStatementLayout<F> {
        &self.layout
    }
    pub fn params(&self) -> &ProveNextLayerParams {
        &self.params
    }
    pub fn verifier(&self) -> CircuitVerifier<SC> {
        self.prepared.verifier()
    }

    pub fn prove(
        &self,
        input: &NativeBinaryMultiStarkInput<F, E>,
        public: &[Vec<F>],
    ) -> Result<RecursionOutput<SC>, VerificationError>
    where
        p3_batch_stark::BatchProof<SC>: ProvingMaybeSend,
    {
        let public: Vec<_> = self
            .layout
            .pack::<Val<SC>>(public)?
            .into_iter()
            .map(SC::Challenge::from)
            .collect();
        let private = input.private_values::<SC::Challenge>(&self.shape)?;
        let mut runner = self.circuit.runner();
        runner.set_public_inputs(&public)?;
        runner.set_private_inputs(&private)?;
        let traces = runner.run()?;
        self.prepared.prove(&traces)
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
        if self.native_identity.as_deref() != Some(&*proof.identity) {
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
