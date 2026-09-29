use alloc::boxed::Box;
use alloc::vec::Vec;

use p3_air::{SymbolicExpression, SymbolicExpressionExt};
use p3_circuit::tables::Traces;
use p3_circuit::{Circuit, StatementSchema};
use p3_circuit_prover::batch_stark_prover::TableProver;
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::config::StarkField;
use p3_circuit_prover::field_params::ExtractBinomialW;
use p3_circuit_prover::{
    BatchStarkProverError, CircuitVerifier, PreparedCircuitProver, ProofMetadataError,
    StatementAirBuilder, StatementPreprocessor, StatementProver,
};
use p3_commit::Pcs;
use p3_field::{Algebra, BasedVectorSpace, ExtensionField, PrimeField64};
use p3_lookup::logup::LogUpGadget;
use p3_uni_stark::{StarkGenericConfig, Val};
use tracing::instrument;

use crate::recursion::{
    PcsRecursionBackend, ProveNextLayerParams, RecursionOutput, build_layer_prover,
};
use crate::traits::RecursiveAir;
use crate::verifier::VerificationError;

pub(crate) struct PreparedProver<SC: StarkGenericConfig + 'static> {
    prepared: PreparedCircuitProver<SC>,
}

impl<SC> PreparedProver<SC>
where
    p3_uni_stark::PcsProverError<SC>: Send,
    SC::Challenger: p3_challenger::GrindingChallenger<Witness = p3_uni_stark::Val<SC>>,
    SC: StarkGenericConfig + Send + Sync + Clone + 'static,
    Val<SC>: PrimeField64 + StarkField,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + ExtractBinomialW<Val<SC>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain: Send + Sync,
    SC::Pcs: Sync,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::ProverData: Sync,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment: Sync,
{
    pub(crate) fn prove(
        &self,
        traces: &Traces<SC::Challenge>,
    ) -> Result<RecursionOutput<SC>, VerificationError> {
        let (proof, prover_data) = self
            .prepared
            .prove_with_legacy_data(traces)
            .map_err(VerificationError::from)?;
        Ok(RecursionOutput(proof, prover_data))
    }

    pub(crate) fn verifier(&self) -> CircuitVerifier<SC> {
        self.prepared.verifier()
    }
}

#[instrument(name = "build_next_layer_prep", skip_all)]
pub(crate) fn prepare_prover<SC, A, B, const D: usize>(
    circuit: &Circuit<SC::Challenge>,
    config: &SC,
    backend: &B,
    params: &ProveNextLayerParams,
) -> Result<PreparedProver<SC>, VerificationError>
where
    SC: StarkGenericConfig + Send + Sync + Clone + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PcsRecursionBackend<SC, A, D>,
    Val<SC>: PrimeField64 + StarkField,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + ExtractBinomialW<Val<SC>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    let preprocessors: Vec<Box<dyn NpoPreprocessor<Val<SC>>>> =
        backend.non_primitive_preprocessors();
    let air_builders: Vec<Box<dyn NpoAirBuilder<SC, D>>> = backend.non_primitive_air_builders();
    let provers: Vec<Box<dyn TableProver<SC>>> = backend.non_primitive_provers(D);
    prepare_prover_from_parts(
        circuit,
        config,
        params,
        &preprocessors,
        &air_builders,
        provers,
    )
}

pub(crate) fn prepare_prover_with_statement<SC, A, B, const D: usize>(
    circuit: &Circuit<SC::Challenge>,
    config: &SC,
    backend: &B,
    params: &ProveNextLayerParams,
    schema: &StatementSchema,
) -> Result<PreparedProver<SC>, VerificationError>
where
    SC: StarkGenericConfig + Send + Sync + Clone + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PcsRecursionBackend<SC, A, D>,
    Val<SC>: PrimeField64 + StarkField,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + ExtractBinomialW<Val<SC>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    StatementPreprocessor: NpoPreprocessor<Val<SC>>,
{
    let mut preprocessors = backend.non_primitive_preprocessors();
    let mut air_builders = backend.non_primitive_air_builders();
    let mut provers = backend.non_primitive_provers(D);
    if schema.base_len() != 0 {
        preprocessors.push(Box::new(StatementPreprocessor::new(schema.clone())));
        air_builders.push(Box::new(StatementAirBuilder::<D>::new(schema.clone())));
        provers.push(Box::new(StatementProver::<D>::new(schema.clone())));
    }
    prepare_prover_from_parts(
        circuit,
        config,
        params,
        &preprocessors,
        &air_builders,
        provers,
    )
}

fn prepare_prover_from_parts<SC, const D: usize>(
    circuit: &Circuit<SC::Challenge>,
    config: &SC,
    params: &ProveNextLayerParams,
    preprocessors: &[Box<dyn NpoPreprocessor<Val<SC>>>],
    air_builders: &[Box<dyn NpoAirBuilder<SC, D>>],
    provers: Vec<Box<dyn TableProver<SC>>>,
) -> Result<PreparedProver<SC>, VerificationError>
where
    SC: StarkGenericConfig + Send + Sync + Clone + 'static,
    Val<SC>: PrimeField64 + StarkField,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + ExtractBinomialW<Val<SC>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    let prover = build_layer_prover(
        config,
        &params.table_packing,
        params.constraint_profile,
        provers,
    );
    let prepared = prover
        .prepare_circuit::<SC::Challenge, D>(
            circuit,
            preprocessors,
            air_builders,
            params.constraint_profile,
        )
        .map_err(map_prepare_prover_error)?;

    Ok(PreparedProver { prepared })
}

fn map_prepare_prover_error(error: BatchStarkProverError) -> VerificationError {
    match error {
        BatchStarkProverError::InvalidMetadata(
            metadata @ ProofMetadataError::ProfileOverflow { .. },
        ) => VerificationError::Circuit(metadata.into()),
        other => VerificationError::Prover(other),
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use core::error::Error as _;

    use p3_circuit::CircuitError;

    use super::*;

    #[test]
    fn preparation_profile_overflow_remains_a_circuit_error() {
        let error = map_prepare_prover_error(BatchStarkProverError::InvalidMetadata(
            ProofMetadataError::ProfileOverflow {
                table: "ALU".into(),
                needed: 16,
                allowed: 8,
            },
        ));

        assert!(matches!(
            error,
            VerificationError::Circuit(CircuitError::ProfileOverflow {
                ref table,
                needed: 16,
                allowed: 8,
            }) if table == "ALU"
        ));
    }

    #[test]
    fn preparation_other_metadata_error_remains_typed_prover_error() {
        let error = map_prepare_prover_error(BatchStarkProverError::InvalidMetadata(
            ProofMetadataError::BadMinTraceHeight(3),
        ));

        assert!(matches!(
            error,
            VerificationError::Prover(BatchStarkProverError::InvalidMetadata(
                ProofMetadataError::BadMinTraceHeight(3)
            ))
        ));
        assert!(
            error
                .source()
                .and_then(|source| source.downcast_ref::<BatchStarkProverError>())
                .is_some()
        );
        assert!(error.to_string().contains("minimum trace height"));
    }
}
