use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::ToString;
use alloc::vec::Vec;

use p3_air::{SymbolicExpression, SymbolicExpressionExt};
use p3_batch_stark::ProverData;
use p3_circuit::Circuit;
use p3_circuit::tables::Traces;
use p3_circuit_prover::batch_stark_prover::TableProver;
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor, get_airs_and_degrees_with_prep};
use p3_circuit_prover::config::StarkField;
use p3_circuit_prover::field_params::ExtractBinomialW;
use p3_circuit_prover::{BatchStarkProver, CircuitProverData};
use p3_commit::Pcs;
use p3_field::{Algebra, BasedVectorSpace, ExtensionField, PrimeField64};
use p3_lookup::logup::LogUpGadget;
use p3_uni_stark::{StarkGenericConfig, Val};

use crate::recursion::{
    PcsRecursionBackend, ProveNextLayerParams, RecursionOutput, build_layer_prover,
};
use crate::traits::RecursiveAir;
use crate::verifier::VerificationError;

pub(crate) struct PreparedProver<SC: StarkGenericConfig + 'static> {
    circuit_prover_data: Rc<CircuitProverData<SC>>,
    prover: BatchStarkProver<SC>,
}

impl<SC> PreparedProver<SC>
where
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
        let proof = self
            .prover
            .prove_all_tables(traces, &self.circuit_prover_data)
            .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
        Ok(RecursionOutput(proof, Rc::clone(&self.circuit_prover_data)))
    }
}

impl<SC: StarkGenericConfig + 'static> PreparedProver<SC> {
    pub(crate) fn into_legacy_parts(self) -> (Rc<CircuitProverData<SC>>, BatchStarkProver<SC>) {
        (self.circuit_prover_data, self.prover)
    }
}

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
    let (airs_degrees, primitive_columns, non_primitive_columns) = {
        let preprocessors: Vec<Box<dyn NpoPreprocessor<Val<SC>>>> =
            backend.non_primitive_preprocessors();
        let air_builders: Vec<Box<dyn NpoAirBuilder<SC, D>>> = backend.non_primitive_air_builders();
        get_airs_and_degrees_with_prep::<SC, SC::Challenge, D>(
            circuit,
            &params.table_packing,
            &preprocessors,
            &air_builders,
            params.constraint_profile,
        )
        .map_err(VerificationError::Circuit)?
    };

    let (airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();
    let ext_degrees: Vec<usize> = degrees
        .iter()
        .map(|&degree| degree + config.is_zk())
        .collect();
    let prover_data = ProverData::from_airs_and_degrees(config, &airs, &ext_degrees);
    let circuit_prover_data = Rc::new(CircuitProverData::new(
        prover_data,
        primitive_columns,
        non_primitive_columns,
    ));
    let provers: Vec<Box<dyn TableProver<SC>>> = backend.non_primitive_provers(D);
    let prover = build_layer_prover(
        config,
        &params.table_packing,
        params.constraint_profile,
        provers,
    );

    Ok(PreparedProver {
        circuit_prover_data,
        prover,
    })
}
