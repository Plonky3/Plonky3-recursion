use p3_air::{SymbolicExpression, SymbolicExpressionExt};
use p3_circuit::Circuit;
use p3_circuit_prover::config::StarkField;
use p3_circuit_prover::field_params::ExtractBinomialW;
use p3_commit::Pcs;
use p3_field::{Algebra, BasedVectorSpace, ExtensionField, PrimeField64};
use p3_lookup::logup::LogUpGadget;
use p3_uni_stark::{StarkGenericConfig, Val};

use super::input::legacy_input;
use super::prover::{PreparedProver, prepare_prover};
use super::{PreparedInput, PreparedPcsRecursionBackend, PreparedSource};
use crate::profile::RecursionLayerProfile;
use crate::recursion::{
    BatchOnly, PcsRecursionBackend, ProveNextLayerParams, RecursionOutput,
    build_aggregation_layer_circuit, run_aggregation_verification_circuit,
};
use crate::traits::RecursiveAir;
use crate::verifier::VerificationError;

/// An owned two-input verifier prepared for inputs and output using the same configuration.
///
/// Both construction proofs may be dropped after [`Self::new`]. The owner retains the two AIR
/// borrows, captured input contracts, verifier circuit, configuration, backend, and prover.
///
/// Batch-only sources infer their marker without a placeholder AIR:
///
/// ```
/// # use p3_batch_stark::CommonData;
/// # use p3_circuit_prover::BatchStarkProof;
/// # use p3_recursion::{BatchOnly, PreparedSource};
/// # use p3_uni_stark::StarkGenericConfig;
/// # fn source<'p, SC: StarkGenericConfig>(proof: &'p BatchStarkProof<SC>, common: &'p CommonData<SC>, public: &'p [Vec<p3_uni_stark::Val<SC>>]) {
/// let _: PreparedSource<'static, 'p, SC, BatchOnly> =
///     PreparedSource::batch(proof, common, public);
/// # }
/// ```
///
/// Configuration and parameters cannot be replaced while proving:
///
/// ```compile_fail,E0061
/// # use p3_air::{SymbolicExpression, SymbolicExpressionExt};
/// # use p3_circuit_prover::config::StarkField;
/// # use p3_circuit_prover::field_params::ExtractBinomialW;
/// # use p3_commit::Pcs;
/// # use p3_field::{Algebra, BasedVectorSpace, ExtensionField, PrimeField64};
/// # use p3_lookup::logup::LogUpGadget;
/// # use p3_recursion::{PreparedAggregation, PreparedInput, PreparedPcsRecursionBackend, ProveNextLayerParams, RecursiveAir};
/// # use p3_uni_stark::{StarkGenericConfig, Val};
/// # fn wrong<SC, A1, A2, B, const D: usize>(owner: &PreparedAggregation<'_, '_, SC, A1, A2, B, D>, left: PreparedInput<'_, SC>, right: PreparedInput<'_, SC>, config: SC, params: ProveNextLayerParams)
/// # where
/// #   SC: StarkGenericConfig + Send + Sync + Clone + 'static,
/// #   A1: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
/// #   A2: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
/// #   B: PreparedPcsRecursionBackend<SC, A1, D> + PreparedPcsRecursionBackend<SC, A2, D>,
/// #   Val<SC>: PrimeField64 + StarkField,
/// #   SC::Challenge: BasedVectorSpace<Val<SC>> + From<Val<SC>> + ExtensionField<Val<SC>> + ExtractBinomialW<Val<SC>>,
/// #   SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
/// #   <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain: Send + Sync,
/// #   SC::Pcs: Sync,
/// #   <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::ProverData: Sync,
/// #   <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment: Sync,
/// # {
/// let _ = owner.prove(left, right, config, params);
/// # }
/// ```
///
/// Verifier results remain private and cannot be replaced:
///
/// ```compile_fail,E0616
/// # use p3_lookup::logup::LogUpGadget;
/// # use p3_recursion::{PreparedAggregation, PreparedPcsRecursionBackend, RecursiveAir};
/// # use p3_uni_stark::{StarkGenericConfig, Val};
/// # fn replace<SC, A1, A2, B, const D: usize>(owner: &mut PreparedAggregation<'_, '_, SC, A1, A2, B, D>, replacement: <B as p3_recursion::PcsRecursionBackend<SC, A1, D>>::VerifierResult)
/// # where SC: StarkGenericConfig + 'static, A1: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>, A2: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>, B: PreparedPcsRecursionBackend<SC, A1, D> + PreparedPcsRecursionBackend<SC, A2, D> {
/// owner.left_result = replacement;
/// # }
/// ```
pub struct PreparedAggregation<'left_air, 'right_air, SC, A1, A2, B, const D: usize>
where
    SC: StarkGenericConfig + 'static,
    A1: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    A2: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PreparedPcsRecursionBackend<SC, A1, D> + PreparedPcsRecursionBackend<SC, A2, D>,
{
    left_air: Option<&'left_air A1>,
    right_air: Option<&'right_air A2>,
    left_contract: <B as PreparedPcsRecursionBackend<SC, A1, D>>::InputContract,
    right_contract: <B as PreparedPcsRecursionBackend<SC, A2, D>>::InputContract,
    circuit: Circuit<SC::Challenge>,
    left_result: <B as PcsRecursionBackend<SC, A1, D>>::VerifierResult,
    right_result: <B as PcsRecursionBackend<SC, A2, D>>::VerifierResult,
    config: SC,
    backend: B,
    params: ProveNextLayerParams,
    profile: Option<RecursionLayerProfile>,
    prep: PreparedProver<SC>,
}

impl<'left_air, 'right_air, SC, A1, A2, B, const D: usize>
    PreparedAggregation<'left_air, 'right_air, SC, A1, A2, B, D>
where
    SC: StarkGenericConfig + Send + Sync + Clone + 'static,
    A1: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    A2: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PreparedPcsRecursionBackend<SC, A1, D> + PreparedPcsRecursionBackend<SC, A2, D>,
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
    /// Capture both trusted contracts before building either verifier, then prepare proving.
    pub fn new(
        left: PreparedSource<'left_air, '_, SC, A1>,
        right: PreparedSource<'right_air, '_, SC, A2>,
        config: SC,
        backend: B,
        params: ProveNextLayerParams,
    ) -> Result<Self, VerificationError> {
        let left_air = source_air(&left);
        let right_air = source_air(&right);
        let left_input = left.as_input();
        let right_input = right.as_input();
        let left_prev = legacy_input(left_air, &left_input)?;
        let right_prev = legacy_input(right_air, &right_input)?;

        let left_contract = <B as PreparedPcsRecursionBackend<SC, A1, D>>::capture_input_contract(
            &backend, &config, &left_prev,
        )?;
        let right_contract = <B as PreparedPcsRecursionBackend<SC, A2, D>>::capture_input_contract(
            &backend,
            &config,
            &right_prev,
        )?;

        let (circuit, (left_result, right_result)) =
            build_aggregation_layer_circuit::<SC, A1, A2, B, D>(
                &left_prev,
                &right_prev,
                &config,
                &backend,
            )?;
        let prep = prepare_prover::<SC, A1, B, D>(&circuit, &config, &backend, &params)?;

        Ok(Self {
            left_air,
            right_air,
            left_contract,
            right_contract,
            circuit,
            left_result,
            right_result,
            config,
            backend,
            params,
            profile: None,
            prep,
        })
    }

    /// Validate both inputs before either verifier result packs witness values.
    pub fn check_inputs(
        &self,
        left: &PreparedInput<'_, SC>,
        right: &PreparedInput<'_, SC>,
    ) -> Result<(), VerificationError> {
        <B as PreparedPcsRecursionBackend<SC, A1, D>>::validate_prepared_input(
            &self.backend,
            &self.config,
            &self.left_contract,
            left,
        )?;
        <B as PreparedPcsRecursionBackend<SC, A2, D>>::validate_prepared_input(
            &self.backend,
            &self.config,
            &self.right_contract,
            right,
        )
    }

    /// Prove one aggregation layer using two native witnesses matching the retained contracts.
    #[tracing::instrument(name = "prove_aggregation_layer", skip_all)]
    pub fn prove(
        &self,
        left: PreparedInput<'_, SC>,
        right: PreparedInput<'_, SC>,
    ) -> Result<RecursionOutput<SC>, VerificationError> {
        self.check_inputs(&left, &right)?;
        let left = legacy_input(self.left_air, &left)?;
        let right = legacy_input(self.right_air, &right)?;
        let traces = run_aggregation_verification_circuit::<SC, A1, A2, B, D>(
            &left,
            &right,
            &self.left_result,
            &self.right_result,
            &self.circuit,
            &self.config,
            &self.backend,
        )?;
        self.prep.prove(&traces)
    }

    /// Parameters fixed when this aggregation verifier was prepared.
    pub const fn params(&self) -> &ProveNextLayerParams {
        &self.params
    }

    /// Profile label fixed at construction, if profile-based preparation was requested.
    pub const fn profile(&self) -> Option<&RecursionLayerProfile> {
        self.profile.as_ref()
    }
}

/// An owned two-input verifier that checks under one configuration and proves under another.
///
/// The input and output configurations are fixed at construction:
///
/// ```compile_fail,E0061
/// # use p3_air::{SymbolicExpression, SymbolicExpressionExt};
/// # use p3_circuit_prover::config::StarkField;
/// # use p3_circuit_prover::field_params::ExtractBinomialW;
/// # use p3_commit::Pcs;
/// # use p3_field::{Algebra, BasedVectorSpace, ExtensionField, PrimeField64};
/// # use p3_lookup::logup::LogUpGadget;
/// # use p3_recursion::{BatchOnly, PreparedAggregationCross, PreparedInput, PreparedPcsRecursionBackend, RecursiveAir};
/// # use p3_uni_stark::{StarkGenericConfig, Val};
/// # fn wrong<InSC, OutSC, A1, A2, B, const D: usize>(owner: &PreparedAggregationCross<'_, '_, InSC, OutSC, A1, A2, B, D>, left: PreparedInput<'_, InSC>, right: PreparedInput<'_, InSC>, input_config: InSC, output_config: OutSC)
/// # where
/// #   InSC: StarkGenericConfig + Send + Sync + Clone + 'static,
/// #   OutSC: StarkGenericConfig<Challenge = InSC::Challenge> + Send + Sync + Clone + 'static,
/// #   A1: RecursiveAir<Val<InSC>, InSC::Challenge, LogUpGadget>,
/// #   A2: RecursiveAir<Val<InSC>, InSC::Challenge, LogUpGadget>,
/// #   B: PreparedPcsRecursionBackend<InSC, A1, D> + PreparedPcsRecursionBackend<InSC, A2, D> + p3_recursion::PcsRecursionBackend<OutSC, BatchOnly, D>,
/// #   Val<InSC>: PrimeField64 + StarkField,
/// #   InSC::Challenge: BasedVectorSpace<Val<InSC>> + From<Val<InSC>> + ExtensionField<Val<InSC>> + ExtractBinomialW<Val<InSC>>,
/// #   Val<OutSC>: PrimeField64 + StarkField,
/// #   OutSC::Challenge: BasedVectorSpace<Val<OutSC>> + From<Val<OutSC>> + ExtensionField<Val<OutSC>> + ExtractBinomialW<Val<OutSC>>,
/// #   SymbolicExpressionExt<Val<InSC>, InSC::Challenge>: Algebra<SymbolicExpression<Val<InSC>>> + Algebra<InSC::Challenge>,
/// #   SymbolicExpressionExt<Val<OutSC>, OutSC::Challenge>: Algebra<SymbolicExpression<Val<OutSC>>> + Algebra<OutSC::Challenge>,
/// #   <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::Domain: Send + Sync,
/// #   OutSC::Pcs: Sync,
/// #   <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::ProverData: Sync,
/// #   <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::Commitment: Sync,
/// # {
/// let _ = owner.prove(left, right, input_config, output_config);
/// # }
/// ```
///
/// An output proof cannot be supplied as an input when the configuration types differ:
///
/// ```compile_fail,E0308
/// # use p3_air::{SymbolicExpression, SymbolicExpressionExt};
/// # use p3_circuit_prover::config::StarkField;
/// # use p3_circuit_prover::field_params::ExtractBinomialW;
/// # use p3_commit::Pcs;
/// # use p3_field::{Algebra, BasedVectorSpace, ExtensionField, PrimeField64};
/// # use p3_lookup::logup::LogUpGadget;
/// # use p3_recursion::{BatchOnly, PreparedAggregationCross, PreparedInput, PreparedPcsRecursionBackend, RecursionOutput, RecursiveAir};
/// # use p3_uni_stark::{StarkGenericConfig, Val};
/// # fn wrong<InSC, OutSC, A1, A2, B, const D: usize>(owner: &PreparedAggregationCross<'_, '_, InSC, OutSC, A1, A2, B, D>, output: &RecursionOutput<OutSC>, right: PreparedInput<'_, InSC>)
/// # where
/// #   InSC: StarkGenericConfig + Send + Sync + Clone + 'static,
/// #   OutSC: StarkGenericConfig<Challenge = InSC::Challenge> + Send + Sync + Clone + 'static,
/// #   A1: RecursiveAir<Val<InSC>, InSC::Challenge, LogUpGadget>,
/// #   A2: RecursiveAir<Val<InSC>, InSC::Challenge, LogUpGadget>,
/// #   B: PreparedPcsRecursionBackend<InSC, A1, D> + PreparedPcsRecursionBackend<InSC, A2, D> + p3_recursion::PcsRecursionBackend<OutSC, BatchOnly, D>,
/// #   Val<InSC>: PrimeField64 + StarkField,
/// #   InSC::Challenge: BasedVectorSpace<Val<InSC>> + From<Val<InSC>> + ExtensionField<Val<InSC>> + ExtractBinomialW<Val<InSC>>,
/// #   Val<OutSC>: PrimeField64 + StarkField,
/// #   OutSC::Challenge: BasedVectorSpace<Val<OutSC>> + From<Val<OutSC>> + ExtensionField<Val<OutSC>> + ExtractBinomialW<Val<OutSC>>,
/// #   SymbolicExpressionExt<Val<InSC>, InSC::Challenge>: Algebra<SymbolicExpression<Val<InSC>>> + Algebra<InSC::Challenge>,
/// #   SymbolicExpressionExt<Val<OutSC>, OutSC::Challenge>: Algebra<SymbolicExpression<Val<OutSC>>> + Algebra<OutSC::Challenge>,
/// #   <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::Domain: Send + Sync,
/// #   OutSC::Pcs: Sync,
/// #   <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::ProverData: Sync,
/// #   <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::Commitment: Sync,
/// # {
/// let left = PreparedInput::<InSC>::BatchStark {
///     proof: &output.0,
///     common_data: &output.0.stark_common,
///     table_public_inputs: &[],
/// };
/// let _ = owner.prove(left, right);
/// # }
/// ```
pub struct PreparedAggregationCross<'left_air, 'right_air, InSC, OutSC, A1, A2, B, const D: usize>
where
    InSC: StarkGenericConfig + 'static,
    OutSC: StarkGenericConfig<Challenge = InSC::Challenge> + 'static,
    A1: RecursiveAir<Val<InSC>, InSC::Challenge, LogUpGadget>,
    A2: RecursiveAir<Val<InSC>, InSC::Challenge, LogUpGadget>,
    B: PreparedPcsRecursionBackend<InSC, A1, D> + PreparedPcsRecursionBackend<InSC, A2, D>,
{
    left_air: Option<&'left_air A1>,
    right_air: Option<&'right_air A2>,
    left_contract: <B as PreparedPcsRecursionBackend<InSC, A1, D>>::InputContract,
    right_contract: <B as PreparedPcsRecursionBackend<InSC, A2, D>>::InputContract,
    circuit: Circuit<InSC::Challenge>,
    left_result: <B as PcsRecursionBackend<InSC, A1, D>>::VerifierResult,
    right_result: <B as PcsRecursionBackend<InSC, A2, D>>::VerifierResult,
    input_config: InSC,
    // Retained to keep the prepared output relation structurally owned after construction.
    #[allow(dead_code)]
    output_config: OutSC,
    backend: B,
    params: ProveNextLayerParams,
    profile: Option<RecursionLayerProfile>,
    prep: PreparedProver<OutSC>,
}

impl<'left_air, 'right_air, InSC, OutSC, A1, A2, B, const D: usize>
    PreparedAggregationCross<'left_air, 'right_air, InSC, OutSC, A1, A2, B, D>
where
    InSC: StarkGenericConfig + Send + Sync + Clone + 'static,
    OutSC: StarkGenericConfig<Challenge = InSC::Challenge> + Send + Sync + Clone + 'static,
    A1: RecursiveAir<Val<InSC>, InSC::Challenge, LogUpGadget>,
    A2: RecursiveAir<Val<InSC>, InSC::Challenge, LogUpGadget>,
    B: PreparedPcsRecursionBackend<InSC, A1, D>
        + PreparedPcsRecursionBackend<InSC, A2, D>
        + PcsRecursionBackend<OutSC, BatchOnly, D>,
    Val<InSC>: PrimeField64 + StarkField,
    InSC::Challenge: BasedVectorSpace<Val<InSC>>
        + From<Val<InSC>>
        + ExtensionField<Val<InSC>>
        + ExtractBinomialW<Val<InSC>>,
    Val<OutSC>: PrimeField64 + StarkField,
    OutSC::Challenge: BasedVectorSpace<Val<OutSC>>
        + From<Val<OutSC>>
        + ExtensionField<Val<OutSC>>
        + ExtractBinomialW<Val<OutSC>>,
    SymbolicExpressionExt<Val<OutSC>, OutSC::Challenge>:
        Algebra<SymbolicExpression<Val<OutSC>>> + Algebra<OutSC::Challenge>,
    SymbolicExpressionExt<Val<InSC>, InSC::Challenge>:
        Algebra<SymbolicExpression<Val<InSC>>> + Algebra<InSC::Challenge>,
    <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::Domain: Send + Sync,
    OutSC::Pcs: Sync,
    <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::ProverData: Sync,
    <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::Commitment: Sync,
{
    /// Capture both input contracts before building either verifier, then prepare the output PCS.
    pub fn new(
        left: PreparedSource<'left_air, '_, InSC, A1>,
        right: PreparedSource<'right_air, '_, InSC, A2>,
        input_config: InSC,
        output_config: OutSC,
        backend: B,
        params: ProveNextLayerParams,
    ) -> Result<Self, VerificationError> {
        let left_air = source_air(&left);
        let right_air = source_air(&right);
        let left_input = left.as_input();
        let right_input = right.as_input();
        let left_prev = legacy_input(left_air, &left_input)?;
        let right_prev = legacy_input(right_air, &right_input)?;

        let left_contract =
            <B as PreparedPcsRecursionBackend<InSC, A1, D>>::capture_input_contract(
                &backend,
                &input_config,
                &left_prev,
            )?;
        let right_contract =
            <B as PreparedPcsRecursionBackend<InSC, A2, D>>::capture_input_contract(
                &backend,
                &input_config,
                &right_prev,
            )?;

        let (circuit, (left_result, right_result)) =
            build_aggregation_layer_circuit::<InSC, A1, A2, B, D>(
                &left_prev,
                &right_prev,
                &input_config,
                &backend,
            )?;
        let prep =
            prepare_prover::<OutSC, BatchOnly, B, D>(&circuit, &output_config, &backend, &params)?;

        Ok(Self {
            left_air,
            right_air,
            left_contract,
            right_contract,
            circuit,
            left_result,
            right_result,
            input_config,
            output_config,
            backend,
            params,
            profile: None,
            prep,
        })
    }

    /// Validate both inputs before either verifier result packs witness values.
    pub fn check_inputs(
        &self,
        left: &PreparedInput<'_, InSC>,
        right: &PreparedInput<'_, InSC>,
    ) -> Result<(), VerificationError> {
        <B as PreparedPcsRecursionBackend<InSC, A1, D>>::validate_prepared_input(
            &self.backend,
            &self.input_config,
            &self.left_contract,
            left,
        )?;
        <B as PreparedPcsRecursionBackend<InSC, A2, D>>::validate_prepared_input(
            &self.backend,
            &self.input_config,
            &self.right_contract,
            right,
        )
    }

    /// Prove under the retained output configuration after validating both input contracts.
    #[tracing::instrument(name = "prove_aggregation_layer", skip_all)]
    pub fn prove(
        &self,
        left: PreparedInput<'_, InSC>,
        right: PreparedInput<'_, InSC>,
    ) -> Result<RecursionOutput<OutSC>, VerificationError> {
        self.check_inputs(&left, &right)?;
        let left = legacy_input(self.left_air, &left)?;
        let right = legacy_input(self.right_air, &right)?;
        let traces = run_aggregation_verification_circuit::<InSC, A1, A2, B, D>(
            &left,
            &right,
            &self.left_result,
            &self.right_result,
            &self.circuit,
            &self.input_config,
            &self.backend,
        )?;
        self.prep.prove(&traces)
    }

    /// Parameters fixed when this aggregation verifier was prepared.
    pub const fn params(&self) -> &ProveNextLayerParams {
        &self.params
    }

    /// Profile label fixed at construction, if profile-based preparation was requested.
    pub const fn profile(&self) -> Option<&RecursionLayerProfile> {
        self.profile.as_ref()
    }
}

const fn source_air<'air, SC, A>(source: &PreparedSource<'air, '_, SC, A>) -> Option<&'air A>
where
    SC: StarkGenericConfig,
{
    match source {
        PreparedSource::UniStark { air, .. } => Some(*air),
        PreparedSource::BatchStark { .. } => None,
    }
}
