//! Unified recursion API: one entry point to prove the next layer over a uni-stark or batch-stark proof.

use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::rc::Rc;
use alloc::string::ToString;
use alloc::vec;
use alloc::vec::Vec;

use p3_air::{SymbolicExpression, SymbolicExpressionExt};
use p3_batch_stark::CommonData;
use p3_circuit::symbolic::ColumnsTargets;
use p3_circuit::tables::Traces;
use p3_circuit::{Circuit, CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_circuit_prover::batch_stark_prover::TableProver;
use p3_circuit_prover::common::{NpoAirBuilder, NpoPreprocessor};
use p3_circuit_prover::config::StarkField;
use p3_circuit_prover::field_params::ExtractBinomialW;
use p3_circuit_prover::{
    AirVariant, BatchStarkProof, BatchStarkProver, CircuitProverData, ConstraintProfile,
    TablePacking,
};
use p3_commit::Pcs;
use p3_field::{Algebra, BasedVectorSpace, ExtensionField, Field, PrimeField64};
use p3_lookup::logup::LogUpGadget;
use p3_lookup::{Lookup, LookupProtocol};
use p3_uni_stark::{Proof, StarkGenericConfig, Val};
use tracing::instrument;

use crate::Target;
use crate::prepared::prover::prepare_prover;
use crate::traits::{LookupMetadata, RecursiveAir};
use crate::types::RecursiveLagrangeSelectors;
use crate::verifier::VerificationError;

fn proof_shape_err(e: &impl ToString) -> VerificationError {
    VerificationError::InvalidProofShape(e.to_string())
}

/// Build the [`BatchStarkProver`] for a recursion layer from the resolved table packing,
/// constraint profile, and the layer's non-primitive table provers.
///
/// `provers` is passed in already constructed so the helper stays agnostic to which AIR the
/// aggregation site dispatches `non_primitive_provers` through.
pub(crate) fn build_layer_prover<SC>(
    config: &SC,
    table_packing: &TablePacking,
    constraint_profile: ConstraintProfile,
    provers: Vec<Box<dyn TableProver<SC>>>,
) -> BatchStarkProver<SC>
where
    SC: StarkGenericConfig + Clone + 'static,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    let mut prover = BatchStarkProver::new(config.clone())
        .with_table_packing(table_packing.clone())
        .with_alu_variant(match constraint_profile {
            ConstraintProfile::Standard => AirVariant::Baseline,
            ConstraintProfile::RecursionOptimized => AirVariant::Optimized,
        });
    for p in provers {
        prover.register_table_prover(p);
    }
    prover
}

/// Input to one recursion step: either a uni-stark proof or a batch-stark proof (with common data).
pub enum RecursionInput<'a, SC, A>
where
    SC: StarkGenericConfig,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
{
    /// A single-instance STARK proof (e.g. from p3-uni-stark) plus its AIR and public inputs.
    UniStark {
        proof: &'a Proof<SC>,
        air: &'a A,
        public_inputs: Vec<Val<SC>>,
        preprocessed_commit: Option<<SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment>,
    },
    /// A batch STARK proof (e.g. from p3-batch-stark / circuit-prover) plus common data and per-table public inputs.
    BatchStark {
        proof: &'a BatchStarkProof<SC>,
        common_data: &'a CommonData<SC>,
        table_public_inputs: Vec<Vec<Val<SC>>>,
    },
}

/// Output of one recursion step: the next-layer batch proof and its prover data (for chaining or verification).
pub struct RecursionOutput<SC>(pub BatchStarkProof<SC>, pub Rc<CircuitProverData<SC>>)
where
    SC: StarkGenericConfig;

impl<SC> RecursionOutput<SC>
where
    SC: StarkGenericConfig,
{
    /// Convert this output into a `RecursionInput::BatchStark` for the next recursion layer.
    /// The type parameter `A` is only used for the recursion input type; use `BatchOnly` when
    /// chaining batch-to-batch (see [`BatchOnly`]).
    pub fn into_recursion_input<A>(&self) -> RecursionInput<'_, SC, A>
    where
        A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    {
        let num_tables = self.0.proof.opened_values.instances.len();
        RecursionInput::BatchStark {
            proof: &self.0,
            common_data: &self.0.stark_common,
            table_public_inputs: vec![vec![]; num_tables],
        }
    }
}

/// Result of building a verifier circuit: holds enough to pack public inputs and set private data.
pub trait VerifierCircuitResult<SC, A>
where
    SC: StarkGenericConfig,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
{
    /// Pack the public inputs for the verifier circuit from the previous recursion input.
    fn pack_public_inputs(
        &self,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<Vec<SC::Challenge>, VerificationError>
    where
        Val<SC>: PrimeField64,
        SC::Challenge: BasedVectorSpace<Val<SC>> + From<Val<SC>>;

    /// Pack the private inputs (opened values, FRI siblings, etc.) for the verifier circuit.
    fn pack_private_inputs(
        &self,
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<Vec<SC::Challenge>, VerificationError>
    where
        Val<SC>: PrimeField64,
        SC::Challenge: BasedVectorSpace<Val<SC>> + From<Val<SC>>;

    /// Operation IDs that require private data (e.g. Merkle paths) for the circuit runner.
    fn op_ids(&self) -> &[NonPrimitiveOpId];
}

/// PCS-specific backend for building verifier circuits and setting private data.
pub trait PcsRecursionBackend<SC, A, const D: usize>
where
    SC: StarkGenericConfig,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
{
    /// Opaque verifier result returned by `build_verifier_circuit`.
    type VerifierResult: VerifierCircuitResult<SC, A>;

    /// Validate the input before backend preparation, plugin construction, or circuit
    /// allocation. Custom backends retain the historical trusted no-op default; audited built-in
    /// backends override this with their raw input guards and perform contextual PCS checks in
    /// their verifier construction path.
    fn validate_input(
        &self,
        _config: &SC,
        _prev: &RecursionInput<'_, SC, A>,
    ) -> Result<(), VerificationError> {
        Ok(())
    }

    /// Prepare the circuit before building the verifier (e.g. enable challenger permutation and NPOs). Called before `build_verifier_circuit`.
    fn prepare_circuit(
        &self,
        config: &SC,
        circuit: &mut CircuitBuilder<SC::Challenge>,
    ) -> Result<(), VerificationError>;

    /// Build the verifier circuit for the given recursion input; add constraints to `circuit`.
    fn build_verifier_circuit(
        &self,
        prev: &RecursionInput<'_, SC, A>,
        config: &SC,
        circuit: &mut CircuitBuilder<SC::Challenge>,
    ) -> Result<Self::VerifierResult, VerificationError>;

    /// Set PCS-specific private data (e.g. FRI Merkle paths) on the runner.
    fn set_private_data(
        &self,
        config: &SC,
        runner: &mut CircuitRunner<'_, SC::Challenge>,
        op_ids: &[NonPrimitiveOpId],
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<(), &'static str>;

    /// Non-primitive preprocessors for this extension degree (e.g. for NPOs that need preprocessing).
    fn non_primitive_preprocessors(&self) -> Vec<Box<dyn NpoPreprocessor<Val<SC>>>> {
        Vec::new()
    }

    /// Non-primitive table provers for the given extension degree.
    /// Default returns empty; backends that use NPOs in the circuit override this.
    fn non_primitive_provers(&self, _ext_degree: usize) -> Vec<Box<dyn TableProver<SC>>> {
        Vec::new()
    }

    /// AIR builders for NPOs from preprocessed data.
    fn non_primitive_air_builders(&self) -> Vec<Box<dyn NpoAirBuilder<SC, D>>> {
        Vec::new()
    }
}

/// Parameters for the shared recursion pipeline (table packing, optional overrides).
#[derive(Clone, Debug)]
pub struct ProveNextLayerParams {
    pub table_packing: TablePacking,
    /// Constraint profile controlling which AIR variants are used for this layer.
    pub constraint_profile: ConstraintProfile,
}

impl Default for ProveNextLayerParams {
    fn default() -> Self {
        Self {
            table_packing: TablePacking::new(1, 4),
            constraint_profile: ConstraintProfile::Standard,
        }
    }
}

/// Marker type for batch-only recursion input. Use with [`RecursionOutput::into_recursion_input`]
/// when chaining batch-to-batch layers (e.g. `output.into_recursion_input::<BatchOnly>()`).
#[derive(Debug)]
pub struct BatchOnly;

impl<F: Field, EF: ExtensionField<F>, LG: LookupProtocol> RecursiveAir<F, EF, LG> for BatchOnly {
    fn expected_public_input_count(&self) -> Option<usize> {
        Some(0)
    }

    fn width(&self) -> usize {
        0
    }

    fn num_periodic_columns(&self) -> usize {
        0
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<F>]> {
        Cow::Borrowed(&[])
    }

    fn eval_folded_circuit(
        &self,
        builder: &mut CircuitBuilder<EF>,
        _sels: &RecursiveLagrangeSelectors,
        _alpha: &Target,
        _lookup_metadata: &LookupMetadata<'_, F>,
        _columns: ColumnsTargets<'_>,
        _lookup_gadget: &LG,
    ) -> Target {
        builder.define_const(EF::ZERO)
    }

    fn get_log_num_quotient_chunks(
        &self,
        _preprocessed_width: usize,
        _trace_len: usize,
        _contexts: &[Lookup<F>],
        _is_zk: usize,
        _lookup_gadget: &LG,
    ) -> usize {
        0
    }

    fn declares_interactions(&self, _preprocessed_width: usize) -> bool {
        false
    }

    fn opens_trace_next(&self) -> bool {
        false
    }

    fn opens_preprocessed_next(&self) -> bool {
        false
    }
}

/// Build a verifier circuit for a recursion layer.
#[instrument(skip_all)]
pub fn build_next_layer_circuit<SC, A, B, const D: usize>(
    prev: &RecursionInput<'_, SC, A>,
    config: &SC,
    backend: &B,
) -> Result<(Circuit<SC::Challenge>, B::VerifierResult), VerificationError>
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
    let mut circuit_builder = CircuitBuilder::new();
    backend.validate_input(config, prev)?;
    backend.prepare_circuit(config, &mut circuit_builder)?;

    // Build verifier constraints.
    let verifier_result = backend.build_verifier_circuit(prev, config, &mut circuit_builder)?;
    let verification_circuit = circuit_builder
        .build()
        .map_err(VerificationError::CircuitBuilder)?;

    Ok((verification_circuit, verifier_result))
}

/// Prove one recursion layer: run the verifier circuit and prove it with batch STARK.
///
/// Preparation is fresh for every call. Callers that need to amortize preparation across
/// repeated proofs should use the owner-based [`crate::prepared::PreparedLayer`] API.
#[instrument(skip_all)]
pub fn prove_next_layer<SC, A, B, const D: usize>(
    prev: &RecursionInput<'_, SC, A>,
    verification_circuit: &Circuit<SC::Challenge>,
    verifier_result: &B::VerifierResult,
    config: &SC,
    backend: &B,
    params: &ProveNextLayerParams,
) -> Result<RecursionOutput<SC>, VerificationError>
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
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain: Send + Sync,
    SC::Pcs: Sync,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::ProverData: Sync,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment: Sync,
{
    let traces = {
        let public_inputs = verifier_result.pack_public_inputs(prev)?;
        let private_inputs = verifier_result.pack_private_inputs(prev)?;
        let mut runner = verification_circuit.runner();
        runner
            .set_public_inputs(&public_inputs)
            .map_err(VerificationError::Circuit)?;
        runner
            .set_private_inputs(&private_inputs)
            .map_err(VerificationError::Circuit)?;

        backend
            .set_private_data(config, &mut runner, verifier_result.op_ids(), prev)
            .map_err(|e| proof_shape_err(&e))?;

        runner.run().map_err(VerificationError::Circuit)?
    };

    prepare_prover::<SC, A, B, D>(verification_circuit, config, backend, params)?.prove(&traces)
}

/// Convenience wrapper that builds a verifier circuit and freshly prepares and proves it.
pub fn build_and_prove_next_layer<SC, A, B, const D: usize>(
    prev: &RecursionInput<'_, SC, A>,
    config: &SC,
    backend: &B,
    params: &ProveNextLayerParams,
) -> Result<RecursionOutput<SC>, VerificationError>
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
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain: Send + Sync,
    SC::Pcs: Sync,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::ProverData: Sync,
    <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment: Sync,
{
    let (verification_circuit, verifier_result) =
        build_next_layer_circuit::<SC, A, B, D>(prev, config, backend)?;

    prove_next_layer::<SC, A, B, D>(
        prev,
        &verification_circuit,
        &verifier_result,
        config,
        backend,
        params,
    )
}

/// Build a 2-to-1 aggregation layer verifier circuit.
///
/// The two inputs may be different `RecursionInput` variants (e.g. one `UniStark` left
/// and one `BatchStark` right) or identical ones.
///
/// The resulting `VerifierResult`s hold only shape-dependent targets (not `left`/`right`'s
/// actual values), so both the circuit and the results can be reused across every pair that
/// shares this shape: pass them to [`prove_aggregation_layer`] once per pair, each with that
/// pair's own `left`/`right`, instead of rebuilding the circuit per pair.
#[instrument(skip_all)]
#[allow(clippy::type_complexity)]
pub fn build_aggregation_layer_circuit<SC, A1, A2, B, const D: usize>(
    left: &RecursionInput<'_, SC, A1>,
    right: &RecursionInput<'_, SC, A2>,
    config: &SC,
    backend: &B,
) -> Result<
    (
        Circuit<SC::Challenge>,
        (
            <B as PcsRecursionBackend<SC, A1, D>>::VerifierResult, // left
            <B as PcsRecursionBackend<SC, A2, D>>::VerifierResult, // right
        ),
    ),
    VerificationError,
>
where
    SC: StarkGenericConfig + Send + Sync + Clone + 'static,
    A1: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    A2: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PcsRecursionBackend<SC, A1, D> + PcsRecursionBackend<SC, A2, D>,
    Val<SC>: PrimeField64 + StarkField,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + ExtractBinomialW<Val<SC>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    let mut circuit_builder = CircuitBuilder::new();

    // Validate both inputs before either backend prepares plugins or allocates verifier targets.
    <B as PcsRecursionBackend<SC, A1, D>>::validate_input(backend, config, left)?;
    <B as PcsRecursionBackend<SC, A2, D>>::validate_input(backend, config, right)?;

    <B as PcsRecursionBackend<SC, A1, D>>::prepare_circuit(backend, config, &mut circuit_builder)?;
    <B as PcsRecursionBackend<SC, A2, D>>::prepare_circuit(backend, config, &mut circuit_builder)?;

    // Build left verifier constraints.
    let left_result = backend.build_verifier_circuit(left, config, &mut circuit_builder)?;
    // Build right verifier constraints into the same builder.
    let right_result = backend.build_verifier_circuit(right, config, &mut circuit_builder)?;

    let verification_circuit = circuit_builder
        .build()
        .map_err(VerificationError::CircuitBuilder)?;

    Ok((verification_circuit, (left_result, right_result)))
}

pub(crate) fn run_aggregation_verification_circuit<SC, A1, A2, B, const D: usize>(
    left: &RecursionInput<'_, SC, A1>,
    right: &RecursionInput<'_, SC, A2>,
    left_result: &<B as PcsRecursionBackend<SC, A1, D>>::VerifierResult,
    right_result: &<B as PcsRecursionBackend<SC, A2, D>>::VerifierResult,
    verification_circuit: &Circuit<SC::Challenge>,
    config: &SC,
    backend: &B,
) -> Result<Traces<SC::Challenge>, VerificationError>
where
    SC: StarkGenericConfig,
    A1: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    A2: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PcsRecursionBackend<SC, A1, D> + PcsRecursionBackend<SC, A2, D>,
    Val<SC>: PrimeField64,
{
    let mut public_inputs = left_result.pack_public_inputs(left)?;
    public_inputs.extend(right_result.pack_public_inputs(right)?);

    let mut private_inputs = left_result.pack_private_inputs(left)?;
    private_inputs.extend(right_result.pack_private_inputs(right)?);

    let mut runner = verification_circuit.runner();
    runner
        .set_public_inputs(&public_inputs)
        .map_err(VerificationError::Circuit)?;
    runner
        .set_private_inputs(&private_inputs)
        .map_err(VerificationError::Circuit)?;

    <B as PcsRecursionBackend<SC, A1, D>>::set_private_data(
        backend,
        config,
        &mut runner,
        left_result.op_ids(),
        left,
    )
    .map_err(|e| proof_shape_err(&e.to_string()))?;

    <B as PcsRecursionBackend<SC, A2, D>>::set_private_data(
        backend,
        config,
        &mut runner,
        right_result.op_ids(),
        right,
    )
    .map_err(|e| proof_shape_err(&e.to_string()))?;

    runner.run().map_err(VerificationError::Circuit)
}

/// Prove a 2-to-1 aggregation layer: build verifier circuits for both `left` and `right`
/// in a single circuit, run it, and produce one aggregated batch STARK proof.
///
/// Preparation is rebuilt on every call. For repeated proofs with retained preparation, use
/// [`crate::prepared::PreparedAggregation`].
///
/// The two inputs may be different `RecursionInput` variants (e.g. one `UniStark` left
/// and one `BatchStark` right) or identical ones.
#[instrument(skip_all)]
#[allow(clippy::too_many_arguments)]
pub fn prove_aggregation_layer<SC, A1, A2, B, const D: usize>(
    left: &RecursionInput<'_, SC, A1>,
    right: &RecursionInput<'_, SC, A2>,
    left_result: &<B as PcsRecursionBackend<SC, A1, D>>::VerifierResult,
    right_result: &<B as PcsRecursionBackend<SC, A2, D>>::VerifierResult,
    verification_circuit: &Circuit<SC::Challenge>,
    config: &SC,
    backend: &B,
    params: &ProveNextLayerParams,
) -> Result<RecursionOutput<SC>, VerificationError>
where
    SC: StarkGenericConfig + Send + Sync + Clone + 'static,
    A1: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    A2: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PcsRecursionBackend<SC, A1, D> + PcsRecursionBackend<SC, A2, D>,
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
    let traces = run_aggregation_verification_circuit::<SC, A1, A2, B, D>(
        left,
        right,
        left_result,
        right_result,
        verification_circuit,
        config,
        backend,
    )?;

    prepare_prover::<SC, A1, B, D>(verification_circuit, config, backend, params)?.prove(&traces)
}

/// Prove a 2-to-1 aggregation layer while verifying the input proofs under `InSC`
/// and committing the aggregated proof under `OutSC`.
///
/// Mirrors [`prove_aggregation_layer`] but splits the verifier config from the output
/// proof config. The two configs must share the same challenge field; this is the seam
/// used to switch the output MMCS arity (e.g. verify arity-2 inputs, emit an arity-4 proof).
/// Preparation is rebuilt on every call. For repeated proofs with retained preparation, use
/// [`crate::prepared::PreparedAggregationCross`].
#[instrument(skip_all)]
#[allow(clippy::too_many_arguments)]
pub fn prove_aggregation_layer_cross<InSC, OutSC, A1, A2, B, const D: usize>(
    left: &RecursionInput<'_, InSC, A1>,
    right: &RecursionInput<'_, InSC, A2>,
    left_result: &<B as PcsRecursionBackend<InSC, A1, D>>::VerifierResult,
    right_result: &<B as PcsRecursionBackend<InSC, A2, D>>::VerifierResult,
    verification_circuit: &Circuit<InSC::Challenge>,
    input_config: &InSC,
    output_config: &OutSC,
    backend: &B,
    params: &ProveNextLayerParams,
) -> Result<RecursionOutput<OutSC>, VerificationError>
where
    InSC: StarkGenericConfig + Send + Sync + Clone + 'static,
    OutSC: StarkGenericConfig<Challenge = InSC::Challenge> + Send + Sync + Clone + 'static,
    A1: RecursiveAir<Val<InSC>, InSC::Challenge, LogUpGadget>,
    A2: RecursiveAir<Val<InSC>, InSC::Challenge, LogUpGadget>,
    B: PcsRecursionBackend<InSC, A1, D>
        + PcsRecursionBackend<InSC, A2, D>
        + PcsRecursionBackend<OutSC, BatchOnly, D>,
    Val<InSC>: PrimeField64,
    InSC::Challenge: BasedVectorSpace<Val<InSC>> + From<Val<InSC>>,
    Val<OutSC>: PrimeField64 + StarkField,
    OutSC::Challenge: BasedVectorSpace<Val<OutSC>>
        + From<Val<OutSC>>
        + ExtensionField<Val<OutSC>>
        + ExtractBinomialW<Val<OutSC>>,
    SymbolicExpressionExt<Val<OutSC>, OutSC::Challenge>:
        Algebra<SymbolicExpression<Val<OutSC>>> + Algebra<OutSC::Challenge>,
    <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::Domain: Send + Sync,
    OutSC::Pcs: Sync,
    <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::ProverData: Sync,
    <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::Commitment: Sync,
{
    let traces = run_aggregation_verification_circuit::<InSC, A1, A2, B, D>(
        left,
        right,
        left_result,
        right_result,
        verification_circuit,
        input_config,
        backend,
    )?;

    prepare_prover::<OutSC, BatchOnly, B, D>(verification_circuit, output_config, backend, params)?
        .prove(&traces)
}

/// Convenience method to build and prove a 2-to-1 aggregation layer.
///
/// The two inputs may be different `RecursionInput` variants (e.g. one `UniStark` left
/// and one `BatchStark` right) or identical ones.
///
/// Preparation is fresh for every call. Use [`crate::prepared::PreparedAggregation`] when
/// repeated proving should retain preparation.
///
/// # Example
///
/// ```ignore
/// let (verification_circuit, (left_result, right_result)) = build_aggregation_layer_circuit::<SC, A1, A2, B, D>(left, right, config, backend)?;
/// let out = prove_aggregation_layer::<SC, A1, A2, B, D>(..., params);
/// ```
pub fn build_and_prove_aggregation_layer<SC, A1, A2, B, const D: usize>(
    left: &RecursionInput<'_, SC, A1>,
    right: &RecursionInput<'_, SC, A2>,
    config: &SC,
    backend: &B,
    params: &ProveNextLayerParams,
) -> Result<RecursionOutput<SC>, VerificationError>
where
    SC: StarkGenericConfig + Send + Sync + Clone + 'static,
    A1: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    A2: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PcsRecursionBackend<SC, A1, D> + PcsRecursionBackend<SC, A2, D>,
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
    let (verification_circuit, (left_result, right_result)) =
        build_aggregation_layer_circuit::<SC, A1, A2, B, D>(left, right, config, backend)?;

    prove_aggregation_layer::<SC, A1, A2, B, D>(
        left,
        right,
        &left_result,
        &right_result,
        &verification_circuit,
        config,
        backend,
        params,
    )
}

/// Convenience method to build and prove a cross-config 2-to-1 aggregation layer.
///
/// Verifies the input proofs under `input_config` (`InSC`) and commits the aggregated proof
/// under `output_config` (`OutSC`). See [`prove_aggregation_layer_cross`].
#[allow(clippy::too_many_arguments)]
pub fn build_and_prove_aggregation_layer_cross<InSC, OutSC, A1, A2, B, const D: usize>(
    left: &RecursionInput<'_, InSC, A1>,
    right: &RecursionInput<'_, InSC, A2>,
    input_config: &InSC,
    output_config: &OutSC,
    backend: &B,
    params: &ProveNextLayerParams,
) -> Result<RecursionOutput<OutSC>, VerificationError>
where
    InSC: StarkGenericConfig + Send + Sync + Clone + 'static,
    OutSC: StarkGenericConfig<Challenge = InSC::Challenge> + Send + Sync + Clone + 'static,
    A1: RecursiveAir<Val<InSC>, InSC::Challenge, LogUpGadget>,
    A2: RecursiveAir<Val<InSC>, InSC::Challenge, LogUpGadget>,
    B: PcsRecursionBackend<InSC, A1, D>
        + PcsRecursionBackend<InSC, A2, D>
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
    SymbolicExpressionExt<Val<InSC>, InSC::Challenge>:
        Algebra<SymbolicExpression<Val<InSC>>> + Algebra<InSC::Challenge>,
    SymbolicExpressionExt<Val<OutSC>, OutSC::Challenge>:
        Algebra<SymbolicExpression<Val<OutSC>>> + Algebra<OutSC::Challenge>,
    <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::Domain: Send + Sync,
    OutSC::Pcs: Sync,
    <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::ProverData: Sync,
    <OutSC::Pcs as Pcs<OutSC::Challenge, OutSC::Challenger>>::Commitment: Sync,
{
    let (verification_circuit, (left_result, right_result)) =
        build_aggregation_layer_circuit::<InSC, A1, A2, B, D>(left, right, input_config, backend)?;

    prove_aggregation_layer_cross::<InSC, OutSC, A1, A2, B, D>(
        left,
        right,
        &left_result,
        &right_result,
        &verification_circuit,
        input_config,
        output_config,
        backend,
        params,
    )
}
