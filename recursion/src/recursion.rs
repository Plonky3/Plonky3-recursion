//! Unified recursion API: one entry point to prove the next layer over a uni-stark or batch-stark proof.

use alloc::rc::Rc;
use alloc::string::ToString;
use alloc::vec::Vec;

use p3_air::SymbolicExpression;
use p3_batch_stark::{CommonData, ProverData};
use p3_circuit::tables::Traces;
use p3_circuit::utils::ColumnsTargets;
use p3_circuit::{Circuit, CircuitBuilder, CircuitRunner, NonPrimitiveOpId};
use p3_circuit_prover::common::{NonPrimitiveConfig, get_airs_and_degrees_with_prep};
use p3_circuit_prover::config::StarkField;
use p3_circuit_prover::field_params::ExtractBinomialW;
use p3_circuit_prover::{
    AirVariant, BatchStarkProof, BatchStarkProver, CircuitProverData, ConstraintProfile,
    TablePacking,
};
use p3_commit::Pcs;
use p3_field::extension::BinomiallyExtendable;
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeField64};
use p3_lookup::logup::LogUpGadget;
use p3_lookup::lookup_traits::{Lookup, LookupData, LookupGadget};
use p3_uni_stark::{Proof, StarkGenericConfig, Val};
use tracing::instrument;

use crate::Target;
use crate::ops::Poseidon2Config;
use crate::traits::{LookupMetadata, RecursiveAir};
use crate::types::RecursiveLagrangeSelectors;
use crate::verifier::VerificationError;

fn proof_shape_err(e: &impl ToString) -> VerificationError {
    VerificationError::InvalidProofShape(e.to_string())
}

/// Cached prover data and prover for aggregation when the same verification circuit is reused per level.
/// Pass `Some(&mut None)` on the first aggregation at a given level; the slot is filled after the
/// first proof and reused for subsequent pairs to avoid ~100ms of clone/from_airs_and_degrees/prover creation.
pub struct AggregationPrepCache<SC: StarkGenericConfig + 'static> {
    pub circuit_prover_data: Rc<CircuitProverData<SC>>,
    pub prover: BatchStarkProver<SC>,
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
            common_data: self.1.common_data(),
            table_public_inputs: alloc::vec![alloc::vec![]; num_tables],
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

    /// Operation IDs that require private data (e.g. Merkle paths) for the circuit runner.
    fn op_ids(&self) -> &[NonPrimitiveOpId];
}

/// PCS-specific backend for building verifier circuits and setting private data.
pub trait PcsRecursionBackend<SC, A>
where
    SC: StarkGenericConfig,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
{
    /// Opaque verifier result returned by `build_verifier_circuit`.
    type VerifierResult: VerifierCircuitResult<SC, A>;

    /// Prepare the circuit before building the verifier (e.g. enable Poseidon2). Called before `build_verifier_circuit`.
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
        runner: &mut CircuitRunner<SC::Challenge>,
        op_ids: &[NonPrimitiveOpId],
        prev: &RecursionInput<'_, SC, A>,
    ) -> Result<(), &'static str>;

    /// If the backend uses Poseidon2 in the circuit (e.g. for MMCS), return its config for `get_airs_and_degrees_with_prep`.
    fn poseidon2_config_for_circuit(&self) -> Option<Poseidon2Config> {
        None
    }
}

/// Parameters for the shared recursion pipeline (table packing, optional overrides).
#[derive(Clone, Debug)]
pub struct ProveNextLayerParams {
    pub table_packing: TablePacking,
    pub use_poseidon2_in_circuit: bool,
    /// Constraint profile controlling which AIR variants are used for this layer.
    pub constraint_profile: ConstraintProfile,
}

impl Default for ProveNextLayerParams {
    fn default() -> Self {
        Self {
            table_packing: TablePacking::new(1, 4),
            use_poseidon2_in_circuit: true,
            constraint_profile: ConstraintProfile::Standard,
        }
    }
}

/// Marker type for batch-only recursion input. Use with [`RecursionOutput::into_recursion_input`]
/// when chaining batch-to-batch layers (e.g. `output.into_recursion_input::<BatchOnly>()`).
#[derive(Debug)]
pub struct BatchOnly;

impl<F: Field, EF: ExtensionField<F>, LG: LookupGadget> RecursiveAir<F, EF, LG> for BatchOnly {
    fn width(&self) -> usize {
        0
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
        _contexts: &[Lookup<F>],
        _lookup_data: &[LookupData<usize>],
        _is_zk: usize,
        _lookup_gadget: &LG,
    ) -> usize {
        0
    }
}

/// Build a verifier circuit for a recursion layer.
#[instrument(skip_all)]
fn build_next_layer_circuit<SC, A, B>(
    prev: &RecursionInput<'_, SC, A>,
    config: &SC,
    backend: &B,
) -> Result<(Circuit<SC::Challenge>, B::VerifierResult), VerificationError>
where
    SC: StarkGenericConfig + Send + Sync + Clone + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PcsRecursionBackend<SC, A>,
    Val<SC>: PrimeField64 + StarkField + BinomiallyExtendable<4>,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + ExtractBinomialW<Val<SC>>,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    let mut circuit_builder = CircuitBuilder::new();
    // Enable Poseidon2
    backend.prepare_circuit(config, &mut circuit_builder)?;

    // Build verifier constraints.
    let verifier_result = backend.build_verifier_circuit(prev, config, &mut circuit_builder)?;
    let verification_circuit = circuit_builder
        .build()
        .map_err(VerificationError::CircuitBuilder)?;

    Ok((verification_circuit, verifier_result))
}

/// Prove one recursion layer: build a verifier circuit for `prev`, run it, and prove it with batch STARK.
#[instrument(skip_all)]
pub fn prove_next_layer<SC, A, B, const D: usize>(
    prev: &RecursionInput<'_, SC, A>,
    verification_circuit: Circuit<SC::Challenge>,
    verifier_result: &B::VerifierResult,
    config: &SC,
    backend: &B,
    params: &ProveNextLayerParams,
) -> Result<RecursionOutput<SC>, VerificationError>
where
    SC: StarkGenericConfig + Send + Sync + Clone + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PcsRecursionBackend<SC, A>,
    Val<SC>: PrimeField64 + StarkField + BinomiallyExtendable<4>,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + ExtractBinomialW<Val<SC>>,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    let non_primitive = backend
        .poseidon2_config_for_circuit()
        .map(|c| alloc::vec![NonPrimitiveConfig::Poseidon2(c)]);
    let non_primitive_ref = non_primitive.as_deref();

    let (airs_degrees, preprocessed_columns) = {
        get_airs_and_degrees_with_prep::<SC, SC::Challenge, D>(
            &verification_circuit,
            params.table_packing,
            non_primitive_ref,
            params.constraint_profile,
        )
        .map_err(VerificationError::Circuit)?
    };

    let (mut airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();

    let traces = {
        let public_inputs = verifier_result.pack_public_inputs(prev)?;
        let mut runner = verification_circuit.runner();
        runner
            .set_public_inputs(&public_inputs)
            .map_err(VerificationError::Circuit)?;

        backend
            .set_private_data(config, &mut runner, verifier_result.op_ids(), prev)
            .map_err(|e| proof_shape_err(&e))?;

        runner.run().map_err(VerificationError::Circuit)?
    };

    let circuit_prover_data = {
        let prover_data = ProverData::from_airs_and_degrees(config, &mut airs, &degrees);
        CircuitProverData::new(prover_data, preprocessed_columns)
    };

    let mut prover = BatchStarkProver::new(config.clone())
        .with_table_packing(params.table_packing)
        .with_alu_variant(match params.constraint_profile {
            ConstraintProfile::Standard => AirVariant::Baseline,
            ConstraintProfile::RecursionOptimized => AirVariant::Optimized,
        });
    if let Some(cfg) = backend.poseidon2_config_for_circuit() {
        prover.register_poseidon2_table(cfg);
    }
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .map_err(|e| proof_shape_err(&e.to_string()))?;

    Ok(RecursionOutput(proof, Rc::new(circuit_prover_data)))
}

/// Convenience method to build and prove a recursion layer.
///
/// In production environments, consider using [`prove_next_layer`] directly for better performance.
///
/// # Example
///
/// ```ignore
/// let (verification_circuit, verifier_result) = build_next_layer_circuit::<SC, A, B>(prev, config, backend)?;
/// let out = prove_next_layer::<SC, A, B, D>(prev, verification_circuit, verifier_result, config, backend, params);
/// ```
pub fn build_and_prove_next_layer<SC, A, B, const D: usize>(
    prev: &RecursionInput<'_, SC, A>,
    config: &SC,
    backend: &B,
    params: &ProveNextLayerParams,
) -> Result<RecursionOutput<SC>, VerificationError>
where
    SC: StarkGenericConfig + Send + Sync + Clone + 'static,
    A: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PcsRecursionBackend<SC, A>,
    Val<SC>: PrimeField64 + StarkField + BinomiallyExtendable<4>,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + ExtractBinomialW<Val<SC>>,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    let (verification_circuit, verifier_result) =
        build_next_layer_circuit::<SC, A, B>(prev, config, backend)?;

    prove_next_layer::<SC, A, B, D>(
        prev,
        verification_circuit,
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
#[instrument(skip_all)]
#[allow(clippy::type_complexity)]
fn build_aggregation_layer_circuit<SC, A1, A2, B, const D: usize>(
    left: &RecursionInput<'_, SC, A1>,
    right: &RecursionInput<'_, SC, A2>,
    config: &SC,
    backend: &B,
) -> Result<
    (
        Circuit<SC::Challenge>,
        (
            <B as PcsRecursionBackend<SC, A1>>::VerifierResult, // left
            <B as PcsRecursionBackend<SC, A2>>::VerifierResult, // right
        ),
    ),
    VerificationError,
>
where
    SC: StarkGenericConfig + Send + Sync + Clone + 'static,
    A1: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    A2: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PcsRecursionBackend<SC, A1> + PcsRecursionBackend<SC, A2>,
    Val<SC>: PrimeField64 + StarkField + BinomiallyExtendable<4>,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + ExtractBinomialW<Val<SC>>,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    let mut circuit_builder = CircuitBuilder::new();

    // Enable Poseidon2 once — shared by both verifications.
    <B as PcsRecursionBackend<SC, A1>>::prepare_circuit(backend, config, &mut circuit_builder)?;
    <B as PcsRecursionBackend<SC, A2>>::prepare_circuit(backend, config, &mut circuit_builder)?;

    // Build left verifier constraints.
    let left_result = backend.build_verifier_circuit(left, config, &mut circuit_builder)?;
    // Build right verifier constraints into the same builder.
    let right_result = backend.build_verifier_circuit(right, config, &mut circuit_builder)?;

    let verification_circuit = circuit_builder
        .build()
        .map_err(VerificationError::CircuitBuilder)?;

    Ok((verification_circuit, (left_result, right_result)))
}

fn run_aggregation_verification_circuit<SC, A1, A2, B>(
    left: &RecursionInput<'_, SC, A1>,
    right: &RecursionInput<'_, SC, A2>,
    left_result: &<B as PcsRecursionBackend<SC, A1>>::VerifierResult,
    right_result: &<B as PcsRecursionBackend<SC, A2>>::VerifierResult,
    verification_circuit: &Circuit<SC::Challenge>,
    config: &SC,
    backend: &B,
) -> Result<Traces<SC::Challenge>, VerificationError>
where
    SC: StarkGenericConfig,
    A1: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    A2: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PcsRecursionBackend<SC, A1> + PcsRecursionBackend<SC, A2>,
    Val<SC>: PrimeField64,
{
    let mut public_inputs = left_result.pack_public_inputs(left)?;
    public_inputs.extend(right_result.pack_public_inputs(right)?);

    let mut runner = verification_circuit.clone().runner();
    runner
        .set_public_inputs(&public_inputs)
        .map_err(VerificationError::Circuit)?;

    <B as PcsRecursionBackend<SC, A1>>::set_private_data(
        backend,
        config,
        &mut runner,
        left_result.op_ids(),
        left,
    )
    .map_err(|e| proof_shape_err(&e.to_string()))?;

    <B as PcsRecursionBackend<SC, A2>>::set_private_data(
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
/// When proving multiple pairs with the same verification circuit (e.g. all pairs at one level),
/// pass `prep_cache: Some(&mut None)` on the first call; the slot is filled and can be passed
/// again for subsequent pairs to skip [`get_airs_and_degrees_with_prep`].
///
/// The two inputs may be different `RecursionInput` variants (e.g. one `UniStark` left
/// and one `BatchStark` right) or identical ones.
#[instrument(skip_all)]
#[allow(clippy::too_many_arguments)]
pub fn prove_aggregation_layer<SC, A1, A2, B, const D: usize>(
    left: &RecursionInput<'_, SC, A1>,
    right: &RecursionInput<'_, SC, A2>,
    left_result: &<B as PcsRecursionBackend<SC, A1>>::VerifierResult,
    right_result: &<B as PcsRecursionBackend<SC, A2>>::VerifierResult,
    verification_circuit: &Circuit<SC::Challenge>,
    config: &SC,
    backend: &B,
    params: &ProveNextLayerParams,
    mut prep_cache: Option<&mut Option<AggregationPrepCache<SC>>>,
) -> Result<RecursionOutput<SC>, VerificationError>
where
    SC: StarkGenericConfig + Send + Sync + Clone + 'static,
    A1: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    A2: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PcsRecursionBackend<SC, A1> + PcsRecursionBackend<SC, A2>,
    Val<SC>: PrimeField64 + StarkField + BinomiallyExtendable<4>,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + ExtractBinomialW<Val<SC>>,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    if let Some(ref mut cache_slot) = prep_cache
        && let Some(cached) = cache_slot.as_ref()
    {
        let traces = run_aggregation_verification_circuit(
            left,
            right,
            left_result,
            right_result,
            verification_circuit,
            config,
            backend,
        )?;
        let proof = cached
            .prover
            .prove_all_tables(&traces, &cached.circuit_prover_data)
            .map_err(|e| proof_shape_err(&e.to_string()))?;
        return Ok(RecursionOutput(
            proof,
            Rc::clone(&cached.circuit_prover_data),
        ));
    }

    let non_primitive = <B as PcsRecursionBackend<SC, A1>>::poseidon2_config_for_circuit(backend)
        .map(|c| alloc::vec![NonPrimitiveConfig::Poseidon2(c)]);
    let (airs_degrees, preprocessed_columns) = {
        get_airs_and_degrees_with_prep::<SC, SC::Challenge, D>(
            verification_circuit,
            params.table_packing,
            non_primitive.as_deref(),
            params.constraint_profile,
        )
        .map_err(VerificationError::Circuit)?
    };

    let (mut airs, degrees): (Vec<_>, Vec<_>) = airs_degrees.into_iter().unzip();

    let traces = run_aggregation_verification_circuit(
        left,
        right,
        left_result,
        right_result,
        verification_circuit,
        config,
        backend,
    )?;

    let circuit_prover_data = {
        let prover_data = ProverData::from_airs_and_degrees(config, &mut airs, &degrees);
        CircuitProverData::new(prover_data, preprocessed_columns)
    };

    let mut prover = BatchStarkProver::new(config.clone())
        .with_table_packing(params.table_packing)
        .with_alu_variant(match params.constraint_profile {
            ConstraintProfile::Standard => AirVariant::Baseline,
            ConstraintProfile::RecursionOptimized => AirVariant::Optimized,
        });
    if let Some(cfg) = <B as PcsRecursionBackend<SC, A1>>::poseidon2_config_for_circuit(backend) {
        prover.register_poseidon2_table(cfg);
    }
    let proof = prover
        .prove_all_tables(&traces, &circuit_prover_data)
        .map_err(|e| proof_shape_err(&e.to_string()))?;

    if let Some(ref mut cache_slot) = prep_cache {
        let circuit_prover_data_rc = Rc::new(circuit_prover_data);
        **cache_slot = Some(AggregationPrepCache {
            circuit_prover_data: Rc::clone(&circuit_prover_data_rc),
            prover,
        });
        Ok(RecursionOutput(proof, circuit_prover_data_rc))
    } else {
        Ok(RecursionOutput(proof, Rc::new(circuit_prover_data)))
    }
}

/// Convenience method to build and prove a 2-to-1 aggregation layer.
///
/// The two inputs may be different `RecursionInput` variants (e.g. one `UniStark` left
/// and one `BatchStark` right) or identical ones.
///
/// In production environments, consider using [`prove_aggregation_layer`] directly for better performance.
///
/// # Example
///
/// ```ignore
/// let (verification_circuit, (left_result, right_result)) = build_aggregation_layer_circuit::<SC, A1, A2, B, D>(left, right, config, backend)?;
/// let out = prove_aggregation_layer::<SC, A1, A2, B, D>(..., params, None);
/// ```
pub fn build_and_prove_aggregation_layer<SC, A1, A2, B, const D: usize>(
    left: &RecursionInput<'_, SC, A1>,
    right: &RecursionInput<'_, SC, A2>,
    config: &SC,
    backend: &B,
    params: &ProveNextLayerParams,
    prep_cache: Option<&mut Option<AggregationPrepCache<SC>>>,
) -> Result<RecursionOutput<SC>, VerificationError>
where
    SC: StarkGenericConfig + Send + Sync + Clone + 'static,
    A1: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    A2: RecursiveAir<Val<SC>, SC::Challenge, LogUpGadget>,
    B: PcsRecursionBackend<SC, A1> + PcsRecursionBackend<SC, A2>,
    Val<SC>: PrimeField64 + StarkField + BinomiallyExtendable<4>,
    SC::Challenge: BasedVectorSpace<Val<SC>>
        + From<Val<SC>>
        + ExtensionField<Val<SC>>
        + ExtractBinomialW<Val<SC>>,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
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
        prep_cache,
    )
}
