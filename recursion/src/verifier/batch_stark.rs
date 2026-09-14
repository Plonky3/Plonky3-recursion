#![allow(clippy::upper_case_acronyms)]

use alloc::borrow::Cow;
use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;
use alloc::{format, vec};

use hashbrown::HashMap;
use p3_air::{Air as P3Air, BaseAir as P3BaseAir};
use p3_batch_stark::CommonData;
use p3_circuit::symbolic::ColumnsTargets;
use p3_circuit::{CircuitBuilder, NonPrimitiveOpId};
use p3_circuit_prover::air::{AluAir, AluExtMulKind, ConstAir, PublicAir};
use p3_circuit_prover::batch_stark_prover::{
    AirVariant, DynamicAirEntry, NUM_PRIMITIVE_TABLES, PrimitiveTable, RowCounts, TableProver,
    lookups_for_circuit_table_air,
};
use p3_circuit_prover::common::CircuitTableAir;
use p3_circuit_prover::field_params::ExtractBinomialW;
use p3_commit::{Pcs, PolynomialSpace};
use p3_field::{
    Algebra, BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField64,
};
use p3_lookup::{Kind, Lookup, LookupProtocol};
use p3_uni_stark::{
    StarkGenericConfig, SymbolicExpression, SymbolicExpressionExt, Val, validate_degree_bits,
};

use super::{ObservableCommitment, VerificationError, recompose_quotient_from_chunks_circuit};
use crate::challenger::CircuitChallenger;
use crate::challenger_perm::ChallengerPermConfig;
use crate::input_contract::stark_layout::{
    CommitmentRole, InstanceLayout, MatrixRoute, NativeStarkLayout,
};
use crate::traits::{
    LookupMetadata, Recursive, RecursiveAir, RecursiveChallenger, RecursiveLookupGadget,
    RecursivePcs,
};
use crate::types::{
    BatchProofTargets, CommonDataTargets, OpenedValuesTargets, OpenedValuesTargetsWithLookups,
};
use crate::{BatchStarkVerifierInputsBuilder, Target};

/// Type alias for PCS verifier parameters.
pub type PcsVerifierParams<SC, InputProof, OpeningProof, Comm> =
    <<SC as StarkGenericConfig>::Pcs as RecursivePcs<
        SC,
        InputProof,
        OpeningProof,
        Comm,
        <<SC as StarkGenericConfig>::Pcs as Pcs<
            <SC as StarkGenericConfig>::Challenge,
            <SC as StarkGenericConfig>::Challenger,
        >>::Domain,
    >>::VerifierParams;

/// Type-erased recursive AIR entry for non-primitive tables.
pub type DynRecursionAirEntry<SC> = DynamicAirEntry<SC>;

/// Wrapper enum for heterogeneous circuit table AIRs used by circuit-prover tables.
pub enum CircuitTablesAir<SC: StarkGenericConfig, const D: usize> {
    Const(ConstAir<Val<SC>, D>),
    Public(PublicAir<Val<SC>, D>),
    Alu(AluAir<Val<SC>, D>),
    Dynamic(DynRecursionAirEntry<SC>),
}

impl<SC: StarkGenericConfig, const D: usize> CircuitTablesAir<SC, D>
where
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SymbolicExpression<Val<SC>>>,
{
    /// Bridge to the circuit-prover enum so the verifier can rebuild its own lookup
    /// contexts from the reconstructed AIRs. Both enums wrap the identical inner AIRs.
    pub(crate) fn to_table_air(&self) -> CircuitTableAir<SC, D> {
        match self {
            Self::Const(a) => CircuitTableAir::Const(a.clone()),
            Self::Public(a) => CircuitTableAir::Public(a.clone()),
            Self::Alu(a) => CircuitTableAir::Alu(a.clone()),
            Self::Dynamic(a) => CircuitTableAir::Dynamic(a.clone()),
        }
    }
}

impl<SC, const D: usize> P3BaseAir<Val<SC>> for CircuitTablesAir<SC, D>
where
    SC: StarkGenericConfig,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>: Algebra<SymbolicExpression<Val<SC>>>,
{
    fn width(&self) -> usize {
        match self {
            Self::Const(a) => P3BaseAir::width(a),
            Self::Public(a) => P3BaseAir::width(a),
            Self::Alu(a) => P3BaseAir::width(a),
            Self::Dynamic(a) => P3BaseAir::width(a),
        }
    }

    fn preprocessed_width(&self) -> usize {
        match self {
            Self::Const(a) => P3BaseAir::preprocessed_width(a),
            Self::Public(a) => P3BaseAir::preprocessed_width(a),
            Self::Alu(a) => P3BaseAir::preprocessed_width(a),
            Self::Dynamic(a) => P3BaseAir::preprocessed_width(a),
        }
    }

    fn num_public_values(&self) -> usize {
        match self {
            Self::Const(a) => P3BaseAir::num_public_values(a),
            Self::Public(a) => P3BaseAir::num_public_values(a),
            Self::Alu(a) => P3BaseAir::num_public_values(a),
            Self::Dynamic(a) => P3BaseAir::num_public_values(a),
        }
    }

    fn main_next_row_columns(&self) -> Vec<usize> {
        match self {
            Self::Const(a) => P3BaseAir::main_next_row_columns(a),
            Self::Public(a) => P3BaseAir::main_next_row_columns(a),
            Self::Alu(a) => P3BaseAir::main_next_row_columns(a),
            Self::Dynamic(a) => P3BaseAir::main_next_row_columns(a),
        }
    }

    fn num_periodic_columns(&self) -> usize {
        match self {
            Self::Const(a) => P3BaseAir::num_periodic_columns(a),
            Self::Public(a) => P3BaseAir::num_periodic_columns(a),
            Self::Alu(a) => P3BaseAir::num_periodic_columns(a),
            Self::Dynamic(a) => P3BaseAir::num_periodic_columns(a),
        }
    }

    fn periodic_columns(&self) -> Cow<'_, [Vec<Val<SC>>]> {
        match self {
            Self::Const(a) => P3BaseAir::periodic_columns(a),
            Self::Public(a) => P3BaseAir::periodic_columns(a),
            Self::Alu(a) => P3BaseAir::periodic_columns(a),
            Self::Dynamic(a) => P3BaseAir::periodic_columns(a),
        }
    }
}

impl<SC, const D: usize>
    P3Air<
        p3_lookup::symbolic::InteractionSymbolicBuilder<
            Val<SC>,
            <SC as StarkGenericConfig>::Challenge,
        >,
    > for CircuitTablesAir<SC, D>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField64,
    <SC as StarkGenericConfig>::Challenge: ExtensionField<Val<SC>>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn eval(
        &self,
        builder: &mut p3_lookup::symbolic::InteractionSymbolicBuilder<
            Val<SC>,
            <SC as StarkGenericConfig>::Challenge,
        >,
    ) {
        match self {
            Self::Const(a) => P3Air::eval(a, builder),
            Self::Public(a) => P3Air::eval(a, builder),
            Self::Alu(a) => P3Air::eval(a, builder),
            Self::Dynamic(inner) => P3Air::eval(inner, builder),
        }
    }
}

/// Create an AluAir with the appropriate constructor based on TRACE_D.
///
/// For D=1 (base field), uses `new_with_preprocessed` with zeroed lane prep.
/// For D=5 with `alu_quintic_trinomial`, uses `new_quintic_trinomial_with_preprocessed`.
/// Otherwise for D>1, uses `new_binomial_with_preprocessed` with `W` from `EF`.
/// `horner_packed_steps` must match `BatchStarkProof.table_packing.horner_packed_steps` from the proof.
///
/// # Errors
/// Returns an error if `TRACE_D` and `alu_quintic_trinomial` (both proof-controlled) don't
/// resolve to a supported ALU extension-multiplication kind for `EF` — e.g. a quintic extension
/// declared without the trinomial flag, which has no binomial `W`.
fn create_alu_air<F, EF, const TRACE_D: usize>(
    num_ops: usize,
    lanes: usize,
    horner_packed_steps: usize,
    alu_quintic_trinomial: bool,
) -> Result<AluAir<F, TRACE_D>, String>
where
    F: Field + PrimeCharacteristicRing + Copy,
    EF: ExtensionField<F> + ExtractBinomialW<F>,
{
    if lanes == 0 {
        return Err("ALU lane count must be non-zero".to_string());
    }
    if horner_packed_steps < 2 {
        return Err("packed Horner step count must be at least two".to_string());
    }
    let reduction = AluExtMulKind::resolve(
        TRACE_D,
        EF::extract_w(),
        TRACE_D == 5 && alu_quintic_trinomial,
    )
    .ok_or_else(|| {
        format!(
            "unsupported ALU extension-multiplication kind for trace degree {TRACE_D} \
             (alu_quintic_trinomial={alu_quintic_trinomial})"
        )
    })?;
    Ok(
        AluAir::<F, TRACE_D>::from_reduction(num_ops, lanes, reduction)
            .with_horner_pack_k(horner_packed_steps),
    )
}

/// The batch-STARK tables a recursion-layer proof describes, rebuilt from the proof's own
/// metadata (packing, row counts, non-primitive manifest) rather than trusted from it.
pub struct ReconstructedBatchTables<SC: StarkGenericConfig, const D: usize> {
    /// One AIR per table, in the order the proof's instances appear.
    pub airs: Vec<CircuitTablesAir<SC, D>>,
    /// Each table's trace length, as the proof declares it.
    pub trace_lens: Vec<usize>,
    /// Each table's public values: empty for the primitive tables, the manifest entry's own for
    /// the non-primitive ones.
    pub public_values: Vec<Vec<Val<SC>>>,
}

/// Rebuild the AIRs a recursion-layer batch proof was produced against.
///
/// The proof carries only a manifest — table packing, per-table row counts, and one entry per
/// non-primitive table — so the AIRs themselves are derived here and never taken from the proof.
/// `non_primitive_provers` supplies the plugins that turn each manifest entry into an AIR; the
/// entry's declared op type is checked against the plugin's before it is used.
pub fn reconstruct_batch_tables<SC: StarkGenericConfig + 'static, const TRACE_D: usize>(
    config: &SC,
    proof: &p3_circuit_prover::batch_stark_prover::BatchStarkProof<SC>,
    non_primitive_provers: &[Box<dyn TableProver<SC>>],
) -> Result<ReconstructedBatchTables<SC, TRACE_D>, VerificationError>
where
    Val<SC>: PrimeField64,
    SC::Challenge: ExtensionField<Val<SC>> + ExtractBinomialW<Val<SC>>,
{
    proof
        .validate()
        .map_err(|e| VerificationError::InvalidProofShape(e.to_string()))?;
    if proof.ext_degree != TRACE_D {
        return Err(VerificationError::InvalidProofShape(format!(
            "trace extension degree mismatch: proof declares {} but verifier expects {TRACE_D}",
            proof.ext_degree
        )));
    }
    if proof.non_primitives.len() != non_primitive_provers.len() {
        return Err(VerificationError::InvalidProofShape(format!(
            "non-primitive table count mismatch: expected {}, got {}",
            non_primitive_provers.len(),
            proof.non_primitives.len()
        )));
    }
    for (i, (entry, plugin)) in proof
        .non_primitives
        .iter()
        .zip(non_primitive_provers.iter())
        .enumerate()
    {
        let expected_op = TableProver::op_type(plugin.as_ref());
        if entry.op_type != expected_op {
            return Err(VerificationError::InvalidProofShape(format!(
                "non-primitive op_type mismatch at index {i}: expected {expected_op:?}, got {:?}",
                entry.op_type
            )));
        }
    }
    let rows: RowCounts = proof.rows;
    let packing = proof.table_packing.clone();
    let public_lanes = packing.public_lanes();
    let alu_lanes = packing.alu_lanes();

    // Create AluAir with appropriate constructor based on TRACE_D and the stored
    // primitive ALU variant used during proving.
    // For now both variants share the same AIR type; this hook allows us to swap
    // in a different ALU AIR in the future based on `proof.alu_variant`.
    let alu_air = match proof.alu_variant {
        AirVariant::Baseline | AirVariant::Optimized => {
            create_alu_air::<Val<SC>, SC::Challenge, TRACE_D>(
                rows[PrimitiveTable::Alu],
                alu_lanes,
                packing.horner_packed_steps(),
                proof.alu_quintic_trinomial,
            )
            .map_err(VerificationError::InvalidProofShape)?
        }
    };

    let mut airs: Vec<CircuitTablesAir<SC, TRACE_D>> = vec![
        CircuitTablesAir::Const(ConstAir::<Val<SC>, TRACE_D>::new(
            rows[PrimitiveTable::Const],
        )),
        CircuitTablesAir::Public(PublicAir::<Val<SC>, TRACE_D>::new(
            rows[PrimitiveTable::Public],
            public_lanes,
        )),
        CircuitTablesAir::Alu(alu_air),
    ];
    let mut trace_lens = vec![
        rows[PrimitiveTable::Const],
        rows[PrimitiveTable::Public],
        rows[PrimitiveTable::Alu],
    ];
    let mut public_values: Vec<Vec<Val<SC>>> = vec![Vec::new(); NUM_PRIMITIVE_TABLES];

    for (entry, plugin) in proof
        .non_primitives
        .iter()
        .zip(non_primitive_provers.iter())
    {
        let air = plugin
            .batch_air_from_table_entry(config, TRACE_D, proof.ext_degree as u32, entry)
            .map_err(VerificationError::InvalidProofShape)?;
        airs.push(CircuitTablesAir::Dynamic(air));
        trace_lens.push(entry.rows);
        public_values.push(entry.public_values.clone());
    }

    Ok(ReconstructedBatchTables {
        airs,
        trace_lens,
        public_values,
    })
}

/// Build and attach a recursive verifier circuit for a circuit-prover [`BatchStarkProof`].
///
/// This reconstructs the circuit table AIRs from the proof metadata (rows + packing) so callers
/// don't need to pass `circuit_airs` explicitly. Returns the allocated input builder to pack
/// public inputs afterwards.
#[allow(clippy::type_complexity)]
#[allow(clippy::too_many_arguments)]
pub fn verify_p3_batch_proof_circuit<
    SC: StarkGenericConfig + 'static,
    Comm: Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        > + Clone
        + ObservableCommitment,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge, Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Proof>,
    LG: RecursiveLookupGadget<SC::Challenge>,
    CP: ChallengerPermConfig,
    const WIDTH: usize,
    const RATE: usize,
    const TRACE_D: usize,
>(
    config: &SC,
    circuit: &mut CircuitBuilder<SC::Challenge>,
    proof: &p3_circuit_prover::batch_stark_prover::BatchStarkProof<SC>,
    pcs_params: &PcsVerifierParams<SC, InputProof, OpeningProof, Comm>,
    common_data: &CommonData<SC>,
    lookup_gadget: &LG,
    challenger_perm_config: CP,
    non_primitive_provers: &[Box<dyn TableProver<SC>>],
) -> Result<
    (
        BatchStarkVerifierInputsBuilder<SC, Comm, OpeningProof>,
        Vec<NonPrimitiveOpId>,
    ),
    VerificationError,
>
where
    <SC as StarkGenericConfig>::Pcs: RecursivePcs<
            SC,
            InputProof,
            OpeningProof,
            Comm,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
    Val<SC>: PrimeField64,
    SC::Challenge: ExtensionField<Val<SC>> + PrimeCharacteristicRing + ExtractBinomialW<Val<SC>>,
    <<SC as StarkGenericConfig>::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain: Clone,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    let tables = reconstruct_batch_tables::<SC, TRACE_D>(config, proof, non_primitive_provers)?;
    let ReconstructedBatchTables {
        airs: circuit_airs,
        trace_lens,
        public_values,
    } = &tables;

    let air_public_counts: Vec<usize> = public_values.iter().map(Vec::len).collect();
    let mut verifier_inputs = BatchStarkVerifierInputsBuilder::<SC, Comm, OpeningProof>::allocate(
        circuit,
        &proof.proof,
        common_data,
        &air_public_counts,
    )?;

    // Rebuild the lookup contexts from the reconstructed (audited) AIRs instead of trusting
    // the proof-supplied `common.lookups`, which drives the CTL folding, aux width, and
    // challenge layout. For an honest proof these are identical (both derived from the same
    // AIRs); a malformed or malicious lookup set is now ignored rather than believed.
    verifier_inputs.common_data.lookups = circuit_airs
        .iter()
        .zip(trace_lens.iter())
        .map(|(air, &trace_len)| {
            lookups_for_circuit_table_air::<SC, TRACE_D>(
                &air.to_table_air(),
                trace_len,
                config.is_zk(),
            )
            .to_vec()
        })
        .collect();

    let common = &verifier_inputs.common_data;

    let mmcs_op_ids = verify_batch_circuit::<
        CircuitTablesAir<SC, TRACE_D>,
        SC,
        Comm,
        InputProof,
        OpeningProof,
        LG,
        CP,
        WIDTH,
        RATE,
    >(
        config,
        circuit_airs,
        circuit,
        &verifier_inputs.proof_targets,
        &verifier_inputs.air_public_targets,
        pcs_params,
        common,
        lookup_gadget,
        challenger_perm_config,
    )?;

    Ok((verifier_inputs, mmcs_op_ids))
}

/// Verify a batch-STARK proof inside a recursive circuit.
///
/// # Returns
/// `Ok(Vec<NonPrimitiveOpId>)` containing operation IDs that require private data
/// (e.g., Merkle sibling values for MMCS verification). The caller must set
/// private data for these operations before running the circuit.
/// `Err` if there was a structural error.
#[allow(clippy::too_many_arguments)]
pub fn verify_batch_circuit<
    A,
    SC: StarkGenericConfig,
    Comm: Recursive<
            SC::Challenge,
            Input = <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Commitment,
        > + Clone
        + ObservableCommitment,
    InputProof: Recursive<SC::Challenge>,
    OpeningProof: Recursive<SC::Challenge>,
    LG: RecursiveLookupGadget<SC::Challenge>,
    CP: ChallengerPermConfig,
    const WIDTH: usize,
    const RATE: usize,
>(
    config: &SC,
    airs: &[A],
    circuit: &mut CircuitBuilder<SC::Challenge>,
    proof_targets: &BatchProofTargets<SC, Comm, OpeningProof>,
    public_values: &[Vec<Target>],
    pcs_params: &PcsVerifierParams<SC, InputProof, OpeningProof, Comm>,
    common: &CommonDataTargets<SC, Comm>,
    lookup_gadget: &LG,
    challenger_perm_config: CP,
) -> Result<Vec<NonPrimitiveOpId>, VerificationError>
where
    A: RecursiveAir<Val<SC>, SC::Challenge, LG>,
    <SC as StarkGenericConfig>::Pcs: RecursivePcs<
            SC,
            InputProof,
            OpeningProof,
            Comm,
            <SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain,
        >,
    Val<SC>: PrimeField64,
    SC::Challenge: ExtensionField<Val<SC>> + PrimeCharacteristicRing,
    <<SC as StarkGenericConfig>::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain: Clone,
{
    let BatchProofTargets {
        commitments_targets,
        flattened_opened_values_targets: flattened,
        opened_values_targets,
        opening_proof,
        lookup_terminals,
        degree_bits,
    } = proof_targets;
    let instances = &opened_values_targets.instances;

    if airs.is_empty() {
        return Err(VerificationError::InvalidProofShape(
            "batch-STARK verification requires at least one instance".to_string(),
        ));
    }

    if airs.len() != instances.len()
        || airs.len() != public_values.len()
        || airs.len() != proof_targets.degree_bits.len()
    {
        return Err(VerificationError::InvalidProofShape(
            "Mismatch between number of AIRs, instances, public values, or degree bits".to_string(),
        ));
    }

    if lookup_terminals.len() != instances.len() {
        return Err(VerificationError::InvalidProofShape(format!(
            "lookup terminal count mismatch: expected {}, got {}",
            instances.len(),
            lookup_terminals.len()
        )));
    }

    // Proof-supplied degree_bits feed `1 << degree_bits` below; validate bounds up front
    // (parity with native p3-batch-stark/p3-uni-stark) instead of shift-overflowing or
    // building a degenerate domain from a crafted proof.
    let pcs = config.pcs();
    for (i, &db) in degree_bits.iter().enumerate() {
        validate_degree_bits(Some(i), db, config.is_zk(), pcs.log_max_lde_height())
            .map_err(|e| VerificationError::InvalidProofShape(e.to_string()))?;
    }

    // `common` is consumed by per-instance indexing below (`common.lookups[i]`,
    // `global.instances.instances[i]`, and `matrix_to_instance` lookups). Validate
    // its lengths and bounds up front so malformed/mismatched `CommonData` returns
    // a typed error instead of panicking during circuit construction.
    if common.lookups.len() != airs.len() {
        return Err(VerificationError::InvalidProofShape(format!(
            "common-data lookups length must equal number of AIR instances: expected {}, got {}",
            airs.len(),
            common.lookups.len()
        )));
    }
    if let Some(global) = &common.preprocessed {
        if global.instances.instances.len() != airs.len() {
            return Err(VerificationError::InvalidProofShape(format!(
                "common-data preprocessed instance metadata length must equal number of AIR \
                 instances: expected {}, got {}",
                airs.len(),
                global.instances.instances.len()
            )));
        }
        if let Some(&bad) = global
            .matrix_to_instance
            .iter()
            .find(|&&idx| idx >= airs.len())
        {
            return Err(VerificationError::InvalidProofShape(format!(
                "common-data matrix_to_instance entry {bad} out of bounds for {} instances",
                airs.len()
            )));
        }
    }

    let all_lookups = &common.lookups;

    let pcs = config.pcs();

    let n_instances = airs.len();

    // Check randomization consistency against the PCS ZK setting.
    if (instances
        .iter()
        .any(|inst| inst.opened_values_no_lookups.random_targets.is_some() != SC::Pcs::ZK))
        || (commitments_targets.random_commit.is_some() != SC::Pcs::ZK)
    {
        return Err(VerificationError::RandomizationError);
    }

    // Pre-compute per-instance quotient degrees and preprocessed widths, and validate proof shape.
    let mut preprocessed_widths = Vec::with_capacity(airs.len());
    let mut log_quotient_degrees = Vec::with_capacity(n_instances);
    let mut quotient_degrees = Vec::with_capacity(n_instances);
    let mut permutation_widths = Vec::with_capacity(n_instances);
    for (i, (air, instance)) in airs.iter().zip(instances.iter()).enumerate() {
        let OpenedValuesTargets {
            trace_local_targets,
            trace_next_targets,
            preprocessed_local_targets,
            preprocessed_next_targets,
            quotient_chunks_targets,
            random_targets,
            ..
        } = &instance.opened_values_no_lookups;

        let pre_w = common
            .preprocessed
            .as_ref()
            .and_then(|g| g.instances.instances[i].as_ref().map(|m| m.width))
            .unwrap_or(0);
        preprocessed_widths.push(pre_w);

        let local_prep_len = preprocessed_local_targets.as_ref().map_or(0, |v| v.len());
        let next_prep_len = preprocessed_next_targets.as_ref().map_or(0, |v| v.len());
        let expected_next_prep_len = if air.opens_preprocessed_next() {
            pre_w
        } else {
            0
        };
        if local_prep_len != pre_w || next_prep_len != expected_next_prep_len {
            return Err(VerificationError::InvalidProofShape(format!(
                "Instance has incorrect preprocessed width: expected {pre_w} / {expected_next_prep_len}, got {local_prep_len} / {next_prep_len}"
            )));
        }
        let air_width = A::width(air);
        // The next-row opening is suppressed (empty) for AIRs that do not access it.
        let expected_next_len = if air.opens_trace_next() { air_width } else { 0 };
        if trace_local_targets.len() != air_width || trace_next_targets.len() != expected_next_len {
            return Err(VerificationError::InvalidProofShape(format!(
                "Instance has incorrect trace width: expected {air_width} / {expected_next_len}, got {} / {}",
                trace_local_targets.len(),
                trace_next_targets.len()
            )));
        }

        let expected_permutation_width = if all_lookups[i].is_empty() {
            0
        } else {
            (all_lookups[i].len() + 1)
                .checked_mul(SC::Challenge::DIMENSION)
                .ok_or_else(|| {
                    VerificationError::InvalidProofShape(
                        "packed permutation width overflows".to_string(),
                    )
                })?
        };
        if instance.permutation_local_targets.len() != expected_permutation_width
            || instance.permutation_next_targets.len() != expected_permutation_width
        {
            return Err(VerificationError::InvalidProofShape(
                "flattened permutation opening width does not match packed lookup metadata"
                    .to_string(),
            ));
        }
        permutation_widths.push(expected_permutation_width);

        // Single-terminal layout: exactly one terminal is present iff the AIR declares any lookup.
        // Derive from the AIR directly — `common.lookups` is prover-supplied and cannot be
        // trusted to correctly report which instances use the lookup argument.
        let expected_present = air.declares_interactions(pre_w);
        if lookup_terminals[i].is_some() != expected_present {
            return Err(VerificationError::InvalidProofShape(
                "Lookup terminal presence does not match the AIR's declared lookups".to_string(),
            ));
        }

        let base_db = degree_bits[i].checked_sub(config.is_zk()).ok_or_else(|| {
            VerificationError::InvalidProofShape(
                "Extended degree bits smaller than ZK adjustment".to_string(),
            )
        })?;
        let log_qd = A::get_log_num_quotient_chunks(
            air,
            pre_w,
            1usize << base_db,
            &all_lookups[i],
            config.is_zk(),
            lookup_gadget,
        );
        let quotient_degree = 1 << (log_qd + config.is_zk());

        if quotient_chunks_targets.len() != quotient_degree {
            return Err(VerificationError::InvalidProofShape(format!(
                "Instance quotient chunk count mismatch: expected {}, got {}",
                quotient_degree,
                quotient_chunks_targets.len()
            )));
        }

        if quotient_chunks_targets
            .iter()
            .any(|chunk| chunk.len() != SC::Challenge::DIMENSION)
        {
            return Err(VerificationError::InvalidProofShape(format!(
                "Invalid quotient chunk length: expected {}",
                SC::Challenge::DIMENSION
            )));
        }

        if random_targets
            .as_ref()
            .is_some_and(|r_vals| r_vals.len() != SC::Challenge::DIMENSION)
        {
            return Err(VerificationError::RandomizationError);
        }

        log_quotient_degrees.push(log_qd);
        quotient_degrees.push(quotient_degree);
    }

    let layout_instances: Vec<InstanceLayout> = airs
        .iter()
        .zip(degree_bits.iter().zip(log_quotient_degrees.iter()))
        .enumerate()
        .map(|(i, (air, (&ext_log, &quotient_log)))| InstanceLayout {
            ext_log,
            base_log: ext_log - config.is_zk(),
            challenge_width: SC::Challenge::DIMENSION,
            trace_width: air.width(),
            trace_next: air.opens_trace_next(),
            pre_width: preprocessed_widths[i],
            pre_next: air.opens_preprocessed_next(),
            quotient_log,
            quotient_chunks: quotient_degrees[i],
            permutation_width: permutation_widths[i],
        })
        .collect();
    let preprocessed_order = common
        .preprocessed
        .as_ref()
        .map_or(&[][..], |global| global.matrix_to_instance.as_slice());
    let layout = NativeStarkLayout::new(
        layout_instances,
        preprocessed_order,
        commitments_targets.random_commit.is_some(),
        common.preprocessed.is_some(),
        commitments_targets.permutation_targets.is_some(),
    )
    .map_err(|error| VerificationError::InvalidProofShape(error.to_string()))?;
    if layout.commitment_count()
        != usize::from(commitments_targets.random_commit.is_some())
            + 2
            + usize::from(common.preprocessed.is_some())
            + usize::from(commitments_targets.permutation_targets.is_some())
    {
        return Err(VerificationError::InvalidProofShape(
            "STARK opening commitment layout mismatch".to_string(),
        ));
    }
    debug_assert_eq!(
        layout.commitment_role(usize::from(layout.has_random)),
        Some(CommitmentRole::Trace)
    );

    // Challenger initialisation mirrors the native batch-STARK verifier transcript.
    // Native uses observe_base_as_algebra_element which decomposes to D coefficients,
    // so we use observe_ext to match.
    let mut challenger = CircuitChallenger::<WIDTH, RATE, CP>::new(challenger_perm_config);
    let inst_count_target = circuit.alloc_const(
        SC::Challenge::from_usize(n_instances),
        "number of instances",
    );
    challenger.observe_ext(circuit, inst_count_target);

    for ((&ext_db, quotient_degree), air) in degree_bits
        .iter()
        .zip(quotient_degrees.iter())
        .zip(airs.iter())
    {
        let base_db = ext_db.checked_sub(config.is_zk()).ok_or_else(|| {
            VerificationError::InvalidProofShape(
                "Extended degree bits smaller than ZK adjustment".to_string(),
            )
        })?;
        let base_db_target =
            circuit.alloc_const(SC::Challenge::from_usize(base_db), "base degree bits");
        let ext_db_target =
            circuit.alloc_const(SC::Challenge::from_usize(ext_db), "extended degree bits");
        let width_target =
            circuit.alloc_const(SC::Challenge::from_usize(A::width(air)), "air width");
        let quotient_chunks_target = circuit.alloc_const(
            SC::Challenge::from_usize(*quotient_degree),
            "quotient chunk count",
        );

        // Native uses observe_base_as_algebra_element (via observe_instance_binding),
        // so we use observe_ext to match by decomposing to D base coefficients.
        challenger.observe_ext(circuit, ext_db_target);
        challenger.observe_ext(circuit, base_db_target);
        challenger.observe_ext(circuit, width_target);
        challenger.observe_ext(circuit, quotient_chunks_target);
    }

    challenger.observe_slice(
        circuit,
        &commitments_targets.trace_targets.to_observation_targets(),
    );
    for pv in public_values {
        challenger.observe_slice(circuit, pv);
    }

    // Observe preprocessed widths for each instance. If a global
    // preprocessed commitment exists, observe it once.
    // Native uses observe_base_as_algebra_element, so we use observe_ext.
    for &pre_w in preprocessed_widths.iter() {
        let pre_w_target =
            circuit.alloc_const(SC::Challenge::from_usize(pre_w), "preprocessed width");
        challenger.observe_ext(circuit, pre_w_target);
    }
    if let Some(global) = &common.preprocessed {
        challenger.observe_slice(circuit, &global.commitment.to_observation_targets());
    }

    // Validate shape of the lookup commitment.
    let is_lookup = proof_targets
        .commitments_targets
        .permutation_targets
        .is_some();
    if is_lookup != all_lookups.iter().any(|c| !c.is_empty()) {
        return Err(VerificationError::InvalidProofShape(
            "Mismatch between lookup commitment and lookup data".to_string(),
        ));
    }

    // Fetch lookups and sample their challenges.
    let challenges_per_instance = get_perm_challenges::<SC, CP, WIDTH, RATE, LG>(
        circuit,
        &mut challenger,
        all_lookups,
        lookup_gadget,
    );

    // Then, observe the permutation tables, if any.
    if is_lookup {
        challenger.observe_slice(
            circuit,
            &commitments_targets
                .permutation_targets
                .clone()
                .expect("We checked that the commitment exists")
                .to_observation_targets(),
        );
        for terminal in lookup_terminals.iter().flatten() {
            challenger.observe_ext(circuit, *terminal);
        }
    }

    // Sample alpha challenge (extension field element)
    let alpha = challenger.sample_ext(circuit);

    challenger.observe_slice(
        circuit,
        &commitments_targets
            .quotient_chunks_targets
            .to_observation_targets(),
    );
    if let Some(random_commit) = &commitments_targets.random_commit {
        challenger.observe_slice(circuit, &random_commit.to_observation_targets());
    }
    // Sample zeta challenge (extension field element)
    let zeta = challenger.sample_ext(circuit);

    // Build per-instance domains.
    let mut trace_domains = Vec::with_capacity(n_instances);
    let mut ext_trace_domains = Vec::with_capacity(n_instances);
    for &ext_db in degree_bits {
        let base_db = ext_db.checked_sub(config.is_zk()).ok_or_else(|| {
            VerificationError::InvalidProofShape(
                "Extended degree bits smaller than ZK adjustment".to_string(),
            )
        })?;
        trace_domains.push(pcs.natural_domain_for_degree(1 << base_db));
        ext_trace_domains.push(pcs.natural_domain_for_degree(1 << ext_db));
    }

    // Collect commitments with opening points for PCS verification.
    // We have, in the typical lookup case, up to five rounds:
    // optional random, trace, quotient, optional preprocessed, and optional permutation.
    let mut coms_to_verify = Vec::with_capacity(5);

    if let Some(random_commit) = &commitments_targets.random_commit {
        let random_round = layout
            .matrices(CommitmentRole::Random)
            .map(|matrix| {
                let MatrixRoute::Random { instance } = matrix.route else {
                    unreachable!("random planner emits only random routes")
                };
                let random_vals = instances[instance]
                    .opened_values_no_lookups
                    .random_targets
                    .as_ref()
                    .ok_or(VerificationError::RandomizationError)?;
                Ok((
                    ext_trace_domains[instance],
                    vec![(zeta, random_vals.clone())],
                ))
            })
            .collect::<Result<Vec<_>, VerificationError>>()?;
        coms_to_verify.push((random_commit.clone(), random_round));
    }

    // Trace-domain generator for `zeta_next = zeta * g`, where `g` advances the domain by one row.
    let trace_domain_generator =
        |trace_dom: &<SC::Pcs as Pcs<SC::Challenge, SC::Challenger>>::Domain| {
            let first_point = pcs.first_point(trace_dom);
            let next_point = trace_dom.next_point(first_point).ok_or_else(|| {
                VerificationError::InvalidProofShape(
                    "Trace domain does not provide next point".to_string(),
                )
            })?;
            Ok::<_, VerificationError>(next_point * first_point.inverse())
        };

    let trace_round: Vec<_> = layout
        .matrices(CommitmentRole::Trace)
        .map(|matrix| {
            let MatrixRoute::Trace { instance } = matrix.route else {
                unreachable!("trace planner emits only trace routes")
            };
            let inst = &instances[instance];
            let mut points = vec![(
                zeta,
                inst.opened_values_no_lookups.trace_local_targets.clone(),
            )];
            if matrix.point_count == 2 {
                let generator_const =
                    circuit.define_const(trace_domain_generator(&trace_domains[instance])?);
                let zeta_next = circuit.mul(zeta, generator_const);
                points.push((
                    zeta_next,
                    inst.opened_values_no_lookups.trace_next_targets.clone(),
                ));
            }
            Ok((ext_trace_domains[instance], points))
        })
        .collect::<Result<_, VerificationError>>()?;
    coms_to_verify.push((commitments_targets.trace_targets.clone(), trace_round));

    let quotient_domains: Vec<Vec<_>> = degree_bits
        .iter()
        .zip(ext_trace_domains.iter())
        .zip(log_quotient_degrees.iter())
        .map(
            |((&ext_db, ext_dom), &log_qd)| -> Result<Vec<_>, VerificationError> {
                let base_db = ext_db.checked_sub(config.is_zk()).ok_or_else(|| {
                    VerificationError::InvalidProofShape(
                        "Extended degree bits smaller than ZK adjustment".to_string(),
                    )
                })?;
                let q_domain =
                    ext_dom.create_disjoint_domain(1 << (base_db + log_qd + config.is_zk()));
                Ok(q_domain.split_domains(1 << (log_qd + config.is_zk())))
            },
        )
        .collect::<Result<Vec<_>, VerificationError>>()?;

    let randomized_quotient_domains: Vec<Vec<_>> = quotient_domains
        .iter()
        .map(|domains| {
            domains
                .iter()
                .map(|domain| pcs.natural_domain_for_degree(pcs.size(domain) << config.is_zk()))
                .collect()
        })
        .collect();

    let mut quotient_round = Vec::with_capacity(
        layout
            .instances
            .iter()
            .map(|instance| instance.quotient_chunks)
            .sum(),
    );
    for matrix in layout.matrices(CommitmentRole::Quotient) {
        let MatrixRoute::Quotient { instance, chunk } = matrix.route else {
            unreachable!("quotient planner emits only quotient routes")
        };
        let domain = randomized_quotient_domains[instance]
            .get(chunk)
            .ok_or_else(|| {
                VerificationError::InvalidProofShape(
                    "Quotient chunk count mismatch across domains".to_string(),
                )
            })?;
        let values = instances[instance]
            .opened_values_no_lookups
            .quotient_chunks_targets
            .get(chunk)
            .ok_or_else(|| {
                VerificationError::InvalidProofShape(
                    "Quotient chunk count mismatch across domains".to_string(),
                )
            })?;
        quotient_round.push((*domain, vec![(zeta, values.clone())]));
    }
    coms_to_verify.push((
        commitments_targets.quotient_chunks_targets.clone(),
        quotient_round,
    ));

    if let Some(global) = &common.preprocessed {
        let mut pre_round = Vec::with_capacity(global.matrix_to_instance.len());

        for matrix in layout.matrices(CommitmentRole::Preprocessed) {
            let MatrixRoute::Preprocessed {
                instance: inst_idx,
                matrix: matrix_index,
            } = matrix.route
            else {
                unreachable!("preprocessed planner emits only preprocessed routes")
            };
            let pre_w = preprocessed_widths[inst_idx];
            if pre_w == 0 {
                return Err(VerificationError::InvalidProofShape(
                    "Instance has preprocessed columns with zero width".to_string(),
                ));
            }

            let inst = &instances[inst_idx];
            let local = inst
                .opened_values_no_lookups
                .preprocessed_local_targets
                .as_ref()
                .ok_or_else(|| {
                    VerificationError::InvalidProofShape(
                        "Missing preprocessed local columns".to_string(),
                    )
                })?;
            let mut points = vec![(zeta, local.clone())];
            // Validate that the preprocessed data's degree metadata matches this instance.
            let ext_db = degree_bits[inst_idx];

            let meta = global.instances.instances[inst_idx]
                .as_ref()
                .ok_or_else(|| {
                    VerificationError::InvalidProofShape(
                        "Missing preprocessed instance metadata".to_string(),
                    )
                })?;
            if meta.matrix_index != matrix_index || meta.degree_bits != ext_db {
                return Err(VerificationError::InvalidProofShape(
                    "Preprocessed instance metadata mismatch".to_string(),
                ));
            }

            // Compute base preprocessed domain (matching prover in generation.rs)
            let pre_domain = pcs.natural_domain_for_degree(1 << meta.degree_bits);

            // Use the base trace domain for zeta_next computation.
            let trace_dom = &trace_domains[inst_idx];
            let generator_const = circuit.define_const(trace_domain_generator(trace_dom)?);
            let zeta_next = circuit.mul(zeta, generator_const);

            if matrix.point_count == 2 {
                let next = inst
                    .opened_values_no_lookups
                    .preprocessed_next_targets
                    .as_ref()
                    .ok_or_else(|| {
                        VerificationError::InvalidProofShape(
                            "Missing preprocessed next columns".to_string(),
                        )
                    })?;
                points.push((zeta_next, next.clone()));
            }

            pre_round.push((pre_domain, points));
        }

        coms_to_verify.push((global.commitment.clone(), pre_round));
    }

    if is_lookup {
        let permutation_commit = commitments_targets
            .permutation_targets
            .clone()
            .expect("We checked that the commitment exists");

        let mut permutation_round = Vec::with_capacity(ext_trace_domains.len());

        for matrix in layout.matrices(CommitmentRole::Permutation) {
            let MatrixRoute::Permutation { instance: i } = matrix.route else {
                unreachable!("permutation planner emits only permutation routes")
            };
            let ext_dom = &ext_trace_domains[i];
            let inst = &instances[i];
            let permutation_local = &inst.permutation_local_targets;
            let permutation_next = &inst.permutation_next_targets;
            let trace_dom = &trace_domains[i];
            let generator_const = circuit.define_const(trace_domain_generator(trace_dom)?);
            let zeta_next = circuit.mul(zeta, generator_const);
            permutation_round.push((
                *ext_dom,
                vec![
                    (zeta, permutation_local.clone()),
                    (zeta_next, permutation_next.clone()),
                ],
            ));
        }

        coms_to_verify.push((permutation_commit, permutation_round));
    }

    // Observe opened values in the correct order (matching native), when this PCS's
    // native transcript expects them pre-observed (FRI). WHIR observes them itself,
    // interleaved with its own per-commitment challenges, inside verify_circuit.
    // For HidingFriPcs, the native verifier merges FRI-level random opened values into
    // each point's values before observing. We must do the same here to keep the
    // Fiat-Shamir transcript in sync with the prover/verifier.
    if SC::Pcs::PRE_OBSERVES_OPENED_VALUES {
        let fri_random_rounds = SC::Pcs::get_fri_random_opened_values(&proof_targets.opening_proof);
        observe_opened_values_circuit::<SC, CP, WIDTH, RATE>(
            circuit,
            &mut challenger,
            instances,
            fri_random_rounds,
            &layout,
        );
    }

    let pcs_challenges = SC::Pcs::get_challenges_circuit::<WIDTH, RATE, CP>(
        circuit,
        &mut challenger,
        &proof_targets.opening_proof,
        flattened,
        pcs_params,
    )?;

    let mmcs_op_ids = pcs.verify_circuit::<WIDTH, RATE, CP>(
        circuit,
        &pcs_challenges,
        &mut challenger,
        &coms_to_verify,
        opening_proof,
        pcs_params,
    )?;

    // Verify AIR constraints per instance.
    for i in 0..n_instances {
        let air = &airs[i];
        let inst = &instances[i];
        let trace_domain = &trace_domains[i];
        let public_values = &public_values[i];
        let domains = &quotient_domains[i];

        let quotient = recompose_quotient_from_chunks_circuit::<SC, _, _, _, _>(
            circuit,
            domains,
            &inst.opened_values_no_lookups.quotient_chunks_targets,
            zeta,
            pcs,
        );

        // Recompose permutation openings from base-flattened columns into extension field columns.
        // The permutation commitment is a base-flattened matrix with `width = aux_width * DIMENSION`.
        // For constraint evaluation, we need an extension field matrix with width `aux_width`.
        //
        // Single-terminal layout: column 0 is the shared accumulator and column `c + 1` is the
        // fraction column for lookup `c`, so `aux_width = num_lookups + 1` (0 with no lookups).
        let aux_width = if all_lookups[i].is_empty() {
            0
        } else {
            all_lookups[i].len() + 1
        };

        let recompose = |circuit: &mut CircuitBuilder<SC::Challenge>,
                         flat: &[Target]|
         -> Result<Vec<Target>, VerificationError> {
            let ext_degree = SC::Challenge::DIMENSION;
            // Hard proof-shape check: a malformed proof can supply extra/missing
            // flattened permutation coefficients. `chunks_exact` would silently
            // drop a remainder in release builds, so reject any length that is
            // not exactly `aux_width * DIMENSION` (including the `aux_width == 0`
            // case, which requires an empty opening).
            let expected = aux_width * ext_degree;
            if flat.len() != expected {
                return Err(VerificationError::InvalidProofShape(format!(
                    "flattened permutation opening length ({}) must equal aux_width ({}) * \
                     DIMENSION ({}) = {}",
                    flat.len(),
                    aux_width,
                    ext_degree,
                    expected
                )));
            }
            if aux_width == 0 {
                return Ok(vec![]);
            }
            // Chunk the flattened coefficients into groups of size `dim`.
            // Each chunk represents the coefficients of one extension field element.
            Ok(flat
                .chunks_exact(ext_degree)
                .map(|coeffs| {
                    let mut sum = circuit.define_const(SC::Challenge::ZERO);
                    // Dot product: sum(coeff_j * basis_j)
                    coeffs.iter().enumerate().for_each(|(j, &coeff)| {
                        let e_i = circuit.define_const(
                            SC::Challenge::ith_basis_element(j)
                                .expect("Basis element should exist"),
                        );
                        sum = circuit.mul_add(coeff, e_i, sum);
                    });
                    sum
                })
                .collect())
        };

        let local_permutation_values = recompose(circuit, &inst.permutation_local_targets)?;
        let next_permutation_values = recompose(circuit, &inst.permutation_next_targets)?;

        let local_prep_values = match inst
            .opened_values_no_lookups
            .preprocessed_local_targets
            .as_ref()
        {
            Some(v) => v.as_slice(),
            None => &[],
        };
        let next_prep_values = match inst
            .opened_values_no_lookups
            .preprocessed_next_targets
            .as_ref()
        {
            Some(v) => v.as_slice(),
            None => &[],
        };

        // Single-terminal layout: the AIR's permutation value is its lookup terminal (one when the
        // AIR declares lookups, none otherwise).
        let permutation_values: Vec<Target> = lookup_terminals[i].into_iter().collect();
        let sels = pcs.selectors_at_point_circuit(circuit, trace_domain, &zeta);
        // Periodic columns are verifier-recomputed AIR constants, evaluated at the
        // opening point. They are not committed, so this touches neither the
        // transcript nor the proof shape (matching the native batch verifier).
        let periodic_columns = air.periodic_columns();
        let periodic_values = pcs.evaluate_periodic_columns_at_point_circuit(
            circuit,
            trace_domain,
            &periodic_columns,
            zeta,
        )?;
        let columns_targets = ColumnsTargets {
            challenges: &challenges_per_instance[i],
            public_values,
            permutation_local_values: &local_permutation_values,
            permutation_next_values: &next_permutation_values,
            permutation_values: &permutation_values,
            local_prep_values,
            next_prep_values,
            periodic_values: &periodic_values,
            local_values: &inst.opened_values_no_lookups.trace_local_targets,
            next_values: &inst.opened_values_no_lookups.trace_next_targets,
        };

        let lookup_metadata = LookupMetadata {
            contexts: &all_lookups[i],
        };
        let folded_constraints = air.eval_folded_circuit(
            circuit,
            &sels,
            &alpha,
            &lookup_metadata,
            columns_targets,
            lookup_gadget,
        );

        let folded_mul = circuit.mul(folded_constraints, sels.inv_vanishing);
        circuit.connect(folded_mul, quotient);
    }

    // Single-terminal LogUp cross-AIR check: the sum of every present per-AIR terminal is zero.
    let present_terminals: Vec<Target> = lookup_terminals.iter().flatten().copied().collect();
    lookup_gadget.verify_terminal_sum_circuit(circuit, &present_terminals);

    Ok(mmcs_op_ids)
}

pub(crate) fn get_perm_challenges<
    SC: StarkGenericConfig,
    CP: ChallengerPermConfig,
    const WIDTH: usize,
    const RATE: usize,
    LG: LookupProtocol,
>(
    circuit: &mut CircuitBuilder<SC::Challenge>,
    challenger: &mut CircuitChallenger<WIDTH, RATE, CP>,
    all_lookups: &[Vec<Lookup<Val<SC>>>],
    lookup_gadget: &LG,
) -> Vec<Vec<Target>>
where
    Val<SC>: PrimeField64,
    SC::Challenge: ExtensionField<Val<SC>>,
{
    assert_eq!(
        lookup_gadget.num_challenges(),
        2,
        "single-pair bus-prefix challenge layout requires exactly two challenges per lookup"
    );

    // Match native: no lookups anywhere ⇒ an empty challenge layout per instance, and no samples.
    if !all_lookups.iter().any(|contexts| !contexts.is_empty()) {
        return all_lookups.iter().map(|_| Vec::new()).collect();
    }

    // Draw the single `(alpha, beta)` pair for the whole batch (extension-field elements).
    let alpha = challenger.sample_ext(circuit);
    let beta = challenger.sample_ext(circuit);

    // Assign each bus a stable id in iteration order: global buses dedup by name, locals fresh
    // per occurrence. Track the widest message payload to place the bus offset above it.
    let mut global_index: HashMap<&str, usize> = HashMap::new();
    let mut next_bus = 0usize;
    let mut max_message_width = 1usize;
    let mut bus_ids: Vec<Vec<usize>> = Vec::with_capacity(all_lookups.len());
    for contexts in all_lookups {
        let mut instance_buses = Vec::with_capacity(contexts.len());
        for context in contexts {
            for tuple in &context.elements {
                max_message_width = max_message_width.max(tuple.len());
            }
            let bus = match &context.kind {
                Kind::Global(name) => *global_index.entry(name.as_str()).or_insert_with(|| {
                    let id = next_bus;
                    next_bus += 1;
                    id
                }),
                Kind::Local => {
                    let id = next_bus;
                    next_bus += 1;
                    id
                }
            };
            instance_buses.push(bus);
        }
        bus_ids.push(instance_buses);
    }

    // gamma = beta^W (W = max message width) sits one power above every payload term, so the bus
    // offset never collides with a payload coefficient.
    let mut gamma = beta;
    for _ in 1..max_message_width {
        gamma = circuit.mul(gamma, beta);
    }

    // bus_prefix[i] = alpha + (i + 1) * gamma, accumulated to skip a multiply per bus.
    let mut prefix = alpha;
    let bus_prefix: Vec<Target> = (0..next_bus)
        .map(|_| {
            prefix = circuit.add(prefix, gamma);
            prefix
        })
        .collect();

    // Lay the challenges out per instance: `[bus_prefix[bus], beta]` for each lookup.
    bus_ids
        .iter()
        .map(|instance_buses| {
            instance_buses
                .iter()
                .flat_map(|&bus| [bus_prefix[bus], beta])
                .collect()
        })
        .collect()
}

/// Observe opened values in the circuit in the correct order to match native.
///
/// For `HidingFriPcs`, the native verifier merges FRI-level random opened values into
/// each point's values before observing them. `fri_random_rounds` carries those extra
/// values (layout: `rounds[round][mat][point]`) and must be interleaved here to keep
/// the Fiat-Shamir transcript in sync. For `TwoAdicFriPcs`, pass an empty slice.
///
/// Observation order (matching native batch-STARK verifier):
/// 1. Random round (if ZK): for each instance, observe random opened values (+ FRI random)
/// 2. Trace round: for each instance, observe trace_local (+ FRI random) then trace_next (+ FRI random)
/// 3. Quotient round: for each chunk, observe quotient values (+ FRI random)
/// 4. Preprocessed round (if present): for each matrix, observe prep_local (+ FRI random) then prep_next (+ FRI random)
/// 5. Permutation round (if present): for each instance, observe perm_local (+ FRI random) then perm_next (+ FRI random)
#[allow(clippy::too_many_arguments)]
fn observe_opened_values_circuit<
    SC,
    CP: ChallengerPermConfig,
    const WIDTH: usize,
    const RATE: usize,
>(
    circuit: &mut CircuitBuilder<SC::Challenge>,
    challenger: &mut CircuitChallenger<WIDTH, RATE, CP>,
    instances: &[OpenedValuesTargetsWithLookups<SC>],
    fri_random_rounds: &[Vec<Vec<Vec<Target>>>],
    layout: &NativeStarkLayout<'_>,
) where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField64,
    SC::Challenge: ExtensionField<Val<SC>>,
{
    // Helper: observe a point's original values followed by any FRI random values.
    let observe_point = |circuit: &mut CircuitBuilder<SC::Challenge>,
                         challenger: &mut CircuitChallenger<WIDTH, RATE, CP>,
                         original: &[Target],
                         fri_random: Option<&Vec<Target>>| {
        challenger.observe_ext_slice(circuit, original);
        if let Some(rand_vals) = fri_random {
            challenger.observe_ext_slice(circuit, rand_vals);
        }
    };

    // Track which round index within `fri_random_rounds` we are at.
    let mut round_idx: usize = 0;

    // 1. Random round (if ZK): for each instance (= mat), one point at zeta.
    if layout.has_random {
        let rand_round = fri_random_rounds.get(round_idx);
        for (mat_idx, matrix) in layout.matrices(CommitmentRole::Random).enumerate() {
            let MatrixRoute::Random { instance } = matrix.route else {
                unreachable!("random planner emits only random routes")
            };
            if let Some(random_vals) = &instances[instance].opened_values_no_lookups.random_targets
            {
                let fri_rand = rand_round
                    .and_then(|r| r.get(mat_idx))
                    .and_then(|m| m.first());
                observe_point(circuit, challenger, random_vals, fri_rand);
            }
        }
        round_idx += 1;
    }

    // 2. Trace round: for each instance (= mat), two points (zeta, zeta_next).
    {
        let rand_round = fri_random_rounds.get(round_idx);
        for (mat_idx, matrix) in layout.matrices(CommitmentRole::Trace).enumerate() {
            let MatrixRoute::Trace { instance } = matrix.route else {
                unreachable!("trace planner emits only trace routes")
            };
            let inst = &instances[instance];
            let fri_rand_local = rand_round
                .and_then(|r| r.get(mat_idx))
                .and_then(|m| m.first());
            let fri_rand_next = rand_round
                .and_then(|r| r.get(mat_idx))
                .and_then(|m| m.get(1));
            observe_point(
                circuit,
                challenger,
                &inst.opened_values_no_lookups.trace_local_targets,
                fri_rand_local,
            );
            if matrix.point_count == 2 {
                observe_point(
                    circuit,
                    challenger,
                    &inst.opened_values_no_lookups.trace_next_targets,
                    fri_rand_next,
                );
            }
        }
        round_idx += 1;
    }

    // 3. Quotient round: mats are flattened chunks across all instances, one point each.
    {
        let rand_round = fri_random_rounds.get(round_idx);
        for (mat_idx, matrix) in layout.matrices(CommitmentRole::Quotient).enumerate() {
            let MatrixRoute::Quotient { instance, chunk } = matrix.route else {
                unreachable!("quotient planner emits only quotient routes")
            };
            let chunk_values = &instances[instance]
                .opened_values_no_lookups
                .quotient_chunks_targets[chunk];
            let fri_rand = rand_round
                .and_then(|r| r.get(mat_idx))
                .and_then(|m| m.first());
            observe_point(circuit, challenger, chunk_values, fri_rand);
        }
        round_idx += 1;
    }

    // 4. Preprocessed round (if present): mats are indexed by matrix_to_instance order.
    if layout.has_preprocessed {
        let rand_round = fri_random_rounds.get(round_idx);
        for (mat_idx, matrix) in layout.matrices(CommitmentRole::Preprocessed).enumerate() {
            let MatrixRoute::Preprocessed {
                instance: inst_idx, ..
            } = matrix.route
            else {
                unreachable!("preprocessed planner emits only preprocessed routes")
            };
            let inst = &instances[inst_idx];
            if let Some(prep_local) = &inst.opened_values_no_lookups.preprocessed_local_targets {
                let fri_rand_local = rand_round
                    .and_then(|r| r.get(mat_idx))
                    .and_then(|m| m.first());
                let fri_rand_next = rand_round
                    .and_then(|r| r.get(mat_idx))
                    .and_then(|m| m.get(1));
                observe_point(circuit, challenger, prep_local, fri_rand_local);
                if matrix.point_count == 2 {
                    let prep_next = &inst.opened_values_no_lookups.preprocessed_next_targets;
                    if let Some(prep_next) = prep_next {
                        observe_point(circuit, challenger, prep_next, fri_rand_next);
                    }
                }
            }
        }
        round_idx += 1;
    }

    // 5. Permutation round (if present): for each instance with non-empty permutation.
    if layout.has_permutation {
        let rand_round = fri_random_rounds.get(round_idx);
        for (mat_idx, matrix) in layout.matrices(CommitmentRole::Permutation).enumerate() {
            let MatrixRoute::Permutation { instance } = matrix.route else {
                unreachable!("permutation planner emits only permutation routes")
            };
            let inst = &instances[instance];
            let fri_rand_local = rand_round
                .and_then(|r| r.get(mat_idx))
                .and_then(|m| m.first());
            let fri_rand_next = rand_round
                .and_then(|r| r.get(mat_idx))
                .and_then(|m| m.get(1));
            observe_point(
                circuit,
                challenger,
                &inst.permutation_local_targets,
                fri_rand_local,
            );
            observe_point(
                circuit,
                challenger,
                &inst.permutation_next_targets,
                fri_rand_next,
            );
        }
    }
}

#[cfg(test)]
mod create_alu_air_tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use p3_air::symbolic::AirLayout;
    use p3_air::{Air, AirBuilder, BaseAir, WindowAccess};
    use p3_batch_stark::common::{GlobalPreprocessed, PreprocessedInstanceMeta};
    use p3_batch_stark::symbolic::get_log_num_quotient_chunks;
    use p3_batch_stark::verifier::commitments_with_opening_points;
    use p3_batch_stark::{
        BatchCommitments, BatchOpenedValues, BatchProof, BatchTranscript, CommonData,
    };
    use p3_challenger::FieldChallenger;
    use p3_circuit::CircuitBuilder;
    use p3_circuit::ops::{Poseidon2Config, generate_poseidon2_trace, generate_recompose_trace};
    use p3_circuit_prover::air::{AluAir, PublicAir};
    use p3_circuit_prover::batch_stark_prover::lookups_for_circuit_table_air;
    use p3_circuit_prover::common::CircuitTableAir;
    use p3_circuit_prover::field_params::ExtractBinomialW;
    use p3_commit::Pcs as PcsTrait;
    use p3_field::extension::{BinomialExtensionField, QuinticTrinomialExtensionField};
    use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing};
    use p3_fri::FriProof;
    use p3_goldilocks::Goldilocks;
    use p3_koala_bear::KoalaBear;
    use p3_lookup::Lookups;
    use p3_lookup::logup::LogUpGadget;
    use p3_matrix::dense::RowMajorMatrix;
    use p3_poseidon2_circuit_air::KoalaBearD4Width16;
    use p3_test_utils::goldilocks_params::MyConfig as GoldilocksRecursionConfig;
    use p3_test_utils::koala_bear_quintic_params::MyConfig as KoalaBearQuinticRecursionConfig;
    use p3_uni_stark::{OpenedValues, StarkGenericConfig, Val};

    use super::{CircuitTablesAir, create_alu_air, observe_opened_values_circuit};
    use crate::challenger::CircuitChallenger;
    use crate::input_contract::stark_layout::{CommitmentRole, InstanceLayout, NativeStarkLayout};
    use crate::prepared::test_common::KoalaBearD4RecursionConfig;
    use crate::traits::{RecursiveAir, RecursiveChallenger};
    use crate::types::{OpenedValuesTargets, OpenedValuesTargetsWithLookups};

    #[derive(Clone, Copy)]
    struct PrefixAir {
        prep_width: usize,
        prep_next: bool,
    }

    impl<Val: Field> BaseAir<Val> for PrefixAir {
        fn width(&self) -> usize {
            1
        }

        fn preprocessed_width(&self) -> usize {
            self.prep_width
        }

        fn main_next_row_columns(&self) -> Vec<usize> {
            Vec::new()
        }

        fn preprocessed_next_row_columns(&self) -> Vec<usize> {
            if self.prep_next {
                (0..self.prep_width).collect()
            } else {
                Vec::new()
            }
        }
    }

    impl<AB: AirBuilder> Air<AB> for PrefixAir
    where
        AB::F: Field,
    {
        fn eval(&self, builder: &mut AB) {
            // A cubic constraint keeps quotient metadata non-zero in this
            // tiny prefix, exercising committed chunk-domain geometry.
            let value = builder.main().current_slice()[0];
            builder.assert_zero(value * value * value);
        }
    }

    /// A proof-controlled `alu_quintic_trinomial = false` against a quintic-trinomial `EF` has
    /// no binomial `W` to fall back to; this must be a rejected proof shape, not a panic.
    #[test]
    fn quintic_without_trinomial_flag_is_rejected() {
        let result = create_alu_air::<KoalaBear, QuinticTrinomialExtensionField<KoalaBear>, 5>(
            4, 1, 4, false,
        );
        assert!(result.is_err());
    }

    /// The matching, honest `alu_quintic_trinomial = true` still succeeds.
    #[test]
    fn quintic_with_trinomial_flag_succeeds() {
        let result = create_alu_air::<KoalaBear, QuinticTrinomialExtensionField<KoalaBear>, 5>(
            4, 1, 4, true,
        );
        assert!(result.is_ok());
    }

    /// The reconstructed verifier wrapper must preserve the producer wrapper's metadata-based
    /// default: a preprocessed trace with no explicit override opens every column at the next row.
    #[test]
    fn reconstructed_public_air_preserves_preprocessed_opening_policy() {
        type Config = KoalaBearD4RecursionConfig;
        type F = Val<Config>;
        let inner = PublicAir::<F, 4>::new(2, 1);
        let producer = CircuitTableAir::<Config, 4>::Public(inner.clone());
        let reconstructed = CircuitTablesAir::<Config, 4>::Public(inner);

        assert_eq!(
            BaseAir::<F>::preprocessed_width(&producer),
            BaseAir::<F>::preprocessed_width(&reconstructed)
        );
        assert_eq!(
            BaseAir::<F>::preprocessed_next_row_columns(&producer),
            BaseAir::<F>::preprocessed_next_row_columns(&reconstructed)
        );
        assert!(<CircuitTablesAir<Config, 4> as RecursiveAir<
            F,
            <Config as StarkGenericConfig>::Challenge,
            LogUpGadget,
        >>::opens_preprocessed_next(&reconstructed));
    }

    fn assert_alu_metadata_parity<F, EF, const D: usize>(old: AluAir<F, D>, actual: AluAir<F, D>)
    where
        F: Field + p3_field::PrimeCharacteristicRing + Copy,
        EF: p3_field::ExtensionField<F> + ExtractBinomialW<F>,
    {
        assert_eq!(BaseAir::<F>::width(&old), BaseAir::<F>::width(&actual));
        assert_eq!(
            BaseAir::<F>::preprocessed_width(&old),
            BaseAir::<F>::preprocessed_width(&actual)
        );
        assert_eq!(
            BaseAir::<F>::main_next_row_columns(&old),
            BaseAir::<F>::main_next_row_columns(&actual)
        );
        assert_eq!(
            BaseAir::<F>::preprocessed_next_row_columns(&old),
            BaseAir::<F>::preprocessed_next_row_columns(&actual)
        );
    }

    fn assert_alu_packed_metadata_parity<SC, const D: usize>(
        old: AluAir<Val<SC>, D>,
        actual: AluAir<Val<SC>, D>,
    ) where
        SC: StarkGenericConfig,
        Val<SC>: p3_field::PrimeField + p3_field::PrimeField64,
        SC::Challenge: p3_field::ExtensionField<Val<SC>>,
        p3_uni_stark::SymbolicExpressionExt<Val<SC>, SC::Challenge>: p3_field::Algebra<p3_uni_stark::SymbolicExpression<Val<SC>>>
            + p3_field::Algebra<SC::Challenge>,
    {
        let old_outer = CircuitTableAir::<SC, D>::Alu(old);
        let actual_outer = CircuitTableAir::<SC, D>::Alu(actual);
        let reconstructed = CircuitTablesAir::<SC, D>::Alu(match &actual_outer {
            CircuitTableAir::Alu(air) => air.clone(),
            _ => unreachable!(),
        });
        assert_eq!(
            BaseAir::<Val<SC>>::num_public_values(&old_outer),
            BaseAir::<Val<SC>>::num_public_values(&reconstructed)
        );
        assert_eq!(
            BaseAir::<Val<SC>>::num_periodic_columns(&old_outer),
            BaseAir::<Val<SC>>::num_periodic_columns(&reconstructed)
        );
        assert_eq!(
            BaseAir::<Val<SC>>::periodic_columns(&old_outer),
            BaseAir::<Val<SC>>::periodic_columns(&reconstructed)
        );
        assert_eq!(
            BaseAir::<Val<SC>>::width(&old_outer),
            BaseAir::<Val<SC>>::width(&reconstructed)
        );
        assert_eq!(
            BaseAir::<Val<SC>>::preprocessed_width(&old_outer),
            BaseAir::<Val<SC>>::preprocessed_width(&reconstructed)
        );
        assert_eq!(
            BaseAir::<Val<SC>>::main_next_row_columns(&old_outer),
            BaseAir::<Val<SC>>::main_next_row_columns(&reconstructed)
        );
        assert_eq!(
            BaseAir::<Val<SC>>::preprocessed_next_row_columns(&old_outer),
            BaseAir::<Val<SC>>::preprocessed_next_row_columns(&reconstructed)
        );
        let old_packed = lookups_for_circuit_table_air(&old_outer, 4, 0);
        let actual_packed = lookups_for_circuit_table_air(&actual_outer, 4, 0);
        assert_eq!(
            postcard::to_allocvec(&old_packed).unwrap(),
            postcard::to_allocvec(&actual_packed).unwrap()
        );
        let gadget = LogUpGadget::new();
        let old_q = get_log_num_quotient_chunks(
            &old_outer,
            AirLayout::from_air(&old_outer),
            4,
            &old_packed,
            0,
            &gadget,
        );
        let actual_q = get_log_num_quotient_chunks(
            &actual_outer,
            AirLayout::from_air(&actual_outer),
            4,
            &actual_packed,
            0,
            &gadget,
        );
        assert_eq!(old_q, actual_q);
        let reconstructed_q = <CircuitTablesAir<SC, D> as RecursiveAir<
            Val<SC>,
            SC::Challenge,
            LogUpGadget,
        >>::get_log_num_quotient_chunks(
            &reconstructed,
            BaseAir::<Val<SC>>::preprocessed_width(&reconstructed),
            4,
            &actual_packed,
            0,
            &gadget,
        );
        assert_eq!(actual_q, reconstructed_q);
        assert_eq!(
            (old_packed.len() + 1) * SC::Challenge::DIMENSION,
            (actual_packed.len() + 1) * SC::Challenge::DIMENSION
        );
    }

    #[test]
    fn lightweight_alu_metadata_matches_zero_preprocessed_d1_k2_k4() {
        for k in [2, 4] {
            let prep = vec![KoalaBear::ZERO; 8 * AluAir::<KoalaBear, 1>::preprocessed_lane_width()];
            let old = AluAir::<KoalaBear, 1>::new_with_preprocessed(8, 2, prep, k);
            let actual = create_alu_air::<KoalaBear, KoalaBear, 1>(8, 2, k, false).unwrap();
            assert_alu_metadata_parity::<KoalaBear, KoalaBear, 1>(old.clone(), actual.clone());
            assert_alu_packed_metadata_parity::<KoalaBearD4RecursionConfig, 1>(old, actual);
        }
    }

    #[test]
    fn lightweight_alu_metadata_matches_zero_preprocessed_d2_k2_k4() {
        type F = Goldilocks;
        type EF = BinomialExtensionField<F, 2>;
        let w = EF::extract_w().expect("test extension has binomial W");
        for k in [2, 4] {
            let prep = vec![F::ZERO; 8 * AluAir::<F, 2>::preprocessed_lane_width()];
            let old = AluAir::<F, 2>::new_binomial_with_preprocessed(8, 2, w, prep, k);
            let actual = create_alu_air::<F, EF, 2>(8, 2, k, false).unwrap();
            assert_alu_metadata_parity::<F, EF, 2>(old.clone(), actual.clone());
            assert_alu_packed_metadata_parity::<GoldilocksRecursionConfig, 2>(old, actual);
        }
    }

    #[test]
    fn lightweight_alu_metadata_matches_zero_preprocessed_d4_k2_k4() {
        type F = KoalaBear;
        type EF = BinomialExtensionField<F, 4>;
        let w = EF::extract_w().expect("test extension has binomial W");
        for k in [2, 4] {
            let prep = vec![F::ZERO; 8 * AluAir::<F, 4>::preprocessed_lane_width()];
            let old = AluAir::<F, 4>::new_binomial_with_preprocessed(8, 2, w, prep, k);
            let actual = create_alu_air::<F, EF, 4>(8, 2, k, false).unwrap();
            assert_alu_metadata_parity::<F, EF, 4>(old.clone(), actual.clone());
            assert_alu_packed_metadata_parity::<KoalaBearD4RecursionConfig, 4>(old, actual);
        }
    }

    #[test]
    fn lightweight_alu_metadata_matches_zero_preprocessed_d5_k2_k4() {
        type F = KoalaBear;
        type EF = QuinticTrinomialExtensionField<F>;
        for k in [2, 4] {
            let prep = vec![F::ZERO; 8 * AluAir::<F, 5>::preprocessed_lane_width()];
            let old = AluAir::<F, 5>::new_quintic_trinomial_with_preprocessed(8, 2, prep, k);
            let actual = create_alu_air::<F, EF, 5>(8, 2, k, true).unwrap();
            assert_alu_metadata_parity::<F, EF, 5>(old.clone(), actual.clone());
            assert_alu_packed_metadata_parity::<KoalaBearQuinticRecursionConfig, 5>(old, actual);
        }
    }

    fn run_coherent_prefix_case(map: &[usize], prep_widths: &[usize]) {
        type Config = p3_test_utils::koala_bear_params::MyConfig;
        type F = Val<Config>;
        type EF = <Config as StarkGenericConfig>::Challenge;
        type PcsType = <Config as StarkGenericConfig>::Pcs;
        type Challenger = <Config as StarkGenericConfig>::Challenger;
        const WIDTH: usize = 16;
        const RATE: usize = 8;
        const ROWS: usize = 8;
        const DEGREE_BITS: usize = 3;

        assert!(map.iter().all(|&index| index < prep_widths.len()));
        assert!(map.windows(2).all(|pair| pair[0] != pair[1]));
        let config = p3_test_utils::koala_bear_params::make_test_config();
        let airs: Vec<_> = prep_widths
            .iter()
            .copied()
            .map(|prep_width| PrefixAir {
                prep_width,
                prep_next: prep_width != 0,
            })
            .collect();
        let domain =
            <PcsType as PcsTrait<EF, Challenger>>::natural_domain_for_degree(config.pcs(), ROWS);
        let matrices = map.iter().map(|&instance| {
            let width = prep_widths[instance];
            let values = (0..ROWS * width)
                .map(|column| F::from_usize(11 + 10 * instance + column % width))
                .collect();
            (domain, RowMajorMatrix::new(values, width))
        });
        let (pre_commitment, _) =
            <PcsType as PcsTrait<EF, Challenger>>::commit_preprocessing(config.pcs(), matrices);

        let preprocessed_instances = prep_widths
            .iter()
            .enumerate()
            .map(|(instance, &width)| {
                (width != 0).then(|| PreprocessedInstanceMeta {
                    matrix_index: map.iter().position(|&index| index == instance).unwrap(),
                    width,
                    degree_bits: DEGREE_BITS,
                })
            })
            .collect();
        let common = CommonData {
            preprocessed: Some(GlobalPreprocessed {
                commitment: pre_commitment.clone(),
                instances: preprocessed_instances,
                matrix_to_instance: map.to_vec(),
            }),
            lookups: prep_widths
                .iter()
                .map(|_| Lookups::<F>::default())
                .collect(),
        };
        let lookup_gadget = LogUpGadget::new();
        let layouts: Vec<_> = airs
            .iter()
            .map(|air| AirLayout {
                preprocessed_width: air.prep_width,
                main_width: 1,
                ..Default::default()
            })
            .collect();
        let log_q: Vec<_> = airs
            .iter()
            .zip(layouts.iter())
            .map(|(air, &layout)| {
                get_log_num_quotient_chunks::<F, EF, _, _>(
                    air,
                    layout,
                    ROWS,
                    &Lookups::<F>::default(),
                    0,
                    &lookup_gadget,
                )
            })
            .collect();
        let opened_instances = airs
            .iter()
            .enumerate()
            .map(|(instance, air)| {
                let preprocessed_local = (air.prep_width != 0).then(|| {
                    (0..air.prep_width)
                        .map(|column| EF::from_usize(11 + 10 * instance + column))
                        .collect()
                });
                let preprocessed_next = (air.prep_width != 0 && air.prep_next).then(|| {
                    (0..air.prep_width)
                        .map(|column| EF::from_usize(11 + 10 * instance + column))
                        .collect()
                });
                p3_batch_stark::proof::OpenedValuesWithLookups {
                    base_opened_values: OpenedValues {
                        trace_local: vec![EF::from_usize(3 + instance)],
                        trace_next: None,
                        preprocessed_local,
                        preprocessed_next,
                        quotient_chunks: vec![
                            vec![EF::ZERO; <EF as BasedVectorSpace<F>>::DIMENSION];
                            1 << log_q[instance]
                        ],
                        random: None,
                    },
                    permutation_local: Vec::new(),
                    permutation_next: Vec::new(),
                }
            })
            .collect();
        let public_values: Vec<Vec<F>> = prep_widths.iter().map(|_| Vec::new()).collect();
        let commitments = BatchCommitments {
            main: pre_commitment.clone(),
            permutation: None,
            quotient_chunks: pre_commitment.clone(),
            random: None,
        };
        let probe: <PcsType as PcsTrait<EF, Challenger>>::Proof = FriProof {
            commit_phase_commits: vec![pre_commitment.clone()],
            commit_pow_witnesses: Vec::new(),
            input_openings: Vec::new(),
            commit_phase_openings: Vec::new(),
            final_poly: Vec::new(),
            query_pow_witness: F::ZERO,
        };
        let proof = BatchProof {
            commitments,
            opened_values: BatchOpenedValues {
                instances: opened_instances,
            },
            opening_proof: probe.clone(),
            lookup_terminals: vec![None; airs.len()],
            degree_bits: vec![DEGREE_BITS; airs.len()],
        };
        let preprocessed_widths = prep_widths.to_vec();

        // This prefix is independently built with the upstream transcript API.
        let mut native_prefix = BatchTranscript::<Config>::new(config.initialise_challenger());
        native_prefix.observe_instance_count(airs.len());
        for &log in &log_q {
            native_prefix.observe_instance_binding(DEGREE_BITS, DEGREE_BITS, 1, 1 << log);
        }
        native_prefix.observe_main(&proof.commitments.main, &public_values);
        native_prefix.observe_preprocessed(&preprocessed_widths, common.preprocessed.as_ref());
        native_prefix.sample_perm_challenges(&common.lookups, &lookup_gadget);
        let native_alpha =
            native_prefix.observe_perm_and_sample_alpha(None, &proof.lookup_terminals);
        native_prefix.observe_quotient_commitment(&proof.commitments.quotient_chunks);
        let native_zeta = native_prefix.sample_zeta();

        let (replay, replay_challenges) = crate::generation::replay_batch_stark_transcript(
            &airs,
            &config,
            &proof,
            &public_values,
            &common,
            &lookup_gadget,
        )
        .unwrap();
        assert_eq!(replay_challenges, vec![native_alpha, native_zeta]);
        let native_argument = commitments_with_opening_points(
            &config,
            &airs,
            native_zeta,
            &proof.commitments,
            &proof.opened_values,
            &common,
            &proof.degree_bits,
            &preprocessed_widths,
            &log_q,
        )
        .unwrap()
        .0;

        // Compare the actual upstream argument geometry with the shared lazy
        // layout.  This checks domain height, matrix width, and point count
        // without deriving any geometry from proof-vector lengths.
        let native_descriptor = native_argument
            .iter()
            .flat_map(|(_, matrices)| {
                matrices.iter().map(|(domain, points)| {
                    (
                        domain.log_size(),
                        points.first().map_or(0, |(_, values)| values.len()),
                        points.len(),
                    )
                })
            })
            .collect::<Vec<(usize, usize, usize)>>();
        let replay_descriptor = replay
            .commitments_with_opening_points
            .iter()
            .flat_map(|(_, matrices)| {
                matrices.iter().map(|(domain, points)| {
                    (
                        domain.log_size(),
                        points.first().map_or(0, |(_, values)| values.len()),
                        points.len(),
                    )
                })
            })
            .collect::<Vec<(usize, usize, usize)>>();
        assert_eq!(native_descriptor, replay_descriptor);
        let layout = NativeStarkLayout::new(
            airs.iter()
                .zip(log_q.iter())
                .map(|(air, &quotient_log)| InstanceLayout {
                    ext_log: DEGREE_BITS,
                    base_log: DEGREE_BITS,
                    challenge_width: <EF as BasedVectorSpace<F>>::DIMENSION,
                    trace_width: BaseAir::<F>::width(air),
                    trace_next: false,
                    pre_width: air.prep_width,
                    pre_next: air.prep_next,
                    quotient_log,
                    quotient_chunks: 1 << quotient_log,
                    permutation_width: 0,
                })
                .collect(),
            map,
            false,
            true,
            false,
        )
        .unwrap();
        let layout_descriptor = [
            CommitmentRole::Trace,
            CommitmentRole::Quotient,
            CommitmentRole::Preprocessed,
        ]
        .into_iter()
        .flat_map(|role| {
            layout
                .matrices(role)
                .map(|matrix| (matrix.log_height, matrix.width, matrix.point_count))
        })
        .collect::<Vec<_>>();
        assert_eq!(native_descriptor, layout_descriptor);

        // Pcs::verify is the independent evaluation consumer.  Its malformed
        // FRI proof reaches this typed stop only after opening observation and
        // one alpha sample (the test config has nonzero query count).
        let mut native_pcs = native_prefix.challenger.clone();
        let result = <PcsType as PcsTrait<EF, Challenger>>::verify(
            config.pcs(),
            native_argument,
            &probe,
            &mut native_pcs,
        );
        assert!(matches!(
            result,
            Err(
                p3_fri::verifier::FriError::CommitPhaseOpeningsCountMismatch {
                    expected: 1,
                    got: 0
                }
            )
        ));

        let mut replay_pcs = replay.challenger.clone();
        crate::generation::observe_opened_values::<Config>(
            &mut replay_pcs,
            &replay.commitments_with_opening_points,
        );
        let _replay_alpha = replay_pcs.sample_algebra_element::<EF>();

        let mut circuit = CircuitBuilder::<EF>::new();
        circuit.enable_poseidon2_perm::<KoalaBearD4Width16, _>(
            generate_poseidon2_trace::<EF, KoalaBearD4Width16>,
            p3_test_utils::koala_bear_params::default_koalabear_poseidon2_16(),
        );
        circuit.enable_recompose::<F>(generate_recompose_trace::<F, EF>);
        let mut circuit_challenger =
            CircuitChallenger::<WIDTH, RATE, Poseidon2Config>::new_koalabear();
        let define = |circuit: &mut CircuitBuilder<EF>, value: EF| circuit.define_const(value);
        let instance_count_target = define(&mut circuit, EF::from_usize(airs.len()));
        RecursiveChallenger::<F, EF>::observe_ext(
            &mut circuit_challenger,
            &mut circuit,
            instance_count_target,
        );
        for (log, air) in log_q.iter().zip(airs.iter()) {
            for value in [DEGREE_BITS, DEGREE_BITS, 1, 1 << log] {
                let value_target = define(&mut circuit, EF::from_usize(value));
                RecursiveChallenger::<F, EF>::observe_ext(
                    &mut circuit_challenger,
                    &mut circuit,
                    value_target,
                );
            }
            assert_eq!(BaseAir::<F>::width(air), 1);
        }
        let commitment_targets = |circuit: &mut CircuitBuilder<EF>| {
            pre_commitment
                .roots()
                .iter()
                .flat_map(|digest| digest.iter().copied())
                .map(|value| define(circuit, EF::from(value)))
                .collect::<Vec<_>>()
        };
        let main_targets = commitment_targets(&mut circuit);
        RecursiveChallenger::<F, EF>::observe_slice(
            &mut circuit_challenger,
            &mut circuit,
            &main_targets,
        );
        for values in &public_values {
            let targets = values
                .iter()
                .map(|&value| define(&mut circuit, EF::from(value)))
                .collect::<Vec<_>>();
            RecursiveChallenger::<F, EF>::observe_slice(
                &mut circuit_challenger,
                &mut circuit,
                &targets,
            );
        }
        for &width in &preprocessed_widths {
            let width_target = define(&mut circuit, EF::from_usize(width));
            RecursiveChallenger::<F, EF>::observe_ext(
                &mut circuit_challenger,
                &mut circuit,
                width_target,
            );
        }
        let pre_targets = commitment_targets(&mut circuit);
        RecursiveChallenger::<F, EF>::observe_slice(
            &mut circuit_challenger,
            &mut circuit,
            &pre_targets,
        );
        let circuit_alpha =
            RecursiveChallenger::<F, EF>::sample_ext(&mut circuit_challenger, &mut circuit);
        let native_alpha_target = define(&mut circuit, native_alpha);
        circuit.connect(circuit_alpha, native_alpha_target);
        let quotient_targets = commitment_targets(&mut circuit);
        RecursiveChallenger::<F, EF>::observe_slice(
            &mut circuit_challenger,
            &mut circuit,
            &quotient_targets,
        );
        let circuit_zeta =
            RecursiveChallenger::<F, EF>::sample_ext(&mut circuit_challenger, &mut circuit);
        let native_zeta_target = define(&mut circuit, native_zeta);
        circuit.connect(circuit_zeta, native_zeta_target);

        let target_instances = proof
            .opened_values
            .instances
            .iter()
            .map(|instance| {
                let base = &instance.base_opened_values;
                let targetize = |values: &[EF], circuit: &mut CircuitBuilder<EF>| {
                    values
                        .iter()
                        .map(|&value| circuit.define_const(value))
                        .collect()
                };
                OpenedValuesTargetsWithLookups {
                    opened_values_no_lookups: OpenedValuesTargets {
                        trace_local_targets: targetize(&base.trace_local, &mut circuit),
                        trace_next_targets: Vec::new(),
                        preprocessed_local_targets: base
                            .preprocessed_local
                            .as_ref()
                            .map(|values| targetize(values, &mut circuit)),
                        preprocessed_next_targets: base
                            .preprocessed_next
                            .as_ref()
                            .map(|values| targetize(values, &mut circuit)),
                        quotient_chunks_targets: base
                            .quotient_chunks
                            .iter()
                            .map(|values| targetize(values, &mut circuit))
                            .collect(),
                        random_targets: None,
                        _phantom: core::marker::PhantomData,
                    },
                    permutation_local_targets: Vec::new(),
                    permutation_next_targets: Vec::new(),
                }
            })
            .collect::<Vec<_>>();
        observe_opened_values_circuit::<Config, Poseidon2Config, WIDTH, RATE>(
            &mut circuit,
            &mut circuit_challenger,
            &target_instances,
            &[],
            &layout,
        );
        let _circuit_alpha =
            RecursiveChallenger::<F, EF>::sample_ext(&mut circuit_challenger, &mut circuit);
        for _ in 0..2 {
            let native_sample = native_pcs.sample_algebra_element::<EF>();
            let replay_sample = replay_pcs.sample_algebra_element::<EF>();
            assert_eq!(native_sample, replay_sample);
            let circuit_sample =
                RecursiveChallenger::<F, EF>::sample_ext(&mut circuit_challenger, &mut circuit);
            let native_sample_target = define(&mut circuit, native_sample);
            circuit.connect(circuit_sample, native_sample_target);
        }
        circuit.build().unwrap().runner().run().unwrap();
    }

    #[test]
    fn coherent_preprocessed_consumers_match_for_reordered_and_sparse_maps() {
        run_coherent_prefix_case(&[1, 0], &[1, 2]);
        run_coherent_prefix_case(&[0, 2], &[1, 0, 2]);
    }
}
