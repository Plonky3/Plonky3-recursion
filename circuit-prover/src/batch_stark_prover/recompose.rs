//! Recompose table prover: builds `RecomposeAir` instances for the batch STARK prover.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use hashbrown::HashMap;
use p3_batch_stark::{StarkGenericConfig, Val};
use p3_circuit::op::{NonPrimitivePreprocessedMap, NpoTypeId};
use p3_circuit::ops::recompose::RecomposeTrace;
use p3_circuit::tables::Traces;
use p3_circuit::{CircuitError, PreprocessedColumns};
use p3_field::extension::BinomialExtensionField;
use p3_field::{Algebra, ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
use p3_uni_stark::{SymbolicExpression, SymbolicExpressionExt};

use super::dynamic_air::{
    BatchAir, BatchTableInstance, DynamicAirEntry, TableProver, transmute_traces,
};
use super::{NonPrimitiveTableEntry, TablePacking};
use crate::air::RecomposeAir;
use crate::common::NpoPreprocessor;
use crate::config::StarkField;
use crate::impl_table_prover_batch_instances_from_base;

impl<SC> BatchAir<SC> for RecomposeAir<Val<SC>, 4>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
}

impl<SC> BatchAir<SC> for RecomposeAir<Val<SC>, 2>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
}

/// Table prover for the recompose (BF→EF packing) NPO.
pub struct RecomposeProver {
    d: usize,
}

impl RecomposeProver {
    pub const fn new(d: usize) -> Self {
        Self { d }
    }

    fn batch_instance_base<SC>(
        &self,
        _config: &SC,
        packing: TablePacking,
        traces: &Traces<Val<SC>>,
    ) -> Option<BatchTableInstance<SC>>
    where
        SC: StarkGenericConfig + 'static + Send + Sync,
        Val<SC>: StarkField,
        SymbolicExpressionExt<Val<SC>, SC::Challenge>:
            Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    {
        let op_type = NpoTypeId::recompose();
        let trace = traces.non_primitive_traces.get(&op_type)?;
        if trace.rows() == 0 {
            return None;
        }

        let t = trace.as_any().downcast_ref::<RecomposeTrace<Val<SC>>>()?;

        let num_ops = t.total_rows();
        let min_height = packing.min_trace_height();
        let lanes = 1;

        // Build preprocessed data: 2 values per operation [output_idx, out_mult]
        // These are stored flat; create_direct_preprocessed_trace handles lane layout.
        let mut preprocessed = Vec::with_capacity(num_ops * 2);
        for row in &t.operations {
            preprocessed.push(Val::<SC>::from_u32(row.output_wid.0 * self.d as u32));
            preprocessed.push(Val::<SC>::ONE); // out_mult placeholder
        }

        let air =
            RecomposeAir::<Val<SC>, 4>::new_with_preprocessed(lanes, preprocessed, min_height);
        let matrix = RecomposeAir::<Val<SC>, 4>::trace_to_matrix(&t.operations, lanes);

        Some(BatchTableInstance {
            op_type,
            air: DynamicAirEntry::new(Box::new(air)),
            trace: matrix,
            public_values: Vec::new(),
            rows: num_ops,
        })
    }
}

impl<SC> TableProver<SC> for RecomposeProver
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn op_type(&self) -> NpoTypeId {
        NpoTypeId::recompose()
    }

    impl_table_prover_batch_instances_from_base!(batch_instance_base);

    fn batch_air_from_table_entry(
        &self,
        _config: &SC,
        _degree: usize,
        _table_entry: &NonPrimitiveTableEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String> {
        let air = RecomposeAir::<Val<SC>, 4>::new_with_preprocessed(1, Vec::new(), 1);
        Ok(DynamicAirEntry::new(Box::new(air)))
    }

    fn air_with_committed_preprocessed(
        &self,
        committed_prep: Vec<Val<SC>>,
        min_height: usize,
    ) -> Option<DynamicAirEntry<SC>> {
        let air = RecomposeAir::<Val<SC>, 4>::new_with_preprocessed(1, committed_prep, min_height);
        Some(DynamicAirEntry::new(Box::new(air)))
    }
}

// ============================================================================
// D=2 Table Prover (Goldilocks)
// ============================================================================

pub struct RecomposeProverD2;

impl RecomposeProverD2 {
    fn batch_instance_base<SC>(
        &self,
        _config: &SC,
        packing: TablePacking,
        traces: &Traces<Val<SC>>,
    ) -> Option<BatchTableInstance<SC>>
    where
        SC: StarkGenericConfig + 'static + Send + Sync,
        Val<SC>: StarkField,
        SymbolicExpressionExt<Val<SC>, SC::Challenge>:
            Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    {
        let op_type = NpoTypeId::recompose();
        let trace = traces.non_primitive_traces.get(&op_type)?;
        if trace.rows() == 0 {
            return None;
        }

        let t = trace.as_any().downcast_ref::<RecomposeTrace<Val<SC>>>()?;
        let num_ops = t.total_rows();
        let min_height = packing.min_trace_height();
        let d = 2;
        let lanes = 1;

        let mut preprocessed = Vec::with_capacity(num_ops * 2);
        for row in &t.operations {
            preprocessed.push(Val::<SC>::from_u32(row.output_wid.0 * d as u32));
            preprocessed.push(Val::<SC>::ONE); // out_mult placeholder
        }

        let air =
            RecomposeAir::<Val<SC>, 2>::new_with_preprocessed(lanes, preprocessed, min_height);
        let matrix = RecomposeAir::<Val<SC>, 2>::trace_to_matrix(&t.operations, lanes);

        Some(BatchTableInstance {
            op_type,
            air: DynamicAirEntry::new(Box::new(air)),
            trace: matrix,
            public_values: Vec::new(),
            rows: num_ops,
        })
    }
}

impl<SC> TableProver<SC> for RecomposeProverD2
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn op_type(&self) -> NpoTypeId {
        NpoTypeId::recompose()
    }

    impl_table_prover_batch_instances_from_base!(batch_instance_base);

    fn batch_air_from_table_entry(
        &self,
        _config: &SC,
        _degree: usize,
        _table_entry: &NonPrimitiveTableEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String> {
        let air = RecomposeAir::<Val<SC>, 2>::new_with_preprocessed(1, Vec::new(), 1);
        Ok(DynamicAirEntry::new(Box::new(air)))
    }

    fn air_with_committed_preprocessed(
        &self,
        committed_prep: Vec<Val<SC>>,
        min_height: usize,
    ) -> Option<DynamicAirEntry<SC>> {
        let air = RecomposeAir::<Val<SC>, 2>::new_with_preprocessed(1, committed_prep, min_height);
        Some(DynamicAirEntry::new(Box::new(air)))
    }
}

// ============================================================================
// Preprocessor
// ============================================================================

/// NpoPreprocessor for the recompose table.
///
/// Converts EF preprocessed data to BF and sets `out_mult` from `ext_reads`.
#[derive(Clone, Default)]
pub struct RecomposePreprocessor;

impl NpoPreprocessor<p3_koala_bear::KoalaBear> for RecomposePreprocessor {
    fn preprocess(
        &self,
        _circuit: &dyn core::any::Any,
        preprocessed: &mut dyn core::any::Any,
    ) -> Result<NonPrimitivePreprocessedMap<p3_koala_bear::KoalaBear>, CircuitError> {
        type F = p3_koala_bear::KoalaBear;
        if let Some(prep) =
            preprocessed.downcast_mut::<PreprocessedColumns<BinomialExtensionField<F, 4>>>()
        {
            return recompose_preprocess_impl::<F, _>(prep);
        }
        if let Some(prep) = preprocessed.downcast_mut::<PreprocessedColumns<F>>() {
            return recompose_preprocess_impl::<F, _>(prep);
        }
        Ok(HashMap::new())
    }
}

impl NpoPreprocessor<p3_baby_bear::BabyBear> for RecomposePreprocessor {
    fn preprocess(
        &self,
        _circuit: &dyn core::any::Any,
        preprocessed: &mut dyn core::any::Any,
    ) -> Result<NonPrimitivePreprocessedMap<p3_baby_bear::BabyBear>, CircuitError> {
        type F = p3_baby_bear::BabyBear;
        if let Some(prep) =
            preprocessed.downcast_mut::<PreprocessedColumns<BinomialExtensionField<F, 4>>>()
        {
            return recompose_preprocess_impl::<F, _>(prep);
        }
        if let Some(prep) = preprocessed.downcast_mut::<PreprocessedColumns<F>>() {
            return recompose_preprocess_impl::<F, _>(prep);
        }
        Ok(HashMap::new())
    }
}

impl NpoPreprocessor<p3_goldilocks::Goldilocks> for RecomposePreprocessor {
    fn preprocess(
        &self,
        _circuit: &dyn core::any::Any,
        preprocessed: &mut dyn core::any::Any,
    ) -> Result<NonPrimitivePreprocessedMap<p3_goldilocks::Goldilocks>, CircuitError> {
        type F = p3_goldilocks::Goldilocks;
        if let Some(prep) =
            preprocessed.downcast_mut::<PreprocessedColumns<BinomialExtensionField<F, 2>>>()
        {
            return recompose_preprocess_impl::<F, _>(prep);
        }
        if let Some(prep) = preprocessed.downcast_mut::<PreprocessedColumns<F>>() {
            return recompose_preprocess_impl::<F, _>(prep);
        }
        Ok(HashMap::new())
    }
}

/// Generic implementation: extract recompose preprocessed data and set output multiplicities.
fn recompose_preprocess_impl<F, EF>(
    prep: &PreprocessedColumns<EF>,
) -> Result<NonPrimitivePreprocessedMap<F>, CircuitError>
where
    F: StarkField + PrimeField64,
    EF: Field + ExtensionField<F> + 'static,
{
    let op_type = NpoTypeId::recompose();
    let ef_data = match prep.non_primitive.get(&op_type) {
        Some(d) if !d.is_empty() => d,
        _ => return Ok(HashMap::new()),
    };

    let d = prep.d;
    let prep_width = 2; // [output_idx, out_mult]

    let mut prep_base: Vec<F> = ef_data
        .iter()
        .map(|v| v.as_base().ok_or(CircuitError::InvalidPreprocessedValues))
        .collect::<Result<Vec<_>, CircuitError>>()?;

    let neg_one = F::ZERO - F::ONE;
    let num_rows = prep_base.len() / prep_width;

    for row_idx in 0..num_rows {
        let row_start = row_idx * prep_width;
        let output_idx_pos = row_start; // output_idx is column 0
        let out_mult_pos = row_start + 1; // out_mult is column 1

        let output_idx_val = prep_base[output_idx_pos];
        let out_wid = F::as_canonical_u64(&output_idx_val) as usize / d;

        let is_dup = prep
            .dup_npo_outputs
            .get(&op_type)
            .and_then(|d| d.get(out_wid).copied())
            .unwrap_or(false);

        if is_dup {
            prep_base[out_mult_pos] = neg_one;
        } else {
            let n_reads = prep.ext_reads.get(out_wid).copied().unwrap_or(0);
            prep_base[out_mult_pos] = F::from_u32(n_reads);
        }
    }

    let mut result = HashMap::new();
    result.insert(op_type, prep_base);
    Ok(result)
}

// ============================================================================
// AIR Builder
// ============================================================================

/// NpoAirBuilder for the recompose table (D=4).
#[derive(Clone)]
pub struct RecomposeAirBuilder;

impl<SC> crate::common::NpoAirBuilder<SC, 4> for RecomposeAirBuilder
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn try_build(
        &self,
        op_type: &NpoTypeId,
        prep_base: &[Val<SC>],
        min_height: usize,
        _constraint_profile: crate::constraint_profile::ConstraintProfile,
    ) -> Option<(crate::common::CircuitTableAir<SC, 4>, usize)> {
        if op_type.as_str() != "recompose" {
            return None;
        }

        let prep_lane_width = RecomposeAir::<Val<SC>, 4>::preprocessed_lane_width();
        let num_rows = prep_base.len() / prep_lane_width;

        let air =
            RecomposeAir::<Val<SC>, 4>::new_with_preprocessed(1, prep_base.to_vec(), min_height);

        let padded_rows = num_rows
            .next_power_of_two()
            .max(min_height.next_power_of_two());
        let degree = p3_util::log2_ceil_usize(padded_rows);

        Some((
            crate::common::CircuitTableAir::Dynamic(DynamicAirEntry::new(Box::new(air))),
            degree,
        ))
    }
}

/// NpoAirBuilder for the recompose table (D=2, e.g. Goldilocks).
#[derive(Clone)]
pub struct RecomposeAirBuilderD2;

impl<SC> crate::common::NpoAirBuilder<SC, 2> for RecomposeAirBuilderD2
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn try_build(
        &self,
        op_type: &NpoTypeId,
        prep_base: &[Val<SC>],
        min_height: usize,
        _constraint_profile: crate::constraint_profile::ConstraintProfile,
    ) -> Option<(crate::common::CircuitTableAir<SC, 2>, usize)> {
        if op_type.as_str() != "recompose" {
            return None;
        }

        let prep_lane_width = RecomposeAir::<Val<SC>, 2>::preprocessed_lane_width();
        let num_rows = prep_base.len() / prep_lane_width;

        let air =
            RecomposeAir::<Val<SC>, 2>::new_with_preprocessed(1, prep_base.to_vec(), min_height);

        let padded_rows = num_rows
            .next_power_of_two()
            .max(min_height.next_power_of_two());
        let degree = p3_util::log2_ceil_usize(padded_rows);

        Some((
            crate::common::CircuitTableAir::Dynamic(DynamicAirEntry::new(Box::new(air))),
            degree,
        ))
    }
}
