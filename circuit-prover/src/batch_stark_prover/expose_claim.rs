//! Expose-claim table prover: builds `ExposeClaimAir` instances for the batch
//! STARK prover and POPULATES `public_values` with the bus-bound claim values.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use hashbrown::HashMap;
use p3_baby_bear::BabyBear;
use p3_batch_stark::{StarkGenericConfig, Val};
use p3_circuit::ops::expose_claim::ExposeClaimTrace;
use p3_circuit::ops::{NonPrimitivePreprocessedMap, NpoTypeId};
use p3_circuit::tables::Traces;
use p3_circuit::{CircuitError, PreprocessedColumns};
use p3_field::extension::{BinomialExtensionField, QuinticTrinomialExtensionField};
use p3_field::{Algebra, ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_koala_bear::KoalaBear;
use p3_uni_stark::{SymbolicExpression, SymbolicExpressionExt};
use p3_util::log2_ceil_usize;

use super::dynamic_air::{
    BatchAir, BatchTableInstance, DynamicAirEntry, TableProver, transmute_traces,
};
use super::{NonPrimitiveTableEntry, TablePacking};
use crate::air::ExposeClaimAir;
use crate::common::{CircuitTableAir, NpoAirBuilder, NpoPreprocessor};
use crate::config::StarkField;
use crate::{ConstraintProfile, impl_table_prover_batch_instances_from_base};

/// Preprocessed lane width (base): `[witness_idx, read_mult]`.
const EXPOSE_CLAIM_PREP_LANE_WIDTH: usize = 2;

impl<SC, const D: usize> BatchAir<SC> for ExposeClaimAir<Val<SC>, D>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
}

/// Table prover for the expose-claim NPO.
pub struct ExposeClaimProver<const D: usize>;

impl<const D: usize> ExposeClaimProver<D> {
    pub const fn new() -> Self {
        Self
    }

    fn batch_instance_base<SC>(
        &self,
        _config: &SC,
        packing: &TablePacking,
        traces: &Traces<Val<SC>>,
    ) -> Option<BatchTableInstance<SC>>
    where
        SC: StarkGenericConfig + 'static + Send + Sync,
        Val<SC>: StarkField,
        SymbolicExpressionExt<Val<SC>, SC::Challenge>:
            Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    {
        let op_type = NpoTypeId::expose_claim();
        let trace = traces.non_primitive_traces.get(&op_type)?;
        if trace.rows() == 0 {
            return None;
        }
        let t = trace
            .as_any()
            .downcast_ref::<ExposeClaimTrace<Val<SC>>>()?;

        let num_claims = t.total_rows();
        let min_height = packing.min_trace_height();

        // Preprocessed (base): [witness_idx, read_mult=-1] per lane.
        let neg_one = Val::<SC>::ZERO - Val::<SC>::ONE;
        let mut preprocessed = Val::<SC>::zero_vec(num_claims * EXPOSE_CLAIM_PREP_LANE_WIDTH);
        for (i, row) in t.operations.iter().enumerate() {
            let base = i * EXPOSE_CLAIM_PREP_LANE_WIDTH;
            preprocessed[base] = row.witness_id.base_field_index::<Val<SC>, D>();
            preprocessed[base + 1] = neg_one;
        }

        // Public values: the claim values, in lane order. THIS is the host-readable
        // channel, bound to the bus-read value by the AIR.
        let public_values: Vec<Val<SC>> = t.operations.iter().map(|row| row.value).collect();

        let air = ExposeClaimAir::<Val<SC>, D>::new_with_preprocessed(
            num_claims,
            preprocessed,
            min_height,
        );
        let matrix = ExposeClaimAir::<Val<SC>, D>::trace_to_matrix(&t.operations, min_height);

        Some(BatchTableInstance {
            op_type,
            air: DynamicAirEntry::new(Box::new(air)),
            trace: matrix,
            public_values,
            rows: num_claims,
            lanes: num_claims,
        })
    }
}

impl<const D: usize> Default for ExposeClaimProver<D> {
    fn default() -> Self {
        Self::new()
    }
}

impl<SC, const D: usize> TableProver<SC> for ExposeClaimProver<D>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn op_type(&self) -> NpoTypeId {
        NpoTypeId::expose_claim()
    }

    fn lanes(&self) -> usize {
        1
    }

    impl_table_prover_batch_instances_from_base!(batch_instance_base);

    fn batch_air_from_table_entry(
        &self,
        _config: &SC,
        _degree: usize,
        _circuit_extension_degree: u32,
        table_entry: &NonPrimitiveTableEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String> {
        // `rows` == number of claims (one lane per claim, one logical row).
        let air = ExposeClaimAir::<Val<SC>, D>::new_with_preprocessed(table_entry.rows, Vec::new(), 1);
        Ok(DynamicAirEntry::new(Box::new(air)))
    }

    fn air_with_committed_preprocessed(
        &self,
        committed_prep: Vec<Val<SC>>,
        min_height: usize,
        _lanes: usize,
        _circuit_extension_degree: u32,
    ) -> Option<DynamicAirEntry<SC>> {
        let num_claims = committed_prep.len() / EXPOSE_CLAIM_PREP_LANE_WIDTH;
        let air = ExposeClaimAir::<Val<SC>, D>::new_with_preprocessed(
            num_claims,
            committed_prep,
            min_height,
        );
        Some(DynamicAirEntry::new(Box::new(air)))
    }
}

// ============================================================================
// Preprocessor
// ============================================================================

/// NpoPreprocessor for the expose-claim table.
///
/// Converts the EF-registered `[witness_idx, mult_placeholder]` lane rows to
/// base, overwriting the placeholder with the reader multiplicity `-1`.
#[derive(Default, Clone)]
pub struct ExposeClaimPreprocessor;

impl ExposeClaimPreprocessor {
    pub const fn new() -> Self {
        Self
    }
}

macro_rules! impl_expose_claim_preprocessor {
    ($field:ty, $( ($ef:ty, $d:literal) ),+ $(,)?) => {
        impl NpoPreprocessor<$field> for ExposeClaimPreprocessor {
            fn preprocess(
                &self,
                _circuit: &dyn core::any::Any,
                preprocessed: &mut dyn core::any::Any,
            ) -> Result<NonPrimitivePreprocessedMap<$field>, CircuitError> {
                type F = $field;
                $(
                    if let Some(prep) =
                        preprocessed.downcast_mut::<PreprocessedColumns<$ef, $d>>()
                    {
                        return expose_claim_preprocess_impl::<F, _, $d>(prep);
                    }
                )+
                if let Some(prep) = preprocessed.downcast_mut::<PreprocessedColumns<F, 1>>() {
                    return expose_claim_preprocess_impl::<F, _, 1>(prep);
                }
                Ok(HashMap::new())
            }
        }
    };
}

impl_expose_claim_preprocessor!(KoalaBear, (BinomialExtensionField<KoalaBear, 4>, 4), (QuinticTrinomialExtensionField<KoalaBear>, 5));
impl_expose_claim_preprocessor!(BabyBear, (BinomialExtensionField<BabyBear, 4>, 4));
impl_expose_claim_preprocessor!(Goldilocks, (BinomialExtensionField<Goldilocks, 2>, 2));

fn expose_claim_preprocess_impl<F, EF, const D: usize>(
    prep: &PreprocessedColumns<EF, D>,
) -> Result<NonPrimitivePreprocessedMap<F>, CircuitError>
where
    F: StarkField + PrimeField64,
    EF: Field + ExtensionField<F> + 'static,
{
    let op_type = NpoTypeId::expose_claim();
    let ef_data = match prep.non_primitive.get(&op_type) {
        Some(d) if !d.is_empty() => d,
        _ => return Ok(HashMap::new()),
    };

    let prep_width = EXPOSE_CLAIM_PREP_LANE_WIDTH;

    let mut prep_base: Vec<F> = ef_data
        .iter()
        .map(|v| v.as_base().ok_or(CircuitError::InvalidPreprocessedValues))
        .collect::<Result<Vec<_>, CircuitError>>()?;

    if !prep_base.len().is_multiple_of(prep_width) {
        return Err(CircuitError::InvalidPreprocessedValues);
    }

    let neg_one = F::ZERO - F::ONE;
    let num_rows = prep_base.len() / prep_width;
    for row_idx in 0..num_rows {
        // Slot 0 = witness index (left as-is); slot 1 = reader multiplicity.
        prep_base[row_idx * prep_width + 1] = neg_one;
    }

    let mut result = HashMap::new();
    result.insert(op_type, prep_base);
    Ok(result)
}

// ============================================================================
// AIR Builder
// ============================================================================

/// NpoAirBuilder for the expose-claim table.
#[derive(Clone, Default)]
pub struct ExposeClaimAirBuilder<const D: usize>;

impl<const D: usize> ExposeClaimAirBuilder<D> {
    pub const fn new() -> Self {
        Self
    }
}

impl<SC, const D: usize> NpoAirBuilder<SC, D> for ExposeClaimAirBuilder<D>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn lanes(&self) -> usize {
        1
    }

    fn try_build(
        &self,
        op_type: &NpoTypeId,
        prep_base: &[Val<SC>],
        min_height: usize,
        _lanes: usize,
        _constraint_profile: ConstraintProfile,
    ) -> Option<(CircuitTableAir<SC, D>, usize)> {
        if op_type.as_str() != "expose_claim" {
            return None;
        }

        let num_claims = (prep_base.len() / EXPOSE_CLAIM_PREP_LANE_WIDTH).max(1);
        let air = ExposeClaimAir::<Val<SC>, D>::new_with_preprocessed(
            num_claims,
            prep_base.to_vec(),
            min_height,
        );

        // The table has exactly one logical (power-of-two-padded) row.
        let padded_rows = 1usize.max(min_height.next_power_of_two());
        let degree = log2_ceil_usize(padded_rows);

        Some((
            CircuitTableAir::Dynamic(DynamicAirEntry::new(Box::new(air))),
            degree,
        ))
    }
}
