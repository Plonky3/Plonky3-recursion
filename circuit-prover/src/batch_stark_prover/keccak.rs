//! Keccak-f\[1600\] table prover: builds [`KeccakF1600Air`] instances for the batch STARK prover.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use hashbrown::HashMap;
use p3_baby_bear::BabyBear;
use p3_batch_stark::{StarkGenericConfig, Val};
use p3_circuit::ops::{KeccakF1600Trace, NonPrimitivePreprocessedMap, NpoTypeId};
use p3_circuit::tables::Traces;
use p3_circuit::{CircuitError, PreprocessedColumns};
use p3_field::extension::{BinomialExtensionField, QuinticTrinomialExtensionField};
use p3_field::{Algebra, ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_koala_bear::KoalaBear;
use p3_uni_stark::{SymbolicExpression, SymbolicExpressionExt};
use p3_util::log2_strict_usize;

use super::dynamic_air::{
    BatchAir, BatchTableInstance, DynamicAirEntry, TableProver, transmute_traces,
};
use super::{AirVariant, NonPrimitiveTableEntry, TablePacking};
use crate::air::keccak_air::{KECCAK_PREP_OP_WIDTH, KeccakF1600Air};
use crate::common::{BuiltNpoTable, CircuitTableAir, NpoAirBuilder, NpoPreprocessor, NpoRelation};
use crate::config::StarkField;
use crate::{ConstraintProfile, impl_table_prover_batch_instances_from_base};

impl<SC, const D: usize> BatchAir<SC> for KeccakF1600Air<Val<SC>, D>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
}

/// Table prover for Keccak-f\[1600\] calls. The table is single-lane: a call spans 24 rows.
#[derive(Clone, Copy, Debug, Default)]
pub struct KeccakF1600Prover<const D: usize>;

impl<const D: usize> KeccakF1600Prover<D> {
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
        let op_type = NpoTypeId::keccak_f1600();
        let trace = traces.non_primitive_traces.get(&op_type)?;
        if trace.rows() == 0 {
            return None;
        }
        let t = trace.as_any().downcast_ref::<KeccakF1600Trace>()?;
        let num_ops = t.operations.len();
        let min_height = packing
            .npo_min_height(&op_type)
            .unwrap_or_else(|| packing.min_trace_height());

        // The instance carries the call indices; the committed preprocessed trace, which also
        // carries the output multiplicities, comes from the prepared prover data.
        let mut preprocessed = Val::<SC>::zero_vec(num_ops * KECCAK_PREP_OP_WIDTH);
        for (op, row) in t.operations.iter().enumerate() {
            let base = op * KECCAK_PREP_OP_WIDTH;
            preprocessed[base] = Val::<SC>::ONE;
            for (j, wid) in row.input_wids.iter().enumerate() {
                preprocessed[base + 1 + j] = wid.base_field_index::<Val<SC>, D>();
            }
            let outputs = base + 1 + row.input_wids.len();
            for (j, wid) in row.output_wids.iter().enumerate() {
                preprocessed[outputs + 2 * j] = wid.base_field_index::<Val<SC>, D>();
            }
        }

        let height = KeccakF1600Air::<Val<SC>, D>::height_for(num_ops, min_height);
        let air = KeccakF1600Air::<Val<SC>, D>::new_with_preprocessed(preprocessed, min_height);
        let matrix = KeccakF1600Air::<Val<SC>, D>::trace_to_matrix(&t.operations, height);

        Some(BatchTableInstance {
            op_type,
            air: DynamicAirEntry::new(Box::new(air)),
            trace: matrix,
            public_values: Vec::new(),
            rows: num_ops,
            lanes: 1,
        })
    }
}

impl<SC, const D: usize> TableProver<SC> for KeccakF1600Prover<D>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn op_type(&self) -> NpoTypeId {
        NpoTypeId::keccak_f1600()
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
        _table_entry: &NonPrimitiveTableEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String> {
        Ok(DynamicAirEntry::new(Box::new(
            KeccakF1600Air::<Val<SC>, D>::new_with_preprocessed(Vec::new(), 1),
        )))
    }

    fn air_with_committed_preprocessed(
        &self,
        committed_prep: Vec<Val<SC>>,
        min_height: usize,
        _lanes: usize,
        _circuit_extension_degree: u32,
    ) -> Option<DynamicAirEntry<SC>> {
        Some(DynamicAirEntry::new(Box::new(
            KeccakF1600Air::<Val<SC>, D>::new_with_preprocessed(committed_prep, min_height),
        )))
    }
}

// ============================================================================
// Preprocessor
// ============================================================================

/// NpoPreprocessor for the Keccak-f table.
///
/// Converts the circuit's extension-field preprocessed values to the base field and sets each
/// output limb's multiplicity: its read count for the limb's creator, `-1` for a duplicate.
#[derive(Clone, Copy, Debug, Default)]
pub struct KeccakF1600Preprocessor;

macro_rules! keccak_preprocessor_for {
    ($field:ty, $(($ext:ty, $d:literal)),+ $(,)?) => {
        impl NpoPreprocessor<$field> for KeccakF1600Preprocessor {
            fn preprocess(
                &self,
                _circuit: &dyn core::any::Any,
                preprocessed: &mut dyn core::any::Any,
            ) -> Result<NonPrimitivePreprocessedMap<$field>, CircuitError> {
                $(
                    if let Some(prep) = preprocessed.downcast_mut::<PreprocessedColumns<$ext, $d>>() {
                        return keccak_preprocess_impl::<$field, _, $d>(prep);
                    }
                )+
                Ok(HashMap::new())
            }
        }
    };
}

keccak_preprocessor_for!(
    KoalaBear,
    (BinomialExtensionField<KoalaBear, 4>, 4),
    (QuinticTrinomialExtensionField<KoalaBear>, 5),
    (KoalaBear, 1),
);
keccak_preprocessor_for!(
    BabyBear,
    (BinomialExtensionField<BabyBear, 4>, 4),
    (BabyBear, 1),
);
keccak_preprocessor_for!(
    Goldilocks,
    (BinomialExtensionField<Goldilocks, 2>, 2),
    (Goldilocks, 1),
);

fn keccak_preprocess_impl<F, EF, const D: usize>(
    prep: &PreprocessedColumns<EF, D>,
) -> Result<NonPrimitivePreprocessedMap<F>, CircuitError>
where
    F: StarkField + PrimeField64,
    EF: Field + ExtensionField<F> + 'static,
{
    let op_type = NpoTypeId::keccak_f1600();
    let ef_data = match prep.non_primitive.get(&op_type) {
        Some(data) if !data.is_empty() => data,
        _ => return Ok(HashMap::new()),
    };
    let mut prep_base: Vec<F> = ef_data
        .iter()
        .map(|v| v.as_base().ok_or(CircuitError::InvalidPreprocessedValues))
        .collect::<Result<_, _>>()?;
    if !prep_base.len().is_multiple_of(KECCAK_PREP_OP_WIDTH) {
        return Err(CircuitError::InvalidPreprocessedValues);
    }

    let dups = prep.dup_npo_outputs.get(&op_type);
    for call in prep_base.chunks_exact_mut(KECCAK_PREP_OP_WIDTH) {
        let outputs = &mut call[1 + p3_circuit::ops::KECCAK_STATE_LIMBS..];
        for pair in outputs.chunks_exact_mut(2) {
            let wid = pair[0].as_canonical_u64() as usize / D;
            let is_dup = dups.and_then(|d| d.get(wid).copied()).unwrap_or(false);
            pair[1] = if is_dup {
                F::NEG_ONE
            } else {
                F::from_u32(prep.ext_reads.get(wid).copied().unwrap_or(0))
            };
        }
    }

    let mut result = HashMap::new();
    result.insert(op_type, prep_base);
    Ok(result)
}

// ============================================================================
// AIR Builder
// ============================================================================

/// NpoAirBuilder for the Keccak-f table.
#[derive(Clone, Copy, Debug, Default)]
pub struct KeccakF1600AirBuilder<const D: usize>;

impl<SC, const D: usize> NpoAirBuilder<SC, D> for KeccakF1600AirBuilder<D>
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
        _lanes: usize,
        _constraint_profile: ConstraintProfile,
    ) -> Option<(CircuitTableAir<SC, D>, usize)> {
        if *op_type != NpoTypeId::keccak_f1600() {
            return None;
        }
        let num_ops = prep_base.len() / KECCAK_PREP_OP_WIDTH;
        let height = KeccakF1600Air::<Val<SC>, D>::height_for(num_ops, min_height);
        let air =
            KeccakF1600Air::<Val<SC>, D>::new_with_preprocessed(prep_base.to_vec(), min_height);
        Some((
            CircuitTableAir::Dynamic(DynamicAirEntry::new(Box::new(air))),
            log2_strict_usize(height),
        ))
    }

    fn try_build_trusted(
        &self,
        op_type: &NpoTypeId,
        prep_base: &[Val<SC>],
        min_height: usize,
        lanes: usize,
        constraint_profile: ConstraintProfile,
    ) -> Option<BuiltNpoTable<SC, D>> {
        let (air, degree) =
            self.try_build(op_type, prep_base, min_height, lanes, constraint_profile)?;
        Some(BuiltNpoTable::new(
            air,
            degree,
            NpoRelation::new(
                op_type.clone(),
                prep_base.len() / KECCAK_PREP_OP_WIDTH,
                1,
                AirVariant::Baseline,
                Vec::new(),
            ),
        ))
    }
}
