//! Prover, preprocessor, and AIR builder for the built-in Statement sink.

use alloc::boxed::Box;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use hashbrown::HashMap;
use p3_baby_bear::BabyBear;
use p3_batch_stark::{StarkGenericConfig, Val};
use p3_circuit::ops::{NonPrimitivePreprocessedMap, NpoTypeId, StatementTrace};
use p3_circuit::tables::Traces;
use p3_circuit::{Circuit, CircuitError, PreprocessedColumns, StatementSchema};
use p3_field::extension::{BinomialExtensionField, QuinticTrinomialExtensionField};
use p3_field::{Algebra, ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
use p3_goldilocks::Goldilocks;
use p3_koala_bear::KoalaBear;
use p3_uni_stark::{SymbolicExpression, SymbolicExpressionExt};
use p3_util::log2_ceil_usize;

use super::dynamic_air::{
    BatchAir, BatchTableInstance, DynamicAirEntry, TableProver, transmute_traces,
};
use super::{AirVariant, NonPrimitiveTableEntry, TablePacking};
use crate::air::StatementAir;
use crate::common::{BuiltNpoTable, CircuitTableAir, NpoAirBuilder, NpoPreprocessor, NpoRelation};
use crate::config::StarkField;
use crate::{ConstraintProfile, impl_table_prover_batch_instances_from_base};

impl<SC, const D: usize> BatchAir<SC> for StatementAir<Val<SC>, D>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
}

/// Table prover for exactly one logical statement row.
pub struct StatementProver<const D: usize> {
    schema: StatementSchema,
}

impl<const D: usize> StatementProver<D> {
    pub const fn new(schema: StatementSchema) -> Self {
        Self { schema }
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
        let op_type = NpoTypeId::statement();
        let trace = traces.non_primitive_traces.get(&op_type)?;
        let statement = trace.as_any().downcast_ref::<StatementTrace<Val<SC>>>()?;
        if statement.values.len() != self.schema.base_len()
            || statement.input_wids.len() != self.schema.base_len()
            || packing.npo_lanes(&op_type).unwrap_or(1) != 1
        {
            return None;
        }
        let min_height = packing
            .npo_min_height(&op_type)
            .unwrap_or_else(|| packing.min_trace_height());
        let mut preprocessed = Val::<SC>::zero_vec(1 + self.schema.base_len());
        preprocessed[0] = Val::<SC>::ONE;
        for (slot, &wid) in statement.input_wids.iter().enumerate() {
            preprocessed[1 + slot] = wid.base_field_index::<Val<SC>, D>();
        }
        let air = StatementAir::<Val<SC>, D>::new_with_preprocessed(
            self.schema.base_len(),
            preprocessed,
            min_height,
        );
        let matrix = StatementAir::<Val<SC>, D>::trace_to_matrix(&statement.values);
        Some(BatchTableInstance {
            op_type,
            air: DynamicAirEntry::new(Box::new(air)),
            trace: matrix,
            public_values: statement.values.clone(),
            rows: 1,
            lanes: 1,
        })
    }
}

impl<SC, const D: usize> TableProver<SC> for StatementProver<D>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn op_type(&self) -> NpoTypeId {
        NpoTypeId::statement()
    }

    impl_table_prover_batch_instances_from_base!(batch_instance_base);

    fn batch_air_from_table_entry(
        &self,
        _config: &SC,
        _degree: usize,
        _circuit_extension_degree: u32,
        table_entry: &NonPrimitiveTableEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String> {
        if table_entry.op_type != NpoTypeId::statement()
            || table_entry.rows != 1
            || table_entry.lanes != 1
            || table_entry.public_values.len() != self.schema.base_len()
        {
            return Err("statement proof metadata does not match its fixed schema".to_string());
        }
        Ok(DynamicAirEntry::new(Box::new(
            StatementAir::<Val<SC>, D>::new_with_preprocessed(
                self.schema.base_len(),
                Vec::new(),
                1,
            ),
        )))
    }

    fn air_with_committed_preprocessed(
        &self,
        committed_prep: Vec<Val<SC>>,
        min_height: usize,
        lanes: usize,
        _circuit_extension_degree: u32,
    ) -> Option<DynamicAirEntry<SC>> {
        if lanes != 1 || committed_prep.len() != 1 + self.schema.base_len() {
            return None;
        }
        Some(DynamicAirEntry::new(Box::new(
            StatementAir::<Val<SC>, D>::new_with_preprocessed(
                self.schema.base_len(),
                committed_prep,
                min_height,
            ),
        )))
    }
}

#[derive(Clone)]
pub struct StatementPreprocessor {
    schema: StatementSchema,
}

impl StatementPreprocessor {
    pub const fn new(schema: StatementSchema) -> Self {
        Self { schema }
    }
}

macro_rules! impl_statement_preprocessor {
    ($base:ty, [$($ef:ty => $d:literal),+ $(,)?]) => {
        impl NpoPreprocessor<$base> for StatementPreprocessor {
            fn preprocess(
                &self,
                circuit: &dyn core::any::Any,
                preprocessed: &mut dyn core::any::Any,
            ) -> Result<NonPrimitivePreprocessedMap<$base>, CircuitError> {
                $(
                    if let (Some(circuit), Some(preprocessed)) = (
                        circuit.downcast_ref::<Circuit<$ef>>(),
                        preprocessed.downcast_mut::<PreprocessedColumns<$ef, $d>>(),
                    ) {
                        return statement_preprocess_impl::<$base, $ef, $d>(
                            circuit,
                            preprocessed,
                            &self.schema,
                        );
                    }
                )+
                Ok(HashMap::new())
            }
        }
    };
}

impl_statement_preprocessor!(
    BabyBear,
    [
        BabyBear => 1,
        BinomialExtensionField<BabyBear, 4> => 4,
    ]
);
impl_statement_preprocessor!(
    KoalaBear,
    [
        KoalaBear => 1,
        BinomialExtensionField<KoalaBear, 4> => 4,
        QuinticTrinomialExtensionField<KoalaBear> => 5,
    ]
);
impl_statement_preprocessor!(
    Goldilocks,
    [
        Goldilocks => 1,
        BinomialExtensionField<Goldilocks, 2> => 2,
    ]
);

fn statement_preprocess_impl<F, EF, const D: usize>(
    circuit: &Circuit<EF>,
    prep: &PreprocessedColumns<EF, D>,
    schema: &StatementSchema,
) -> Result<NonPrimitivePreprocessedMap<F>, CircuitError>
where
    F: StarkField + PrimeField64,
    EF: Field + ExtensionField<F>,
{
    if circuit.statement_schema() != Some(schema) {
        return Err(CircuitError::InvalidStatementConfiguration);
    }
    if schema.base_len() == 0 {
        return Ok(HashMap::new());
    }
    let values = prep
        .non_primitive
        .get(&NpoTypeId::statement())
        .ok_or(CircuitError::InvalidStatementConfiguration)?;
    if values.len() != 1 + schema.base_len() {
        return Err(CircuitError::InvalidStatementConfiguration);
    }
    let base = values
        .iter()
        .map(|value| {
            value
                .as_base()
                .ok_or(CircuitError::InvalidPreprocessedValues)
        })
        .collect::<Result<Vec<_>, _>>()?;
    if base[0] != F::ONE {
        return Err(CircuitError::InvalidStatementConfiguration);
    }
    Ok(core::iter::once((NpoTypeId::statement(), base)).collect())
}

#[derive(Clone)]
pub struct StatementAirBuilder<const D: usize> {
    schema: StatementSchema,
}

impl<const D: usize> StatementAirBuilder<D> {
    pub const fn new(schema: StatementSchema) -> Self {
        Self { schema }
    }
}

impl<SC, const D: usize> NpoAirBuilder<SC, D> for StatementAirBuilder<D>
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
        lanes: usize,
        _constraint_profile: ConstraintProfile,
    ) -> Option<(CircuitTableAir<SC, D>, usize)> {
        if *op_type != NpoTypeId::statement()
            || lanes != 1
            || prep_base.len() != 1 + self.schema.base_len()
            || prep_base.first().copied() != Some(Val::<SC>::ONE)
        {
            return None;
        }
        let air = StatementAir::<Val<SC>, D>::new_with_preprocessed(
            self.schema.base_len(),
            prep_base.to_vec(),
            min_height,
        );
        Some((
            CircuitTableAir::Dynamic(DynamicAirEntry::new(Box::new(air))),
            log2_ceil_usize(min_height.next_power_of_two()),
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
            NpoRelation::new(op_type.clone(), 1, 1, AirVariant::Baseline, Vec::new()),
        ))
    }
}
