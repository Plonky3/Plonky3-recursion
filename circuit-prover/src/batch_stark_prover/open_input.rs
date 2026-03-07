use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use core::any::Any;

use hashbrown::HashMap;
use p3_air::{SymbolicExpression, SymbolicExpressionExt};
use p3_batch_stark::{StarkGenericConfig, Val};
use p3_circuit::op::{NonPrimitivePreprocessedMap, NpoTypeId};
use p3_circuit::ops::open_input::OpenInputTrace;
use p3_circuit::tables::Traces;
use p3_circuit::{CircuitError, PreprocessedColumns};
use p3_field::extension::{BinomialExtensionField, BinomiallyExtendable};
use p3_field::{Algebra, ExtensionField, Field, PrimeCharacteristicRing, PrimeField64};
use p3_fri_air::OpenInputAir;

use super::dynamic_air::{BatchTableInstance, DynamicAirEntry, TableProver};
use crate::batch_stark_prover::{BatchAir, NonPrimitiveTableEntry, TablePacking};
use crate::common::{CircuitTableAir, NpoAirBuilder, NpoPreprocessor};
use crate::config::StarkField;
use crate::constraint_profile::ConstraintProfile;

impl<SC, const D: usize> BatchAir<SC> for OpenInputAir<Val<SC>, D>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
}

/// Prover plugin for the `OpenInput` non-primitive table.
///
/// `circuit_d` is the extension degree of the verification circuit (e.g. 4 for KoalaBear/BabyBear,
/// 2 for Goldilocks). This determines the `NpoTypeId` used to look up the trace.
#[derive(Clone)]
pub struct OpenInputProver {
    circuit_d: usize,
}

unsafe impl Send for OpenInputProver {}
unsafe impl Sync for OpenInputProver {}

impl OpenInputProver {
    pub const fn new(circuit_d: usize) -> Self {
        Self { circuit_d }
    }
}

impl<SC> TableProver<SC> for OpenInputProver
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField + BinomiallyExtendable<4>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn op_type(&self) -> NpoTypeId {
        NpoTypeId::open_input_d(self.circuit_d)
    }

    fn batch_instance_d1(
        &self,
        _config: &SC,
        packing: TablePacking,
        traces: &Traces<Val<SC>>,
    ) -> Option<BatchTableInstance<SC>> {
        let op_type = NpoTypeId::open_input_d(self.circuit_d);
        let trace = traces.non_primitive_trace::<OpenInputTrace<Val<SC>>>(&op_type)?;

        let rows = trace.rows.len();
        if rows == 0 {
            return None;
        }

        let min_height = packing.min_trace_height();
        let preprocessed = OpenInputAir::<Val<SC>, 1>::trace_to_preprocessed(trace);
        let generator = Val::<SC>::GENERATOR;
        // w_binomial is unused for D=1 (no extension multiplication).
        let air = OpenInputAir::<Val<SC>, 1>::new_with_preprocessed(Val::<SC>::ZERO, preprocessed)
            .with_generator(generator)
            .with_min_height(min_height);
        let matrix = air.trace_to_matrix::<Val<SC>>(&trace.rows);
        let padded_rows = rows.next_power_of_two();

        Some(BatchTableInstance {
            op_type: NpoTypeId::open_input_d(self.circuit_d),
            air: DynamicAirEntry::new(Box::new(air)),
            trace: matrix,
            public_values: Vec::new(),
            rows: padded_rows,
        })
    }

    fn batch_instance_d1_with_committed_prep(
        &self,
        _config: &SC,
        packing: TablePacking,
        traces: &Traces<Val<SC>>,
        committed_prep: Vec<Val<SC>>,
    ) -> Option<BatchTableInstance<SC>> {
        let op_type = NpoTypeId::open_input_d(self.circuit_d);
        let trace = traces.non_primitive_trace::<OpenInputTrace<Val<SC>>>(&op_type)?;

        let rows = trace.rows.len();
        if rows == 0 {
            return None;
        }

        let min_height = packing.min_trace_height();
        let generator = Val::<SC>::GENERATOR;
        // Use committed preprocessed data directly, skipping trace_to_preprocessed.
        // w_binomial is unused for D=1 (no extension multiplication).
        let air =
            OpenInputAir::<Val<SC>, 1>::new_with_preprocessed(Val::<SC>::ZERO, committed_prep)
                .with_generator(generator)
                .with_min_height(min_height);
        let matrix = air.trace_to_matrix::<Val<SC>>(&trace.rows);
        let padded_rows = rows.next_power_of_two();

        Some(BatchTableInstance {
            op_type: NpoTypeId::open_input_d(self.circuit_d),
            air: DynamicAirEntry::new(Box::new(air)),
            trace: matrix,
            public_values: Vec::new(),
            rows: padded_rows,
        })
    }

    fn batch_instance_d2(
        &self,
        _config: &SC,
        _packing: TablePacking,
        _traces: &Traces<BinomialExtensionField<Val<SC>, 2>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    fn batch_instance_d4(
        &self,
        _config: &SC,
        packing: TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 4>>,
    ) -> Option<BatchTableInstance<SC>>
    where
        Val<SC>: BinomiallyExtendable<4>,
    {
        type EF4<F> = BinomialExtensionField<F, 4>;
        let op_type = NpoTypeId::open_input_d(self.circuit_d);
        let trace = traces.non_primitive_trace::<OpenInputTrace<EF4<Val<SC>>>>(&op_type)?;

        let rows = trace.rows.len();
        if rows == 0 {
            return None;
        }

        let min_height = packing.min_trace_height();
        let preprocessed = OpenInputAir::<Val<SC>, 4>::trace_to_preprocessed(trace);
        let w = <Val<SC> as BinomiallyExtendable<4>>::W;
        let generator = Val::<SC>::GENERATOR;
        let air = OpenInputAir::<Val<SC>, 4>::new_with_preprocessed(w, preprocessed)
            .with_generator(generator)
            .with_min_height(min_height);
        let matrix = air.trace_to_matrix::<EF4<Val<SC>>>(&trace.rows);
        let padded_rows = rows.next_power_of_two();

        Some(BatchTableInstance {
            op_type: NpoTypeId::open_input_d(self.circuit_d),
            air: DynamicAirEntry::new(Box::new(air)),
            trace: matrix,
            public_values: Vec::new(),
            rows: padded_rows,
        })
    }

    fn batch_instance_d4_with_committed_prep(
        &self,
        _config: &SC,
        packing: TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 4>>,
        committed_prep: Vec<Val<SC>>,
    ) -> Option<BatchTableInstance<SC>>
    where
        Val<SC>: BinomiallyExtendable<4>,
    {
        type EF4<F> = BinomialExtensionField<F, 4>;
        let op_type = NpoTypeId::open_input_d(self.circuit_d);
        // The OpenInput trace stores EF4 rows so that `trace_to_matrix::<EF4>` can extract
        // the correct D=4 limbs per value.
        let trace = traces.non_primitive_trace::<OpenInputTrace<EF4<Val<SC>>>>(&op_type)?;

        let rows = trace.rows.len();
        if rows == 0 {
            return None;
        }

        let min_height = packing.min_trace_height();
        let w = <Val<SC> as BinomiallyExtendable<4>>::W;
        let generator = Val::<SC>::GENERATOR;
        // Use committed preprocessed data directly, skipping trace_to_preprocessed.
        let air = OpenInputAir::<Val<SC>, 4>::new_with_preprocessed(w, committed_prep)
            .with_generator(generator)
            .with_min_height(min_height);
        let matrix = air.trace_to_matrix::<EF4<Val<SC>>>(&trace.rows);
        let padded_rows = rows.next_power_of_two();

        Some(BatchTableInstance {
            op_type: NpoTypeId::open_input_d(self.circuit_d),
            air: DynamicAirEntry::new(Box::new(air)),
            trace: matrix,
            public_values: Vec::new(),
            rows: padded_rows,
        })
    }

    fn batch_instance_d6(
        &self,
        _config: &SC,
        _packing: TablePacking,
        _traces: &Traces<BinomialExtensionField<Val<SC>, 6>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    fn batch_instance_d8(
        &self,
        _config: &SC,
        _packing: TablePacking,
        _traces: &Traces<BinomialExtensionField<Val<SC>, 8>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    fn batch_air_from_table_entry(
        &self,
        _config: &SC,
        _degree: usize,
        _table_entry: &NonPrimitiveTableEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String> {
        let generator = Val::<SC>::GENERATOR;
        match self.circuit_d {
            4 => {
                let w = <Val<SC> as BinomiallyExtendable<4>>::W;
                Ok(DynamicAirEntry::new(Box::new(
                    OpenInputAir::<Val<SC>, 4>::new(w).with_generator(generator),
                )))
            }
            _ => Ok(DynamicAirEntry::new(Box::new(
                OpenInputAir::<Val<SC>, 1>::new(Val::<SC>::ZERO).with_generator(generator),
            ))),
        }
    }

    fn air_with_committed_preprocessed(
        &self,
        committed_prep: Vec<Val<SC>>,
        min_height: usize,
    ) -> Option<DynamicAirEntry<SC>> {
        // The committed preprocessed data from `get_airs_and_degrees_with_prep` uses
        // D-scaled witness indices, while `trace_to_preprocessed` uses raw WitnessId
        // indices. We must override with the committed data so lookup tuples match
        // the D-scaled indices used by all other tables (Const, Public, ALU, Poseidon2).
        let generator = Val::<SC>::GENERATOR;
        match self.circuit_d {
            4 => {
                let w = <Val<SC> as BinomiallyExtendable<4>>::W;
                let air = OpenInputAir::<Val<SC>, 4>::new_with_preprocessed(w, committed_prep)
                    .with_generator(generator)
                    .with_min_height(min_height);
                Some(DynamicAirEntry::new(Box::new(air)))
            }
            _ => {
                let air = OpenInputAir::<Val<SC>, 1>::new_with_preprocessed(
                    Val::<SC>::ZERO,
                    committed_prep,
                )
                .with_generator(generator)
                .with_min_height(min_height);
                Some(DynamicAirEntry::new(Box::new(air)))
            }
        }
    }
}

/// Prover plugin for the `OpenInput` non-primitive table in D=2 circuits (e.g. Goldilocks).
///
/// This is a separate type from [`OpenInputProver`] because the `TableProver` trait bound
/// requires `BinomiallyExtendable<4>` for the D=4 variant, which Goldilocks does not satisfy.
#[derive(Clone)]
pub struct OpenInputProverD2 {
    circuit_d: usize,
}

unsafe impl Send for OpenInputProverD2 {}
unsafe impl Sync for OpenInputProverD2 {}

impl OpenInputProverD2 {
    pub const fn new(circuit_d: usize) -> Self {
        Self { circuit_d }
    }
}

impl<SC> TableProver<SC> for OpenInputProverD2
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField + BinomiallyExtendable<2>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn op_type(&self) -> NpoTypeId {
        NpoTypeId::open_input_d(self.circuit_d)
    }

    fn batch_instance_d1(
        &self,
        _config: &SC,
        packing: TablePacking,
        traces: &Traces<Val<SC>>,
    ) -> Option<BatchTableInstance<SC>> {
        let op_type = NpoTypeId::open_input_d(self.circuit_d);
        let trace = traces.non_primitive_trace::<OpenInputTrace<Val<SC>>>(&op_type)?;

        let rows = trace.rows.len();
        if rows == 0 {
            return None;
        }

        let min_height = packing.min_trace_height();
        let preprocessed = OpenInputAir::<Val<SC>, 1>::trace_to_preprocessed(trace);
        let generator = Val::<SC>::GENERATOR;
        let air = OpenInputAir::<Val<SC>, 1>::new_with_preprocessed(Val::<SC>::ZERO, preprocessed)
            .with_generator(generator)
            .with_min_height(min_height);
        let matrix = air.trace_to_matrix::<Val<SC>>(&trace.rows);
        let padded_rows = rows.next_power_of_two();

        Some(BatchTableInstance {
            op_type: NpoTypeId::open_input_d(self.circuit_d),
            air: DynamicAirEntry::new(Box::new(air)),
            trace: matrix,
            public_values: Vec::new(),
            rows: padded_rows,
        })
    }

    fn batch_instance_d2(
        &self,
        _config: &SC,
        packing: TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 2>>,
    ) -> Option<BatchTableInstance<SC>> {
        type EF2<F> = BinomialExtensionField<F, 2>;
        let op_type = NpoTypeId::open_input_d(self.circuit_d);
        let trace = traces.non_primitive_trace::<OpenInputTrace<EF2<Val<SC>>>>(&op_type)?;

        let rows = trace.rows.len();
        if rows == 0 {
            return None;
        }

        let min_height = packing.min_trace_height();
        let preprocessed = OpenInputAir::<Val<SC>, 2>::trace_to_preprocessed(trace);
        let w = <Val<SC> as BinomiallyExtendable<2>>::W;
        let generator = Val::<SC>::GENERATOR;
        let air = OpenInputAir::<Val<SC>, 2>::new_with_preprocessed(w, preprocessed)
            .with_generator(generator)
            .with_min_height(min_height);
        let matrix = air.trace_to_matrix::<EF2<Val<SC>>>(&trace.rows);
        let padded_rows = rows.next_power_of_two();

        Some(BatchTableInstance {
            op_type: NpoTypeId::open_input_d(self.circuit_d),
            air: DynamicAirEntry::new(Box::new(air)),
            trace: matrix,
            public_values: Vec::new(),
            rows: padded_rows,
        })
    }

    fn batch_instance_d2_with_committed_prep(
        &self,
        _config: &SC,
        packing: TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 2>>,
        committed_prep: Vec<Val<SC>>,
    ) -> Option<BatchTableInstance<SC>>
    where
        Val<SC>: BinomiallyExtendable<2>,
    {
        type EF2<F> = BinomialExtensionField<F, 2>;
        let op_type = NpoTypeId::open_input_d(self.circuit_d);
        let trace = traces.non_primitive_trace::<OpenInputTrace<EF2<Val<SC>>>>(&op_type)?;

        let rows = trace.rows.len();
        if rows == 0 {
            return None;
        }

        let min_height = packing.min_trace_height();
        let w = <Val<SC> as BinomiallyExtendable<2>>::W;
        let generator = Val::<SC>::GENERATOR;
        // Use committed preprocessed data directly, skipping trace_to_preprocessed.
        let air = OpenInputAir::<Val<SC>, 2>::new_with_preprocessed(w, committed_prep)
            .with_generator(generator)
            .with_min_height(min_height);
        let matrix = air.trace_to_matrix::<EF2<Val<SC>>>(&trace.rows);
        let padded_rows = rows.next_power_of_two();

        Some(BatchTableInstance {
            op_type: NpoTypeId::open_input_d(self.circuit_d),
            air: DynamicAirEntry::new(Box::new(air)),
            trace: matrix,
            public_values: Vec::new(),
            rows: padded_rows,
        })
    }

    fn batch_instance_d4(
        &self,
        _config: &SC,
        _packing: TablePacking,
        _traces: &Traces<BinomialExtensionField<Val<SC>, 4>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    fn batch_instance_d6(
        &self,
        _config: &SC,
        _packing: TablePacking,
        _traces: &Traces<BinomialExtensionField<Val<SC>, 6>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    fn batch_instance_d8(
        &self,
        _config: &SC,
        _packing: TablePacking,
        _traces: &Traces<BinomialExtensionField<Val<SC>, 8>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    fn batch_air_from_table_entry(
        &self,
        _config: &SC,
        _degree: usize,
        _table_entry: &NonPrimitiveTableEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String> {
        let generator = Val::<SC>::GENERATOR;
        match self.circuit_d {
            2 => {
                let w = <Val<SC> as BinomiallyExtendable<2>>::W;
                Ok(DynamicAirEntry::new(Box::new(
                    OpenInputAir::<Val<SC>, 2>::new(w).with_generator(generator),
                )))
            }
            _ => Ok(DynamicAirEntry::new(Box::new(
                OpenInputAir::<Val<SC>, 1>::new(Val::<SC>::ZERO).with_generator(generator),
            ))),
        }
    }

    fn air_with_committed_preprocessed(
        &self,
        committed_prep: Vec<Val<SC>>,
        min_height: usize,
    ) -> Option<DynamicAirEntry<SC>> {
        let generator = Val::<SC>::GENERATOR;
        match self.circuit_d {
            2 => {
                let w = <Val<SC> as BinomiallyExtendable<2>>::W;
                let air = OpenInputAir::<Val<SC>, 2>::new_with_preprocessed(w, committed_prep)
                    .with_generator(generator)
                    .with_min_height(min_height);
                Some(DynamicAirEntry::new(Box::new(air)))
            }
            _ => {
                let air = OpenInputAir::<Val<SC>, 1>::new_with_preprocessed(
                    Val::<SC>::ZERO,
                    committed_prep,
                )
                .with_generator(generator)
                .with_min_height(min_height);
                Some(DynamicAirEntry::new(Box::new(air)))
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Preprocessing: convert ext-field preprocessed data to base-field and
// fill in `ro_ext_mult` from `ext_reads`.
// ---------------------------------------------------------------------------

fn open_input_preprocess_for_prover<F, ExtF, const D: usize>(
    preprocessed: &mut PreprocessedColumns<ExtF>,
) -> Result<NonPrimitivePreprocessedMap<F>, CircuitError>
where
    F: StarkField + PrimeField64,
    ExtF: ExtensionField<F>,
{
    const PREP_WIDTH: usize = 10;
    // Column indices within each preprocessed row.
    const RO_INDEX_COL: usize = 5;
    const RO_EXT_MULT_COL: usize = 6;

    let mut non_primitive_base: NonPrimitivePreprocessedMap<F> = HashMap::new();

    for (op_type, prep) in preprocessed.non_primitive.iter() {
        if op_type != &NpoTypeId::open_input_d(D) {
            continue;
        }

        // Convert ExtF → F and fill ro_ext_mult in one pass, avoiding a second scan.
        let num_rows = prep.len() / PREP_WIDTH;
        let mut prep_base: Vec<F> = Vec::with_capacity(prep.len());
        for row_idx in 0..num_rows {
            let row_start = row_idx * PREP_WIDTH;
            for (col, val) in prep[row_start..row_start + PREP_WIDTH].iter().enumerate() {
                let base = val
                    .as_base()
                    .ok_or(CircuitError::InvalidPreprocessedValues)?;
                if col == RO_EXT_MULT_COL {
                    // Derive ro_ext_mult from the already-converted ro_index in the same row.
                    // ro_index was written to prep_base at position row_start + RO_INDEX_COL.
                    let ro_idx_val = prep_base[row_start + RO_INDEX_COL];
                    let ro_wid = (F::as_canonical_u64(&ro_idx_val) as usize) / D;
                    let mult = if ro_wid > 0 {
                        F::from_u32(preprocessed.ext_reads.get(ro_wid).copied().unwrap_or(0))
                    } else {
                        F::ZERO
                    };
                    prep_base.push(mult);
                } else {
                    prep_base.push(base);
                }
            }
        }

        non_primitive_base.insert(op_type.clone(), prep_base);
    }

    Ok(non_primitive_base)
}

/// Stateless plugin for OpenInput preprocessing.
#[derive(Clone, Default)]
pub struct OpenInputPreprocessor;

macro_rules! impl_open_input_preprocessor {
    ($F:ty, $D:literal) => {
        impl NpoPreprocessor<$F> for OpenInputPreprocessor {
            fn preprocess(
                &self,
                _circuit: &dyn Any,
                preprocessed: &mut dyn Any,
            ) -> Result<NonPrimitivePreprocessedMap<$F>, CircuitError> {
                if let Some(prep) = preprocessed.downcast_mut::<PreprocessedColumns<$F>>() {
                    return open_input_preprocess_for_prover::<$F, $F, 1>(prep);
                }
                if let Some(prep) = preprocessed
                    .downcast_mut::<PreprocessedColumns<BinomialExtensionField<$F, $D>>>()
                {
                    return open_input_preprocess_for_prover::<
                        $F,
                        BinomialExtensionField<$F, $D>,
                        $D,
                    >(prep);
                }
                Ok(NonPrimitivePreprocessedMap::new())
            }
        }
    };
}

impl_open_input_preprocessor!(p3_baby_bear::BabyBear, 4);
impl_open_input_preprocessor!(p3_koala_bear::KoalaBear, 4);
impl_open_input_preprocessor!(p3_goldilocks::Goldilocks, 2);

// ---------------------------------------------------------------------------
// AIR builder: construct OpenInputAir from committed preprocessed data.
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct OpenInputAirBuilderD4;

impl<SC> NpoAirBuilder<SC, 4> for OpenInputAirBuilderD4
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField + BinomiallyExtendable<4>,
    p3_uni_stark::SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<p3_uni_stark::SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn try_build(
        &self,
        op_type: &NpoTypeId,
        prep_base: &[Val<SC>],
        min_height: usize,
        _constraint_profile: ConstraintProfile,
    ) -> Option<(CircuitTableAir<SC, 4>, usize)> {
        if op_type != &NpoTypeId::open_input_d(4) {
            return None;
        }
        let w = <Val<SC> as BinomiallyExtendable<4>>::W;
        let generator = Val::<SC>::GENERATOR;
        let air = OpenInputAir::<Val<SC>, 4>::new_with_preprocessed(w, prep_base.to_vec())
            .with_generator(generator)
            .with_min_height(min_height);
        let num_rows = prep_base.len() / OpenInputAir::<Val<SC>, 4>::preprocessed_width();
        let degree = p3_util::log2_ceil_usize(
            num_rows
                .next_power_of_two()
                .max(min_height.next_power_of_two()),
        );
        Some((
            CircuitTableAir::Dynamic(DynamicAirEntry::new(Box::new(air))),
            degree,
        ))
    }
}

/// Builds an `OpenInputAir<F, 1>` (base-field proof traces) for use in circuits of any
/// extension degree. The `D` const parameter on `NpoAirBuilder` is the circuit's extension
/// degree; the proof's extension degree (always 1 here) is encoded in the `NpoTypeId`.
#[derive(Clone, Default)]
pub struct OpenInputAirBuilderD1;

macro_rules! impl_open_input_air_builder_d1 {
    ($circuit_d:literal) => {
        impl<SC> NpoAirBuilder<SC, $circuit_d> for OpenInputAirBuilderD1
        where
            SC: StarkGenericConfig + 'static + Send + Sync,
            Val<SC>: StarkField,
            p3_uni_stark::SymbolicExpressionExt<Val<SC>, SC::Challenge>:
                Algebra<p3_uni_stark::SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
        {
            fn try_build(
                &self,
                op_type: &NpoTypeId,
                prep_base: &[Val<SC>],
                min_height: usize,
                _constraint_profile: ConstraintProfile,
            ) -> Option<(CircuitTableAir<SC, $circuit_d>, usize)> {
                if op_type != &NpoTypeId::open_input_d(1) {
                    return None;
                }
                let generator = Val::<SC>::GENERATOR;
                let air = OpenInputAir::<Val<SC>, 1>::new_with_preprocessed(
                    Val::<SC>::ZERO,
                    prep_base.to_vec(),
                )
                .with_generator(generator)
                .with_min_height(min_height);
                let num_rows = prep_base.len() / OpenInputAir::<Val<SC>, 1>::preprocessed_width();
                let degree = p3_util::log2_ceil_usize(
                    num_rows
                        .next_power_of_two()
                        .max(min_height.next_power_of_two()),
                );
                Some((
                    CircuitTableAir::Dynamic(DynamicAirEntry::new(Box::new(air))),
                    degree,
                ))
            }
        }
    };
}

impl_open_input_air_builder_d1!(1);
impl_open_input_air_builder_d1!(2);
impl_open_input_air_builder_d1!(4);

/// Builds an `OpenInputAir<F, 2>` (D=2 proof traces) for use in D=2 circuits (e.g. Goldilocks).
#[derive(Clone, Default)]
pub struct OpenInputAirBuilderD2;

impl<SC> NpoAirBuilder<SC, 2> for OpenInputAirBuilderD2
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField + BinomiallyExtendable<2>,
    p3_uni_stark::SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<p3_uni_stark::SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn try_build(
        &self,
        op_type: &NpoTypeId,
        prep_base: &[Val<SC>],
        min_height: usize,
        _constraint_profile: ConstraintProfile,
    ) -> Option<(CircuitTableAir<SC, 2>, usize)> {
        if op_type != &NpoTypeId::open_input_d(2) {
            return None;
        }
        let w = <Val<SC> as BinomiallyExtendable<2>>::W;
        let generator = Val::<SC>::GENERATOR;
        let air = OpenInputAir::<Val<SC>, 2>::new_with_preprocessed(w, prep_base.to_vec())
            .with_generator(generator)
            .with_min_height(min_height);
        let num_rows = prep_base.len() / OpenInputAir::<Val<SC>, 2>::preprocessed_width();
        let degree = p3_util::log2_ceil_usize(
            num_rows
                .next_power_of_two()
                .max(min_height.next_power_of_two()),
        );
        Some((
            CircuitTableAir::Dynamic(DynamicAirEntry::new(Box::new(air))),
            degree,
        ))
    }
}
