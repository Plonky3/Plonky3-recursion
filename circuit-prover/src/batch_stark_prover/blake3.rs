//! Blake3 non-primitive table prover, AIR builder, and preprocessor.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::any::Any;

use p3_batch_stark::{StarkGenericConfig, Val};
use p3_circuit::ops::{Blake3Trace, NonPrimitivePreprocessedMap, NpoTypeId};
use p3_circuit::tables::Traces;
use p3_circuit::{CircuitError, PreprocessedColumns};
use p3_field::extension::{
    BinomialExtensionField, BinomiallyExtendable, QuinticTrinomialExtensionField,
};
use p3_field::{
    Algebra, BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField64,
};
use p3_lookup::LookupAir;
use p3_uni_stark::{SymbolicExpression, SymbolicExpressionExt};
use p3_util::log2_ceil_usize;

use super::NonPrimitiveTableEntry;
use super::dynamic_air::{BatchAir, BatchTableInstance, DynamicAirEntry, TableProver};
use super::packing::TablePacking;
use crate::air::blake3_air::{Blake3Air, extract_blake3_preprocessed, pad_blake3_padding_rows};
use crate::air::blake3_columns::BLAKE3_PREP_WIDTH;
use crate::common::{CircuitTableAir, NpoAirBuilder, NpoPreprocessor};
use crate::config::StarkField;
use crate::constraint_profile::ConstraintProfile;

#[cfg(debug_assertions)]
impl<SC, const D: usize> BatchAir<SC> for Blake3Air<Val<SC>, D>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
}

#[cfg(not(debug_assertions))]
impl<SC, const D: usize> BatchAir<SC> for Blake3Air<Val<SC>, D>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
}

// ---------------------------------------------------------------------------
// Blake3Prover — TableProver implementation
// ---------------------------------------------------------------------------

pub struct Blake3Prover;

unsafe impl Send for Blake3Prover {}
unsafe impl Sync for Blake3Prover {}

fn pad_ops(t: &Blake3Trace, padded_rows: usize) -> Vec<p3_circuit::ops::Blake3CircuitRow> {
    let mut padded_ops = t.operations.clone();
    pad_blake3_padding_rows(&mut padded_ops, padded_rows);
    padded_ops
}

fn make_air_entry_typed<SC, const D: usize>(
    preprocessed: Vec<Val<SC>>,
    min_height: usize,
) -> DynamicAirEntry<SC>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    let mut air = Blake3Air::<Val<SC>, D>::new_with_preprocessed(preprocessed, min_height);
    let _ = LookupAir::add_lookup_columns(&mut air);
    DynamicAirEntry::new(Box::new(air))
}

fn batch_instance_typed<SC, const D: usize>(
    t: &Blake3Trace,
    min_height: usize,
    witness_ctl_scale: u32,
) -> Option<BatchTableInstance<SC>>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    let rows = t.total_rows();
    let padded_rows = rows.next_power_of_two().max(min_height.next_power_of_two());
    let padded_ops = pad_ops(t, padded_rows);

    let preprocessed = extract_blake3_preprocessed::<Val<SC>>(&t.operations, witness_ctl_scale);
    let matrix = Blake3Air::<Val<SC>, D>::generate_trace_rows(&padded_ops, min_height);
    let air_entry = make_air_entry_typed::<SC, D>(preprocessed, min_height);

    Some(BatchTableInstance {
        op_type: NpoTypeId::blake3(),
        air: air_entry,
        trace: matrix,
        public_values: vec![Val::<SC>::ZERO; crate::air::blake3_air::BLAKE3_NUM_PUBLIC_VALUES],
        rows,
        lanes: 1,
    })
}

impl Blake3Prover {
    pub const fn new() -> Self {
        Self
    }

    fn blake3_op_type() -> NpoTypeId {
        NpoTypeId::blake3()
    }

    fn make_air_entry_dispatch<SC>(
        preprocessed: Vec<Val<SC>>,
        min_height: usize,
        circuit_extension_degree: u32,
    ) -> DynamicAirEntry<SC>
    where
        SC: StarkGenericConfig + 'static + Send + Sync,
        Val<SC>: StarkField + BinomiallyExtendable<4>,
        SymbolicExpressionExt<Val<SC>, SC::Challenge>:
            Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
    {
        match circuit_extension_degree {
            1 => make_air_entry_typed::<SC, 1>(preprocessed, min_height),
            _ => make_air_entry_typed::<SC, 4>(preprocessed, min_height),
        }
    }
}

impl<SC> TableProver<SC> for Blake3Prover
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField + BinomiallyExtendable<4>,
    SymbolicExpressionExt<Val<SC>, SC::Challenge>:
        Algebra<SymbolicExpression<Val<SC>>> + Algebra<SC::Challenge>,
{
    fn op_type(&self) -> NpoTypeId {
        Self::blake3_op_type()
    }

    fn batch_instance_d1(
        &self,
        _config: &SC,
        packing: &TablePacking,
        traces: &Traces<Val<SC>>,
    ) -> Option<BatchTableInstance<SC>> {
        let t = traces.non_primitive_trace::<Blake3Trace>(&Self::blake3_op_type())?;
        if t.total_rows() == 0 {
            return None;
        }
        let min_height = packing.min_trace_height();
        batch_instance_typed::<SC, 1>(t, min_height, 1)
    }

    fn batch_instance_d2(
        &self,
        _config: &SC,
        _packing: &TablePacking,
        _traces: &Traces<BinomialExtensionField<Val<SC>, 2>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    fn batch_instance_d4(
        &self,
        _config: &SC,
        packing: &TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 4>>,
    ) -> Option<BatchTableInstance<SC>> {
        let t = traces.non_primitive_trace::<Blake3Trace>(&Self::blake3_op_type())?;
        if t.total_rows() == 0 {
            return None;
        }
        let min_height = packing.min_trace_height();
        batch_instance_typed::<SC, 4>(t, min_height, 4)
    }

    fn batch_instance_d6(
        &self,
        _config: &SC,
        _packing: &TablePacking,
        _traces: &Traces<BinomialExtensionField<Val<SC>, 6>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    fn batch_instance_d8(
        &self,
        _config: &SC,
        _packing: &TablePacking,
        _traces: &Traces<BinomialExtensionField<Val<SC>, 8>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    fn batch_instance_d5(
        &self,
        _config: &SC,
        _packing: &TablePacking,
        _traces: &Traces<QuinticTrinomialExtensionField<Val<SC>>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    fn batch_air_from_table_entry(
        &self,
        _config: &SC,
        _degree: usize,
        circuit_extension_degree: u32,
        _table_entry: &NonPrimitiveTableEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String> {
        Ok(Self::make_air_entry_dispatch(
            Vec::new(),
            1,
            circuit_extension_degree,
        ))
    }

    fn air_with_committed_preprocessed(
        &self,
        committed_prep: Vec<Val<SC>>,
        min_height: usize,
        _lanes: usize,
        circuit_extension_degree: u32,
    ) -> Option<DynamicAirEntry<SC>> {
        Some(Self::make_air_entry_dispatch(
            committed_prep,
            min_height,
            circuit_extension_degree,
        ))
    }
}

// ---------------------------------------------------------------------------
// Blake3AirBuilder — NpoAirBuilder implementation
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct Blake3AirBuilder<const D: usize>;

impl<SC> NpoAirBuilder<SC, 4> for Blake3AirBuilder<4>
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField + BinomiallyExtendable<4>,
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
    ) -> Option<(CircuitTableAir<SC, 4>, usize)> {
        if op_type.as_str() != "blake3" {
            return None;
        }
        let mut air =
            Blake3Air::<Val<SC>, 4>::new_with_preprocessed(prep_base.to_vec(), min_height);
        let _ = LookupAir::add_lookup_columns(&mut air);
        let wrapper = DynamicAirEntry::new(Box::new(air));

        let num_rows = if prep_base.is_empty() {
            0
        } else {
            prep_base.len().div_ceil(BLAKE3_PREP_WIDTH)
        };
        let degree = log2_ceil_usize(
            num_rows
                .next_power_of_two()
                .max(min_height.next_power_of_two()),
        );
        Some((CircuitTableAir::Dynamic(wrapper), degree))
    }
}

impl<SC> NpoAirBuilder<SC, 1> for Blake3AirBuilder<1>
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
    ) -> Option<(CircuitTableAir<SC, 1>, usize)> {
        if op_type.as_str() != "blake3" {
            return None;
        }
        let mut air =
            Blake3Air::<Val<SC>, 1>::new_with_preprocessed(prep_base.to_vec(), min_height);
        let _ = LookupAir::add_lookup_columns(&mut air);
        let wrapper = DynamicAirEntry::new(Box::new(air));

        let num_rows = if prep_base.is_empty() {
            0
        } else {
            prep_base.len().div_ceil(BLAKE3_PREP_WIDTH)
        };
        let degree = log2_ceil_usize(
            num_rows
                .next_power_of_two()
                .max(min_height.next_power_of_two()),
        );
        Some((CircuitTableAir::Dynamic(wrapper), degree))
    }
}

// ---------------------------------------------------------------------------
// Blake3Preprocessor — NpoPreprocessor implementation
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
pub struct Blake3Preprocessor;

impl<F> NpoPreprocessor<F> for Blake3Preprocessor
where
    F: StarkField + PrimeField64 + BinomiallyExtendable<4>,
{
    fn preprocess(
        &self,
        _circuit: &dyn Any,
        preprocessed: &mut dyn Any,
    ) -> Result<NonPrimitivePreprocessedMap<F>, CircuitError> {
        macro_rules! try_preprocess {
            ($ext:ty, $d:expr) => {
                if let Some(prep) = preprocessed.downcast_mut::<PreprocessedColumns<$ext, $d>>() {
                    return blake3_preprocess_for_prover::<F, $ext, $d>(prep);
                }
            };
        }

        try_preprocess!(F, 1);

        {
            type Ext4<F> = BinomialExtensionField<F, 4>;
            if let Some(prep) = preprocessed.downcast_mut::<PreprocessedColumns<Ext4<F>, 4>>() {
                return blake3_preprocess_for_prover::<F, Ext4<F>, 4>(prep);
            }
        }

        Ok(NonPrimitivePreprocessedMap::new())
    }
}

fn blake3_preprocess_for_prover<F, ExtF, const D: usize>(
    preprocessed: &mut PreprocessedColumns<ExtF, D>,
) -> Result<NonPrimitivePreprocessedMap<F>, CircuitError>
where
    F: StarkField + PrimeField64,
    ExtF: ExtensionField<F>,
{
    let op_type = NpoTypeId::blake3();
    let mut result = NonPrimitivePreprocessedMap::new();

    let prep = match preprocessed.non_primitive.get(&op_type) {
        Some(p) => p,
        None => return Ok(result),
    };

    if prep.is_empty() {
        return Ok(result);
    }

    let prep_base: Vec<F> = prep
        .iter()
        .map(|v| v.as_base().ok_or(CircuitError::InvalidPreprocessedValues))
        .collect::<Result<Vec<_>, CircuitError>>()?;

    // Each row has 32 values: 16 output indices + 16 CTL flags.
    let raw_row_width = 32;
    if prep_base.len() % raw_row_width != 0 {
        panic!(
            "blake3_preprocess_for_prover: prep_base.len()={} not divisible by raw_row_width={}",
            prep_base.len(),
            raw_row_width
        );
    }

    let num_rows = prep_base.len() / raw_row_width;
    let neg_one = F::NEG_ONE;
    let dup_wids = preprocessed.dup_npo_outputs.get(&op_type);

    let mut out_prep: Vec<F> = Vec::with_capacity(num_rows * BLAKE3_PREP_WIDTH);

    for i in 0..num_rows {
        let base = i * raw_row_width;
        // Raw layout: [out_idx[0..16], ctl_flag[0..16]]
        // Blake3PrepCols layout: [out_idx[0..16], out_mult[0..16]] (grouped)

        // First: all 16 output indices
        for limb in 0..16 {
            out_prep.push(prep_base[base + limb]);
        }

        // Then: all 16 multiplicities (derived from CTL flags)
        for limb in 0..16 {
            let out_idx = prep_base[base + limb];
            let ctl_flag = prep_base[base + 16 + limb];

            if ctl_flag != F::ZERO {
                let out_wid = (F::as_canonical_u64(&out_idx) as usize) / D;
                let is_dup = dup_wids
                    .and_then(|d| d.get(out_wid).copied())
                    .unwrap_or(false);
                if is_dup {
                    out_prep.push(neg_one);
                } else {
                    let n_reads = preprocessed.ext_reads.get(out_wid).copied().unwrap_or(0);
                    out_prep.push(F::from_u32(n_reads));
                }
            } else {
                out_prep.push(F::ZERO);
            }
        }
    }

    result.insert(op_type, out_prep);
    Ok(result)
}
