//! Dynamic non-primitive table plugins for the batch prover.

use alloc::boxed::Box;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use p3_air::{Air, BaseAir};
use p3_batch_stark::{StarkGenericConfig, Val as BatchVal};
use p3_circuit::tables::Traces;
use p3_field::extension::BinomialExtensionField;
use p3_matrix::dense::RowMajorMatrix;
use p3_mmcs_air::air::{MmcsTableConfig, MmcsVerifyAir};
use p3_uni_stark::{ProverConstraintFolder, SymbolicAirBuilder, VerifierConstraintFolder};

use crate::config::StarkField;

/// Configuration for packing multiple primitive operations into a single AIR row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TablePacking {
    add_lanes: usize,
    mul_lanes: usize,
}

impl TablePacking {
    pub fn new(add_lanes: usize, mul_lanes: usize) -> Self {
        Self {
            add_lanes: add_lanes.max(1),
            mul_lanes: mul_lanes.max(1),
        }
    }

    pub fn from_counts(add_lanes: usize, mul_lanes: usize) -> Self {
        Self::new(add_lanes, mul_lanes)
    }

    pub const fn add_lanes(self) -> usize {
        self.add_lanes
    }

    pub const fn mul_lanes(self) -> usize {
        self.mul_lanes
    }
}

impl Default for TablePacking {
    fn default() -> Self {
        Self::new(1, 1)
    }
}

/// Manifest entry describing a dynamically dispatched non-primitive table inside a batch proof.
pub struct NonPrimitiveManifestEntry<SC>
where
    SC: StarkGenericConfig,
{
    /// Plugin identifier (must match `TableProver::id`).
    pub id: &'static str,
    /// Number of logical rows produced for this table.
    pub rows: usize,
    /// Public values exposed by this table (if any).
    pub public_values: Vec<BatchVal<SC>>,
    /// Opaque plugin-specific data required to rebuild AIRs during verification.
    pub data: Vec<u8>,
}

/// Type-erased AIR implementation for dynamically registered non-primitive tables.
pub struct DynamicAirEntry<SC>
where
    SC: StarkGenericConfig,
{
    air: Box<dyn BatchAir<SC>>,
}

impl<SC> DynamicAirEntry<SC>
where
    SC: StarkGenericConfig,
{
    pub fn new(inner: Box<dyn BatchAir<SC>>) -> Self {
        Self { air: inner }
    }

    pub fn air(&self) -> &dyn BatchAir<SC> {
        &*self.air
    }
}

/// Trait describing the behaviour of a dynamically dispatched AIR used in batched proofs.
pub trait BatchAir<SC>: Send + Sync
where
    SC: StarkGenericConfig,
{
    fn width(&self) -> usize;
    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<BatchVal<SC>>> {
        None
    }
    fn eval_symbolic(&self, builder: &mut SymbolicAirBuilder<BatchVal<SC>>);
    fn eval_prover(&self, builder: &mut ProverConstraintFolder<'_, SC>);
    fn eval_verifier(&self, builder: &mut VerifierConstraintFolder<'_, SC>);
}

/// Pre-packaged data for inserting a dynamic table instance into the batched prover.
pub struct BatchTableInstance<SC>
where
    SC: StarkGenericConfig,
{
    pub id: &'static str,
    pub air: DynamicAirEntry<SC>,
    pub trace: RowMajorMatrix<BatchVal<SC>>,
    pub public_values: Vec<BatchVal<SC>>,
    pub rows: usize,
    pub data: Vec<u8>,
}

#[inline(always)]
pub(crate) unsafe fn transmute_traces<FromEF, ToEF>(t: &Traces<FromEF>) -> &Traces<ToEF> {
    unsafe { &*(t as *const _ as *const Traces<ToEF>) }
}

/// Trait implemented by all non-primitive table plugins used by the batch prover.
pub trait TableProver<SC>: Send + Sync
where
    SC: StarkGenericConfig + 'static,
{
    /// Identifier for this prover.
    fn id(&self) -> &'static str;

    /// Produce a batched table instance for base-field traces.
    fn batch_instance_d1(
        &self,
        _cfg: &SC,
        _packing: TablePacking,
        _traces: &Traces<BatchVal<SC>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    /// Produce a batched table instance for degree-2 extension traces.
    fn batch_instance_d2(
        &self,
        _cfg: &SC,
        _packing: TablePacking,
        _traces: &Traces<BinomialExtensionField<BatchVal<SC>, 2>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    /// Produce a batched table instance for degree-4 extension traces.
    fn batch_instance_d4(
        &self,
        _cfg: &SC,
        _packing: TablePacking,
        _traces: &Traces<BinomialExtensionField<BatchVal<SC>, 4>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    /// Produce a batched table instance for degree-6 extension traces.
    fn batch_instance_d6(
        &self,
        _cfg: &SC,
        _packing: TablePacking,
        _traces: &Traces<BinomialExtensionField<BatchVal<SC>, 6>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    /// Produce a batched table instance for degree-8 extension traces.
    fn batch_instance_d8(
        &self,
        _cfg: &SC,
        _packing: TablePacking,
        _traces: &Traces<BinomialExtensionField<BatchVal<SC>, 8>>,
    ) -> Option<BatchTableInstance<SC>> {
        None
    }

    /// Rebuild the AIR for verification from the recorded manifest entry.
    fn batch_air_from_manifest(
        &self,
        _cfg: &SC,
        _degree: usize,
        _manifest: &NonPrimitiveManifestEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String> {
        Err(format!(
            "plugin {} does not support batch dispatch",
            self.id()
        ))
    }
}

#[macro_export]
macro_rules! impl_batch_table_instances_from_base {
    ($base:ident) => {
        fn batch_instance_d1(
            &self,
            cfg: &SC,
            packing: $crate::prover::TablePacking,
            traces: &p3_circuit::tables::Traces<p3_batch_stark::Val<SC>>,
        ) -> Option<$crate::prover::BatchTableInstance<SC>> {
            self.$base::<SC>(cfg, packing, traces)
        }

        fn batch_instance_d2(
            &self,
            cfg: &SC,
            packing: $crate::prover::TablePacking,
            traces: &p3_circuit::tables::Traces<
                p3_field::extension::BinomialExtensionField<p3_batch_stark::Val<SC>, 2>,
            >,
        ) -> Option<$crate::prover::BatchTableInstance<SC>> {
            let t: &p3_circuit::tables::Traces<p3_batch_stark::Val<SC>> =
                unsafe { $crate::prover::transmute_traces(traces) };
            self.$base::<SC>(cfg, packing, t)
        }

        fn batch_instance_d4(
            &self,
            cfg: &SC,
            packing: $crate::prover::TablePacking,
            traces: &p3_circuit::tables::Traces<
                p3_field::extension::BinomialExtensionField<p3_batch_stark::Val<SC>, 4>,
            >,
        ) -> Option<$crate::prover::BatchTableInstance<SC>> {
            let t: &p3_circuit::tables::Traces<p3_batch_stark::Val<SC>> =
                unsafe { $crate::prover::transmute_traces(traces) };
            self.$base::<SC>(cfg, packing, t)
        }

        fn batch_instance_d6(
            &self,
            cfg: &SC,
            packing: $crate::prover::TablePacking,
            traces: &p3_circuit::tables::Traces<
                p3_field::extension::BinomialExtensionField<p3_batch_stark::Val<SC>, 6>,
            >,
        ) -> Option<$crate::prover::BatchTableInstance<SC>> {
            let t: &p3_circuit::tables::Traces<p3_batch_stark::Val<SC>> =
                unsafe { $crate::prover::transmute_traces(traces) };
            self.$base::<SC>(cfg, packing, t)
        }

        fn batch_instance_d8(
            &self,
            cfg: &SC,
            packing: $crate::prover::TablePacking,
            traces: &p3_circuit::tables::Traces<
                p3_field::extension::BinomialExtensionField<p3_batch_stark::Val<SC>, 8>,
            >,
        ) -> Option<$crate::prover::BatchTableInstance<SC>> {
            let t: &p3_circuit::tables::Traces<p3_batch_stark::Val<SC>> =
                unsafe { $crate::prover::transmute_traces(traces) };
            self.$base::<SC>(cfg, packing, t)
        }
    };
}

/// MMCS prover plugin.
pub struct MmcsProver {
    pub config: MmcsTableConfig,
}

struct MmcsBatchAir<SC>
where
    SC: StarkGenericConfig,
{
    air: MmcsVerifyAir<BatchVal<SC>>,
}

impl<SC> BatchAir<SC> for MmcsBatchAir<SC>
where
    SC: StarkGenericConfig,
    BatchVal<SC>: StarkField,
{
    fn width(&self) -> usize {
        self.air.width()
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<BatchVal<SC>>> {
        self.air.preprocessed_trace()
    }

    fn eval_symbolic(&self, builder: &mut SymbolicAirBuilder<BatchVal<SC>>) {
        self.air.eval(builder);
    }

    fn eval_prover(&self, builder: &mut ProverConstraintFolder<'_, SC>) {
        self.air.eval(builder);
    }

    fn eval_verifier(&self, builder: &mut VerifierConstraintFolder<'_, SC>) {
        self.air.eval(builder);
    }
}

impl MmcsProver {
    fn batch_instance_base<SC>(
        &self,
        _cfg: &SC,
        _packing: TablePacking,
        traces: &Traces<BatchVal<SC>>,
    ) -> Option<BatchTableInstance<SC>>
    where
        SC: StarkGenericConfig + 'static,
        BatchVal<SC>: StarkField,
    {
        let t = &traces.mmcs_trace;
        if t.mmcs_paths.is_empty() {
            return None;
        }
        let rows: usize = t
            .mmcs_paths
            .iter()
            .map(|path| path.left_values.len() + 1)
            .sum();
        let matrix = MmcsVerifyAir::trace_to_matrix(&self.config, t);
        let air = DynamicAirEntry::new(Box::new(MmcsBatchAir::<SC> {
            air: MmcsVerifyAir::new(self.config),
        }));
        Some(BatchTableInstance {
            id: "mmcs_verify",
            air,
            trace: matrix,
            public_values: Vec::new(),
            rows,
            data: Vec::new(),
        })
    }
}

impl<SC> TableProver<SC> for MmcsProver
where
    SC: StarkGenericConfig + 'static,
    BatchVal<SC>: StarkField,
{
    fn id(&self) -> &'static str {
        "mmcs_verify"
    }

    impl_batch_table_instances_from_base!(batch_instance_base);

    fn batch_air_from_manifest(
        &self,
        _cfg: &SC,
        _degree: usize,
        _manifest: &NonPrimitiveManifestEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String> {
        Ok(DynamicAirEntry::new(Box::new(MmcsBatchAir::<SC> {
            air: MmcsVerifyAir::new(self.config),
        })))
    }
}
