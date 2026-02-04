//! Table prover trait and supporting types for non-primitive tables.

use alloc::string::String;
use alloc::vec::Vec;

use p3_batch_stark::{StarkGenericConfig, Val};
use p3_circuit::op::NonPrimitiveOpType;
use p3_circuit::tables::Traces;
use p3_field::extension::BinomialExtensionField;
use p3_matrix::dense::RowMajorMatrix;

use super::NonPrimitiveTableEntry;
use super::dynamic_air::DynamicAirEntry;
use super::packing::TablePacking;

/// Data needed to insert a dynamic table instance into the batched prover.
///
/// A `BatchTableInstance` bundles everything the batch prover needs from a
/// non-primitive table plugin: the AIR, its populated trace matrix, any
/// public values it exposes, and the number of rows it produces.
pub struct BatchTableInstance<SC>
where
    SC: StarkGenericConfig,
{
    /// Operation type (it should match `TableProver::op_type`).
    pub op_type: NonPrimitiveOpType,
    /// The AIR implementation for this table.
    pub air: DynamicAirEntry<SC>,
    /// The populated trace matrix for this table.
    pub trace: RowMajorMatrix<Val<SC>>,
    /// Public values exposed by this table.
    pub public_values: Vec<Val<SC>>,
    /// Number of rows produced for this table.
    pub rows: usize,
}

#[inline(always)]
/// # Safety
///
/// Caller must ensure that both `Traces<FromEF>` and `Traces<ToEF>` share an
/// identical in-memory representation.
pub unsafe fn transmute_traces<FromEF, ToEF>(t: &Traces<FromEF>) -> &Traces<ToEF> {
    debug_assert_eq!(
        core::mem::size_of::<Traces<FromEF>>(),
        core::mem::size_of::<Traces<ToEF>>()
    );
    debug_assert_eq!(
        core::mem::align_of::<Traces<FromEF>>(),
        core::mem::align_of::<Traces<ToEF>>()
    );

    unsafe { &*(t as *const _ as *const Traces<ToEF>) }
}

/// Trait implemented by all non-primitive table plugins used by the batch prover.
///
/// Implementors would typically delegate to an existing AIR type, define a base case
/// for base-field traces, and then use the [`impl_table_prover_batch_instances_from_base!`]
/// macro to generate the degree-specific implementations.
///
/// ```ignore
/// impl<SC> TableProver<SC> for MyPlugin {
///     fn op_type(&self) -> NonPrimitiveOpType {
///         NonPrimitiveOpType::Poseidon2Perm(Poseidon2Config::BabyBearD4Width16)
///     }
///
///     impl_table_prover_batch_instances_from_base!(batch_instance_base);
/// }
/// ```
pub trait TableProver<SC>: Send + Sync
where
    SC: StarkGenericConfig + 'static,
{
    /// Operation type for this prover.
    fn op_type(&self) -> NonPrimitiveOpType;

    /// Produce a batched table instance for base-field traces.
    fn batch_instance_d1(
        &self,
        config: &SC,
        packing: TablePacking,
        traces: &Traces<Val<SC>>,
    ) -> Option<BatchTableInstance<SC>>;

    /// Produce a batched table instance for degree-2 extension traces.
    fn batch_instance_d2(
        &self,
        config: &SC,
        packing: TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 2>>,
    ) -> Option<BatchTableInstance<SC>>;

    /// Produce a batched table instance for degree-4 extension traces.
    fn batch_instance_d4(
        &self,
        config: &SC,
        packing: TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 4>>,
    ) -> Option<BatchTableInstance<SC>>;

    /// Produce a batched table instance for degree-6 extension traces.
    fn batch_instance_d6(
        &self,
        config: &SC,
        packing: TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 6>>,
    ) -> Option<BatchTableInstance<SC>>;

    /// Produce a batched table instance for degree-8 extension traces.
    fn batch_instance_d8(
        &self,
        config: &SC,
        packing: TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 8>>,
    ) -> Option<BatchTableInstance<SC>>;

    /// Rebuild the AIR for verification from the recorded non-primitive table entry.
    fn batch_air_from_table_entry(
        &self,
        config: &SC,
        degree: usize,
        table_entry: &NonPrimitiveTableEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String>;
}

/// Convenience macro for deriving all degree-specific helpers from a single base
/// implementation.
///
/// Plugins usually implement a single `batch_instance_base` method that operates on
/// base-field traces. This macro reuses that method to provide the `batch_instance_d*`
/// variants by casting higher-degree traces back to the base field.
///
/// Users can invoke it inside their `TableProver` impl:
///
/// ```ignore
/// impl<SC> TableProver<SC> for MyPlugin {
///     fn op_type(&self) -> NonPrimitiveOpType {
///         NonPrimitiveOpType::Poseidon2Perm(Poseidon2Config::BabyBearD4Width16)
///     }
///
///     impl_table_prover_batch_instances_from_base!(batch_instance_base);
///
///     fn batch_air_from_table_entry(
///         &self,
///         config: &SC,
///         degree: usize,
///         table_entry: &NonPrimitiveTableEntry<SC>,
///     ) -> Result<DynamicAirEntry<SC>, String> {
///         Ok(DynamicAirEntry::new(Box::new(MyPluginAir::<Val<SC>>::new(config))))
///     }
/// }
/// ```
#[macro_export]
macro_rules! impl_table_prover_batch_instances_from_base {
    ($base:ident) => {
        fn batch_instance_d1(
            &self,
            config: &SC,
            packing: $crate::batch_stark::TablePacking,
            traces: &p3_circuit::tables::Traces<p3_batch_stark::Val<SC>>,
        ) -> Option<$crate::batch_stark::BatchTableInstance<SC>> {
            self.$base::<SC>(config, packing, traces)
        }

        fn batch_instance_d2(
            &self,
            config: &SC,
            packing: $crate::batch_stark::TablePacking,
            traces: &p3_circuit::tables::Traces<
                p3_field::extension::BinomialExtensionField<p3_batch_stark::Val<SC>, 2>,
            >,
        ) -> Option<$crate::batch_stark::BatchTableInstance<SC>> {
            let t: &p3_circuit::tables::Traces<p3_batch_stark::Val<SC>> =
                unsafe { $crate::batch_stark::transmute_traces(traces) };
            self.$base::<SC>(config, packing, t)
        }

        fn batch_instance_d4(
            &self,
            config: &SC,
            packing: $crate::batch_stark::TablePacking,
            traces: &p3_circuit::tables::Traces<
                p3_field::extension::BinomialExtensionField<p3_batch_stark::Val<SC>, 4>,
            >,
        ) -> Option<$crate::batch_stark::BatchTableInstance<SC>> {
            let t: &p3_circuit::tables::Traces<p3_batch_stark::Val<SC>> =
                unsafe { $crate::batch_stark::transmute_traces(traces) };
            self.$base::<SC>(config, packing, t)
        }

        fn batch_instance_d6(
            &self,
            config: &SC,
            packing: $crate::batch_stark::TablePacking,
            traces: &p3_circuit::tables::Traces<
                p3_field::extension::BinomialExtensionField<p3_batch_stark::Val<SC>, 6>,
            >,
        ) -> Option<$crate::batch_stark::BatchTableInstance<SC>> {
            let t: &p3_circuit::tables::Traces<p3_batch_stark::Val<SC>> =
                unsafe { $crate::batch_stark::transmute_traces(traces) };
            self.$base::<SC>(config, packing, t)
        }

        fn batch_instance_d8(
            &self,
            config: &SC,
            packing: $crate::batch_stark::TablePacking,
            traces: &p3_circuit::tables::Traces<
                p3_field::extension::BinomialExtensionField<p3_batch_stark::Val<SC>, 8>,
            >,
        ) -> Option<$crate::batch_stark::BatchTableInstance<SC>> {
            let t: &p3_circuit::tables::Traces<p3_batch_stark::Val<SC>> =
                unsafe { $crate::batch_stark::transmute_traces(traces) };
            self.$base::<SC>(config, packing, t)
        }
    };
}
