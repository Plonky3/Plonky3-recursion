use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;

use p3_air::{Air, AirBuilder, BaseAir};
#[cfg(debug_assertions)]
use p3_batch_stark::DebugConstraintBuilderWithLookups;
use p3_batch_stark::{StarkGenericConfig, Val};
use p3_circuit::op::NonPrimitiveOpType;
use p3_circuit::tables::Traces;
use p3_field::PrimeField;
use p3_field::extension::BinomialExtensionField;
use p3_lookup::folder::{ProverConstraintFolderWithLookups, VerifierConstraintFolderWithLookups};
use p3_lookup::lookup_traits::Lookup;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{SymbolicAirBuilder, SymbolicExpression};

use super::TablePacking;

/// Type-erased AIR implementation for dynamically registered non-primitive tables.
///
/// This allows the batch prover to mix primitive AIRs with plugin AIRs in a single heterogeneous
/// batch.
/// Internally,`DynamicAirEntry` wraps the boxed plugin AIR and exposes a shared accessor
/// so that both prover and verifier can operate without knowing the concrete underlying type.
pub struct DynamicAirEntry<SC>
where
    SC: StarkGenericConfig,
{
    air: Box<dyn CloneableBatchAir<SC>>,
}

impl<SC> DynamicAirEntry<SC>
where
    SC: StarkGenericConfig,
{
    pub fn new(inner: Box<dyn CloneableBatchAir<SC>>) -> Self {
        Self { air: inner }
    }

    pub fn air(&self) -> &dyn CloneableBatchAir<SC> {
        &*self.air
    }

    pub fn air_mut(&mut self) -> &mut dyn CloneableBatchAir<SC> {
        &mut *self.air
    }
}

impl<SC> Clone for DynamicAirEntry<SC>
where
    SC: StarkGenericConfig,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    fn clone(&self) -> Self {
        Self {
            air: self.air.clone_box(),
        }
    }
}

impl<SC> BaseAir<Val<SC>> for DynamicAirEntry<SC>
where
    SC: StarkGenericConfig,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    fn width(&self) -> usize {
        <dyn CloneableBatchAir<SC> as BaseAir<Val<SC>>>::width(self.air())
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val<SC>>> {
        <dyn CloneableBatchAir<SC> as BaseAir<Val<SC>>>::preprocessed_trace(self.air())
    }
}

macro_rules! impl_air_for_dynamic_entry {
    (
        $(#[$cfg:meta])?
        $lt:lifetime,
        $builder:ty,
        $eval_method:ident,
        $add_lookup_method:ident,
        $get_lookup_method:ident
    ) => {
        $(#[$cfg])?
        impl<$lt, SC> Air<$builder> for DynamicAirEntry<SC>
        where
            SC: StarkGenericConfig,
            Val<SC>: PrimeField,
            SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
        {
            fn eval(&self, builder: &mut $builder) {
                self.air().$eval_method(builder);
            }

            fn add_lookup_columns(&mut self) -> Vec<usize> {
                self.air_mut().$add_lookup_method()
            }

            fn get_lookups(
                &mut self,
            ) -> Vec<Lookup<<$builder as AirBuilder>::F>> {
                self.air_mut().$get_lookup_method()
            }
        }
    };
    (
        $(#[$cfg:meta])?
        $builder:ty,
        $eval_method:ident,
        $add_lookup_method:ident,
        $get_lookup_method:ident
    ) => {
        $(#[$cfg])?
        impl<SC> Air<$builder> for DynamicAirEntry<SC>
        where
            SC: StarkGenericConfig,
            Val<SC>: PrimeField,
            SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
        {
            fn eval(&self, builder: &mut $builder) {
                self.air().$eval_method(builder);
            }

            fn add_lookup_columns(&mut self) -> Vec<usize> {
                self.air_mut().$add_lookup_method()
            }

            fn get_lookups(
                &mut self,
            ) -> Vec<Lookup<<$builder as AirBuilder>::F>> {
                self.air_mut().$get_lookup_method()
            }
        }
    };
}

impl_air_for_dynamic_entry!(
    SymbolicAirBuilder<Val<SC>, SC::Challenge>,
    eval_symbolic,
    add_lookup_columns_symbolic,
    get_lookups_symbolic
);

#[cfg(debug_assertions)]
impl_air_for_dynamic_entry!(
    'a,
    DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>,
    eval_debug,
    add_lookup_columns_debug,
    get_lookups_debug
);

impl_air_for_dynamic_entry!(
    'a,
    ProverConstraintFolderWithLookups<'a, SC>,
    eval_prover,
    add_lookup_columns_prover,
    get_lookups_prover
);

impl_air_for_dynamic_entry!(
    'a,
    VerifierConstraintFolderWithLookups<'a, SC>,
    eval_verifier,
    add_lookup_columns_verifier,
    get_lookups_verifier
);

/// Simple super trait of [`Air`] describing the behaviour of a non-primitive
/// dynamically dispatched AIR used in batched proofs.
#[cfg(debug_assertions)]
pub trait BatchAir<SC>:
    BaseAir<Val<SC>>
    + Air<SymbolicAirBuilder<Val<SC>, SC::Challenge>>
    + for<'a> Air<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>
    + for<'a> Air<ProverConstraintFolderWithLookups<'a, SC>>
    + for<'a> Air<VerifierConstraintFolderWithLookups<'a, SC>>
    + Send
    + Sync
where
    SC: StarkGenericConfig,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
}

#[cfg(not(debug_assertions))]
pub trait BatchAir<SC>:
    BaseAir<Val<SC>>
    + Air<SymbolicAirBuilder<Val<SC>, SC::Challenge>>
    + for<'a> Air<ProverConstraintFolderWithLookups<'a, SC>>
    + for<'a> Air<VerifierConstraintFolderWithLookups<'a, SC>>
    + Send
    + Sync
where
    SC: StarkGenericConfig,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
}

macro_rules! impl_cloneable_batch_air_forwarding {
    (
        $(#[$cfg:meta])?
        $lt:lifetime,
        $builder:ty,
        $eval_method:ident,
        $add_lookup_method:ident,
        $get_lookup_method:ident
    ) => {
        $(#[$cfg])?
        fn $eval_method<$lt>(&self, builder: &mut $builder) {
            <T as Air<$builder>>::eval(self, builder);
        }

        $(#[$cfg])?
        fn $add_lookup_method<$lt>(&mut self) -> Vec<usize> {
            <T as Air<$builder>>::add_lookup_columns(self)
        }

        $(#[$cfg])?
        fn $get_lookup_method<$lt>(&mut self) -> Vec<Lookup<Val<SC>>> {
            <T as Air<$builder>>::get_lookups(self)
        }
    };
    (
        $(#[$cfg:meta])?
        $builder:ty,
        $eval_method:ident,
        $add_lookup_method:ident,
        $get_lookup_method:ident
    ) => {
        $(#[$cfg])?
        fn $eval_method(&self, builder: &mut $builder) {
            <T as Air<$builder>>::eval(self, builder);
        }

        $(#[$cfg])?
        fn $add_lookup_method(&mut self) -> Vec<usize> {
            <T as Air<$builder>>::add_lookup_columns(self)
        }

        $(#[$cfg])?
        fn $get_lookup_method(&mut self) -> Vec<Lookup<Val<SC>>> {
            <T as Air<$builder>>::get_lookups(self)
        }
    };
}

pub trait CloneableBatchAir<SC>: BaseAir<Val<SC>> + Send + Sync
where
    SC: StarkGenericConfig,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    fn clone_box(&self) -> Box<dyn CloneableBatchAir<SC>>;

    #[cfg(debug_assertions)]
    fn eval_debug<'a>(
        &self,
        builder: &mut DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>,
    );
    fn eval_symbolic(&self, builder: &mut SymbolicAirBuilder<Val<SC>, SC::Challenge>);
    fn eval_prover<'a>(&self, builder: &mut ProverConstraintFolderWithLookups<'a, SC>);
    fn eval_verifier<'a>(&self, builder: &mut VerifierConstraintFolderWithLookups<'a, SC>);

    #[cfg(debug_assertions)]
    fn add_lookup_columns_debug(&mut self) -> Vec<usize>;
    fn add_lookup_columns_symbolic(&mut self) -> Vec<usize>;
    fn add_lookup_columns_prover(&mut self) -> Vec<usize>;
    fn add_lookup_columns_verifier(&mut self) -> Vec<usize>;

    #[cfg(debug_assertions)]
    fn get_lookups_debug(&mut self) -> Vec<Lookup<Val<SC>>>;
    fn get_lookups_symbolic(&mut self) -> Vec<Lookup<Val<SC>>>;
    fn get_lookups_prover(&mut self) -> Vec<Lookup<Val<SC>>>;
    fn get_lookups_verifier(&mut self) -> Vec<Lookup<Val<SC>>>;
}

impl<SC, T> CloneableBatchAir<SC> for T
where
    SC: StarkGenericConfig,
    T: BatchAir<SC> + Clone + 'static,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    fn clone_box(&self) -> Box<dyn CloneableBatchAir<SC>> {
        Box::new(self.clone())
    }

    impl_cloneable_batch_air_forwarding!(
        SymbolicAirBuilder<Val<SC>, SC::Challenge>,
        eval_symbolic,
        add_lookup_columns_symbolic,
        get_lookups_symbolic
    );

    #[cfg(debug_assertions)]
    impl_cloneable_batch_air_forwarding!(
        'a,
        DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>,
        eval_debug,
        add_lookup_columns_debug,
        get_lookups_debug
    );

    impl_cloneable_batch_air_forwarding!(
        'a,
        ProverConstraintFolderWithLookups<'a, SC>,
        eval_prover,
        add_lookup_columns_prover,
        get_lookups_prover
    );

    impl_cloneable_batch_air_forwarding!(
        'a,
        VerifierConstraintFolderWithLookups<'a, SC>,
        eval_verifier,
        add_lookup_columns_verifier,
        get_lookups_verifier
    );
}

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
pub(crate) unsafe fn transmute_traces<FromEF, ToEF>(t: &Traces<FromEF>) -> &Traces<ToEF> {
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
        table_entry: &super::NonPrimitiveTableEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String>;
}
