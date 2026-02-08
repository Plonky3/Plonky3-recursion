//! Batch STARK prover and verifier that unifies all circuit tables
//! into a single batched STARK proof using `p3-batch-stark`.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::borrow::Borrow;
use core::mem::transmute;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_baby_bear::{BabyBear, GenericPoseidon2LinearLayersBabyBear};
#[cfg(debug_assertions)]
use p3_batch_stark::DebugConstraintBuilderWithLookups;
use p3_batch_stark::{BatchProof, CommonData, ProverData, StarkGenericConfig, StarkInstance, Val};
use p3_circuit::PreprocessedColumns;
use p3_circuit::op::{NonPrimitiveOpType, Poseidon2Config, PrimitiveOpType};
use p3_circuit::ops::{Poseidon2CircuitRow, Poseidon2Params, Poseidon2Trace};
use p3_circuit::tables::Traces;
use p3_field::extension::{BinomialExtensionField, BinomiallyExtendable};
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField};
use p3_koala_bear::{GenericPoseidon2LinearLayersKoalaBear, KoalaBear};
use p3_lookup::folder::{ProverConstraintFolderWithLookups, VerifierConstraintFolderWithLookups};
use p3_lookup::lookup_traits::Lookup;
use p3_matrix::Matrix;
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::RoundConstants;
use p3_poseidon2_circuit_air::{
    BabyBearD4Width16, BabyBearD4Width24, KoalaBearD4Width16, KoalaBearD4Width24,
    Poseidon2CircuitAir, Poseidon2CircuitAirBabyBearD4Width16,
    Poseidon2CircuitAirBabyBearD4Width24, Poseidon2CircuitAirKoalaBearD4Width16,
    Poseidon2CircuitAirKoalaBearD4Width24, eval_unchecked, extract_preprocessed_from_operations,
};
use p3_uni_stark::{
    ProverConstraintFolder, SymbolicAirBuilder, SymbolicExpression, VerifierConstraintFolder,
};
use thiserror::Error;
use tracing::instrument;

use crate::air::{AddAir, ConstAir, MulAir, PublicAir, WitnessAir};
use crate::common::CircuitTableAir;
use crate::config::StarkField;
use crate::field_params::ExtractBinomialW;

/// Pad a trace matrix to at least `min_height` rows.
/// The height is always rounded up to a power of two.
fn pad_matrix_to_min_height<F: Field>(
    mut matrix: RowMajorMatrix<F>,
    min_height: usize,
) -> RowMajorMatrix<F> {
    let current_height = matrix.height();
    // Target height is max of current power-of-two and min_height
    let target_height = current_height
        .next_power_of_two()
        .max(min_height.next_power_of_two());

    if current_height < target_height {
        // Pad with zeros to reach target height
        let width = matrix.width();
        let padding_rows = target_height - current_height;
        matrix
            .values
            .extend(core::iter::repeat(F::ZERO).take(padding_rows * width));
    }
    matrix
}

/// Configuration for packing multiple primitive operations into a single AIR row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TablePacking {
    witness_lanes: usize,
    public_lanes: usize,
    add_lanes: usize,
    mul_lanes: usize,
    /// Minimum trace height for all tables (must be power of two).
    /// This is required for FRI with higher `log_final_poly_len`.
    /// FRI requires: log_trace_height > log_final_poly_len + log_blowup
    /// So min_trace_height should be >= 2^(log_final_poly_len + log_blowup + 1)
    min_trace_height: usize,
}

impl TablePacking {
    pub fn new(
        witness_lanes: usize,
        public_lanes: usize,
        add_lanes: usize,
        mul_lanes: usize,
    ) -> Self {
        Self {
            witness_lanes: witness_lanes.max(1),
            public_lanes: public_lanes.max(1),
            add_lanes: add_lanes.max(1),
            mul_lanes: mul_lanes.max(1),
            min_trace_height: 1,
        }
    }

    /// Create TablePacking with a minimum trace height requirement.
    ///
    /// Use this when FRI parameters have `log_final_poly_len > 0`.
    /// The minimum trace height must satisfy: `min_trace_height > 2^(log_final_poly_len + log_blowup)`
    ///
    /// For example, with `log_final_poly_len = 3` and `log_blowup = 1`:
    /// - Required: `min_trace_height > 2^(3+1) = 16`
    /// - So use `min_trace_height = 32` (next power of two)
    pub fn with_min_trace_height(mut self, min_trace_height: usize) -> Self {
        // Ensure min_trace_height is a power of two and at least 1
        self.min_trace_height = min_trace_height.next_power_of_two().max(1);
        self
    }

    /// Create TablePacking with minimum height derived from FRI parameters.
    ///
    /// This automatically calculates the minimum trace height from `log_final_poly_len` and `log_blowup`.
    pub fn with_fri_params(mut self, log_final_poly_len: usize, log_blowup: usize) -> Self {
        // FRI requires: log_min_height > log_final_poly_len + log_blowup
        // So min_height must be >= 2^(log_final_poly_len + log_blowup + 1)
        let min_log_height = log_final_poly_len + log_blowup + 1;
        self.min_trace_height = 1usize << min_log_height;
        self
    }

    pub fn from_counts(
        witness_lanes: usize,
        public_lanes: usize,
        add_lanes: usize,
        mul_lanes: usize,
    ) -> Self {
        Self::new(witness_lanes, public_lanes, add_lanes, mul_lanes)
    }

    pub const fn witness_lanes(self) -> usize {
        self.witness_lanes
    }

    pub const fn public_lanes(self) -> usize {
        self.public_lanes
    }

    pub const fn add_lanes(self) -> usize {
        self.add_lanes
    }

    pub const fn mul_lanes(self) -> usize {
        self.mul_lanes
    }

    pub const fn min_trace_height(self) -> usize {
        self.min_trace_height
    }
}

impl Default for TablePacking {
    fn default() -> Self {
        Self::new(1, 1, 1, 1)
    }
}

/// Summary of trace lengths for all circuit tables.
#[derive(Debug, Clone)]
pub struct TraceLengths {
    pub witness: usize,
    pub const_: usize,
    pub public: usize,
    pub add: usize,
    pub mul: usize,
    pub non_primitive: Vec<(NonPrimitiveOpType, usize)>,
}

impl TraceLengths {
    /// Compute trace lengths from traces and packing configuration.
    pub fn from_traces<F>(traces: &Traces<F>, packing: TablePacking) -> Self {
        Self {
            witness: traces.witness_trace.num_rows() / packing.witness_lanes(),
            const_: traces.const_trace.values.len(),
            public: traces.public_trace.values.len() / packing.public_lanes(),
            add: traces.add_trace.lhs_values.len() / packing.add_lanes(),
            mul: traces.mul_trace.lhs_values.len() / packing.mul_lanes(),
            non_primitive: traces
                .non_primitive_traces
                .iter()
                .map(|(&op, t)| (op, t.rows()))
                .collect(),
        }
    }

    /// Log all trace lengths at info level.
    pub fn log(&self) {
        tracing::info!(
            witness = %self.witness,
            const_ = %self.const_,
            public = %self.public,
            add = %self.add,
            mul = %self.mul,
            "Primitive trace lengths"
        );
        for (op, rows) in &self.non_primitive {
            tracing::info!(?op, rows, "Non-primitive trace");
        }
    }
}

/// Metadata describing a non-primitive table inside a batch proof.
///
/// Every non-primitive dynamic plugin produces exactly one `NonPrimitiveTableEntry`
/// per batch instance. The entry is stored inside a `BatchStarkProof` and later provided
/// back to the plugin during verification through
/// [`TableProver::batch_air_from_table_entry`].
pub struct NonPrimitiveTableEntry<SC>
where
    SC: StarkGenericConfig,
{
    /// Operation type (it should match `TableProver::op_type`).
    pub op_type: NonPrimitiveOpType,
    /// Number of logical rows produced for this table.
    pub rows: usize,
    /// Public values exposed by this table (if any).
    pub public_values: Vec<Val<SC>>,
}

/// Combined data for circuit proving, including STARK prover data and preprocessed columns.
///
/// This struct bundles the upstream [`ProverData`] with circuit-specific [`PreprocessedColumns`],
/// providing a cleaner API for `prove_all_tables`.
pub struct CircuitProverData<SC: StarkGenericConfig> {
    /// STARK prover data from p3_batch_stark.
    pub prover_data: ProverData<SC>,
    /// Preprocessed columns for all primitive and non-primitive operations.
    pub preprocessed_columns: PreprocessedColumns<Val<SC>>,
}

impl<SC: StarkGenericConfig> CircuitProverData<SC> {
    /// Create new circuit prover data from components.
    pub const fn new(
        prover_data: ProverData<SC>,
        preprocessed_columns: PreprocessedColumns<Val<SC>>,
    ) -> Self {
        Self {
            prover_data,
            preprocessed_columns,
        }
    }

    /// Get a reference to the common data.
    pub const fn common_data(&self) -> &CommonData<SC> {
        &self.prover_data.common
    }

    /// Get a reference to the preprocessed columns.
    pub const fn preprocessed_columns(&self) -> &PreprocessedColumns<Val<SC>> {
        &self.preprocessed_columns
    }
}

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
            packing: TablePacking,
            traces: &p3_circuit::tables::Traces<p3_batch_stark::Val<SC>>,
        ) -> Option<BatchTableInstance<SC>> {
            self.$base::<SC>(config, packing, traces)
        }

        fn batch_instance_d2(
            &self,
            config: &SC,
            packing: TablePacking,
            traces: &p3_circuit::tables::Traces<
                p3_field::extension::BinomialExtensionField<p3_batch_stark::Val<SC>, 2>,
            >,
        ) -> Option<BatchTableInstance<SC>> {
            let t: &p3_circuit::tables::Traces<p3_batch_stark::Val<SC>> =
                unsafe { transmute_traces(traces) };
            self.$base::<SC>(config, packing, t)
        }

        fn batch_instance_d4(
            &self,
            config: &SC,
            packing: TablePacking,
            traces: &p3_circuit::tables::Traces<
                p3_field::extension::BinomialExtensionField<p3_batch_stark::Val<SC>, 4>,
            >,
        ) -> Option<BatchTableInstance<SC>> {
            let t: &p3_circuit::tables::Traces<p3_batch_stark::Val<SC>> =
                unsafe { transmute_traces(traces) };
            self.$base::<SC>(config, packing, t)
        }

        fn batch_instance_d6(
            &self,
            config: &SC,
            packing: TablePacking,
            traces: &p3_circuit::tables::Traces<
                p3_field::extension::BinomialExtensionField<p3_batch_stark::Val<SC>, 6>,
            >,
        ) -> Option<BatchTableInstance<SC>> {
            let t: &p3_circuit::tables::Traces<p3_batch_stark::Val<SC>> =
                unsafe { transmute_traces(traces) };
            self.$base::<SC>(config, packing, t)
        }

        fn batch_instance_d8(
            &self,
            config: &SC,
            packing: TablePacking,
            traces: &p3_circuit::tables::Traces<
                p3_field::extension::BinomialExtensionField<p3_batch_stark::Val<SC>, 8>,
            >,
        ) -> Option<BatchTableInstance<SC>> {
            let t: &p3_circuit::tables::Traces<p3_batch_stark::Val<SC>> =
                unsafe { transmute_traces(traces) };
            self.$base::<SC>(config, packing, t)
        }
    };
}

/// Wrapper for Poseidon2CircuitAir that implements BatchAir<SC>
// We need this because `BatchAir` requires `BaseAir<Val<SC>>`.
// but `Poseidon2CircuitAir` works over a specific field.
enum Poseidon2AirWrapperInner {
    BabyBearD4Width16(Box<Poseidon2CircuitAirBabyBearD4Width16>),
    BabyBearD4Width24(Box<Poseidon2CircuitAirBabyBearD4Width24>),
    KoalaBearD4Width16(Box<Poseidon2CircuitAirKoalaBearD4Width16>),
    KoalaBearD4Width24(Box<Poseidon2CircuitAirKoalaBearD4Width24>),
}

impl Poseidon2AirWrapperInner {
    fn width(&self) -> usize {
        match self {
            Self::BabyBearD4Width16(air) => air.width(),
            Self::BabyBearD4Width24(air) => air.width(),
            Self::KoalaBearD4Width16(air) => air.width(),
            Self::KoalaBearD4Width24(air) => air.width(),
        }
    }
}

impl Clone for Poseidon2AirWrapperInner {
    fn clone(&self) -> Self {
        match self {
            Self::BabyBearD4Width16(air) => Self::BabyBearD4Width16(air.clone()),
            Self::BabyBearD4Width24(air) => Self::BabyBearD4Width24(air.clone()),
            Self::KoalaBearD4Width16(air) => Self::KoalaBearD4Width16(air.clone()),
            Self::KoalaBearD4Width24(air) => Self::KoalaBearD4Width24(air.clone()),
        }
    }
}

struct Poseidon2AirWrapper<SC: StarkGenericConfig> {
    inner: Poseidon2AirWrapperInner,
    width: usize,
    _phantom: core::marker::PhantomData<SC>,
}

impl<SC> BatchAir<SC> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
}

impl<SC: StarkGenericConfig> Clone for Poseidon2AirWrapper<SC> {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
            width: self.width,
            _phantom: core::marker::PhantomData,
        }
    }
}

const BABY_BEAR_MODULUS: u64 = 0x78000001;
const KOALA_BEAR_MODULUS: u64 = 0x7f000001;

impl<SC> BaseAir<Val<SC>> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
{
    fn width(&self) -> usize {
        self.width
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val<SC>>> {
        match &self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => {
                // SAFETY: Val<SC> == BabyBear when this variant is used
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);

                let preprocessed = BaseAir::<BabyBear>::preprocessed_trace(air.as_ref())?;
                Some(unsafe {
                    transmute::<RowMajorMatrix<BabyBear>, RowMajorMatrix<Val<SC>>>(preprocessed)
                })
            }
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => {
                // SAFETY: Val<SC> == BabyBear when this variant is used
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);

                let preprocessed = BaseAir::<BabyBear>::preprocessed_trace(air.as_ref())?;
                Some(unsafe {
                    transmute::<RowMajorMatrix<BabyBear>, RowMajorMatrix<Val<SC>>>(preprocessed)
                })
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => {
                // SAFETY: Val<SC> == KoalaBear when this variant is used
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);

                let preprocessed = BaseAir::<KoalaBear>::preprocessed_trace(air.as_ref())?;
                Some(unsafe {
                    transmute::<RowMajorMatrix<KoalaBear>, RowMajorMatrix<Val<SC>>>(preprocessed)
                })
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => {
                // SAFETY: Val<SC> == KoalaBear when this variant is used
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);

                let preprocessed = BaseAir::<KoalaBear>::preprocessed_trace(air.as_ref())?;
                Some(unsafe {
                    transmute::<RowMajorMatrix<KoalaBear>, RowMajorMatrix<Val<SC>>>(preprocessed)
                })
            }
        }
    }
}

impl<SC> Air<SymbolicAirBuilder<Val<SC>, SC::Challenge>> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
{
    fn eval(&self, builder: &mut SymbolicAirBuilder<Val<SC>, SC::Challenge>) {
        // Delegate to the actual AIR instance stored in the wrapper
        match &self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => {
                // Runtime check: verify Val<SC> == BabyBear before transmute
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                // SAFETY: Val<SC> == BabyBear when this variant is used
                // SymbolicAirBuilder<BabyBear> and SymbolicAirBuilder<Val<SC>> have the same layout
                unsafe {
                    let builder_bb: &mut SymbolicAirBuilder<BabyBear> =
                        core::mem::transmute(builder);
                    Air::eval(air.as_ref(), builder_bb);
                }
            }
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => {
                // Runtime check: verify Val<SC> == BabyBear before transmute
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                // SAFETY: Val<SC> == BabyBear when this variant is used
                // SymbolicAirBuilder<BabyBear> and SymbolicAirBuilder<Val<SC>> have the same layout
                unsafe {
                    let builder_bb: &mut SymbolicAirBuilder<BabyBear> =
                        core::mem::transmute(builder);
                    Air::eval(air.as_ref(), builder_bb);
                }
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => {
                // Runtime check: verify Val<SC> == KoalaBear before transmute
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                // SAFETY: Val<SC> == KoalaBear when this variant is used
                // SymbolicAirBuilder<KoalaBear> and SymbolicAirBuilder<Val<SC>> have the same layout
                unsafe {
                    let builder_kb: &mut SymbolicAirBuilder<KoalaBear> =
                        core::mem::transmute(builder);
                    Air::eval(air.as_ref(), builder_kb);
                }
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => {
                // Runtime check: verify Val<SC> == KoalaBear before transmute
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                // SAFETY: Val<SC> == KoalaBear when this variant is used
                // SymbolicAirBuilder<KoalaBear> and SymbolicAirBuilder<Val<SC>> have the same layout
                unsafe {
                    let builder_kb: &mut SymbolicAirBuilder<KoalaBear> =
                        core::mem::transmute(builder);
                    Air::eval(air.as_ref(), builder_kb);
                }
            }
        }
    }

    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match &mut self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => {
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width16 = air.as_mut();
                <Poseidon2CircuitAirBabyBearD4Width16 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::add_lookup_columns(air_bb)
            }
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => {
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width24 = air.as_mut();
                <Poseidon2CircuitAirBabyBearD4Width24 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::add_lookup_columns(air_bb)
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => {
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width16 = air.as_mut();
                <Poseidon2CircuitAirKoalaBearD4Width16 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::add_lookup_columns(air_kb)
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => {
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width24 = air.as_mut();
                <Poseidon2CircuitAirKoalaBearD4Width24 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::add_lookup_columns(air_kb)
            }
        }
    }

    #[allow(clippy::missing_transmute_annotations)] // this gets overly verbose otherwise
    fn get_lookups(
        &mut self,
    ) -> Vec<Lookup<<SymbolicAirBuilder<Val<SC>, SC::Challenge> as AirBuilder>::F>> {
        match &mut self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => unsafe {
                // Runtime check: verify Val<SC> == BabyBear before transmute
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width16 = air.as_mut();
                let lookups_bb = <Poseidon2CircuitAirBabyBearD4Width16 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::get_lookups(air_bb);
                core::mem::transmute(lookups_bb)
            },
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => unsafe {
                // Runtime check: verify Val<SC> == BabyBear before transmute
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width24 = air.as_mut();
                let lookups_bb = <Poseidon2CircuitAirBabyBearD4Width24 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::get_lookups(air_bb);
                core::mem::transmute(lookups_bb)
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => unsafe {
                // Runtime check: verify Val<SC> == KoalaBear before transmute
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width16 = air.as_mut();
                let lookups_kb = <Poseidon2CircuitAirKoalaBearD4Width16 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::get_lookups(air_kb);
                core::mem::transmute(lookups_kb)
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => unsafe {
                // Runtime check: verify Val<SC> == KoalaBear before transmute
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width24 = air.as_mut();
                let lookups_kb = <Poseidon2CircuitAirKoalaBearD4Width24 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::get_lookups(air_kb);
                core::mem::transmute(lookups_kb)
            },
        }
    }
}

/// Helper function to evaluate a Poseidon2 variant with a given builder.
/// This encapsulates the common pattern of transmuting slices and calling eval_unchecked.
unsafe fn eval_poseidon2_variant<
    SC,
    F: PrimeField,
    AB: AirBuilder,
    LinearLayers,
    const D: usize,
    const WIDTH: usize,
    const WIDTH_EXT: usize,
    const RATE_EXT: usize,
    const CAPACITY_EXT: usize,
    const SBOX_DEGREE: u64,
    const SBOX_REGISTERS: usize,
    const HALF_FULL_ROUNDS: usize,
    const PARTIAL_ROUNDS: usize,
>(
    air: &Poseidon2CircuitAir<
        F,
        LinearLayers,
        D,
        WIDTH,
        WIDTH_EXT,
        RATE_EXT,
        CAPACITY_EXT,
        SBOX_DEGREE,
        SBOX_REGISTERS,
        HALF_FULL_ROUNDS,
        PARTIAL_ROUNDS,
    >,
    builder: &mut AB,
    local_slice: &[<AB as AirBuilder>::Var],
    next_slice: &[<AB as AirBuilder>::Var],
    next_preprocessed_slice: &[<AB as AirBuilder>::Var],
) where
    SC: StarkGenericConfig,
    Val<SC>: StarkField + PrimeField,
    AB::F: PrimeField,
    LinearLayers: p3_poseidon2::GenericPoseidon2LinearLayers<WIDTH>,
{
    // Transmute slices from PackedVal<SC> to F::Packing
    // SAFETY: Val<SC> == F at runtime
    unsafe {
        let local_slice_ptr = local_slice.as_ptr() as *const <F as p3_field::Field>::Packing;
        let local_slice_f = core::slice::from_raw_parts(local_slice_ptr, local_slice.len());
        let local_f: &p3_poseidon2_circuit_air::Poseidon2CircuitCols<
            <F as p3_field::Field>::Packing,
            p3_poseidon2_air::Poseidon2Cols<
                <F as p3_field::Field>::Packing,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >,
        > = (*local_slice_f).borrow();

        let next_slice_ptr = next_slice.as_ptr() as *const <F as p3_field::Field>::Packing;
        let next_slice_f = core::slice::from_raw_parts(next_slice_ptr, next_slice.len());
        let next_f: &p3_poseidon2_circuit_air::Poseidon2CircuitCols<
            <F as p3_field::Field>::Packing,
            p3_poseidon2_air::Poseidon2Cols<
                <F as p3_field::Field>::Packing,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >,
        > = (*next_slice_f).borrow();

        let next_preprocessed_ptr =
            next_preprocessed_slice.as_ptr() as *const <F as p3_field::Field>::Packing;
        let next_preprocessed_f =
            core::slice::from_raw_parts(next_preprocessed_ptr, next_preprocessed_slice.len());

        // Transmute struct references to match builder's Var type
        let local_var: &p3_poseidon2_circuit_air::Poseidon2CircuitCols<
            AB::Var,
            p3_poseidon2_air::Poseidon2Cols<
                AB::Var,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >,
        > = core::mem::transmute(local_f);

        let next_var: &p3_poseidon2_circuit_air::Poseidon2CircuitCols<
            AB::Var,
            p3_poseidon2_air::Poseidon2Cols<
                AB::Var,
                WIDTH,
                SBOX_DEGREE,
                SBOX_REGISTERS,
                HALF_FULL_ROUNDS,
                PARTIAL_ROUNDS,
            >,
        > = core::mem::transmute(next_f);

        let next_preprocessed_var: &[AB::Var] = core::mem::transmute(next_preprocessed_f);

        eval_unchecked::<
            F,
            AB,
            LinearLayers,
            D,
            WIDTH,
            WIDTH_EXT,
            RATE_EXT,
            CAPACITY_EXT,
            SBOX_DEGREE,
            SBOX_REGISTERS,
            HALF_FULL_ROUNDS,
            PARTIAL_ROUNDS,
        >(air, builder, local_var, next_var, next_preprocessed_var);
    }
}

impl<'a, SC> Air<ProverConstraintFolder<'a, SC>> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField + PrimeField,
{
    fn eval(&self, builder: &mut ProverConstraintFolder<'a, SC>) {
        // Extract row data (same pattern as Poseidon2CircuitAir::eval)
        let main = builder.main();
        let local_slice = main.row_slice(0).expect("The matrix is empty?");
        let next_slice = main.row_slice(1).expect("The matrix has only one row?");
        let preprocessed = builder
            .preprocessed()
            .expect("Expected preprocessed columns");
        let next_preprocessed_slice = preprocessed
            .row_slice(1)
            .expect("The preprocessed matrix has only one row?");

        match &self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    BabyBear,
                    ProverConstraintFolder<'a, SC>,
                    GenericPoseidon2LinearLayersBabyBear,
                    { BabyBearD4Width16::D },
                    { BabyBearD4Width16::WIDTH },
                    { BabyBearD4Width16::WIDTH_EXT },
                    { BabyBearD4Width16::RATE_EXT },
                    { BabyBearD4Width16::CAPACITY_EXT },
                    { BabyBearD4Width16::SBOX_DEGREE },
                    { BabyBearD4Width16::SBOX_REGISTERS },
                    { BabyBearD4Width16::HALF_FULL_ROUNDS },
                    { BabyBearD4Width16::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    BabyBear,
                    ProverConstraintFolder<'a, SC>,
                    GenericPoseidon2LinearLayersBabyBear,
                    { BabyBearD4Width24::D },
                    { BabyBearD4Width24::WIDTH },
                    { BabyBearD4Width24::WIDTH_EXT },
                    { BabyBearD4Width24::RATE_EXT },
                    { BabyBearD4Width24::CAPACITY_EXT },
                    { BabyBearD4Width24::SBOX_DEGREE },
                    { BabyBearD4Width24::SBOX_REGISTERS },
                    { BabyBearD4Width24::HALF_FULL_ROUNDS },
                    { BabyBearD4Width24::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    KoalaBear,
                    ProverConstraintFolder<'a, SC>,
                    GenericPoseidon2LinearLayersKoalaBear,
                    { KoalaBearD4Width16::D },
                    { KoalaBearD4Width16::WIDTH },
                    { KoalaBearD4Width16::WIDTH_EXT },
                    { KoalaBearD4Width16::RATE_EXT },
                    { KoalaBearD4Width16::CAPACITY_EXT },
                    { KoalaBearD4Width16::SBOX_DEGREE },
                    { KoalaBearD4Width16::SBOX_REGISTERS },
                    { KoalaBearD4Width16::HALF_FULL_ROUNDS },
                    { KoalaBearD4Width16::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    KoalaBear,
                    ProverConstraintFolder<'a, SC>,
                    GenericPoseidon2LinearLayersKoalaBear,
                    { KoalaBearD4Width24::D },
                    { KoalaBearD4Width24::WIDTH },
                    { KoalaBearD4Width24::WIDTH_EXT },
                    { KoalaBearD4Width24::RATE_EXT },
                    { KoalaBearD4Width24::CAPACITY_EXT },
                    { KoalaBearD4Width24::SBOX_DEGREE },
                    { KoalaBearD4Width24::SBOX_REGISTERS },
                    { KoalaBearD4Width24::HALF_FULL_ROUNDS },
                    { KoalaBearD4Width24::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
        }
    }
}

impl<'a, SC> Air<VerifierConstraintFolder<'a, SC>> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField + PrimeField,
{
    fn eval(&self, builder: &mut VerifierConstraintFolder<'a, SC>) {
        let main = builder.main();
        let local_slice = main.row_slice(0).expect("The matrix is empty?");
        let next_slice = main.row_slice(1).expect("The matrix has only one row?");
        let preprocessed = builder
            .preprocessed()
            .expect("Expected preprocessed columns");
        let next_preprocessed_slice = preprocessed
            .row_slice(1)
            .expect("The preprocessed matrix has only one row?");

        match &self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    BabyBear,
                    VerifierConstraintFolder<'a, SC>,
                    GenericPoseidon2LinearLayersBabyBear,
                    { BabyBearD4Width16::D },
                    { BabyBearD4Width16::WIDTH },
                    { BabyBearD4Width16::WIDTH_EXT },
                    { BabyBearD4Width16::RATE_EXT },
                    { BabyBearD4Width16::CAPACITY_EXT },
                    { BabyBearD4Width16::SBOX_DEGREE },
                    { BabyBearD4Width16::SBOX_REGISTERS },
                    { BabyBearD4Width16::HALF_FULL_ROUNDS },
                    { BabyBearD4Width16::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    BabyBear,
                    VerifierConstraintFolder<'a, SC>,
                    GenericPoseidon2LinearLayersBabyBear,
                    { BabyBearD4Width24::D },
                    { BabyBearD4Width24::WIDTH },
                    { BabyBearD4Width24::WIDTH_EXT },
                    { BabyBearD4Width24::RATE_EXT },
                    { BabyBearD4Width24::CAPACITY_EXT },
                    { BabyBearD4Width24::SBOX_DEGREE },
                    { BabyBearD4Width24::SBOX_REGISTERS },
                    { BabyBearD4Width24::HALF_FULL_ROUNDS },
                    { BabyBearD4Width24::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    KoalaBear,
                    VerifierConstraintFolder<'a, SC>,
                    GenericPoseidon2LinearLayersKoalaBear,
                    { KoalaBearD4Width16::D },
                    { KoalaBearD4Width16::WIDTH },
                    { KoalaBearD4Width16::WIDTH_EXT },
                    { KoalaBearD4Width16::RATE_EXT },
                    { KoalaBearD4Width16::CAPACITY_EXT },
                    { KoalaBearD4Width16::SBOX_DEGREE },
                    { KoalaBearD4Width16::SBOX_REGISTERS },
                    { KoalaBearD4Width16::HALF_FULL_ROUNDS },
                    { KoalaBearD4Width16::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    KoalaBear,
                    VerifierConstraintFolder<'a, SC>,
                    GenericPoseidon2LinearLayersKoalaBear,
                    { KoalaBearD4Width24::D },
                    { KoalaBearD4Width24::WIDTH },
                    { KoalaBearD4Width24::WIDTH_EXT },
                    { KoalaBearD4Width24::RATE_EXT },
                    { KoalaBearD4Width24::CAPACITY_EXT },
                    { KoalaBearD4Width24::SBOX_DEGREE },
                    { KoalaBearD4Width24::SBOX_REGISTERS },
                    { KoalaBearD4Width24::HALF_FULL_ROUNDS },
                    { KoalaBearD4Width24::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
        }
    }
}

#[cfg(debug_assertions)]
impl<'a, SC> Air<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>
    for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField + PrimeField,
{
    fn eval(&self, builder: &mut DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>) {
        let main = builder.main();
        let local_slice = main.row_slice(0).expect("The matrix is empty?");
        let next_slice = main.row_slice(1).expect("The matrix has only one row?");
        let preprocessed = builder
            .preprocessed()
            .expect("Expected preprocessed columns");
        let next_preprocessed_slice = preprocessed
            .row_slice(1)
            .expect("The preprocessed matrix has only one row?");

        match &self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    BabyBear,
                    DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>,
                    GenericPoseidon2LinearLayersBabyBear,
                    { BabyBearD4Width16::D },
                    { BabyBearD4Width16::WIDTH },
                    { BabyBearD4Width16::WIDTH_EXT },
                    { BabyBearD4Width16::RATE_EXT },
                    { BabyBearD4Width16::CAPACITY_EXT },
                    { BabyBearD4Width16::SBOX_DEGREE },
                    { BabyBearD4Width16::SBOX_REGISTERS },
                    { BabyBearD4Width16::HALF_FULL_ROUNDS },
                    { BabyBearD4Width16::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    BabyBear,
                    DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>,
                    GenericPoseidon2LinearLayersBabyBear,
                    { BabyBearD4Width24::D },
                    { BabyBearD4Width24::WIDTH },
                    { BabyBearD4Width24::WIDTH_EXT },
                    { BabyBearD4Width24::RATE_EXT },
                    { BabyBearD4Width24::CAPACITY_EXT },
                    { BabyBearD4Width24::SBOX_DEGREE },
                    { BabyBearD4Width24::SBOX_REGISTERS },
                    { BabyBearD4Width24::HALF_FULL_ROUNDS },
                    { BabyBearD4Width24::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    KoalaBear,
                    DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>,
                    GenericPoseidon2LinearLayersKoalaBear,
                    { KoalaBearD4Width16::D },
                    { KoalaBearD4Width16::WIDTH },
                    { KoalaBearD4Width16::WIDTH_EXT },
                    { KoalaBearD4Width16::RATE_EXT },
                    { KoalaBearD4Width16::CAPACITY_EXT },
                    { KoalaBearD4Width16::SBOX_DEGREE },
                    { KoalaBearD4Width16::SBOX_REGISTERS },
                    { KoalaBearD4Width16::HALF_FULL_ROUNDS },
                    { KoalaBearD4Width16::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    KoalaBear,
                    DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>,
                    GenericPoseidon2LinearLayersKoalaBear,
                    { KoalaBearD4Width24::D },
                    { KoalaBearD4Width24::WIDTH },
                    { KoalaBearD4Width24::WIDTH_EXT },
                    { KoalaBearD4Width24::RATE_EXT },
                    { KoalaBearD4Width24::CAPACITY_EXT },
                    { KoalaBearD4Width24::SBOX_DEGREE },
                    { KoalaBearD4Width24::SBOX_REGISTERS },
                    { KoalaBearD4Width24::HALF_FULL_ROUNDS },
                    { KoalaBearD4Width24::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
        }
    }

    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match &mut self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => {
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width16 = air.as_mut();
                <Poseidon2CircuitAirBabyBearD4Width16 as Air<
                    DebugConstraintBuilderWithLookups<
                        'a,
                        BabyBear,
                        BinomialExtensionField<BabyBear, 4>,
                    >,
                >>::add_lookup_columns(air_bb)
            }
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => {
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width24 = air.as_mut();
                <Poseidon2CircuitAirBabyBearD4Width24 as Air<
                    DebugConstraintBuilderWithLookups<
                        'a,
                        BabyBear,
                        BinomialExtensionField<BabyBear, 4>,
                    >,
                >>::add_lookup_columns(air_bb)
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => {
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width16 = air.as_mut();
                <Poseidon2CircuitAirKoalaBearD4Width16 as Air<
                    DebugConstraintBuilderWithLookups<
                        'a,
                        KoalaBear,
                        BinomialExtensionField<KoalaBear, 4>,
                    >,
                >>::add_lookup_columns(air_kb)
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => {
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width24 = air.as_mut();
                <Poseidon2CircuitAirKoalaBearD4Width24 as Air<
                    DebugConstraintBuilderWithLookups<
                        'a,
                        KoalaBear,
                        BinomialExtensionField<KoalaBear, 4>,
                    >,
                >>::add_lookup_columns(air_kb)
            }
        }
    }

    #[allow(clippy::missing_transmute_annotations)] // this gets overly verbose otherwise
    fn get_lookups(
        &mut self,
    ) -> Vec<Lookup<<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge> as AirBuilder>::F>>
    {
        match &mut self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => unsafe {
                // Runtime check: verify Val<SC> == BabyBear before transmute
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width16 = air.as_mut();
                let lookups_bb = <Poseidon2CircuitAirBabyBearD4Width16 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::get_lookups(air_bb);
                core::mem::transmute(lookups_bb)
            },
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => unsafe {
                // Runtime check: verify Val<SC> == BabyBear before transmute
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width24 = air.as_mut();
                let lookups_bb = <Poseidon2CircuitAirBabyBearD4Width24 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::get_lookups(air_bb);
                core::mem::transmute(lookups_bb)
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => unsafe {
                // Runtime check: verify Val<SC> == KoalaBear before transmute
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width16 = air.as_mut();
                let lookups_kb = <Poseidon2CircuitAirKoalaBearD4Width16 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::get_lookups(air_kb);
                core::mem::transmute(lookups_kb)
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => unsafe {
                // Runtime check: verify Val<SC> == KoalaBear before transmute
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width24 = air.as_mut();
                let lookups_kb = <Poseidon2CircuitAirKoalaBearD4Width24 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::get_lookups(air_kb);
                core::mem::transmute(lookups_kb)
            },
        }
    }
}

impl<'a, SC> Air<ProverConstraintFolderWithLookups<'a, SC>> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField + PrimeField,
{
    fn eval(&self, builder: &mut ProverConstraintFolderWithLookups<'a, SC>) {
        let main = builder.main();
        let local_slice = main.row_slice(0).expect("The matrix is empty?");
        let next_slice = main.row_slice(1).expect("The matrix has only one row?");
        let preprocessed = builder
            .preprocessed()
            .expect("Expected preprocessed columns");
        let next_preprocessed_slice = preprocessed
            .row_slice(1)
            .expect("The preprocessed matrix has only one row?");

        match &self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    BabyBear,
                    ProverConstraintFolderWithLookups<'a, SC>,
                    GenericPoseidon2LinearLayersBabyBear,
                    { BabyBearD4Width16::D },
                    { BabyBearD4Width16::WIDTH },
                    { BabyBearD4Width16::WIDTH_EXT },
                    { BabyBearD4Width16::RATE_EXT },
                    { BabyBearD4Width16::CAPACITY_EXT },
                    { BabyBearD4Width16::SBOX_DEGREE },
                    { BabyBearD4Width16::SBOX_REGISTERS },
                    { BabyBearD4Width16::HALF_FULL_ROUNDS },
                    { BabyBearD4Width16::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    BabyBear,
                    ProverConstraintFolderWithLookups<'a, SC>,
                    GenericPoseidon2LinearLayersBabyBear,
                    { BabyBearD4Width24::D },
                    { BabyBearD4Width24::WIDTH },
                    { BabyBearD4Width24::WIDTH_EXT },
                    { BabyBearD4Width24::RATE_EXT },
                    { BabyBearD4Width24::CAPACITY_EXT },
                    { BabyBearD4Width24::SBOX_DEGREE },
                    { BabyBearD4Width24::SBOX_REGISTERS },
                    { BabyBearD4Width24::HALF_FULL_ROUNDS },
                    { BabyBearD4Width24::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    KoalaBear,
                    ProverConstraintFolderWithLookups<'a, SC>,
                    GenericPoseidon2LinearLayersKoalaBear,
                    { KoalaBearD4Width16::D },
                    { KoalaBearD4Width16::WIDTH },
                    { KoalaBearD4Width16::WIDTH_EXT },
                    { KoalaBearD4Width16::RATE_EXT },
                    { KoalaBearD4Width16::CAPACITY_EXT },
                    { KoalaBearD4Width16::SBOX_DEGREE },
                    { KoalaBearD4Width16::SBOX_REGISTERS },
                    { KoalaBearD4Width16::HALF_FULL_ROUNDS },
                    { KoalaBearD4Width16::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    KoalaBear,
                    ProverConstraintFolderWithLookups<'a, SC>,
                    GenericPoseidon2LinearLayersKoalaBear,
                    { KoalaBearD4Width24::D },
                    { KoalaBearD4Width24::WIDTH },
                    { KoalaBearD4Width24::WIDTH_EXT },
                    { KoalaBearD4Width24::RATE_EXT },
                    { KoalaBearD4Width24::CAPACITY_EXT },
                    { KoalaBearD4Width24::SBOX_DEGREE },
                    { KoalaBearD4Width24::SBOX_REGISTERS },
                    { KoalaBearD4Width24::HALF_FULL_ROUNDS },
                    { KoalaBearD4Width24::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
        }
    }

    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match &mut self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => {
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width16 = air.as_mut();
                <Poseidon2CircuitAirBabyBearD4Width16 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::add_lookup_columns(air_bb)
            }
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => {
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width24 = air.as_mut();
                <Poseidon2CircuitAirBabyBearD4Width24 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::add_lookup_columns(air_bb)
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => {
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width16 = air.as_mut();
                <Poseidon2CircuitAirKoalaBearD4Width16 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::add_lookup_columns(air_kb)
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => {
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width24 = air.as_mut();
                <Poseidon2CircuitAirKoalaBearD4Width24 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::add_lookup_columns(air_kb)
            }
        }
    }

    #[allow(clippy::missing_transmute_annotations)]
    fn get_lookups(
        &mut self,
    ) -> Vec<Lookup<<ProverConstraintFolderWithLookups<'a, SC> as AirBuilder>::F>> {
        match &mut self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width16 = air.as_mut();
                let lookups_bb = <Poseidon2CircuitAirBabyBearD4Width16 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::get_lookups(air_bb);
                core::mem::transmute(lookups_bb)
            },
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width24 = air.as_mut();
                let lookups_bb = <Poseidon2CircuitAirBabyBearD4Width24 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::get_lookups(air_bb);
                core::mem::transmute(lookups_bb)
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width16 = air.as_mut();
                let lookups_kb = <Poseidon2CircuitAirKoalaBearD4Width16 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::get_lookups(air_kb);
                core::mem::transmute(lookups_kb)
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width24 = air.as_mut();
                let lookups_kb = <Poseidon2CircuitAirKoalaBearD4Width24 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::get_lookups(air_kb);
                core::mem::transmute(lookups_kb)
            },
        }
    }
}

impl<'a, SC> Air<VerifierConstraintFolderWithLookups<'a, SC>> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField + PrimeField,
{
    fn eval(&self, builder: &mut VerifierConstraintFolderWithLookups<'a, SC>) {
        let main = builder.main();
        let local_slice = main.row_slice(0).expect("The matrix is empty?");
        let next_slice = main.row_slice(1).expect("The matrix has only one row?");
        let preprocessed = builder
            .preprocessed()
            .expect("Expected preprocessed columns");
        let next_preprocessed_slice = preprocessed
            .row_slice(1)
            .expect("The preprocessed matrix has only one row?");

        match &self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    BabyBear,
                    VerifierConstraintFolderWithLookups<'a, SC>,
                    GenericPoseidon2LinearLayersBabyBear,
                    { BabyBearD4Width16::D },
                    { BabyBearD4Width16::WIDTH },
                    { BabyBearD4Width16::WIDTH_EXT },
                    { BabyBearD4Width16::RATE_EXT },
                    { BabyBearD4Width16::CAPACITY_EXT },
                    { BabyBearD4Width16::SBOX_DEGREE },
                    { BabyBearD4Width16::SBOX_REGISTERS },
                    { BabyBearD4Width16::HALF_FULL_ROUNDS },
                    { BabyBearD4Width16::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    BabyBear,
                    VerifierConstraintFolderWithLookups<'a, SC>,
                    GenericPoseidon2LinearLayersBabyBear,
                    { BabyBearD4Width24::D },
                    { BabyBearD4Width24::WIDTH },
                    { BabyBearD4Width24::WIDTH_EXT },
                    { BabyBearD4Width24::RATE_EXT },
                    { BabyBearD4Width24::CAPACITY_EXT },
                    { BabyBearD4Width24::SBOX_DEGREE },
                    { BabyBearD4Width24::SBOX_REGISTERS },
                    { BabyBearD4Width24::HALF_FULL_ROUNDS },
                    { BabyBearD4Width24::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    KoalaBear,
                    VerifierConstraintFolderWithLookups<'a, SC>,
                    GenericPoseidon2LinearLayersKoalaBear,
                    { KoalaBearD4Width16::D },
                    { KoalaBearD4Width16::WIDTH },
                    { KoalaBearD4Width16::WIDTH_EXT },
                    { KoalaBearD4Width16::RATE_EXT },
                    { KoalaBearD4Width16::CAPACITY_EXT },
                    { KoalaBearD4Width16::SBOX_DEGREE },
                    { KoalaBearD4Width16::SBOX_REGISTERS },
                    { KoalaBearD4Width16::HALF_FULL_ROUNDS },
                    { KoalaBearD4Width16::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => unsafe {
                eval_poseidon2_variant::<
                    SC,
                    KoalaBear,
                    VerifierConstraintFolderWithLookups<'a, SC>,
                    GenericPoseidon2LinearLayersKoalaBear,
                    { KoalaBearD4Width24::D },
                    { KoalaBearD4Width24::WIDTH },
                    { KoalaBearD4Width24::WIDTH_EXT },
                    { KoalaBearD4Width24::RATE_EXT },
                    { KoalaBearD4Width24::CAPACITY_EXT },
                    { KoalaBearD4Width24::SBOX_DEGREE },
                    { KoalaBearD4Width24::SBOX_REGISTERS },
                    { KoalaBearD4Width24::HALF_FULL_ROUNDS },
                    { KoalaBearD4Width24::PARTIAL_ROUNDS },
                >(
                    air.as_ref(),
                    builder,
                    &local_slice,
                    &next_slice,
                    &next_preprocessed_slice,
                );
            },
        }
    }

    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match &mut self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => {
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width16 = air.as_mut();
                <Poseidon2CircuitAirBabyBearD4Width16 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::add_lookup_columns(air_bb)
            }
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => {
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width24 = air.as_mut();
                <Poseidon2CircuitAirBabyBearD4Width24 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::add_lookup_columns(air_bb)
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => {
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width16 = air.as_mut();
                <Poseidon2CircuitAirKoalaBearD4Width16 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::add_lookup_columns(air_kb)
            }
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => {
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width24 = air.as_mut();
                <Poseidon2CircuitAirKoalaBearD4Width24 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::add_lookup_columns(air_kb)
            }
        }
    }

    #[allow(clippy::missing_transmute_annotations)]
    fn get_lookups(
        &mut self,
    ) -> Vec<Lookup<<VerifierConstraintFolderWithLookups<'a, SC> as AirBuilder>::F>> {
        match &mut self.inner {
            Poseidon2AirWrapperInner::BabyBearD4Width16(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width16 = air.as_mut();
                let lookups_bb = <Poseidon2CircuitAirBabyBearD4Width16 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::get_lookups(air_bb);
                core::mem::transmute(lookups_bb)
            },
            Poseidon2AirWrapperInner::BabyBearD4Width24(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(BABY_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_bb: &mut Poseidon2CircuitAirBabyBearD4Width24 = air.as_mut();
                let lookups_bb = <Poseidon2CircuitAirBabyBearD4Width24 as Air<
                    SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
                >>::get_lookups(air_bb);
                core::mem::transmute(lookups_bb)
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width16(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width16 = air.as_mut();
                let lookups_kb = <Poseidon2CircuitAirKoalaBearD4Width16 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::get_lookups(air_kb);
                core::mem::transmute(lookups_kb)
            },
            Poseidon2AirWrapperInner::KoalaBearD4Width24(air) => unsafe {
                assert_eq!(Val::<SC>::from_u64(KOALA_BEAR_MODULUS), Val::<SC>::ZERO,);
                let air_kb: &mut Poseidon2CircuitAirKoalaBearD4Width24 = air.as_mut();
                let lookups_kb = <Poseidon2CircuitAirKoalaBearD4Width24 as Air<
                    SymbolicAirBuilder<KoalaBear, BinomialExtensionField<KoalaBear, 4>>,
                >>::get_lookups(air_kb);
                core::mem::transmute(lookups_kb)
            },
        }
    }
}

/// Poseidon2 prover plugin that supports runtime configuration
///
/// This prover handles Poseidon2 hash operations in the circuit.
/// It stores a configuration enum that can represent different
/// Poseidon2 configurations (BabyBear/KoalaBear, different widths, etc).
#[derive(Clone)]
pub struct Poseidon2Prover {
    /// The configuration that provides permutation and constants
    config: Poseidon2Config,
}

unsafe impl Send for Poseidon2Prover {}
unsafe impl Sync for Poseidon2Prover {}

impl Poseidon2Prover {
    /// Create a new Poseidon2Prover with the given configuration
    pub const fn new(config: Poseidon2Config) -> Self {
        Self { config }
    }

    const fn baby_bear_constants_16() -> RoundConstants<BabyBear, 16, 4, 13> {
        let beginning_full: [[BabyBear; 16]; 4] = p3_baby_bear::BABYBEAR_RC16_EXTERNAL_INITIAL;
        let partial: [BabyBear; 13] = p3_baby_bear::BABYBEAR_RC16_INTERNAL;
        let ending_full: [[BabyBear; 16]; 4] = p3_baby_bear::BABYBEAR_RC16_EXTERNAL_FINAL;
        RoundConstants::new(beginning_full, partial, ending_full)
    }

    const fn baby_bear_constants_24() -> RoundConstants<BabyBear, 24, 4, 21> {
        let beginning_full: [[BabyBear; 24]; 4] = p3_baby_bear::BABYBEAR_RC24_EXTERNAL_INITIAL;
        let partial: [BabyBear; 21] = p3_baby_bear::BABYBEAR_RC24_INTERNAL;
        let ending_full: [[BabyBear; 24]; 4] = p3_baby_bear::BABYBEAR_RC24_EXTERNAL_FINAL;
        RoundConstants::new(beginning_full, partial, ending_full)
    }

    const fn koala_bear_constants_16() -> RoundConstants<KoalaBear, 16, 4, 20> {
        let beginning_full: [[KoalaBear; 16]; 4] = p3_koala_bear::KOALABEAR_RC16_EXTERNAL_INITIAL;
        let partial: [KoalaBear; 20] = p3_koala_bear::KOALABEAR_RC16_INTERNAL;
        let ending_full: [[KoalaBear; 16]; 4] = p3_koala_bear::KOALABEAR_RC16_EXTERNAL_FINAL;
        RoundConstants::new(beginning_full, partial, ending_full)
    }

    const fn koala_bear_constants_24() -> RoundConstants<KoalaBear, 24, 4, 23> {
        let beginning_full: [[KoalaBear; 24]; 4] = p3_koala_bear::KOALABEAR_RC24_EXTERNAL_INITIAL;
        let partial: [KoalaBear; 23] = p3_koala_bear::KOALABEAR_RC24_INTERNAL;
        let ending_full: [[KoalaBear; 24]; 4] = p3_koala_bear::KOALABEAR_RC24_EXTERNAL_FINAL;
        RoundConstants::new(beginning_full, partial, ending_full)
    }

    fn air_wrapper_for_config(config: Poseidon2Config) -> Poseidon2AirWrapperInner {
        match config {
            // D=1 and D=4 use the same underlying AIR (operates on 16 base field elements)
            Poseidon2Config::BabyBearD1Width16 | Poseidon2Config::BabyBearD4Width16 => {
                Poseidon2AirWrapperInner::BabyBearD4Width16(Box::new(
                    Poseidon2CircuitAirBabyBearD4Width16::new(Self::baby_bear_constants_16()),
                ))
            }
            Poseidon2Config::BabyBearD4Width24 => {
                Poseidon2AirWrapperInner::BabyBearD4Width24(Box::new(
                    Poseidon2CircuitAirBabyBearD4Width24::new(Self::baby_bear_constants_24()),
                ))
            }
            // D=1 and D=4 use the same underlying AIR (operates on 16 base field elements)
            Poseidon2Config::KoalaBearD1Width16 | Poseidon2Config::KoalaBearD4Width16 => {
                Poseidon2AirWrapperInner::KoalaBearD4Width16(Box::new(
                    Poseidon2CircuitAirKoalaBearD4Width16::new(Self::koala_bear_constants_16()),
                ))
            }
            Poseidon2Config::KoalaBearD4Width24 => {
                Poseidon2AirWrapperInner::KoalaBearD4Width24(Box::new(
                    Poseidon2CircuitAirKoalaBearD4Width24::new(Self::koala_bear_constants_24()),
                ))
            }
        }
    }

    fn air_wrapper_for_config_with_preprocessed<F: Field>(
        config: Poseidon2Config,
        preprocessed: Vec<F>,
    ) -> Poseidon2AirWrapperInner {
        match config {
            // D=1 and D=4 use the same underlying AIR (operates on 16 base field elements)
            Poseidon2Config::BabyBearD1Width16 | Poseidon2Config::BabyBearD4Width16 => {
                assert!(F::from_u64(BABY_BEAR_MODULUS) == F::ZERO,);
                Poseidon2AirWrapperInner::BabyBearD4Width16(Box::new(
                    Poseidon2CircuitAirBabyBearD4Width16::new_with_preprocessed(
                        Self::baby_bear_constants_16(),
                        unsafe { transmute::<Vec<F>, Vec<BabyBear>>(preprocessed) },
                    ),
                ))
            }
            Poseidon2Config::BabyBearD4Width24 => {
                assert!(F::from_u64(BABY_BEAR_MODULUS) == F::ZERO,);
                Poseidon2AirWrapperInner::BabyBearD4Width24(Box::new(
                    Poseidon2CircuitAirBabyBearD4Width24::new_with_preprocessed(
                        Self::baby_bear_constants_24(),
                        unsafe { transmute::<Vec<F>, Vec<BabyBear>>(preprocessed) },
                    ),
                ))
            }
            // D=1 and D=4 use the same underlying AIR (operates on 16 base field elements)
            Poseidon2Config::KoalaBearD1Width16 | Poseidon2Config::KoalaBearD4Width16 => {
                assert!(F::from_u64(KOALA_BEAR_MODULUS) == F::ZERO,);
                Poseidon2AirWrapperInner::KoalaBearD4Width16(Box::new(
                    Poseidon2CircuitAirKoalaBearD4Width16::new_with_preprocessed(
                        Self::koala_bear_constants_16(),
                        unsafe { transmute::<Vec<F>, Vec<KoalaBear>>(preprocessed) },
                    ),
                ))
            }
            Poseidon2Config::KoalaBearD4Width24 => {
                assert!(F::from_u64(KOALA_BEAR_MODULUS) == F::ZERO,);
                Poseidon2AirWrapperInner::KoalaBearD4Width24(Box::new(
                    Poseidon2CircuitAirKoalaBearD4Width24::new_with_preprocessed(
                        Self::koala_bear_constants_24(),
                        unsafe { transmute::<Vec<F>, Vec<KoalaBear>>(preprocessed) },
                    ),
                ))
            }
        }
    }

    pub fn wrapper_from_config_with_preprocessed<SC>(
        &self,
        preprocessed: Vec<Val<SC>>,
    ) -> DynamicAirEntry<SC>
    where
        SC: StarkGenericConfig + 'static + Send + Sync,
        Val<SC>: StarkField,
        SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
    {
        DynamicAirEntry::new(Box::new(Poseidon2AirWrapper {
            inner: Self::air_wrapper_for_config_with_preprocessed::<Val<SC>>(
                self.config,
                preprocessed,
            ),
            width: self.width_from_config(),
            _phantom: core::marker::PhantomData::<SC>,
        }))
    }

    pub fn width_from_config(&self) -> usize {
        match self.config {
            // D=1 and D=4 use the same underlying AIR
            Poseidon2Config::BabyBearD1Width16 | Poseidon2Config::BabyBearD4Width16 => {
                Poseidon2CircuitAirBabyBearD4Width16::new(Self::baby_bear_constants_16()).width()
            }
            Poseidon2Config::BabyBearD4Width24 => {
                Poseidon2CircuitAirBabyBearD4Width24::new(Self::baby_bear_constants_24()).width()
            }
            // D=1 and D=4 use the same underlying AIR
            Poseidon2Config::KoalaBearD1Width16 | Poseidon2Config::KoalaBearD4Width16 => {
                Poseidon2CircuitAirKoalaBearD4Width16::new(Self::koala_bear_constants_16()).width()
            }
            Poseidon2Config::KoalaBearD4Width24 => {
                Poseidon2CircuitAirKoalaBearD4Width24::new(Self::koala_bear_constants_24()).width()
            }
        }
    }

    pub const fn preprocessed_width_from_config(&self) -> usize {
        match self.config {
            // D=1 and D=4 use the same underlying AIR
            Poseidon2Config::BabyBearD1Width16 | Poseidon2Config::BabyBearD4Width16 => {
                Poseidon2CircuitAirBabyBearD4Width16::preprocessed_width()
            }
            Poseidon2Config::BabyBearD4Width24 => {
                Poseidon2CircuitAirBabyBearD4Width24::preprocessed_width()
            }
            // D=1 and D=4 use the same underlying AIR
            Poseidon2Config::KoalaBearD1Width16 | Poseidon2Config::KoalaBearD4Width16 => {
                Poseidon2CircuitAirKoalaBearD4Width16::preprocessed_width()
            }
            Poseidon2Config::KoalaBearD4Width24 => {
                Poseidon2CircuitAirKoalaBearD4Width24::preprocessed_width()
            }
        }
    }

    fn batch_instance_from_traces<SC, CF>(
        &self,
        _config: &SC,
        _packing: TablePacking,
        traces: &Traces<CF>,
    ) -> Option<BatchTableInstance<SC>>
    where
        SC: StarkGenericConfig + 'static + Send + Sync,
        Val<SC>: StarkField,
        CF: Field + ExtensionField<Val<SC>>,
        SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
    {
        let t = traces.non_primitive_trace::<Poseidon2Trace<Val<SC>>>(
            NonPrimitiveOpType::Poseidon2Perm(self.config),
        )?;

        let rows = t.total_rows();
        if rows == 0 {
            return None;
        }

        // Pad to power of two and generate trace matrix based on configuration
        match self.config {
            // D=1 and D=4 use the same underlying AIR
            Poseidon2Config::BabyBearD1Width16 | Poseidon2Config::BabyBearD4Width16 => {
                self.batch_instance_base_impl::<SC, p3_baby_bear::BabyBear, 16, 4, 13, 2>(t)
            }
            Poseidon2Config::BabyBearD4Width24 => {
                self.batch_instance_base_impl::<SC, p3_baby_bear::BabyBear, 24, 4, 21, 4>(t)
            }
            // D=1 and D=4 use the same underlying AIR
            Poseidon2Config::KoalaBearD1Width16 | Poseidon2Config::KoalaBearD4Width16 => {
                self.batch_instance_base_impl::<SC, p3_koala_bear::KoalaBear, 16, 4, 20, 2>(t)
            }
            Poseidon2Config::KoalaBearD4Width24 => {
                self.batch_instance_base_impl::<SC, p3_koala_bear::KoalaBear, 24, 4, 23, 4>(t)
            }
        }
    }

    fn batch_instance_base_impl<
        SC,
        F,
        const WIDTH: usize,
        const HALF_FULL_ROUNDS: usize,
        const PARTIAL_ROUNDS: usize,
        const RATE_EXT: usize,
    >(
        &self,
        t: &Poseidon2Trace<Val<SC>>,
    ) -> Option<BatchTableInstance<SC>>
    where
        SC: StarkGenericConfig + 'static + Send + Sync,
        F: StarkField + PrimeCharacteristicRing,
        Val<SC>: StarkField,
        SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
    {
        let rows = t.total_rows();

        // Pad to power of two
        let padded_rows = rows.next_power_of_two();
        let mut padded_ops = t.operations.clone();
        while padded_ops.len() < padded_rows {
            padded_ops.push(
                padded_ops
                    .last()
                    .cloned()
                    .unwrap_or_else(|| Poseidon2CircuitRow {
                        new_start: true,
                        merkle_path: false,
                        mmcs_bit: false,
                        mmcs_index_sum: Val::<SC>::ZERO,
                        input_values: vec![Val::<SC>::ZERO; WIDTH],
                        in_ctl: [false; 4],
                        input_indices: [0; 4],
                        out_ctl: [false; 2],
                        output_indices: [0; 2],
                        mmcs_index_sum_idx: 0,
                        mmcs_ctl_enabled: false,
                    }),
            );
        }

        // Convert trace from Val<SC> to F
        // Val<SC> and F are guaranteed to be the same type at runtime (BabyBear/KoalaBear)
        let ops_converted: Vec<Poseidon2CircuitRow<F>> = unsafe { transmute(padded_ops) };

        // Create an AIR instance based on the configuration
        // This is a bit verbose but we can't get over const generics
        let (air, matrix) = match self.config {
            // D=1 and D=4 use the same underlying AIR
            Poseidon2Config::BabyBearD1Width16 | Poseidon2Config::BabyBearD4Width16 => {
                let constants = Self::baby_bear_constants_16();
                let preprocessed =
                    extract_preprocessed_from_operations::<BabyBear, Val<SC>>(&t.operations);
                let air = Poseidon2CircuitAirBabyBearD4Width16::new_with_preprocessed(
                    constants.clone(),
                    preprocessed.clone(),
                );
                // F is guaranteed to be BabyBear at runtime in this branch
                let ops_babybear: Vec<Poseidon2CircuitRow<BabyBear>> =
                    unsafe { transmute(ops_converted) };
                let matrix_f = air.generate_trace_rows(&ops_babybear, &constants, 0);
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { transmute(matrix_f) };
                (
                    Poseidon2AirWrapper {
                        inner: Self::air_wrapper_for_config_with_preprocessed::<BabyBear>(
                            self.config,
                            preprocessed,
                        ),
                        width: air.width(),
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
            Poseidon2Config::BabyBearD4Width24 => {
                let constants = Self::baby_bear_constants_24();
                let preprocessed =
                    extract_preprocessed_from_operations::<BabyBear, Val<SC>>(&t.operations);
                let air = Poseidon2CircuitAirBabyBearD4Width24::new_with_preprocessed(
                    constants.clone(),
                    preprocessed.clone(),
                );
                // F is guaranteed to be BabyBear at runtime in this branch
                let ops_babybear: Vec<Poseidon2CircuitRow<BabyBear>> =
                    unsafe { transmute(ops_converted) };
                let matrix_f = air.generate_trace_rows(&ops_babybear, &constants, 0);
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { transmute(matrix_f) };
                (
                    // Preprocessed values are already stored in the AIR, so we don't need to pass them again in the wrapper.
                    Poseidon2AirWrapper {
                        inner: Self::air_wrapper_for_config_with_preprocessed(
                            self.config,
                            preprocessed,
                        ),
                        width: air.width(),
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
            // D=1 and D=4 use the same underlying AIR
            Poseidon2Config::KoalaBearD1Width16 | Poseidon2Config::KoalaBearD4Width16 => {
                let constants = Self::koala_bear_constants_16();
                let preprocessed =
                    extract_preprocessed_from_operations::<KoalaBear, Val<SC>>(&t.operations);
                let air = Poseidon2CircuitAirKoalaBearD4Width16::new_with_preprocessed(
                    constants.clone(),
                    preprocessed.clone(),
                );
                // F is guaranteed to be KoalaBear at runtime in this branch
                let ops_koalabear: Vec<Poseidon2CircuitRow<KoalaBear>> =
                    unsafe { transmute(ops_converted) };
                let matrix_f = air.generate_trace_rows(&ops_koalabear, &constants, 0);
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { transmute(matrix_f) };
                (
                    // Preprocessed values are already stored in the AIR, so we don't need to pass them again in the wrapper.
                    Poseidon2AirWrapper {
                        inner: Self::air_wrapper_for_config_with_preprocessed(
                            self.config,
                            preprocessed,
                        ),
                        width: air.width(),
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
            Poseidon2Config::KoalaBearD4Width24 => {
                let constants = Self::koala_bear_constants_24();
                let preprocessed =
                    extract_preprocessed_from_operations::<KoalaBear, Val<SC>>(&t.operations);
                let air = Poseidon2CircuitAirKoalaBearD4Width24::new_with_preprocessed(
                    constants.clone(),
                    preprocessed.clone(),
                );
                let ops_koalabear: Vec<Poseidon2CircuitRow<KoalaBear>> =
                    unsafe { core::mem::transmute(ops_converted) };
                let matrix_f = air.generate_trace_rows(&ops_koalabear, &constants, 0);
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { core::mem::transmute(matrix_f) };
                (
                    // Preprocessed values are already stored in the AIR, so we don't need to pass them again in the wrapper.
                    Poseidon2AirWrapper {
                        inner: Self::air_wrapper_for_config_with_preprocessed(
                            self.config,
                            preprocessed,
                        ),
                        width: air.width(),
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
        };

        Some(BatchTableInstance {
            op_type: NonPrimitiveOpType::Poseidon2Perm(self.config),
            air: DynamicAirEntry::new(Box::new(air)),
            trace: matrix,
            public_values: Vec::new(),
            rows: padded_rows,
        })
    }
}

impl<SC> TableProver<SC> for Poseidon2Prover
where
    SC: StarkGenericConfig + 'static + Send + Sync,
    Val<SC>: StarkField + BinomiallyExtendable<4>,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    fn op_type(&self) -> NonPrimitiveOpType {
        NonPrimitiveOpType::Poseidon2Perm(self.config)
    }

    fn batch_instance_d1(
        &self,
        config: &SC,
        packing: TablePacking,
        traces: &Traces<Val<SC>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.batch_instance_from_traces::<SC, Val<SC>>(config, packing, traces)
    }

    fn batch_instance_d2(
        &self,
        config: &SC,
        packing: TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 2>>,
    ) -> Option<BatchTableInstance<SC>> {
        // Not supported for Poseidon2 table; extension circuits use D=4.
        let _ = (config, packing, traces);
        None
    }

    fn batch_instance_d4(
        &self,
        config: &SC,
        packing: TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 4>>,
    ) -> Option<BatchTableInstance<SC>> {
        self.batch_instance_from_traces::<SC, BinomialExtensionField<Val<SC>, 4>>(
            config, packing, traces,
        )
    }

    fn batch_instance_d6(
        &self,
        config: &SC,
        packing: TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 6>>,
    ) -> Option<BatchTableInstance<SC>> {
        // Not supported for Poseidon2 table; extension circuits use D=4.
        let _ = (config, packing, traces);
        None
    }

    fn batch_instance_d8(
        &self,
        config: &SC,
        packing: TablePacking,
        traces: &Traces<BinomialExtensionField<Val<SC>, 8>>,
    ) -> Option<BatchTableInstance<SC>> {
        // Not supported for Poseidon2 table; extension circuits use D=4.
        let _ = (config, packing, traces);
        None
    }

    fn batch_air_from_table_entry(
        &self,
        _config: &SC,
        _degree: usize,
        _table_entry: &NonPrimitiveTableEntry<SC>,
    ) -> Result<DynamicAirEntry<SC>, String> {
        // Recreate the AIR wrapper from the configuration
        let inner = Self::air_wrapper_for_config(self.config);
        let width = inner.width();
        let wrapper = Poseidon2AirWrapper {
            inner,
            width,
            _phantom: core::marker::PhantomData::<SC>,
        };
        Ok(DynamicAirEntry::new(Box::new(wrapper)))
    }
}

pub type PrimitiveTable = PrimitiveOpType;

/// Number of primitive circuit tables included in the unified batch STARK proof.
pub const NUM_PRIMITIVE_TABLES: usize = PrimitiveTable::Mul as usize + 1;

/// Row counts wrapper with type-safe indexing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RowCounts([usize; NUM_PRIMITIVE_TABLES]);

impl RowCounts {
    /// Creates a new RowCounts with the given row counts for each table.
    pub const fn new(rows: [usize; NUM_PRIMITIVE_TABLES]) -> Self {
        // Validate that all row counts are non-zero
        let mut i = 0;
        while i < rows.len() {
            assert!(rows[i] > 0);
            i += 1;
        }
        Self(rows)
    }

    /// Gets the row count for a specific table.
    #[inline]
    pub const fn get(&self, t: PrimitiveTable) -> usize {
        self.0[t as usize]
    }
}

impl core::ops::Index<PrimitiveTable> for RowCounts {
    type Output = usize;
    fn index(&self, table: PrimitiveTable) -> &Self::Output {
        &self.0[table as usize]
    }
}

impl From<[usize; NUM_PRIMITIVE_TABLES]> for RowCounts {
    fn from(rows: [usize; NUM_PRIMITIVE_TABLES]) -> Self {
        Self(rows)
    }
}

/// Proof bundle and metadata for the unified batch STARK proof across all circuit tables.
pub struct BatchStarkProof<SC>
where
    SC: StarkGenericConfig,
{
    /// The core cryptographic proof generated by `p3-batch-stark`.
    pub proof: BatchProof<SC>,
    /// Packing configuration used for the Witness, Add, and Mul tables.
    pub table_packing: TablePacking,
    /// The number of rows in each of the circuit tables.
    pub rows: RowCounts,
    /// The degree of the field extension (`D`) used for the proof.
    pub ext_degree: usize,
    /// The binomial coefficient `W` for extension field multiplication, if `ext_degree > 1`.
    pub w_binomial: Option<Val<SC>>,
    /// Manifest describing batched non-primitive tables defined at runtime.
    pub non_primitives: Vec<NonPrimitiveTableEntry<SC>>,
}

impl<SC> core::fmt::Debug for BatchStarkProof<SC>
where
    SC: StarkGenericConfig,
{
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BatchStarkProof")
            .field("table_packing", &self.table_packing)
            .field("rows", &self.rows)
            .field("ext_degree", &self.ext_degree)
            .field("w_binomial", &self.w_binomial)
            .finish()
    }
}

/// Produces a single batch STARK proof covering all circuit tables.
pub struct BatchStarkProver<SC>
where
    SC: StarkGenericConfig + 'static,
{
    config: SC,
    table_packing: TablePacking,
    /// Registered dynamic non-primitive table provers.
    non_primitive_provers: Vec<Box<dyn TableProver<SC>>>,
}

/// Errors for the batch STARK table prover.
#[derive(Debug, Error)]
pub enum BatchStarkProverError {
    #[error("unsupported extension degree: {0} (supported: 1,2,4,6,8)")]
    UnsupportedDegree(usize),

    #[error("missing binomial parameter W for extension-field multiplication")]
    MissingWForExtension,

    #[error("verification failed: {0}")]
    Verify(String),

    #[error("missing table prover for non-primitive op `{0:?}`")]
    MissingTableProver(NonPrimitiveOpType),
}

impl<SC, const D: usize> BaseAir<Val<SC>> for CircuitTableAir<SC, D>
where
    SC: StarkGenericConfig,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    fn width(&self) -> usize {
        match self {
            Self::Witness(a) => a.width(),
            Self::Const(a) => a.width(),
            Self::Public(a) => a.width(),
            Self::Add(a) => a.width(),
            Self::Mul(a) => a.width(),
            Self::Dynamic(a) => <dyn CloneableBatchAir<SC> as BaseAir<Val<SC>>>::width(a.air()),
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val<SC>>> {
        match self {
            Self::Witness(a) => a.preprocessed_trace(),
            Self::Const(a) => a.preprocessed_trace(),
            Self::Public(a) => a.preprocessed_trace(),
            Self::Add(a) => a.preprocessed_trace(),
            Self::Mul(a) => a.preprocessed_trace(),
            Self::Dynamic(a) => {
                <dyn CloneableBatchAir<SC> as BaseAir<Val<SC>>>::preprocessed_trace(a.air())
            }
        }
    }
}

impl<SC, const D: usize> Air<SymbolicAirBuilder<Val<SC>, SC::Challenge>> for CircuitTableAir<SC, D>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    fn eval(&self, builder: &mut SymbolicAirBuilder<Val<SC>, SC::Challenge>) {
        match self {
            Self::Witness(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::eval(a, builder),
            Self::Const(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::eval(a, builder),
            Self::Public(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::eval(a, builder),
            Self::Add(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::eval(a, builder),
            Self::Mul(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::eval(a, builder),
            Self::Dynamic(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::eval(a, builder),
        }
    }

    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match self {
            Self::Witness(a) => {
                Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::add_lookup_columns(a)
            }
            Self::Const(a) => {
                Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::add_lookup_columns(a)
            }
            Self::Public(a) => {
                Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::add_lookup_columns(a)
            }
            Self::Add(a) => {
                Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::add_lookup_columns(a)
            }
            Self::Mul(a) => {
                Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::add_lookup_columns(a)
            }
            Self::Dynamic(a) => {
                Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::add_lookup_columns(a)
            }
        }
    }

    fn get_lookups(
        &mut self,
    ) -> Vec<Lookup<<SymbolicAirBuilder<Val<SC>, SC::Challenge> as AirBuilder>::F>> {
        match self {
            Self::Witness(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::get_lookups(a),
            Self::Const(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::get_lookups(a),
            Self::Public(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::get_lookups(a),
            Self::Add(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::get_lookups(a),
            Self::Mul(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::get_lookups(a),
            Self::Dynamic(a) => Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::get_lookups(a),
        }
    }
}

#[cfg(debug_assertions)]
impl<'a, SC, const D: usize> Air<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>
    for CircuitTableAir<SC, D>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    fn eval(&self, builder: &mut DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>) {
        match self {
            Self::Witness(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::eval(
                    a, builder,
                );
            }
            Self::Const(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::eval(
                    a, builder,
                );
            }
            Self::Public(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::eval(
                    a, builder,
                );
            }
            Self::Add(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::eval(
                    a, builder,
                );
            }
            Self::Mul(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::eval(
                    a, builder,
                );
            }
            Self::Dynamic(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::eval(
                    a, builder,
                );
            }
        }
    }

    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match self {
            Self::Witness(a) => Air::<
                DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>,
            >::add_lookup_columns(a),
            Self::Const(a) => Air::<
                DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>,
            >::add_lookup_columns(a),
            Self::Public(a) => Air::<
                DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>,
            >::add_lookup_columns(a),
            Self::Add(a) => Air::<
                DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>,
            >::add_lookup_columns(a),
            Self::Mul(a) => Air::<
                DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>,
            >::add_lookup_columns(a),
            Self::Dynamic(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::add_lookup_columns(a)
            }
        }
    }

    fn get_lookups(
        &mut self,
    ) -> Vec<Lookup<<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge> as AirBuilder>::F>>
    {
        match self {
            Self::Witness(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::get_lookups(a)
            }
            Self::Const(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::get_lookups(a)
            }
            Self::Public(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::get_lookups(a)
            }
            Self::Add(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::get_lookups(a)
            }
            Self::Mul(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::get_lookups(a)
            }
            Self::Dynamic(a) => {
                Air::<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>::get_lookups(a)
            }
        }
    }
}

impl<'a, SC, const D: usize> Air<ProverConstraintFolderWithLookups<'a, SC>>
    for CircuitTableAir<SC, D>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    fn eval(&self, builder: &mut ProverConstraintFolderWithLookups<'a, SC>) {
        match self {
            Self::Witness(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::eval(a, builder),
            Self::Const(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::eval(a, builder),
            Self::Public(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::eval(a, builder),
            Self::Add(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::eval(a, builder),
            Self::Mul(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::eval(a, builder),
            Self::Dynamic(a) => {
                Air::<ProverConstraintFolderWithLookups<'a, SC>>::eval(a, builder);
            }
        }
    }

    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match self {
            Self::Witness(a) => {
                Air::<ProverConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a)
            }
            Self::Const(a) => {
                Air::<ProverConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a)
            }
            Self::Public(a) => {
                Air::<ProverConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a)
            }
            Self::Add(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a),
            Self::Mul(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a),
            Self::Dynamic(a) => {
                Air::<ProverConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a)
            }
        }
    }

    fn get_lookups(
        &mut self,
    ) -> Vec<Lookup<<ProverConstraintFolderWithLookups<'a, SC> as AirBuilder>::F>> {
        match self {
            Self::Witness(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
            Self::Const(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
            Self::Public(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
            Self::Add(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
            Self::Mul(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
            Self::Dynamic(a) => Air::<ProverConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
        }
    }
}

impl<'a, SC, const D: usize> Air<VerifierConstraintFolderWithLookups<'a, SC>>
    for CircuitTableAir<SC, D>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    fn eval(&self, builder: &mut VerifierConstraintFolderWithLookups<'a, SC>) {
        match self {
            Self::Witness(a) => {
                Air::<VerifierConstraintFolderWithLookups<'a, SC>>::eval(a, builder);
            }
            Self::Const(a) => Air::<VerifierConstraintFolderWithLookups<'a, SC>>::eval(a, builder),
            Self::Public(a) => Air::<VerifierConstraintFolderWithLookups<'a, SC>>::eval(a, builder),
            Self::Add(a) => Air::<VerifierConstraintFolderWithLookups<'a, SC>>::eval(a, builder),
            Self::Mul(a) => Air::<VerifierConstraintFolderWithLookups<'a, SC>>::eval(a, builder),
            Self::Dynamic(a) => {
                Air::<VerifierConstraintFolderWithLookups<'a, SC>>::eval(a, builder);
            }
        }
    }

    fn add_lookup_columns(&mut self) -> Vec<usize> {
        match self {
            Self::Witness(a) => {
                Air::<VerifierConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a)
            }
            Self::Const(a) => {
                Air::<VerifierConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a)
            }
            Self::Public(a) => {
                Air::<VerifierConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a)
            }
            Self::Add(a) => {
                Air::<VerifierConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a)
            }
            Self::Mul(a) => {
                Air::<VerifierConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a)
            }
            Self::Dynamic(a) => {
                Air::<VerifierConstraintFolderWithLookups<'a, SC>>::add_lookup_columns(a)
            }
        }
    }

    fn get_lookups(
        &mut self,
    ) -> Vec<Lookup<<VerifierConstraintFolderWithLookups<'a, SC> as AirBuilder>::F>> {
        match self {
            Self::Witness(a) => Air::<VerifierConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
            Self::Const(a) => Air::<VerifierConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
            Self::Public(a) => Air::<VerifierConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
            Self::Add(a) => Air::<VerifierConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
            Self::Mul(a) => Air::<VerifierConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
            Self::Dynamic(a) => Air::<VerifierConstraintFolderWithLookups<'a, SC>>::get_lookups(a),
        }
    }
}

impl<SC> BatchStarkProver<SC>
where
    SC: StarkGenericConfig + 'static,
    Val<SC>: StarkField,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    pub fn new(config: SC) -> Self {
        Self {
            config,
            table_packing: TablePacking::default(),
            non_primitive_provers: Vec::new(),
        }
    }

    #[must_use]
    pub const fn with_table_packing(mut self, table_packing: TablePacking) -> Self {
        self.table_packing = table_packing;
        self
    }

    /// Register a dynamic non-primitive table prover.
    pub fn register_table_prover(&mut self, prover: Box<dyn TableProver<SC>>) {
        self.non_primitive_provers.push(prover);
    }

    /// Builder-style registration for a dynamic non-primitive table prover.
    #[must_use]
    pub fn with_table_prover(mut self, prover: Box<dyn TableProver<SC>>) -> Self {
        self.register_table_prover(prover);
        self
    }

    /// Register the non-primitive Poseidon2 prover plugin with the given configuration.
    pub fn register_poseidon2_table(&mut self, config: Poseidon2Config)
    where
        SC: Send + Sync,
        Val<SC>: BinomiallyExtendable<4>,
    {
        self.register_table_prover(Box::new(Poseidon2Prover::new(config)));
    }

    #[inline]
    pub const fn table_packing(&self) -> TablePacking {
        self.table_packing
    }

    /// Generate a unified batch STARK proof for all circuit tables.
    #[instrument(skip_all)]
    pub fn prove_all_tables<EF>(
        &self,
        traces: &Traces<EF>,
        circuit_prover_data: &CircuitProverData<SC>,
    ) -> Result<BatchStarkProof<SC>, BatchStarkProverError>
    where
        EF: Field + BasedVectorSpace<Val<SC>> + ExtractBinomialW<Val<SC>>,
        SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
    {
        let w_opt = EF::extract_w();
        match EF::DIMENSION {
            1 => self.prove::<EF, 1>(traces, None, circuit_prover_data),
            2 => self.prove::<EF, 2>(traces, w_opt, circuit_prover_data),
            4 => self.prove::<EF, 4>(traces, w_opt, circuit_prover_data),
            6 => self.prove::<EF, 6>(traces, w_opt, circuit_prover_data),
            8 => self.prove::<EF, 8>(traces, w_opt, circuit_prover_data),
            d => Err(BatchStarkProverError::UnsupportedDegree(d)),
        }
    }

    /// Verify the unified batch STARK proof against all tables.
    pub fn verify_all_tables(
        &self,
        proof: &BatchStarkProof<SC>,
        common: &CommonData<SC>,
    ) -> Result<(), BatchStarkProverError> {
        match proof.ext_degree {
            1 => self.verify::<1>(proof, None, common),
            2 => self.verify::<2>(proof, proof.w_binomial, common),
            4 => self.verify::<4>(proof, proof.w_binomial, common),
            6 => self.verify::<6>(proof, proof.w_binomial, common),
            8 => self.verify::<8>(proof, proof.w_binomial, common),
            d => Err(BatchStarkProverError::UnsupportedDegree(d)),
        }
    }

    /// Generate a batch STARK proof for a specific extension field degree.
    ///
    /// This is the core proving logic that handles all circuit tables for a given
    /// extension field dimension. It constructs AIRs, converts traces to matrices,
    /// and generates the unified proof.
    fn prove<EF, const D: usize>(
        &self,
        traces: &Traces<EF>,
        w_binomial: Option<Val<SC>>,
        circuit_prover_data: &CircuitProverData<SC>,
    ) -> Result<BatchStarkProof<SC>, BatchStarkProverError>
    where
        EF: Field + BasedVectorSpace<Val<SC>>,
    {
        let PreprocessedColumns {
            primitive,
            non_primitive: _,
        } = &circuit_prover_data.preprocessed_columns;
        let prover_data = &circuit_prover_data.prover_data;

        // Build matrices and AIRs per table.
        let packing = self.table_packing;
        let witness_lanes = packing.witness_lanes();
        let min_height = packing.min_trace_height();

        // Check if Add/Mul tables have only dummy operations (trace length <= 1).
        // The table implementation adds a dummy row when empty, so we check for <= 1.
        // Using lanes > 1 with only dummy operations causes issues in recursive verification
        // due to a bug in how multi-lane padding interacts with lookup constraints.
        // We automatically reduce lanes to 1 in these cases with a warning.
        //
        // The trace length check is more reliable than checking preprocessed width because
        // the circuit tables add dummy rows to avoid empty traces.
        let add_trace_only_dummy = traces.add_trace.lhs_values.len() <= 1;
        let mul_trace_only_dummy = traces.mul_trace.lhs_values.len() <= 1;

        let add_lanes = if add_trace_only_dummy && packing.add_lanes() > 1 {
            tracing::warn!(
                "Add table has only dummy operations but add_lanes={} > 1. Reducing to \
                 add_lanes=1 to avoid recursive verification issues. Consider using \
                 add_lanes=1 when no additions are expected.",
                packing.add_lanes()
            );
            1
        } else {
            packing.add_lanes()
        };

        let mul_lanes = if mul_trace_only_dummy && packing.mul_lanes() > 1 {
            tracing::warn!(
                "Mul table has only dummy operations but mul_lanes={} > 1. Reducing to \
                 mul_lanes=1 to avoid recursive verification issues. Consider using \
                 mul_lanes=1 when no multiplications are expected.",
                packing.mul_lanes()
            );
            1
        } else {
            packing.mul_lanes()
        };

        TraceLengths::from_traces(traces, packing).log();

        // Witness
        let witness_rows = traces.witness_trace.num_rows();
        let witness_multiplicities = primitive[PrimitiveOpType::Witness as usize].clone();
        let witness_air = WitnessAir::<Val<SC>, D>::new_with_preprocessed(
            witness_rows,
            witness_lanes,
            witness_multiplicities,
        )
        .with_min_height(min_height);
        let witness_matrix: RowMajorMatrix<Val<SC>> =
            WitnessAir::<Val<SC>, D>::trace_to_matrix(&traces.witness_trace, witness_lanes);

        // Const
        let const_rows = traces.const_trace.values.len();
        let const_prep = primitive[PrimitiveOpType::Const as usize].clone();
        let const_air = ConstAir::<Val<SC>, D>::new_with_preprocessed(const_rows, const_prep)
            .with_min_height(min_height);
        let const_matrix: RowMajorMatrix<Val<SC>> =
            ConstAir::<Val<SC>, D>::trace_to_matrix(&traces.const_trace);

        // Public
        // Similar to Add/Mul, reduce lanes to 1 if the table has only dummy operations.
        let public_trace_only_dummy = traces.public_trace.values.len() <= 1;
        let public_lanes = if public_trace_only_dummy && packing.public_lanes() > 1 {
            tracing::warn!(
                "Public table has only dummy operations but public_lanes={} > 1. Reducing to \
                 public_lanes=1 to avoid recursive verification issues. Consider using \
                 public_lanes=1 when few public inputs are expected.",
                packing.public_lanes()
            );
            1
        } else {
            packing.public_lanes()
        };

        let public_rows = traces.public_trace.values.len();
        let public_prep = primitive[PrimitiveOpType::Public as usize].clone();
        let public_air =
            PublicAir::<Val<SC>, D>::new_with_preprocessed(public_rows, public_lanes, public_prep)
                .with_min_height(min_height);
        let public_matrix: RowMajorMatrix<Val<SC>> =
            PublicAir::<Val<SC>, D>::trace_to_matrix(&traces.public_trace, public_lanes);

        // Add
        // When the Add trace is empty, we add a dummy operation to match
        // what get_airs_and_degrees_with_prep does for the CommonData preprocessed commitment.
        // This ensures the prover's AIR.preprocessed_trace() matches the committed data.
        let add_rows = traces.add_trace.lhs_values.len();
        let (add_rows, add_prep) = if add_rows == 0 {
            // Add dummy operation with indices [0, 0, 0]
            let dummy_prep =
                vec![Val::<SC>::ZERO; AddAir::<Val<SC>, D>::preprocessed_lane_width() - 1];
            (1, dummy_prep)
        } else {
            (add_rows, primitive[PrimitiveOpType::Add as usize].clone())
        };
        let add_air = AddAir::<Val<SC>, D>::new_with_preprocessed(add_rows, add_lanes, add_prep)
            .with_min_height(min_height);
        let add_matrix: RowMajorMatrix<Val<SC>> =
            AddAir::<Val<SC>, D>::trace_to_matrix(&traces.add_trace, add_lanes);

        // Mul
        // When the Mul trace is empty, we add a dummy operation to match
        // what get_airs_and_degrees_with_prep does for the CommonData preprocessed commitment.
        // This ensures the prover's AIR.preprocessed_trace() matches the committed data.
        let mul_rows = traces.mul_trace.lhs_values.len();
        let (mul_rows, mul_prep) = if mul_rows == 0 {
            // Add dummy operation with indices [0, 0, 0]
            let dummy_prep =
                vec![Val::<SC>::ZERO; MulAir::<Val<SC>, D>::preprocessed_lane_width() - 1];
            (1, dummy_prep)
        } else {
            (mul_rows, primitive[PrimitiveOpType::Mul as usize].clone())
        };
        let mul_air: MulAir<Val<SC>, D> = if D == 1 {
            MulAir::<Val<SC>, D>::new_with_preprocessed(mul_rows, mul_lanes, mul_prep)
                .with_min_height(min_height)
        } else {
            let w = w_binomial.ok_or(BatchStarkProverError::MissingWForExtension)?;
            MulAir::<Val<SC>, D>::new_binomial_with_preprocessed(mul_rows, mul_lanes, w, mul_prep)
                .with_min_height(min_height)
        };
        let mul_matrix: RowMajorMatrix<Val<SC>> =
            MulAir::<Val<SC>, D>::trace_to_matrix(&traces.mul_trace, mul_lanes);

        TraceLengths::from_traces(traces, packing).log();

        // We first handle all non-primitive tables dynamically, which will then be batched alongside primitive ones.
        // Each trace must have a corresponding registered prover for it to be provable.
        for (&op_type, trace) in &traces.non_primitive_traces {
            if trace.rows() == 0 {
                continue;
            }
            if !self
                .non_primitive_provers
                .iter()
                .any(|p| p.op_type() == op_type)
            {
                return Err(BatchStarkProverError::MissingTableProver(op_type));
            }
        }

        let mut dynamic_instances: Vec<BatchTableInstance<SC>> = Vec::new();
        if D == 1 {
            let t: &Traces<Val<SC>> = unsafe { transmute_traces(traces) };
            for p in &self.non_primitive_provers {
                if let Some(instance) = p.batch_instance_d1(&self.config, packing, t) {
                    dynamic_instances.push(instance);
                }
            }
        } else if D == 2 {
            type EF2<F> = BinomialExtensionField<F, 2>;
            let t: &Traces<EF2<Val<SC>>> = unsafe { transmute_traces(traces) };
            for p in &self.non_primitive_provers {
                if let Some(instance) = p.batch_instance_d2(&self.config, packing, t) {
                    dynamic_instances.push(instance);
                }
            }
        } else if D == 4 {
            type EF4<F> = BinomialExtensionField<F, 4>;
            let t: &Traces<EF4<Val<SC>>> = unsafe { transmute_traces(traces) };
            for p in &self.non_primitive_provers {
                if let Some(instance) = p.batch_instance_d4(&self.config, packing, t) {
                    dynamic_instances.push(instance);
                }
            }
        } else if D == 6 {
            type EF6<F> = BinomialExtensionField<F, 6>;
            let t: &Traces<EF6<Val<SC>>> = unsafe { transmute_traces(traces) };
            for p in &self.non_primitive_provers {
                if let Some(instance) = p.batch_instance_d6(&self.config, packing, t) {
                    dynamic_instances.push(instance);
                }
            }
        } else if D == 8 {
            type EF8<F> = BinomialExtensionField<F, 8>;
            let t: &Traces<EF8<Val<SC>>> = unsafe { transmute_traces(traces) };
            for p in &self.non_primitive_provers {
                if let Some(instance) = p.batch_instance_d8(&self.config, packing, t) {
                    dynamic_instances.push(instance);
                }
            }
        }

        // Wrap AIRs in enum for heterogeneous batching and build instances in fixed order.
        // TODO: Support public values for tables
        let mut air_storage: Vec<CircuitTableAir<SC, D>> =
            Vec::with_capacity(NUM_PRIMITIVE_TABLES + dynamic_instances.len());
        let mut trace_storage: Vec<RowMajorMatrix<Val<SC>>> =
            Vec::with_capacity(NUM_PRIMITIVE_TABLES + dynamic_instances.len());
        let mut public_storage: Vec<Vec<Val<SC>>> =
            Vec::with_capacity(NUM_PRIMITIVE_TABLES + dynamic_instances.len());
        let mut non_primitives: Vec<NonPrimitiveTableEntry<SC>> =
            Vec::with_capacity(dynamic_instances.len());

        // Pad all trace matrices to at least min_height (for FRI compatibility)
        air_storage.push(CircuitTableAir::Witness(witness_air));
        trace_storage.push(pad_matrix_to_min_height(witness_matrix, min_height));
        public_storage.push(Vec::new());

        air_storage.push(CircuitTableAir::Const(const_air));
        trace_storage.push(pad_matrix_to_min_height(const_matrix, min_height));
        public_storage.push(Vec::new());

        air_storage.push(CircuitTableAir::Public(public_air));
        trace_storage.push(pad_matrix_to_min_height(public_matrix, min_height));
        public_storage.push(Vec::new());

        air_storage.push(CircuitTableAir::Add(add_air));
        trace_storage.push(pad_matrix_to_min_height(add_matrix, min_height));
        public_storage.push(Vec::new());

        air_storage.push(CircuitTableAir::Mul(mul_air));
        trace_storage.push(pad_matrix_to_min_height(mul_matrix, min_height));
        public_storage.push(Vec::new());

        for instance in dynamic_instances {
            let BatchTableInstance {
                op_type,
                air,
                trace,
                public_values,
                rows,
            } = instance;
            air_storage.push(CircuitTableAir::Dynamic(air));
            trace_storage.push(pad_matrix_to_min_height(trace, min_height));
            public_storage.push(public_values.clone());
            non_primitives.push(NonPrimitiveTableEntry {
                op_type,
                rows,
                public_values,
            });
        }

        let instances: Vec<StarkInstance<'_, SC, CircuitTableAir<SC, D>>> = air_storage
            .iter_mut()
            .zip(trace_storage)
            .zip(public_storage)
            .map(|((air, trace), public_values)| {
                let lookups = Air::<SymbolicAirBuilder<Val<SC>, SC::Challenge>>::get_lookups(air);

                StarkInstance {
                    air,
                    trace,
                    public_values,
                    lookups,
                }
            })
            .collect();

        let proof = p3_batch_stark::prove_batch(&self.config, &instances, prover_data);

        // Ensure all primitive table row counts are at least 1
        // RowCounts::new requires non-zero counts, so pad zeros to 1
        let witness_rows_padded = witness_rows.max(1);
        let const_rows_padded = const_rows.max(1);
        let public_rows_padded = public_rows.max(1);
        let add_rows_padded = add_rows.max(1);
        let mul_rows_padded = mul_rows.max(1);

        // Store the effective packing (with reduced lanes if applicable) so the verifier
        // uses the same configuration that was actually used during proving.
        let effective_packing =
            TablePacking::new(witness_lanes, public_lanes, add_lanes, mul_lanes)
                .with_min_trace_height(min_height);

        Ok(BatchStarkProof {
            proof,
            table_packing: effective_packing,
            rows: RowCounts::new([
                witness_rows_padded,
                const_rows_padded,
                public_rows_padded,
                add_rows_padded,
                mul_rows_padded,
            ]),
            ext_degree: D,
            w_binomial: if D > 1 { w_binomial } else { None },
            non_primitives,
        })
    }

    /// Verify a batch STARK proof for a specific extension field degree.
    ///
    /// This reconstructs the AIRs from the proof metadata and verifies the proof
    /// against all circuit tables. The AIRs are reconstructed using the same
    /// configuration that was used during proof generation.
    fn verify<const D: usize>(
        &self,
        proof: &BatchStarkProof<SC>,
        w_binomial: Option<Val<SC>>,
        common: &CommonData<SC>,
    ) -> Result<(), BatchStarkProverError> {
        // Rebuild AIRs in the same order as prove.
        let packing = proof.table_packing;
        let witness_lanes = packing.witness_lanes();
        let public_lanes = packing.public_lanes();
        let add_lanes = packing.add_lanes();
        let mul_lanes = packing.mul_lanes();
        let min_height = packing.min_trace_height();

        let witness_air = CircuitTableAir::Witness(
            WitnessAir::<Val<SC>, D>::new(proof.rows[PrimitiveTable::Witness], witness_lanes)
                .with_min_height(min_height),
        );
        let const_air = CircuitTableAir::Const(
            ConstAir::<Val<SC>, D>::new(proof.rows[PrimitiveTable::Const])
                .with_min_height(min_height),
        );
        let public_air = CircuitTableAir::Public(
            PublicAir::<Val<SC>, D>::new(proof.rows[PrimitiveTable::Public], public_lanes)
                .with_min_height(min_height),
        );
        let add_air = CircuitTableAir::Add(
            AddAir::<Val<SC>, D>::new(proof.rows[PrimitiveTable::Add], add_lanes)
                .with_min_height(min_height),
        );
        let mul_air: CircuitTableAir<SC, D> = if D == 1 {
            CircuitTableAir::Mul(
                MulAir::<Val<SC>, D>::new(proof.rows[PrimitiveTable::Mul], mul_lanes)
                    .with_min_height(min_height),
            )
        } else {
            let w = w_binomial.ok_or(BatchStarkProverError::MissingWForExtension)?;
            CircuitTableAir::Mul(
                MulAir::<Val<SC>, D>::new_binomial(proof.rows[PrimitiveTable::Mul], mul_lanes, w)
                    .with_min_height(min_height),
            )
        };
        let mut airs = vec![witness_air, const_air, public_air, add_air, mul_air];
        // TODO: Handle public values.
        let mut pvs: Vec<Vec<Val<SC>>> = vec![Vec::new(); NUM_PRIMITIVE_TABLES];

        for entry in &proof.non_primitives {
            let plugin = self
                .non_primitive_provers
                .iter()
                .find(|p| {
                    let tp = p.as_ref();
                    TableProver::op_type(tp) == entry.op_type
                })
                .ok_or_else(|| {
                    BatchStarkProverError::Verify(format!(
                        "unknown non-primitive op: {:?}",
                        entry.op_type
                    ))
                })?;
            let air = plugin
                .batch_air_from_table_entry(&self.config, D, entry)
                .map_err(BatchStarkProverError::Verify)?;
            airs.push(CircuitTableAir::Dynamic(air));
            pvs.push(entry.public_values.clone());
        }

        p3_batch_stark::verify_batch(&self.config, &airs, &proof.proof, &pvs, common)
            .map_err(|e| BatchStarkProverError::Verify(format!("{e:?}")))
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_circuit::builder::CircuitBuilder;
    use p3_field::PrimeCharacteristicRing;
    use p3_goldilocks::Goldilocks;
    use p3_koala_bear::KoalaBear;

    use super::*;
    use crate::common::get_airs_and_degrees_with_prep;
    use crate::config::{self, BabyBearConfig, GoldilocksConfig, KoalaBearConfig};

    #[test]
    fn test_babybear_batch_stark_base_field() {
        let mut builder = CircuitBuilder::<BabyBear>::new();

        // x + 5*2 - 3 + (-1) == expected
        let x = builder.add_public_input();
        let expected = builder.add_public_input();
        let c5 = builder.add_const(BabyBear::from_u64(5));
        let c2 = builder.add_const(BabyBear::from_u64(2));
        let c3 = builder.add_const(BabyBear::from_u64(3));
        let neg_one = builder.add_const(BabyBear::NEG_ONE);

        let mul_result = builder.mul(c5, c2); // 10
        let add_result = builder.add(x, mul_result); // x + 10
        let sub_result = builder.sub(add_result, c3); // x + 7
        let final_result = builder.add(sub_result, neg_one); // x + 6

        let diff = builder.sub(final_result, expected);
        builder.assert_zero(diff);

        let circuit = builder.build().unwrap();
        let cfg = config::baby_bear().build();
        let (airs_degrees, preprocessed_columns) =
            get_airs_and_degrees_with_prep::<BabyBearConfig, _, 1>(
                &circuit,
                TablePacking::default(),
                None,
            )
            .unwrap();
        let (mut airs, log_degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let prover_data = ProverData::from_airs_and_degrees(&cfg, &mut airs, &log_degrees);
        let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);

        let mut runner = circuit.runner();

        let x_val = BabyBear::from_u64(7);
        let expected_val = BabyBear::from_u64(13); // 7 + 10 - 3 - 1 = 13
        runner.set_public_inputs(&[x_val, expected_val]).unwrap();
        let traces = runner.run().unwrap();

        let prover = BatchStarkProver::new(cfg);

        let proof = prover
            .prove_all_tables(&traces, &circuit_prover_data)
            .unwrap();
        assert_eq!(proof.ext_degree, 1);
        assert!(proof.w_binomial.is_none());

        assert!(
            prover
                .verify_all_tables(&proof, circuit_prover_data.common_data())
                .is_ok()
        );
    }

    #[test]
    fn test_table_lookups() {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let cfg = config::baby_bear().build();

        // x + 5*2 - 3 + (-1) == expected
        let x = builder.add_public_input();
        let expected = builder.add_public_input();
        let c5 = builder.add_const(BabyBear::from_u64(5));
        let c2 = builder.add_const(BabyBear::from_u64(2));
        let c3 = builder.add_const(BabyBear::from_u64(3));
        let neg_one = builder.add_const(BabyBear::NEG_ONE);

        let mul_result = builder.mul(c5, c2); // 10
        let add_result = builder.add(x, mul_result); // x + 10
        let sub_result = builder.sub(add_result, c3); // x + 7
        let final_result = builder.add(sub_result, neg_one); // x + 6

        let diff = builder.sub(final_result, expected);
        builder.assert_zero(diff);

        let circuit = builder.build().unwrap();
        let default_packing = TablePacking::default();
        let (airs_degrees, preprocessed_columns) =
            get_airs_and_degrees_with_prep::<BabyBearConfig, _, 1>(&circuit, default_packing, None)
                .unwrap();
        let (mut airs, log_degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

        // Check that the multiplicities of `WitnessAir` are computed correctly.
        // We can count the number of times the witness addresses appear in the various tables. We get:
        let mut expected_multiplicities = vec![BabyBear::from_u64(2); 11];
        // Pad multiplicities.
        let total_witness_length = (expected_multiplicities
            .len()
            .div_ceil(default_packing.witness_lanes()))
        .next_power_of_two()
            * default_packing.witness_lanes();
        expected_multiplicities.resize(total_witness_length, BabyBear::ZERO);

        // Get expected preprocessed trace for `WitnessAir`.
        let expected_preprocessed_trace = RowMajorMatrix::new(
            expected_multiplicities
                .iter()
                .enumerate()
                .flat_map(|(i, m)| vec![*m, BabyBear::from_usize(i)])
                .collect::<Vec<_>>(),
            2 * TablePacking::default().witness_lanes(),
        );
        assert_eq!(
            airs[0]
                .preprocessed_trace()
                .expect("Witness table should have preprocessed trace"),
            expected_preprocessed_trace,
            "witness_multiplicities {:?} expected {:?}",
            airs[0].preprocessed_trace(),
            expected_preprocessed_trace,
        );

        let mut runner = circuit.runner();

        let x_val = BabyBear::from_u64(7);
        let expected_val = BabyBear::from_u64(13); // 7 + 10 - 3 - 1 = 13
        runner.set_public_inputs(&[x_val, expected_val]).unwrap();
        let traces = runner.run().unwrap();
        let prover_data = ProverData::from_airs_and_degrees(&cfg, &mut airs, &log_degrees);
        let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);

        let prover = BatchStarkProver::new(cfg);

        let proof = prover
            .prove_all_tables(&traces, &circuit_prover_data)
            .unwrap();
        assert_eq!(proof.ext_degree, 1);
        assert!(proof.w_binomial.is_none());

        assert!(
            prover
                .verify_all_tables(&proof, circuit_prover_data.common_data())
                .is_ok()
        );

        // Check that the generated lookups are correct and consistent across tables.
        for air in airs.iter_mut() {
            let lookups = Air::<
                SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
            >::get_lookups(air);

            match air {
                CircuitTableAir::Witness(_) => {
                    assert_eq!(
                        lookups.len(),
                        default_packing.witness_lanes(),
                        "Witness table should have {} lookups, found {}",
                        default_packing.witness_lanes(),
                        lookups.len()
                    );
                }
                CircuitTableAir::Const(_) => {
                    assert_eq!(lookups.len(), 1, "Const table should have one lookup");
                }
                CircuitTableAir::Public(_) => {
                    assert_eq!(lookups.len(), 1, "Public table should have one lookup");
                }
                CircuitTableAir::Add(_) => {
                    let expected_num_lookups =
                        default_packing.add_lanes() * AddAir::<BabyBear, 1>::lane_width();
                    assert_eq!(
                        lookups.len(),
                        expected_num_lookups,
                        "Add table should have {} lookups, found {}",
                        expected_num_lookups,
                        lookups.len()
                    );
                }
                CircuitTableAir::Mul(_) => {
                    let expected_num_lookups =
                        default_packing.mul_lanes() * MulAir::<BabyBear, 1>::lane_width();
                    assert_eq!(
                        lookups.len(),
                        expected_num_lookups,
                        "Mul table should have {} lookups, found {}",
                        expected_num_lookups,
                        lookups.len()
                    );
                }
                CircuitTableAir::Dynamic(_dynamic_air) => {
                    assert!(
                        lookups.is_empty(),
                        "There is no dynamic table in this test, so no lookups expected"
                    );
                }
            }
        }
    }

    #[test]
    fn test_extension_field_batch_stark() {
        const D: usize = 4;
        type Ext4 = BinomialExtensionField<BabyBear, D>;
        let cfg = config::baby_bear().build();

        let mut builder = CircuitBuilder::<Ext4>::new();
        let x = builder.add_public_input();
        let y = builder.add_public_input();
        let z = builder.add_public_input();
        let expected = builder.add_public_input();
        let xy = builder.mul(x, y);
        let res = builder.add(xy, z);
        let diff = builder.sub(res, expected);
        builder.assert_zero(diff);

        let circuit = builder.build().unwrap();
        let (airs_degrees, preprocessed_columns) =
            get_airs_and_degrees_with_prep::<BabyBearConfig, _, D>(
                &circuit,
                TablePacking::default(),
                None,
            )
            .unwrap();
        let (mut airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

        let mut runner = circuit.runner();
        let xv = Ext4::from_basis_coefficients_slice(&[
            BabyBear::from_u64(2),
            BabyBear::from_u64(3),
            BabyBear::from_u64(5),
            BabyBear::from_u64(7),
        ])
        .unwrap();
        let yv = Ext4::from_basis_coefficients_slice(&[
            BabyBear::from_u64(11),
            BabyBear::from_u64(13),
            BabyBear::from_u64(17),
            BabyBear::from_u64(19),
        ])
        .unwrap();
        let zv = Ext4::from_basis_coefficients_slice(&[
            BabyBear::from_u64(23),
            BabyBear::from_u64(29),
            BabyBear::from_u64(31),
            BabyBear::from_u64(37),
        ])
        .unwrap();
        let expected_v = xv * yv + zv;
        runner.set_public_inputs(&[xv, yv, zv, expected_v]).unwrap();
        let traces = runner.run().unwrap();

        let prover_data = ProverData::from_airs_and_degrees(&cfg, &mut airs, &degrees);
        let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);
        let prover = BatchStarkProver::new(cfg);

        let proof = prover
            .prove_all_tables(&traces, &circuit_prover_data)
            .unwrap();
        assert_eq!(proof.ext_degree, 4);
        // Ensure W was captured
        let expected_w = <Ext4 as ExtractBinomialW<BabyBear>>::extract_w().unwrap();
        assert_eq!(proof.w_binomial, Some(expected_w));
        prover
            .verify_all_tables(&proof, circuit_prover_data.common_data())
            .unwrap();
    }

    #[test]
    fn test_extension_field_table_lookups() {
        const D: usize = 4;
        type Ext4 = BinomialExtensionField<BabyBear, D>;
        let cfg = config::baby_bear().build();

        let mut builder = CircuitBuilder::<Ext4>::new();
        let x = builder.add_public_input();
        let y = builder.add_public_input();
        let z = builder.add_public_input();
        let expected = builder.add_public_input();
        let xy = builder.mul(x, y);
        let res = builder.add(xy, z);
        let diff = builder.sub(res, expected);
        builder.assert_zero(diff);

        let circuit = builder.build().unwrap();
        let default_packing = TablePacking::default();
        let (airs_degrees, preprocessed_columns) =
            get_airs_and_degrees_with_prep::<BabyBearConfig, _, D>(&circuit, default_packing, None)
                .unwrap();
        let (mut airs, log_degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

        // Check that the multiplicities of `WitnessAir` are computed correctly.
        // We can count the number of times the witness addresses appear in the various tables. We get:
        let mut expected_multiplicities = vec![BabyBear::from_u64(2); 7];
        // Pad multiplicities.
        let total_witness_length = (expected_multiplicities
            .len()
            .div_ceil(default_packing.witness_lanes()))
        .next_power_of_two()
            * default_packing.witness_lanes();
        expected_multiplicities.resize(total_witness_length, BabyBear::ZERO);

        // Get expected preprocessed trace for `WitnessAir`.
        let expected_preprocessed_trace = RowMajorMatrix::new(
            expected_multiplicities
                .iter()
                .enumerate()
                .flat_map(|(i, m)| vec![*m, BabyBear::from_usize(i)])
                .collect::<Vec<_>>(),
            2 * TablePacking::default().witness_lanes(),
        );

        assert_eq!(
            airs[0]
                .preprocessed_trace()
                .expect("Witness table should have preprocessed trace"),
            expected_preprocessed_trace,
            "witness_multiplicities {:?} expected {:?}",
            airs[0].preprocessed_trace(),
            expected_preprocessed_trace,
        );

        let mut runner = circuit.runner();

        let xv = Ext4::from_basis_coefficients_slice(&[
            BabyBear::from_u64(2),
            BabyBear::from_u64(3),
            BabyBear::from_u64(5),
            BabyBear::from_u64(7),
        ])
        .unwrap();
        let yv = Ext4::from_basis_coefficients_slice(&[
            BabyBear::from_u64(11),
            BabyBear::from_u64(13),
            BabyBear::from_u64(17),
            BabyBear::from_u64(19),
        ])
        .unwrap();
        let zv = Ext4::from_basis_coefficients_slice(&[
            BabyBear::from_u64(23),
            BabyBear::from_u64(29),
            BabyBear::from_u64(31),
            BabyBear::from_u64(37),
        ])
        .unwrap();
        let expected_v = xv * yv + zv;
        runner.set_public_inputs(&[xv, yv, zv, expected_v]).unwrap();
        let traces = runner.run().unwrap();

        let prover_data = ProverData::from_airs_and_degrees(&cfg, &mut airs, &log_degrees);
        let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);

        let prover = BatchStarkProver::new(cfg);

        let proof = prover
            .prove_all_tables(&traces, &circuit_prover_data)
            .unwrap();
        assert_eq!(proof.ext_degree, 4);
        // Ensure W was captured
        let expected_w = <Ext4 as ExtractBinomialW<BabyBear>>::extract_w().unwrap();
        assert_eq!(proof.w_binomial, Some(expected_w));

        assert!(
            prover
                .verify_all_tables(&proof, circuit_prover_data.common_data())
                .is_ok()
        );

        // Check that the generated lookups are correct and consistent across tables.
        for air in airs.iter_mut() {
            let lookups = Air::<
                SymbolicAirBuilder<BabyBear, BinomialExtensionField<BabyBear, 4>>,
            >::get_lookups(air);

            match air {
                CircuitTableAir::Witness(_) => {
                    assert_eq!(
                        lookups.len(),
                        default_packing.witness_lanes(),
                        "Witness table should have {} lookups, found {}",
                        default_packing.witness_lanes(),
                        lookups.len()
                    );
                }
                CircuitTableAir::Const(_) => {
                    assert_eq!(lookups.len(), 1, "Const table should have one lookup");
                }
                CircuitTableAir::Public(_) => {
                    assert_eq!(lookups.len(), 1, "Public table should have one lookup");
                }
                CircuitTableAir::Add(_) => {
                    let expected_num_lookups =
                        default_packing.add_lanes() * AddAir::<BabyBear, 1>::lane_width();
                    assert_eq!(
                        lookups.len(),
                        expected_num_lookups,
                        "Add table should have {} lookups, found {}",
                        expected_num_lookups,
                        lookups.len()
                    );
                }
                CircuitTableAir::Mul(_) => {
                    let expected_num_lookups =
                        default_packing.mul_lanes() * MulAir::<BabyBear, 1>::lane_width();
                    assert_eq!(
                        lookups.len(),
                        expected_num_lookups,
                        "Mul table should have {} lookups, found {}",
                        expected_num_lookups,
                        lookups.len()
                    );
                }
                CircuitTableAir::Dynamic(_dynamic_air) => {
                    assert!(
                        lookups.is_empty(),
                        "There is no dynamic table in this test, so no lookups expected"
                    );
                }
            }
        }
    }

    #[test]
    fn test_koalabear_batch_stark_base_field() {
        let mut builder = CircuitBuilder::<KoalaBear>::new();
        let cfg = config::koala_bear().build();

        // a * b + 100 - (-1) == expected
        let a = builder.add_public_input();
        let b = builder.add_public_input();
        let expected = builder.add_public_input();
        let c = builder.add_const(KoalaBear::from_u64(100));
        let d = builder.add_const(KoalaBear::NEG_ONE);

        let ab = builder.mul(a, b);
        let add = builder.add(ab, c);
        let final_res = builder.sub(add, d);
        let diff = builder.sub(final_res, expected);
        builder.assert_zero(diff);

        let circuit = builder.build().unwrap();
        let (airs_degrees, preprocessed_columns) =
            get_airs_and_degrees_with_prep::<KoalaBearConfig, _, 1>(
                &circuit,
                TablePacking::default(),
                None,
            )
            .unwrap();
        let (mut airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let mut runner = circuit.runner();

        let a_val = KoalaBear::from_u64(42);
        let b_val = KoalaBear::from_u64(13);
        let expected_val = KoalaBear::from_u64(647); // 42*13 + 100 - (-1)
        runner
            .set_public_inputs(&[a_val, b_val, expected_val])
            .unwrap();
        let traces = runner.run().unwrap();

        let prover_data = ProverData::from_airs_and_degrees(&cfg, &mut airs, &degrees);
        let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);
        let prover = BatchStarkProver::new(cfg);

        let proof = prover
            .prove_all_tables(&traces, &circuit_prover_data)
            .unwrap();
        assert_eq!(proof.ext_degree, 1);
        assert!(proof.w_binomial.is_none());
        prover
            .verify_all_tables(&proof, circuit_prover_data.common_data())
            .unwrap();
    }

    #[test]
    fn test_koalabear_batch_stark_extension_field_d8() {
        const D: usize = 8;
        type KBExtField = BinomialExtensionField<KoalaBear, D>;
        let mut builder = CircuitBuilder::<KBExtField>::new();
        let cfg = config::koala_bear().build();

        // x * y * z == expected
        let x = builder.add_public_input();
        let y = builder.add_public_input();
        let expected = builder.add_public_input();
        let z = builder.add_const(
            KBExtField::from_basis_coefficients_slice(&[
                KoalaBear::from_u64(1),
                KoalaBear::NEG_ONE,
                KoalaBear::from_u64(2),
                KoalaBear::from_u64(3),
                KoalaBear::from_u64(4),
                KoalaBear::from_u64(5),
                KoalaBear::from_u64(6),
                KoalaBear::from_u64(7),
            ])
            .unwrap(),
        );

        let xy = builder.mul(x, y);
        let xyz = builder.mul(xy, z);
        let diff = builder.sub(xyz, expected);
        builder.assert_zero(diff);

        let circuit = builder.build().unwrap();
        let (airs_degrees, preprocessed_columns) =
            get_airs_and_degrees_with_prep::<KoalaBearConfig, _, D>(
                &circuit,
                TablePacking::default(),
                None,
            )
            .unwrap();
        let (mut airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let mut runner = circuit.runner();

        let x_val = KBExtField::from_basis_coefficients_slice(&[
            KoalaBear::from_u64(4),
            KoalaBear::from_u64(6),
            KoalaBear::from_u64(8),
            KoalaBear::from_u64(10),
            KoalaBear::from_u64(12),
            KoalaBear::from_u64(14),
            KoalaBear::from_u64(16),
            KoalaBear::from_u64(18),
        ])
        .unwrap();
        let y_val = KBExtField::from_basis_coefficients_slice(&[
            KoalaBear::from_u64(12),
            KoalaBear::from_u64(14),
            KoalaBear::from_u64(16),
            KoalaBear::from_u64(18),
            KoalaBear::from_u64(20),
            KoalaBear::from_u64(22),
            KoalaBear::from_u64(24),
            KoalaBear::from_u64(26),
        ])
        .unwrap();
        let z_val = KBExtField::from_basis_coefficients_slice(&[
            KoalaBear::from_u64(1),
            KoalaBear::NEG_ONE,
            KoalaBear::from_u64(2),
            KoalaBear::from_u64(3),
            KoalaBear::from_u64(4),
            KoalaBear::from_u64(5),
            KoalaBear::from_u64(6),
            KoalaBear::from_u64(7),
        ])
        .unwrap();

        let expected_val = x_val * y_val * z_val;
        runner
            .set_public_inputs(&[x_val, y_val, expected_val])
            .unwrap();
        let traces = runner.run().unwrap();

        let prover_data = ProverData::from_airs_and_degrees(&cfg, &mut airs, &degrees);
        let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);
        let prover = BatchStarkProver::new(cfg);

        let proof = prover
            .prove_all_tables(&traces, &circuit_prover_data)
            .unwrap();
        assert_eq!(proof.ext_degree, 8);
        let expected_w = <KBExtField as ExtractBinomialW<KoalaBear>>::extract_w().unwrap();
        assert_eq!(proof.w_binomial, Some(expected_w));
        prover
            .verify_all_tables(&proof, circuit_prover_data.common_data())
            .unwrap();
    }

    #[test]
    fn test_goldilocks_batch_stark_extension_field_d2() {
        const D: usize = 2;
        type Ext2 = BinomialExtensionField<Goldilocks, D>;
        let mut builder = CircuitBuilder::<Ext2>::new();
        let cfg = config::goldilocks().build();

        // x * y + z == expected
        let x = builder.add_public_input();
        let y = builder.add_public_input();
        let z = builder.add_public_input();
        let expected = builder.add_public_input();

        let xy = builder.mul(x, y);
        let res = builder.add(xy, z);
        let diff = builder.sub(res, expected);
        builder.assert_zero(diff);

        let circuit = builder.build().unwrap();
        let (airs_degrees, preprocessed_columns) =
            get_airs_and_degrees_with_prep::<GoldilocksConfig, _, D>(
                &circuit,
                TablePacking::default(),
                None,
            )
            .unwrap();
        let (mut airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let mut runner = circuit.runner();

        let x_val =
            Ext2::from_basis_coefficients_slice(&[Goldilocks::from_u64(3), Goldilocks::NEG_ONE])
                .unwrap();
        let y_val = Ext2::from_basis_coefficients_slice(&[
            Goldilocks::from_u64(7),
            Goldilocks::from_u64(11),
        ])
        .unwrap();
        let z_val = Ext2::from_basis_coefficients_slice(&[
            Goldilocks::from_u64(13),
            Goldilocks::from_u64(17),
        ])
        .unwrap();
        let expected_val = x_val * y_val + z_val;

        runner
            .set_public_inputs(&[x_val, y_val, z_val, expected_val])
            .unwrap();
        let traces = runner.run().unwrap();

        let prover_data = ProverData::from_airs_and_degrees(&cfg, &mut airs, &degrees);
        let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);
        let prover = BatchStarkProver::new(cfg);

        let proof = prover
            .prove_all_tables(&traces, &circuit_prover_data)
            .unwrap();
        assert_eq!(proof.ext_degree, 2);
        let expected_w = <Ext2 as ExtractBinomialW<Goldilocks>>::extract_w().unwrap();
        assert_eq!(proof.w_binomial, Some(expected_w));
        prover
            .verify_all_tables(&proof, circuit_prover_data.common_data())
            .unwrap();
    }

    #[test]
    fn test_koalabear_modulus_constant() {
        // Verify KOALA_BEAR_MODULUS matches the actual KoalaBear field modulus.
        // The modulus p satisfies: from_u64(p) == 0 in the field.
        assert_eq!(
            KoalaBear::from_u64(KOALA_BEAR_MODULUS),
            KoalaBear::ZERO,
            "KOALA_BEAR_MODULUS (0x{:x}) does not match KoalaBear's actual modulus",
            KOALA_BEAR_MODULUS
        );

        // Verify the exact hex value (2130706433 = 0x7f000001).
        assert_eq!(KOALA_BEAR_MODULUS, 0x7f000001);
        assert_eq!(KOALA_BEAR_MODULUS, 2130706433);

        // Verify arithmetic at the modulus boundary with hardcoded expected values.
        // (p - 1) + 2 = 1 in the field
        let p_minus_1 = KoalaBear::from_u64(KOALA_BEAR_MODULUS - 1);
        assert_eq!(p_minus_1, KoalaBear::NEG_ONE);
        assert_eq!(p_minus_1 + KoalaBear::TWO, KoalaBear::ONE);

        // (p - 1) * (p - 1) = 1 in the field (since (-1) * (-1) = 1)
        assert_eq!(p_minus_1 * p_minus_1, KoalaBear::ONE);

        // Verify from_u64(p + 1) == 1
        assert_eq!(KoalaBear::from_u64(KOALA_BEAR_MODULUS + 1), KoalaBear::ONE);
    }

    #[test]
    fn test_babybear_modulus_constant() {
        // Verify BABY_BEAR_MODULUS matches the actual BabyBear field modulus.
        assert_eq!(
            BabyBear::from_u64(BABY_BEAR_MODULUS),
            BabyBear::ZERO,
            "BABY_BEAR_MODULUS (0x{:x}) does not match BabyBear's actual modulus",
            BABY_BEAR_MODULUS
        );

        // Verify the exact hex value (2013265921 = 0x78000001).
        assert_eq!(BABY_BEAR_MODULUS, 0x78000001);
        assert_eq!(BABY_BEAR_MODULUS, 2013265921);

        // Verify arithmetic at the modulus boundary.
        let p_minus_1 = BabyBear::from_u64(BABY_BEAR_MODULUS - 1);
        assert_eq!(p_minus_1, BabyBear::NEG_ONE);
        assert_eq!(p_minus_1 + BabyBear::TWO, BabyBear::ONE);
        assert_eq!(BabyBear::from_u64(BABY_BEAR_MODULUS + 1), BabyBear::ONE);
    }

    #[test]
    fn test_empty_add_table_padding() {
        // Circuit with only mul operations - add table will have 0 rows and get padded to 1.
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let cfg = config::baby_bear().build();

        let x = builder.add_public_input();
        let y = builder.add_public_input();

        // Only multiplication, no addition
        builder.mul(x, y);

        let circuit = builder.build().unwrap();
        let (airs_degrees, preprocessed_columns) =
            get_airs_and_degrees_with_prep::<BabyBearConfig, _, 1>(
                &circuit,
                TablePacking::default(),
                None,
            )
            .unwrap();
        let (mut airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let mut runner = circuit.runner();

        let x_val = BabyBear::from_u64(7);
        let y_val = BabyBear::from_u64(11);
        runner.set_public_inputs(&[x_val, y_val]).unwrap();
        let traces = runner.run().unwrap();

        let prover_data = ProverData::from_airs_and_degrees(&cfg, &mut airs, &degrees);
        let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);

        let common = circuit_prover_data.common_data();

        let prover = BatchStarkProver::new(cfg);

        let proof = prover
            .prove_all_tables(&traces, &circuit_prover_data)
            .unwrap();
        prover.verify_all_tables(&proof, common).unwrap();
    }

    #[test]
    fn test_empty_mul_table_padding() {
        // Circuit with only add operations - mul table will have 0 rows and get padded to 1.
        let mut builder = CircuitBuilder::<BabyBear>::new();
        let cfg = config::baby_bear().build();

        let x = builder.add_public_input();
        let y = builder.add_public_input();
        let expected = builder.add_public_input();

        // Only addition, no multiplication
        let sum = builder.add(x, y);
        let diff = builder.sub(sum, expected);
        builder.assert_zero(diff);

        let circuit = builder.build().unwrap();
        let (airs_degrees, preprocessed_columns) =
            get_airs_and_degrees_with_prep::<BabyBearConfig, _, 1>(
                &circuit,
                TablePacking::default(),
                None,
            )
            .unwrap();
        let (mut airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let mut runner = circuit.runner();

        let x_val = BabyBear::from_u64(42);
        let y_val = BabyBear::from_u64(13);
        let expected_val = x_val + y_val;
        runner
            .set_public_inputs(&[x_val, y_val, expected_val])
            .unwrap();
        let traces = runner.run().unwrap();

        let prover_data = ProverData::from_airs_and_degrees(&cfg, &mut airs, &degrees);
        let circuit_prover_data = CircuitProverData::new(prover_data, preprocessed_columns);

        let common = circuit_prover_data.common_data();

        let prover = BatchStarkProver::new(cfg);

        let proof = prover
            .prove_all_tables(&traces, &circuit_prover_data)
            .unwrap();
        prover.verify_all_tables(&proof, common).unwrap();
    }
}
