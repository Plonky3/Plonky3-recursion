//! Batch STARK prover and verifier that unifies all circuit tables
//! into a single batched STARK proof using `p3-batch-stark`.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};

use p3_air::{Air, AirBuilder, BaseAir};
#[cfg(debug_assertions)]
use p3_batch_stark::DebugConstraintBuilderWithLookups;
use p3_batch_stark::{BatchProof, CommonData, ProverData, StarkGenericConfig, StarkInstance, Val};
use p3_circuit::PreprocessedColumns;
use p3_circuit::op::{NonPrimitiveOpType, Poseidon2Config, PrimitiveOpType};
use p3_circuit::tables::Traces;
use p3_field::extension::{BinomialExtensionField, BinomiallyExtendable};
use p3_field::{BasedVectorSpace, Field, PrimeCharacteristicRing, PrimeField};
use p3_lookup::folder::{ProverConstraintFolderWithLookups, VerifierConstraintFolderWithLookups};
use p3_lookup::lookup_traits::Lookup;
use p3_matrix::dense::RowMajorMatrix;
use p3_uni_stark::{SymbolicAirBuilder, SymbolicExpression};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tracing::instrument;

use crate::air::{AluAir, ConstAir, PublicAir, WitnessAir};
use crate::batch_stark_prover::dynamic_air::transmute_traces;
use crate::common::CircuitTableAir;
use crate::config::StarkField;
use crate::field_params::ExtractBinomialW;

mod dynamic_air;
mod packing;
mod poseidon2;

pub use dynamic_air::{
    BatchAir, BatchTableInstance, CloneableBatchAir, DynamicAirEntry, TableProver,
};
pub use packing::{TablePacking, TraceLengths};
pub use poseidon2::{
    Poseidon2AirWrapperInner, Poseidon2Prover, poseidon2_verifier_air_from_config,
};

pub const BABY_BEAR_MODULUS: u64 = 0x7800_0001;
pub const KOALA_BEAR_MODULUS: u64 = 0x7f00_0001;

/// Metadata describing a non-primitive table inside a batch proof.
///
/// Every non-primitive dynamic plugin produces exactly one `NonPrimitiveTableEntry`
/// per batch instance. The entry is stored inside a `BatchStarkProof` and later provided
/// back to the plugin during verification through
/// [`TableProver::batch_air_from_table_entry`].
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
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

pub type PrimitiveTable = PrimitiveOpType;

/// Number of primitive circuit tables included in the unified batch STARK proof.
pub const NUM_PRIMITIVE_TABLES: usize = PrimitiveTable::Alu as usize + 1;

/// Row counts wrapper with type-safe indexing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
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
#[derive(Serialize, Deserialize)]
#[serde(bound = "")]
pub struct BatchStarkProof<SC>
where
    SC: StarkGenericConfig,
{
    /// The core cryptographic proof generated by `p3-batch-stark`.
    pub proof: BatchProof<SC>,
    /// Packing configuration used for the Witness, Public, and unified ALU tables.
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
    /// When true, run the lookup debugger before proving to report imbalanced multisets.
    debug_lookups: bool,
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
            Self::Alu(a) => a.width(),
            Self::Dynamic(a) => <dyn CloneableBatchAir<SC> as BaseAir<Val<SC>>>::width(a.air()),
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val<SC>>> {
        match self {
            Self::Witness(a) => a.preprocessed_trace(),
            Self::Const(a) => a.preprocessed_trace(),
            Self::Public(a) => a.preprocessed_trace(),
            Self::Alu(a) => a.preprocessed_trace(),
            Self::Dynamic(a) => {
                <dyn CloneableBatchAir<SC> as BaseAir<Val<SC>>>::preprocessed_trace(a.air())
            }
        }
    }
}

macro_rules! impl_circuit_table_air_for_builder {
    ($builder_ty:ty) => {
        fn eval(&self, builder: &mut $builder_ty) {
            match self {
                Self::Witness(a) => Air::<$builder_ty>::eval(a, builder),
                Self::Const(a) => Air::<$builder_ty>::eval(a, builder),
                Self::Public(a) => Air::<$builder_ty>::eval(a, builder),
                Self::Alu(a) => Air::<$builder_ty>::eval(a, builder),
                Self::Dynamic(a) => Air::<$builder_ty>::eval(a, builder),
            }
        }

        fn add_lookup_columns(&mut self) -> Vec<usize> {
            match self {
                Self::Witness(a) => Air::<$builder_ty>::add_lookup_columns(a),
                Self::Const(a) => Air::<$builder_ty>::add_lookup_columns(a),
                Self::Public(a) => Air::<$builder_ty>::add_lookup_columns(a),
                Self::Alu(a) => Air::<$builder_ty>::add_lookup_columns(a),
                Self::Dynamic(a) => Air::<$builder_ty>::add_lookup_columns(a),
            }
        }

        fn get_lookups(&mut self) -> Vec<Lookup<<$builder_ty as AirBuilder>::F>> {
            match self {
                Self::Witness(a) => Air::<$builder_ty>::get_lookups(a),
                Self::Const(a) => Air::<$builder_ty>::get_lookups(a),
                Self::Public(a) => Air::<$builder_ty>::get_lookups(a),
                Self::Alu(a) => Air::<$builder_ty>::get_lookups(a),
                Self::Dynamic(a) => Air::<$builder_ty>::get_lookups(a),
            }
        }
    };
}

impl<SC, const D: usize> Air<SymbolicAirBuilder<Val<SC>, SC::Challenge>> for CircuitTableAir<SC, D>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    impl_circuit_table_air_for_builder!(SymbolicAirBuilder<Val<SC>, SC::Challenge>);
}

#[cfg(debug_assertions)]
impl<'a, SC, const D: usize> Air<DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>>
    for CircuitTableAir<SC, D>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    impl_circuit_table_air_for_builder!(
        DebugConstraintBuilderWithLookups<'a, Val<SC>, SC::Challenge>
    );
}

impl<'a, SC, const D: usize> Air<ProverConstraintFolderWithLookups<'a, SC>>
    for CircuitTableAir<SC, D>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    impl_circuit_table_air_for_builder!(ProverConstraintFolderWithLookups<'a, SC>);
}

impl<'a, SC, const D: usize> Air<VerifierConstraintFolderWithLookups<'a, SC>>
    for CircuitTableAir<SC, D>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField,
    SymbolicExpression<SC::Challenge>: From<SymbolicExpression<Val<SC>>>,
{
    impl_circuit_table_air_for_builder!(VerifierConstraintFolderWithLookups<'a, SC>);
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
            debug_lookups: false,
        }
    }

    #[must_use]
    pub const fn with_table_packing(mut self, table_packing: TablePacking) -> Self {
        self.table_packing = table_packing;
        self
    }

    /// Enable the lookup debugger. When set, `prove_all_tables` will run
    /// `check_lookups` on the constructed traces before generating the proof,
    /// panicking with a detailed message on any multiset imbalance.
    #[must_use]
    pub const fn with_debug_lookups(mut self) -> Self {
        self.debug_lookups = true;
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

        // Check if Alu table has only dummy operations (trace length <= 1).
        // The table implementation adds a dummy row when empty, so we check for <= 1.
        // Using lanes > 1 with only dummy operations causes issues in recursive verification
        // due to a bug in how multi-lane padding interacts with lookup constraints.
        // We automatically reduce lanes to 1 in these cases with a warning.
        //
        // The trace length check is more reliable than checking preprocessed width because
        // the circuit tables add dummy rows to avoid empty traces.
        let alu_trace_only_dummy = traces.alu_trace.op_kind.len() <= 1;

        let alu_lanes = if alu_trace_only_dummy && packing.alu_lanes() > 1 {
            tracing::warn!(
                "ALu table has only dummy operations but alu_lanes={} > 1. Reducing to \
                 alu_lanes=1 to avoid recursive verification issues. Consider using \
                 alu_lanes=1 when no additions are expected.",
                packing.alu_lanes()
            );
            1
        } else {
            packing.alu_lanes()
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
        // Similar to other primitive tables, reduce lanes to 1 if the table has only dummy operations.
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

        // ALU (unified Add/Mul/BoolCheck/MulAdd)
        // When the ALU trace is empty, we add a dummy operation to match
        // what get_airs_and_degrees_with_prep does for the CommonData preprocessed commitment.
        // This ensures the prover's AIR.preprocessed_trace() matches the committed data.
        let alu_rows = traces.alu_trace.a_values.len();
        let (alu_rows, alu_prep) = if alu_rows == 0 {
            // Add dummy operation with indices [0, 0, 0]
            let dummy_prep =
                vec![Val::<SC>::ZERO; AluAir::<Val<SC>, D>::preprocessed_lane_width() - 1];
            (1, dummy_prep)
        } else {
            (alu_rows, primitive[PrimitiveOpType::Alu as usize].clone())
        };
        let alu_air: AluAir<Val<SC>, D> = if D == 1 {
            AluAir::<Val<SC>, D>::new_with_preprocessed(alu_rows, alu_lanes, alu_prep)
                .with_min_height(min_height)
        } else {
            let w = w_binomial.ok_or(BatchStarkProverError::MissingWForExtension)?;
            AluAir::<Val<SC>, D>::new_binomial_with_preprocessed(alu_rows, alu_lanes, w, alu_prep)
                .with_min_height(min_height)
        };
        let alu_matrix: RowMajorMatrix<Val<SC>> =
            AluAir::<Val<SC>, D>::trace_to_matrix(&traces.alu_trace, alu_lanes);

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
        trace_storage.push(packing::pad_matrix_to_min_height(
            witness_matrix,
            min_height,
        ));
        public_storage.push(Vec::new());

        air_storage.push(CircuitTableAir::Const(const_air));
        trace_storage.push(packing::pad_matrix_to_min_height(const_matrix, min_height));
        public_storage.push(Vec::new());

        air_storage.push(CircuitTableAir::Public(public_air));
        trace_storage.push(packing::pad_matrix_to_min_height(public_matrix, min_height));
        public_storage.push(Vec::new());

        air_storage.push(CircuitTableAir::Alu(alu_air));
        trace_storage.push(packing::pad_matrix_to_min_height(alu_matrix, min_height));
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
            trace_storage.push(packing::pad_matrix_to_min_height(trace, min_height));
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

        if self.debug_lookups {
            use p3_lookup::debug_util::{LookupDebugInstance, check_lookups};

            let preprocessed_traces: Vec<Option<RowMajorMatrix<Val<SC>>>> = instances
                .iter()
                .map(|inst| inst.air.preprocessed_trace())
                .collect();
            let debug_instances: Vec<LookupDebugInstance<'_, Val<SC>>> = instances
                .iter()
                .zip(preprocessed_traces.iter())
                .map(|(inst, prep)| LookupDebugInstance {
                    main_trace: &inst.trace,
                    preprocessed_trace: prep,
                    public_values: &inst.public_values,
                    lookups: &inst.lookups,
                    permutation_challenges: &[],
                })
                .collect();
            check_lookups(&debug_instances);
        }

        let proof = p3_batch_stark::prove_batch(&self.config, &instances, prover_data);

        // Ensure all primitive table row counts are at least 1
        // RowCounts::new requires non-zero counts, so pad zeros to 1
        let witness_rows_padded = witness_rows.max(1);
        let const_rows_padded = const_rows.max(1);
        let public_rows_padded = public_rows.max(1);
        let alu_rows_padded = alu_rows.max(1);

        // Store the effective packing (with reduced lanes if applicable) so the verifier
        // uses the same configuration that was actually used during proving.
        let effective_packing = TablePacking::new(witness_lanes, public_lanes, alu_lanes)
            .with_min_trace_height(min_height);

        Ok(BatchStarkProof {
            proof,
            table_packing: effective_packing,
            rows: RowCounts::new([
                witness_rows_padded,
                const_rows_padded,
                public_rows_padded,
                alu_rows_padded,
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
        let alu_lanes = packing.alu_lanes();
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
        let alu_air: CircuitTableAir<SC, D> = if D == 1 {
            CircuitTableAir::Alu(
                AluAir::<Val<SC>, D>::new(proof.rows[PrimitiveTable::Alu], alu_lanes)
                    .with_min_height(min_height),
            )
        } else {
            let w = w_binomial.ok_or(BatchStarkProverError::MissingWForExtension)?;
            CircuitTableAir::Alu(
                AluAir::<Val<SC>, D>::new_binomial(proof.rows[PrimitiveTable::Alu], alu_lanes, w)
                    .with_min_height(min_height),
            )
        };
        let mut airs = vec![witness_air, const_air, public_air, alu_air];
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
mod tests;
