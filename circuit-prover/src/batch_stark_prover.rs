//! Batch STARK prover and verifier that unifies all circuit tables
//! into a single batched STARK proof using `p3-batch-stark`.

use alloc::boxed::Box;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::mem::transmute;

use p3_air::{Air, AirBuilder, BaseAir};
use p3_baby_bear::{BabyBear, default_babybear_poseidon2_16, default_babybear_poseidon2_24};
use p3_batch_stark::{BatchProof, CommonData, StarkGenericConfig, StarkInstance, Val};
use p3_circuit::op::PrimitiveOpType;
use p3_circuit::tables::{
    Poseidon2CircuitRow, Poseidon2CircuitRowDyn, Poseidon2CircuitTrace, Poseidon2Params,
    Poseidon2Trace, Poseidon2TraceDyn, Traces,
};
use p3_field::extension::{BinomialExtensionField, BinomiallyExtendable};
use p3_field::{BasedVectorSpace, ExtensionField, Field, PrimeCharacteristicRing, PrimeField};
use p3_koala_bear::{KoalaBear, default_koalabear_poseidon2_16, default_koalabear_poseidon2_24};
use p3_matrix::dense::RowMajorMatrix;
use p3_poseidon2_air::RoundConstants;
use p3_poseidon2_circuit_air::{
    BabyBearD4Width16, BabyBearD4Width24, KoalaBearD4Width16, KoalaBearD4Width24,
    Poseidon2CircuitAirBabyBearD4Width16, Poseidon2CircuitAirBabyBearD4Width24,
    Poseidon2CircuitAirKoalaBearD4Width16, Poseidon2CircuitAirKoalaBearD4Width24,
};
use p3_symmetric::CryptographicPermutation;
use p3_uni_stark::{ProverConstraintFolder, SymbolicAirBuilder, VerifierConstraintFolder};
use thiserror::Error;
use tracing::instrument;

use crate::air::{AddAir, ConstAir, MulAir, PublicAir, WitnessAir};
use crate::common::CircuitTableAir;
use crate::config::StarkField;
use crate::field_params::ExtractBinomialW;

/// Configuration for packing multiple primitive operations into a single AIR row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TablePacking {
    witness_lanes: usize,
    add_lanes: usize,
    mul_lanes: usize,
}

impl TablePacking {
    pub fn new(witness_lanes: usize, add_lanes: usize, mul_lanes: usize) -> Self {
        Self {
            witness_lanes: witness_lanes.max(1),
            add_lanes: add_lanes.max(1),
            mul_lanes: mul_lanes.max(1),
        }
    }

    pub fn from_counts(witness_lanes: usize, add_lanes: usize, mul_lanes: usize) -> Self {
        Self::new(witness_lanes, add_lanes, mul_lanes)
    }

    pub const fn witness_lanes(self) -> usize {
        self.witness_lanes
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
        Self::new(1, 1, 1)
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
    /// Plugin identifier (it should match `TableProver::id`).
    pub id: &'static str,
    /// Number of logical rows produced for this table.
    pub rows: usize,
    /// Public values exposed by this table (if any).
    pub public_values: Vec<Val<SC>>,
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

/// Simple super trait of [`Air`] describing the behaviour of a non-primitive
/// dynamically dispatched AIR used in batched proofs.
pub trait BatchAir<SC>:
    BaseAir<Val<SC>>
    + Air<SymbolicAirBuilder<Val<SC>>>
    + for<'a> Air<ProverConstraintFolder<'a, SC>>
    + for<'a> Air<VerifierConstraintFolder<'a, SC>>
    + Send
    + Sync
where
    SC: StarkGenericConfig,
{
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
    /// Plugin identifier (it should match `TableProver::id`).
    pub id: &'static str,
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
///     fn id(&self) -> &'static str { "my_plugin" }
///
///     impl_table_prover_batch_instances_from_base!(batch_instance_base);
/// }
/// ```
pub trait TableProver<SC>: Send + Sync
where
    SC: StarkGenericConfig + 'static,
{
    /// Identifier for this prover.
    fn id(&self) -> &'static str;

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
///     fn id(&self) -> &'static str { "my_plugin" }
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

/// Poseidon2 configuration that can be selected at runtime.
/// This enum represents different Poseidon2 configurations (field type, width, etc.).
#[derive(Debug, Clone)]
pub enum Poseidon2Config {
    /// BabyBear D=4, WIDTH=16 configuration
    BabyBearD4Width16 {
        permutation: p3_baby_bear::Poseidon2BabyBear<16>,
        constants: RoundConstants<p3_baby_bear::BabyBear, 16, 4, 13>,
    },
    /// BabyBear D=4, WIDTH=24 configuration
    BabyBearD4Width24 {
        permutation: p3_baby_bear::Poseidon2BabyBear<24>,
        constants: RoundConstants<p3_baby_bear::BabyBear, 24, 4, 21>,
    },
    /// KoalaBear D=4, WIDTH=16 configuration
    KoalaBearD4Width16 {
        permutation: p3_koala_bear::Poseidon2KoalaBear<16>,
        constants: RoundConstants<p3_koala_bear::KoalaBear, 16, 4, 20>,
    },
    /// KoalaBear D=4, WIDTH=24 configuration
    KoalaBearD4Width24 {
        permutation: p3_koala_bear::Poseidon2KoalaBear<24>,
        constants: RoundConstants<p3_koala_bear::KoalaBear, 24, 4, 23>,
    },
}

impl Poseidon2Config {
    /// Create BabyBear D=4 WIDTH=16 configuration from default permutation.
    /// Uses the same permutation and constants as `default_babybear_poseidon2_16()`.
    pub fn baby_bear_d4_width16() -> Self {
        let perm = default_babybear_poseidon2_16();

        let beginning_full: [[BabyBear; 16]; 4] = p3_baby_bear::BABYBEAR_RC16_EXTERNAL_INITIAL;
        let partial: [BabyBear; 13] = p3_baby_bear::BABYBEAR_RC16_INTERNAL;
        let ending_full: [[BabyBear; 16]; 4] = p3_baby_bear::BABYBEAR_RC16_EXTERNAL_FINAL;

        let constants = RoundConstants::new(beginning_full, partial, ending_full);

        Self::BabyBearD4Width16 {
            permutation: perm,
            constants,
        }
    }

    /// Create BabyBear D=4 WIDTH=24 configuration from default permutation.
    /// Uses the same permutation and constants as `default_babybear_poseidon2_24()`.
    pub fn baby_bear_d4_width24() -> Self {
        let perm = default_babybear_poseidon2_24();

        let beginning_full: [[BabyBear; 24]; 4] = p3_baby_bear::BABYBEAR_RC24_EXTERNAL_INITIAL;
        let partial: [BabyBear; 21] = p3_baby_bear::BABYBEAR_RC24_INTERNAL;
        let ending_full: [[BabyBear; 24]; 4] = p3_baby_bear::BABYBEAR_RC24_EXTERNAL_FINAL;

        let constants = RoundConstants::new(beginning_full, partial, ending_full);

        Self::BabyBearD4Width24 {
            permutation: perm,
            constants,
        }
    }

    /// Create KoalaBear D=4 WIDTH=16 configuration from default permutation.
    /// Uses the same permutation and constants as `default_koalabear_poseidon2_16()`.
    pub fn koala_bear_d4_width16() -> Self {
        let perm = default_koalabear_poseidon2_16();

        let beginning_full: [[KoalaBear; 16]; 4] = p3_koala_bear::KOALABEAR_RC16_EXTERNAL_INITIAL;
        let partial: [KoalaBear; 20] = p3_koala_bear::KOALABEAR_RC16_INTERNAL;
        let ending_full: [[KoalaBear; 16]; 4] = p3_koala_bear::KOALABEAR_RC16_EXTERNAL_FINAL;

        let constants = RoundConstants::new(beginning_full, partial, ending_full);

        Self::KoalaBearD4Width16 {
            permutation: perm,
            constants,
        }
    }

    /// Create KoalaBear D=4 WIDTH=24 configuration from default permutation.
    /// Uses the same permutation and constants as `default_koalabear_poseidon2_24()`.
    pub fn koala_bear_d4_width24() -> Self {
        let perm = default_koalabear_poseidon2_24();

        let beginning_full: [[KoalaBear; 24]; 4] = p3_koala_bear::KOALABEAR_RC24_EXTERNAL_INITIAL;
        let partial: [KoalaBear; 23] = p3_koala_bear::KOALABEAR_RC24_INTERNAL;
        let ending_full: [[KoalaBear; 24]; 4] = p3_koala_bear::KOALABEAR_RC24_EXTERNAL_FINAL;

        let constants = RoundConstants::new(beginning_full, partial, ending_full);

        Self::KoalaBearD4Width24 {
            permutation: perm,
            constants,
        }
    }
}

/// Wrapper for Poseidon2CircuitAir that implements BatchAir<SC>
// We need this because `BatchAir` requires `BaseAir<Val<SC>>`.
// but `Poseidon2CircuitAir` works over a specific field.
struct Poseidon2AirWrapper<SC: StarkGenericConfig> {
    width: usize,
    _phantom: core::marker::PhantomData<SC>,
}

impl<SC> BatchAir<SC> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
{
}

impl<SC> BaseAir<Val<SC>> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    Val<SC>: StarkField,
{
    fn width(&self) -> usize {
        self.width
    }
}

impl<SC, AB> Air<AB> for Poseidon2AirWrapper<SC>
where
    SC: StarkGenericConfig + Send + Sync,
    AB: AirBuilder<F = Val<SC>>,
    Val<SC>: StarkField,
{
    fn eval(&self, _builder: &mut AB) {
        // The actual evaluation is handled by the concrete AIR type
        // This wrapper is just for type erasure
        // TODO: Delegate to the actual AIR if we can store it
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
    {
        // Get the trace - it's stored over the circuit field CF
        let t_cf = traces.non_primitive_trace::<Poseidon2Trace<CF>>("poseidon2")?;

        let rows = t_cf.total_rows();
        if rows == 0 {
            return None;
        }

        // Convert trace from circuit field to base field
        // Extract base field coefficients from extension field values
        let t: Poseidon2Trace<Val<SC>> = {
            let operations: Vec<_> = t_cf
                .operations
                .iter()
                .map(|row| {
                    // Extract base field coefficients (first coefficient of extension field)
                    let input_values: Vec<Val<SC>> = row
                        .input_values
                        .iter()
                        .map(|v| {
                            let coeffs = v.as_basis_coefficients_slice();
                            coeffs[0] // First coefficient is the base field value
                        })
                        .collect();
                    let mmcs_index_sum = {
                        let coeffs = row.mmcs_index_sum.as_basis_coefficients_slice();
                        coeffs[0]
                    };
                    Poseidon2CircuitRowDyn {
                        new_start: row.new_start,
                        merkle_path: row.merkle_path,
                        mmcs_bit: row.mmcs_bit,
                        mmcs_index_sum,
                        input_values,
                        in_ctl: row.in_ctl.clone(),
                        input_indices: row.input_indices.clone(),
                        out_ctl: row.out_ctl.clone(),
                        output_indices: row.output_indices.clone(),
                        mmcs_index_sum_idx: row.mmcs_index_sum_idx,
                    }
                })
                .collect();
            Poseidon2TraceDyn::new(operations)
        };

        // Pad to power of two and generate trace matrix based on configuration
        match &self.config {
            Poseidon2Config::BabyBearD4Width16 {
                permutation,
                constants,
            } => self.batch_instance_base_impl::<SC, p3_baby_bear::BabyBear, _, { BabyBearD4Width16::WIDTH }, { BabyBearD4Width16::HALF_FULL_ROUNDS }, { BabyBearD4Width16::PARTIAL_ROUNDS }, { BabyBearD4Width16::WIDTH_EXT }, { BabyBearD4Width16::RATE_EXT }, { BabyBearD4Width16::DIGEST_EXT }>(
                &t,
                permutation,
                constants,
            ),
            Poseidon2Config::BabyBearD4Width24 {
                permutation,
                constants,
            } => self.batch_instance_base_impl::<SC, p3_baby_bear::BabyBear, _, { BabyBearD4Width24::WIDTH }, { BabyBearD4Width24::HALF_FULL_ROUNDS }, { BabyBearD4Width24::PARTIAL_ROUNDS }, { BabyBearD4Width24::WIDTH_EXT }, { BabyBearD4Width24::RATE_EXT }, { BabyBearD4Width24::DIGEST_EXT }>(
                &t,
                permutation,
                constants,
            ),
            Poseidon2Config::KoalaBearD4Width16 {
                permutation,
                constants,
            } => self.batch_instance_base_impl::<SC, p3_koala_bear::KoalaBear, _, { KoalaBearD4Width16::WIDTH }, { KoalaBearD4Width16::HALF_FULL_ROUNDS }, { KoalaBearD4Width16::PARTIAL_ROUNDS }, { KoalaBearD4Width16::WIDTH_EXT }, { KoalaBearD4Width16::RATE_EXT }, { KoalaBearD4Width16::DIGEST_EXT }>(
                &t,
                permutation,
                constants,
            ),
            Poseidon2Config::KoalaBearD4Width24 {
                permutation,
                constants,
            } => self.batch_instance_base_impl::<SC, p3_koala_bear::KoalaBear, _, { KoalaBearD4Width24::WIDTH }, { KoalaBearD4Width24::HALF_FULL_ROUNDS }, { KoalaBearD4Width24::PARTIAL_ROUNDS }, { KoalaBearD4Width24::WIDTH_EXT }, { KoalaBearD4Width24::RATE_EXT }, { KoalaBearD4Width24::DIGEST_EXT }>(
                &t,
                permutation,
                constants,
            ),
        }
    }

    fn batch_instance_base_impl<
        SC,
        F,
        P,
        const WIDTH: usize,
        const HALF_FULL_ROUNDS: usize,
        const PARTIAL_ROUNDS: usize,
        const WIDTH_EXT: usize,
        const RATE_EXT: usize,
        const DIGEST_EXT: usize,
    >(
        &self,
        t: &Poseidon2Trace<Val<SC>>,
        _permutation: &P,
        _constants: &RoundConstants<F, WIDTH, HALF_FULL_ROUNDS, PARTIAL_ROUNDS>,
    ) -> Option<BatchTableInstance<SC>>
    where
        SC: StarkGenericConfig + 'static + Send + Sync,
        F: StarkField + PrimeCharacteristicRing,
        P: CryptographicPermutation<[F; WIDTH]> + Clone,
        Val<SC>: StarkField,
    {
        // Convert to const-generic trace
        let t = t
            .to_const_generic::<WIDTH_EXT, RATE_EXT, DIGEST_EXT>()
            .ok()?;
        let rows = t.total_rows();

        // Pad to power of two
        let padded_rows = rows.next_power_of_two();
        let mut padded_ops = t.operations;
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
                        in_ctl: [false; WIDTH_EXT],
                        input_indices: [0; WIDTH_EXT],
                        out_ctl: [false; DIGEST_EXT],
                        output_indices: [0; DIGEST_EXT],
                        mmcs_index_sum_idx: 0,
                    }),
            );
        }

        // Convert trace from Val<SC> to F using unsafe transmute
        // This is safe when Val<SC> and F have the same size and layout
        // For BabyBear/KoalaBear configs, Val<SC> should be BabyBear/KoalaBear
        let ops_converted: Poseidon2CircuitTrace<F, WIDTH_EXT, RATE_EXT, DIGEST_EXT> =
            unsafe { transmute(padded_ops) };

        // Create an AIR instance based on the configuration
        // This is a bit verbose but we can't get over const generics
        let (air, matrix) = match &self.config {
            Poseidon2Config::BabyBearD4Width16 {
                permutation,
                constants,
            } => {
                let air = Poseidon2CircuitAirBabyBearD4Width16::new(constants.clone());
                let ops_babybear: Poseidon2CircuitTrace<
                    BabyBear,
                    { BabyBearD4Width16::WIDTH_EXT },
                    { BabyBearD4Width16::RATE_EXT },
                    { BabyBearD4Width16::DIGEST_EXT },
                > = unsafe { transmute(ops_converted) };
                let matrix_f = air.generate_trace_rows(&ops_babybear, constants, 0, permutation);
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { transmute(matrix_f) };
                (
                    Poseidon2AirWrapper {
                        width: air.width(),
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
            Poseidon2Config::BabyBearD4Width24 {
                permutation,
                constants,
            } => {
                let air = Poseidon2CircuitAirBabyBearD4Width24::new(constants.clone());
                let ops_babybear: Poseidon2CircuitTrace<
                    BabyBear,
                    { BabyBearD4Width24::WIDTH_EXT },
                    { BabyBearD4Width24::RATE_EXT },
                    { BabyBearD4Width24::DIGEST_EXT },
                > = unsafe { transmute(ops_converted) };
                let matrix_f = air.generate_trace_rows(&ops_babybear, constants, 0, permutation);
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { transmute(matrix_f) };
                (
                    Poseidon2AirWrapper {
                        width: air.width(),
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
            Poseidon2Config::KoalaBearD4Width16 {
                permutation,
                constants,
            } => {
                let air = Poseidon2CircuitAirKoalaBearD4Width16::new(constants.clone());
                let ops_koalabear: Poseidon2CircuitTrace<
                    KoalaBear,
                    { KoalaBearD4Width16::WIDTH_EXT },
                    { KoalaBearD4Width16::RATE_EXT },
                    { KoalaBearD4Width16::DIGEST_EXT },
                > = unsafe { transmute(ops_converted) };
                let matrix_f = air.generate_trace_rows(&ops_koalabear, constants, 0, permutation);
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { transmute(matrix_f) };
                (
                    Poseidon2AirWrapper {
                        width: air.width(),
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
            Poseidon2Config::KoalaBearD4Width24 {
                permutation,
                constants,
            } => {
                let air = Poseidon2CircuitAirKoalaBearD4Width24::new(constants.clone());
                let ops_koalabear: Poseidon2CircuitTrace<
                    KoalaBear,
                    { KoalaBearD4Width24::WIDTH_EXT },
                    { KoalaBearD4Width24::RATE_EXT },
                    { KoalaBearD4Width24::DIGEST_EXT },
                > = unsafe { core::mem::transmute(ops_converted) };
                let matrix_f = air.generate_trace_rows(&ops_koalabear, constants, 0, permutation);
                let matrix: RowMajorMatrix<Val<SC>> = unsafe { core::mem::transmute(matrix_f) };
                (
                    Poseidon2AirWrapper {
                        width: air.width(),
                        _phantom: core::marker::PhantomData::<SC>,
                    },
                    matrix,
                )
            }
        };

        Some(BatchTableInstance {
            id: "poseidon2",
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
{
    fn id(&self) -> &'static str {
        "poseidon2"
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
        match &self.config {
            Poseidon2Config::BabyBearD4Width16 { constants, .. } => {
                use p3_poseidon2_circuit_air::Poseidon2CircuitAirBabyBearD4Width16;
                let air = Poseidon2CircuitAirBabyBearD4Width16::new(constants.clone());
                let wrapper = Poseidon2AirWrapper {
                    width: air.width(),
                    _phantom: core::marker::PhantomData::<SC>,
                };
                Ok(DynamicAirEntry::new(Box::new(wrapper)))
            }
            Poseidon2Config::BabyBearD4Width24 { constants, .. } => {
                use p3_poseidon2_circuit_air::Poseidon2CircuitAirBabyBearD4Width24;
                let air = Poseidon2CircuitAirBabyBearD4Width24::new(constants.clone());
                let wrapper = Poseidon2AirWrapper {
                    width: air.width(),
                    _phantom: core::marker::PhantomData::<SC>,
                };
                Ok(DynamicAirEntry::new(Box::new(wrapper)))
            }
            Poseidon2Config::KoalaBearD4Width16 { constants, .. } => {
                use p3_poseidon2_circuit_air::Poseidon2CircuitAirKoalaBearD4Width16;
                let air = Poseidon2CircuitAirKoalaBearD4Width16::new(constants.clone());
                let wrapper = Poseidon2AirWrapper {
                    width: air.width(),
                    _phantom: core::marker::PhantomData::<SC>,
                };
                Ok(DynamicAirEntry::new(Box::new(wrapper)))
            }
            Poseidon2Config::KoalaBearD4Width24 { constants, .. } => {
                use p3_poseidon2_circuit_air::Poseidon2CircuitAirKoalaBearD4Width24;
                let air = Poseidon2CircuitAirKoalaBearD4Width24::new(constants.clone());
                let wrapper = Poseidon2AirWrapper {
                    width: air.width(),
                    _phantom: core::marker::PhantomData::<SC>,
                };
                Ok(DynamicAirEntry::new(Box::new(wrapper)))
            }
        }
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

    #[error("missing table prover for non-primitive table `{0}`")]
    MissingTableProver(&'static str),
}

impl<SC, const D: usize> BaseAir<Val<SC>> for CircuitTableAir<SC, D>
where
    SC: StarkGenericConfig,
{
    fn width(&self) -> usize {
        match self {
            Self::Witness(a) => a.width(),
            Self::Const(a) => a.width(),
            Self::Public(a) => a.width(),
            Self::Add(a) => a.width(),
            Self::Mul(a) => a.width(),
            Self::Dynamic(a) => <dyn BatchAir<SC> as BaseAir<Val<SC>>>::width(a.air()),
        }
    }

    fn preprocessed_trace(&self) -> Option<RowMajorMatrix<Val<SC>>> {
        match self {
            Self::Witness(a) => a.preprocessed_trace(),
            Self::Const(a) => a.preprocessed_trace(),
            Self::Public(a) => a.preprocessed_trace(),
            Self::Add(a) => a.preprocessed_trace(),
            Self::Mul(a) => a.preprocessed_trace(),
            Self::Dynamic(a) => <dyn BatchAir<SC> as BaseAir<Val<SC>>>::preprocessed_trace(a.air()),
        }
    }
}

impl<SC, const D: usize> Air<SymbolicAirBuilder<Val<SC>>> for CircuitTableAir<SC, D>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField,
{
    fn eval(&self, builder: &mut SymbolicAirBuilder<Val<SC>>) {
        match self {
            Self::Witness(a) => a.eval(builder),
            Self::Const(a) => a.eval(builder),
            Self::Public(a) => a.eval(builder),
            Self::Add(a) => a.eval(builder),
            Self::Mul(a) => a.eval(builder),
            Self::Dynamic(a) => {
                <dyn BatchAir<SC> as Air<SymbolicAirBuilder<Val<SC>>>>::eval(a.air(), builder);
            }
        }
    }
}

impl<'a, SC, const D: usize> Air<ProverConstraintFolder<'a, SC>> for CircuitTableAir<SC, D>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField,
{
    fn eval(&self, builder: &mut ProverConstraintFolder<'a, SC>) {
        match self {
            Self::Witness(a) => a.eval(builder),
            Self::Const(a) => a.eval(builder),
            Self::Public(a) => a.eval(builder),
            Self::Add(a) => a.eval(builder),
            Self::Mul(a) => a.eval(builder),
            Self::Dynamic(a) => {
                <dyn BatchAir<SC> as Air<ProverConstraintFolder<'a, SC>>>::eval(a.air(), builder);
            }
        }
    }
}

impl<'a, SC, const D: usize> Air<VerifierConstraintFolder<'a, SC>> for CircuitTableAir<SC, D>
where
    SC: StarkGenericConfig,
    Val<SC>: PrimeField,
{
    fn eval(&self, builder: &mut VerifierConstraintFolder<'a, SC>) {
        match self {
            Self::Witness(a) => a.eval(builder),
            Self::Const(a) => a.eval(builder),
            Self::Public(a) => a.eval(builder),
            Self::Add(a) => a.eval(builder),
            Self::Mul(a) => a.eval(builder),
            Self::Dynamic(a) => {
                <dyn BatchAir<SC> as Air<VerifierConstraintFolder<'a, SC>>>::eval(a.air(), builder);
            }
        }
    }
}

impl<SC> BatchStarkProver<SC>
where
    SC: StarkGenericConfig + 'static,
    Val<SC>: StarkField,
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
        common: &CommonData<SC>,
    ) -> Result<BatchStarkProof<SC>, BatchStarkProverError>
    where
        EF: Field + BasedVectorSpace<Val<SC>> + ExtractBinomialW<Val<SC>>,
    {
        let w_opt = EF::extract_w();
        match EF::DIMENSION {
            1 => self.prove::<EF, 1>(traces, None, common),
            2 => self.prove::<EF, 2>(traces, w_opt, common),
            4 => self.prove::<EF, 4>(traces, w_opt, common),
            6 => self.prove::<EF, 6>(traces, w_opt, common),
            8 => self.prove::<EF, 8>(traces, w_opt, common),
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
        common: &CommonData<SC>,
    ) -> Result<BatchStarkProof<SC>, BatchStarkProverError>
    where
        EF: Field + BasedVectorSpace<Val<SC>>,
    {
        // TODO: Consider parallelizing AIR construction and trace-to-matrix conversions.
        // Build matrices and AIRs per table.
        let packing = self.table_packing;
        let witness_lanes = packing.witness_lanes();
        let add_lanes = packing.add_lanes();
        let mul_lanes = packing.mul_lanes();

        // Witness
        let witness_rows = traces.witness_trace.values.len();
        let witness_air = WitnessAir::<Val<SC>, D>::new(witness_rows, witness_lanes);
        let witness_matrix: RowMajorMatrix<Val<SC>> =
            WitnessAir::<Val<SC>, D>::trace_to_matrix(&traces.witness_trace, witness_lanes);

        // Const
        let const_rows = traces.const_trace.values.len();
        let const_prep = ConstAir::<Val<SC>, D>::trace_to_preprocessed(&traces.const_trace);
        let const_air = ConstAir::<Val<SC>, D>::new_with_preprocessed(const_rows, const_prep);
        let const_matrix: RowMajorMatrix<Val<SC>> =
            ConstAir::<Val<SC>, D>::trace_to_matrix(&traces.const_trace);

        // Public
        let public_rows = traces.public_trace.values.len();
        let public_prep = PublicAir::<Val<SC>, D>::trace_to_preprocessed(&traces.public_trace);
        let public_air = PublicAir::<Val<SC>, D>::new_with_preprocessed(public_rows, public_prep);
        let public_matrix: RowMajorMatrix<Val<SC>> =
            PublicAir::<Val<SC>, D>::trace_to_matrix(&traces.public_trace);

        // Add
        let add_rows = traces.add_trace.lhs_values.len();
        let add_prep = AddAir::<Val<SC>, D>::trace_to_preprocessed(&traces.add_trace, add_lanes);
        let add_air = AddAir::<Val<SC>, D>::new_with_preprocessed(add_rows, add_lanes, add_prep);
        let add_matrix: RowMajorMatrix<Val<SC>> =
            AddAir::<Val<SC>, D>::trace_to_matrix(&traces.add_trace, add_lanes);

        // Mul
        let mul_rows = traces.mul_trace.lhs_values.len();
        let mul_prep = MulAir::<Val<SC>, D>::trace_to_preprocessed(&traces.mul_trace, mul_lanes);
        let mul_air: MulAir<Val<SC>, D> = if D == 1 {
            MulAir::<Val<SC>, D>::new_with_preprocessed(mul_rows, mul_lanes, mul_prep)
        } else {
            let w = w_binomial.ok_or(BatchStarkProverError::MissingWForExtension)?;
            MulAir::<Val<SC>, D>::new_binomial_with_preprocessed(mul_rows, mul_lanes, w, mul_prep)
        };
        let mul_matrix: RowMajorMatrix<Val<SC>> =
            MulAir::<Val<SC>, D>::trace_to_matrix(&traces.mul_trace, mul_lanes);

        // We first handle all non-primitive tables dynamically, which will then be batched alongside primitive ones.
        // Each trace must have a corresponding registered prover for it to be provable.
        for (&id, trace) in &traces.non_primitive_traces {
            if trace.rows() == 0 {
                continue;
            }
            if !self.non_primitive_provers.iter().any(|p| p.id() == id) {
                return Err(BatchStarkProverError::MissingTableProver(id));
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

        air_storage.push(CircuitTableAir::Witness(witness_air));
        trace_storage.push(witness_matrix);
        public_storage.push(Vec::new());

        air_storage.push(CircuitTableAir::Const(const_air));
        trace_storage.push(const_matrix);
        public_storage.push(Vec::new());

        air_storage.push(CircuitTableAir::Public(public_air));
        trace_storage.push(public_matrix);
        public_storage.push(Vec::new());

        air_storage.push(CircuitTableAir::Add(add_air));
        trace_storage.push(add_matrix);
        public_storage.push(Vec::new());

        air_storage.push(CircuitTableAir::Mul(mul_air));
        trace_storage.push(mul_matrix);
        public_storage.push(Vec::new());

        for instance in dynamic_instances {
            let BatchTableInstance {
                id,
                air,
                trace,
                public_values,
                rows,
            } = instance;
            air_storage.push(CircuitTableAir::Dynamic(air));
            trace_storage.push(trace);
            public_storage.push(public_values.clone());
            non_primitives.push(NonPrimitiveTableEntry {
                id,
                rows,
                public_values,
            });
        }

        let instances: Vec<StarkInstance<'_, SC, CircuitTableAir<SC, D>>> = air_storage
            .iter()
            .zip(trace_storage)
            .zip(public_storage)
            .map(|((air, trace), public_values)| StarkInstance {
                air,
                trace,
                public_values,
            })
            .collect();

        let proof = p3_batch_stark::prove_batch(&self.config, instances, common);

        // Ensure all primitive table row counts are at least 1
        // RowCounts::new requires non-zero counts, so pad zeros to 1
        let witness_rows_padded = witness_rows.max(1);
        let const_rows_padded = const_rows.max(1);
        let public_rows_padded = public_rows.max(1);
        let add_rows_padded = add_rows.max(1);
        let mul_rows_padded = mul_rows.max(1);

        Ok(BatchStarkProof {
            proof,
            table_packing: packing,
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
        let add_lanes = packing.add_lanes();
        let mul_lanes = packing.mul_lanes();

        let witness_air = CircuitTableAir::Witness(WitnessAir::<Val<SC>, D>::new(
            proof.rows[PrimitiveTable::Witness],
            witness_lanes,
        ));
        let const_air = CircuitTableAir::Const(ConstAir::<Val<SC>, D>::new(
            proof.rows[PrimitiveTable::Const],
        ));
        let public_air = CircuitTableAir::Public(PublicAir::<Val<SC>, D>::new(
            proof.rows[PrimitiveTable::Public],
        ));
        let add_air = CircuitTableAir::Add(AddAir::<Val<SC>, D>::new(
            proof.rows[PrimitiveTable::Add],
            add_lanes,
        ));
        let mul_air: CircuitTableAir<SC, D> = if D == 1 {
            CircuitTableAir::Mul(MulAir::<Val<SC>, D>::new(
                proof.rows[PrimitiveTable::Mul],
                mul_lanes,
            ))
        } else {
            let w = w_binomial.ok_or(BatchStarkProverError::MissingWForExtension)?;
            CircuitTableAir::Mul(MulAir::<Val<SC>, D>::new_binomial(
                proof.rows[PrimitiveTable::Mul],
                mul_lanes,
                w,
            ))
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
                    TableProver::id(tp) == entry.id
                })
                .ok_or_else(|| {
                    BatchStarkProverError::Verify(format!(
                        "unknown non-primitive plugin: {}",
                        entry.id
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
    use crate::config;

    #[test]
    fn test_babybear_batch_stark_base_field() {
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
        let airs_degrees =
            get_airs_and_degrees_with_prep::<_, _, 1>(&circuit, TablePacking::default()).unwrap();
        let (airs, log_degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

        let mut runner = circuit.runner();

        let x_val = BabyBear::from_u64(7);
        let expected_val = BabyBear::from_u64(13); // 7 + 10 - 3 - 1 = 13
        runner.set_public_inputs(&[x_val, expected_val]).unwrap();
        let traces = runner.run().unwrap();
        let common = CommonData::from_airs_and_degrees(&cfg, &airs, &log_degrees);

        let prover = BatchStarkProver::new(cfg);

        let proof = prover.prove_all_tables(&traces, &common).unwrap();
        assert_eq!(proof.ext_degree, 1);
        assert!(proof.w_binomial.is_none());

        assert!(prover.verify_all_tables(&proof, &common).is_ok());
    }

    #[test]
    fn test_extension_field_batch_stark() {
        const D: usize = 4;
        type Ext4 = BinomialExtensionField<BabyBear, D>;
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
        let airs_degrees =
            get_airs_and_degrees_with_prep::<_, _, D>(&circuit, TablePacking::default()).unwrap();
        let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();

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

        let cfg = config::baby_bear().build();
        let common = CommonData::from_airs_and_degrees(&cfg, &airs, &degrees);
        let prover = BatchStarkProver::new(cfg);
        let proof = prover.prove_all_tables(&traces, &common).unwrap();
        assert_eq!(proof.ext_degree, 4);
        // Ensure W was captured
        let expected_w = <Ext4 as ExtractBinomialW<BabyBear>>::extract_w().unwrap();
        assert_eq!(proof.w_binomial, Some(expected_w));
        prover.verify_all_tables(&proof, &common).unwrap();
    }

    #[test]
    fn test_koalabear_batch_stark_base_field() {
        let mut builder = CircuitBuilder::<KoalaBear>::new();

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
        let airs_degrees =
            get_airs_and_degrees_with_prep::<_, _, 1>(&circuit, TablePacking::default()).unwrap();
        let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
        let mut runner = circuit.runner();

        let a_val = KoalaBear::from_u64(42);
        let b_val = KoalaBear::from_u64(13);
        let expected_val = KoalaBear::from_u64(647); // 42*13 + 100 - (-1)
        runner
            .set_public_inputs(&[a_val, b_val, expected_val])
            .unwrap();
        let traces = runner.run().unwrap();

        let cfg = config::koala_bear().build();
        let common = CommonData::from_airs_and_degrees(&cfg, &airs, &degrees);
        let prover = BatchStarkProver::new(cfg);
        let proof = prover.prove_all_tables(&traces, &common).unwrap();
        assert_eq!(proof.ext_degree, 1);
        assert!(proof.w_binomial.is_none());
        prover.verify_all_tables(&proof, &common).unwrap();
    }

    #[test]
    fn test_koalabear_batch_stark_extension_field_d8() {
        const D: usize = 8;
        type KBExtField = BinomialExtensionField<KoalaBear, D>;
        let mut builder = CircuitBuilder::<KBExtField>::new();

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
        let airs_degrees =
            get_airs_and_degrees_with_prep::<_, _, D>(&circuit, TablePacking::default()).unwrap();
        let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
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

        let cfg = config::koala_bear().build();
        let common = CommonData::from_airs_and_degrees(&cfg, &airs, &degrees);
        let prover = BatchStarkProver::new(cfg);
        let proof = prover.prove_all_tables(&traces, &common).unwrap();
        assert_eq!(proof.ext_degree, 8);
        let expected_w = <KBExtField as ExtractBinomialW<KoalaBear>>::extract_w().unwrap();
        assert_eq!(proof.w_binomial, Some(expected_w));
        prover.verify_all_tables(&proof, &common).unwrap();
    }

    #[test]
    fn test_goldilocks_batch_stark_extension_field_d2() {
        const D: usize = 2;
        type Ext2 = BinomialExtensionField<Goldilocks, D>;
        let mut builder = CircuitBuilder::<Ext2>::new();

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
        let airs_degrees =
            get_airs_and_degrees_with_prep::<_, _, D>(&circuit, TablePacking::default()).unwrap();
        let (airs, degrees): (Vec<_>, Vec<usize>) = airs_degrees.into_iter().unzip();
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

        let cfg = config::goldilocks().build();
        let common = CommonData::from_airs_and_degrees(&cfg, &airs, &degrees);
        let prover = BatchStarkProver::new(cfg);
        let proof = prover.prove_all_tables(&traces, &common).unwrap();
        assert_eq!(proof.ext_degree, 2);
        let expected_w = <Ext2 as ExtractBinomialW<Goldilocks>>::extract_w().unwrap();
        assert_eq!(proof.w_binomial, Some(expected_w));
        prover.verify_all_tables(&proof, &common).unwrap();
    }
}
