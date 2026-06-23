//! Shared building blocks for the Poseidon1 and Poseidon2 permutation operations.
//!
//! The two permutation variants differ only in their AIR backend, trace row
//! type, and the operation label used in diagnostics. Their execution state and
//! private-data layout are identical and live here, parameterized over a
//! zero-sized [`PoseidonVariant`] marker.

mod builder;
mod call;
mod executor;
mod plugin;
mod state;

use alloc::sync::Arc;
use alloc::vec::Vec;

use p3_field::Field;
use p3_poseidon1_circuit_air::Poseidon1CircuitRow;

pub(crate) use call::{PoseidonPermCall, PoseidonPermCallBase};
pub(crate) use plugin::PoseidonCircuitPlugin;
pub(crate) use state::PoseidonExecutionState;
pub use state::PoseidonPermPrivateData;

use crate::builder::{NonPrimitiveOpParams, NpoLoweringContext};
use crate::ops::poseidon1_perm::config::{Poseidon1Config, Poseidon1PermConfigData};
use crate::ops::poseidon2_perm::config::{Poseidon2Config, Poseidon2PermConfigData};
use crate::ops::poseidon2_perm::trace::Poseidon2CircuitRow;
use crate::ops::{NpoConfig, NpoTypeId};
use crate::types::{ExprId, NonPrimitiveOpId, WitnessId};
use crate::{CircuitBuilderError, CircuitError};

/// Permutation execution closure shared by both Poseidon variants.
///
/// Takes `width_ext` field elements and returns `width_ext` output elements.
/// For D=1 mode, `width_ext == width` and the elements are base field values.
pub(crate) type PoseidonPermExec<F> = Arc<dyn Fn(&[F]) -> Vec<F> + Send + Sync>;

/// Plain field bundle assembled by the executor before constructing a variant's
/// concrete trace row.
pub struct PoseidonRowFields<F> {
    pub new_start: bool,
    pub merkle_path: bool,
    pub mmcs_bit: bool,
    pub mmcs_index_sum: F,
    pub input_values: Vec<F>,
    pub in_ctl: Vec<bool>,
    pub input_indices: Vec<u32>,
    pub out_ctl: Vec<bool>,
    pub output_indices: Vec<u32>,
    pub mmcs_index_sum_idx: u32,
    pub mmcs_ctl_enabled: bool,
}

/// Config methods consumed by the shared Poseidon plugin and executor.
pub trait PoseidonConfigApi: Copy {
    fn d(self) -> usize;
    fn width(self) -> usize;
    fn rate_ext(self) -> usize;
    fn capacity_ext(self) -> usize;
    fn width_ext(self) -> usize;
    fn validate_io_counts(
        self,
        input_count: usize,
        output_count: usize,
        merkle_path: bool,
    ) -> Result<(), CircuitBuilderError>;
    fn lower_inputs<F: Field>(
        self,
        input_exprs: &[Vec<ExprId>],
        ctx: &NpoLoweringContext<'_, F>,
        merkle_path: bool,
    ) -> Result<Vec<Vec<WitnessId>>, CircuitBuilderError>;
}

impl PoseidonConfigApi for Poseidon1Config {
    fn d(self) -> usize {
        Self::d(self)
    }
    fn width(self) -> usize {
        Self::width(self)
    }
    fn rate_ext(self) -> usize {
        Self::rate_ext(self)
    }
    fn capacity_ext(self) -> usize {
        Self::capacity_ext(self)
    }
    fn width_ext(self) -> usize {
        Self::width_ext(self)
    }
    fn validate_io_counts(
        self,
        input_count: usize,
        output_count: usize,
        merkle_path: bool,
    ) -> Result<(), CircuitBuilderError> {
        Self::validate_io_counts(self, input_count, output_count, merkle_path)
    }
    fn lower_inputs<F: Field>(
        self,
        input_exprs: &[Vec<ExprId>],
        ctx: &NpoLoweringContext<'_, F>,
        merkle_path: bool,
    ) -> Result<Vec<Vec<WitnessId>>, CircuitBuilderError> {
        Self::lower_inputs(self, input_exprs, ctx, merkle_path)
    }
}

impl PoseidonConfigApi for Poseidon2Config {
    fn d(self) -> usize {
        Self::d(self)
    }
    fn width(self) -> usize {
        Self::width(self)
    }
    fn rate_ext(self) -> usize {
        Self::rate_ext(self)
    }
    fn capacity_ext(self) -> usize {
        Self::capacity_ext(self)
    }
    fn width_ext(self) -> usize {
        Self::width_ext(self)
    }
    fn validate_io_counts(
        self,
        input_count: usize,
        output_count: usize,
        merkle_path: bool,
    ) -> Result<(), CircuitBuilderError> {
        Self::validate_io_counts(self, input_count, output_count, merkle_path)
    }
    fn lower_inputs<F: Field>(
        self,
        input_exprs: &[Vec<ExprId>],
        ctx: &NpoLoweringContext<'_, F>,
        merkle_path: bool,
    ) -> Result<Vec<Vec<WitnessId>>, CircuitBuilderError> {
        Self::lower_inputs(self, input_exprs, ctx, merkle_path)
    }
}

/// Type-level marker distinguishing the two Poseidon permutation variants so the
/// shared execution machinery can stay generic over them.
pub trait PoseidonVariant: Send + Sync + 'static {
    /// Per-row trace type produced by this variant's executor and trace generator.
    type Row<F>: core::fmt::Debug + Send + Sync + 'static
    where
        F: Field;
    /// Field-agnostic configuration bundle for this variant.
    type Config: PoseidonConfigApi + core::fmt::Debug + Send + Sync + 'static;

    /// Operation label used in lowering diagnostics and CTL/witness slot names.
    const OP_LABEL: &'static str;
    /// Short variant name used in the executor's chain-state trace log line.
    const DEBUG_NAME: &'static str;
    /// Default configuration for the extension-mode call struct.
    const DEFAULT_CALL_CONFIG: Self::Config;
    /// Default configuration for the base-field (D=1) call struct.
    const DEFAULT_BASE_CONFIG: Self::Config;

    /// Build the `NpoTypeId` for this variant and config (a soundness boundary:
    /// the two variants must produce distinct CTL bus keys).
    fn npo_type_id(config: Self::Config) -> NpoTypeId;

    /// Error returned when chaining is requested but no prior output exists.
    fn chain_missing_error(operation_index: NonPrimitiveOpId) -> CircuitError;

    /// Extract the `(new_start, merkle_path)` flags from the operation params.
    fn perm_params<F>(params: &NonPrimitiveOpParams<F>) -> Option<(bool, bool)>;

    /// Build this variant's builder-side operation params for one perm row.
    fn perm_op_params<F>(new_start: bool, merkle_path: bool) -> NonPrimitiveOpParams<F>;

    /// Wrap a permutation closure in this variant's `NpoConfig` payload.
    fn make_config_data<F: Field>(exec: PoseidonPermExec<F>) -> NpoConfig;

    /// Recover the permutation closure from this variant's stored config payload.
    fn exec_from_config<F: Field>(config: &NpoConfig) -> Option<PoseidonPermExec<F>>;

    /// Construct this variant's concrete trace row from the shared field bundle.
    fn build_row<F: Field>(fields: PoseidonRowFields<F>) -> Self::Row<F>;
}

/// Marker for the Poseidon1 permutation variant.
pub enum Poseidon1Variant {}

/// Marker for the Poseidon2 permutation variant.
pub enum Poseidon2Variant {}

impl PoseidonVariant for Poseidon1Variant {
    type Row<F>
        = Poseidon1CircuitRow<F>
    where
        F: Field;
    type Config = Poseidon1Config;

    const OP_LABEL: &'static str = "Poseidon1Perm";
    const DEBUG_NAME: &'static str = "Poseidon1";
    const DEFAULT_CALL_CONFIG: Self::Config = Poseidon1Config::BABY_BEAR_D4_W16;
    const DEFAULT_BASE_CONFIG: Self::Config = Poseidon1Config::BABY_BEAR_D1_W16;

    fn npo_type_id(config: Self::Config) -> NpoTypeId {
        NpoTypeId::poseidon1_perm(config)
    }

    fn chain_missing_error(operation_index: NonPrimitiveOpId) -> CircuitError {
        CircuitError::Poseidon1ChainMissingPreviousState { operation_index }
    }

    fn perm_params<F>(params: &NonPrimitiveOpParams<F>) -> Option<(bool, bool)> {
        params.as_poseidon1_perm()
    }

    fn perm_op_params<F>(new_start: bool, merkle_path: bool) -> NonPrimitiveOpParams<F> {
        NonPrimitiveOpParams::Poseidon1Perm {
            new_start,
            merkle_path,
        }
    }

    fn make_config_data<F: Field>(exec: PoseidonPermExec<F>) -> NpoConfig {
        NpoConfig::new(Poseidon1PermConfigData { exec })
    }

    fn exec_from_config<F: Field>(config: &NpoConfig) -> Option<PoseidonPermExec<F>> {
        config
            .downcast_ref::<Poseidon1PermConfigData<F>>()
            .map(|cfg| cfg.exec.clone())
    }

    fn build_row<F: Field>(fields: PoseidonRowFields<F>) -> Self::Row<F> {
        Poseidon1CircuitRow {
            new_start: fields.new_start,
            merkle_path: fields.merkle_path,
            mmcs_bit: fields.mmcs_bit,
            mmcs_index_sum: fields.mmcs_index_sum,
            input_values: fields.input_values,
            in_ctl: fields.in_ctl,
            input_indices: fields.input_indices,
            out_ctl: fields.out_ctl,
            output_indices: fields.output_indices,
            mmcs_index_sum_idx: fields.mmcs_index_sum_idx,
            mmcs_ctl_enabled: fields.mmcs_ctl_enabled,
        }
    }
}

impl PoseidonVariant for Poseidon2Variant {
    type Row<F>
        = Poseidon2CircuitRow<F>
    where
        F: Field;
    type Config = Poseidon2Config;

    const OP_LABEL: &'static str = "Poseidon2Perm";
    const DEBUG_NAME: &'static str = "Poseidon2";
    const DEFAULT_CALL_CONFIG: Self::Config = Poseidon2Config::BABY_BEAR_D4_W16;
    const DEFAULT_BASE_CONFIG: Self::Config = Poseidon2Config::BABY_BEAR_D1_W16;

    fn npo_type_id(config: Self::Config) -> NpoTypeId {
        NpoTypeId::poseidon2_perm(config)
    }

    fn chain_missing_error(operation_index: NonPrimitiveOpId) -> CircuitError {
        CircuitError::Poseidon2ChainMissingPreviousState { operation_index }
    }

    fn perm_params<F>(params: &NonPrimitiveOpParams<F>) -> Option<(bool, bool)> {
        params.as_poseidon2_perm()
    }

    fn perm_op_params<F>(new_start: bool, merkle_path: bool) -> NonPrimitiveOpParams<F> {
        NonPrimitiveOpParams::Poseidon2Perm {
            new_start,
            merkle_path,
        }
    }

    fn make_config_data<F: Field>(exec: PoseidonPermExec<F>) -> NpoConfig {
        NpoConfig::new(Poseidon2PermConfigData { exec })
    }

    fn exec_from_config<F: Field>(config: &NpoConfig) -> Option<PoseidonPermExec<F>> {
        config
            .downcast_ref::<Poseidon2PermConfigData<F>>()
            .map(|cfg| cfg.exec.clone())
    }

    fn build_row<F: Field>(fields: PoseidonRowFields<F>) -> Self::Row<F> {
        Poseidon2CircuitRow {
            new_start: fields.new_start,
            merkle_path: fields.merkle_path,
            mmcs_bit: fields.mmcs_bit,
            mmcs_index_sum: fields.mmcs_index_sum,
            input_values: fields.input_values,
            in_ctl: fields.in_ctl,
            input_indices: fields.input_indices,
            out_ctl: fields.out_ctl,
            output_indices: fields.output_indices,
            mmcs_index_sum_idx: fields.mmcs_index_sum_idx,
            mmcs_ctl_enabled: fields.mmcs_ctl_enabled,
        }
    }
}
