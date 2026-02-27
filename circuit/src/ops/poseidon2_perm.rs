//! Poseidon2 permutation non-primitive operation (one Poseidon2 call per row).
//!
//! This module contains all Poseidon2 permutation related code:
//! - Builder API (`Poseidon2PermCall`, `Poseidon2PermOps`)
//! - Executor (`Poseidon2PermExecutor`)
//! - Execution state (`Poseidon2ExecutionState`, `Poseidon2PermRowRecord`)
//! - Private data (`Poseidon2PermPrivateData`)
//! - Trace generation types (`Poseidon2Params`, `Poseidon2CircuitRow`, `Poseidon2Trace`)
//!
//! This operation is designed to support both standard hashing and specific logic required for
//! Merkle path verification within a circuit. Its features include:
//!
//! - **Hashing**: Performs a standard Poseidon2 permutation.
//! - **Chaining**: Can start a new hash computation or continue from the output of the previous row
//!   (controlled by `new_start`).
//! - **Merkle Path Verification**: When `merkle_path` is enabled, it supports logic for verifying
//!   a path up a Merkle tree. This involves conditionally arranging inputs (sibling vs. computed hash)
//!   based on a direction bit (`mmcs_bit`).
//! - **Index Accumulation**: Supports accumulating path indices (`mmcs_index_sum`) to verify the
//!   leaf's position in the tree.
//!
//! Only supports extension degree D=4 for now.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::any::Any;
use core::fmt::Debug;

use hashbrown::HashMap;
use p3_field::{ExtensionField, Field, PrimeCharacteristicRing, PrimeField};
use serde::{Deserialize, Serialize};

use crate::builder::{CircuitBuilder, NonPrimitiveOpParams, NpoCircuitPlugin, NpoLoweringContext};
use crate::circuit::CircuitField;
use crate::op::{ExecutionContext, NonPrimitiveExecutor, NpoTypeId, Op, OpExecutionState};
use crate::tables::{NonPrimitiveTrace, TraceGeneratorFn};
use crate::types::{ExprId, NonPrimitiveOpId, WitnessId};
use crate::{CircuitBuilderError, CircuitError, PreprocessedColumns};

// ============================================================================
// Configuration
// ============================================================================

/// Poseidon2 configuration used as a stable operation key and parameter source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub enum Poseidon2Config {
    /// BabyBear with extension degree D=1 (base field challenges), width 16.
    BabyBearD1Width16,
    BabyBearD4Width16,
    BabyBearD4Width24,
    /// KoalaBear with extension degree D=1 (base field challenges), width 16.
    KoalaBearD1Width16,
    KoalaBearD4Width16,
    KoalaBearD4Width24,
    /// Goldilocks with extension degree D=2, width 8 (matches Poseidon2Goldilocks<8>).
    GoldilocksD2Width8,
}

impl Poseidon2Config {
    pub const fn d(self) -> usize {
        match self {
            Self::BabyBearD1Width16 | Self::KoalaBearD1Width16 => 1,
            Self::GoldilocksD2Width8 => 2,
            Self::BabyBearD4Width16
            | Self::BabyBearD4Width24
            | Self::KoalaBearD4Width16
            | Self::KoalaBearD4Width24 => 4,
        }
    }

    pub const fn width(self) -> usize {
        match self {
            Self::BabyBearD1Width16
            | Self::BabyBearD4Width16
            | Self::KoalaBearD1Width16
            | Self::KoalaBearD4Width16 => 16,
            Self::BabyBearD4Width24 | Self::KoalaBearD4Width24 => 24,
            Self::GoldilocksD2Width8 => 8,
        }
    }

    /// Rate in extension field elements (WIDTH / D for D=4, or WIDTH for D=1).
    pub const fn rate_ext(self) -> usize {
        match self {
            Self::BabyBearD1Width16 | Self::KoalaBearD1Width16 => 8,
            Self::BabyBearD4Width16 | Self::KoalaBearD4Width16 => 2,
            Self::BabyBearD4Width24 | Self::KoalaBearD4Width24 => 4,
            Self::GoldilocksD2Width8 => 2,
        }
    }

    pub const fn rate(self) -> usize {
        self.rate_ext() * self.d()
    }

    /// Capacity in extension field elements.
    pub const fn capacity_ext(self) -> usize {
        match self {
            Self::BabyBearD1Width16 | Self::KoalaBearD1Width16 => 8,
            Self::BabyBearD4Width16
            | Self::BabyBearD4Width24
            | Self::KoalaBearD4Width16
            | Self::KoalaBearD4Width24 => 2,
            Self::GoldilocksD2Width8 => 2,
        }
    }

    pub const fn sbox_degree(self) -> u64 {
        match self {
            Self::BabyBearD1Width16 | Self::BabyBearD4Width16 | Self::BabyBearD4Width24 => 7,
            Self::KoalaBearD1Width16 | Self::KoalaBearD4Width16 | Self::KoalaBearD4Width24 => 3,
            Self::GoldilocksD2Width8 => 7,
        }
    }

    pub const fn sbox_registers(self) -> usize {
        match self {
            Self::BabyBearD1Width16
            | Self::BabyBearD4Width16
            | Self::BabyBearD4Width24
            | Self::GoldilocksD2Width8 => 1,
            Self::KoalaBearD1Width16 | Self::KoalaBearD4Width16 | Self::KoalaBearD4Width24 => 0,
        }
    }

    pub const fn half_full_rounds(self) -> usize {
        match self {
            Self::BabyBearD1Width16
            | Self::BabyBearD4Width16
            | Self::BabyBearD4Width24
            | Self::KoalaBearD1Width16
            | Self::KoalaBearD4Width16
            | Self::KoalaBearD4Width24
            | Self::GoldilocksD2Width8 => 4,
        }
    }

    pub const fn partial_rounds(self) -> usize {
        match self {
            Self::BabyBearD1Width16 | Self::BabyBearD4Width16 => 13,
            Self::BabyBearD4Width24 => 21,
            Self::KoalaBearD1Width16 | Self::KoalaBearD4Width16 => 20,
            Self::KoalaBearD4Width24 => 23,
            Self::GoldilocksD2Width8 => 22,
        }
    }

    pub const fn width_ext(self) -> usize {
        self.rate_ext() + self.capacity_ext()
    }

    /// Stable string name for this config variant, used to build `NpoTypeId`.
    pub const fn variant_name(self) -> &'static str {
        match self {
            Self::BabyBearD1Width16 => "baby_bear_d1_w16",
            Self::BabyBearD4Width16 => "baby_bear_d4_w16",
            Self::BabyBearD4Width24 => "baby_bear_d4_w24",
            Self::KoalaBearD1Width16 => "koala_bear_d1_w16",
            Self::KoalaBearD4Width16 => "koala_bear_d4_w16",
            Self::KoalaBearD4Width24 => "koala_bear_d4_w24",
            Self::GoldilocksD2Width8 => "goldilocks_d2_w8",
        }
    }

    /// Parse a `Poseidon2Config` from a variant name string.
    pub fn from_variant_name(name: &str) -> Option<Self> {
        match name {
            "baby_bear_d1_w16" => Some(Self::BabyBearD1Width16),
            "baby_bear_d4_w16" => Some(Self::BabyBearD4Width16),
            "baby_bear_d4_w24" => Some(Self::BabyBearD4Width24),
            "koala_bear_d1_w16" => Some(Self::KoalaBearD1Width16),
            "koala_bear_d4_w16" => Some(Self::KoalaBearD4Width16),
            "koala_bear_d4_w24" => Some(Self::KoalaBearD4Width24),
            "goldilocks_d2_w8" => Some(Self::GoldilocksD2Width8),
            _ => None,
        }
    }
}

/// Poseidon2 permutation execution closure (extension field mode).
/// Takes width_ext extension field limbs and returns width_ext output limbs.
pub type Poseidon2PermExec<F> = Arc<dyn Fn(&[F]) -> Vec<F> + Send + Sync>;

/// Type alias for the Poseidon2 permutation execution closure for D=1 (base field).
///
/// The closure takes 16 base field elements and returns 16 base field elements.
pub type Poseidon2PermExecBase<F> = Arc<dyn Fn(&[F; 16]) -> [F; 16] + Send + Sync>;

/// Config data stored inside `NpoConfig` for Poseidon2 D>=2 (extension field) mode.
#[derive(Clone)]
pub struct Poseidon2PermConfigData<F> {
    pub config: Poseidon2Config,
    pub exec: Poseidon2PermExec<F>,
}

/// Config data stored inside `NpoConfig` for Poseidon2 D=1 (base field) mode.
#[derive(Clone)]
pub struct Poseidon2PermBaseConfigData<F> {
    pub config: Poseidon2Config,
    pub exec: Poseidon2PermExecBase<F>,
}

/// Internal enum to hold either extension or base-field config payload.
enum Poseidon2PluginConfig<F> {
    Ext(Poseidon2PermConfigData<F>),
    Base(Poseidon2PermBaseConfigData<F>),
}

fn get_witness_id_for_poseidon2(
    expr_to_widx: &HashMap<ExprId, WitnessId>,
    expr_id: ExprId,
    context: &str,
) -> Result<WitnessId, CircuitBuilderError> {
    expr_to_widx
        .get(&expr_id)
        .copied()
        .ok_or_else(|| CircuitBuilderError::MissingExprMapping {
            expr_id,
            context: context.to_string(),
        })
}

/// Circuit-layer plugin for Poseidon2 non-primitive operations.
pub struct Poseidon2CircuitPlugin<F: Field> {
    type_id: NpoTypeId,
    poseidon2_config: Poseidon2Config,
    config_payload: Poseidon2PluginConfig<F>,
    trace_gen: TraceGeneratorFn<F>,
}

impl<F: Field> Poseidon2CircuitPlugin<F> {
    pub fn new_ext(
        config: Poseidon2Config,
        exec: Poseidon2PermExec<F>,
        trace_gen: TraceGeneratorFn<F>,
    ) -> Self {
        let type_id = NpoTypeId::poseidon2_perm(config);
        let payload = Poseidon2PluginConfig::Ext(Poseidon2PermConfigData { config, exec });
        Self {
            type_id,
            poseidon2_config: config,
            config_payload: payload,
            trace_gen,
        }
    }

    pub fn new_base(
        config: Poseidon2Config,
        exec: Poseidon2PermExecBase<F>,
        trace_gen: TraceGeneratorFn<F>,
    ) -> Self {
        let type_id = NpoTypeId::poseidon2_perm(config);
        let payload = Poseidon2PluginConfig::Base(Poseidon2PermBaseConfigData { config, exec });
        Self {
            type_id,
            poseidon2_config: config,
            config_payload: payload,
            trace_gen,
        }
    }

    /// Minimal plugin used when an op is enabled via `enable_op` without an explicit
    /// Poseidon2 registration. The executor will panic if actually invoked; this path
    /// is intended only for tests that never execute the circuit.
    pub fn new_config_only(config: Poseidon2Config) -> Self {
        let type_id = NpoTypeId::poseidon2_perm(config);
        let dummy_exec: Poseidon2PermExec<F> =
            Arc::new(|_| panic!("Poseidon2PermExec used without proper registration"));
        let payload = Poseidon2PluginConfig::Ext(Poseidon2PermConfigData {
            config,
            exec: dummy_exec,
        });
        let dummy_trace: TraceGeneratorFn<F> = |_op_states| Ok(None);
        Self {
            type_id,
            poseidon2_config: config,
            config_payload: payload,
            trace_gen: dummy_trace,
        }
    }
}

impl<F> NpoCircuitPlugin<F> for Poseidon2CircuitPlugin<F>
where
    F: CircuitField,
{
    fn type_id(&self) -> NpoTypeId {
        self.type_id.clone()
    }

    fn lower(
        &self,
        data: &crate::builder::NonPrimitiveOperationData<F>,
        output_exprs: &[(u32, ExprId)],
        ctx: &mut NpoLoweringContext<'_, F>,
    ) -> Result<crate::op::Op<F>, crate::builder::CircuitBuilderError> {
        let expr_to_widx = &mut *ctx.expr_to_widx;

        // Enforce that output ExprIds map to witness IDs.
        for (_output_idx, expr_id) in output_exprs {
            expr_to_widx
                .entry(*expr_id)
                .or_insert_with(|| (ctx.alloc_witness_id)(expr_id.0 as usize));
        }

        // Recover config from plugin field.
        let config = self.poseidon2_config;
        let (new_start, merkle_path) = match data.params.as_ref().ok_or_else(|| {
            crate::builder::CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                op: data.op_type.clone(),
            }
        })? {
            NonPrimitiveOpParams::Poseidon2Perm {
                new_start,
                merkle_path,
            } => (*new_start, *merkle_path),
            _ => {
                return Err(
                    crate::builder::CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                        op: data.op_type.clone(),
                    },
                );
            }
        };

        let d = config.d();
        let width_ext = config.width_ext();
        let rate_ext = config.rate_ext();
        let is_d1_mode = d == 1;
        let expected_inputs_ext = width_ext + 2;

        let expected_inputs = if is_d1_mode { 16 } else { expected_inputs_ext };
        if data.input_exprs.len() != expected_inputs {
            return Err(crate::builder::CircuitBuilderError::NonPrimitiveOpArity {
                op: "Poseidon2Perm",
                expected: format!("{} inputs (D=1: 16, D>1: width_ext+2)", expected_inputs),
                got: data.input_exprs.len(),
            });
        }

        let valid_output_count = if is_d1_mode {
            data.output_exprs.len() == 8 || data.output_exprs.len() == 16
        } else {
            data.output_exprs.len() == rate_ext || data.output_exprs.len() == width_ext
        };

        if !valid_output_count {
            return Err(crate::builder::CircuitBuilderError::NonPrimitiveOpArity {
                op: "Poseidon2Perm",
                expected: if is_d1_mode {
                    "8 or 16 outputs for D=1 mode".to_string()
                } else {
                    format!("{rate_ext} or {width_ext} outputs for D>1 mode")
                },
                got: data.output_exprs.len(),
            });
        }

        let mut inputs_widx: Vec<Vec<WitnessId>> = Vec::with_capacity(data.input_exprs.len());

        if is_d1_mode {
            // D=1 mode: 16 input elements (no mmcs_index_sum, no mmcs_bit)
            for (i, limb_exprs) in data.input_exprs.iter().enumerate() {
                if !(limb_exprs.is_empty() || limb_exprs.len() == 1) {
                    return Err(crate::builder::CircuitBuilderError::NonPrimitiveOpArity {
                        op: "Poseidon2Perm",
                        expected: "0 or 1 base field element per input".to_string(),
                        got: limb_exprs.len(),
                    });
                }
                let limb_widx = limb_exprs
                    .iter()
                    .map(|&expr| {
                        get_witness_id_for_poseidon2(
                            expr_to_widx,
                            expr,
                            &format!("Poseidon2Perm D=1 input {i}"),
                        )
                    })
                    .collect::<Result<Vec<WitnessId>, _>>()?;
                inputs_widx.push(limb_widx);
            }
        } else {
            for (i, limb_exprs) in data.input_exprs.iter().take(width_ext).enumerate() {
                if !(limb_exprs.is_empty() || limb_exprs.len() == 1) {
                    return Err(crate::builder::CircuitBuilderError::NonPrimitiveOpArity {
                        op: "Poseidon2Perm",
                        expected: "0 or 1 extension element per input limb".to_string(),
                        got: limb_exprs.len(),
                    });
                }
                let limb_widx = limb_exprs
                    .iter()
                    .map(|&expr| {
                        get_witness_id_for_poseidon2(
                            expr_to_widx,
                            expr,
                            &format!("Poseidon2Perm input limb {i}"),
                        )
                    })
                    .collect::<Result<Vec<WitnessId>, _>>()?;
                inputs_widx.push(limb_widx);
            }

            let mmcs_exprs = &data.input_exprs[width_ext];
            if !(mmcs_exprs.is_empty() || mmcs_exprs.len() == 1) {
                return Err(crate::builder::CircuitBuilderError::NonPrimitiveOpArity {
                    op: "Poseidon2Perm",
                    expected: "0 or 1 element for mmcs_index_sum".to_string(),
                    got: mmcs_exprs.len(),
                });
            }
            let mmcs_widx = mmcs_exprs
                .iter()
                .map(|&expr| {
                    get_witness_id_for_poseidon2(
                        expr_to_widx,
                        expr,
                        "Poseidon2Perm mmcs_index_sum input",
                    )
                })
                .collect::<Result<Vec<WitnessId>, _>>()?;
            inputs_widx.push(mmcs_widx);

            let mmcs_bit_exprs = &data.input_exprs[width_ext + 1];
            if !(mmcs_bit_exprs.is_empty() || mmcs_bit_exprs.len() == 1) {
                return Err(crate::builder::CircuitBuilderError::NonPrimitiveOpArity {
                    op: "Poseidon2Perm",
                    expected: "0 or 1 element for mmcs_bit".to_string(),
                    got: mmcs_bit_exprs.len(),
                });
            }
            let mmcs_bit_widx = mmcs_bit_exprs
                .iter()
                .map(|&expr| {
                    get_witness_id_for_poseidon2(expr_to_widx, expr, "Poseidon2Perm mmcs_bit input")
                })
                .collect::<Result<Vec<WitnessId>, _>>()?;
            inputs_widx.push(mmcs_bit_widx);
        }

        // Output CTL exposures (0 or 1 element each).
        //
        // For Poseidon2Perm we take outputs exclusively from `data.output_exprs` to avoid
        // generating multiple witness ids per output limb (which breaks both execution and
        // trace building).
        let mut poseidon2_outputs: Vec<Vec<WitnessId>> =
            Vec::with_capacity(data.output_exprs.len());
        for (i, limb_exprs) in data.output_exprs.iter().enumerate() {
            if !(limb_exprs.is_empty() || limb_exprs.len() == 1) {
                return Err(crate::builder::CircuitBuilderError::NonPrimitiveOpArity {
                    op: "Poseidon2Perm",
                    expected: "0 or 1 element per output".to_string(),
                    got: limb_exprs.len(),
                });
            }
            if let Some(&expr) = limb_exprs.first() {
                let w = get_witness_id_for_poseidon2(
                    expr_to_widx,
                    expr,
                    &format!("Poseidon2Perm output {i}"),
                )?;
                poseidon2_outputs.push(vec![w]);
            } else {
                poseidon2_outputs.push(Vec::new());
            }
        }

        Ok(Op::NonPrimitiveOpWithExecutor {
            inputs: inputs_widx,
            outputs: poseidon2_outputs,
            executor: Box::new(Poseidon2PermExecutor::new(
                data.op_type.clone(),
                config,
                new_start,
                merkle_path,
            )),
            op_id: data.op_id,
        })
    }

    fn trace_generator(&self) -> TraceGeneratorFn<F> {
        self.trace_gen
    }

    fn config(&self) -> crate::op::NpoConfig {
        match &self.config_payload {
            Poseidon2PluginConfig::Ext(d) => crate::op::NpoConfig::new(d.clone()),
            Poseidon2PluginConfig::Base(d) => crate::op::NpoConfig::new(d.clone()),
        }
    }
}

// ============================================================================
// Private Data
// ============================================================================

/// Private data for Poseidon2 permutation.
/// Only used for Merkle mode operations, contains exactly `SIBLING_LIMBS` extension field limbs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Poseidon2PermPrivateData<F, const SIBLING_LIMBS: usize> {
    pub sibling: [F; SIBLING_LIMBS],
}

// ============================================================================
// Execution State
// ============================================================================

/// Execution state for Poseidon2 permutation operations.
#[derive(Debug, Default)]
struct Poseidon2ExecutionState<F> {
    last_output_normal: Option<Vec<F>>,
    last_output_merkle: Option<Vec<F>>,
    /// Circuit rows captured during execution.
    rows: Vec<Poseidon2CircuitRow<F>>,
}

impl<F: Send + Sync + Debug + 'static> OpExecutionState for Poseidon2ExecutionState<F> {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
}

/// User-facing arguments for adding a Poseidon2 perm row.
pub struct Poseidon2PermCall {
    /// Poseidon2 configuration for this permutation row.
    pub config: Poseidon2Config,
    /// Flag indicating whether a new chain is started.
    pub new_start: bool,
    /// Flag indicating whether we are verifying a Merkle path
    pub merkle_path: bool,
    /// MMCS direction bit input (base field, boolean).
    ///
    /// Required when `merkle_path = true`. When `merkle_path = false`, this may be omitted and
    /// defaults to 0 (not exposed via CTL).
    pub mmcs_bit: Option<ExprId>,
    /// Optional CTL exposure for each input limb (one extension element).
    /// If `None`, the limb is not exposed via CTL (in_ctl = 0).
    /// Note: For Merkle mode, unexposed limbs are provided via Poseidon2PermPrivateData (the sibling).
    pub inputs: Vec<Option<ExprId>>,
    /// Output exposure flags for rate limbs (CTL-verified against witness table).
    ///
    /// When `out_ctl[i]` is true, this call allocates an output witness expression for limb `i`
    /// (returned from `add_poseidon2_perm`) and exposes it via CTL.
    pub out_ctl: Vec<bool>,
    /// Whether to return all 4 output limbs (for challenger use).
    ///
    /// When true, outputs 2-3 are also allocated and returned, but NOT CTL-verified
    /// (they are capacity elements, constrained only by the Poseidon2 permutation itself).
    /// This is used by challenger operations that need the full sponge state.
    pub return_all_outputs: bool,
    /// Optional MMCS index accumulator value to expose.
    pub mmcs_index_sum: Option<ExprId>,
}

/// Convenience helpers to build calls with defaults.
impl Default for Poseidon2PermCall {
    fn default() -> Self {
        Self {
            config: Poseidon2Config::BabyBearD4Width16,
            new_start: false,
            merkle_path: false,
            mmcs_bit: None,
            inputs: vec![None; 4],
            out_ctl: vec![false; 2],
            return_all_outputs: false,
            mmcs_index_sum: None,
        }
    }
}

/// User-facing arguments for adding a Poseidon2 perm row with D=1 (base field).
///
/// This variant is for D=1 configurations where we have 16 base field elements
/// instead of 4 extension field limbs.
pub struct Poseidon2PermCallBase {
    /// Poseidon2 configuration for this permutation row (must be D=1).
    pub config: Poseidon2Config,
    /// Flag indicating whether a new chain is started.
    pub new_start: bool,
    /// Optional CTL exposure for each of the 16 input elements.
    /// If `None`, the element is not exposed via CTL.
    pub inputs: [Option<ExprId>; 16],
    /// Output exposure flags for the rate elements (first RATE=8 elements).
    /// When `out_ctl[i]` is true for i in 0..8, output[i] is CTL-verified.
    pub out_ctl: [bool; 8],
    /// Whether to return all 16 output elements (for challenger use).
    /// When true, outputs 8-15 are also allocated and returned, but NOT CTL-verified
    /// (they are capacity elements, constrained only by the Poseidon2 permutation itself).
    pub return_all_outputs: bool,
}

impl Default for Poseidon2PermCallBase {
    fn default() -> Self {
        Self {
            config: Poseidon2Config::BabyBearD1Width16,
            new_start: false,
            inputs: [None; 16],
            out_ctl: [false; 8],
            return_all_outputs: false,
        }
    }
}

pub trait Poseidon2PermOps<F: Clone + PrimeCharacteristicRing + Eq> {
    /// Add a Poseidon2 perm row (one permutation) for D=4 extension field.
    ///
    /// - `new_start`: if true, this row starts a new chain (no chaining from previous row).
    /// - `merkle_path`: if true, Merkle-path chaining semantics apply (chained digest placement depends on `mmcs_bit`).
    /// - `mmcs_bit`: Merkle direction bit witness for this row (used when `merkle_path` is true).
    /// - `inputs`: optional CTL exposure per limb (extension element, length 4 if provided).
    ///   Base-component inputs are not supported; unexposed limbs in Merkle mode are
    ///   provided separately via `Poseidon2PermPrivateData`.
    /// - `out_ctl`: whether to allocate/expose output limbs 0–1 via CTL.
    /// - `return_all_outputs`: if true, also returns outputs 2-3 (not CTL-exposed, for challenger).
    /// - `mmcs_index_sum`: optional exposure of the MMCS index accumulator (base field element).
    ///
    /// Returns `(op_id, outputs)` where outputs has length width_ext:
    /// - outputs[0..rate_ext]: present if `out_ctl[i]` is true (CTL-verified)
    /// - outputs[rate_ext..]: present if `return_all_outputs` is true (NOT CTL-verified, capacity elements)
    fn add_poseidon2_perm(
        &mut self,
        call: Poseidon2PermCall,
    ) -> Result<(NonPrimitiveOpId, Vec<Option<ExprId>>), crate::CircuitBuilderError>;

    /// Add a Poseidon2 perm row (one permutation) for D=1 base field.
    ///
    /// This variant is for D=1 configurations where the permutation operates on
    /// 16 base field elements directly (no extension field packing).
    ///
    /// - `new_start`: if true, this row starts a new chain (no chaining from previous row).
    /// - `inputs`: optional CTL exposure for each of the 16 base field elements.
    /// - `out_ctl`: whether to allocate/expose output elements 0-7 (rate) via CTL.
    /// - `return_all_outputs`: if true, also returns outputs 8-15 (not CTL-exposed, capacity).
    ///
    /// Returns `(op_id, outputs)` where outputs is `[Option<ExprId>; 16]`:
    /// - outputs[0-7]: present if `out_ctl[i]` is true (CTL-verified, rate elements)
    /// - outputs[8-15]: present if `return_all_outputs` is true (NOT CTL-verified, capacity elements)
    fn add_poseidon2_perm_base(
        &mut self,
        call: Poseidon2PermCallBase,
    ) -> Result<(NonPrimitiveOpId, [Option<ExprId>; 16]), crate::CircuitBuilderError>;
}

impl<F: Field> Poseidon2PermOps<F> for CircuitBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + Eq + core::hash::Hash,
{
    fn add_poseidon2_perm(
        &mut self,
        call: Poseidon2PermCall,
    ) -> Result<(NonPrimitiveOpId, Vec<Option<ExprId>>), crate::CircuitBuilderError> {
        let op_type = NpoTypeId::poseidon2_perm(call.config);
        self.ensure_op_enabled(&op_type)?;
        if call.merkle_path && call.mmcs_bit.is_none() {
            return Err(crate::CircuitBuilderError::Poseidon2MerkleMissingMmcsBit);
        }
        if !call.merkle_path && call.mmcs_bit.is_some() {
            return Err(crate::CircuitBuilderError::Poseidon2NonMerkleWithMmcsBit);
        }

        let width_ext = call.config.width_ext();
        let rate_ext = call.config.rate_ext();

        let mut input_exprs: Vec<Vec<ExprId>> = Vec::with_capacity(width_ext + 2);
        for limb in call.inputs.iter() {
            if let Some(val) = limb {
                input_exprs.push(vec![*val]);
            } else {
                input_exprs.push(Vec::new());
            }
        }

        if let Some(idx_sum) = call.mmcs_index_sum {
            input_exprs.push(vec![idx_sum]);
        } else {
            input_exprs.push(Vec::new());
        }

        if let Some(bit) = call.mmcs_bit {
            input_exprs.push(vec![bit]);
        } else {
            input_exprs.push(Vec::new());
        }

        let mut output_labels: Vec<Option<&'static str>> = Vec::with_capacity(width_ext);
        for i in 0..rate_ext {
            let expose = call.out_ctl.get(i).copied().unwrap_or(false);
            output_labels.push(expose.then_some("poseidon2_perm_out"));
        }
        for _ in rate_ext..width_ext {
            output_labels.push(
                call.return_all_outputs
                    .then_some("poseidon2_perm_out_capacity"),
            );
        }

        let (op_id, _call_expr_id, outputs) = self.push_non_primitive_op_with_outputs(
            op_type,
            input_exprs,
            output_labels,
            Some(NonPrimitiveOpParams::Poseidon2Perm {
                new_start: call.new_start,
                merkle_path: call.merkle_path,
            }),
            "poseidon2_perm",
        );
        Ok((op_id, outputs))
    }

    fn add_poseidon2_perm_base(
        &mut self,
        call: Poseidon2PermCallBase,
    ) -> Result<(NonPrimitiveOpId, [Option<ExprId>; 16]), crate::CircuitBuilderError> {
        let op_type = NpoTypeId::poseidon2_perm(call.config);
        self.ensure_op_enabled(&op_type)?;

        // Verify this is a D=1 configuration
        if call.config.d() != 1 {
            return Err(crate::CircuitBuilderError::Poseidon2ConfigMismatch {
                expected: "D=1 configuration".to_string(),
                got: format!("D={} configuration", call.config.d()),
            });
        }

        // Build input_exprs layout for D=1: [in0, in1, ..., in15]
        // No mmcs_index_sum or mmcs_bit for base field mode (no merkle path support for D=1)
        let mut input_exprs: Vec<Vec<ExprId>> = Vec::with_capacity(16);

        for element in call.inputs.iter() {
            if let Some(val) = element {
                input_exprs.push(vec![*val]);
            } else {
                input_exprs.push(Vec::new());
            }
        }

        // Build output labels: first 8 (rate) can be CTL-exposed, last 8 (capacity) are optional
        let mut output_labels: Vec<Option<&'static str>> = Vec::with_capacity(16);
        for i in 0..8 {
            if call.out_ctl[i] {
                output_labels.push(Some("poseidon2_perm_base_out"));
            } else {
                output_labels.push(None);
            }
        }
        for _ in 8..16 {
            if call.return_all_outputs {
                output_labels.push(Some("poseidon2_perm_base_out_capacity"));
            } else {
                output_labels.push(None);
            }
        }

        let (op_id, _call_expr_id, outputs) = self.push_non_primitive_op_with_outputs(
            op_type,
            input_exprs,
            output_labels,
            Some(NonPrimitiveOpParams::Poseidon2Perm {
                new_start: call.new_start,
                merkle_path: false, // No merkle path for D=1
            }),
            "poseidon2_perm_base",
        );

        Ok((
            op_id,
            [
                outputs[0],
                outputs[1],
                outputs[2],
                outputs[3],
                outputs[4],
                outputs[5],
                outputs[6],
                outputs[7],
                outputs[8],
                outputs[9],
                outputs[10],
                outputs[11],
                outputs[12],
                outputs[13],
                outputs[14],
                outputs[15],
            ],
        ))
    }
}

/// Executor for Poseidon2 perm operations.
///
#[derive(Debug, Clone)]
pub(crate) struct Poseidon2PermExecutor {
    op_type: NpoTypeId,
    config: Poseidon2Config,
    pub new_start: bool,
    pub merkle_path: bool,
}

impl Poseidon2PermExecutor {
    pub const fn new(
        op_type: NpoTypeId,
        config: Poseidon2Config,
        new_start: bool,
        merkle_path: bool,
    ) -> Self {
        Self {
            op_type,
            config,
            new_start,
            merkle_path,
        }
    }
}

impl<F: Field + Send + Sync + 'static> NonPrimitiveExecutor<F> for Poseidon2PermExecutor {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        let config = ctx.get_config(&self.op_type)?;

        if let Some(base_cfg) = config.downcast_ref::<Poseidon2PermBaseConfigData<F>>() {
            return self.execute_base(inputs, outputs, ctx, &Arc::clone(&base_cfg.exec));
        }

        let ext_cfg = config
            .downcast_ref::<Poseidon2PermConfigData<F>>()
            .ok_or_else(|| CircuitError::InvalidNonPrimitiveOpConfiguration {
                op: self.op_type.clone(),
            })?;
        let poseidon2_config = ext_cfg.config;
        let exec = Arc::clone(&ext_cfg.exec);

        let width_ext = poseidon2_config.width_ext();
        let rate_ext = poseidon2_config.rate_ext();
        let expected_inputs = width_ext + 2;

        if inputs.len() != expected_inputs {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op_type.clone(),
                expected: format!("{expected_inputs} input vectors"),
                got: inputs.len(),
            });
        }
        for limb_inputs in inputs[..width_ext].iter() {
            if limb_inputs.len() > 1 {
                return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                    op: self.op_type.clone(),
                    expected: "0 or 1 witness per input limb (extension-only)".to_string(),
                    got: limb_inputs.len(),
                });
            }
        }
        if inputs[width_ext].len() > 1 {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                op: self.op_type.clone(),
                expected: "0 or 1 element for mmcs_index_sum".to_string(),
                got: inputs[width_ext].len(),
            });
        }
        if inputs[width_ext + 1].len() > 1 {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                op: self.op_type.clone(),
                expected: "0 or 1 element for mmcs_bit".to_string(),
                got: inputs[width_ext + 1].len(),
            });
        }
        if outputs.len() != rate_ext && outputs.len() != width_ext {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op_type.clone(),
                expected: format!("{rate_ext} or {width_ext} output vectors"),
                got: outputs.len(),
            });
        }

        let private_inputs: Option<&[F]> = match ctx.get_private_data() {
            Ok(private_data) => {
                if let Some(data) = private_data.downcast_ref::<Poseidon2PermPrivateData<F, 2>>() {
                    if !self.merkle_path {
                        return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                            op: self.op_type.clone(),
                            operation_index: ctx.operation_id(),
                            expected: "no private data (only Merkle mode accepts private data)"
                                .to_string(),
                            got: "private data provided for non-Merkle operation".to_string(),
                        });
                    }
                    Some(&data.sibling[..])
                } else {
                    None
                }
            }
            Err(_) => None,
        };

        let mmcs_bit = if let Some(&wid) = inputs[width_ext + 1].first() {
            let val = ctx.get_witness(wid)?;
            match val {
                v if v == F::ZERO => false,
                v if v == F::ONE => true,
                v => {
                    return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                        op: self.op_type.clone(),
                        operation_index: ctx.operation_id(),
                        expected: "boolean mmcs_bit (0 or 1)".into(),
                        got: format!("{v:?}"),
                    });
                }
            }
        } else if self.merkle_path {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateData {
                op: self.op_type.clone(),
                operation_index: ctx.operation_id(),
                expected: "mmcs_bit must be provided when merkle_path=true".into(),
                got: "missing mmcs_bit".into(),
            });
        } else {
            false
        };

        let last_output: Option<&Vec<F>> = ctx
            .get_op_state::<Poseidon2ExecutionState<F>>(&self.op_type)
            .and_then(|s| {
                if self.merkle_path {
                    s.last_output_merkle.as_ref()
                } else {
                    s.last_output_normal.as_ref()
                }
            });

        let mut resolved_inputs = vec![F::ZERO; width_ext];
        for (limb, resolved) in resolved_inputs.iter_mut().enumerate() {
            *resolved = self.resolve_input_limb(
                limb,
                inputs,
                private_inputs,
                ctx,
                last_output.map(|v| v.as_slice()),
                mmcs_bit,
                width_ext,
                rate_ext,
            )?;
        }

        let output = exec(&resolved_inputs);

        let (in_ctl, input_indices) = inputs[..width_ext].iter().enumerate().fold(
            (vec![false; width_ext], vec![0u32; width_ext]),
            |(mut in_ctl, mut input_indices), (i, inp)| {
                if let Some(&wid) = inp.first() {
                    in_ctl[i] = true;
                    input_indices[i] = wid.0;
                }
                (in_ctl, input_indices)
            },
        );

        let (out_ctl, output_indices) = outputs.iter().take(rate_ext).enumerate().fold(
            (vec![false; rate_ext], vec![0u32; rate_ext]),
            |(mut out_ctl, mut output_indices), (i, out_slot)| {
                if let Some(&wid) = out_slot.first() {
                    out_ctl[i] = true;
                    output_indices[i] = wid.0;
                }
                (out_ctl, output_indices)
            },
        );

        let (mmcs_index_sum, mmcs_index_sum_idx, mmcs_ctl_enabled) = if inputs[width_ext].len() == 1
        {
            let wid = inputs[width_ext][0];
            let val = ctx.get_witness(wid)?;
            (val, wid.0, true)
        } else {
            (F::ZERO, 0, false)
        };

        let input_values = resolved_inputs;
        debug_assert_eq!(
            input_values.len(),
            width_ext,
            "Execution row must have width_ext input limbs"
        );

        let row = Poseidon2CircuitRow {
            new_start: self.new_start,
            merkle_path: self.merkle_path,
            mmcs_bit,
            mmcs_index_sum,
            input_values,
            in_ctl,
            input_indices,
            out_ctl,
            output_indices,
            mmcs_index_sum_idx,
            mmcs_ctl_enabled,
        };

        for (out_idx, out_slot) in outputs.iter().enumerate() {
            if out_slot.len() == 1 {
                let wid = out_slot[0];
                ctx.set_witness(wid, output[out_idx])?;
            } else if !out_slot.is_empty() {
                return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                    op: self.op_type.clone(),
                    expected: "0 or 1 witness per output limb".to_string(),
                    got: out_slot.len(),
                });
            }
        }

        let op_id = ctx.operation_id();
        let state = ctx.get_op_state_mut::<Poseidon2ExecutionState<F>>(&self.op_type);
        if self.merkle_path {
            tracing::trace!(
                "Poseidon2 op {:?}: updating last_output_merkle from {:?} to {:?}",
                op_id,
                state
                    .last_output_merkle
                    .as_ref()
                    .map(|o| format!("{:?}", o)),
                format!("{:?}", output)
            );
            state.last_output_merkle = Some(output);
        } else {
            tracing::trace!(
                "Poseidon2 op {:?}: updating last_output_normal from {:?} to {:?}",
                op_id,
                state
                    .last_output_normal
                    .as_ref()
                    .map(|o| format!("{:?}", o)),
                format!("{:?}", output)
            );
            state.last_output_normal = Some(output);
        }
        state.rows.push(row);

        Ok(())
    }

    fn op_type(&self) -> &NpoTypeId {
        &self.op_type
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn preprocess(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        preprocessed: &mut PreprocessedColumns<F>,
    ) -> Result<(), CircuitError> {
        let config = self.config;
        let width_ext = config.width_ext();
        let rate_ext = config.rate_ext();

        for (limb_idx, inp) in inputs[0..width_ext].iter().enumerate() {
            if inp.is_empty() {
                // Private input
                preprocessed.register_non_primitive_preprocessed_no_read(
                    &self.op_type,
                    &[F::ZERO, F::ZERO], // in_idx, in_ctl
                );
            } else {
                // Exposed input
                // Update witness multiplicities only if NOT merkle_path mode.
                // In merkle_path mode, input CTL lookups are disabled in the AIR
                // because the value permutation (based on runtime mmcs_bit) would
                // require degree-1 conditional logic that exceeds constraint limits.
                if self.merkle_path {
                    // Don't update multiplicities - just register the D-scaled index
                    preprocessed.register_non_primitive_preprocessed_no_read(
                        &self.op_type,
                        &[preprocessed.witness_index_as_field(inp[0])],
                    );
                } else {
                    // Register the witness read (updates multiplicities)
                    preprocessed.register_non_primitive_witness_reads(&self.op_type, inp)?;
                }
                // Add in_ctl value
                preprocessed.register_non_primitive_preprocessed_no_read(&self.op_type, &[F::ONE]);
            }
            let normal_chain_sel =
                if !self.new_start && !self.merkle_path && inputs[limb_idx].is_empty() {
                    F::ONE
                } else {
                    F::ZERO
                };

            preprocessed
                .register_non_primitive_preprocessed_no_read(&self.op_type, &[normal_chain_sel]);

            let merkle_chain_sel =
                if !self.new_start && self.merkle_path && inputs[limb_idx].is_empty() {
                    F::ONE
                } else {
                    F::ZERO
                };
            preprocessed
                .register_non_primitive_preprocessed_no_read(&self.op_type, &[merkle_chain_sel]);
        }

        for out in outputs.iter().take(rate_ext) {
            if out.is_empty() {
                // Private output
                preprocessed.register_non_primitive_preprocessed_no_read(
                    &self.op_type,
                    &[F::ZERO, F::ZERO], // out_idx, out_ctl
                );
            } else {
                // Exposed output: store the D-scaled index for the out_ctl lookup.
                // Do NOT increment ext_reads here; Poseidon2 is the CREATOR of this witness,
                // not a reader. The out_ctl multiplicity (+N_reads) is computed in
                // get_airs_and_degrees_with_prep based on how many other tables read this witness.
                preprocessed.register_non_primitive_output_index(&self.op_type, out);
                // Add out_ctl value (placeholder 1; overwritten in get_airs_and_degrees_with_prep).
                preprocessed.register_non_primitive_preprocessed_no_read(&self.op_type, &[F::ONE]);
            }
        }
        if inputs[width_ext].is_empty() {
            preprocessed.register_non_primitive_preprocessed_no_read(&self.op_type, &[F::ZERO]);
        } else {
            preprocessed.register_non_primitive_preprocessed_no_read(
                &self.op_type,
                &[preprocessed.witness_index_as_field(inputs[width_ext][0])],
            );
        }

        let mmcs_ctl_enabled = !inputs[width_ext].is_empty();
        let mmcs_merkle_flag = if mmcs_ctl_enabled && self.merkle_path {
            F::ONE
        } else {
            F::ZERO
        };
        preprocessed
            .register_non_primitive_preprocessed_no_read(&self.op_type, &[mmcs_merkle_flag]);

        // We need to insert `new_start` and `merkle_path` as well.
        let new_start_val = if self.new_start { F::ONE } else { F::ZERO };
        let merkle_path_val = if self.merkle_path { F::ONE } else { F::ZERO };
        preprocessed.register_non_primitive_preprocessed_no_read(
            &self.op_type,
            &[new_start_val, merkle_path_val],
        );

        Ok(())
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}

impl Poseidon2PermExecutor {
    /// Execute D=1 (base field) permutation with 16 input/output elements.
    fn execute_base<F: Field + Send + Sync + 'static>(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
        exec: &Poseidon2PermExecBase<F>,
    ) -> Result<(), CircuitError> {
        // D=1 mode: Input layout: [in0, in1, ..., in15]
        // Output layout: [out0, ..., out7] (rate) or [out0, ..., out15] (with capacity)
        if inputs.len() != 16 {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op_type.clone(),
                expected: "16 input vectors for D=1 mode".to_string(),
                got: inputs.len(),
            });
        }
        for (i, inp) in inputs.iter().enumerate() {
            if inp.len() > 1 {
                return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                    op: self.op_type.clone(),
                    expected: format!("0 or 1 witness per input element {}", i),
                    got: inp.len(),
                });
            }
        }
        // Support 8 outputs (rate only) or 16 outputs (with capacity)
        if outputs.len() != 8 && outputs.len() != 16 {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op_type.clone(),
                expected: "8 or 16 output vectors for D=1 mode".to_string(),
                got: outputs.len(),
            });
        }

        // Resolve input values: use witness value if available, otherwise zero
        let mut resolved_inputs = [F::ZERO; 16];
        for (i, inp) in inputs.iter().enumerate() {
            if inp.len() == 1 {
                resolved_inputs[i] = ctx.get_witness(inp[0])?;
            }
            // If inp is empty, leave as zero (capacity or unused input)
        }

        // Execute the permutation
        let output = exec(&resolved_inputs);

        let mut in_ctl = vec![false; 4];
        let mut input_indices = vec![0u32; 4];
        for limb in 0..4 {
            for d in 0..4 {
                let idx = limb * 4 + d;
                if !inputs[idx].is_empty() {
                    in_ctl[limb] = true;
                    if input_indices[limb] == 0 {
                        input_indices[limb] = inputs[idx][0].0;
                    }
                }
            }
        }

        let mut out_ctl = vec![false; 2];
        let mut output_indices = vec![0u32; 2];
        for limb in 0..2 {
            for d in 0..4 {
                let idx = limb * 4 + d;
                if idx < outputs.len() && !outputs[idx].is_empty() {
                    out_ctl[limb] = true;
                    if output_indices[limb] == 0 {
                        output_indices[limb] = outputs[idx][0].0;
                    }
                }
            }
        }

        // Convert resolved inputs to Vec for the row record
        let input_values = resolved_inputs.to_vec();

        let row = Poseidon2CircuitRow {
            new_start: self.new_start,
            merkle_path: false, // No merkle path for D=1
            mmcs_bit: false,
            mmcs_index_sum: F::ZERO,
            input_values,
            in_ctl,
            input_indices,
            out_ctl,
            output_indices,
            mmcs_index_sum_idx: 0,
            mmcs_ctl_enabled: false,
        };

        // Update state: store rows for trace generation
        // Note: D=1 doesn't use chaining state the same way D=4 does
        let state = ctx.get_op_state_mut::<Poseidon2ExecutionState<F>>(&self.op_type);
        state.rows.push(row);

        // Write outputs to witness
        for (out_idx, out_slot) in outputs.iter().enumerate() {
            if out_slot.len() == 1 {
                let wid = out_slot[0];
                ctx.set_witness(wid, output[out_idx])?;
            } else if !out_slot.is_empty() {
                return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                    op: self.op_type.clone(),
                    expected: "0 or 1 witness per output element".to_string(),
                    got: out_slot.len(),
                });
            }
        }

        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    fn resolve_input_limb<F: Field>(
        &self,
        limb: usize,
        inputs: &[Vec<WitnessId>],
        private_inputs: Option<&[F]>,
        ctx: &ExecutionContext<'_, F>,
        last_output: Option<&[F]>,
        mmcs_bit: bool,
        width_ext: usize,
        rate_ext: usize,
    ) -> Result<F, CircuitError> {
        let mut resolved: Vec<Option<F>> = vec![None; width_ext];

        if !self.new_start {
            let prev =
                last_output.ok_or_else(|| CircuitError::Poseidon2ChainMissingPreviousState {
                    operation_index: ctx.operation_id(),
                })?;

            if !self.merkle_path {
                for i in 0..width_ext.min(prev.len()) {
                    resolved[i] = Some(prev[i]);
                }
            } else {
                for i in 0..rate_ext.min(prev.len()) {
                    resolved[i] = Some(prev[i]);
                }
            }
        } else if !self.merkle_path {
            for r in resolved.iter_mut() {
                *r = Some(F::ZERO);
            }
        }

        if let Some(private) = private_inputs
            && self.merkle_path
        {
            for (i, &p) in private.iter().enumerate().take(rate_ext) {
                if rate_ext + i < width_ext {
                    resolved[rate_ext + i] = Some(p);
                }
            }
        }

        for i in 0..width_ext {
            if inputs.len() > i && inputs[i].len() == 1 {
                let wid = inputs[i][0];
                let val = ctx.get_witness(wid)?;
                resolved[i] = Some(val);
            }
        }

        let permuted_idx = if self.merkle_path && mmcs_bit && limb < 2 * rate_ext {
            if limb < rate_ext {
                limb + rate_ext
            } else {
                limb - rate_ext
            }
        } else {
            limb
        };

        resolved.get(permuted_idx).and_then(|x| *x).ok_or_else(|| {
            if self.merkle_path && permuted_idx >= rate_ext && permuted_idx < 2 * rate_ext {
                CircuitError::Poseidon2MerkleMissingSiblingInput {
                    operation_index: ctx.operation_id(),
                    limb,
                }
            } else {
                CircuitError::Poseidon2MissingInput {
                    operation_index: ctx.operation_id(),
                    limb,
                }
            }
        })
    }
}

// ============================================================================
// Trace Types
// ============================================================================

/// Trait to provide Poseidon2 configuration parameters for a field type.
///
/// This allows the trace generator and AIR to work with different Poseidon2 configurations
/// without hardcoding parameters. Implementations should provide the standard
/// parameters for their field type.
pub trait Poseidon2Params {
    type BaseField: PrimeField + PrimeCharacteristicRing;
    /// Poseidon2 configuration key for this parameter set.
    const CONFIG: Poseidon2Config;
    /// Extension degree D
    const D: usize = Self::CONFIG.d();
    /// Total width in base field elements
    const WIDTH: usize = Self::CONFIG.width();

    /// Rate in extension elements
    const RATE_EXT: usize = Self::CONFIG.rate_ext();
    /// Capacity in extension elements
    const CAPACITY_EXT: usize = Self::CONFIG.capacity_ext();
    /// Capacity size in base field elements = CAPACITY_EXT * D
    const CAPACITY_SIZE: usize = Self::CAPACITY_EXT * Self::D;

    /// S-box degree (polynomial degree for the S-box)
    const SBOX_DEGREE: u64 = Self::CONFIG.sbox_degree();
    /// Number of S-box registers
    const SBOX_REGISTERS: usize = Self::CONFIG.sbox_registers();

    /// Number of half full rounds
    const HALF_FULL_ROUNDS: usize = Self::CONFIG.half_full_rounds();
    /// Number of partial rounds
    const PARTIAL_ROUNDS: usize = Self::CONFIG.partial_rounds();

    /// Width in extension elements = RATE_EXT + CAPACITY_EXT
    const WIDTH_EXT: usize = Self::RATE_EXT + Self::CAPACITY_EXT;
}

/// BabyBear D=1 Width=16 configuration for base field challenges.
///
/// This is used when the challenge type is the base field itself (no extension).
/// The Poseidon2 permutation operates directly on 16 base field elements.
pub struct BabyBearD1Width16;

impl Poseidon2Params for BabyBearD1Width16 {
    type BaseField = p3_baby_bear::BabyBear;
    const CONFIG: Poseidon2Config = Poseidon2Config::BabyBearD1Width16;
}

/// KoalaBear D=1 Width=16 configuration for base field challenges.
///
/// This is used when the challenge type is the base field itself (no extension).
/// The Poseidon2 permutation operates directly on 16 base field elements.
pub struct KoalaBearD1Width16;

impl Poseidon2Params for KoalaBearD1Width16 {
    type BaseField = p3_koala_bear::KoalaBear;
    const CONFIG: Poseidon2Config = Poseidon2Config::KoalaBearD1Width16;
}

/// Goldilocks D=2 Width=8 configuration (matches Poseidon2Goldilocks<8>).
pub struct GoldilocksD2Width8;

impl Poseidon2Params for GoldilocksD2Width8 {
    type BaseField = p3_goldilocks::Goldilocks;
    const CONFIG: Poseidon2Config = Poseidon2Config::GoldilocksD2Width8;
}

/// Poseidon2 operation table row.
///
/// This implements the Poseidon Permutation Table specification.
/// See: https://github.com/Plonky3/Plonky3-recursion/discussions/186
///
/// The table has one row per Poseidon call, implementing:
/// - Standard chaining (Challenger-style sponge use)
/// - Merkle-path chaining (MMCS directional hashing)
/// - Selective limb exposure to the witness via CTL
/// - Optional MMCS index accumulator
#[derive(Debug, Clone)]
pub struct Poseidon2CircuitRow<F> {
    /// Control: If 1, row begins a new independent Poseidon chain.
    pub new_start: bool,
    /// Control: 0 → normal sponge/Challenger mode, 1 → Merkle-path mode.
    pub merkle_path: bool,
    /// Control: Direction bit for Merkle left/right hashing (only meaningful when merkle_path = 1).
    pub mmcs_bit: bool,
    /// Value: Optional MMCS accumulator (base field, encodes a u32-like integer).
    pub mmcs_index_sum: F,
    /// Inputs to the Poseidon2 permutation (flattened state).
    /// For execution rows: 4 extension limbs. For trace rows: WIDTH base field elements.
    pub input_values: Vec<F>,
    /// Input exposure flags for CTL lookups: permuted to match the physical trace layout.
    pub in_ctl: Vec<bool>,
    /// Input exposure indices for CTL lookups.
    pub input_indices: Vec<u32>,
    /// Output exposure flags for rate limbs (CTL-verified when true).
    pub out_ctl: Vec<bool>,
    /// Output exposure indices: index into the witness table for rate limbs.
    pub output_indices: Vec<u32>,
    /// MMCS index exposure: index for CTL exposure of mmcs_index_sum.
    pub mmcs_index_sum_idx: u32,
    /// Whether mmcs_index_sum CTL is enabled. When false, the mmcs_index_sum lookup is disabled.
    pub mmcs_ctl_enabled: bool,
}

/// Poseidon2 trace for all hash operations in the circuit.
#[derive(Debug, Clone)]
pub struct Poseidon2Trace<F> {
    /// Operation type for this Poseidon2 trace.
    pub op_type: NpoTypeId,
    /// All Poseidon2 operations (permutation rows) in this trace.
    pub operations: Vec<Poseidon2CircuitRow<F>>,
}

impl<F> Poseidon2Trace<F> {
    pub const fn total_rows(&self) -> usize {
        self.operations.len()
    }
}

impl<TraceF: Clone + Send + Sync + 'static, CF> NonPrimitiveTrace<CF> for Poseidon2Trace<TraceF> {
    fn op_type(&self) -> NpoTypeId {
        self.op_type.clone()
    }

    fn rows(&self) -> usize {
        self.total_rows()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn boxed_clone(&self) -> Box<dyn NonPrimitiveTrace<CF>> {
        Box::new(self.clone())
    }
}

// ============================================================================
// Trace Generation
// ============================================================================

/// Generate the Poseidon2 trace from execution state.
///
/// Converts circuit rows from extension field format (4 limbs) to base field format (16 elements).
///
/// # Type Parameters
/// - `F`: The circuit field type (extension field)
/// - `Config`: A type implementing `Poseidon2Params` that specifies the Poseidon2 configuration
pub fn generate_poseidon2_trace<
    F: CircuitField + ExtensionField<Config::BaseField>,
    Config: Poseidon2Params,
>(
    op_states: &crate::op::OpStateMap,
) -> Result<Option<Box<dyn NonPrimitiveTrace<F>>>, CircuitError> {
    let op_type = NpoTypeId::poseidon2_perm(Config::CONFIG);
    let Some(state) = op_states
        .get(&op_type)
        .and_then(|s| s.as_any().downcast_ref::<Poseidon2ExecutionState<F>>())
    else {
        return Ok(None);
    };

    if state.rows.is_empty() {
        return Ok(None);
    }

    let d = Config::D;

    // Convert extension field rows to base field rows
    let operations: Vec<Poseidon2CircuitRow<Config::BaseField>> = state
        .rows
        .iter()
        .enumerate()
        .map(|(row_index, row)| -> Result<_, CircuitError> {
            let limb_count = Config::WIDTH / d;
            // Flatten extension limbs to WIDTH base field elements.
            assert_eq!(
                row.input_values.len(),
                limb_count,
                "Source row must have WIDTH/D input limbs"
            );
            let mut input_values = vec![Config::BaseField::ZERO; Config::WIDTH];
            assert_eq!(
                input_values.len(),
                Config::WIDTH,
                "Target row must have WIDTH input elements"
            );
            for (limb, ext_val) in row.input_values.iter().enumerate() {
                let coeffs = ext_val.as_basis_coefficients_slice();
                input_values[limb * d..(limb + 1) * d].copy_from_slice(coeffs);
            }

            let mmcs_index_sum = row.mmcs_index_sum.as_base().ok_or_else(|| {
                CircuitError::IncorrectNonPrimitiveOpPrivateData {
                    op: op_type.clone(),
                    operation_index: NonPrimitiveOpId(row_index as u32),
                    expected: "base field mmcs_index_sum".to_string(),
                    got: "extension value".to_string(),
                }
            })?;

            Ok(Poseidon2CircuitRow {
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
                mmcs_ctl_enabled: row.mmcs_ctl_enabled,
            })
        })
        .collect::<Result<Vec<_>, CircuitError>>()?;

    Ok(Some(Box::new(Poseidon2Trace {
        op_type,
        operations,
    })))
}
