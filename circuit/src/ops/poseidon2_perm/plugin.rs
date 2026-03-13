//! Poseidon2 circuit plugin — [`NpoCircuitPlugin`] implementation.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{format, vec};

use hashbrown::HashMap;
use p3_field::Field;

use crate::CircuitBuilderError;
use crate::builder::{NonPrimitiveOpParams, NpoCircuitPlugin, NpoLoweringContext};
use crate::ops::poseidon2_perm::config::{
    Poseidon2Config, Poseidon2PermBaseConfigData, Poseidon2PermConfigData, Poseidon2PermExec,
    Poseidon2PermExecBase,
};
use crate::ops::poseidon2_perm::executor::Poseidon2PermExecutor;
use crate::ops::{NpoTypeId, Op};
use crate::tables::TraceGeneratorFn;
use crate::types::{ExprId, WitnessId};

/// Internal enum to hold either extension or base-field config payload.
enum Poseidon2PluginConfig<F> {
    Ext(Poseidon2PermConfigData<F>),
    Base(Poseidon2PermBaseConfigData<F>),
}

/// Resolve an `ExprId` to its `WitnessId`, returning an error with context on failure.
fn resolve_witness_id(
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

/// Lower a group of expression slots (each 0 or 1 element) into witness ID vectors.
///
/// Each slot must contain exactly 0 or 1 expressions. Returns one `Vec<WitnessId>` per slot.
fn lower_expr_slots(
    slots: &[Vec<ExprId>],
    expr_to_widx: &HashMap<ExprId, WitnessId>,
    context_prefix: &str,
) -> Result<Vec<Vec<WitnessId>>, CircuitBuilderError> {
    let mut result = Vec::with_capacity(slots.len());
    for (i, slot) in slots.iter().enumerate() {
        if slot.len() > 1 {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "Poseidon2Perm",
                expected: format!("0 or 1 element per {context_prefix}"),
                got: slot.len(),
            });
        }
        let widx = slot
            .iter()
            .map(|&expr| {
                resolve_witness_id(
                    expr_to_widx,
                    expr,
                    &format!("Poseidon2Perm {context_prefix} {i}"),
                )
            })
            .collect::<Result<Vec<_>, _>>()?;
        result.push(widx);
    }
    Ok(result)
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
        // Default to binary Merkle arity for extension-mode Poseidon2 tables.
        let payload = Poseidon2PluginConfig::Ext(Poseidon2PermConfigData::new(config, exec, 2));
        Self {
            type_id,
            poseidon2_config: config,
            config_payload: payload,
            trace_gen,
        }
    }

    /// Extension-mode plugin constructor with an explicit Merkle arity.
    ///
    /// This allows callers (e.g. recursion backends) to prepare Poseidon2 tables
    /// that conceptually correspond to 4-ary Merkle trees, while keeping the
    /// existing binary behavior when `merkle_arity = 2`.
    pub fn new_ext_with_merkle_arity(
        config: Poseidon2Config,
        exec: Poseidon2PermExec<F>,
        trace_gen: TraceGeneratorFn<F>,
        merkle_arity: u8,
    ) -> Self {
        let type_id = NpoTypeId::poseidon2_perm(config);
        let payload =
            Poseidon2PluginConfig::Ext(Poseidon2PermConfigData::new(config, exec, merkle_arity));
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

    /// Minimal plugin for tests that never execute the circuit.
    ///
    /// The executor will panic if actually invoked.
    pub fn new_config_only(config: Poseidon2Config) -> Self {
        let type_id = NpoTypeId::poseidon2_perm(config);
        let dummy_exec: Poseidon2PermExec<F> =
            Arc::new(|_| panic!("Poseidon2PermExec used without proper registration"));
        let payload =
            Poseidon2PluginConfig::Ext(Poseidon2PermConfigData::new(config, dummy_exec, 2));
        Self {
            type_id,
            poseidon2_config: config,
            config_payload: payload,
            trace_gen: |_| Ok(None),
        }
    }
}

impl<F: Field> NpoCircuitPlugin<F> for Poseidon2CircuitPlugin<F> {
    fn type_id(&self) -> NpoTypeId {
        self.type_id.clone()
    }

    fn lower(
        &self,
        data: &crate::builder::NonPrimitiveOperationData<F>,
        output_exprs: &[(u32, ExprId)],
        ctx: &mut NpoLoweringContext<'_, F>,
    ) -> Result<Op<F>, CircuitBuilderError> {
        let expr_to_widx = &mut *ctx.expr_to_widx;

        // Ensure output ExprIds have witness IDs.
        for (_output_idx, expr_id) in output_exprs {
            expr_to_widx
                .entry(*expr_id)
                .or_insert_with(|| (ctx.alloc_witness_id)(expr_id.0 as usize));
        }

        let config = self.poseidon2_config;
        let (new_start, merkle_path) = match data.params.as_ref().ok_or_else(|| {
            CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                op: data.op_type.clone(),
            }
        })? {
            NonPrimitiveOpParams::Poseidon2Perm {
                new_start,
                merkle_path,
            } => (*new_start, *merkle_path),
            _ => {
                return Err(CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                    op: data.op_type.clone(),
                });
            }
        };

        let d = config.d();
        let width_ext = config.width_ext();
        let rate_ext = config.rate_ext();
        let is_d1_mode = d == 1;

        // Validate input count: width_ext + mmcs_index_sum + 0..=2 mmcs_bits
        let min_inputs = width_ext + 1;
        let max_inputs = width_ext + 1 + 2;
        let n_inputs = data.input_exprs.len();
        if is_d1_mode {
            if n_inputs != 16 {
                return Err(CircuitBuilderError::NonPrimitiveOpArity {
                    op: "Poseidon2Perm",
                    expected: "16 inputs for D=1".to_string(),
                    got: n_inputs,
                });
            }
        } else if n_inputs < min_inputs || n_inputs > max_inputs {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "Poseidon2Perm",
                expected: format!("{min_inputs}..={max_inputs} inputs"),
                got: n_inputs,
            });
        }

        // Validate output count
        let valid_output_count = if is_d1_mode {
            data.output_exprs.len() == 8 || data.output_exprs.len() == 16
        } else {
            data.output_exprs.len() == rate_ext || data.output_exprs.len() == width_ext
        };
        if !valid_output_count {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "Poseidon2Perm",
                expected: if is_d1_mode {
                    "8 or 16 outputs for D=1 mode".to_string()
                } else {
                    format!("{rate_ext} or {width_ext} outputs for D>1 mode")
                },
                got: data.output_exprs.len(),
            });
        }

        // Lower inputs to witness IDs
        let inputs_widx = if is_d1_mode {
            lower_expr_slots(&data.input_exprs, expr_to_widx, "D=1 input")?
        } else {
            let mut widx =
                lower_expr_slots(&data.input_exprs[..width_ext], expr_to_widx, "input limb")?;
            widx.push(
                lower_expr_slots(
                    &data.input_exprs[width_ext..width_ext + 1],
                    expr_to_widx,
                    "mmcs_index_sum",
                )?
                .pop()
                .unwrap(),
            );
            for (i, slot) in data.input_exprs[width_ext + 1..].iter().enumerate() {
                widx.push(
                    lower_expr_slots(
                        core::slice::from_ref(slot),
                        expr_to_widx,
                        &format!("mmcs_bit_{i}"),
                    )?
                    .pop()
                    .unwrap(),
                );
            }
            widx
        };

        // Lower outputs to witness IDs
        let mut poseidon2_outputs: Vec<Vec<WitnessId>> =
            Vec::with_capacity(data.output_exprs.len());
        for (i, limb_exprs) in data.output_exprs.iter().enumerate() {
            if limb_exprs.len() > 1 {
                return Err(CircuitBuilderError::NonPrimitiveOpArity {
                    op: "Poseidon2Perm",
                    expected: "0 or 1 element per output".to_string(),
                    got: limb_exprs.len(),
                });
            }
            if let Some(&expr) = limb_exprs.first() {
                let w =
                    resolve_witness_id(expr_to_widx, expr, &format!("Poseidon2Perm output {i}"))?;
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

    fn config(&self) -> crate::ops::NpoConfig {
        match &self.config_payload {
            Poseidon2PluginConfig::Ext(d) => crate::ops::NpoConfig::new(d.clone()),
            Poseidon2PluginConfig::Base(d) => crate::ops::NpoConfig::new(d.clone()),
        }
    }
}
