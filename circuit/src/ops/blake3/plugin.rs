//! Blake3 circuit plugin — [`NpoCircuitPlugin`] implementation.

use alloc::boxed::Box;

use p3_field::Field;

use crate::CircuitBuilderError;
use crate::builder::{NpoCircuitPlugin, NpoLoweringContext};
use crate::ops::blake3::config::Blake3ConfigData;
use crate::ops::blake3::executor::Blake3Executor;
use crate::ops::{NpoConfig, NpoTypeId, Op};
use crate::tables::TraceGeneratorFn;
use crate::types::ExprId;

/// Circuit-layer plugin for Blake3 non-primitive operations.
pub struct Blake3CircuitPlugin<F: Field> {
    type_id: NpoTypeId,
    npo_config: NpoConfig,
    trace_gen: TraceGeneratorFn<F>,
}

impl<F: Field> Blake3CircuitPlugin<F> {
    pub fn new(trace_gen: TraceGeneratorFn<F>) -> Self {
        let type_id = NpoTypeId::blake3();
        Self {
            type_id,
            npo_config: NpoConfig::new(Blake3ConfigData::default()),
            trace_gen,
        }
    }
}

impl<F: Field> NpoCircuitPlugin<F> for Blake3CircuitPlugin<F> {
    fn type_id(&self) -> NpoTypeId {
        self.type_id.clone()
    }

    fn lower(
        &self,
        data: &crate::builder::NonPrimitiveOperationData<F>,
        output_exprs: &[(u32, ExprId)],
        ctx: &mut NpoLoweringContext<'_, F>,
    ) -> Result<Op<F>, CircuitBuilderError> {
        for (_output_idx, expr_id) in output_exprs {
            ctx.ensure_witness_id(*expr_id);
        }

        let (new_start, is_new_blake, is_hash_output) = data
            .params
            .as_ref()
            .and_then(|p| p.as_blake3())
            .ok_or_else(|| CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                op: data.op_type.clone(),
            })?;

        let inputs_widx = ctx.lower_expr_slots(&data.input_exprs, "Blake3", "input")?;
        let outputs_widx = ctx.lower_expr_slots(&data.output_exprs, "Blake3", "output")?;

        Ok(Op::NonPrimitiveOpWithExecutor {
            inputs: inputs_widx,
            outputs: outputs_widx,
            executor: Box::new(Blake3Executor::new(
                data.op_type.clone(),
                new_start,
                is_new_blake,
                is_hash_output,
            )),
            op_id: data.op_id,
        })
    }

    fn trace_generator(&self) -> TraceGeneratorFn<F> {
        self.trace_gen
    }

    fn config(&self) -> NpoConfig {
        self.npo_config.clone()
    }
}

unsafe impl<F: Field> Send for Blake3CircuitPlugin<F> {}
unsafe impl<F: Field> Sync for Blake3CircuitPlugin<F> {}
