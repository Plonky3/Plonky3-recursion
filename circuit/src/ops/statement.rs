//! Built-in statement sink: records existing witnesses as one ordered public row.

use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::any::Any;
use core::fmt::Debug;

use p3_field::{ExtensionField, Field, PrimeField64};

use crate::builder::{CircuitBuilderError, NpoCircuitPlugin, NpoLoweringContext};
use crate::ops::{ExecutionContext, NonPrimitiveExecutor, NpoConfig, NpoTypeId, Op};
use crate::tables::{NonPrimitiveTrace, TraceGeneratorFn};
use crate::types::{ExprId, WitnessId};
use crate::{CircuitError, StatementSchema};

#[derive(Clone, Debug)]
pub(crate) struct StatementConfig {
    pub schema: StatementSchema,
}

#[derive(Clone, Debug)]
pub struct StatementCircuitRow<F> {
    pub input_wids: Vec<WitnessId>,
    pub values: Vec<F>,
}

#[derive(Debug, Default)]
pub struct StatementExecutionState<F> {
    pub rows: Vec<StatementCircuitRow<F>>,
}

#[derive(Clone, Debug)]
pub struct StatementExecutor {
    op_type: NpoTypeId,
    public_len: usize,
}

impl StatementExecutor {
    pub fn new(public_len: usize) -> Self {
        Self {
            op_type: NpoTypeId::statement(),
            public_len,
        }
    }
}

impl<F: Field + Send + Sync + 'static> NonPrimitiveExecutor<F> for StatementExecutor {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        if inputs.len() != 1 || inputs[0].len() != self.public_len || !outputs.is_empty() {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op_type.clone(),
                expected: format!(
                    "1 input group with {} witnesses and no outputs",
                    self.public_len
                ),
                got: inputs.len(),
            });
        }

        let values = inputs[0]
            .iter()
            .map(|&wid| ctx.get_witness(wid))
            .collect::<Result<Vec<_>, _>>()?;
        let state = ctx.get_op_state_mut::<StatementExecutionState<F>>(&self.op_type);
        if !state.rows.is_empty() {
            return Err(CircuitError::MultipleStatementOperations);
        }
        state.rows.push(StatementCircuitRow {
            input_wids: inputs[0].clone(),
            values,
        });
        Ok(())
    }

    fn op_type(&self) -> &NpoTypeId {
        &self.op_type
    }

    fn preprocess(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        preprocessed: &mut dyn crate::PreprocessedWriter<F>,
    ) -> Result<(), CircuitError> {
        if inputs.len() != 1 || inputs[0].len() != self.public_len || !outputs.is_empty() {
            return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                op: self.op_type.clone(),
                expected: format!(
                    "1 input group with {} witnesses and no outputs",
                    self.public_len
                ),
                got: inputs.len(),
            });
        }
        preprocessed.register_non_primitive_preprocessed_no_read(&self.op_type, &[F::ONE]);
        preprocessed.register_non_primitive_witness_reads(&self.op_type, &inputs[0])
    }

    fn num_exposed_outputs(&self) -> Option<usize> {
        Some(0)
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}

pub(crate) struct StatementCircuitPlugin<F: Field> {
    schema: StatementSchema,
    trace_gen: TraceGeneratorFn<F>,
}

impl<F: Field> StatementCircuitPlugin<F> {
    pub const fn new(schema: StatementSchema, trace_gen: TraceGeneratorFn<F>) -> Self {
        Self { schema, trace_gen }
    }
}

impl<F: Field> Debug for StatementCircuitPlugin<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("StatementCircuitPlugin")
            .field("schema", &self.schema)
            .finish()
    }
}

impl<F: Field> NpoCircuitPlugin<F> for StatementCircuitPlugin<F> {
    fn type_id(&self) -> NpoTypeId {
        NpoTypeId::statement()
    }

    fn lower(
        &self,
        data: &crate::builder::NonPrimitiveOperationData<F>,
        output_exprs: &[(u32, ExprId)],
        ctx: &mut NpoLoweringContext<'_, F>,
    ) -> Result<Op<F>, CircuitBuilderError> {
        if data.params.is_some() || !output_exprs.is_empty() || !data.output_exprs.is_empty() {
            return Err(CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                op: data.op_type.clone(),
            });
        }
        if data.input_exprs.len() != 1 || data.input_exprs[0].len() != self.schema.base_len() {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "Statement",
                expected: format!(
                    "1 input group with {} flattened base-field values",
                    self.schema.base_len()
                ),
                got: data.input_exprs.len(),
            });
        }
        let input_wids = data.input_exprs[0]
            .iter()
            .enumerate()
            .map(|(i, &expr)| ctx.resolve_witness_id(expr, || format!("Statement input value {i}")))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Op::NonPrimitiveOpWithExecutor {
            inputs: vec![input_wids],
            outputs: vec![],
            executor: Box::new(StatementExecutor::new(self.schema.base_len())),
            op_id: data.op_id,
        })
    }

    fn trace_generator(&self) -> TraceGeneratorFn<F> {
        self.trace_gen
    }

    fn config(&self) -> NpoConfig {
        NpoConfig::new(StatementConfig {
            schema: self.schema.clone(),
        })
    }
}

pub fn generate_statement_trace<BF, EF>(
    op_states: &crate::ops::OpStateMap,
) -> Result<Option<Box<dyn NonPrimitiveTrace<EF>>>, CircuitError>
where
    BF: PrimeField64,
    EF: Field + ExtensionField<BF>,
{
    let op_type = NpoTypeId::statement();
    let Some(state) = op_states
        .get(&op_type)
        .and_then(|state| state.downcast_ref::<StatementExecutionState<EF>>())
    else {
        return Ok(None);
    };
    if state.rows.is_empty() {
        return Ok(None);
    }
    if state.rows.len() != 1 {
        return Err(CircuitError::MultipleStatementOperations);
    }
    let row = &state.rows[0];
    let values = row
        .values
        .iter()
        .enumerate()
        .map(|(slot, value)| {
            value
                .as_base()
                .ok_or(CircuitError::StatementValueNotBase { slot })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Some(Box::new(StatementTrace {
        input_wids: row.input_wids.clone(),
        values,
    })))
}

#[derive(Clone, Debug)]
pub struct StatementTrace<F> {
    pub input_wids: Vec<WitnessId>,
    pub values: Vec<F>,
}

impl<TraceF: Clone + Send + Sync + 'static, CF> NonPrimitiveTrace<CF> for StatementTrace<TraceF> {
    fn op_type(&self) -> NpoTypeId {
        NpoTypeId::statement()
    }

    fn rows(&self) -> usize {
        1
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn boxed_clone(&self) -> Box<dyn NonPrimitiveTrace<CF>> {
        Box::new(self.clone())
    }
}
