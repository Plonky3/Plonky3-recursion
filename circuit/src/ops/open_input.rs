use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::any::Any;

use p3_field::{ExtensionField, Field};

use crate::builder::NonPrimitiveOpParams;
// TODO Linda: alpha_pow and intermediary ros should be private inputs.
use crate::op::{ExecutionContext, NonPrimitiveExecutor, OpExecutionState, OpStateMap};
use crate::tables::NonPrimitiveTrace;
use crate::{
    CircuitBuilder, CircuitBuilderError, CircuitError, CircuitField, ExprId, NonPrimitiveOpId,
    NonPrimitiveOpType, WitnessId,
};

#[derive(Default, Debug, Clone)]
pub struct OpenInputRow<F> {
    // All `Vec`s correspond to one extension limb in execution rows, and D base field elements in trace rows.
    pub alpha: Vec<F>, // Also corresponds to the accumulator when the operation is `EvalPoint`.
    pub alpha_index: u32,
    pub pow_at_x: Vec<F>, // Also corresponds to `g_pow` when the operation is `EvalPoint`.
    pub pow_at_x_index: u32,
    pub pow_at_z: Vec<F>, // The first column also corresponds to `g_pow` when the operation is `EvalPoint`.
    pub pow_at_z_index: u32,
    pub ro_index: u32,
    pub is_last: bool,
    pub is_real: bool,
}

#[derive(Debug, Clone)]
pub struct OpenInputTrace<F> {
    pub op_type: NonPrimitiveOpType,
    pub rows: Vec<OpenInputRow<F>>,
}

impl<TraceF: Clone + Send + Sync + 'static, CF> NonPrimitiveTrace<CF> for OpenInputTrace<TraceF> {
    fn op_type(&self) -> NonPrimitiveOpType {
        self.op_type
    }

    fn rows(&self) -> usize {
        self.rows.len()
    }

    fn as_any(&self) -> &dyn Any {
        self
    }

    fn boxed_clone(&self) -> Box<dyn NonPrimitiveTrace<CF>> {
        Box::new(self.clone())
    }
}

#[derive(Default, Debug, Clone)]
pub struct OpenInputState<F> {
    pub last_ro: Option<F>,
    pub rows: Vec<OpenInputRow<F>>,
}

impl<F: Field> OpExecutionState for OpenInputState<F> {
    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

/// Executor for OpenInput operations.
#[derive(Debug, Clone)]
pub(crate) struct OpenInputExecutor {
    op_type: NonPrimitiveOpType,
    is_last: bool,
}

impl OpenInputExecutor {
    pub fn new(is_last: bool) -> Self {
        Self {
            op_type: NonPrimitiveOpType::OpenInput,
            is_last,
        }
    }
}

impl<F: Field> NonPrimitiveExecutor<F> for OpenInputExecutor {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        assert_eq!(inputs.len(), 3);
        // The OpenInput updates the reduced_openings and alpha_pow columns.
        let inps_and_indices = inputs
            .iter()
            .map(|inp| {
                if inp.len() != 1 {
                    return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                        op: self.op_type,
                        expected: format!("0 or 1 witness per input element {}", inp.len()),
                        got: inp.len(),
                    });
                }
                let value = match ctx.get_witness(inp[0]) {
                    Ok(value) => value,
                    Err(_) => {
                        return Err(CircuitError::WitnessNotSet { witness_id: inp[0] });
                    }
                };

                Ok((value, inp[0].0))
            })
            .collect::<Result<Vec<_>, CircuitError>>()?;

        let alpha = &inps_and_indices[0];
        let p_at_x = &inps_and_indices[1];
        let p_at_z = &inps_and_indices[2];

        // Compute the next `alpha_pow` and `ro` values.
        let state = ctx.get_op_state_mut::<OpenInputState<F>>(&self.op_type);
        let ro = state.last_ro.unwrap_or(F::ZERO);
        let new_ro = ro * alpha.0 + (p_at_z.0 - p_at_x.0);

        let output_index = if self.is_last {
            assert_eq!(outputs.len(), 1);
            assert_eq!(outputs[0].len(), 1);
            outputs[0][0].0
        } else {
            0
        };

        state.last_ro = Some(new_ro);

        state.rows.push(OpenInputRow {
            alpha: vec![alpha.0],
            alpha_index: alpha.1,
            pow_at_x: vec![p_at_x.0],
            pow_at_x_index: p_at_x.1,
            pow_at_z: vec![p_at_z.0],
            pow_at_z_index: p_at_z.1,
            ro_index: output_index,
            is_last: self.is_last,
            is_real: true,
        });

        if self.is_last {
            state.last_ro = None;
        }

        // Update the witness values in the context.
        // There only are outputs if last is true. And in that case, we only need to set the value of the last ro.
        if self.is_last {
            assert_eq!(outputs.len(), 1);
            assert_eq!(outputs[0].len(), 1);
            ctx.set_witness(outputs[0][0], new_ro)?;
        } else {
            assert_eq!(outputs[0].len(), 0);
        }

        Ok(())
    }

    fn op_type(&self) -> &NonPrimitiveOpType {
        &self.op_type
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn preprocess(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        preprocessed: &mut crate::PreprocessedColumns<F>,
    ) -> Result<(), CircuitError> {
        // We need to preprocess indices from the inputs, as well as whether the current operation is the last one in the sequence of OpenInput operations. We only need to preprocess the output index when it's the last operation.

        // Preprocess `is_last`.
        preprocessed.register_non_primitive_preprocessed_no_read(
            self.op_type,
            &[F::from_u64(self.is_last as u64)],
        );

        // Preprocess `is_real`
        preprocessed.register_non_primitive_preprocessed_no_read(self.op_type, &[F::ONE]);

        // Preprocess input indices.
        for inp in inputs {
            if inp.len() != 1 {
                return Err(CircuitError::NonPrimitiveOpLayoutMismatch {
                    op: self.op_type,
                    expected: format!("0 or 1 witness per input element {}", inp.len()),
                    got: inp.len(),
                });
            }
            preprocessed.register_non_primitive_witness_read(self.op_type, inp[0])?;
        }

        // Preprocess output index if this is the last OpenInput operation.
        // ro is an OUTPUT (creator on the bus), not a read, so we use
        // register_non_primitive_output_index to avoid incrementing ext_reads.
        if self.is_last {
            assert_eq!(outputs.len(), 1);
            assert_eq!(outputs[0].len(), 1);
            preprocessed.register_non_primitive_output_index(self.op_type, &outputs[0]);
        } else {
            preprocessed.register_non_primitive_preprocessed_no_read(self.op_type, &[F::ZERO]);
        }

        // ro_ext_mult placeholder (populated later by get_airs_and_degrees_with_prep
        // from ext_reads[ro_wid]).
        preprocessed.register_non_primitive_preprocessed_no_read(self.op_type, &[F::ZERO]);

        Ok(())
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}

pub fn generate_open_input_trace<
    BaseF: Field,
    F: CircuitField + ExtensionField<BaseF>,
    const D: usize,
>(
    op_states: &OpStateMap,
) -> Result<Option<Box<dyn NonPrimitiveTrace<F>>>, CircuitError> {
    let op_type = NonPrimitiveOpType::OpenInput;

    let Some(state) = op_states
        .get(&op_type)
        .and_then(|s| s.as_any().downcast_ref::<OpenInputState<F>>())
    else {
        return Ok(None);
    };

    if state.rows.is_empty() {
        return Ok(None);
    }

    let operations: Vec<OpenInputRow<BaseF>> = state
        .rows
        .iter()
        .map(|row| -> Result<_, CircuitError> {
            Ok(OpenInputRow {
                alpha: row.alpha[0].as_basis_coefficients_slice().to_vec(),
                alpha_index: row.alpha_index,
                pow_at_x: row.pow_at_x[0].as_basis_coefficients_slice().to_vec(),
                pow_at_x_index: row.pow_at_x_index,
                pow_at_z: row.pow_at_z[0].as_basis_coefficients_slice().to_vec(),
                pow_at_z_index: row.pow_at_z_index,
                ro_index: row.ro_index,
                is_last: row.is_last,
                is_real: row.is_real,
            })
        })
        .collect::<Result<Vec<_>, CircuitError>>()?;

    Ok(Some(Box::new(OpenInputTrace {
        op_type,
        rows: operations,
    })))
}

pub struct OpenInputCall {
    pub alpha: ExprId,
    pub p_at_x: ExprId,
    pub p_at_z: ExprId,
    pub is_last: bool,
}

pub trait OpenInputOp {
    fn add_open_input(
        &mut self,
        call: OpenInputCall,
    ) -> Result<(NonPrimitiveOpId, Option<ExprId>), CircuitBuilderError>;
}

impl<F: Field> OpenInputOp for CircuitBuilder<F> {
    fn add_open_input(
        &mut self,
        call: OpenInputCall,
    ) -> Result<(NonPrimitiveOpId, Option<ExprId>), CircuitBuilderError> {
        let op_type = NonPrimitiveOpType::OpenInput;
        self.ensure_op_enabled(op_type)?;

        let input_exprs = vec![vec![call.alpha], vec![call.p_at_x], vec![call.p_at_z]];

        let (op_id, _call_expr_id, outputs) = self.push_non_primitive_op_with_outputs(
            op_type,
            input_exprs,
            vec![call.is_last.then_some("OpenInput output")],
            Some(NonPrimitiveOpParams::OpenInput {
                is_last: call.is_last,
            }),
            "open_input",
        );

        Ok((op_id, outputs[0]))
    }
}
