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
    pub alpha: Vec<F>,
    pub alpha_index: u32,
    pub pow_at_x: Vec<F>, // For EvalPoint: [rev_bit, 0, ..., 0]
    pub pow_at_x_index: u32, // For EvalPoint: rev_bit witness index
    pub pow_at_z: Vec<F>,
    pub pow_at_z_index: u32,
    pub ro_index: u32, // For EvalPoint: output index for eval result
    pub is_last: bool,
    pub is_real: bool,
    pub is_eval: bool,  // true for EvalPoint rows, false for ReducedOpening rows
    pub g_power: F,     // g^(2^i) for EvalPoint rows, F::ZERO otherwise
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
            is_eval: false,
            g_power: F::ZERO,
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

        // is_eval = 0 for ReducedOpening rows.
        preprocessed.register_non_primitive_preprocessed_no_read(self.op_type, &[F::ZERO]);

        // g_power = 0 for ReducedOpening rows.
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
                is_eval: row.is_eval,
                g_power: row.g_power.as_basis_coefficients_slice()[0],
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

// ---------------------------------------------------------------------------
// EvalPoint operation — computes evaluation points within the OpenInput table.
// ---------------------------------------------------------------------------

pub struct EvalPointCall<F> {
    pub rev_bit: ExprId,  // Witness target for the reversed bit
    pub g_power: F,       // g^(2^i) constant for this row
    pub generator: F,     // Coset generator (F::GENERATOR promoted to EF)
    pub is_last: bool,    // Last row of eval sequence
}

pub trait EvalPointOp<F> {
    fn add_eval_point(
        &mut self,
        call: EvalPointCall<F>,
    ) -> Result<(NonPrimitiveOpId, Option<ExprId>), CircuitBuilderError>;
}

impl<F: Field> EvalPointOp<F> for CircuitBuilder<F> {
    fn add_eval_point(
        &mut self,
        call: EvalPointCall<F>,
    ) -> Result<(NonPrimitiveOpId, Option<ExprId>), CircuitBuilderError> {
        let op_type = NonPrimitiveOpType::OpenInput;
        self.ensure_op_enabled(op_type)?;

        // Inputs layout: [alpha(empty), p_at_x(rev_bit), p_at_z(empty)]
        let input_exprs = vec![vec![], vec![call.rev_bit], vec![]];

        let (op_id, _call_expr_id, outputs) = self.push_non_primitive_op_with_outputs(
            op_type,
            input_exprs,
            vec![call.is_last.then_some("EvalPoint output")],
            Some(NonPrimitiveOpParams::EvalPoint {
                is_last: call.is_last,
                g_power: call.g_power,
                generator: call.generator,
            }),
            "eval_point",
        );

        Ok((op_id, outputs[0]))
    }
}

/// Executor for EvalPoint operations within the OpenInput table.
#[derive(Debug, Clone)]
pub struct EvalPointExecutor<F> {
    op_type: NonPrimitiveOpType,
    is_last: bool,
    g_power: F,
    generator: F,
}

impl<F: Field> EvalPointExecutor<F> {
    pub fn new(is_last: bool, g_power: F, generator: F) -> Self {
        Self {
            op_type: NonPrimitiveOpType::OpenInput,
            is_last,
            g_power,
            generator,
        }
    }
}

impl<F: Field> NonPrimitiveExecutor<F> for EvalPointExecutor<F> {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        assert_eq!(inputs.len(), 3);
        // Only inputs[1] (p_at_x slot) has a value: the rev_bit.
        assert!(inputs[0].is_empty(), "alpha slot must be empty for EvalPoint");
        assert_eq!(inputs[1].len(), 1, "p_at_x slot must have exactly 1 witness for rev_bit");
        assert!(inputs[2].is_empty(), "p_at_z slot must be empty for EvalPoint");

        let rev_bit_wid = inputs[1][0];
        let rev_bit = ctx.get_witness(rev_bit_wid).map_err(|_| CircuitError::WitnessNotSet {
            witness_id: rev_bit_wid,
        })?;

        // mult = 1 + rev_bit * (g_power - 1)
        let mult = F::ONE + rev_bit * (self.g_power - F::ONE);

        let state = ctx.get_op_state_mut::<OpenInputState<F>>(&self.op_type);

        // If first in sequence (last_ro is None), start at GENERATOR * mult.
        // Otherwise, continue accumulation: prev_eval * mult.
        let eval = match state.last_ro {
            Some(prev) => prev * mult,
            None => self.generator * mult,
        };

        let output_index = if self.is_last {
            assert_eq!(outputs.len(), 1);
            assert_eq!(outputs[0].len(), 1);
            outputs[0][0].0
        } else {
            0
        };

        state.last_ro = Some(eval);

        state.rows.push(OpenInputRow {
            alpha: vec![F::ZERO],
            alpha_index: 0,
            pow_at_x: vec![rev_bit],
            pow_at_x_index: rev_bit_wid.0,
            pow_at_z: vec![F::ZERO],
            pow_at_z_index: 0,
            ro_index: output_index,
            is_last: self.is_last,
            is_real: true,
            is_eval: true,
            g_power: self.g_power,
        });

        if self.is_last {
            state.last_ro = None;
            assert_eq!(outputs.len(), 1);
            assert_eq!(outputs[0].len(), 1);
            ctx.set_witness(outputs[0][0], eval)?;
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
        // [0] is_last
        preprocessed.register_non_primitive_preprocessed_no_read(
            self.op_type,
            &[F::from_u64(self.is_last as u64)],
        );

        // [1] is_real
        preprocessed.register_non_primitive_preprocessed_no_read(self.op_type, &[F::ONE]);

        // [2] alpha_index = 0 (unused for EvalPoint)
        preprocessed.register_non_primitive_preprocessed_no_read(self.op_type, &[F::ZERO]);

        // [3] p_at_x_index = rev_bit witness index
        assert_eq!(inputs[1].len(), 1);
        preprocessed.register_non_primitive_witness_read(self.op_type, inputs[1][0])?;

        // [4] p_at_z_index = 0 (unused for EvalPoint)
        preprocessed.register_non_primitive_preprocessed_no_read(self.op_type, &[F::ZERO]);

        // [5] ro_index
        if self.is_last {
            assert_eq!(outputs.len(), 1);
            assert_eq!(outputs[0].len(), 1);
            preprocessed.register_non_primitive_output_index(self.op_type, &outputs[0]);
        } else {
            preprocessed.register_non_primitive_preprocessed_no_read(self.op_type, &[F::ZERO]);
        }

        // [6] ro_ext_mult placeholder
        preprocessed.register_non_primitive_preprocessed_no_read(self.op_type, &[F::ZERO]);

        // [7] is_eval = 1
        preprocessed.register_non_primitive_preprocessed_no_read(self.op_type, &[F::ONE]);

        // [8] g_power
        preprocessed.register_non_primitive_preprocessed_no_read(self.op_type, &[self.g_power]);

        Ok(())
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}
