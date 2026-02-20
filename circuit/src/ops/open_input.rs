use alloc::boxed::Box;
use alloc::vec::Vec;
use alloc::{format, vec};

use p3_field::Field;

// TODO Linda: alpha_pow and intermediary ros should be private inputs.
use crate::op::{ExecutionContext, NonPrimitiveExecutor, OpExecutionState};
use crate::{CircuitError, NonPrimitiveOpType, WitnessId};

#[derive(Debug, Clone)]
pub struct OpenInputRow<F> {
    // All `Vec`s correspond to one extension limb in execution rows, and D base field elements in trace rows.
    pub alpha: Vec<F>,
    pub alpha_index: u32,
    pub x: Vec<F>,
    pub x_index: u32,
    pub z: Vec<F>,
    pub z_index: u32,
    pub pow_at_x: Vec<F>,
    pub pow_at_x_index: u32,
    pub pow_at_z: Vec<F>,
    pub pow_at_z_index: u32,
    pub ro_index: u32,
    pub is_last: bool,
}

#[derive(Debug, Clone, Default)]
pub struct OpenInputTrace<F> {
    pub rows: Vec<OpenInputRow<F>>,
}

#[derive(Debug, Clone, Default)]
pub struct OpenInputState<F> {
    pub last_ro: Option<F>,
    pub last_alpha_pow: Option<F>,
    pub trace: OpenInputTrace<F>,
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
    pub fn new() -> Self {
        Self {
            op_type: NonPrimitiveOpType::OpenInput,
            is_last: false,
        }
    }

    fn set_is_last(&mut self, is_last: bool) {
        self.is_last = is_last;
    }
}

impl<F: Field> NonPrimitiveExecutor<F> for OpenInputExecutor {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError> {
        assert_eq!(inputs.len(), 6);
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
        let x = &inps_and_indices[1];
        let z = &inps_and_indices[2];
        let p_at_x = &inps_and_indices[3];
        let p_at_z = &inps_and_indices[4];

        // Compute the next `alpha_pow` and `ro` values.
        let state = ctx.get_op_state_mut::<OpenInputState<F>>(&self.op_type);
        let alpha_pow = state.last_alpha_pow.unwrap_or(alpha.0);
        let new_alpha_pow = alpha.0 * alpha_pow;
        let ro = state.last_ro.unwrap_or(F::ZERO);
        let new_ro = ro + alpha_pow * (p_at_z.0 - p_at_x.0) / (z.0 - x.0);

        let output_index = if self.is_last {
            assert_eq!(outputs.len(), 1);
            assert_eq!(outputs[0].len(), 1);
            outputs[0][0].0
        } else {
            0
        };

        state.last_alpha_pow = Some(new_alpha_pow);
        state.last_ro = Some(new_ro);
        state.trace.rows.push(OpenInputRow {
            alpha: vec![alpha.0],
            alpha_index: alpha.1,
            x: vec![x.0],
            x_index: x.1,
            z: vec![z.0],
            z_index: z.1,
            pow_at_x: vec![p_at_x.0],
            pow_at_x_index: p_at_x.1,
            pow_at_z: vec![p_at_z.0],
            pow_at_z_index: p_at_z.1,
            ro_index: output_index,
            is_last: self.is_last,
        });

        // Update the witness values in the context.
        // There only are outputs if last is true. And then we only need the last ro.
        if self.is_last {
            assert_eq!(outputs.len(), 1);
            assert_eq!(outputs[0].len(), 1);
            ctx.set_witness(outputs[0][0], new_ro)?;
        } else {
            assert_eq!(outputs.len(), 0);
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
        if self.is_last {
            assert_eq!(outputs.len(), 1);
            assert_eq!(outputs[0].len(), 1);
            preprocessed.register_non_primitive_witness_read(self.op_type, outputs[0][0])?;
        } else {
            preprocessed.register_non_primitive_preprocessed_no_read(self.op_type, &[F::ZERO]);
        }

        // Preprocess `is_last`.
        preprocessed.register_non_primitive_preprocessed_no_read(
            self.op_type,
            &[F::from_u64(self.is_last as u64)],
        );

        Ok(())
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}
