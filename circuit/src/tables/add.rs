use alloc::vec::Vec;

use p3_field::Field;

use crate::CircuitError;
use crate::op::Op;
use crate::types::WitnessId;

/// Addition operation table.
///
/// Records every addition operation in the circuit.
/// Each row represents one constraint: lhs + rhs = result.
#[derive(Debug, Clone)]
pub struct AddTrace<F> {
    /// Left operand values
    pub lhs_values: Vec<F>,
    /// Left operand indices (references witness bus)
    pub lhs_index: Vec<WitnessId>,
    /// Right operand values
    pub rhs_values: Vec<F>,
    /// Right operand indices (references witness bus)
    pub rhs_index: Vec<WitnessId>,
    /// Result values
    pub result_values: Vec<F>,
    /// Result indices (references witness bus)
    pub result_index: Vec<WitnessId>,
}

/// Builder for generating addition traces.
pub struct AddTraceBuilder<'a, F> {
    primitive_ops: &'a [Op<F>],
    witness: &'a [Option<F>],
}

impl<'a, F: Clone + Field> AddTraceBuilder<'a, F> {
    /// Creates a new addition trace builder.
    pub fn new(primitive_ops: &'a [Op<F>], witness: &'a [Option<F>]) -> Self {
        Self {
            primitive_ops,
            witness,
        }
    }

    /// Builds the addition trace from circuit operations.
    pub fn build(self) -> Result<AddTrace<F>, CircuitError> {
        let mut lhs_values = Vec::new();
        let mut lhs_index = Vec::new();
        let mut rhs_values = Vec::new();
        let mut rhs_index = Vec::new();
        let mut result_values = Vec::new();
        let mut result_index = Vec::new();

        for prim in self.primitive_ops {
            if let Op::Add { a, b, out } = prim {
                let a_val = self
                    .witness
                    .get(a.0 as usize)
                    .and_then(|opt| opt.as_ref())
                    .cloned()
                    .ok_or(CircuitError::WitnessNotSet { witness_id: *a })?;
                let b_val = self
                    .witness
                    .get(b.0 as usize)
                    .and_then(|opt| opt.as_ref())
                    .cloned()
                    .ok_or(CircuitError::WitnessNotSet { witness_id: *b })?;
                let out_val = self
                    .witness
                    .get(out.0 as usize)
                    .and_then(|opt| opt.as_ref())
                    .cloned()
                    .ok_or(CircuitError::WitnessNotSet { witness_id: *out })?;

                lhs_values.push(a_val);
                lhs_index.push(*a);
                rhs_values.push(b_val);
                rhs_index.push(*b);
                result_values.push(out_val);
                result_index.push(*out);
            }
        }

        // If trace is empty, add a dummy row: 0 + 0 = 0
        if lhs_values.is_empty() {
            lhs_values.push(F::ZERO);
            lhs_index.push(WitnessId(0));
            rhs_values.push(F::ZERO);
            rhs_index.push(WitnessId(0));
            result_values.push(F::ZERO);
            result_index.push(WitnessId(0));
        }

        Ok(AddTrace {
            lhs_values,
            lhs_index,
            rhs_values,
            rhs_index,
            result_values,
            result_index,
        })
    }
}
