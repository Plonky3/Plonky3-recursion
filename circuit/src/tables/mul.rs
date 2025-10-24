use alloc::vec::Vec;

use crate::CircuitError;
use crate::op::Op;
use crate::types::WitnessId;

/// Multiplication operation table.
///
/// Records every multiplication operation in the circuit.
/// Each row represents one constraint: lhs * rhs = result.
#[derive(Debug, Clone)]
pub struct MulTrace<F> {
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

/// Builder for generating multiplication traces.
pub struct MulTraceBuilder<'a, F> {
    primitive_ops: &'a [Op<F>],
    witness: &'a [Option<F>],
}

impl<'a, F: Clone> MulTraceBuilder<'a, F> {
    /// Creates a new multiplication trace builder.
    pub fn new(primitive_ops: &'a [Op<F>], witness: &'a [Option<F>]) -> Self {
        Self {
            primitive_ops,
            witness,
        }
    }

    /// Builds the multiplication trace from circuit operations.
    pub fn build(self) -> Result<MulTrace<F>, CircuitError> {
        let mut lhs_values = Vec::new();
        let mut lhs_index = Vec::new();
        let mut rhs_values = Vec::new();
        let mut rhs_index = Vec::new();
        let mut result_values = Vec::new();
        let mut result_index = Vec::new();

        for prim in self.primitive_ops {
            if let Op::Mul { a, b, out } = prim {
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

        Ok(MulTrace {
            lhs_values,
            lhs_index,
            rhs_values,
            rhs_index,
            result_values,
            result_index,
        })
    }
}
