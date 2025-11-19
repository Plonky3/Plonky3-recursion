use alloc::vec::Vec;

use crate::CircuitError;
use crate::op::Op;
use crate::types::WitnessId;

/// Constant values table.
///
/// Stores all compile-time known constant values used in the circuit.
/// Each constant binds to a specific witness ID.
/// Both prover and verifier know these values in advance.
#[derive(Debug, Clone)]
pub struct ConstTrace<F> {
    /// Witness IDs that each constant binds to.
    ///
    /// Maps each constant to its location in the witness table.
    pub index: Vec<WitnessId>,
    /// Constant field element values.
    pub values: Vec<F>,
}

/// Builder for generating constant traces.
pub struct ConstTraceBuilder<'a, F> {
    primitive_ops: &'a [Op<F>],
}

impl<'a, F: Clone> ConstTraceBuilder<'a, F> {
    /// Creates a new constant trace builder.
    pub const fn new(primitive_ops: &'a [Op<F>]) -> Self {
        Self { primitive_ops }
    }

    /// Builds the constant trace from circuit operations.
    pub fn build(self) -> Result<ConstTrace<F>, CircuitError> {
        let mut index = Vec::new();
        let mut values = Vec::new();

        for prim in self.primitive_ops {
            if let Op::Const { out, val } = prim {
                index.push(*out);
                values.push(val.clone());
            }
        }

        Ok(ConstTrace { index, values })
    }
}
