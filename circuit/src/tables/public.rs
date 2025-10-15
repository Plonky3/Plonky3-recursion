use alloc::vec::Vec;

use crate::CircuitError;
use crate::op::Prim;
use crate::types::WitnessId;

/// Public input table.
///
/// Tracks all public inputs to the circuit.
/// Both prover and verifier know these values.
/// They represent the externally visible interface to the computation.
#[derive(Debug, Clone)]
pub struct PublicTrace<F> {
    /// Witness IDs of each public input.
    ///
    /// Identifies which witness slots contain public values.
    pub index: Vec<WitnessId>,

    /// Public input field element values.
    ///
    /// Provided by the external caller.
    /// Serve as the starting point for computation.
    pub values: Vec<F>,
}

/// Builder for generating public input traces.
pub struct PublicTraceBuilder<'a, F> {
    primitive_ops: &'a [Prim<F>],
    witness: &'a [Option<F>],
}

impl<'a, F: Clone> PublicTraceBuilder<'a, F> {
    /// Creates a new public trace builder.
    pub fn new(primitive_ops: &'a [Prim<F>], witness: &'a [Option<F>]) -> Self {
        Self {
            primitive_ops,
            witness,
        }
    }

    /// Builds the public input trace from circuit operations.
    pub fn build(self) -> Result<PublicTrace<F>, CircuitError> {
        let mut index = Vec::new();
        let mut values = Vec::new();

        for prim in self.primitive_ops {
            if let Prim::Public { out, public_pos: _ } = prim {
                index.push(*out);
                let value = self
                    .witness
                    .get(out.0 as usize)
                    .and_then(|opt| opt.as_ref())
                    .cloned()
                    .ok_or(CircuitError::WitnessNotSet { witness_id: *out })?;
                values.push(value);
            }
        }

        Ok(PublicTrace { index, values })
    }
}
