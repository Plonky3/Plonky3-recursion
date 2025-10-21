use alloc::vec::Vec;

use crate::CircuitError;
use crate::types::WitnessId;

/// Central witness table.
///
/// Primary storage for all intermediate values in the circuit.
/// Acts as the "bus" that all operation tables reference.
/// Witnesses have sequential IDs starting from 0.
#[derive(Debug, Clone)]
pub struct WitnessTrace<F> {
    /// Sequential witness IDs: WitnessId(0), WitnessId(1), WitnessId(2), ...
    ///
    /// Forms a preprocessed column for lookups from other tables.
    pub index: Vec<WitnessId>,

    /// Witness field element values.
    ///
    /// Each value is one computation result.
    /// Computed during circuit execution.
    pub values: Vec<F>,
}

/// Builder for generating witness traces.
pub struct WitnessTraceBuilder<'a, F> {
    witness: &'a [Option<F>],
}

impl<'a, F: Clone> WitnessTraceBuilder<'a, F> {
    /// Creates a new witness trace builder.
    pub fn new(witness: &'a [Option<F>]) -> Self {
        Self { witness }
    }

    /// Builds the witness trace from the populated witness table.
    pub fn build(self) -> Result<WitnessTrace<F>, CircuitError> {
        let mut index = Vec::new();
        let mut values = Vec::new();

        for (i, witness_opt) in self.witness.iter().enumerate() {
            match witness_opt {
                Some(value) => {
                    index.push(WitnessId(i as u32));
                    values.push(value.clone());
                }
                None => {
                    return Err(CircuitError::WitnessNotSetForIndex { index: i });
                }
            }
        }

        Ok(WitnessTrace { index, values })
    }
}
