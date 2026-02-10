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
    values: Vec<F>,
}

impl<F> WitnessTrace<F> {
    /// Create a new instance of [`WitnessTrace`].
    pub fn new(index: Vec<WitnessId>, values: Vec<F>) -> Self {
        assert_eq!(index.len(), values.len());
        Self { index, values }
    }

    /// Output the number of rows in the trace.
    pub const fn num_rows(&self) -> usize {
        self.values.len()
    }

    #[cfg(debug_assertions)]
    /// Return a reference to the values of the witness trace.
    pub(crate) fn values(&self) -> &[F] {
        &self.values
    }

    /// Return a reference to the value at the given witness id.
    /// Returns `None` if the target [`WitnessId`] is not set.
    pub fn get_value(&self, witness_id: WitnessId) -> Option<&F> {
        self.values.get(witness_id.0 as usize)
    }

    /// Return the last value in the trace.
    /// This is useful for padding.
    pub fn last_value(&self) -> Option<&F> {
        self.values.last()
    }
}

/// Builder for generating witness traces.
pub struct WitnessTraceBuilder<'a, F> {
    witness: &'a [Option<F>],
}

impl<'a, F: Clone> WitnessTraceBuilder<'a, F> {
    /// Creates a new witness trace builder.
    pub const fn new(witness: &'a [Option<F>]) -> Self {
        Self { witness }
    }

    /// Builds the witness trace from the populated witness table.
    pub fn build(self) -> Result<WitnessTrace<F>, CircuitError> {
        let capacity = self.witness.len();
        let mut index = Vec::with_capacity(capacity);
        let mut values = Vec::with_capacity(capacity);

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

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    type F = BabyBear;

    #[test]
    fn test_single_witness() {
        // Create a witness table with a single value
        let val = F::from_u64(42);
        let witness = vec![Some(val)];

        // Build the trace using the builder pattern
        let builder = WitnessTraceBuilder::new(&witness);
        let trace = builder.build().expect("Failed to build trace");

        // Verify the trace contains exactly one witness
        assert_eq!(trace.index.len(), 1, "Should have one witness entry");
        assert_eq!(trace.values.len(), 1, "Should have one witness value");

        // Verify the witness is correctly recorded with sequential index
        assert_eq!(trace.index[0], WitnessId(0));
        assert_eq!(trace.values[0], val);
    }

    #[test]
    fn test_multiple_witnesses() {
        // Create a witness table with multiple values
        let val1 = F::from_u64(10);
        let val2 = F::from_u64(20);
        let val3 = F::from_u64(30);

        let witness = vec![Some(val1), Some(val2), Some(val3)];

        // Build the trace
        let builder = WitnessTraceBuilder::new(&witness);
        let trace = builder.build().expect("Failed to build trace");

        // Verify we have exactly three witnesses
        assert_eq!(trace.index.len(), 3, "Should have three witness entries");
        assert_eq!(trace.values.len(), 3, "Should have three witness values");

        // Verify indices are sequential starting from 0
        assert_eq!(trace.index[0], WitnessId(0));
        assert_eq!(trace.index[1], WitnessId(1));
        assert_eq!(trace.index[2], WitnessId(2));

        // Verify values match the input order
        assert_eq!(trace.values[0], val1);
        assert_eq!(trace.values[1], val2);
        assert_eq!(trace.values[2], val3);
    }

    #[test]
    fn test_empty_witness() {
        // Provide an empty witness table
        let witness: Vec<Option<F>> = vec![];

        // Build the trace
        let builder = WitnessTraceBuilder::new(&witness);
        let trace = builder.build().expect("Failed to build trace");

        // Verify the trace is empty
        assert_eq!(trace.index.len(), 0, "Should have no witness entries");
        assert_eq!(trace.values.len(), 0, "Should have no values");
    }

    #[test]
    fn test_witness_not_set_error() {
        // Create a witness table with an unset slot in the middle
        let witness: Vec<Option<F>> = vec![Some(F::from_u64(10)), None, Some(F::from_u64(30))];

        // Attempt to build the trace
        let builder = WitnessTraceBuilder::new(&witness);
        let result = builder.build();

        // Verify the build fails with the expected error at index 1
        assert!(result.is_err(), "Should fail when witness slot is not set");
        assert!(matches!(
            result,
            Err(CircuitError::WitnessNotSetForIndex { index: 1 })
        ));
    }
}
