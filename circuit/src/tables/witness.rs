use alloc::vec::Vec;

use crate::types::WitnessId;

/// Witness value store.
///
/// Holds all intermediate computation values produced during circuit execution.
/// It exists only as a convenient value store for inspection.
#[derive(Debug, Clone)]
pub struct WitnessTrace<F> {
    /// Sequential witness IDs: WitnessId(0), WitnessId(1), WitnessId(2), ...
    ///
    /// Kept for API compatibility with existing tests and tools.
    pub index: Vec<WitnessId>,

    /// Witness field element values.
    values: Vec<F>,
}

impl<F> WitnessTrace<F> {
    /// Create a new instance from a flat vector of values.
    ///
    /// IDs are assigned sequentially starting from `WitnessId(0)`.
    pub fn new(values: Vec<F>) -> Self {
        let index = (0..values.len() as u32).map(WitnessId).collect();
        Self { index, values }
    }

    /// Number of witness entries.
    pub const fn num_rows(&self) -> usize {
        self.values.len()
    }

    /// Return a reference to the value at the given witness ID.
    /// Returns `None` if `witness_id` is out of bounds.
    pub fn get_value(&self, witness_id: WitnessId) -> Option<&F> {
        self.values.get(witness_id.0 as usize)
    }

    /// Return the last value (useful for padding in matrix construction).
    pub fn last_value(&self) -> Option<&F> {
        self.values.last()
    }

    #[cfg(feature = "debugging")]
    pub(crate) fn values(&self) -> &[F] {
        &self.values
    }
}
