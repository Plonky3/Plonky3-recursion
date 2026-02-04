//! Configuration for packing multiple primitive operations into a single AIR row.

/// Configuration for packing multiple primitive operations into a single AIR row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TablePacking {
    witness_lanes: usize,
    add_lanes: usize,
    mul_lanes: usize,
}

impl TablePacking {
    pub fn new(witness_lanes: usize, add_lanes: usize, mul_lanes: usize) -> Self {
        Self {
            witness_lanes: witness_lanes.max(1),
            add_lanes: add_lanes.max(1),
            mul_lanes: mul_lanes.max(1),
        }
    }

    pub fn from_counts(witness_lanes: usize, add_lanes: usize, mul_lanes: usize) -> Self {
        Self::new(witness_lanes, add_lanes, mul_lanes)
    }

    pub const fn witness_lanes(self) -> usize {
        self.witness_lanes
    }

    pub const fn add_lanes(self) -> usize {
        self.add_lanes
    }

    pub const fn mul_lanes(self) -> usize {
        self.mul_lanes
    }
}

impl Default for TablePacking {
    fn default() -> Self {
        Self::new(1, 1, 1)
    }
}
