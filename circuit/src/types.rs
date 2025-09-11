use core::fmt;

use serde::{Deserialize, Serialize};

/// Witness ID type - a unique identifier for extension field values in the global witness bus
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WitnessId(pub u32);

impl fmt::Display for WitnessId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "w{}", self.0)
    }
}

/// Handle to an expression in the graph
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExprId(pub u32);

/// Handle to a non-primitive operation (for setting private data later)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NonPrimitiveOpId(pub u32);

/// Witness allocator for monotonic index assignment
#[derive(Debug, Clone)]
pub struct WitnessAllocator {
    next_idx: u32,
}

impl WitnessAllocator {
    pub fn new() -> Self {
        Self { next_idx: 0 }
    }

    pub fn alloc(&mut self) -> WitnessId {
        let idx = WitnessId(self.next_idx);
        self.next_idx += 1;
        idx
    }

    pub fn slot_count(&self) -> u32 {
        self.next_idx
    }
}

impl Default for WitnessAllocator {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_witness_id_display() {
        let idx = WitnessId(42);
        assert_eq!(format!("{idx}"), "w42");
    }

    #[test]
    fn test_witness_allocator() {
        let mut allocator = WitnessAllocator::new();

        let w0 = allocator.alloc();
        let w1 = allocator.alloc();
        let w2 = allocator.alloc();

        assert_eq!(w0, WitnessId(0));
        assert_eq!(w1, WitnessId(1));
        assert_eq!(w2, WitnessId(2));
        assert_eq!(allocator.slot_count(), 3);
    }
}
