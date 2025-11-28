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

impl fmt::Display for ExprId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "e{}", self.0)
    }
}

impl ExprId {
    /// The zero expression ID - always points to Const(0)
    pub const ZERO: Self = Self(0);
}

/// Handle to a non-primitive operation (for setting private data later)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NonPrimitiveOpId(pub u32);

impl fmt::Display for NonPrimitiveOpId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "id{}", self.0)
    }
}

/// Witness allocator for monotonic index assignment
#[derive(Debug, Clone, Default)]
pub struct WitnessAllocator {
    next_idx: u32,
}

impl WitnessAllocator {
    pub const fn new() -> Self {
        Self { next_idx: 0 }
    }

    pub const fn alloc(&mut self) -> WitnessId {
        let idx = WitnessId(self.next_idx);
        self.next_idx += 1;
        idx
    }

    pub const fn witness_count(&self) -> u32 {
        self.next_idx
    }
}

#[cfg(test)]
mod tests {
    use alloc::format;

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
        assert_eq!(allocator.witness_count(), 3);
    }

    #[cfg(test)]
    mod proptests {
        use proptest::prelude::*;

        use super::*;

        proptest! {
            #[test]
            fn witness_id_ordering(a in 0u32..u32::MAX, b in 0u32..u32::MAX) {
                let id_a = WitnessId(a);
                let id_b = WitnessId(b);

                if a < b {
                    prop_assert!(id_a < id_b, "ordering should match inner value");
                } else if a > b {
                    prop_assert!(id_a > id_b, "ordering should match inner value");
                } else {
                    prop_assert_eq!(id_a, id_b, "equal values should compare equal");
                }
            }

            #[test]
            fn expr_id_ordering(a in 0u32..u32::MAX, b in 0u32..u32::MAX) {
                let id_a = ExprId(a);
                let id_b = ExprId(b);

                if a < b {
                    prop_assert!(id_a < id_b, "ordering should match inner value");
                } else if a > b {
                    prop_assert!(id_a > id_b, "ordering should match inner value");
                } else {
                    prop_assert_eq!(id_a, id_b, "equal values should compare equal");
                }
            }

            #[test]
            fn non_primitive_op_id_equality(a in 0u32..u32::MAX, b in 0u32..u32::MAX) {
                let id_a1 = NonPrimitiveOpId(a);
                let id_a2 = NonPrimitiveOpId(a);
                let id_b = NonPrimitiveOpId(b);

                prop_assert_eq!(id_a1, id_a2, "same value should be equal");
                if a != b {
                    prop_assert_ne!(id_a1, id_b, "different values should not be equal");
                }
            }

            #[test]
            fn witness_allocator_unique(count in 1usize..100) {
                let mut allocator = WitnessAllocator::new();
                let mut seen = hashbrown::HashSet::new();

                for _ in 0..count {
                    let id = allocator.alloc();
                    prop_assert!(seen.insert(id), "each allocation should be unique");
                }
            }

            #[test]
            fn witness_allocator_count_accurate(count in 0usize..100) {
                let mut allocator = WitnessAllocator::new();

                prop_assert_eq!(allocator.witness_count(), 0, "new allocator should have count 0");

                for i in 1..=count {
                    allocator.alloc();
                    prop_assert_eq!(
                        allocator.witness_count(),
                        i as u32,
                        "count should increment with each allocation"
                    );
                }
            }
        }
    }
}
