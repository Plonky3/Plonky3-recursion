//! Structured wrapper for allocating public input targets.

use alloc::vec::Vec;

use p3_circuit::CircuitBuilder;
use p3_field::Field;

use crate::Target;

/// Wrapper for allocating public input targets.
///
/// Each target allocation contains a associated label for debugging purposes.
///
/// # Example
/// ```ignore
/// let mut alloc = TargetAllocator::new(circuit);
/// let commitment = alloc.alloc_array::<8>("commitment digest");
/// let sibling = alloc.alloc("FRI sibling value");
/// let values = alloc.alloc_vec(5, "opened values");
/// ```
pub struct TargetAllocator<'a, F> {
    circuit: &'a mut CircuitBuilder<F>,
    #[cfg(debug_assertions)]
    allocation_log: Vec<&'static str>,
}

impl<'a, F: Field> TargetAllocator<'a, F> {
    /// Create a new target allocator.
    pub fn new(circuit: &'a mut CircuitBuilder<F>) -> Self {
        Self {
            circuit,
            #[cfg(debug_assertions)]
            allocation_log: Vec::new(),
        }
    }

    /// Allocate a single public input target with a descriptive label.
    ///
    /// # Parameters
    /// - `label`: Description of what this target represents (used for debugging)
    ///
    /// # Returns
    /// The allocated target
    #[allow(unused_variables)] // Release mode
    pub fn alloc(&mut self, label: &'static str) -> Target {
        #[cfg(debug_assertions)]
        self.allocation_log.push(label);

        self.circuit.add_public_input()
    }

    /// Allocate multiple public input targets with a descriptive label.
    ///
    /// # Parameters
    /// - `count`: Number of targets to allocate
    /// - `label`: Description of what these targets represent
    ///
    /// # Returns
    /// Vector of allocated targets
    pub fn alloc_vec(&mut self, count: usize, label: &'static str) -> Vec<Target> {
        (0..count).map(|_| self.alloc(label)).collect()
    }

    /// Allocate an array of public input targets with a descriptive label.
    ///
    /// # Parameters
    /// - `label`: Description of what these targets represent
    ///
    /// # Returns
    /// Array of allocated targets
    pub fn alloc_array<const N: usize>(&mut self, label: &'static str) -> [Target; N] {
        core::array::from_fn(|_| self.alloc(label))
    }

    /// Get the number of allocations made.
    pub fn count(&self) -> usize {
        #[cfg(debug_assertions)]
        return self.allocation_log.len();

        #[cfg(not(debug_assertions))]
        {
            // We don't track allocations count in release mode
            0
        }
    }

    /// Dump the allocation log (debug builds only).
    ///
    /// Useful for debugging public input ordering issues.
    #[cfg(debug_assertions)]
    pub fn dump_log(&self) {
        for (idx, label) in self.allocation_log.iter().enumerate() {
            tracing::debug!("PublicInput[{}]: {}", idx, label);
        }
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;

    use super::*;

    #[test]
    fn test_target_allocator_basic() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        let mut alloc = TargetAllocator::new(&mut circuit);

        let t1 = alloc.alloc("first");
        let t2 = alloc.alloc("second");

        // Targets are sequential (note: ExprId(0) is reserved for Const(0))
        assert!(t2.0 > t1.0);
        assert_eq!(t2.0, t1.0 + 1);

        #[cfg(debug_assertions)]
        assert_eq!(alloc.count(), 2);
    }

    #[test]
    fn test_target_allocator_vec() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        let mut alloc = TargetAllocator::new(&mut circuit);

        let targets = alloc.alloc_vec(3, "test values");

        assert_eq!(targets.len(), 3);
        // Verify sequential allocation
        assert_eq!(targets[1].0, targets[0].0 + 1);
        assert_eq!(targets[2].0, targets[1].0 + 1);
    }

    #[test]
    fn test_target_allocator_array() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        let mut alloc = TargetAllocator::new(&mut circuit);

        let targets = alloc.alloc_array::<8>("digest");

        assert_eq!(targets.len(), 8);
        // Verify sequential allocation
        for i in 1..8 {
            assert_eq!(targets[i].0, targets[i - 1].0 + 1);
        }
    }
}
