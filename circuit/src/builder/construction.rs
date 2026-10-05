//! Optional periodic budgets for retained circuit-construction entries.

use super::CircuitBuilderError;

/// Limits construction entries before lowering. These are separate from final
/// witness, operation and trace limits, and do not measure memory in bytes.
///
/// Infallible builder operations can cross a limit. Checked helpers reject at
/// their next checkpoint, and both build entry points always check before lowering.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CircuitConstructionLimits {
    pub max_expression_nodes: usize,
    pub max_pending_connects: usize,
    pub max_non_primitive_calls: usize,
    /// Input/output slot descriptors plus their retained expression references.
    pub max_non_primitive_slots: usize,
}

/// Exact retained entry counts at a construction checkpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CircuitConstructionUsage {
    pub expression_nodes: usize,
    pub pending_connects: usize,
    pub non_primitive_calls: usize,
    pub non_primitive_slots: usize,
}

impl CircuitConstructionLimits {
    pub(super) fn check(self, usage: CircuitConstructionUsage) -> Result<(), CircuitBuilderError> {
        for (component, actual, limit) in [
            (
                "expression nodes",
                usage.expression_nodes,
                self.max_expression_nodes,
            ),
            (
                "pending connections",
                usage.pending_connects,
                self.max_pending_connects,
            ),
            (
                "non-primitive calls",
                usage.non_primitive_calls,
                self.max_non_primitive_calls,
            ),
            (
                "non-primitive slots",
                usage.non_primitive_slots,
                self.max_non_primitive_slots,
            ),
        ] {
            if actual > limit {
                return Err(CircuitBuilderError::ConstructionLimitExceeded {
                    component,
                    actual,
                    limit,
                });
            }
        }
        Ok(())
    }
}
