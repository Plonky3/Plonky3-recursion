//! Source metadata for a builder-produced compiled circuit snapshot.
//!
//! This metadata is valid for the operations and expression mapping emitted by
//! `CircuitBuilder`. Mutating a circuit's public operation or mapping fields can
//! invalidate it; a changed operation count makes `Circuit::provenance` return
//! `None`, while same-length edits cannot be detected.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use crate::alloc_entry::{AllocationEntry, AllocationLog};
use crate::types::{ExprId, WitnessId};

/// Immutable source identities and allocation records for a compiled circuit.
#[derive(Debug)]
pub struct CircuitProvenance {
    allocations: AllocationLog,
    operation_origins: Vec<Vec<ExprId>>,
    witness_origins: BTreeMap<WitnessId, Vec<ExprId>>,
}

impl CircuitProvenance {
    pub(crate) fn new(
        allocations: AllocationLog,
        mut operation_origins: Vec<Vec<ExprId>>,
        expr_to_widx: &hashbrown::HashMap<ExprId, WitnessId>,
    ) -> Self {
        for origins in &mut operation_origins {
            origins.sort_unstable();
            origins.dedup();
        }
        let mut witness_origins: BTreeMap<WitnessId, Vec<ExprId>> = BTreeMap::new();
        for (&expr, &witness) in expr_to_widx {
            witness_origins.entry(witness).or_default().push(expr);
        }
        for origins in witness_origins.values_mut() {
            origins.sort_unstable();
            origins.dedup();
        }
        Self {
            allocations,
            operation_origins,
            witness_origins,
        }
    }

    /// Return the first recorded allocation for an expression, if any.
    ///
    /// Pooled constants and expression CSE keep the first allocation's label
    /// and innermost scope. `ExprId::ZERO` has no allocation record.
    pub fn allocation(&self, expression: ExprId) -> Option<&AllocationEntry> {
        self.allocations
            .iter()
            .find(|entry| entry.expr_id == expression)
    }

    /// Exact source expressions for a zero-based compiled operation index.
    pub fn operation_origins(&self, operation_index: usize) -> &[ExprId] {
        self.operation_origins
            .get(operation_index)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Source expressions sharing a final canonical witness ID.
    ///
    /// Resolve an old witness through `Circuit::witness_rewrite` first.
    pub fn witness_origins(&self, canonical_witness: WitnessId) -> &[ExprId] {
        self.witness_origins
            .get(&canonical_witness)
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    pub(crate) const fn operation_count(&self) -> usize {
        self.operation_origins.len()
    }
}
