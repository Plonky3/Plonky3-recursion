use crate::prim::{NonPrimitiveOp, Prim};
use crate::types::WitnessId;

/// Immutable circuit specification containing constraint system and metadata
///
/// This represents the compiled output of a `CircuitBuilder`. It contains:
/// - Primitive operations (add, multiply, subtract, constants, public inputs)
/// - Non-primitive operations (complex operations like Merkle verification)
/// - Public input metadata and witness table structure
///
/// The circuit is immutable and serializable. Use `.instantiate()` to create
/// a `CircuitInstance` for execution with specific input values.
#[derive(Debug, Clone)]
pub struct Circuit<F> {
    /// Number of witness table rows
    pub slot_count: u32,
    /// Primitive operations in topological order
    pub primitive_ops: Vec<Prim<F>>,
    /// Non-primitive operations
    pub non_primitive_ops: Vec<NonPrimitiveOp>,
    /// Public input witness indices
    pub public_rows: Vec<WitnessId>,
    /// Total number of public field elements
    pub public_flat_len: usize,
}

impl<F> Circuit<F> {
    pub fn new(slot_count: u32) -> Self {
        Self {
            slot_count,
            primitive_ops: Vec::new(),
            non_primitive_ops: Vec::new(),
            public_rows: Vec::new(),
            public_flat_len: 0,
        }
    }
}
