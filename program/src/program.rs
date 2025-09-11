use crate::prim::{NonPrimitiveOp, Prim};
use crate::types::WitnessId;

/// Main program artifact - serializable and immutable
#[derive(Debug, Clone)]
pub struct Program<F> {
    /// Number of witness table rows
    pub slot_count: u32,
    /// Primitive operations in topological order
    pub primitive_op: Vec<Prim<F>>,
    /// Non-primitive operations
    pub non_primitive_op: Vec<NonPrimitiveOp>,
    /// Public input witness indices
    pub public_rows: Vec<WitnessId>,
    /// Total number of public field elements
    pub public_flat_len: usize,
}

impl<F> Program<F> {
    pub fn new(slot_count: u32) -> Self {
        Self {
            slot_count,
            primitive_op: Vec::new(),
            non_primitive_op: Vec::new(),
            public_rows: Vec::new(),
            public_flat_len: 0,
        }
    }
}
