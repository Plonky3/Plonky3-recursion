use crate::prim::{ComplexOp, Prim};
use crate::types::WitnessIndex;

/// Main program artifact - serializable and immutable
#[derive(Debug, Clone)]
pub struct Program<F> {
    /// Number of witness table rows
    pub slot_count: u32,
    /// Primitive operations in topological order
    pub prim_ops: Vec<Prim<F>>,
    /// Complex operations (non-primitive)
    pub complex_ops: Vec<ComplexOp>,
    /// Public input witness indices
    pub public_rows: Vec<WitnessIndex>,
    /// Total number of public field elements
    pub public_flat_len: usize,
}

impl<F> Program<F> {
    pub fn new(slot_count: u32) -> Self {
        Self {
            slot_count,
            prim_ops: Vec::new(),
            complex_ops: Vec::new(),
            public_rows: Vec::new(),
            public_flat_len: 0,
        }
    }
}
