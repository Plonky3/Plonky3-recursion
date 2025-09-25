use alloc::vec::Vec;

use crate::op::{NonPrimitiveOp, Prim};
use crate::types::WitnessId;

/// Static circuit specification containing constraint system and metadata
///
/// This represents the compiled output of a `CircuitBuilder`. It contains:
/// - Primitive operations (add, multiply, subtract, constants, public inputs)
/// - Non-primitive operations (complex operations like Merkle verification)
/// - Public input metadata and witness table structure
///
/// The circuit is static and serializable. Use `.runner()` to create
/// a `CircuitRunner` for execution with specific input values.
#[derive(Debug, Clone)]
pub struct Circuit<F> {
    /// Number of witness table rows
    pub witness_count: u32,
    /// Primitive operations in topological order
    pub primitive_ops: Vec<Prim<F>>,
    /// Non-primitive operations
    pub non_primitive_ops: Vec<NonPrimitiveOp<F>>,
    /// Public input witness indices
    pub public_rows: Vec<WitnessId>,
    /// Total number of public field elements
    pub public_flat_len: usize,
}

impl<F> Circuit<F> {
    pub fn new(witness_count: u32) -> Self {
        Self {
            witness_count,
            primitive_ops: Vec::new(),
            non_primitive_ops: Vec::new(),
            public_rows: Vec::new(),
            public_flat_len: 0,
        }
    }
}
