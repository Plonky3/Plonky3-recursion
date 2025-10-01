use alloc::vec::Vec;

use hashbrown::HashMap;
use p3_field::Field;

use crate::op::{NonPrimitiveOp, NonPrimitiveOpConfig, NonPrimitiveOpType, Prim};
use crate::tables::CircuitRunner;
use crate::types::WitnessId;

/// Trait encapsulating the required field operations for circuits
pub trait CircuitField:
    Clone
    + Default
    + core::ops::Add<Output = Self>
    + core::ops::Sub<Output = Self>
    + core::ops::Mul<Output = Self>
    + PartialEq
    + core::fmt::Debug
    + Field
{
}

impl<F> CircuitField for F where
    F: Clone
        + Default
        + core::ops::Add<Output = F>
        + core::ops::Sub<Output = F>
        + core::ops::Mul<Output = F>
        + PartialEq
        + core::fmt::Debug
        + Field
{
}

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
    pub non_primitive_ops: Vec<NonPrimitiveOp>,
    /// Public input witness indices
    pub public_rows: Vec<WitnessId>,
    /// Total number of public field elements
    pub public_flat_len: usize,
    /// Enabled non-primitive operation types with their respective configuration
    pub enabled_ops: HashMap<NonPrimitiveOpType, NonPrimitiveOpConfig<F>>,
}

impl<F> Circuit<F> {
    pub fn new(witness_count: u32) -> Self {
        Self {
            witness_count,
            primitive_ops: Vec::new(),
            non_primitive_ops: Vec::new(),
            public_rows: Vec::new(),
            public_flat_len: 0,
            enabled_ops: HashMap::new(),
        }
    }
}

impl<F: CircuitField> Circuit<F> {
    /// Create a circuit runner for execution and trace generation
    pub fn runner(self) -> CircuitRunner<F> {
        CircuitRunner::new(self)
    }
}
