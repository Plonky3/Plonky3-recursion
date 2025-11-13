use alloc::vec;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::ops::{Add, Mul, Sub};

use hashbrown::HashMap;
use p3_field::Field;
use strum::EnumCount;

use crate::op::{NonPrimitiveOpConfig, NonPrimitiveOpType, Op, PrimitiveOpType};
use crate::tables::CircuitRunner;
use crate::types::{ExprId, WitnessId};

/// Trait encapsulating the required field operations for circuits
pub trait CircuitField:
    Clone
    + Default
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + PartialEq
    + Debug
    + Field
{
}

impl<F> CircuitField for F where
    F: Clone
        + Default
        + Add<Output = F>
        + Sub<Output = F>
        + Mul<Output = F>
        + PartialEq
        + Debug
        + Field
{
}

/// Static circuit specification containing constraint system and metadata
///
/// This represents the compiled output of a `CircuitBuilder`. It contains:
/// - Primitive operations (add, multiply, subtract, constants, public inputs)
/// - Non-primitive operations (complex operations like MMCS verification)
/// - Public input metadata and witness table structure
///
/// The circuit is static and serializable. Use `.runner()` to create
/// a `CircuitRunner` for execution with specific input values.
#[derive(Debug)]
pub struct Circuit<F> {
    /// Number of witness table rows
    pub witness_count: u32,
    /// Primitive operations in topological order
    pub primitive_ops: Vec<Op<F>>,
    /// Non-primitive operations
    pub non_primitive_ops: Vec<Op<F>>,
    /// Public input witness indices
    pub public_rows: Vec<WitnessId>,
    /// Total number of public field elements
    pub public_flat_len: usize,
    /// Enabled non-primitive operation types with their respective configuration
    pub enabled_ops: HashMap<NonPrimitiveOpType, NonPrimitiveOpConfig>,
    pub expr_to_widx: HashMap<ExprId, WitnessId>,
}

impl<F: Field + Clone> Clone for Circuit<F> {
    fn clone(&self) -> Self {
        Self {
            witness_count: self.witness_count,
            primitive_ops: self.primitive_ops.clone(),
            non_primitive_ops: self.non_primitive_ops.clone(),
            public_rows: self.public_rows.clone(),
            public_flat_len: self.public_flat_len,
            enabled_ops: self.enabled_ops.clone(),
            expr_to_widx: self.expr_to_widx.clone(),
        }
    }
}

impl<F: Field> Circuit<F> {
    pub fn new(witness_count: u32, expr_to_widx: HashMap<ExprId, WitnessId>) -> Self {
        Self {
            witness_count,
            primitive_ops: Vec::new(),
            non_primitive_ops: Vec::new(),
            public_rows: Vec::new(),
            public_flat_len: 0,
            enabled_ops: HashMap::new(),
            expr_to_widx,
        }
    }

    /// Generates the preprocessed values for all ops except non-primitive ops.
    ///
    /// The preprocessed values for `Witness` are deduced from the other ops:
    /// they correspond to 0..`n` where `n` is the largest witness index used in the circuit.
    pub fn generate_preprocessed_columns(
        &mut self,
    ) -> Result<Vec<Vec<F>>, crate::CircuitBuilderError> {
        let n = PrimitiveOpType::COUNT; // Exclude non-primitive ops
        let mut preprocessed = vec![vec![]; n];

        let mut max_idx = 0;
        for prim in &self.primitive_ops {
            match prim {
                Op::Const { out, val } => {
                    let table_idx = PrimitiveOpType::Const as usize;
                    preprocessed[table_idx].extend(&[F::from_u32(out.0), *val]);
                    max_idx = max_idx.max(out.0);
                }
                Op::Public { out, .. } => {
                    let table_idx = PrimitiveOpType::Public as usize;
                    preprocessed[table_idx].extend(&[F::from_u32(out.0)]);
                    max_idx = max_idx.max(out.0);
                }
                Op::Add { a, b, out } => {
                    let table_idx = PrimitiveOpType::Add as usize;
                    preprocessed[table_idx].extend(&[
                        F::from_u32(a.0),
                        F::from_u32(b.0),
                        F::from_u32(out.0),
                    ]);
                    max_idx = max_idx.max(a.0).max(b.0).max(out.0);
                }
                Op::Mul { a, b, out } => {
                    let table_idx = PrimitiveOpType::Mul as usize;
                    preprocessed[table_idx].extend(&[
                        F::from_u32(a.0),
                        F::from_u32(b.0),
                        F::from_u32(out.0),
                    ]);
                    max_idx = max_idx.max(a.0).max(b.0).max(out.0);
                }
                Op::NonPrimitiveOpWithExecutor { .. } => panic!(
                    "preprocessed values are not yet implemented for non primitivie operations."
                ),
            }
        }

        // Now, we can generate the values for `Witness` using `max_idx`.
        let table_idx = PrimitiveOpType::Witness as usize;
        preprocessed[table_idx].extend((0..=max_idx).map(|i| F::from_u32(i)));

        Ok(preprocessed)
    }
}

impl<F: CircuitField> Circuit<F> {
    /// Create a circuit runner for execution and trace generation
    pub fn runner(self) -> CircuitRunner<F> {
        CircuitRunner::new(self)
    }
}
