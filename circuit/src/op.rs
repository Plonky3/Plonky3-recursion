use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt::Debug;
use core::hash::Hash;

use hashbrown::HashMap;
use p3_field::Field;

use crate::ops::MmcsVerifyConfig;
use crate::tables::MmcsPrivateData;
use crate::types::{NonPrimitiveOpId, WitnessId};
use crate::{CircuitError, ExprId};

/// Circuit operations.
///
/// Operations are distinguised as primitive and non-primitive:
///
/// # Primitive operations
///
/// Primitive operations that represent basic field arithmetic
///
/// These operations form the core computational primitives after expression lowering.
/// All primitive operations:
/// - Operate on witness table slots (WitnessId)
/// - Can be heavily optimized (constant folding, CSE, etc.)
/// - Are executed in topological order during circuit evaluation
/// - Form a directed acyclic graph (DAG) of dependencies
///
/// # Non-primitive operations
///
/// Non-primitive operations may represent complex computations that would require too many,
/// primitive operations to be expressed equivalently.
///
/// They can be user-defined and selected at runtime, have private data that does not appear
/// in the central Witness bus, and are subject to their own optimization passes.
#[derive(Debug)]
pub enum Op<F> {
    /// Load a constant value into the witness table
    ///
    /// Sets `witness[out] = val`. Used for literal constants and
    /// supports constant pooling optimization where identical constants
    /// reuse the same witness slot.
    Const { out: WitnessId, val: F },

    /// Load a public input value into the witness table
    ///
    /// Sets `witness[out] = public_inputs[public_pos]`. Public inputs
    /// are values known to both prover and verifier, typically used
    /// for circuit inputs and expected outputs.
    Public { out: WitnessId, public_pos: usize },

    /// Field addition: witness[out] = witness[a] + witness[b]
    Add {
        a: WitnessId,
        b: WitnessId,
        out: WitnessId,
    },

    /// Field multiplication: witness[out] = witness[a] * witness[b]
    Mul {
        a: WitnessId,
        b: WitnessId,
        out: WitnessId,
    },

    /// Load unconstrained values into the witness table
    ///
    /// Sets `witness[output]`, for each `output` in `outputs`, to aribitrary values
    /// defined by `filler`
    Unconstrained {
        inputs: Vec<WitnessId>,
        outputs: Vec<WitnessId>,
        filler: Box<dyn WitnessHintFiller<F>>,
    },

    /// Non-primitive operation with executor-based dispatch
    NonPrimitiveOpWithExecutor {
        inputs: Vec<Vec<WitnessId>>,
        outputs: Vec<Vec<WitnessId>>,
        executor: Box<dyn NonPrimitiveExecutor<F>>,
        /// For private data lookup and error reporting
        op_id: NonPrimitiveOpId,
    },
}

// Custom Clone implementation for Op
impl<F: Field + Clone> Clone for Op<F> {
    fn clone(&self) -> Self {
        match self {
            Op::Const { out, val } => Op::Const {
                out: *out,
                val: *val,
            },
            Op::Public { out, public_pos } => Op::Public {
                out: *out,
                public_pos: *public_pos,
            },
            Op::Add { a, b, out } => Op::Add {
                a: *a,
                b: *b,
                out: *out,
            },
            Op::Mul { a, b, out } => Op::Mul {
                a: *a,
                b: *b,
                out: *out,
            },
            Op::Unconstrained {
                inputs,
                outputs,
                filler,
            } => Op::Unconstrained {
                inputs: inputs.clone(),
                outputs: outputs.clone(),
                filler: filler.clone(),
            },
            Op::NonPrimitiveOpWithExecutor {
                inputs,
                outputs,
                executor,
                op_id,
            } => Op::NonPrimitiveOpWithExecutor {
                inputs: inputs.clone(),
                outputs: outputs.clone(),
                executor: executor.boxed(),
                op_id: *op_id,
            },
        }
    }
}

// Custom PartialEq implementation for Op
impl<F: Field + PartialEq> PartialEq for Op<F> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Op::Const { out: o1, val: v1 }, Op::Const { out: o2, val: v2 }) => {
                o1 == o2 && v1 == v2
            }
            (
                Op::Public {
                    out: o1,
                    public_pos: p1,
                },
                Op::Public {
                    out: o2,
                    public_pos: p2,
                },
            ) => o1 == o2 && p1 == p2,
            (
                Op::Add {
                    a: a1,
                    b: b1,
                    out: o1,
                },
                Op::Add {
                    a: a2,
                    b: b2,
                    out: o2,
                },
            ) => a1 == a2 && b1 == b2 && o1 == o2,
            (
                Op::Mul {
                    a: a1,
                    b: b1,
                    out: o1,
                },
                Op::Mul {
                    a: a2,
                    b: b2,
                    out: o2,
                },
            ) => a1 == a2 && b1 == b2 && o1 == o2,
            (
                Op::NonPrimitiveOpWithExecutor {
                    inputs: i1,
                    outputs: o1,
                    executor: e1,
                    op_id: id1,
                },
                Op::NonPrimitiveOpWithExecutor {
                    inputs: i2,
                    outputs: o2,
                    executor: e2,
                    op_id: id2,
                },
            ) => i1 == i2 && o1 == o2 && e1.op_type() == e2.op_type() && id1 == id2,
            _ => false,
        }
    }
}

/// Non-primitive operation types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NonPrimitiveOpType {
    // Mmcs Verify gate with the argument is the size of the path
    MmcsVerify,
    FriVerify,
    /// Hash absorb operation - absorbs field elements into sponge state
    HashAbsorb {
        reset: bool,
    },
    /// Hash squeeze operation - extracts field elements from sponge state
    HashSqueeze,
}

/// Non-primitive operation types
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NonPrimitiveOpConfig {
    MmcsVerifyConfig(MmcsVerifyConfig),
    None,
}

/// Non-primitive operations representing complex cryptographic constraints.
///
/// These operations implement sophisticated cryptographic primitives that:
/// - Have dedicated AIR tables for constraint verification
/// - Take witness values as public interface
/// - May require separate private data for complete specification
/// - Are NOT subject to primitive optimizations (CSE, constant folding)
/// - Enable modular addition of complex functionality
///
/// Non-primitive operations are isolated from primitive optimizations to:
/// 1. Maintain clean separation between basic arithmetic and complex crypto
/// 2. Allow specialized constraint systems for each operation type
/// 3. Enable parallel development of different cryptographic primitives
/// 4. Avoid optimization passes breaking complex constraint relationships
#[derive(Debug, Clone, PartialEq)]
pub enum NonPrimitiveOp {
    /// Verifies that a leaf value is contained in a Mmcs with given root.
    /// The actual Mmcs path verification logic is implemented in a dedicated
    /// AIR table that constrains the relationship between leaf and root.
    ///
    /// Public interface (on witness bus):
    /// - `leaves`: The leaves values being verified. Each one correspond to the hash of a matrix row .
    /// - `directions`: The directions in the tree taken by the merkle path.
    /// - `root`: The expected Mmcs root (single field element)
    ///
    /// Private data (set via NonPrimitiveOpId):
    /// - Mmcs path siblings and direction bits
    /// - See `MmcsPrivateData` for complete specification
    MmcsVerify {
        leaves: Vec<Vec<WitnessId>>,
        directions: Vec<WitnessId>,
        root: Vec<WitnessId>,
    },

    /// Hash absorb operation - absorbs inputs into sponge state.
    ///
    /// Public interface (on witness bus):
    /// - `inputs`: Field elements to absorb into the sponge
    /// - `reset_flag`: Whether to reset the sponge state before absorbing
    HashAbsorb {
        reset_flag: bool,
        inputs: Vec<WitnessId>,
    },

    /// Hash squeeze operation - extracts outputs from sponge state.
    ///
    /// Public interface (on witness bus):
    /// - `outputs`: Field elements extracted from the sponge
    HashSqueeze { outputs: Vec<WitnessId> },
}

/// Private auxiliary data for non-primitive operations
///
/// This data is NOT part of the witness table but provides additional
/// parameters needed to fully specify complex operations. Private data:
/// - Is set during circuit execution via `NonPrimitiveOpId`
/// - Contains sensitive information like cryptographic witnesses
/// - Is used by AIR tables to generate the appropriate constraints
#[derive(Debug, Clone, PartialEq)]
pub enum NonPrimitiveOpPrivateData<F> {
    /// Private data for Mmcs verification
    ///
    /// Contains the complete Mmcs path information needed by the prover
    /// to generate a valid proof. This data is not part of the public
    /// circuit specification.
    MmcsVerify(MmcsPrivateData<F>),
}

/// Execution context providing operations access to witness table, private data, and configs
///
/// This context is passed to operation executors to give them access to all necessary
/// runtime state without exposing internal implementation details.
pub struct ExecutionContext<'a, F> {
    /// Mutable reference to witness table for reading/writing values
    witness: &'a mut [Option<F>],
    /// Private data map for non-primitive operations
    non_primitive_op_private_data: &'a [Option<NonPrimitiveOpPrivateData<F>>],
    /// Operation configurations
    enabled_ops: &'a HashMap<NonPrimitiveOpType, NonPrimitiveOpConfig>,
    /// Current operation's NonPrimitiveOpId for error reporting
    operation_id: NonPrimitiveOpId,
}

impl<'a, F: Field> ExecutionContext<'a, F> {
    /// Create a new execution context
    pub fn new(
        witness: &'a mut [Option<F>],
        non_primitive_op_private_data: &'a [Option<NonPrimitiveOpPrivateData<F>>],
        enabled_ops: &'a HashMap<NonPrimitiveOpType, NonPrimitiveOpConfig>,
        operation_id: NonPrimitiveOpId,
    ) -> Self {
        Self {
            witness,
            non_primitive_op_private_data,
            enabled_ops,
            operation_id,
        }
    }

    /// Get witness value at the given index
    pub fn get_witness(&self, widx: WitnessId) -> Result<F, CircuitError> {
        self.witness
            .get(widx.0 as usize)
            .and_then(|opt| opt.as_ref())
            .cloned()
            .ok_or(CircuitError::WitnessNotSet { witness_id: widx })
    }

    /// Set witness value at the given index
    pub fn set_witness(&mut self, widx: WitnessId, value: F) -> Result<(), CircuitError> {
        if widx.0 as usize >= self.witness.len() {
            return Err(CircuitError::WitnessIdOutOfBounds { witness_id: widx });
        }

        // Check for conflicting reassignment
        if let Some(existing_value) = self.witness[widx.0 as usize]
            && existing_value != value
        {
            return Err(CircuitError::WitnessConflict {
                witness_id: widx,
                existing: alloc::format!("{existing_value:?}"),
                new: alloc::format!("{value:?}"),
            });
        }

        self.witness[widx.0 as usize] = Some(value);
        Ok(())
    }

    /// Get private data for the current operation
    pub fn get_private_data(&self) -> Result<&NonPrimitiveOpPrivateData<F>, CircuitError> {
        self.non_primitive_op_private_data
            .get(self.operation_id.0 as usize)
            .and_then(|opt| opt.as_ref())
            .ok_or(CircuitError::NonPrimitiveOpMissingPrivateData {
                operation_index: self.operation_id,
            })
    }

    /// Get operation configuration by type
    pub fn get_config(
        &self,
        op_type: &NonPrimitiveOpType,
    ) -> Result<&NonPrimitiveOpConfig, CircuitError> {
        self.enabled_ops
            .get(op_type)
            .ok_or(CircuitError::InvalidNonPrimitiveOpConfiguration {
                op: op_type.clone(),
            })
    }

    /// Get the current operation ID
    pub fn operation_id(&self) -> NonPrimitiveOpId {
        self.operation_id
    }
}

/// Trait for executable non-primitive operations
///
/// This trait enables dynamic dispatch and allows each operation to control
/// its own execution logic with full access to the execution context.
pub trait NonPrimitiveExecutor<F: Field>: Debug {
    /// Execute the operation with full context access
    ///
    /// # Arguments
    /// * `inputs` - Input witness indices
    /// * `outputs` - Output witness indices  
    /// * `ctx` - Execution context with access to witness table, private data, and configs
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        ctx: &mut ExecutionContext<F>,
    ) -> Result<(), CircuitError>;

    /// Get operation type identifier (for config lookup, error reporting)
    fn op_type(&self) -> &NonPrimitiveOpType;

    /// Clone as trait object
    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>>;
}

// Implement Clone for Box<dyn NonPrimitiveExecutor<F>>
impl<F: Field> Clone for Box<dyn NonPrimitiveExecutor<F>> {
    fn clone(&self) -> Self {
        self.boxed()
    }
}

/// A trait for defining how unconstrained data (hints) is set.
pub trait WitnessHintFiller<F>: Debug + WitnessFillerClone<F> {
    /// Return the `ExprId` of the inputs
    fn inputs(&self) -> &[ExprId];
    /// Returns number of outputs filled by this filler
    fn n_outputs(&self) -> usize;
    /// Compute the output given the inputs
    /// # Arguments
    /// * `inputs` - Input witness
    fn compute_outputs(&self, inputs_val: Vec<F>) -> Result<Vec<F>, CircuitError>;
}

impl<F> Clone for Box<dyn WitnessHintFiller<F>> {
    fn clone(&self) -> Self {
        self.clone_box()
    }
}

// Object-safe "clone into Box" helper
pub trait WitnessFillerClone<F> {
    fn clone_box(&self) -> Box<dyn WitnessHintFiller<F>>;
}

impl<F, T> WitnessFillerClone<F> for T
where
    T: WitnessHintFiller<F> + Clone + 'static,
{
    fn clone_box(&self) -> Box<dyn WitnessHintFiller<F>> {
        Box::new(self.clone())
    }
}
