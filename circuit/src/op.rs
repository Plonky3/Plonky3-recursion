use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::any::Any;
use core::fmt::Debug;
use core::hash::Hash;

use hashbrown::HashMap;
use p3_field::{Field, PrimeCharacteristicRing};
use strum_macros::EnumCount;

use crate::ops::Poseidon2PermPrivateData;
use crate::types::{NonPrimitiveOpId, WitnessId};
use crate::{CircuitError, PreprocessedColumns};

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

    /// Non-primitive operation with executor-based dispatch
    NonPrimitiveOpWithExecutor {
        inputs: Vec<Vec<WitnessId>>,
        outputs: Vec<Vec<WitnessId>>,
        executor: Box<dyn NonPrimitiveExecutor<F>>,
        /// For private data lookup and error reporting
        op_id: NonPrimitiveOpId,
    },
}

#[derive(EnumCount)]
pub enum PrimitiveOpType {
    Witness = 0,
    Const = 1,
    Public = 2,
    Add = 3,
    Mul = 4,
}

#[allow(clippy::fallible_impl_from)]
impl From<usize> for PrimitiveOpType {
    fn from(value: usize) -> Self {
        match value {
            0 => Self::Witness,
            1 => Self::Const,
            2 => Self::Public,
            3 => Self::Add,
            4 => Self::Mul,
            _ => panic!("Invalid PrimitiveOpType value: {}", value),
        }
    }
}

// Custom Clone implementation for Op
impl<F: Field + Clone> Clone for Op<F> {
    fn clone(&self) -> Self {
        match self {
            Self::Const { out, val } => Self::Const {
                out: *out,
                val: *val,
            },
            Self::Public { out, public_pos } => Self::Public {
                out: *out,
                public_pos: *public_pos,
            },
            Self::Add { a, b, out } => Self::Add {
                a: *a,
                b: *b,
                out: *out,
            },
            Self::Mul { a, b, out } => Self::Mul {
                a: *a,
                b: *b,
                out: *out,
            },
            Self::NonPrimitiveOpWithExecutor {
                inputs,
                outputs,
                executor,
                op_id,
            } => Self::NonPrimitiveOpWithExecutor {
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
            (Self::Const { out: o1, val: v1 }, Self::Const { out: o2, val: v2 }) => {
                o1 == o2 && v1 == v2
            }
            (
                Self::Public {
                    out: o1,
                    public_pos: p1,
                },
                Self::Public {
                    out: o2,
                    public_pos: p2,
                },
            ) => o1 == o2 && p1 == p2,
            (
                Self::Add {
                    a: a1,
                    b: b1,
                    out: o1,
                },
                Self::Add {
                    a: a2,
                    b: b2,
                    out: o2,
                },
            ) => a1 == a2 && b1 == b2 && o1 == o2,
            (
                Self::Mul {
                    a: a1,
                    b: b1,
                    out: o1,
                },
                Self::Mul {
                    a: a2,
                    b: b2,
                    out: o2,
                },
            ) => a1 == a2 && b1 == b2 && o1 == o2,
            (
                Self::NonPrimitiveOpWithExecutor {
                    inputs: i1,
                    outputs: o1,
                    executor: e1,
                    op_id: id1,
                },
                Self::NonPrimitiveOpWithExecutor {
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

/// Non-primitive operation types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub enum NonPrimitiveOpType {
    /// Poseidon2 permutation operation (one Poseidon2 call / table row).
    Poseidon2Perm(Poseidon2Config),
    /// Unconstrained operation, used to set outputs to non-deterministic advices.
    Unconstrained,
}

// Re-export Poseidon2 config types from their canonical location
pub use crate::ops::poseidon2_perm::{Poseidon2Config, Poseidon2PermExec, Poseidon2PermExecBase};

/// Preprocessed data for non-primitive tables, keyed by operation type.
pub type NonPrimitivePreprocessedMap<F> = HashMap<NonPrimitiveOpType, Vec<F>>;

/// Non-primitive operation configuration.
///
/// Contains operation-specific configuration data, such as execution closures.
pub enum NonPrimitiveOpConfig<F> {
    /// No configuration needed (placeholder for future operations).
    None,
    /// Poseidon2 permutation configuration with exec closure (D=4, 4 extension elements).
    Poseidon2Perm {
        config: Poseidon2Config,
        exec: Poseidon2PermExec<F, 4>,
    },
    /// Poseidon2 permutation configuration for base field (D=1, 16 base elements).
    Poseidon2PermBase {
        config: Poseidon2Config,
        exec: Poseidon2PermExecBase<F>,
    },
}

impl<F> Clone for NonPrimitiveOpConfig<F> {
    fn clone(&self) -> Self {
        match self {
            Self::None => Self::None,
            Self::Poseidon2Perm { config, exec } => Self::Poseidon2Perm {
                config: *config,
                exec: Arc::clone(exec),
            },
            Self::Poseidon2PermBase { config, exec } => Self::Poseidon2PermBase {
                config: *config,
                exec: Arc::clone(exec),
            },
        }
    }
}

impl<F> Debug for NonPrimitiveOpConfig<F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::None => write!(f, "None"),
            Self::Poseidon2Perm { config, .. } => f
                .debug_struct("Poseidon2Perm")
                .field("config", config)
                .field("exec", &"<closure>")
                .finish(),
            Self::Poseidon2PermBase { config, .. } => f
                .debug_struct("Poseidon2PermBase")
                .field("config", config)
                .field("exec", &"<closure>")
                .finish(),
        }
    }
}

// Compare/Hash by variant/config only (ignore closure contents)
impl<F> PartialEq for NonPrimitiveOpConfig<F> {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::None, Self::None) => true,
            (Self::Poseidon2Perm { config: c1, .. }, Self::Poseidon2Perm { config: c2, .. }) => {
                c1 == c2
            }
            (
                Self::Poseidon2PermBase { config: c1, .. },
                Self::Poseidon2PermBase { config: c2, .. },
            ) => c1 == c2,
            _ => false,
        }
    }
}

impl<F> Eq for NonPrimitiveOpConfig<F> {}

impl<F> Hash for NonPrimitiveOpConfig<F> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        core::mem::discriminant(self).hash(state);
        match self {
            Self::Poseidon2Perm { config, .. } | Self::Poseidon2PermBase { config, .. } => {
                config.hash(state);
            }
            Self::None => {}
        }
    }
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
///
/// Private auxiliary data for non-primitive operations
///
/// This data is NOT part of the witness table but provides additional
/// parameters needed to fully specify complex operations. Private data:
/// - Is set during circuit execution via `NonPrimitiveOpId`
/// - Contains sensitive information like cryptographic witnesses
/// - Is used by AIR tables to generate the appropriate constraints
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NonPrimitiveOpPrivateData<F> {
    Poseidon2Perm(Poseidon2PermPrivateData<F, 2>),
}

/// Trait for operation-specific execution state.
///
/// Each non-primitive operation type can define its own state struct that persists
/// across invocations during circuit execution. This enables features like:
/// - Permutation chaining (storing previous output for next input)
/// - Recording execution data for canonical trace generation
///
/// Implementors must support downcasting via `Any` for type-safe retrieval.
pub trait OpExecutionState: Any + Send + Sync + Debug {
    /// Downcast to concrete type for reading.
    fn as_any(&self) -> &dyn Any;
    /// Downcast to concrete type for mutation.
    fn as_any_mut(&mut self) -> &mut dyn Any;
}

/// Type-erased storage for operation execution states.
///
/// This allows each operation type to maintain its own state without
/// coupling `ExecutionContext` to specific operation implementations.
pub type OpStateMap = BTreeMap<NonPrimitiveOpType, Box<dyn OpExecutionState>>;

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
    enabled_ops: &'a HashMap<NonPrimitiveOpType, NonPrimitiveOpConfig<F>>,
    /// Current operation's NonPrimitiveOpId for error reporting
    operation_id: NonPrimitiveOpId,
    /// Operation-specific execution state storage.
    /// Each operation type can store its own state (e.g., chaining state, row records).
    op_states: &'a mut OpStateMap,
}

impl<'a, F: PrimeCharacteristicRing + Eq + Clone> ExecutionContext<'a, F> {
    /// Create a new execution context
    pub fn new(
        witness: &'a mut [Option<F>],
        non_primitive_op_private_data: &'a [Option<NonPrimitiveOpPrivateData<F>>],
        enabled_ops: &'a HashMap<NonPrimitiveOpType, NonPrimitiveOpConfig<F>>,
        operation_id: NonPrimitiveOpId,
        op_states: &'a mut OpStateMap,
    ) -> Self {
        Self {
            witness,
            non_primitive_op_private_data,
            enabled_ops,
            operation_id,
            op_states,
        }
    }

    /// Get witness value at the given index
    #[inline]
    pub fn get_witness(&self, widx: WitnessId) -> Result<F, CircuitError> {
        self.witness
            .get(widx.0 as usize)
            .and_then(|opt| opt.as_ref())
            .cloned()
            .ok_or(CircuitError::WitnessNotSet { witness_id: widx })
    }

    /// Set witness value at the given index
    #[inline]
    pub fn set_witness(&mut self, widx: WitnessId, value: F) -> Result<(), CircuitError> {
        if widx.0 as usize >= self.witness.len() {
            return Err(CircuitError::WitnessIdOutOfBounds { witness_id: widx });
        }

        let slot = &mut self.witness[widx.0 as usize];

        // Check for conflicting reassignment
        if let Some(existing_value) = slot.as_ref() {
            if *existing_value == value {
                // Same value - this is fine (duplicate set via connect)
                return Ok(());
            }
            return Err(CircuitError::WitnessConflict {
                witness_id: widx,
                existing: format!("{existing_value:?}"),
                new: format!("{value:?}"),
                expr_ids: vec![], // TODO: Could be filled with expression IDs if tracked
            });
        }

        *slot = Some(value);
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
    ) -> Result<&NonPrimitiveOpConfig<F>, CircuitError> {
        self.enabled_ops
            .get(op_type)
            .ok_or(CircuitError::InvalidNonPrimitiveOpConfiguration { op: *op_type })
    }

    /// Get the current operation ID
    pub const fn operation_id(&self) -> NonPrimitiveOpId {
        self.operation_id
    }

    /// Get operation-specific state for reading.
    ///
    /// Returns `None` if no state has been initialized for this operation type.
    pub fn get_op_state<T: OpExecutionState + 'static>(
        &self,
        op_type: &NonPrimitiveOpType,
    ) -> Option<&T> {
        self.op_states
            .get(op_type)
            .and_then(|state| state.as_any().downcast_ref::<T>())
    }

    /// Get operation-specific state for mutation, creating default if not present.
    ///
    /// This is the primary way executors should access their state.
    pub fn get_op_state_mut<T: OpExecutionState + Default + 'static>(
        &mut self,
        op_type: &NonPrimitiveOpType,
    ) -> &mut T {
        // Entry API with type-erased storage
        if !self.op_states.contains_key(op_type) {
            self.op_states.insert(*op_type, Box::new(T::default()));
        }
        self.op_states
            .get_mut(op_type)
            .and_then(|state| state.as_any_mut().downcast_mut::<T>())
            .expect("type mismatch in op state - this is a bug")
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
        ctx: &mut ExecutionContext<'_, F>,
    ) -> Result<(), CircuitError>;

    /// Get operation type identifier (for config lookup, error reporting)
    fn op_type(&self) -> &NonPrimitiveOpType;

    /// Allow downcasting to concrete executor types
    fn as_any(&self) -> &dyn core::any::Any;

    /// Update the preprocessed values related to this operation. This consists of:
    /// - the preprocessed values for the associated table
    /// - the multiplicity for the `Witness` table.
    ///
    /// Uses the `PreprocessedColumns` API to ensure witness multiplicities are updated
    /// consistently when reading from the witness table.
    fn preprocess(
        &self,
        _inputs: &[Vec<WitnessId>],
        _outputs: &[Vec<WitnessId>],
        _preprocessed: &mut PreprocessedColumns<F>,
    ) -> Result<(), CircuitError> {
        Ok(())
    }

    /// Clone as trait object
    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>>;
}

// Implement Clone for Box<dyn NonPrimitiveExecutor<F>>
impl<F: Field> Clone for Box<dyn NonPrimitiveExecutor<F>> {
    fn clone(&self) -> Self {
        self.boxed()
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::ops::poseidon2_perm::Poseidon2PermPrivateData;

    type F = BabyBear;

    #[test]
    fn test_op_partial_eq_different_variants() {
        // Create operations of completely different types
        let const_op = Op::Const {
            out: WitnessId(0),
            val: F::from_u64(5),
        };

        let add_op = Op::Add {
            a: WitnessId(0),
            b: WitnessId(1),
            out: WitnessId(2),
        };

        // Operations of different variants should never be equal
        assert_ne!(const_op, add_op);
    }

    #[test]
    fn test_op_partial_eq_same_variant_different_values() {
        // Create two addition operations with different witness indices
        let add_op1: Op<F> = Op::Add {
            a: WitnessId(0),
            b: WitnessId(1),
            out: WitnessId(2),
        };

        let add_op2: Op<F> = Op::Add {
            a: WitnessId(3),
            b: WitnessId(4),
            out: WitnessId(5),
        };

        // Same variant but different values should not be equal
        assert_ne!(add_op1, add_op2);
    }

    #[test]
    fn test_op_partial_eq_add_same_values() {
        // Create two identical addition operations
        let a = WitnessId(0);
        let b = WitnessId(1);
        let out = WitnessId(2);

        let add_op1: Op<F> = Op::Add { a, b, out };
        let add_op2: Op<F> = Op::Add { a, b, out };

        // Identical operations should be equal
        assert_eq!(add_op1, add_op2);
    }

    #[test]
    fn test_op_partial_eq_const_different_values() {
        // Create two constant operations with different values
        let out = WitnessId(0);
        let val1 = F::from_u64(10);
        let val2 = F::from_u64(20);

        let const_op1: Op<F> = Op::Const { out, val: val1 };
        let const_op2: Op<F> = Op::Const { out, val: val2 };

        // Same output but different values should not be equal
        assert_ne!(const_op1, const_op2);
    }

    #[test]
    fn test_op_partial_eq_const_different_outputs() {
        // Create two constant operations with same value but different outputs
        let val = F::from_u64(42);
        let out1 = WitnessId(0);
        let out2 = WitnessId(1);

        let const_op1: Op<F> = Op::Const { out: out1, val };
        let const_op2: Op<F> = Op::Const { out: out2, val };

        // Same value but different outputs should not be equal
        assert_ne!(const_op1, const_op2);
    }

    #[test]
    fn test_op_partial_eq_const_same_values() {
        // Create two identical constant operations
        let out = WitnessId(0);
        let val = F::from_u64(99);

        let const_op1: Op<F> = Op::Const { out, val };
        let const_op2: Op<F> = Op::Const { out, val };

        // Identical constant operations should be equal
        assert_eq!(const_op1, const_op2);
    }

    #[test]
    fn test_op_partial_eq_public_different_positions() {
        // Create two public input operations with different positions
        let out = WitnessId(0);
        let pos1 = 0;
        let pos2 = 1;

        let public_op1: Op<F> = Op::Public {
            out,
            public_pos: pos1,
        };
        let public_op2: Op<F> = Op::Public {
            out,
            public_pos: pos2,
        };

        // Same output but different positions should not be equal
        assert_ne!(public_op1, public_op2);
    }

    #[test]
    fn test_op_partial_eq_public_same_values() {
        // Create two identical public input operations
        let out = WitnessId(5);
        let public_pos = 3;

        let public_op1: Op<F> = Op::Public { out, public_pos };
        let public_op2: Op<F> = Op::Public { out, public_pos };

        // Identical public operations should be equal
        assert_eq!(public_op1, public_op2);
    }

    #[test]
    fn test_op_partial_eq_mul_different_values() {
        // Create two multiplication operations with different witness indices
        let mul_op1: Op<F> = Op::Mul {
            a: WitnessId(0),
            b: WitnessId(1),
            out: WitnessId(2),
        };

        let mul_op2: Op<F> = Op::Mul {
            a: WitnessId(10),
            b: WitnessId(11),
            out: WitnessId(12),
        };

        // Different witness indices should not be equal
        assert_ne!(mul_op1, mul_op2);
    }

    #[test]
    fn test_op_partial_eq_mul_same_values() {
        // Create two identical multiplication operations
        let a = WitnessId(7);
        let b = WitnessId(8);
        let out = WitnessId(9);

        let mul_op1: Op<F> = Op::Mul { a, b, out };
        let mul_op2: Op<F> = Op::Mul { a, b, out };

        // Identical multiplication operations should be equal
        assert_eq!(mul_op1, mul_op2);
    }

    #[test]
    fn test_op_partial_eq_add_partial_match() {
        // Create two addition operations where only some fields match
        let add_op1: Op<F> = Op::Add {
            a: WitnessId(0),
            b: WitnessId(1),
            out: WitnessId(2),
        };

        let add_op2: Op<F> = Op::Add {
            a: WitnessId(0),
            b: WitnessId(1),
            out: WitnessId(99), // Different output
        };

        // Partial match is not enough for equality
        assert_ne!(add_op1, add_op2);
    }

    #[test]
    #[should_panic(expected = "Invalid PrimitiveOpType value")]
    fn test_primitive_op_type_invalid_conversion() {
        // Attempt to convert an invalid index to an operation type
        //
        // This should panic
        let _ = PrimitiveOpType::from(999);
    }

    #[test]
    fn test_execution_context_get_witness() {
        // Create a witness table with known test values
        let val = F::from_u64(42);
        let mut witness = vec![Some(val), Some(F::from_u64(100))];
        let private_data = vec![];
        let configs = HashMap::new();
        let op_id = NonPrimitiveOpId(0);
        let mut op_states = BTreeMap::new();

        // Create an execution context for operations to access the witness
        let ctx =
            ExecutionContext::new(&mut witness, &private_data, &configs, op_id, &mut op_states);

        // Read a value from the witness table
        let result = ctx.get_witness(WitnessId(0));

        // Verify the read operation succeeded and returned the correct value
        assert_eq!(result.unwrap(), val);
    }

    #[test]
    fn test_execution_context_get_witness_unset() {
        // Create a witness table where some values are not yet set
        let mut witness = vec![None, Some(F::from_u64(100))];
        let private_data = vec![];
        let configs = HashMap::new();
        let op_id = NonPrimitiveOpId(0);
        let mut op_states = BTreeMap::new();

        // Create execution context
        let ctx =
            ExecutionContext::new(&mut witness, &private_data, &configs, op_id, &mut op_states);

        // Attempt to read a value that hasn't been set yet
        let result = ctx.get_witness(WitnessId(0));

        // Reading unset values should produce an error
        assert!(result.is_err());
        match result {
            Err(CircuitError::WitnessNotSet { witness_id }) => {
                assert_eq!(witness_id, WitnessId(0));
            }
            _ => panic!("Expected WitnessNotSet error"),
        }
    }

    #[test]
    fn test_execution_context_set_witness() {
        // Create an empty witness table to be populated
        let mut witness = vec![None, None];
        let private_data = vec![];
        let configs = HashMap::new();
        let op_id = NonPrimitiveOpId(0);
        let mut op_states = BTreeMap::new();

        // Create execution context with mutable access to witness
        let mut ctx =
            ExecutionContext::new(&mut witness, &private_data, &configs, op_id, &mut op_states);

        // Write a computed value into the witness table
        let val = F::from_u64(99);
        let result = ctx.set_witness(WitnessId(0), val);

        // Verify the write operation succeeded
        assert!(result.is_ok());

        // Verify the value was actually written to the witness table
        assert_eq!(witness[0], Some(val));
    }

    #[test]
    fn test_execution_context_set_witness_conflict() {
        // Create a witness table with an existing value
        let existing_val = F::from_u64(50);
        let mut witness = vec![Some(existing_val)];
        let private_data = vec![];
        let configs = HashMap::new();
        let op_id = NonPrimitiveOpId(0);
        let mut op_states = BTreeMap::new();

        // Create execution context
        let mut ctx =
            ExecutionContext::new(&mut witness, &private_data, &configs, op_id, &mut op_states);

        // Attempt to write a different value to the same slot
        //
        // This represents a conflicting constraint in the circuit
        let new_val = F::from_u64(99);
        let result = ctx.set_witness(WitnessId(0), new_val);

        // Conflicting writes must be detected and reported as errors
        assert!(result.is_err());
        match result {
            Err(CircuitError::WitnessConflict { witness_id, .. }) => {
                assert_eq!(witness_id, WitnessId(0));
            }
            _ => panic!("Expected WitnessConflict error"),
        }
    }

    #[test]
    fn test_execution_context_set_witness_idempotent() {
        // Create a witness table with an existing value
        let val = F::from_u64(50);
        let mut witness = vec![Some(val)];
        let private_data = vec![];
        let configs = HashMap::new();
        let op_id = NonPrimitiveOpId(0);
        let mut op_states = BTreeMap::new();

        // Create execution context
        let mut ctx =
            ExecutionContext::new(&mut witness, &private_data, &configs, op_id, &mut op_states);

        // Write the same value again to the same slot
        //
        // This is allowed and represents consistent constraints
        let result = ctx.set_witness(WitnessId(0), val);

        // Idempotent writes should succeed without error
        assert!(result.is_ok());
        assert_eq!(witness[0], Some(val));
    }

    #[test]
    fn test_execution_context_set_witness_out_of_bounds() {
        // Create a small witness table with limited capacity
        let mut witness = vec![None];
        let private_data = vec![];
        let configs = HashMap::new();
        let op_id = NonPrimitiveOpId(0);
        let mut op_states = BTreeMap::new();

        // Create execution context
        let mut ctx =
            ExecutionContext::new(&mut witness, &private_data, &configs, op_id, &mut op_states);

        // Attempt to write to an index beyond the table bounds
        let result = ctx.set_witness(WitnessId(10), F::from_u64(1));

        // Out of bounds writes must be caught to prevent memory corruption
        assert!(result.is_err());
        match result {
            Err(CircuitError::WitnessIdOutOfBounds { witness_id }) => {
                assert_eq!(witness_id, WitnessId(10));
            }
            _ => panic!("Expected WitnessIdOutOfBounds error"),
        }
    }

    #[test]
    fn test_execution_context_get_private_data() {
        // Create private auxiliary data for a verification operation
        let poseidon2_data: Poseidon2PermPrivateData<F, 2> = Poseidon2PermPrivateData {
            sibling: [F::ZERO, F::ZERO],
        };
        let private_data = vec![Some(NonPrimitiveOpPrivateData::Poseidon2Perm(
            poseidon2_data.clone(),
        ))];

        // Create execution context with access to private data
        let mut witness = vec![];
        let configs = HashMap::new();
        let op_id = NonPrimitiveOpId(0);
        let mut op_states = BTreeMap::new();
        let ctx =
            ExecutionContext::new(&mut witness, &private_data, &configs, op_id, &mut op_states);

        // Operations can access their private data through the context
        let result = ctx.get_private_data();

        // Verify private data access succeeded
        assert_eq!(
            *result.unwrap(),
            NonPrimitiveOpPrivateData::Poseidon2Perm(poseidon2_data)
        );
    }

    #[test]
    fn test_execution_context_get_private_data_missing() {
        // Create an execution context without private data
        let private_data = vec![];
        let mut witness = vec![];
        let configs = HashMap::new();
        let op_id = NonPrimitiveOpId(0);
        let mut op_states = BTreeMap::new();

        // Create execution context
        let ctx: ExecutionContext<'_, F> =
            ExecutionContext::new(&mut witness, &private_data, &configs, op_id, &mut op_states);

        // Attempt to access private data that wasn't provided
        let result = ctx.get_private_data();

        // Missing private data should be reported as an error
        assert!(result.is_err());
        match result {
            Err(CircuitError::NonPrimitiveOpMissingPrivateData { operation_index }) => {
                assert_eq!(operation_index, op_id);
            }
            _ => panic!("Expected NonPrimitiveOpMissingPrivateData error"),
        }
    }

    #[test]
    fn test_execution_context_get_config() {
        // Create a configuration map for operation parameters
        let mut configs = HashMap::new();
        let op_type = NonPrimitiveOpType::Poseidon2Perm(Poseidon2Config::BabyBearD4Width16);
        configs.insert(op_type, NonPrimitiveOpConfig::None);

        // Create execution context with configurations
        let mut witness = vec![];
        let private_data = vec![];
        let op_id = NonPrimitiveOpId(0);
        let mut op_states = BTreeMap::new();
        let ctx: ExecutionContext<'_, F> =
            ExecutionContext::new(&mut witness, &private_data, &configs, op_id, &mut op_states);

        // Operations can query their configuration at runtime
        let result = ctx.get_config(&op_type);

        // Verify configuration lookup succeeded
        assert_eq!(*result.unwrap(), NonPrimitiveOpConfig::None);
    }

    #[test]
    fn test_execution_context_get_config_missing() {
        // Create an empty configuration map
        let configs = HashMap::new();
        let mut witness = vec![];
        let private_data = vec![];
        let op_id = NonPrimitiveOpId(0);
        let mut op_states = BTreeMap::new();

        // Create execution context
        let ctx: ExecutionContext<'_, F> =
            ExecutionContext::new(&mut witness, &private_data, &configs, op_id, &mut op_states);

        // Attempt to access a configuration that wasn't registered
        let op_type = NonPrimitiveOpType::Poseidon2Perm(Poseidon2Config::BabyBearD4Width16);
        let result = ctx.get_config(&op_type);

        // Missing configurations indicate setup errors
        assert!(result.is_err());
        match result {
            Err(CircuitError::InvalidNonPrimitiveOpConfiguration { op }) => {
                assert_eq!(op, op_type);
            }
            _ => panic!("Expected InvalidNonPrimitiveOpConfiguration error"),
        }
    }

    #[test]
    fn test_execution_context_operation_id() {
        // Create execution context with a specific operation identifier
        let mut witness = vec![];
        let private_data = vec![];
        let configs = HashMap::new();
        let expected_id = NonPrimitiveOpId(42);
        let mut op_states = BTreeMap::new();
        let ctx: ExecutionContext<'_, F> = ExecutionContext::new(
            &mut witness,
            &private_data,
            &configs,
            expected_id,
            &mut op_states,
        );

        // Retrieve the operation ID from the context
        let retrieved_id = ctx.operation_id();

        // Verify the ID is correctly preserved
        assert_eq!(retrieved_id, expected_id);
    }

    /// Test state type for verifying generic state management.
    #[derive(Debug, Default)]
    struct TestOpState {
        value: Option<u64>,
    }

    impl OpExecutionState for TestOpState {
        fn as_any(&self) -> &dyn core::any::Any {
            self
        }
        fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
            self
        }
    }

    #[test]
    fn test_execution_context_op_state() {
        // Test the generic operation state accessors
        let mut witness: Vec<Option<F>> = vec![];
        let private_data = vec![];
        let configs = HashMap::new();
        let op_id = NonPrimitiveOpId(0);
        let mut op_states = BTreeMap::new();

        let mut ctx =
            ExecutionContext::new(&mut witness, &private_data, &configs, op_id, &mut op_states);

        // Initially, no state should be present
        assert!(
            ctx.get_op_state::<TestOpState>(&NonPrimitiveOpType::Poseidon2Perm(
                Poseidon2Config::BabyBearD4Width16,
            ))
            .is_none()
        );

        // Get or create state (should create default)
        let state = ctx.get_op_state_mut::<TestOpState>(&NonPrimitiveOpType::Poseidon2Perm(
            Poseidon2Config::BabyBearD4Width16,
        ));
        assert!(state.value.is_none());

        // Modify the state
        state.value = Some(42);

        // Verify the state was stored and can be retrieved
        let state_ref = ctx
            .get_op_state::<TestOpState>(&NonPrimitiveOpType::Poseidon2Perm(
                Poseidon2Config::BabyBearD4Width16,
            ))
            .unwrap();
        assert_eq!(state_ref.value, Some(42));
    }
}
