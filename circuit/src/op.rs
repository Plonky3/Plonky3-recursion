use alloc::boxed::Box;
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::any::Any;
use core::fmt::Debug;
use core::hash::Hash;

use hashbrown::HashMap;
use p3_field::{Field, PrimeCharacteristicRing};
use serde::{Deserialize, Serialize};
use strum_macros::EnumCount;

// Re-export Poseidon2 config types from their canonical location
pub use crate::ops::poseidon2_perm::{Poseidon2Config, Poseidon2PermExec, Poseidon2PermExecBase};
use crate::types::{NonPrimitiveOpId, WitnessId};
use crate::{CircuitError, PreprocessedColumns};

/// ALU operation kinds for the unified arithmetic table.
///
/// This enum defines the different arithmetic operations that can be performed
/// in a single ALU row, selected by preprocessed selectors.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AluOpKind {
    /// Addition: out = a + b
    Add,
    /// Multiplication: out = a * b
    Mul,
    /// Boolean check: a * (a - 1) = 0, out = a
    BoolCheck,
    /// Fused multiply-add: out = a * b + c
    MulAdd,
}

/// Circuit operations.
///
/// Operations are distinguised as primitive, non-primitive, and hints:
///
/// - Primitive ops (`Const`, `Public`, `Alu`) are the basic arithmetic building blocks
/// - Non-primitive ops (`NonPrimitiveOpWithExecutor`) are table-backed plugin operations
/// - Hint ops (`Hint`) are non-deterministic witness assignments that do NOT have tables,
///   AIR, or traces; they are purely a convenience for filling witnesses.
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

    /// Unified ALU operation supporting multiple arithmetic operations.
    ///
    /// The `kind` field determines the operation:
    /// - `Add`: out = a + b
    /// - `Mul`: out = a * b
    /// - `BoolCheck`: a * (a - 1) = 0, out = a
    /// - `MulAdd`: out = a * b + c
    Alu {
        kind: AluOpKind,
        a: WitnessId,
        b: WitnessId,
        /// Third operand, only used for MulAdd
        c: Option<WitnessId>,
        out: WitnessId,
        /// Intermediate output for MulAdd: stores a * b when fused from separate mul + add.
        /// The runner sets this witness value so dependent operations still work.
        intermediate_out: Option<WitnessId>,
    },

    /// Hint operation: non-deterministically fills witness values via a user-provided closure.
    ///
    /// Hints are NOT table-backed:
    /// - they do not have an AIR
    /// - they do not participate in non-primitive traces
    /// - they do not have private data or configs
    ///
    /// They are used for things like bit decompositions and extension-field decompositions.
    Hint {
        /// Input witnesses read by the hint.
        inputs: Vec<WitnessId>,
        /// Output witnesses written by the hint.
        outputs: Vec<WitnessId>,
        /// User-provided executor that implements the hint logic.
        executor: Box<dyn HintExecutor<F>>,
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

impl<F> Op<F> {
    /// Create an addition operation (convenience wrapper for Op::Alu with AluOpKind::Add).
    pub const fn add(a: WitnessId, b: WitnessId, out: WitnessId) -> Self {
        Self::Alu {
            kind: AluOpKind::Add,
            a,
            b,
            c: None,
            out,
            intermediate_out: None,
        }
    }

    /// Create a multiplication operation (convenience wrapper for Op::Alu with AluOpKind::Mul).
    pub const fn mul(a: WitnessId, b: WitnessId, out: WitnessId) -> Self {
        Self::Alu {
            kind: AluOpKind::Mul,
            a,
            b,
            c: None,
            out,
            intermediate_out: None,
        }
    }

    /// Create a fused multiply-add operation: out = a * b + c.
    pub const fn mul_add(a: WitnessId, b: WitnessId, c: WitnessId, out: WitnessId) -> Self {
        Self::Alu {
            kind: AluOpKind::MulAdd,
            a,
            b,
            c: Some(c),
            out,
            intermediate_out: None,
        }
    }

    /// Create a boolean check operation: a * (a - 1) = 0.
    pub const fn bool_check(a: WitnessId, b: WitnessId, out: WitnessId) -> Self {
        Self::Alu {
            kind: AluOpKind::BoolCheck,
            a,
            b,
            c: None,
            out,
            intermediate_out: None,
        }
    }

    /// Check if this is an ALU operation of the given kind.
    pub fn is_alu_kind(&self, kind: AluOpKind) -> bool {
        matches!(self, Self::Alu { kind: k, .. } if *k == kind)
    }

    /// Check if this is an addition operation.
    pub fn is_add(&self) -> bool {
        self.is_alu_kind(AluOpKind::Add)
    }

    /// Check if this is a multiplication operation.
    pub fn is_mul(&self) -> bool {
        self.is_alu_kind(AluOpKind::Mul)
    }

    /// Rewrite witness IDs in place using the given map (follows chains to canonical ID).
    /// Used by the optimizer to apply ALU dedup without re-boxing non-primitive executors.
    pub fn apply_witness_rewrite(&mut self, rewrite: &HashMap<WitnessId, WitnessId>) {
        if rewrite.is_empty() {
            return;
        }
        let resolve = |id: WitnessId| {
            let mut cur = id;
            while let Some(&next) = rewrite.get(&cur) {
                cur = next;
            }
            cur
        };
        match self {
            Self::Const { out, .. } => *out = resolve(*out),
            Self::Public { out, .. } => *out = resolve(*out),
            Self::Alu {
                a,
                b,
                c,
                out,
                intermediate_out,
                ..
            } => {
                *a = resolve(*a);
                *b = resolve(*b);
                *c = c.map(resolve);
                *out = resolve(*out);
                *intermediate_out = intermediate_out.map(resolve);
            }
            Self::Hint {
                inputs, outputs, ..
            } => {
                for w in inputs.iter_mut() {
                    *w = resolve(*w);
                }
                for w in outputs.iter_mut() {
                    *w = resolve(*w);
                }
            }
            Self::NonPrimitiveOpWithExecutor {
                inputs, outputs, ..
            } => {
                for g in inputs.iter_mut() {
                    for w in g.iter_mut() {
                        *w = resolve(*w);
                    }
                }
                for g in outputs.iter_mut() {
                    for w in g.iter_mut() {
                        *w = resolve(*w);
                    }
                }
            }
        }
    }
}

#[derive(EnumCount, Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PrimitiveOpType {
    Const = 0,
    Public = 1,
    /// Unified ALU table (combines Add, Mul, BoolCheck, MulAdd)
    Alu = 2,
}

#[allow(clippy::fallible_impl_from)]
impl From<usize> for PrimitiveOpType {
    fn from(value: usize) -> Self {
        match value {
            0 => Self::Const,
            1 => Self::Public,
            2 => Self::Alu,
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
            Self::Alu {
                kind,
                a,
                b,
                c,
                out,
                intermediate_out,
            } => Self::Alu {
                kind: *kind,
                a: *a,
                b: *b,
                c: *c,
                out: *out,
                intermediate_out: *intermediate_out,
            },
            Self::Hint {
                inputs,
                outputs,
                executor,
            } => Self::Hint {
                inputs: inputs.clone(),
                outputs: outputs.clone(),
                executor: executor.boxed(),
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
                Self::Alu {
                    kind: k1,
                    a: a1,
                    b: b1,
                    c: c1,
                    out: o1,
                    intermediate_out: io1,
                },
                Self::Alu {
                    kind: k2,
                    a: a2,
                    b: b2,
                    c: c2,
                    out: o2,
                    intermediate_out: io2,
                },
            ) => k1 == k2 && a1 == a2 && b1 == b2 && c1 == c2 && o1 == o2 && io1 == io2,
            (
                Self::Hint {
                    inputs: i1,
                    outputs: o1,
                    executor: _,
                },
                Self::Hint {
                    inputs: i2,
                    outputs: o2,
                    executor: _,
                },
            ) => {
                // Compare by value layout only; executors are opaque closures.
                i1 == i2 && o1 == o2
            }
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

/// Opaque, string-based identifier for non-primitive operation types.
///
/// Each unique (operation-kind, configuration) pair gets its own `NpoTypeId`.
/// For example, Poseidon2 with BabyBear D=4 W=16 is `"poseidon2_perm/baby_bear_d4_w16"`.
#[derive(Clone, PartialEq, Eq, Hash, Ord, PartialOrd, Serialize, Deserialize)]
pub struct NpoTypeId(String);

impl NpoTypeId {
    /// Create a new NPO type identifier.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// The string key.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Convenience: Poseidon2 permutation type ID for a given config.
    pub fn poseidon2_perm(config: Poseidon2Config) -> Self {
        Self::new(alloc::format!("poseidon2_perm/{}", config.variant_name()))
    }

    /// Convenience: Unconstrained (hint) operation type ID.
    ///
    /// This is kept only for profiling / debugging purposes; Unconstrained is
    /// no longer a table-backed non-primitive op and is executed via `Op::Hint`.
    pub fn unconstrained() -> Self {
        Self::new("unconstrained")
    }
}

impl Debug for NpoTypeId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NpoTypeId({})", self.0)
    }
}

impl core::fmt::Display for NpoTypeId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Preprocessed data for non-primitive tables, keyed by operation type.
pub type NonPrimitivePreprocessedMap<F> = HashMap<NpoTypeId, Vec<F>>;

/// Type-erased, plugin-owned configuration for a non-primitive operation.
///
/// Each NPO plugin both produces and consumes its own typed data through
/// this wrapper. The core infrastructure never inspects the contents.
pub struct NpoConfig(pub Box<dyn Any + Send + Sync>);

/// Backward-compatible alias during migration.
pub type NonPrimitiveOpConfig = NpoConfig;

impl NpoConfig {
    /// Wrap a concrete config value.
    pub fn new<T: Any + Send + Sync>(val: T) -> Self {
        Self(Box::new(val))
    }

    /// Downcast to a concrete config type.
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        self.0.downcast_ref::<T>()
    }
}

impl Clone for NpoConfig {
    fn clone(&self) -> Self {
        panic!("NpoConfig cannot be cloned generically; plugins must re-register their config")
    }
}

impl Debug for NpoConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NpoConfig(<type-erased>)")
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
/// Type-erased private auxiliary data for non-primitive operations.
///
/// This data is NOT part of the witness table but provides additional
/// parameters needed to fully specify complex operations. Private data:
/// - Is set during circuit execution via `NonPrimitiveOpId`
/// - Contains sensitive information like cryptographic witnesses
/// - Is used by AIR tables to generate the appropriate constraints
///
/// Each NPO plugin both produces and consumes its own typed data through
/// this wrapper. The core infrastructure never inspects the contents.
pub struct NpoPrivateData(pub Box<dyn Any + Send + Sync>);

/// Backward-compatible alias during migration.
pub type NonPrimitiveOpPrivateData = NpoPrivateData;

impl NpoPrivateData {
    /// Wrap concrete private data.
    pub fn new<T: Any + Send + Sync>(val: T) -> Self {
        Self(Box::new(val))
    }

    /// Downcast to a concrete private data type.
    pub fn downcast_ref<T: Any>(&self) -> Option<&T> {
        self.0.downcast_ref::<T>()
    }
}

impl Debug for NpoPrivateData {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "NpoPrivateData(<type-erased>)")
    }
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
pub type OpStateMap = BTreeMap<NpoTypeId, Box<dyn OpExecutionState>>;

/// Execution context providing operations access to witness table, private data, and configs
///
/// This context is passed to operation executors to give them access to all necessary
/// runtime state without exposing internal implementation details.
pub struct ExecutionContext<'a, F> {
    /// Mutable reference to witness table for reading/writing values
    witness: &'a mut [Option<F>],
    /// Private data map for non-primitive operations
    non_primitive_op_private_data: &'a [Option<NpoPrivateData>],
    /// Operation configurations
    enabled_ops: &'a HashMap<NpoTypeId, NpoConfig>,
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
        non_primitive_op_private_data: &'a [Option<NpoPrivateData>],
        enabled_ops: &'a HashMap<NpoTypeId, NpoConfig>,
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
                return Ok(());
            }
            return Err(CircuitError::WitnessConflict {
                witness_id: widx,
                existing: format!("{existing_value:?}"),
                new: format!("{value:?}"),
                expr_ids: vec![],
            });
        }

        *slot = Some(value);
        Ok(())
    }

    /// Get private data for the current operation
    pub fn get_private_data(&self) -> Result<&NpoPrivateData, CircuitError> {
        self.non_primitive_op_private_data
            .get(self.operation_id.0 as usize)
            .and_then(|opt| opt.as_ref())
            .ok_or(CircuitError::NonPrimitiveOpMissingPrivateData {
                operation_index: self.operation_id,
            })
    }

    /// Get operation configuration by type
    pub fn get_config(&self, op_type: &NpoTypeId) -> Result<&NpoConfig, CircuitError> {
        self.enabled_ops.get(op_type).ok_or_else(|| {
            CircuitError::InvalidNonPrimitiveOpConfiguration {
                op: op_type.clone(),
            }
        })
    }

    /// Get the current operation ID
    pub const fn operation_id(&self) -> NonPrimitiveOpId {
        self.operation_id
    }

    /// Get operation-specific state for reading.
    ///
    /// Returns `None` if no state has been initialized for this operation type.
    pub fn get_op_state<T: OpExecutionState + 'static>(&self, op_type: &NpoTypeId) -> Option<&T> {
        self.op_states
            .get(op_type)
            .and_then(|state| state.as_any().downcast_ref::<T>())
    }

    /// Get operation-specific state for mutation, creating default if not present.
    ///
    /// This is the primary way executors should access their state.
    pub fn get_op_state_mut<T: OpExecutionState + Default + 'static>(
        &mut self,
        op_type: &NpoTypeId,
    ) -> &mut T {
        if !self.op_states.contains_key(op_type) {
            self.op_states
                .insert(op_type.clone(), Box::new(T::default()));
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
    fn op_type(&self) -> &NpoTypeId;

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

/// Trait for executable hint operations.
///
/// Hints are non-deterministic witness assignments that do not have associated AIR tables
/// or traces. They operate directly on the witness array.
pub trait HintExecutor<F: Field>: Debug {
    /// Execute the hint.
    ///
    /// - `inputs`: Witness IDs to read from
    /// - `outputs`: Witness IDs to write to
    /// - `witness`: Mutable reference to the witness table
    fn execute(
        &self,
        inputs: &[WitnessId],
        outputs: &[WitnessId],
        witness: &mut [Option<F>],
    ) -> Result<(), CircuitError>;

    /// Clone as trait object.
    fn boxed(&self) -> Box<dyn HintExecutor<F>>;
}

// Implement Clone for Box<dyn HintExecutor<F>>
impl<F: Field> Clone for Box<dyn HintExecutor<F>> {
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

        let alu_op = Op::add(WitnessId(0), WitnessId(1), WitnessId(2));

        // Operations of different variants should never be equal
        assert_ne!(const_op, alu_op);
    }

    #[test]
    fn test_op_partial_eq_same_variant_different_values() {
        // Create two ALU operations with different witness indices
        let alu_op1: Op<F> = Op::add(WitnessId(0), WitnessId(1), WitnessId(2));
        let alu_op2: Op<F> = Op::add(WitnessId(3), WitnessId(4), WitnessId(5));

        // Same variant but different values should not be equal
        assert_ne!(alu_op1, alu_op2);
    }

    #[test]
    fn test_op_partial_eq_alu_add_same_values() {
        // Create two identical ALU addition operations
        let a = WitnessId(0);
        let b = WitnessId(1);
        let out = WitnessId(2);

        let alu_op1: Op<F> = Op::add(a, b, out);
        let alu_op2: Op<F> = Op::add(a, b, out);

        // Identical operations should be equal
        assert_eq!(alu_op1, alu_op2);
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
    fn test_op_partial_eq_alu_mul_different_values() {
        // Create two ALU multiplication operations with different witness indices
        let mul_op1: Op<F> = Op::mul(WitnessId(0), WitnessId(1), WitnessId(2));
        let mul_op2: Op<F> = Op::mul(WitnessId(10), WitnessId(11), WitnessId(12));

        // Different witness indices should not be equal
        assert_ne!(mul_op1, mul_op2);
    }

    #[test]
    fn test_op_partial_eq_alu_mul_same_values() {
        // Create two identical ALU multiplication operations
        let a = WitnessId(7);
        let b = WitnessId(8);
        let out = WitnessId(9);

        let mul_op1: Op<F> = Op::mul(a, b, out);
        let mul_op2: Op<F> = Op::mul(a, b, out);

        // Identical multiplication operations should be equal
        assert_eq!(mul_op1, mul_op2);
    }

    #[test]
    fn test_op_partial_eq_alu_partial_match() {
        // Create two ALU operations where only some fields match
        let alu_op1: Op<F> = Op::add(WitnessId(0), WitnessId(1), WitnessId(2));
        let alu_op2: Op<F> = Op::add(WitnessId(0), WitnessId(1), WitnessId(99)); // Different output

        // Partial match is not enough for equality
        assert_ne!(alu_op1, alu_op2);
    }

    #[test]
    fn test_op_partial_eq_alu_different_kinds() {
        // Create two ALU operations with same operands but different kinds
        let add_op: Op<F> = Op::add(WitnessId(0), WitnessId(1), WitnessId(2));
        let mul_op: Op<F> = Op::mul(WitnessId(0), WitnessId(1), WitnessId(2));

        // Different operation kinds should not be equal
        assert_ne!(add_op, mul_op);
    }

    #[test]
    fn test_op_partial_eq_alu_muladd() {
        // Create two identical MulAdd operations
        let muladd_op1: Op<F> = Op::mul_add(WitnessId(0), WitnessId(1), WitnessId(2), WitnessId(3));
        let muladd_op2: Op<F> = Op::mul_add(WitnessId(0), WitnessId(1), WitnessId(2), WitnessId(3));

        assert_eq!(muladd_op1, muladd_op2);
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
        let poseidon2_data: Poseidon2PermPrivateData<F, 2> = Poseidon2PermPrivateData {
            sibling: [F::ZERO, F::ZERO],
        };
        let private_data = vec![Some(NpoPrivateData::new(poseidon2_data.clone()))];

        let mut witness: Vec<Option<F>> = vec![];
        let configs = HashMap::new();
        let op_id = NonPrimitiveOpId(0);
        let mut op_states = BTreeMap::new();
        let ctx: ExecutionContext<'_, F> =
            ExecutionContext::new(&mut witness, &private_data, &configs, op_id, &mut op_states);

        let result = ctx.get_private_data();
        assert!(result.is_ok());
        let downcast = result
            .unwrap()
            .downcast_ref::<Poseidon2PermPrivateData<F, 2>>()
            .unwrap();
        assert_eq!(*downcast, poseidon2_data);
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
        let mut configs = HashMap::new();
        let op_type = NpoTypeId::poseidon2_perm(Poseidon2Config::BabyBearD4Width16);
        configs.insert(op_type.clone(), NpoConfig::new(42u32));

        let mut witness = vec![];
        let private_data = vec![];
        let op_id = NonPrimitiveOpId(0);
        let mut op_states = BTreeMap::new();
        let ctx: ExecutionContext<'_, F> =
            ExecutionContext::new(&mut witness, &private_data, &configs, op_id, &mut op_states);

        let result = ctx.get_config(&op_type);
        assert!(result.is_ok());
    }

    #[test]
    fn test_execution_context_get_config_missing() {
        let configs = HashMap::new();
        let mut witness = vec![];
        let private_data = vec![];
        let op_id = NonPrimitiveOpId(0);
        let mut op_states = BTreeMap::new();

        let ctx: ExecutionContext<'_, F> =
            ExecutionContext::new(&mut witness, &private_data, &configs, op_id, &mut op_states);

        let op_type = NpoTypeId::poseidon2_perm(Poseidon2Config::BabyBearD4Width16);
        let result = ctx.get_config(&op_type);

        assert!(result.is_err());
        match result {
            Err(CircuitError::InvalidNonPrimitiveOpConfiguration { .. }) => {}
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
        let mut witness: Vec<Option<F>> = vec![];
        let private_data = vec![];
        let configs = HashMap::new();
        let op_id = NonPrimitiveOpId(0);
        let mut op_states = BTreeMap::new();

        let mut ctx =
            ExecutionContext::new(&mut witness, &private_data, &configs, op_id, &mut op_states);

        let key = NpoTypeId::poseidon2_perm(Poseidon2Config::BabyBearD4Width16);

        assert!(ctx.get_op_state::<TestOpState>(&key).is_none());

        let state = ctx.get_op_state_mut::<TestOpState>(&key);
        assert!(state.value.is_none());
        state.value = Some(42);

        let state_ref = ctx.get_op_state::<TestOpState>(&key).unwrap();
        assert_eq!(state_ref.value, Some(42));
    }
}
