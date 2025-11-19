//! Module defining hash operations for circuit builder.
//!
//! Provides methods for absorbing and squeezing elements using a sponge
//! construction within the circuit.

use alloc::boxed::Box;
use alloc::string::ToString;
use alloc::vec::Vec;
use alloc::{format, vec};
use core::hash::Hash;

use p3_field::{Field, PrimeCharacteristicRing};

use crate::CircuitError;
use crate::builder::{CircuitBuilder, CircuitBuilderError};
use crate::op::{ExecutionContext, NonPrimitiveExecutor, NonPrimitiveOpType, WitnessHintsFiller};
use crate::types::{ExprId, NonPrimitiveOpId, WitnessId};

/// Hash operations trait for `CircuitBuilder`.
pub trait HashOps<F: Clone + PrimeCharacteristicRing + Eq + Hash> {
    /// Absorb field elements into the sponge state.
    ///
    /// # Arguments
    ///
    /// * `inputs` - The `ExprId`s to absorb
    /// * `reset` - Whether to reset the sponge state before absorbing
    fn add_hash_absorb(
        &mut self,
        inputs: &[ExprId],
        reset: bool,
    ) -> Result<NonPrimitiveOpId, CircuitBuilderError>;

    /// Squeeze field elements from the sponge state, creating outputs.
    ///
    /// Returns the newly created output `ExprId`s.
    fn add_hash_squeeze(&mut self, count: usize) -> Result<Vec<ExprId>, CircuitBuilderError>;

    /// Add hash squeeze operation with custom hint filler.
    /// This allows providing precomputed values for the squeeze outputs.
    fn add_hash_squeeze_with_filler<W: 'static + WitnessHintsFiller<F>>(
        &mut self,
        filler: W,
        label: &'static str,
    ) -> Result<Vec<ExprId>, CircuitBuilderError>;

    /// Compress two inputs into one output using Poseidon2.
    /// Returns the output `ExprId`s.
    fn add_hash_compress(
        &mut self,
        left: &[ExprId],
        right: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError>;
}

impl<F> HashOps<F> for CircuitBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + Eq + Hash,
{
    fn add_hash_absorb(
        &mut self,
        inputs: &[ExprId],
        reset: bool,
    ) -> Result<NonPrimitiveOpId, CircuitBuilderError> {
        self.ensure_op_enabled(NonPrimitiveOpType::HashAbsorb { reset })?;

        Ok(self.push_non_primitive_op(
            NonPrimitiveOpType::HashAbsorb { reset },
            vec![inputs.to_vec()],
            "HashAbsorb",
        ))
    }

    fn add_hash_squeeze(&mut self, count: usize) -> Result<Vec<ExprId>, CircuitBuilderError> {
        self.ensure_op_enabled(NonPrimitiveOpType::HashSqueeze)?;

        let outputs = self.alloc_witness_hints_default_filler(count, "hash_squeeze_output");

        let _ = self.push_non_primitive_op(
            NonPrimitiveOpType::HashSqueeze,
            vec![outputs.to_vec()],
            "HashSqueeze",
        );

        Ok(outputs)
    }

    fn add_hash_squeeze_with_filler<W: 'static + WitnessHintsFiller<F>>(
        &mut self,
        filler: W,
        label: &'static str,
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
        self.ensure_op_enabled(NonPrimitiveOpType::HashSqueeze)?;

        let outputs = self.alloc_witness_hints(filler, label);

        let _ = self.push_non_primitive_op(
            NonPrimitiveOpType::HashSqueeze,
            vec![outputs.to_vec()],
            "HashSqueeze",
        );

        Ok(outputs)
    }

    fn add_hash_compress(
        &mut self,
        left: &[ExprId],
        right: &[ExprId],
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
        self.ensure_op_enabled(NonPrimitiveOpType::HashCompress)?;

        // Validate input sizes match
        if left.len() != right.len() {
            return Err(CircuitBuilderError::NonPrimitiveOpArity {
                op: "HashCompress",
                expected: format!(
                    "left and right inputs must have same size (got left={}, right={})",
                    left.len(),
                    right.len()
                ),
                got: 0,
            });
        }

        // Allocate output hints
        let outputs = self.alloc_witness_hints_default_filler(left.len(), "hash_compress_output");

        let _ = self.push_non_primitive_op(
            NonPrimitiveOpType::HashCompress,
            vec![left.to_vec(), right.to_vec(), outputs.to_vec()],
            "HashCompress",
        );

        Ok(outputs)
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::op::NonPrimitiveOpConfig;

    #[test]
    fn test_hash_absorb() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        circuit.enable_op(
            NonPrimitiveOpType::HashAbsorb { reset: true },
            NonPrimitiveOpConfig::None,
        );

        let input1 = circuit.add_const(BabyBear::ONE);
        let input2 = circuit.add_const(BabyBear::TWO);

        circuit.add_hash_absorb(&[input1, input2], true).unwrap();
    }

    #[test]
    fn test_hash_squeeze() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        circuit.enable_op(NonPrimitiveOpType::HashSqueeze, NonPrimitiveOpConfig::None);

        let _outputs = circuit.add_hash_squeeze(1).unwrap();
    }

    #[test]
    fn test_hash_absorb_squeeze_sequence() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        circuit.enable_op(
            NonPrimitiveOpType::HashAbsorb { reset: true },
            NonPrimitiveOpConfig::None,
        );
        circuit.enable_op(NonPrimitiveOpType::HashSqueeze, NonPrimitiveOpConfig::None);

        // Absorb
        let input = circuit.add_const(BabyBear::ONE);
        circuit.add_hash_absorb(&[input], true).unwrap();

        // Squeeze
        let _outputs = circuit.add_hash_squeeze(1).unwrap();
    }

    #[test]
    fn test_hash_absorb_not_enabled() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();

        let input = circuit.add_const(BabyBear::ONE);
        let result = circuit.add_hash_absorb(&[input], true);

        assert!(result.is_err());
    }
}

/// Executor for hash absorb operations
///
/// TODO: This is a dummy implementation.
/// Sponge state will be tracked by a dedicated AIR structure in the future.
#[derive(Debug, Clone)]
pub struct HashAbsorbExecutor {
    op_type: NonPrimitiveOpType,
}

impl HashAbsorbExecutor {
    /// Create a new hash absorb executor
    pub fn new(reset: bool) -> Self {
        Self {
            op_type: NonPrimitiveOpType::HashAbsorb { reset },
        }
    }
}

impl<F: Field> NonPrimitiveExecutor<F> for HashAbsorbExecutor {
    fn execute(
        &self,
        _inputs: &[Vec<WitnessId>],
        _outputs: &[Vec<WitnessId>],
        _ctx: &mut ExecutionContext<F>,
    ) -> Result<(), CircuitError> {
        Ok(())
    }

    fn op_type(&self) -> &NonPrimitiveOpType {
        &self.op_type
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}

/// Executor for hash squeeze operations
///
/// TODO: This is a dummy implementation.
/// Sponge state will be tracked by a dedicated AIR structure in the future.
#[derive(Debug, Clone)]
pub struct HashSqueezeExecutor {
    op_type: NonPrimitiveOpType,
}

impl HashSqueezeExecutor {
    /// Create a new hash squeeze executor
    pub fn new() -> Self {
        Self {
            op_type: NonPrimitiveOpType::HashSqueeze,
        }
    }
}

impl Default for HashSqueezeExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field> NonPrimitiveExecutor<F> for HashSqueezeExecutor {
    fn execute(
        &self,
        _inputs: &[Vec<WitnessId>],
        _outputs: &[Vec<WitnessId>],
        _ctx: &mut ExecutionContext<F>,
    ) -> Result<(), CircuitError> {
        Ok(())
    }

    fn op_type(&self) -> &NonPrimitiveOpType {
        &self.op_type
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}

/// Executor for hash compress operations
///
/// Compresses two inputs into one output using Poseidon2.
/// Used for MMCS Merkle tree compression.
#[derive(Debug, Clone)]
pub struct HashCompressExecutor {
    op_type: NonPrimitiveOpType,
}

impl HashCompressExecutor {
    /// Create a new hash compress executor
    pub fn new() -> Self {
        Self {
            op_type: NonPrimitiveOpType::HashCompress,
        }
    }
}

impl Default for HashCompressExecutor {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: Field> NonPrimitiveExecutor<F> for HashCompressExecutor {
    fn execute(
        &self,
        inputs: &[Vec<WitnessId>],
        outputs: &[Vec<WitnessId>],
        _ctx: &mut ExecutionContext<F>,
    ) -> Result<(), CircuitError> {
        // Validate inputs and outputs
        if inputs.len() < 2 {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                op: self.op_type.clone(),
                expected: "at least 2 input vectors (left and right)".to_string(),
                got: inputs.len(),
            });
        }
        if outputs.is_empty() {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                op: self.op_type.clone(),
                expected: "at least 1 output vector".to_string(),
                got: outputs.len(),
            });
        }

        let left_size = inputs[0].len();
        let right_size = inputs[1].len();
        let output_size = outputs[0].len();

        if left_size != right_size || left_size != output_size {
            return Err(CircuitError::IncorrectNonPrimitiveOpPrivateDataSize {
                op: self.op_type.clone(),
                expected: format!(
                    "all vectors should have same size (got left={}, right={}, output={})",
                    left_size, right_size, output_size
                ),
                got: 0,
            });
        }

        Ok(())
    }

    fn op_type(&self) -> &NonPrimitiveOpType {
        &self.op_type
    }

    fn boxed(&self) -> Box<dyn NonPrimitiveExecutor<F>> {
        Box::new(self.clone())
    }
}
