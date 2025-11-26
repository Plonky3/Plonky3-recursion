//! Module defining hash operations for circuit builder.
//!
//! Provides methods for absorbing and squeezing elements using a sponge
//! construction within the circuit.

use alloc::boxed::Box;
use alloc::vec;
use alloc::vec::Vec;
use core::hash::Hash;

use p3_field::{ExtensionField, Field, PrimeCharacteristicRing};
use p3_symmetric::CryptographicPermutation;

use crate::CircuitError;
use crate::builder::{CircuitBuilder, CircuitBuilderError};
use crate::op::{
    ExecutionContext, HashSqueezeHint, NonPrimitiveExecutor, NonPrimitiveOpConfig,
    NonPrimitiveOpType,
};
use crate::types::{ExprId, WitnessId};

/// Configuration parameters for hash operations.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct HashConfig {
    /// Rate (number of elements absorbed/squeezed per operation)
    pub rate: usize,
}

/// Hash operations trait for `CircuitBuilder`.
pub trait HashOps<F: Clone + PrimeCharacteristicRing + Eq + Hash> {
    /// Consumes all buffered inputs and squeeze `RATE` field elements from the sponge state, creating outputs.
    /// If `reset` is set to `true`, the sponge state is reset before absorbing inputs.
    fn add_hash_squeeze<BF, P, const WIDTH: usize>(
        &mut self,
        inputs: &[ExprId],
        permutation: P,
        reset: bool,
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        BF: Field,
        F: ExtensionField<BF>,
        [BF; WIDTH]: Default,
        P: CryptographicPermutation<[BF; WIDTH]> + alloc::fmt::Debug + 'static;
}

impl<F> HashOps<F> for CircuitBuilder<F>
where
    F: Clone + PrimeCharacteristicRing + Eq + Hash + 'static,
{
    fn add_hash_squeeze<BF, P, const WIDTH: usize>(
        &mut self,
        inputs: &[ExprId],
        permutation: P,
        reset: bool,
    ) -> Result<Vec<ExprId>, CircuitBuilderError>
    where
        BF: Field,
        F: ExtensionField<BF>,
        [BF; WIDTH]: Default,
        P: CryptographicPermutation<[BF; WIDTH]> + alloc::fmt::Debug + 'static,
    {
        let hash_config = if let Some(config) = self
            .config()
            .get_op_config(&NonPrimitiveOpType::HashSqueeze { reset })
        {
            if let NonPrimitiveOpConfig::HashConfig(hash_config) = config {
                hash_config
            } else {
                return Err(CircuitBuilderError::InvalidNonPrimitiveOpConfiguration {
                    op: NonPrimitiveOpType::HashSqueeze { reset },
                });
            }
        } else {
            return Err(CircuitBuilderError::OpNotAllowed {
                op: NonPrimitiveOpType::HashSqueeze { reset },
            });
        };

        let filler = HashSqueezeHint::new(inputs, hash_config.rate, permutation, reset);
        let outputs = self.alloc_witness_hints(filler, "hash squeeze");

        let _ = self.push_non_primitive_op(
            NonPrimitiveOpType::HashSqueeze { reset },
            vec![inputs.to_vec(), outputs.clone()],
            "hash squeeze",
        );

        Ok(outputs)
    }
}

#[cfg(test)]
mod tests {
    use p3_baby_bear::{BabyBear, default_babybear_poseidon2_16};
    use p3_field::PrimeCharacteristicRing;
    use p3_symmetric::{CryptographicHasher, PaddingFreeSponge};

    use super::*;
    use crate::tables::{Poseidon2Params, generate_poseidon2_trace};

    struct DummyParams;

    impl Poseidon2Params for DummyParams {
        const D: usize = 4;
        const WIDTH: usize = 16;
        const RATE_EXT: usize = 2;
        const CAPACITY_EXT: usize = 2;
        const SBOX_DEGREE: u64 = 7;
        const SBOX_REGISTERS: usize = 1;
        const HALF_FULL_ROUNDS: usize = 4;
        const PARTIAL_ROUNDS: usize = 13;
    }

    #[test]
    fn test_hash_squeeze() {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        builder.enable_hash_squeeze(
            &HashConfig { rate: 8 },
            generate_poseidon2_trace::<BabyBear, DummyParams>,
        );
        let input = builder.add_const(BabyBear::ONE);
        let permutation = default_babybear_poseidon2_16();
        let _ = builder
            .add_hash_squeeze(&[input], permutation.clone(), true)
            .unwrap();

        builder.dump_allocation_log();

        let circuit = builder.build().unwrap().0;

        let runner = circuit.runner();
        let traces = runner.run().unwrap();

        traces.dump_primitive_traces_log();

        let hasher = PaddingFreeSponge::<_, 16, 8, 8>::new(permutation);
        let expected_value = hasher.hash_item(BabyBear::ONE);

        for (i, &value) in expected_value.iter().enumerate() {
            // The first 2 values are the constants 0, always present, and 1.
            assert_eq!(value, traces.witness_trace.values[2 + i]);
        }
    }

    #[test]
    fn test_hash_squeeze_with_state() {
        let mut builder = CircuitBuilder::<BabyBear>::new();
        builder.enable_hash_squeeze(
            &HashConfig { rate: 8 },
            generate_poseidon2_trace::<BabyBear, DummyParams>,
        );
        let zero = builder.add_const(BabyBear::ZERO);
        let one = builder.add_const(BabyBear::ONE);
        let input = [zero, zero, zero, zero, zero, zero, zero, one];
        let repeated_input = [
            zero, zero, zero, zero, zero, zero, zero, one, zero, zero, zero, zero, zero, zero,
            zero, one,
        ];
        let permutation = default_babybear_poseidon2_16();

        // Compute the digest with a single squeeze
        let _ = builder.add_hash_squeeze(&repeated_input, permutation.clone(), true);

        // Now compute the same output with two calls to squeeze, without reseting the state
        // in the second one.
        let _ = builder
            .add_hash_squeeze(&input, permutation.clone(), true)
            .unwrap();
        // Squeeze again without resetting the state
        let _ = builder.add_hash_squeeze(&input, permutation.clone(), false);

        let circuit = builder.build().unwrap().0;
        let runner = circuit.runner();
        let traces = runner.run().unwrap();

        let hasher = PaddingFreeSponge::<_, 16, 8, 8>::new(permutation);
        let input = [
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ONE,
        ];
        let repeated_input = [
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ONE,
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ZERO,
            BabyBear::ONE,
        ];
        let expected_first_digest = hasher.hash_slice(&input);
        let expected_second_digest = hasher.hash_slice(&repeated_input);

        // Verify first digest
        for (i, &value) in expected_second_digest.iter().enumerate() {
            // The first two witnesses are constants 0 and 1.
            assert_eq!(value, traces.witness_trace.values[2 + i]);
        }

        // Verify second digest
        for (i, &value) in expected_first_digest.iter().enumerate() {
            assert_eq!(value, traces.witness_trace.values[10 + i]);
        }

        // Verify third digest
        for (i, &value) in expected_second_digest.iter().enumerate() {
            assert_eq!(value, traces.witness_trace.values[18 + i]);
        }
    }

    #[test]
    fn test_hash_squeeze_not_enabled() {
        let mut circuit = CircuitBuilder::<BabyBear>::new();
        let input = circuit.add_const(BabyBear::ONE);
        let permutation = default_babybear_poseidon2_16();
        let result = circuit.add_hash_squeeze(&[input], permutation, true);
        assert!(result.is_err());
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
    pub const fn new(reset: bool) -> Self {
        Self {
            op_type: NonPrimitiveOpType::HashSqueeze { reset },
        }
    }
}

impl Default for HashSqueezeExecutor {
    fn default() -> Self {
        Self::new(true)
    }
}

impl<F: Field> NonPrimitiveExecutor<F> for HashSqueezeExecutor {
    fn execute(
        &self,
        _inputs: &[Vec<WitnessId>],
        _outputs: &[Vec<WitnessId>],
        _ctx: &mut ExecutionContext<'_, F>,
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
