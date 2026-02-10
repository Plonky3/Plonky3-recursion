use alloc::vec::Vec;

use crate::CircuitError;
use crate::op::Op;
use crate::types::WitnessId;

/// Constant values table.
///
/// Stores all compile-time known constant values used in the circuit.
/// Each constant binds to a specific witness ID.
/// Both prover and verifier know these values in advance.
#[derive(Debug, Clone)]
pub struct ConstTrace<F> {
    /// Witness IDs that each constant binds to.
    ///
    /// Maps each constant to its location in the witness table.
    pub index: Vec<WitnessId>,
    /// Constant field element values.
    pub values: Vec<F>,
}

/// Builder for generating constant traces.
pub struct ConstTraceBuilder<'a, F> {
    primitive_ops: &'a [Op<F>],
}

impl<'a, F: Clone> ConstTraceBuilder<'a, F> {
    /// Creates a new constant trace builder.
    pub const fn new(primitive_ops: &'a [Op<F>]) -> Self {
        Self { primitive_ops }
    }

    /// Builds the constant trace from circuit operations.
    pub fn build(self) -> Result<ConstTrace<F>, CircuitError> {
        let estimated_len = self.primitive_ops.len();
        let mut index = Vec::with_capacity(estimated_len);
        let mut values = Vec::with_capacity(estimated_len);

        for prim in self.primitive_ops {
            if let Op::Const { out, val } = prim {
                index.push(*out);
                values.push(val.clone());
            }
        }

        Ok(ConstTrace { index, values })
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;

    type F = BabyBear;

    #[test]
    fn test_single_constant() {
        // Create a single constant operation that loads a value into witness
        let val = F::from_u64(42);
        let out = WitnessId(0);

        let ops = vec![Op::Const { out, val }];

        // Build the trace using the builder pattern
        let builder = ConstTraceBuilder::new(&ops);
        let trace = builder.build().expect("Failed to build trace");

        // Verify the trace contains exactly one constant
        assert_eq!(trace.index.len(), 1, "Should have one constant operation");
        assert_eq!(trace.values.len(), 1, "Should have one constant value");

        // Verify the constant is correctly recorded
        assert_eq!(trace.index[0], out);
        assert_eq!(trace.values[0], val);
    }

    #[test]
    fn test_multiple_constants() {
        // Create multiple constant operations with different values
        let val1 = F::from_u64(10);
        let out1 = WitnessId(0);

        let val2 = F::from_u64(20);
        let out2 = WitnessId(1);

        let val3 = F::from_u64(30);
        let out3 = WitnessId(2);

        let ops = vec![
            Op::Const {
                out: out1,
                val: val1,
            },
            Op::Const {
                out: out2,
                val: val2,
            },
            Op::Const {
                out: out3,
                val: val3,
            },
        ];

        // Build the trace
        let builder = ConstTraceBuilder::new(&ops);
        let trace = builder.build().expect("Failed to build trace");

        // Verify we have exactly three constants
        assert_eq!(
            trace.index.len(),
            3,
            "Should have three constant operations"
        );
        assert_eq!(trace.values.len(), 3, "Should have three constant values");

        // Verify first constant
        assert_eq!(trace.index[0], out1);
        assert_eq!(trace.values[0], val1);

        // Verify second constant
        assert_eq!(trace.index[1], out2);
        assert_eq!(trace.values[1], val2);

        // Verify third constant
        assert_eq!(trace.index[2], out3);
        assert_eq!(trace.values[2], val3);
    }

    #[test]
    fn test_empty_operations() {
        // Provide an empty operations list
        let ops: Vec<Op<F>> = vec![];

        // Build the trace
        let builder = ConstTraceBuilder::new(&ops);
        let trace = builder.build().expect("Failed to build trace");

        // Verify the trace is empty
        assert_eq!(trace.index.len(), 0, "Should have no constants");
        assert_eq!(trace.values.len(), 0, "Should have no values");
    }
}
