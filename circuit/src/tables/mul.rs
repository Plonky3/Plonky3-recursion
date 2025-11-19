use alloc::vec::Vec;

use p3_field::Field;

use crate::CircuitError;
use crate::op::Op;
use crate::types::WitnessId;

/// Multiplication operation table.
///
/// Records every multiplication operation in the circuit.
/// Each row represents one constraint: lhs * rhs = result.
#[derive(Debug, Clone)]
pub struct MulTrace<F> {
    /// Left operand values
    pub lhs_values: Vec<F>,
    /// Left operand indices (references witness bus)
    pub lhs_index: Vec<WitnessId>,
    /// Right operand values
    pub rhs_values: Vec<F>,
    /// Right operand indices (references witness bus)
    pub rhs_index: Vec<WitnessId>,
    /// Result values
    pub result_values: Vec<F>,
    /// Result indices (references witness bus)
    pub result_index: Vec<WitnessId>,
}

/// Builder for generating multiplication traces.
pub struct MulTraceBuilder<'a, F> {
    primitive_ops: &'a [Op<F>],
    witness: &'a [Option<F>],
}

impl<'a, F: Clone + Field> MulTraceBuilder<'a, F> {
    /// Creates a new multiplication trace builder.
    pub const fn new(primitive_ops: &'a [Op<F>], witness: &'a [Option<F>]) -> Self {
        Self {
            primitive_ops,
            witness,
        }
    }

    /// Builds the multiplication trace from circuit operations.
    pub fn build(self) -> Result<MulTrace<F>, CircuitError> {
        let mut lhs_values = Vec::new();
        let mut lhs_index = Vec::new();
        let mut rhs_values = Vec::new();
        let mut rhs_index = Vec::new();
        let mut result_values = Vec::new();
        let mut result_index = Vec::new();

        for prim in self.primitive_ops {
            if let Op::Mul { a, b, out } = prim {
                let a_val = self.resolve(a)?;
                let b_val = self.resolve(b)?;
                let out_val = self.resolve(out)?;

                lhs_values.push(a_val);
                lhs_index.push(*a);
                rhs_values.push(b_val);
                rhs_index.push(*b);
                result_values.push(out_val);
                result_index.push(*out);
            }
        }

        // If trace is empty, add a dummy row: 0 * 0 = 0
        if lhs_values.is_empty() {
            lhs_values.push(F::ZERO);
            lhs_index.push(WitnessId(0));
            rhs_values.push(F::ZERO);
            rhs_index.push(WitnessId(0));
            result_values.push(F::ZERO);
            result_index.push(WitnessId(0));
        }

        Ok(MulTrace {
            lhs_values,
            lhs_index,
            rhs_values,
            rhs_index,
            result_values,
            result_index,
        })
    }

    /// Resolves a single witness value safely.
    #[inline]
    fn resolve(&self, id: &WitnessId) -> Result<F, CircuitError> {
        self.witness
            .get(id.0 as usize)
            .and_then(|opt| opt.as_ref())
            .cloned()
            .ok_or(CircuitError::WitnessNotSet { witness_id: *id })
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
    fn test_single_multiplication() {
        // Create a simple witness containing three values
        //
        // Index 0: value 5 (left operand)
        // Index 1: value 3 (right operand)
        // Index 2: value 15 (result of 5 * 3)
        let lhs = F::from_u64(5);
        let rhs = F::from_u64(3);
        let out = F::from_u64(15);
        let witness = vec![
            Some(lhs), // WitnessId(0)
            Some(rhs), // WitnessId(1)
            Some(out), // WitnessId(2)
        ];

        // Define a single multiplication operation: witness[0] * witness[1] = witness[2]
        //
        // This represents the constraint: 5 * 3 = 15
        let ops = vec![Op::Mul {
            a: WitnessId(0),
            b: WitnessId(1),
            out: WitnessId(2),
        }];

        // Build the trace using the builder pattern
        let builder = MulTraceBuilder::new(&ops, &witness);
        let trace = builder.build().expect("Failed to build trace");

        // Verify the trace contains exactly one row
        assert_eq!(
            trace.lhs_values.len(),
            1,
            "Should have one multiplication operation"
        );

        // Verify left operand (lhs) is correctly recorded
        assert_eq!(trace.lhs_values[0], lhs);
        assert_eq!(trace.lhs_index[0], WitnessId(0));

        // Verify right operand (rhs) is correctly recorded
        assert_eq!(trace.rhs_values[0], rhs);
        assert_eq!(trace.rhs_index[0], WitnessId(1));

        // Verify result is correctly recorded
        assert_eq!(trace.result_values[0], out);
        assert_eq!(trace.result_index[0], WitnessId(2));
    }

    #[test]
    fn test_multiple_multiplications() {
        // Create witness with values for three separate multiplications
        //
        // We have 9 witness slots total (3 multiplications × 3 values each)
        let lhs1 = F::from_u64(10);
        let rhs1 = F::from_u64(20);
        let out1 = F::from_u64(200);

        let lhs2 = F::from_u64(7);
        let rhs2 = F::from_u64(13);
        let out2 = F::from_u64(91);

        let lhs3 = F::from_u64(3);
        let rhs3 = F::from_u64(4);
        let out3 = F::from_u64(12);

        let witness = vec![
            Some(lhs1), // First multiplication: lhs
            Some(rhs1), // First multiplication: rhs
            Some(out1), // First multiplication: result
            Some(lhs2), // Second multiplication: lhs
            Some(rhs2), // Second multiplication: rhs
            Some(out2), // Second multiplication: result
            Some(lhs3), // Third multiplication: lhs
            Some(rhs3), // Third multiplication: rhs
            Some(out3), // Third multiplication: result
        ];

        // Define three multiplication operations
        let lhs1_witness_id = WitnessId(0);
        let rhs1_witness_id = WitnessId(1);
        let out1_witness_id = WitnessId(2);
        let lhs2_witness_id = WitnessId(3);
        let rhs2_witness_id = WitnessId(4);
        let out2_witness_id = WitnessId(5);
        let lhs3_witness_id = WitnessId(6);
        let rhs3_witness_id = WitnessId(7);
        let out3_witness_id = WitnessId(8);

        let ops = vec![
            Op::Mul {
                a: lhs1_witness_id,
                b: rhs1_witness_id,
                out: out1_witness_id,
            },
            Op::Mul {
                a: lhs2_witness_id,
                b: rhs2_witness_id,
                out: out2_witness_id,
            },
            Op::Mul {
                a: lhs3_witness_id,
                b: rhs3_witness_id,
                out: out3_witness_id,
            },
        ];

        // Build the trace
        let builder = MulTraceBuilder::new(&ops, &witness);
        let trace = builder.build().expect("Failed to build trace");

        // Verify we have exactly three rows
        assert_eq!(
            trace.lhs_values.len(),
            3,
            "Should have three multiplication operations"
        );

        // Verify first multiplication
        assert_eq!(trace.lhs_values[0], lhs1);
        assert_eq!(trace.lhs_index[0], lhs1_witness_id);
        assert_eq!(trace.rhs_values[0], rhs1);
        assert_eq!(trace.rhs_index[0], rhs1_witness_id);
        assert_eq!(trace.result_values[0], out1);
        assert_eq!(trace.result_index[0], out1_witness_id);

        // Verify second multiplication
        assert_eq!(trace.lhs_values[1], lhs2);
        assert_eq!(trace.lhs_index[1], lhs2_witness_id);
        assert_eq!(trace.rhs_values[1], rhs2);
        assert_eq!(trace.rhs_index[1], rhs2_witness_id);
        assert_eq!(trace.result_values[1], out2);
        assert_eq!(trace.result_index[1], out2_witness_id);

        // Verify third multiplication
        assert_eq!(trace.lhs_values[2], lhs3);
        assert_eq!(trace.lhs_index[2], lhs3_witness_id);
        assert_eq!(trace.rhs_values[2], rhs3);
        assert_eq!(trace.rhs_index[2], rhs3_witness_id);
        assert_eq!(trace.result_values[2], out3);
        assert_eq!(trace.result_index[2], out3_witness_id);
    }

    #[test]
    fn test_empty_operations_creates_dummy_row() {
        // Create a witness with at least one entry (for the dummy row to reference)
        let witness = vec![Some(F::ZERO)];

        // Provide an empty operations list (no multiplications to process)
        let ops: Vec<Op<F>> = vec![];

        // Build the trace
        let builder = MulTraceBuilder::new(&ops, &witness);
        let trace = builder.build().expect("Failed to build trace");

        // Verify exactly one dummy row exists
        assert_eq!(trace.lhs_values.len(), 1, "Should have one dummy row");

        // Verify the dummy row contains: 0 * 0 = 0
        assert_eq!(trace.lhs_values[0], F::ZERO);
        assert_eq!(trace.lhs_index[0], WitnessId(0));
        assert_eq!(trace.rhs_values[0], F::ZERO);
        assert_eq!(trace.rhs_index[0], WitnessId(0));
        assert_eq!(trace.result_values[0], F::ZERO);
        assert_eq!(trace.result_index[0], WitnessId(0));
    }

    #[test]
    fn test_mixed_operations_filters_correctly() {
        // Create witness for one multiplication and one addition
        let lhs = F::from_u64(4);
        let rhs = F::from_u64(6);
        let mul_out = F::from_u64(24);
        let add_out = F::from_u64(10);

        let witness = vec![
            Some(lhs),     // WitnessId(0)
            Some(rhs),     // WitnessId(1)
            Some(mul_out), // WitnessId(2)
            Some(add_out), // WitnessId(3) for Add
        ];

        // Create a mixed list of operations
        //
        // Only the Mul operation should be processed; Add should be ignored
        let ops = vec![
            Op::Add {
                a: WitnessId(0),
                b: WitnessId(1),
                out: WitnessId(3),
            }, // Should be ignored
            Op::Mul {
                a: WitnessId(0),
                b: WitnessId(1),
                out: WitnessId(2),
            }, // Should be processed
            Op::Add {
                a: WitnessId(1),
                b: WitnessId(2),
                out: WitnessId(3),
            }, // Should be ignored
        ];

        // Build the trace
        let builder = MulTraceBuilder::new(&ops, &witness);
        let trace = builder.build().expect("Failed to build trace");

        // Verify only one row exists (only one Mul operation)
        assert_eq!(
            trace.lhs_values.len(),
            1,
            "Should process only the Mul operation"
        );

        // Verify the single multiplication row is correct (4 * 6 = 24)
        assert_eq!(trace.lhs_values[0], lhs);
        assert_eq!(trace.rhs_values[0], rhs);
        assert_eq!(trace.result_values[0], mul_out);
    }

    #[test]
    fn test_missing_witness_lhs_returns_error() {
        // Create witness where the left operand (index 0) is missing
        let rhs = F::from_u64(5);
        let out = F::from_u64(25);

        let witness = vec![
            None,      // WitnessId(0) - NOT SET
            Some(rhs), // WitnessId(1)
            Some(out), // WitnessId(2)
        ];

        // Define a multiplication that references the missing witness
        let ops = vec![Op::Mul {
            a: WitnessId(0), // References the None value
            b: WitnessId(1),
            out: WitnessId(2),
        }];

        // Attempt to build the trace
        let builder = MulTraceBuilder::new(&ops, &witness);
        let result = builder.build();

        // Verify the operation fails with the correct error
        assert!(result.is_err(), "Should fail when lhs witness is not set");
        match result {
            Err(CircuitError::WitnessNotSet { witness_id }) => {
                assert_eq!(
                    witness_id,
                    WitnessId(0),
                    "Error should reference WitnessId(0)"
                );
            }
            _ => panic!("Expected WitnessNotSet error"),
        }
    }

    #[test]
    fn test_missing_witness_rhs_returns_error() {
        // Create witness where the right operand (index 1) is missing
        let lhs = F::from_u64(5);
        let out = F::from_u64(25);

        let witness = vec![
            Some(lhs), // WitnessId(0)
            None,      // WitnessId(1) - NOT SET
            Some(out), // WitnessId(2)
        ];

        // Define a multiplication that references the missing witness
        let ops = vec![Op::Mul {
            a: WitnessId(0),
            b: WitnessId(1), // References the None value
            out: WitnessId(2),
        }];

        // Attempt to build the trace
        let builder = MulTraceBuilder::new(&ops, &witness);
        let result = builder.build();

        // Verify the operation fails with the correct error
        assert!(result.is_err(), "Should fail when rhs witness is not set");
        match result {
            Err(CircuitError::WitnessNotSet { witness_id }) => {
                assert_eq!(
                    witness_id,
                    WitnessId(1),
                    "Error should reference WitnessId(1)"
                );
            }
            _ => panic!("Expected WitnessNotSet error"),
        }
    }

    #[test]
    fn test_missing_witness_result_returns_error() {
        // Create witness where the result (index 2) is missing
        let lhs = F::from_u64(5);
        let rhs = F::from_u64(3);

        let witness = vec![
            Some(lhs), // WitnessId(0)
            Some(rhs), // WitnessId(1)
            None,      // WitnessId(2) - NOT SET
        ];

        // Define a multiplication that references the missing result
        let ops = vec![Op::Mul {
            a: WitnessId(0),
            b: WitnessId(1),
            out: WitnessId(2), // References the None value
        }];

        // Attempt to build the trace
        let builder = MulTraceBuilder::new(&ops, &witness);
        let result = builder.build();

        // Verify the operation fails with the correct error
        assert!(
            result.is_err(),
            "Should fail when result witness is not set"
        );
        match result {
            Err(CircuitError::WitnessNotSet { witness_id }) => {
                assert_eq!(
                    witness_id,
                    WitnessId(2),
                    "Error should reference WitnessId(2)"
                );
            }
            _ => panic!("Expected WitnessNotSet error"),
        }
    }

    #[test]
    fn test_out_of_bounds_witness_id() {
        // Create a small witness array with only 2 elements
        let lhs = F::from_u64(5);
        let rhs = F::from_u64(3);

        let witness = vec![Some(lhs), Some(rhs)];

        // Attempt to reference WitnessId(5), which doesn't exist
        let ops = vec![Op::Mul {
            a: WitnessId(0),
            b: WitnessId(1),
            out: WitnessId(5), // Out of bounds!
        }];

        // Attempt to build the trace
        let builder = MulTraceBuilder::new(&ops, &witness);
        let result = builder.build();

        // Verify proper error handling
        assert!(
            result.is_err(),
            "Should fail when witness ID is out of bounds"
        );
        match result {
            Err(CircuitError::WitnessNotSet { witness_id }) => {
                assert_eq!(
                    witness_id,
                    WitnessId(5),
                    "Error should reference WitnessId(5)"
                );
            }
            _ => panic!("Expected WitnessNotSet error"),
        }
    }
}
