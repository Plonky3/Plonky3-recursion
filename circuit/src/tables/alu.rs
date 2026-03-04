use alloc::vec::Vec;

use p3_field::Field;

use crate::op::AluOpKind;
use crate::types::WitnessId;

/// Record of an ALU operation captured during execution (avoids re-reading witness).
#[derive(Debug, Clone)]
pub struct AluOpRecord<F> {
    pub kind: AluOpKind,
    pub a_index: WitnessId,
    pub b_index: WitnessId,
    pub c_index: WitnessId,
    pub out_index: WitnessId,
    pub a_val: F,
    pub b_val: F,
    pub c_val: F,
    pub out_val: F,
}

/// Unified ALU operation table.
///
/// Records all ALU operations (Add, Mul, BoolCheck, MulAdd) in the circuit.
/// Each row represents one constraint based on the operation kind:
/// - Add: a + b = out
/// - Mul: a * b = out
/// - BoolCheck: a * (a - 1) = 0, out = a
/// - MulAdd: a * b + c = out
#[derive(Debug, Clone)]
pub struct AluTrace<F> {
    /// Operation kind for each row
    pub op_kind: Vec<AluOpKind>,
    /// Operand values (a, b, c, out)
    pub values: Vec<[F; 4]>,
    /// Operand indices (a, b, c, out)
    pub indices: Vec<[WitnessId; 4]>,
}

impl<F> AluTrace<F> {
    /// Returns the number of operations in the trace.
    pub const fn len(&self) -> usize {
        self.values.len()
    }

    /// Returns true if the trace is empty.
    pub const fn is_empty(&self) -> bool {
        self.values.is_empty()
    }

    /// Builds an ALU trace from execution records (no witness lookups).
    pub fn from_records(records: Vec<AluOpRecord<F>>) -> Self
    where
        F: Field,
    {
        let mut op_kind = Vec::with_capacity(records.len());
        let mut values = Vec::with_capacity(records.len());
        let mut indices = Vec::with_capacity(records.len());

        for r in records {
            op_kind.push(r.kind);
            values.push([r.a_val, r.b_val, r.c_val, r.out_val]);
            indices.push([r.a_index, r.b_index, r.c_index, r.out_index]);
        }

        if op_kind.is_empty() {
            op_kind.push(AluOpKind::Add);
            values.push([F::ZERO, F::ZERO, F::ZERO, F::ZERO]);
            indices.push([WitnessId(0), WitnessId(0), WitnessId(0), WitnessId(0)]);
        }

        Self {
            op_kind,
            values,
            indices,
        }
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;

    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;

    use super::*;
    use crate::{CircuitError, Op};

    /// Builder for generating ALU traces.
    pub struct AluTraceBuilder<'a, F> {
        primitive_ops: &'a [Op<F>],
        witness: &'a [Option<F>],
    }

    impl<'a, F: Clone + Field> AluTraceBuilder<'a, F> {
        /// Creates a new ALU trace builder.
        pub const fn new(primitive_ops: &'a [Op<F>], witness: &'a [Option<F>]) -> Self {
            Self {
                primitive_ops,
                witness,
            }
        }

        /// Builds the ALU trace from circuit operations.
        pub fn build(self) -> Result<AluTrace<F>, CircuitError> {
            let mut op_kind = Vec::with_capacity(1 << 15);
            let mut values = Vec::with_capacity(1 << 15);
            let mut indices = Vec::with_capacity(1 << 15);

            for prim in self.primitive_ops {
                if let Op::Alu {
                    kind, a, b, c, out, ..
                } = prim
                {
                    let a_val = self.resolve(a)?;
                    let b_val = self.resolve(b)?;
                    let c_val = if let Some(c_id) = c {
                        self.resolve(c_id)?
                    } else {
                        F::ZERO
                    };
                    let out_val = self.resolve(out)?;

                    op_kind.push(*kind);
                    values.push([a_val, b_val, c_val, out_val]);
                    indices.push([*a, *b, c.unwrap_or(WitnessId(0)), *out]);
                }
            }

            // If trace is empty, add a dummy row: 0 + 0 = 0
            if values.is_empty() {
                op_kind.push(AluOpKind::Add);
                values.push([F::ZERO, F::ZERO, F::ZERO, F::ZERO]);
                indices.push([WitnessId(0), WitnessId(0), WitnessId(0), WitnessId(0)]);
            }

            Ok(AluTrace {
                op_kind,
                values,
                indices,
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

    type F = BabyBear;

    #[test]
    fn test_single_addition() {
        let a = F::from_u64(5);
        let b = F::from_u64(3);
        let out = F::from_u64(8);
        let witness = vec![Some(a), Some(b), Some(out)];

        let ops = vec![Op::add(WitnessId(0), WitnessId(1), WitnessId(2))];

        let builder = AluTraceBuilder::new(&ops, &witness);
        let trace = builder.build().expect("Failed to build trace");

        assert_eq!(trace.len(), 1);
        assert_eq!(trace.op_kind[0], AluOpKind::Add);
        assert_eq!(trace.values[0][0], a);
        assert_eq!(trace.values[0][1], b);
        assert_eq!(trace.values[0][2], F::ZERO);
        assert_eq!(trace.values[0][3], out);
    }

    #[test]
    fn test_single_multiplication() {
        let a = F::from_u64(5);
        let b = F::from_u64(3);
        let out = F::from_u64(15);
        let witness = vec![Some(a), Some(b), Some(out)];

        let ops = vec![Op::mul(WitnessId(0), WitnessId(1), WitnessId(2))];

        let builder = AluTraceBuilder::new(&ops, &witness);
        let trace = builder.build().expect("Failed to build trace");

        assert_eq!(trace.len(), 1);
        assert_eq!(trace.op_kind[0], AluOpKind::Mul);
        assert_eq!(trace.values[0][0], a);
        assert_eq!(trace.values[0][1], b);
        assert_eq!(trace.values[0][2], F::ZERO);
        assert_eq!(trace.values[0][3], out);
    }

    #[test]
    fn test_mul_add() {
        // a * b + c = out => 5 * 3 + 2 = 17
        let a = F::from_u64(5);
        let b = F::from_u64(3);
        let c = F::from_u64(2);
        let out = F::from_u64(17);
        let witness = vec![Some(a), Some(b), Some(c), Some(out)];

        let ops = vec![Op::mul_add(
            WitnessId(0),
            WitnessId(1),
            WitnessId(2),
            WitnessId(3),
        )];

        let builder = AluTraceBuilder::new(&ops, &witness);
        let trace = builder.build().expect("Failed to build trace");

        assert_eq!(trace.len(), 1);
        assert_eq!(trace.op_kind[0], AluOpKind::MulAdd);
        assert_eq!(trace.values[0][0], a);
        assert_eq!(trace.values[0][1], b);
        assert_eq!(trace.values[0][2], c);
        assert_eq!(trace.values[0][3], out);
    }

    #[test]
    fn test_bool_check() {
        // BoolCheck: a * (a - 1) = 0, out = a
        // For a = 1: 1 * 0 = 0 ✓
        let a = F::ONE;
        let witness = vec![Some(a), Some(F::ZERO)]; // a and placeholder for b

        let ops = vec![Op::bool_check(WitnessId(0), WitnessId(1), WitnessId(0))];

        let builder = AluTraceBuilder::new(&ops, &witness);
        let trace = builder.build().expect("Failed to build trace");

        assert_eq!(trace.len(), 1);
        assert_eq!(trace.op_kind[0], AluOpKind::BoolCheck);
        assert_eq!(trace.values[0][0], a);
        assert_eq!(trace.values[0][1], F::ZERO);
        assert_eq!(trace.values[0][2], F::ZERO);
        assert_eq!(trace.values[0][3], a);
    }

    #[test]
    fn test_mixed_operations() {
        let a1 = F::from_u64(10);
        let b1 = F::from_u64(20);
        let out1 = F::from_u64(30); // add

        let a2 = F::from_u64(7);
        let b2 = F::from_u64(3);
        let out2 = F::from_u64(21); // mul

        let witness = vec![
            Some(a1),
            Some(b1),
            Some(out1),
            Some(a2),
            Some(b2),
            Some(out2),
        ];

        let ops = vec![
            Op::add(WitnessId(0), WitnessId(1), WitnessId(2)),
            Op::mul(WitnessId(3), WitnessId(4), WitnessId(5)),
        ];

        let builder = AluTraceBuilder::new(&ops, &witness);
        let trace = builder.build().expect("Failed to build trace");

        assert_eq!(trace.len(), 2);
        assert_eq!(trace.op_kind[0], AluOpKind::Add);
        assert_eq!(trace.op_kind[1], AluOpKind::Mul);
    }

    #[test]
    fn test_empty_operations_creates_dummy_row() {
        let witness = vec![Some(F::ZERO)];
        let ops: Vec<Op<F>> = vec![];

        let builder = AluTraceBuilder::new(&ops, &witness);
        let trace = builder.build().expect("Failed to build trace");

        assert_eq!(trace.len(), 1);
        assert_eq!(trace.op_kind[0], AluOpKind::Add);
        assert_eq!(trace.values[0][0], F::ZERO);
        assert_eq!(trace.values[0][1], F::ZERO);
        assert_eq!(trace.values[0][2], F::ZERO);
        assert_eq!(trace.values[0][3], F::ZERO);
    }

    #[test]
    fn test_missing_witness_returns_error() {
        let witness = vec![None, Some(F::from_u64(5)), Some(F::from_u64(5))];

        let ops = vec![Op::add(WitnessId(0), WitnessId(1), WitnessId(2))];

        let builder = AluTraceBuilder::new(&ops, &witness);
        let result = builder.build();

        assert!(result.is_err());
        match result {
            Err(CircuitError::WitnessNotSet { witness_id }) => {
                assert_eq!(witness_id, WitnessId(0));
            }
            _ => panic!("Expected WitnessNotSet error"),
        }
    }
}
