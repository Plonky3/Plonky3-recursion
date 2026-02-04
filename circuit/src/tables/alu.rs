use alloc::vec::Vec;

use p3_field::Field;

use crate::CircuitError;
use crate::op::{AluOpKind, Op};
use crate::types::WitnessId;

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
    /// First operand values (a)
    pub a_values: Vec<F>,
    /// First operand indices (references witness bus)
    pub a_index: Vec<WitnessId>,
    /// Second operand values (b)
    pub b_values: Vec<F>,
    /// Second operand indices (references witness bus)
    pub b_index: Vec<WitnessId>,
    /// Third operand values (c) - only used for MulAdd, zero otherwise
    pub c_values: Vec<F>,
    /// Third operand indices - only meaningful for MulAdd
    pub c_index: Vec<WitnessId>,
    /// Result values
    pub out_values: Vec<F>,
    /// Result indices (references witness bus)
    pub out_index: Vec<WitnessId>,
}

impl<F> AluTrace<F> {
    /// Returns the number of operations in the trace.
    pub const fn len(&self) -> usize {
        self.a_values.len()
    }

    /// Returns true if the trace is empty.
    pub const fn is_empty(&self) -> bool {
        self.a_values.is_empty()
    }
}

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
        let mut op_kind = Vec::new();
        let mut a_values = Vec::new();
        let mut a_index = Vec::new();
        let mut b_values = Vec::new();
        let mut b_index = Vec::new();
        let mut c_values = Vec::new();
        let mut c_index = Vec::new();
        let mut out_values = Vec::new();
        let mut out_index = Vec::new();

        for prim in self.primitive_ops {
            if let Op::Alu { kind, a, b, c, out } = prim {
                let a_val = self.resolve(a)?;
                let b_val = self.resolve(b)?;
                let c_val = if let Some(c_id) = c {
                    self.resolve(c_id)?
                } else {
                    F::ZERO
                };
                let out_val = self.resolve(out)?;

                op_kind.push(*kind);
                a_values.push(a_val);
                a_index.push(*a);
                b_values.push(b_val);
                b_index.push(*b);
                c_values.push(c_val);
                c_index.push(c.unwrap_or(WitnessId(0)));
                out_values.push(out_val);
                out_index.push(*out);
            }
        }

        // If trace is empty, add a dummy row: 0 + 0 = 0
        if a_values.is_empty() {
            op_kind.push(AluOpKind::Add);
            a_values.push(F::ZERO);
            a_index.push(WitnessId(0));
            b_values.push(F::ZERO);
            b_index.push(WitnessId(0));
            c_values.push(F::ZERO);
            c_index.push(WitnessId(0));
            out_values.push(F::ZERO);
            out_index.push(WitnessId(0));
        }

        Ok(AluTrace {
            op_kind,
            a_values,
            a_index,
            b_values,
            b_index,
            c_values,
            c_index,
            out_values,
            out_index,
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
    fn test_single_addition() {
        let a = F::from_u64(5);
        let b = F::from_u64(3);
        let out = F::from_u64(8);
        let witness = vec![Some(a), Some(b), Some(out)];

        let ops = vec![Op::Alu {
            kind: AluOpKind::Add,
            a: WitnessId(0),
            b: WitnessId(1),
            c: None,
            out: WitnessId(2),
        }];

        let builder = AluTraceBuilder::new(&ops, &witness);
        let trace = builder.build().expect("Failed to build trace");

        assert_eq!(trace.len(), 1);
        assert_eq!(trace.op_kind[0], AluOpKind::Add);
        assert_eq!(trace.a_values[0], a);
        assert_eq!(trace.b_values[0], b);
        assert_eq!(trace.out_values[0], out);
    }

    #[test]
    fn test_single_multiplication() {
        let a = F::from_u64(5);
        let b = F::from_u64(3);
        let out = F::from_u64(15);
        let witness = vec![Some(a), Some(b), Some(out)];

        let ops = vec![Op::Alu {
            kind: AluOpKind::Mul,
            a: WitnessId(0),
            b: WitnessId(1),
            c: None,
            out: WitnessId(2),
        }];

        let builder = AluTraceBuilder::new(&ops, &witness);
        let trace = builder.build().expect("Failed to build trace");

        assert_eq!(trace.len(), 1);
        assert_eq!(trace.op_kind[0], AluOpKind::Mul);
        assert_eq!(trace.a_values[0], a);
        assert_eq!(trace.b_values[0], b);
        assert_eq!(trace.out_values[0], out);
    }

    #[test]
    fn test_mul_add() {
        // a * b + c = out => 5 * 3 + 2 = 17
        let a = F::from_u64(5);
        let b = F::from_u64(3);
        let c = F::from_u64(2);
        let out = F::from_u64(17);
        let witness = vec![Some(a), Some(b), Some(c), Some(out)];

        let ops = vec![Op::Alu {
            kind: AluOpKind::MulAdd,
            a: WitnessId(0),
            b: WitnessId(1),
            c: Some(WitnessId(2)),
            out: WitnessId(3),
        }];

        let builder = AluTraceBuilder::new(&ops, &witness);
        let trace = builder.build().expect("Failed to build trace");

        assert_eq!(trace.len(), 1);
        assert_eq!(trace.op_kind[0], AluOpKind::MulAdd);
        assert_eq!(trace.a_values[0], a);
        assert_eq!(trace.b_values[0], b);
        assert_eq!(trace.c_values[0], c);
        assert_eq!(trace.out_values[0], out);
    }

    #[test]
    fn test_bool_check() {
        // BoolCheck: a * (a - 1) = 0, out = a
        // For a = 1: 1 * 0 = 0 ✓
        let a = F::ONE;
        let witness = vec![Some(a), Some(F::ZERO)]; // a and placeholder for b

        let ops = vec![Op::Alu {
            kind: AluOpKind::BoolCheck,
            a: WitnessId(0),
            b: WitnessId(1), // unused for BoolCheck but required structurally
            c: None,
            out: WitnessId(0), // out = a
        }];

        let builder = AluTraceBuilder::new(&ops, &witness);
        let trace = builder.build().expect("Failed to build trace");

        assert_eq!(trace.len(), 1);
        assert_eq!(trace.op_kind[0], AluOpKind::BoolCheck);
        assert_eq!(trace.a_values[0], a);
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
            Op::Alu {
                kind: AluOpKind::Add,
                a: WitnessId(0),
                b: WitnessId(1),
                c: None,
                out: WitnessId(2),
            },
            Op::Alu {
                kind: AluOpKind::Mul,
                a: WitnessId(3),
                b: WitnessId(4),
                c: None,
                out: WitnessId(5),
            },
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
        assert_eq!(trace.a_values[0], F::ZERO);
        assert_eq!(trace.b_values[0], F::ZERO);
        assert_eq!(trace.out_values[0], F::ZERO);
    }

    #[test]
    fn test_missing_witness_returns_error() {
        let witness = vec![None, Some(F::from_u64(5)), Some(F::from_u64(5))];

        let ops = vec![Op::Alu {
            kind: AluOpKind::Add,
            a: WitnessId(0),
            b: WitnessId(1),
            c: None,
            out: WitnessId(2),
        }];

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
