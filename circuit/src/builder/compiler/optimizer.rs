use alloc::vec::Vec;

use hashbrown::HashMap;
use p3_field::Field;

use crate::op::{AluOpKind, Op};
use crate::types::WitnessId;

/// Responsible for performing optimization passes on primitive operations.
#[derive(Debug, Default)]
pub struct Optimizer;

/// Information about an operation definition.
#[derive(Clone)]
enum OpDef<F> {
    Const(F),
    Add { a: WitnessId, b: WitnessId },
    Mul { a: WitnessId, b: WitnessId },
    Other,
}

/// A candidate MulAdd operation to be created.
struct MulAddCandidate<F> {
    /// Index of the mul operation that will be consumed by this MulAdd
    consumed_mul_idx: usize,
    /// The MulAdd operation to emit
    op: Op<F>,
}

impl Optimizer {
    /// Creates a new optimizer.
    pub const fn new() -> Self {
        Self
    }

    /// Optimizes primitive operations.
    ///
    /// Currently implements:
    /// - BoolCheck fusion: detects `b * (b - 1) = 0` patterns and fuses them into BoolCheck ops
    ///
    /// MulAdd fusion is implemented but disabled pending:
    /// 1. Update runner to compute intermediate witness values for fused ops
    /// 2. Update tests to check alu_trace instead of separate mul_trace/add_trace
    ///
    /// Future passes that can be added here:
    /// - Dead code elimination
    /// - Common subexpression elimination
    /// - Constant folding
    pub fn optimize<F: Field>(&self, primitive_ops: Vec<Op<F>>) -> Vec<Op<F>> {
        // Run BoolCheck fusion
        self.fuse_bool_checks(primitive_ops)
        // MulAdd fusion disabled for now - see docstring above
        // self.fuse_mul_adds(ops)
    }

    /// Detects and fuses `a * b + c` patterns into MulAdd operations.
    ///
    /// Pattern: add(mul(a, b), c) where the mul result is only used by this add.
    /// This saves one row in the ALU table by combining the mul and add into one operation.
    fn fuse_mul_adds<F: Field>(&self, ops: Vec<Op<F>>) -> Vec<Op<F>> {
        // Build use counts for each witness ID
        let mut use_counts: HashMap<WitnessId, usize> = HashMap::new();
        for op in &ops {
            if let Op::Alu { a, b, c, .. } = op {
                *use_counts.entry(*a).or_insert(0) += 1;
                *use_counts.entry(*b).or_insert(0) += 1;
                if let Some(c_id) = c {
                    *use_counts.entry(*c_id).or_insert(0) += 1;
                }
            }
        }

        // Build a map from output witness ID to operation definition
        let mut defs: HashMap<WitnessId, (usize, OpDef<F>)> = HashMap::new();
        for (idx, op) in ops.iter().enumerate() {
            match op {
                Op::Alu {
                    kind: AluOpKind::Mul,
                    a,
                    b,
                    out,
                    c: None,
                    ..
                } => {
                    defs.insert(*out, (idx, OpDef::Mul { a: *a, b: *b }));
                }
                Op::Alu {
                    kind: AluOpKind::Add,
                    a,
                    b,
                    out,
                    c: None,
                    ..
                } => {
                    defs.insert(*out, (idx, OpDef::Add { a: *a, b: *b }));
                }
                Op::Alu { out, .. } => {
                    defs.insert(*out, (idx, OpDef::Other));
                }
                Op::Const { out, val } => {
                    defs.insert(*out, (idx, OpDef::Const(*val)));
                }
                Op::Public { out, .. } => {
                    defs.insert(*out, (idx, OpDef::Other));
                }
                Op::NonPrimitiveOpWithExecutor { .. } => {}
            }
        }

        // First pass: identify which muls will be consumed by MulAdd fusion
        let mut consumed_muls: hashbrown::HashSet<usize> = hashbrown::HashSet::new();
        let mut add_to_muladd: HashMap<usize, MulAddCandidate<F>> = HashMap::new();

        for (idx, op) in ops.iter().enumerate() {
            if let Op::Alu {
                kind: AluOpKind::Add,
                a: add_a,
                b: add_b,
                c: None,
                out,
            } = op
            {
                // Check if add_a is a mul result with use count 1
                if let Some(muladd) =
                    self.try_create_muladd(*add_a, *add_b, *out, &defs, &use_counts)
                    && !consumed_muls.contains(&muladd.consumed_mul_idx)
                {
                    consumed_muls.insert(muladd.consumed_mul_idx);
                    add_to_muladd.insert(idx, muladd);
                    continue;
                }

                // Check symmetric case: add_b is a mul result
                if let Some(muladd) =
                    self.try_create_muladd(*add_b, *add_a, *out, &defs, &use_counts)
                    && !consumed_muls.contains(&muladd.consumed_mul_idx)
                {
                    consumed_muls.insert(muladd.consumed_mul_idx);
                    add_to_muladd.insert(idx, muladd);
                }
            }
        }

        // Second pass: build result, skipping consumed muls and replacing adds with MulAdds
        let mut result = Vec::with_capacity(ops.len() - consumed_muls.len());

        for (idx, op) in ops.into_iter().enumerate() {
            // Skip muls that were consumed by a MulAdd
            if consumed_muls.contains(&idx) {
                continue;
            }

            // Replace adds with MulAdds where applicable
            if let Some(muladd) = add_to_muladd.remove(&idx) {
                result.push(muladd.op);
                continue;
            }

            result.push(op);
        }

        result
    }

    /// Tries to create a MulAdd operation from add(mul_result, addend).
    ///
    /// Returns Some if:
    /// - mul_result is the output of a Mul operation
    /// - mul_result has use count of exactly 1 (only used by this add)
    fn try_create_muladd<F: Field>(
        &self,
        mul_result: WitnessId,
        addend: WitnessId,
        out: WitnessId,
        defs: &HashMap<WitnessId, (usize, OpDef<F>)>,
        use_counts: &HashMap<WitnessId, usize>,
    ) -> Option<MulAddCandidate<F>> {
        // Check if mul_result is from a Mul operation
        let (mul_idx, mul_def) = defs.get(&mul_result)?;
        let (mul_a, mul_b) = match mul_def {
            OpDef::Mul { a, b } => (*a, *b),
            _ => return None,
        };

        // Check that mul_result is only used once (by this add)
        let use_count = use_counts.get(&mul_result).copied().unwrap_or(0);
        if use_count != 1 {
            return None;
        }

        // Create the MulAdd operation
        Some(MulAddCandidate {
            consumed_mul_idx: *mul_idx,
            op: Op::Alu {
                kind: AluOpKind::MulAdd,
                a: mul_a,
                b: mul_b,
                c: Some(addend),
                out,
            },
        })
    }

    /// Detects and fuses `assert_bool` patterns into BoolCheck operations.
    ///
    /// Pattern: `b * (b - 1) = 0` which appears as:
    /// 1. `neg_one = mul(one, const_neg_1)` (creates -1)
    /// 2. `b_minus_1 = add(b, neg_one)` (b - 1)
    /// 3. `product = mul(b, b_minus_1)` (b * (b-1))
    /// 4. The product is connected to zero (assert_zero)
    ///
    /// We detect step 3 and transform it into a BoolCheck if the pattern matches.
    fn fuse_bool_checks<F: Field>(&self, ops: Vec<Op<F>>) -> Vec<Op<F>> {
        // Build a map from output witness ID to operation info
        let mut defs: HashMap<WitnessId, OpDef<F>> = HashMap::new();

        for op in &ops {
            match op {
                Op::Const { out, val } => {
                    defs.insert(*out, OpDef::Const(*val));
                }
                Op::Public { out, .. } => {
                    defs.insert(*out, OpDef::Other);
                }
                Op::Alu {
                    kind: AluOpKind::Add,
                    a,
                    b,
                    out,
                    ..
                } => {
                    defs.insert(*out, OpDef::Add { a: *a, b: *b });
                }
                Op::Alu {
                    kind: AluOpKind::Mul,
                    a,
                    b,
                    out,
                    ..
                } => {
                    defs.insert(*out, OpDef::Mul { a: *a, b: *b });
                }
                Op::Alu { out, .. } => {
                    defs.insert(*out, OpDef::Other);
                }
                Op::NonPrimitiveOpWithExecutor { .. } => {}
            }
        }

        let mut result = Vec::with_capacity(ops.len());

        for op in ops {
            // Check if this is a mul that could be a BoolCheck
            if let Op::Alu {
                kind: AluOpKind::Mul,
                a,
                b,
                c: None,
                out,
            } = &op
            {
                // Check if this matches the pattern: mul(X, add(X, -1))
                // where the second operand is X - 1
                if let Some(bool_check_input) = self.detect_bool_check_pattern(*a, *b, &defs) {
                    // Replace with BoolCheck: a * (a - 1) = 0, out = a
                    result.push(Op::Alu {
                        kind: AluOpKind::BoolCheck,
                        a: bool_check_input,
                        b: *b, // Keep original b for structural compatibility
                        c: None,
                        out: *out,
                    });
                    continue;
                }
            }

            result.push(op);
        }

        result
    }

    /// Detects if `mul(a, b)` matches the pattern `X * (X - 1)`.
    ///
    /// Returns `Some(X)` if the pattern matches, `None` otherwise.
    fn detect_bool_check_pattern<F: Field>(
        &self,
        mul_a: WitnessId,
        mul_b: WitnessId,
        defs: &HashMap<WitnessId, OpDef<F>>,
    ) -> Option<WitnessId> {
        // Check if b = add(a, -1) or b = add(a, neg_one_result)
        // where neg_one_result is the result of some computation that equals -1
        if let Some(OpDef::Add { a: add_a, b: add_b }) = defs.get(&mul_b) {
            // Pattern: mul(a, add(a, X)) where X = -1
            if *add_a == mul_a && self.is_neg_one(*add_b, defs) {
                return Some(mul_a);
            }
        }

        // Also check symmetric case: mul(add(a, X), a) where X = -1
        if let Some(OpDef::Add { a: add_a, b: add_b }) = defs.get(&mul_a)
            && *add_a == mul_b
            && self.is_neg_one(*add_b, defs)
        {
            return Some(mul_b);
        }

        None
    }

    /// Checks if a witness ID holds the value -1 (either directly or through computation).
    fn is_neg_one<F: Field>(&self, id: WitnessId, defs: &HashMap<WitnessId, OpDef<F>>) -> bool {
        match defs.get(&id) {
            // Direct constant check
            Some(OpDef::Const(val)) => *val == -F::ONE,

            // Check if it's the result of mul(1, -1) = -1
            // This is how sub(a, b) creates the negation
            Some(OpDef::Mul { a, b }) => {
                let a_is_one = matches!(defs.get(a), Some(OpDef::Const(v)) if *v == F::ONE);
                let b_is_neg_one = matches!(defs.get(b), Some(OpDef::Const(v)) if *v == -F::ONE);
                let a_is_neg_one = matches!(defs.get(a), Some(OpDef::Const(v)) if *v == -F::ONE);
                let b_is_one = matches!(defs.get(b), Some(OpDef::Const(v)) if *v == F::ONE);

                (a_is_one && b_is_neg_one) || (a_is_neg_one && b_is_one)
            }

            _ => false,
        }
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
    fn test_optimizer_passthrough() {
        let optimizer = Optimizer::new();

        let ops: Vec<Op<F>> = vec![
            Op::Const {
                out: WitnessId(0),
                val: F::ZERO,
            },
            Op::add(WitnessId(0), WitnessId(1), WitnessId(2)),
        ];

        let optimized = optimizer.optimize(ops.clone());
        assert_eq!(optimized, ops);
    }

    #[test]
    fn test_bool_check_fusion() {
        let optimizer = Optimizer::new();

        // Simulate the pattern created by assert_bool(b):
        // 1. one = Const(1) at WitnessId(1)
        // 2. neg_one = Const(-1) at WitnessId(2)
        // 3. one_times_neg_one = mul(one, neg_one) = -1 at WitnessId(3)
        // 4. b_minus_one = add(b, one_times_neg_one) = b - 1 at WitnessId(4)
        // 5. product = mul(b, b_minus_one) = b * (b-1) at WitnessId(5)
        //
        // After BoolCheck fusion: op 5 becomes BoolCheck(b)
        let b = WitnessId(0);
        let one = WitnessId(1);
        let neg_one = WitnessId(2);
        let one_times_neg_one = WitnessId(3);
        let b_minus_one = WitnessId(4);
        let product = WitnessId(5);

        let ops: Vec<Op<F>> = vec![
            Op::Const {
                out: one,
                val: F::ONE,
            },
            Op::Const {
                out: neg_one,
                val: -F::ONE,
            },
            Op::mul(one, neg_one, one_times_neg_one),   // -1
            Op::add(b, one_times_neg_one, b_minus_one), // b - 1
            Op::mul(b, b_minus_one, product),           // b * (b - 1) - this should be fused
        ];

        let optimized = optimizer.optimize(ops);

        // BoolCheck fusion converts the final mul into BoolCheck
        // All other ops remain unchanged
        assert_eq!(optimized.len(), 5);

        // Check that the last op is now a BoolCheck
        match &optimized[4] {
            Op::Alu {
                kind: AluOpKind::BoolCheck,
                a,
                out,
                ..
            } => {
                assert_eq!(*a, b, "BoolCheck should check witness b");
                assert_eq!(
                    *out, product,
                    "BoolCheck output should be at product location"
                );
            }
            _ => panic!("Expected last op to be BoolCheck, got {:?}", optimized[4]),
        }
    }

    #[test]
    fn test_no_false_positive_bool_check() {
        let optimizer = Optimizer::new();

        // A regular mul that doesn't match the pattern
        let a = WitnessId(0);
        let b = WitnessId(1);
        let out = WitnessId(2);

        let ops: Vec<Op<F>> = vec![Op::mul(a, b, out)];

        let optimized = optimizer.optimize(ops.clone());

        // Should remain unchanged
        assert_eq!(optimized, ops);
    }

    #[test]
    fn test_muladd_fusion_internal() {
        // Test the fuse_mul_adds method directly (bypassing the disabled public API)
        let optimizer = Optimizer::new();

        // Pattern: a * b + c where mul result is only used once
        let a = WitnessId(0);
        let b = WitnessId(1);
        let c = WitnessId(2);
        let mul_result = WitnessId(3);
        let add_result = WitnessId(4);

        let ops: Vec<Op<F>> = vec![
            Op::mul(a, b, mul_result),          // a * b
            Op::add(mul_result, c, add_result), // (a * b) + c
        ];

        // Call fuse_mul_adds directly
        let optimized = optimizer.fuse_mul_adds(ops);

        // Should fuse into a single MulAdd
        assert_eq!(
            optimized.len(),
            1,
            "Should have fused mul+add into one MulAdd"
        );

        match &optimized[0] {
            Op::Alu {
                kind: AluOpKind::MulAdd,
                a: mul_a,
                b: mul_b,
                c: Some(add_c),
                out,
            } => {
                assert_eq!(*mul_a, a, "MulAdd a should be from original mul");
                assert_eq!(*mul_b, b, "MulAdd b should be from original mul");
                assert_eq!(*add_c, c, "MulAdd c should be the addend");
                assert_eq!(*out, add_result, "MulAdd out should be the add result");
            }
            _ => panic!("Expected MulAdd, got {:?}", optimized[0]),
        }
    }

    #[test]
    fn test_muladd_fusion_symmetric_internal() {
        // Test the fuse_mul_adds method directly (bypassing the disabled public API)
        let optimizer = Optimizer::new();

        // Pattern: c + a * b (addend first, mul second)
        let a = WitnessId(0);
        let b = WitnessId(1);
        let c = WitnessId(2);
        let mul_result = WitnessId(3);
        let add_result = WitnessId(4);

        let ops: Vec<Op<F>> = vec![
            Op::mul(a, b, mul_result),          // a * b
            Op::add(c, mul_result, add_result), // c + (a * b)
        ];

        // Call fuse_mul_adds directly
        let optimized = optimizer.fuse_mul_adds(ops);

        // Should fuse into a single MulAdd
        assert_eq!(
            optimized.len(),
            1,
            "Should have fused mul+add into one MulAdd"
        );

        match &optimized[0] {
            Op::Alu {
                kind: AluOpKind::MulAdd,
                a: mul_a,
                b: mul_b,
                c: Some(add_c),
                out,
            } => {
                assert_eq!(*mul_a, a, "MulAdd a should be from original mul");
                assert_eq!(*mul_b, b, "MulAdd b should be from original mul");
                assert_eq!(*add_c, c, "MulAdd c should be the addend");
                assert_eq!(*out, add_result, "MulAdd out should be the add result");
            }
            _ => panic!("Expected MulAdd, got {:?}", optimized[0]),
        }
    }

    #[test]
    fn test_no_muladd_fusion_when_mul_has_multiple_uses_internal() {
        // Test the fuse_mul_adds method directly (bypassing the disabled public API)
        let optimizer = Optimizer::new();

        // Pattern: mul result is used twice (in add and elsewhere)
        let a = WitnessId(0);
        let b = WitnessId(1);
        let c = WitnessId(2);
        let mul_result = WitnessId(3);
        let add_result = WitnessId(4);
        let other_result = WitnessId(5);

        let ops: Vec<Op<F>> = vec![
            Op::mul(a, b, mul_result),            // a * b
            Op::add(mul_result, c, add_result),   // (a * b) + c
            Op::add(mul_result, a, other_result), // mul_result used again!
        ];

        // Call fuse_mul_adds directly
        let optimized = optimizer.fuse_mul_adds(ops);

        // Should NOT fuse because mul_result has use count > 1
        assert_eq!(
            optimized.len(),
            3,
            "Should not fuse when mul has multiple uses"
        );

        // First op should still be mul
        assert!(
            matches!(
                optimized[0],
                Op::Alu {
                    kind: AluOpKind::Mul,
                    ..
                }
            ),
            "First op should remain Mul"
        );
    }
}
