use alloc::vec::Vec;

use hashbrown::HashMap;
use p3_field::Field;

use crate::op::{AluOpKind, Op};
use crate::types::WitnessId;

/// Responsible for performing optimization passes on primitive operations.
#[derive(Debug, Default)]
pub struct Optimizer;

/// Information about an operation definition.
#[derive(Clone, Debug)]
enum OpDef<F> {
    Const(F),
    Add { a: WitnessId, b: WitnessId },
    Mul { a: WitnessId, b: WitnessId },
    Other,
}

// MulAddCandidate struct removed - now using inline tuple returns

impl Optimizer {
    /// Creates a new optimizer.
    pub const fn new() -> Self {
        Self
    }

    /// Optimizes primitive operations.
    ///
    /// Currently implements:
    /// - BoolCheck fusion: detects `b * (b - 1) = 0` patterns and fuses them into BoolCheck ops
    /// - MulAdd fusion: detects `a * b + c` patterns and fuses them into MulAdd ops
    ///
    /// Future passes that can be added here:
    /// - Dead code elimination
    /// - Common subexpression elimination
    /// - Constant folding
    pub fn optimize<F: Field>(&self, primitive_ops: Vec<Op<F>>) -> Vec<Op<F>> {
        // BoolCheck first, then MulAdd
        let ops = self.fuse_bool_checks(primitive_ops);
        self.fuse_mul_adds(ops)
    }

    /// Detects and fuses `a * b + c` patterns into MulAdd operations.
    ///
    /// Pattern: add(mul(a, b), c) where the mul result is only used by this add.
    /// This saves one row in the ALU table by combining the mul and add into one operation.
    ///
    /// Uses a two-phase approach to handle chained patterns correctly:
    /// 1. Identify all potential fusions (ignoring ordering)
    /// 2. Filter to only keep fusions where the addend is available at the mul's position
    fn fuse_mul_adds<F: Field>(&self, ops: Vec<Op<F>>) -> Vec<Op<F>> {
        // Build use counts for each witness ID (counting ALL uses, not just ALU)
        let mut use_counts: HashMap<WitnessId, usize> = HashMap::new();
        for op in &ops {
            match op {
                Op::Alu { a, b, c, .. } => {
                    *use_counts.entry(*a).or_insert(0) += 1;
                    *use_counts.entry(*b).or_insert(0) += 1;
                    if let Some(c_id) = c {
                        *use_counts.entry(*c_id).or_insert(0) += 1;
                    }
                }
                Op::NonPrimitiveOpWithExecutor { inputs, .. } => {
                    for input_group in inputs {
                        for witness_id in input_group {
                            *use_counts.entry(*witness_id).or_insert(0) += 1;
                        }
                    }
                }
                _ => {}
            }
        }

        // Build a map from output witness ID to operation definition.
        // Important: Const entries are never overwritten because witness slots shared
        // via connect() should keep the Const definition.
        let mut defs: HashMap<WitnessId, (usize, OpDef<F>)> = HashMap::new();

        // Also track witnesses computed by backwards adds.
        // In a backwards add(a, b, out), if `out` is already defined, then `b` is computed.
        // We need to track where `b` is computed so we don't treat it as always available.
        let mut backwards_add_computed: HashMap<WitnessId, usize> = HashMap::new();

        for (idx, op) in ops.iter().enumerate() {
            match op {
                Op::Const { out, val } => {
                    defs.insert(*out, (idx, OpDef::Const(*val)));
                }
                Op::Alu {
                    kind: AluOpKind::Mul,
                    a,
                    b,
                    out,
                    c: None,
                    ..
                } => {
                    if !matches!(defs.get(out), Some((_, OpDef::Const(_)))) {
                        // Check if this is a backwards mul (division)
                        // If `out` is already defined, then `b` is computed
                        if let Some((out_def_idx, _)) = defs.get(out)
                            && *out_def_idx < idx
                        {
                            backwards_add_computed.insert(*b, idx);
                            // Also track the computed value in defs so subsequent
                            // backwards adds can detect their output is defined
                            if !matches!(defs.get(b), Some((_, OpDef::Const(_)))) {
                                defs.insert(*b, (idx, OpDef::Other));
                            }
                        }
                        defs.insert(*out, (idx, OpDef::Mul { a: *a, b: *b }));
                    }
                }
                Op::Alu {
                    kind: AluOpKind::Add,
                    a,
                    b,
                    out,
                    c: None,
                    ..
                } => {
                    if !matches!(defs.get(out), Some((_, OpDef::Const(_)))) {
                        // Check if this is a backwards add (subtraction)
                        // If `out` is already defined, then `b` is computed
                        if let Some((out_def_idx, _)) = defs.get(out)
                            && *out_def_idx < idx
                        {
                            backwards_add_computed.insert(*b, idx);
                            // Also track the computed value in defs so subsequent
                            // backwards adds can detect their output is defined
                            if !matches!(defs.get(b), Some((_, OpDef::Const(_)))) {
                                defs.insert(*b, (idx, OpDef::Other));
                            }
                        }
                        defs.insert(*out, (idx, OpDef::Add { a: *a, b: *b }));
                    }
                }
                Op::Alu { out, .. } => {
                    if !matches!(defs.get(out), Some((_, OpDef::Const(_)))) {
                        defs.insert(*out, (idx, OpDef::Other));
                    }
                }
                Op::Public { out, .. } => {
                    if !matches!(defs.get(out), Some((_, OpDef::Const(_)))) {
                        defs.insert(*out, (idx, OpDef::Other));
                    }
                }
                Op::NonPrimitiveOpWithExecutor { outputs, .. } => {
                    for output_group in outputs {
                        for out_id in output_group {
                            if !matches!(defs.get(out_id), Some((_, OpDef::Const(_)))) {
                                defs.insert(*out_id, (idx, OpDef::Other));
                            }
                        }
                    }
                }
            }
        }

        // Phase 1: Identify ALL potential fusions (without ordering checks)
        // Store: add_idx -> (mul_idx, MulAdd op, addend)
        let mut potential_fusions: HashMap<usize, (usize, Op<F>, WitnessId)> = HashMap::new();

        for (add_idx, op) in ops.iter().enumerate() {
            if let Op::Alu {
                kind: AluOpKind::Add,
                a: add_a,
                b: add_b,
                c: None,
                out,
                ..
            } = op
            {
                // Skip adds where output is a Const (connect aliasing)
                if matches!(defs.get(out), Some((_, OpDef::Const(_)))) {
                    continue;
                }

                // Detect backwards adds: if `out` is defined BEFORE this add,
                // then this add computes one of its inputs (a or b), not `out`.
                // We cannot fuse backwards adds.
                let is_backwards_add = defs
                    .get(out)
                    .map(|(def_idx, _)| *def_idx < add_idx)
                    .unwrap_or(false);
                if is_backwards_add {
                    continue;
                }

                // Try add_a as mul result
                if let Some((mul_idx, muladd_op, addend)) = self.try_create_muladd_candidate(
                    *add_a,
                    *add_b,
                    *out,
                    add_idx,
                    &defs,
                    &use_counts,
                    &backwards_add_computed,
                ) {
                    potential_fusions.insert(add_idx, (mul_idx, muladd_op, addend));
                    continue;
                }

                // Try add_b as mul result (symmetric)
                if let Some((mul_idx, muladd_op, addend)) = self.try_create_muladd_candidate(
                    *add_b,
                    *add_a,
                    *out,
                    add_idx,
                    &defs,
                    &use_counts,
                    &backwards_add_computed,
                ) {
                    potential_fusions.insert(add_idx, (mul_idx, muladd_op, addend));
                }
            }
        }

        // Phase 2: Iteratively filter fusions based on ordering constraints
        // We iterate until no more fusions are invalidated.
        //
        // A fusion is valid if its addend is available at the mul's position.
        // The addend's effective position depends on whether the op producing it will be fused.

        let mut valid_add_indices: hashbrown::HashSet<usize> =
            potential_fusions.keys().copied().collect();

        loop {
            // Build map: add_out -> mul_idx for CURRENTLY valid fusions only
            let mut add_out_to_mul_idx: HashMap<WitnessId, usize> = HashMap::new();
            for &add_idx in &valid_add_indices {
                if let Some((mul_idx, _, _)) = potential_fusions.get(&add_idx)
                    && let Some(Op::Alu { out, .. }) = ops.get(add_idx)
                {
                    add_out_to_mul_idx.insert(*out, *mul_idx);
                }
            }

            // Check each currently valid fusion
            let mut to_remove: Vec<usize> = Vec::new();

            for &add_idx in &valid_add_indices {
                if let Some((mul_idx, _, addend)) = potential_fusions.get(&add_idx) {
                    let addend_available_at =
                        self.compute_effective_position(*addend, &defs, &add_out_to_mul_idx);

                    // Invalid if addend isn't available when MulAdd runs
                    // None means always available (witness/public input), which is fine
                    if let Some(pos) = addend_available_at
                        && pos >= *mul_idx
                    {
                        to_remove.push(add_idx);
                    }
                }
            }

            if to_remove.is_empty() {
                break; // Fixed point reached
            }

            for add_idx in to_remove {
                valid_add_indices.remove(&add_idx);
            }
        }

        // Build valid_fusions from the remaining valid indices
        let mut valid_fusions: HashMap<usize, (usize, Op<F>)> = HashMap::new();
        for add_idx in valid_add_indices {
            if let Some((mul_idx, muladd_op, _addend)) = potential_fusions.remove(&add_idx) {
                valid_fusions.insert(add_idx, (mul_idx, muladd_op));
            }
        }

        // Build the result
        let mut consumed_adds: hashbrown::HashSet<usize> = hashbrown::HashSet::new();
        let mut mul_to_muladd: HashMap<usize, Op<F>> = HashMap::new();

        for (add_idx, (mul_idx, muladd_op)) in valid_fusions {
            // Avoid double-fusing the same mul
            if !mul_to_muladd.contains_key(&mul_idx) {
                mul_to_muladd.insert(mul_idx, muladd_op);
                consumed_adds.insert(add_idx);
            }
        }

        let mut result = Vec::with_capacity(ops.len() - consumed_adds.len());

        for (idx, op) in ops.into_iter().enumerate() {
            if consumed_adds.contains(&idx) {
                continue;
            }

            if let Some(muladd_op) = mul_to_muladd.remove(&idx) {
                result.push(muladd_op);
                continue;
            }

            result.push(op);
        }

        result
    }

    /// Creates a MulAdd candidate without full ordering checks.
    /// Returns (mul_idx, MulAdd op, addend) if the pattern matches.
    #[allow(clippy::too_many_arguments)]
    fn try_create_muladd_candidate<F: Field>(
        &self,
        mul_result: WitnessId,
        addend: WitnessId,
        out: WitnessId,
        add_idx: usize,
        defs: &HashMap<WitnessId, (usize, OpDef<F>)>,
        use_counts: &HashMap<WitnessId, usize>,
        backwards_add_computed: &HashMap<WitnessId, usize>,
    ) -> Option<(usize, Op<F>, WitnessId)> {
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

        // Don't fuse if mul_result is a constant (connect aliasing)
        if matches!(defs.get(&mul_result), Some((_, OpDef::Const(_)))) {
            return None;
        }

        // Don't fuse if the addend isn't defined yet (would be computed by this add)
        if let Some((addend_def_idx, _)) = defs.get(&addend)
            && *addend_def_idx >= add_idx
        {
            return None;
        }

        // Don't fuse if the addend is computed by a backwards add that runs at or after mul_idx
        // (the MulAdd would run at mul_idx but the addend wouldn't be available yet)
        if let Some(&computed_at_idx) = backwards_add_computed.get(&addend)
            && computed_at_idx >= *mul_idx
        {
            return None;
        }

        let muladd_op = Op::Alu {
            kind: AluOpKind::MulAdd,
            a: mul_a,
            b: mul_b,
            c: Some(addend),
            out,
            intermediate_out: Some(mul_result),
        };

        Some((*mul_idx, muladd_op, addend))
    }

    /// Computes the effective position where a witness will be available.
    /// Takes into account that an Add's output might be moved if it gets fused.
    /// Returns None for witnesses that are always available (public inputs, witness inputs).
    fn compute_effective_position<F>(
        &self,
        witness: WitnessId,
        defs: &HashMap<WitnessId, (usize, OpDef<F>)>,
        add_out_to_mul_idx: &HashMap<WitnessId, usize>,
    ) -> Option<usize> {
        // If this witness is the output of an Add that will be fused,
        // its effective position is the corresponding Mul's position
        if let Some(&mul_idx) = add_out_to_mul_idx.get(&witness) {
            return Some(mul_idx);
        }

        // Otherwise, use the original definition position
        // If not in defs (witness/public input), it's always available
        defs.get(&witness).map(|(idx, _)| *idx)
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
                ..
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
                        intermediate_out: None,
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

        // BoolCheck fusion converts mul(b, b_minus_one) into BoolCheck
        // MulAdd fusion fuses mul(one, neg_one) + add(b, ...) into MulAdd
        // Result: 2 Const + 1 MulAdd + 1 BoolCheck = 4 ops
        assert_eq!(optimized.len(), 4, "Expected 4 ops, got {:?}", optimized);

        // Check that there's a BoolCheck
        let bool_check_count = optimized
            .iter()
            .filter(|op| {
                matches!(
                    op,
                    Op::Alu {
                        kind: AluOpKind::BoolCheck,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(bool_check_count, 1, "Expected 1 BoolCheck");

        // Check that there's a MulAdd
        let muladd_count = optimized
            .iter()
            .filter(|op| {
                matches!(
                    op,
                    Op::Alu {
                        kind: AluOpKind::MulAdd,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(muladd_count, 1, "Expected 1 MulAdd");
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
    fn test_muladd_fusion_chained() {
        // Test chained mul+add pattern like in decompose_to_bits:
        // acc0 = const
        // term0 = mul(bit0, pow0)
        // acc1 = add(acc0, term0)
        // term1 = mul(bit1, pow1)
        // acc2 = add(acc1, term1)
        let optimizer = Optimizer::new();

        let acc0 = WitnessId(0);
        let bit0 = WitnessId(1);
        let pow0 = WitnessId(2);
        let term0 = WitnessId(3);
        let acc1 = WitnessId(4);
        let bit1 = WitnessId(5);
        let pow1 = WitnessId(6);
        let term1 = WitnessId(7);
        let acc2 = WitnessId(8);

        let ops: Vec<Op<F>> = vec![
            Op::Const {
                out: acc0,
                val: F::ZERO,
            }, // idx 0: acc0 = 0
            Op::Const {
                out: pow0,
                val: F::ONE,
            }, // idx 1: pow0 = 1
            Op::Const {
                out: pow1,
                val: F::TWO,
            }, // idx 2: pow1 = 2
            // bit0 and bit1 would be from a hint, but they're just witness IDs here
            Op::mul(bit0, pow0, term0), // idx 3: term0 = bit0 * pow0
            Op::add(acc0, term0, acc1), // idx 4: acc1 = acc0 + term0
            Op::mul(bit1, pow1, term1), // idx 5: term1 = bit1 * pow1
            Op::add(acc1, term1, acc2), // idx 6: acc2 = acc1 + term1
        ];

        let optimized = optimizer.fuse_mul_adds(ops);

        // Both fusions should happen:
        // - First: mul(bit0, pow0) + add(acc0, term0) -> MulAdd (acc0 is Const, available at mul's position)
        // - Second: mul(bit1, pow1) + add(acc1, term1) -> MulAdd (acc1 is from first MulAdd, runs at mul0's position which is before mul1)
        // Result: 3 consts + 2 MulAdds = 5 ops
        assert_eq!(
            optimized.len(),
            5,
            "Should have 3 consts + 2 MulAdds, got {} ops: {:?}",
            optimized.len(),
            optimized
        );

        // Verify both MulAdds exist
        let muladd_count = optimized
            .iter()
            .filter(|op| {
                matches!(
                    op,
                    Op::Alu {
                        kind: AluOpKind::MulAdd,
                        ..
                    }
                )
            })
            .count();
        assert_eq!(muladd_count, 2, "Expected 2 MulAdds");
    }

    #[test]
    fn test_muladd_fusion_with_sub_pattern() {
        // Test that backwards adds from sub() are NOT fused
        // Pattern from assert_bool: sub(b, one) -> b_minus_one
        // Encoded as: add(one, b_minus_one) = b (out is already defined)
        let optimizer = Optimizer::new();

        let b = WitnessId(0); // bit from hint
        let one = WitnessId(1); // const 1
        let b_minus_one = WitnessId(2); // result of sub
        let pow = WitnessId(3); // const power of 2
        let term = WitnessId(4); // mul result
        let acc = WitnessId(5); // initial accumulator
        let new_acc = WitnessId(6); // result of add

        let ops: Vec<Op<F>> = vec![
            Op::Const {
                out: one,
                val: F::ONE,
            }, // idx 0
            Op::Const {
                out: pow,
                val: F::TWO,
            }, // idx 1
            Op::Const {
                out: acc,
                val: F::ZERO,
            }, // idx 2
            // Sub encoded as backwards add: one + b_minus_one = b
            // Note: 'b' (WitnessId(0)) is NOT defined by any op here - simulating hint output
            Op::add(one, b_minus_one, b), // idx 3: backwards add (b is already defined)
            Op::mul(b, pow, term),        // idx 4: term = b * pow
            Op::add(acc, term, new_acc),  // idx 5: new_acc = acc + term
        ];

        let optimized = optimizer.fuse_mul_adds(ops);

        // The backwards add at idx 3 should NOT be fused (b is not in defs, so out_def_idx check fails)
        // The forward add at idx 5 CAN be fused with mul at idx 4
        // Result: 3 consts + 1 backwards add + 1 MulAdd = 5 ops
        assert_eq!(
            optimized.len(),
            5,
            "Should have 3 consts + backwards add + MulAdd, got {} ops: {:?}",
            optimized.len(),
            optimized
        );
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
                ..
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
                ..
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
