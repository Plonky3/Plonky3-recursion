use alloc::vec::Vec;

use hashbrown::{HashMap, HashSet};
use p3_field::Field;

#[cfg(feature = "debugging")]
use super::OptimizedWithOrigins;
use super::analysis::AluKey;
use crate::ops::{AluOpKind, Op};
#[cfg(feature = "debugging")]
use crate::types::ExprId;
use crate::types::WitnessId;

#[cfg(feature = "debugging")]
type SeenOperation = (WitnessId, usize);
#[cfg(not(feature = "debugging"))]
type SeenOperation = WitnessId;

struct Duplicate {
    duplicate_output: WitnessId,
    canonical_output: WitnessId,
    #[cfg(feature = "debugging")]
    retained_index: usize,
}

/// Removes duplicate ALU operations by tracking a canonical output per `AluKey`.
///
/// When a duplicate is found its output witness is rewritten to the canonical one.
/// Later ops see the canonical ID through `apply_witness_rewrite`.
pub(super) struct Deduplicator {
    rewrite: HashMap<WitnessId, WitnessId>,
    seen: HashMap<(AluKey, Option<WitnessId>, Option<WitnessId>), SeenOperation>,
    protected: HashSet<WitnessId>,
}

impl Deduplicator {
    /// `capacity` is a hint for the number of ops to be deduplicated; `rewrite` and `seen` can
    /// never hold more entries than that.
    pub(super) fn with_capacity(capacity: usize) -> Self {
        Self {
            rewrite: HashMap::with_capacity(capacity),
            seen: HashMap::with_capacity(capacity),
            protected: HashSet::new(),
        }
    }

    pub(super) fn preserving_inputs(mut self, inputs: &[WitnessId]) -> Self {
        self.protected.extend(inputs.iter().copied());
        self
    }

    /// Consumes the op list and returns deduplicated ops + the rewrite map.
    pub(super) fn run<F: Field>(
        self,
        ops: Vec<Op<F>>,
    ) -> (Vec<Op<F>>, HashMap<WitnessId, WitnessId>) {
        #[cfg(feature = "debugging")]
        let result = self.run_inner(ops, None);
        #[cfg(not(feature = "debugging"))]
        let result = self.run_inner(ops);
        (result.ops, result.rewrite)
    }

    #[cfg(feature = "debugging")]
    pub(super) fn run_with_origins<F: Field>(
        self,
        ops: Vec<Op<F>>,
        origins: Vec<Vec<ExprId>>,
    ) -> OptimizedWithOrigins<F> {
        assert_eq!(ops.len(), origins.len());
        let result = self.run_inner(ops, Some(origins));
        (result.ops, result.rewrite, result.origins.unwrap())
    }

    fn run_inner<F: Field>(
        mut self,
        ops: Vec<Op<F>>,
        #[cfg(feature = "debugging")] origins: Option<Vec<Vec<ExprId>>>,
    ) -> DedupResult<F> {
        // Source slots are initialized by setters or producer rows. An ALU
        // constrained into one may be deduplicated only within that same slot.
        self.protected.extend(ops.iter().filter_map(|op| match op {
            Op::Const { out, .. } | Op::Public { out, .. } => Some(*out),
            _ => None,
        }));
        let mut result = Vec::with_capacity(ops.len());
        #[cfg(feature = "debugging")]
        let mut source_iter = origins.map(Vec::into_iter);
        #[cfg(feature = "debugging")]
        let mut result_origins: Option<Vec<Vec<ExprId>>> =
            source_iter.as_ref().map(|_| Vec::with_capacity(ops.len()));

        for mut op in ops {
            #[cfg(feature = "debugging")]
            let source = source_iter.as_mut().map(|iter| iter.next().unwrap());
            op.apply_witness_rewrite(&self.rewrite);

            #[cfg(feature = "debugging")]
            let duplicate = self.detect_duplicate(&op, result.len());
            #[cfg(not(feature = "debugging"))]
            let duplicate = self.detect_duplicate(&op);
            self.protect_occurrences(&op);
            if let Some(duplicate) = duplicate {
                let root = duplicate.canonical_output.resolve(&self.rewrite);
                if duplicate.duplicate_output != root {
                    self.rewrite.insert(duplicate.duplicate_output, root);
                }
                #[cfg(feature = "debugging")]
                if let (Some(result_origins), Some(source)) = (&mut result_origins, source) {
                    result_origins[duplicate.retained_index].extend(source);
                }
                continue;
            }

            result.push(op);
            #[cfg(feature = "debugging")]
            if let (Some(result_origins), Some(source)) = (&mut result_origins, source) {
                result_origins.push(source);
            }
        }

        DedupResult {
            ops: result,
            rewrite: self.rewrite,
            #[cfg(feature = "debugging")]
            origins: result_origins,
        }
    }

    // Rewriting a slot used by an earlier operation would disconnect its
    // existing constraint or producer. Only a fresh result may be redirected.
    fn protect_occurrences<F>(&mut self, op: &Op<F>) {
        match op {
            Op::Const { out, .. } | Op::Public { out, .. } => {
                self.protected.insert(*out);
            }
            Op::Alu {
                a,
                b,
                c,
                out,
                intermediate_out,
                ..
            } => {
                self.protected.extend([*a, *b, *out]);
                self.protected.extend(c.iter().copied());
                self.protected.extend(intermediate_out.iter().copied());
            }
            Op::Hint {
                inputs, outputs, ..
            } => {
                self.protected.extend(inputs.iter().chain(outputs).copied());
            }
            Op::NonPrimitiveOpWithExecutor {
                inputs, outputs, ..
            } => {
                self.protected
                    .extend(inputs.iter().chain(outputs).flatten().copied());
            }
        }
    }

    /// Returns duplicate and the exact retained operation index for the seen key.
    fn detect_duplicate<F: Field>(
        &mut self,
        op: &Op<F>,
        #[cfg(feature = "debugging")] retained_len: usize,
    ) -> Option<Duplicate> {
        let Op::Alu {
            kind,
            a,
            b,
            c,
            out,
            intermediate_out,
            ..
        } = op
        else {
            return None;
        };

        let key = AluKey::new(
            *kind,
            a.resolve(&self.rewrite),
            b.resolve(&self.rewrite),
            c.map(|id| id.resolve(&self.rewrite)),
        );
        // HornerAcc's accumulator is an independent input (the previous step's output)
        // that `AluKey` does not capture — unlike MulAdd's intermediate, which is fully
        // determined by `a * b`. Fold it into the dedup discriminator so two Horner steps
        // that differ only in their accumulator are never merged.
        let acc = match kind {
            AluOpKind::HornerAcc => intermediate_out.map(|id| id.resolve(&self.rewrite)),
            _ => None,
        };

        let protected_output = self.protected.contains(out).then_some(*out);
        let discriminator = (key, acc, protected_output);
        let retained = self.seen.get(&discriminator).copied().or_else(|| {
            let same_slot = self.seen.get(&(key, acc, None)).copied()?;
            #[cfg(feature = "debugging")]
            let canonical = same_slot.0;
            #[cfg(not(feature = "debugging"))]
            let canonical = same_slot;
            (protected_output.is_some() && canonical.resolve(&self.rewrite) == *out)
                .then_some(same_slot)
        });
        if let Some(retained) = retained {
            #[cfg(feature = "debugging")]
            let (canonical_output, retained_index) = retained;
            #[cfg(not(feature = "debugging"))]
            let canonical_output = retained;
            Some(Duplicate {
                duplicate_output: *out,
                canonical_output,
                #[cfg(feature = "debugging")]
                retained_index,
            })
        } else {
            #[cfg(feature = "debugging")]
            self.seen.insert(discriminator, (*out, retained_len));
            #[cfg(not(feature = "debugging"))]
            self.seen.insert(discriminator, *out);
            None
        }
    }
}

struct DedupResult<F> {
    ops: Vec<Op<F>>,
    rewrite: HashMap<WitnessId, WitnessId>,
    #[cfg(feature = "debugging")]
    origins: Option<Vec<Vec<ExprId>>>,
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use p3_test_utils::baby_bear_params::{BabyBear, PrimeCharacteristicRing};

    use super::*;
    use crate::CircuitBuilder;

    type F = BabyBear;

    #[test]
    fn an_existing_output_slot_keeps_both_of_its_constraints() {
        let [u, v, a, b, x, y] = core::array::from_fn(|i| WitnessId(i as u32));
        let ops: Vec<Op<F>> = vec![Op::add(u, v, x), Op::add(a, b, y), Op::add(a, b, x)];
        let (deduped, rewrite) = Deduplicator::with_capacity(ops.len()).run(ops.clone());
        assert_eq!(deduped, ops);
        assert!(!rewrite.contains_key(&x));
    }

    #[test]
    fn test_duplicated_op_fusion() {
        let a = WitnessId(0);
        let b = WitnessId(1);
        let c = WitnessId(2);
        let mul_out = WitnessId(3);
        let mul_out2 = WitnessId(5);
        let add_out = WitnessId(4);

        let ops: Vec<Op<F>> = vec![
            Op::mul(a, b, mul_out),
            Op::mul(a, b, mul_out2),
            Op::add(mul_out, c, add_out),
        ];

        let (deduped, rewrite) = Deduplicator::with_capacity(ops.len()).run(ops);

        assert_eq!(
            deduped,
            vec![Op::mul(a, b, mul_out), Op::add(mul_out, c, add_out)]
        );
        assert_eq!(rewrite.get(&mul_out2), Some(&mul_out));
    }

    #[test]
    fn test_duplicated_op_fusion_in_builder() {
        let mut builder = CircuitBuilder::<F>::new();
        let a = builder.define_const(F::TWO);
        let b = builder.public_input();
        let c = builder.public_input();

        builder.connect(b, c);
        builder.alloc_mul(a, b, "mul_result1");
        builder.alloc_mul(a, c, "mul_result2");

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();
        runner
            .set_public_inputs(&[F::from_u32(42), F::from_u32(42)])
            .unwrap();

        assert_eq!(runner.run().unwrap().alu_trace.values.len(), 1);
    }

    #[test]
    fn test_all_deduplicated_circuit() {
        let mut builder = CircuitBuilder::<F>::new();
        let a = builder.define_const(F::TWO);
        let b = builder.public_input();
        let r1 = builder.mul(a, b);
        let r2 = builder.mul(a, b);
        builder.connect(r1, r2);

        let circuit = builder.build().unwrap();
        let mut runner = circuit.runner();
        runner.set_public_inputs(&[F::from_u64(5)]).unwrap();

        let traces = runner.run().unwrap();
        let mul_count = traces
            .alu_trace
            .values
            .iter()
            .filter(|row| row[3] == F::from_u64(10))
            .count();
        assert_eq!(mul_count, 1, "Duplicate mul should be deduped");
    }

    #[test]
    fn test_empty_input() {
        let ops: Vec<Op<F>> = vec![];
        let (deduped, rewrite) = Deduplicator::with_capacity(ops.len()).run(ops);
        assert!(deduped.is_empty());
        assert!(rewrite.is_empty());
    }

    #[test]
    fn test_non_alu_ops_pass_through() {
        let ops: Vec<Op<F>> = vec![
            Op::Const {
                out: WitnessId(0),
                val: F::ONE,
            },
            Op::Const {
                out: WitnessId(1),
                val: F::TWO,
            },
        ];

        let (deduped, rewrite) = Deduplicator::with_capacity(ops.len()).run(ops.clone());
        assert_eq!(deduped, ops);
        assert!(rewrite.is_empty());
    }

    #[test]
    fn test_commutative_dedup_add() {
        let (a, b) = (WitnessId(0), WitnessId(1));
        let ops: Vec<Op<F>> = vec![
            Op::add(a, b, WitnessId(2)),
            Op::add(b, a, WitnessId(3)), // same as above (commutative)
        ];

        let (deduped, rewrite) = Deduplicator::with_capacity(ops.len()).run(ops);
        assert_eq!(deduped, vec![Op::add(a, b, WitnessId(2))]);
        assert_eq!(rewrite.get(&WitnessId(3)), Some(&WitnessId(2)));
    }

    #[test]
    fn test_commutative_dedup_mul() {
        let (a, b) = (WitnessId(0), WitnessId(1));
        let ops: Vec<Op<F>> = vec![Op::mul(a, b, WitnessId(2)), Op::mul(b, a, WitnessId(3))];

        let (deduped, rewrite) = Deduplicator::with_capacity(ops.len()).run(ops);
        assert_eq!(deduped, vec![Op::mul(a, b, WitnessId(2))]);
        assert_eq!(rewrite.get(&WitnessId(3)), Some(&WitnessId(2)));
    }

    #[test]
    fn test_chained_rewrite() {
        // op0: a + b = c
        // op1: a + b = d  (dup of op0, d -> c)
        // op2: d + a = e  (d rewrites to c, so this is c + a = e)
        // op3: c + a = f  (dup of op2 after rewrite, f -> e)
        let (a, b) = (WitnessId(0), WitnessId(1));
        let ops: Vec<Op<F>> = vec![
            Op::add(a, b, WitnessId(2)),
            Op::add(a, b, WitnessId(3)),
            Op::add(WitnessId(3), a, WitnessId(4)),
            Op::add(WitnessId(2), a, WitnessId(5)),
        ];

        let (deduped, rewrite) = Deduplicator::with_capacity(ops.len()).run(ops);
        assert_eq!(
            deduped,
            vec![
                Op::add(a, b, WitnessId(2)),
                Op::add(WitnessId(2), a, WitnessId(4)),
            ]
        );
        assert_eq!(rewrite.get(&WitnessId(3)), Some(&WitnessId(2)));
        assert_eq!(rewrite.get(&WitnessId(5)), Some(&WitnessId(4)));
    }

    #[test]
    fn test_distinct_ops_not_deduped() {
        let ops: Vec<Op<F>> = vec![
            Op::add(WitnessId(0), WitnessId(1), WitnessId(2)),
            Op::mul(WitnessId(0), WitnessId(1), WitnessId(3)),
        ];

        let (deduped, rewrite) = Deduplicator::with_capacity(ops.len()).run(ops.clone());
        assert_eq!(deduped, ops);
        assert!(rewrite.is_empty());
    }

    #[test]
    fn horner_acc_distinct_accumulators_not_deduped() {
        // Two HornerAcc ops with identical `(a, b, c)` but different accumulators must
        // NOT merge: the accumulator (`intermediate_out`) is an independent input. When
        // the dedup key ignored it, the second step was wrongly merged into the first,
        // dropping its accumulator binding.
        let (a, b, c) = (WitnessId(1), WitnessId(2), WitnessId(3));
        let ops: Vec<Op<F>> = vec![
            Op::horner_acc(a, b, c, WitnessId(20), WitnessId(10)),
            Op::horner_acc(a, b, c, WitnessId(21), WitnessId(11)),
        ];

        let (deduped, rewrite) = Deduplicator::with_capacity(ops.len()).run(ops.clone());
        assert_eq!(
            deduped, ops,
            "distinct accumulators must not be deduplicated"
        );
        assert!(rewrite.is_empty());
    }

    #[test]
    fn horner_acc_same_accumulator_deduped() {
        // Genuinely identical Horner steps (same `a, b, c` and accumulator) still dedup.
        let (a, b, c, acc) = (WitnessId(1), WitnessId(2), WitnessId(3), WitnessId(10));
        let ops: Vec<Op<F>> = vec![
            Op::horner_acc(a, b, c, WitnessId(20), acc),
            Op::horner_acc(a, b, c, WitnessId(21), acc),
        ];

        let (deduped, rewrite) = Deduplicator::with_capacity(ops.len()).run(ops);
        assert_eq!(deduped.len(), 1, "identical Horner steps should dedup");
        assert_eq!(rewrite.get(&WitnessId(21)), Some(&WitnessId(20)));
    }

    #[cfg(feature = "debugging")]
    #[test]
    fn origins_merge_by_exact_key_when_distinct_constraints_share_an_output() {
        let (a, b, c) = (WitnessId(0), WitnessId(1), WitnessId(2));
        let shared = WitnessId(3);
        let duplicate = WitnessId(4);
        let ops: Vec<Op<F>> = vec![
            Op::add(a, b, shared),
            Op::mul(a, c, shared),
            Op::add(b, a, duplicate),
        ];
        let sources = vec![vec![ExprId(10)], vec![ExprId(11)], vec![ExprId(12)]];
        let (kept, rewrite, origins) =
            Deduplicator::with_capacity(ops.len()).run_with_origins(ops, sources);
        assert_eq!(kept.len(), 2);
        assert_eq!(rewrite.get(&duplicate), Some(&shared));
        assert_eq!(
            origins,
            vec![vec![ExprId(10), ExprId(12)], vec![ExprId(11)]]
        );
    }
}
