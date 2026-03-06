use alloc::vec;
use alloc::vec::Vec;

use hashbrown::HashMap;
use p3_air::{BaseEntry, BaseLeaf, ExtEntry, ExtLeaf, SymbolicExpressionExt};
use p3_field::{ExtensionField, Field};
use p3_uni_stark::SymbolicExpression;

use crate::{CircuitBuilder, ExprId};

/// Identifiers for special row selector flags in the circuit.
#[derive(Clone, Copy, Debug)]
pub struct RowSelectorsTargets {
    pub is_first_row: ExprId,
    pub is_last_row: ExprId,
    pub is_transition: ExprId,
}

/// Targets for all columns in the circuit.
#[derive(Clone, Debug)]
pub struct ColumnsTargets<'a> {
    /// Challenges added to the circuit.
    pub challenges: &'a [ExprId],
    /// Public values added to the circuit.
    pub public_values: &'a [ExprId],
    /// Targets for the permutation values used in the circuit.
    pub permutation_local_values: &'a [ExprId],
    /// Targets for the permutation values evaluated at the next row.
    pub permutation_next_values: &'a [ExprId],
    /// Targets for the global lookup expected cumulated values (PermutationValue entries).
    pub permutation_values: &'a [ExprId],
    /// Targets for the preprocessed values used in the circuit.
    pub local_prep_values: &'a [ExprId],
    /// Targets for the preprocessed values evaluated at the next row.
    pub next_prep_values: &'a [ExprId],
    /// Targets for the main trace values.
    pub local_values: &'a [ExprId],
    /// Targets for the main trace values evaluated at the next row.
    pub next_values: &'a [ExprId],
}

/// Given symbolic constraints, adds the corresponding recursive circuit to `circuit`.
/// The `public_values`, `local_prep_values`, `next_prep_values`, `local_values`, and `next_values`
/// are assumed to be in the same order as those used to create the symbolic expressions.
// Recursive approaches blowup quickly, so this takes an iterative DAG approach with
// some caching of `SymbolicExpression` nodes.
pub fn symbolic_to_circuit<F: Field>(
    row_selectors: RowSelectorsTargets,
    columns: &ColumnsTargets<'_>,
    symbolic: &SymbolicExpression<F>,
    circuit: &mut CircuitBuilder<F>,
) -> ExprId {
    let mut cache = HashMap::new();
    symbolic_to_circuit_core(row_selectors, columns, symbolic, circuit, &mut cache, |c| c)
}

/// Convert base-field symbolic constraints to extension-field circuit operations.
///
/// Unlike [`symbolic_to_circuit`], this accepts `SymbolicExpression<F>` (base field)
/// with a `CircuitBuilder<EF>` (extension field), lifting constants via `EF::from(c)`.
///
/// Converting directly the tree SymbolicExpression<F> → SymbolicExpression<EF>
/// destroys Arc-based sub-expression sharing and causes exponential blowup.
/// Instead, we lift F → EF constants directly.
///
/// Additionally, the `cache` is shared across all constraint calls to reuse circuit
/// operations for sub-expressions shared between different constraints.
pub fn symbolic_to_circuit_base<F: Field, EF: ExtensionField<F>>(
    row_selectors: RowSelectorsTargets,
    columns: &ColumnsTargets<'_>,
    symbolic: &SymbolicExpression<F>,
    circuit: &mut CircuitBuilder<EF>,
    cache: &mut HashMap<*const SymbolicExpression<F>, ExprId>,
) -> ExprId {
    symbolic_to_circuit_core(row_selectors, columns, symbolic, circuit, cache, EF::from)
}

/// Convert extension-field symbolic constraints to circuit operations with an external cache.
///
/// Same as [`symbolic_to_circuit`] but with an external `cache` to allow sharing across
/// multiple calls.
pub fn symbolic_to_circuit_ext<F: Field>(
    row_selectors: RowSelectorsTargets,
    columns: &ColumnsTargets<'_>,
    symbolic: &SymbolicExpression<F>,
    circuit: &mut CircuitBuilder<F>,
    cache: &mut HashMap<*const SymbolicExpression<F>, ExprId>,
) -> ExprId {
    symbolic_to_circuit_core(row_selectors, columns, symbolic, circuit, cache, |c| c)
}

/// Convert extension-field [`SymbolicExpressionExt`] constraints to circuit operations.
///
/// Handles the split representation where extension expressions can embed
/// base-field sub-trees via [`ExtLeaf::Base`], extension-field variables
/// (permutation columns / challenges) via [`ExtLeaf::ExtVariable`], and
/// extension-field constants via [`ExtLeaf::ExtConstant`].
pub fn symbolic_ext_expr_to_circuit<F: Field, EF: ExtensionField<F>>(
    row_selectors: RowSelectorsTargets,
    columns: &ColumnsTargets<'_>,
    symbolic: &SymbolicExpressionExt<F, EF>,
    circuit: &mut CircuitBuilder<EF>,
    base_cache: &mut HashMap<*const SymbolicExpression<F>, ExprId>,
    ext_cache: &mut HashMap<*const SymbolicExpressionExt<F, EF>, ExprId>,
) -> ExprId {
    enum Work<'a, F: Field, EF> {
        Eval(&'a SymbolicExpressionExt<F, EF>),
        Build(*const SymbolicExpressionExt<F, EF>, Op, usize),
    }

    #[derive(Copy, Clone)]
    enum Op {
        Add,
        Sub,
        Mul,
        Neg,
    }

    let mut tasks = vec![Work::Eval(symbolic)];
    let mut stack = Vec::with_capacity(16);

    while let Some(work) = tasks.pop() {
        match work {
            Work::Eval(expr) => {
                let key = expr as *const _;
                if let Some(&cached) = ext_cache.get(&key) {
                    stack.push(cached);
                    continue;
                }
                match expr {
                    SymbolicExpressionExt::Leaf(ExtLeaf::Base(base_expr)) => {
                        let id = symbolic_to_circuit_base(
                            row_selectors,
                            columns,
                            base_expr,
                            circuit,
                            base_cache,
                        );
                        ext_cache.insert(key, id);
                        stack.push(id);
                    }
                    SymbolicExpressionExt::Leaf(ExtLeaf::ExtVariable(v)) => {
                        let id = match v.entry {
                            ExtEntry::Permutation { offset } => match offset {
                                0 => columns.permutation_local_values[v.index],
                                1 => columns.permutation_next_values[v.index],
                                _ => {
                                    panic!("Cannot have expressions involving more than two rows.")
                                }
                            },
                            ExtEntry::Challenge => columns.challenges[v.index],
                            ExtEntry::PermutationValue => columns.permutation_values[v.index],
                        };
                        ext_cache.insert(key, id);
                        stack.push(id);
                    }
                    SymbolicExpressionExt::Leaf(ExtLeaf::ExtConstant(c)) => {
                        let id = circuit.define_const(*c);
                        ext_cache.insert(key, id);
                        stack.push(id);
                    }
                    SymbolicExpressionExt::Neg { x, .. } => {
                        tasks.push(Work::Build(key, Op::Neg, 1));
                        tasks.push(Work::Eval(x));
                    }
                    SymbolicExpressionExt::Add { x, y, .. } => {
                        tasks.push(Work::Build(key, Op::Add, 2));
                        tasks.push(Work::Eval(y));
                        tasks.push(Work::Eval(x));
                    }
                    SymbolicExpressionExt::Sub { x, y, .. } => {
                        tasks.push(Work::Build(key, Op::Sub, 2));
                        tasks.push(Work::Eval(y));
                        tasks.push(Work::Eval(x));
                    }
                    SymbolicExpressionExt::Mul { x, y, .. } => {
                        tasks.push(Work::Build(key, Op::Mul, 2));
                        tasks.push(Work::Eval(y));
                        tasks.push(Work::Eval(x));
                    }
                }
            }
            Work::Build(key, op, arity) => {
                let rhs = stack.pop().expect("rhs");
                let lhs = if arity == 2 {
                    stack.pop().expect("lhs")
                } else {
                    rhs
                };
                let id = match op {
                    Op::Add => circuit.add(lhs, rhs),
                    Op::Sub => circuit.sub(lhs, rhs),
                    Op::Mul => circuit.mul(lhs, rhs),
                    Op::Neg => {
                        let zero = circuit.define_const(EF::ZERO);
                        circuit.sub(zero, rhs)
                    }
                };
                ext_cache.insert(key, id);
                stack.push(id);
            }
        }
    }

    stack.pop().expect("final target")
}

/// Core implementation of symbolic-to-circuit conversion.
///
/// Generic over the expression constant field (`CF`) and circuit field (`F`).
/// `convert_const` lifts expression constants from `CF` to `F`.
fn symbolic_to_circuit_core<CF: Field, F: Field>(
    row_selectors: RowSelectorsTargets,
    columns: &ColumnsTargets<'_>,
    symbolic: &SymbolicExpression<CF>,
    circuit: &mut CircuitBuilder<F>,
    cache: &mut HashMap<*const SymbolicExpression<CF>, ExprId>,
    convert_const: impl Fn(CF) -> F,
) -> ExprId {
    enum Work<'a, CF: Field> {
        Eval(&'a SymbolicExpression<CF>),
        Build(*const SymbolicExpression<CF>, Op, usize),
    }

    #[derive(Copy, Clone)]
    enum Op {
        Add,
        Sub,
        Mul,
        Neg,
    }

    let RowSelectorsTargets {
        is_first_row,
        is_last_row,
        is_transition,
    } = row_selectors;

    let ColumnsTargets {
        challenges: _,
        public_values,
        permutation_local_values: _,
        permutation_next_values: _,
        permutation_values: _,
        local_prep_values,
        next_prep_values,
        local_values,
        next_values,
    } = columns;

    let mut tasks = vec![Work::Eval(symbolic)];
    let mut stack = Vec::with_capacity(16);

    while let Some(work) = tasks.pop() {
        match work {
            Work::Eval(expr) => {
                let key = expr as *const _;
                if let Some(&cached) = cache.get(&key) {
                    stack.push(cached);
                    continue;
                }
                match expr {
                    SymbolicExpression::Leaf(BaseLeaf::Constant(c)) => {
                        let id = circuit.define_const(convert_const(*c));
                        cache.insert(key, id);
                        stack.push(id);
                    }
                    SymbolicExpression::Leaf(BaseLeaf::Variable(v)) => {
                        let get_val =
                            |offset: usize,
                             index: usize,
                             local_vals: &[ExprId],
                             next_vals: &[ExprId]| match offset {
                                0 => local_vals[index],
                                1 => next_vals[index],
                                _ => {
                                    panic!("Cannot have expressions involving more than two rows.")
                                }
                            };
                        let id = match v.entry {
                            BaseEntry::Preprocessed { offset } => {
                                get_val(offset, v.index, local_prep_values, next_prep_values)
                            }
                            BaseEntry::Main { offset } => {
                                get_val(offset, v.index, local_values, next_values)
                            }
                            BaseEntry::Public => public_values[v.index],
                            BaseEntry::Periodic => {
                                unimplemented!(
                                    "Periodic values are not supported in symbolic_to_circuit"
                                )
                            }
                        };
                        cache.insert(key, id);
                        stack.push(id);
                    }
                    SymbolicExpression::Leaf(BaseLeaf::IsFirstRow) => stack.push(is_first_row),
                    SymbolicExpression::Leaf(BaseLeaf::IsLastRow) => stack.push(is_last_row),
                    SymbolicExpression::Leaf(BaseLeaf::IsTransition) => stack.push(is_transition),
                    SymbolicExpression::Neg { x, .. } => {
                        tasks.push(Work::Build(key, Op::Neg, 1));
                        tasks.push(Work::Eval(x));
                    }
                    SymbolicExpression::Add { x, y, .. } => {
                        tasks.push(Work::Build(key, Op::Add, 2));
                        tasks.push(Work::Eval(y));
                        tasks.push(Work::Eval(x));
                    }
                    SymbolicExpression::Sub { x, y, .. } => {
                        tasks.push(Work::Build(key, Op::Sub, 2));
                        tasks.push(Work::Eval(y));
                        tasks.push(Work::Eval(x));
                    }
                    SymbolicExpression::Mul { x, y, .. } => {
                        tasks.push(Work::Build(key, Op::Mul, 2));
                        tasks.push(Work::Eval(y));
                        tasks.push(Work::Eval(x));
                    }
                }
            }
            Work::Build(key, op, arity) => {
                let rhs = stack.pop().expect("rhs");
                let lhs = if arity == 2 {
                    stack.pop().expect("lhs")
                } else {
                    rhs // placeholder; for Neg we overwrite below
                };
                let id = match op {
                    Op::Add => circuit.add(lhs, rhs),
                    Op::Sub => circuit.sub(lhs, rhs),
                    Op::Mul => circuit.mul(lhs, rhs),
                    Op::Neg => {
                        let zero = circuit.define_const(F::ZERO);
                        circuit.sub(zero, rhs)
                    }
                };
                cache.insert(key, id);
                stack.push(id);
            }
        }
    }

    stack.pop().expect("final target")
}

#[cfg(test)]
mod tests {
    use p3_air::{Air, AirLayout, BaseAir, RowWindow};
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::DuplexChallenger;
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::extension::BinomialExtensionField;
    use p3_field::integers::QuotientMap;
    use p3_fri::TwoAdicFriPcs;
    use p3_matrix::dense::RowMajorMatrixView;
    use p3_matrix::stack::VerticalPair;
    use p3_merkle_tree::MerkleTreeMmcs;
    use p3_symmetric::{PaddingFreeSponge, TruncatedPermutation};
    use p3_uni_stark::{
        StarkConfig, SymbolicExpression, VerifierConstraintFolder, get_symbolic_constraints,
    };
    use rand::rngs::SmallRng;
    use rand::{Rng, SeedableRng};

    use super::*;

    type F = BabyBear;
    const D: usize = 4;
    type Challenge = BinomialExtensionField<F, D>;
    type Dft = Radix2DitParallel<F>;
    type Perm = Poseidon2BabyBear<16>;
    type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
    type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    type ValMmcs =
        MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, MyHash, MyCompress, 2, 8>;
    type ChallengeMmcs = ExtensionMmcs<F, Challenge, ValMmcs>;
    type Challenger = DuplexChallenger<F, Perm, 16, 8>;
    type MyPcs = TwoAdicFriPcs<F, Dft, ValMmcs, ChallengeMmcs>;
    type MyConfig = StarkConfig<MyPcs, Challenge, Challenger>;
    use p3_field::PrimeCharacteristicRing;

    use crate::test_utils::{FibonacciAir, NUM_FIBONACCI_COLS};
    use crate::utils::{ColumnsTargets, RowSelectorsTargets, symbolic_to_circuit};
    use crate::{CircuitBuilder, CircuitError};

    #[test]
    fn test_symbolic_to_circuit() -> Result<(), CircuitError> {
        let mut rng = SmallRng::seed_from_u64(1);
        let x = 21;

        let pis = vec![F::ZERO, F::ONE, F::from_u64(x)];
        let pis_ext = pis
            .iter()
            .map(|c| Challenge::from_prime_subfield(*c))
            .collect::<Vec<_>>();

        let air = FibonacciAir {};

        let alpha = Challenge::from_u64(rng.next_u64());

        // Let us simulate the constraints folding.
        // First, get random values for the trace.
        let width = <FibonacciAir as BaseAir<F>>::width(&air);
        let mut trace_local = Vec::with_capacity(width);
        let mut trace_next = Vec::with_capacity(width);
        for _ in 0..width {
            trace_local.push(Challenge::from_prime_subfield(F::from_int(rng.next_u64())));
            trace_next.push(Challenge::from_prime_subfield(F::from_int(rng.next_u64())));
        }
        let main = VerticalPair::new(
            RowMajorMatrixView::new_row(&trace_local),
            RowMajorMatrixView::new_row(&trace_next),
        );

        // Get random values for the selectors.
        let sels = [
            Challenge::from_u64(rng.next_u64()),
            Challenge::from_u64(rng.next_u64()),
            Challenge::from_u64(rng.next_u64()),
        ];

        let preprocessed = VerticalPair::new(
            RowMajorMatrixView::new(&[], 0),
            RowMajorMatrixView::new(&[], 0),
        );

        let preprocessed_window =
            RowWindow::from_two_rows(preprocessed.top.values, preprocessed.bottom.values);

        // Fold the constraints using random values for the trace and selectors.
        let mut folder: VerifierConstraintFolder<'_, MyConfig> = VerifierConstraintFolder {
            main,
            preprocessed,
            preprocessed_window,
            public_values: &pis,
            is_first_row: sels[0],
            is_last_row: sels[1],
            is_transition: sels[2],
            alpha,
            accumulator: Challenge::ZERO,
        };
        air.eval(&mut folder);
        let folded_constraints = folder.accumulator;

        let layout = AirLayout {
            preprocessed_width: 3,
            main_width: BaseAir::<F>::width(&air),
            num_public_values: BaseAir::<F>::num_public_values(&air),
            permutation_width: 0,
            num_permutation_challenges: 0,
            num_permutation_values: 0,
            num_periodic_columns: 0,
        };

        // Get the symbolic constraints from `FibonacciAir`.
        let symbolic_constraints: Vec<p3_uni_stark::SymbolicExpression<Challenge>> =
            get_symbolic_constraints(&air, layout);

        // Fold the symbolic constraints using `alpha`.
        let folded_symbolic_constraints = {
            let mut acc =
                SymbolicExpression::<Challenge>::Leaf(BaseLeaf::Constant(Challenge::ZERO));
            let ch = SymbolicExpression::Leaf(BaseLeaf::Constant(alpha));
            for s_c in symbolic_constraints.iter() {
                acc = ch.clone() * acc;
                acc += s_c.clone();
            }
            acc
        };

        // Build a circuit adding public inputs for `sels`, public values, local values and next values.
        let mut circuit = CircuitBuilder::new();
        let circuit_sels = [
            circuit.public_input(),
            circuit.public_input(),
            circuit.public_input(),
        ];
        let circuit_public_values = [
            circuit.public_input(),
            circuit.public_input(),
            circuit.public_input(),
        ];
        let mut circuit_local_values = Vec::with_capacity(NUM_FIBONACCI_COLS);
        let mut circuit_next_values = Vec::with_capacity(NUM_FIBONACCI_COLS);
        for _ in 0..NUM_FIBONACCI_COLS {
            circuit_local_values.push(circuit.public_input());
            circuit_next_values.push(circuit.public_input());
        }

        let row_selectors = RowSelectorsTargets {
            is_first_row: circuit_sels[0],
            is_last_row: circuit_sels[1],
            is_transition: circuit_sels[2],
        };

        let columns = ColumnsTargets {
            challenges: &[],
            public_values: &circuit_public_values,
            permutation_local_values: &[],
            permutation_next_values: &[],
            permutation_values: &[],
            local_prep_values: &[],
            next_prep_values: &[],
            local_values: &circuit_local_values,
            next_values: &circuit_next_values,
        };

        // Get the circuit for the folded constraints.
        let sum = symbolic_to_circuit(
            row_selectors,
            &columns,
            &folded_symbolic_constraints,
            &mut circuit,
        );

        // Check that the circuit output equals the folded constraints.
        let final_result_const = circuit.define_const(folded_constraints);
        circuit.connect(final_result_const, sum);

        let mut all_public_values = sels.to_vec();
        all_public_values.extend_from_slice(&pis_ext);
        for i in 0..NUM_FIBONACCI_COLS {
            all_public_values.push(trace_local[i]);
            all_public_values.push(trace_next[i]);
        }

        let builder = circuit.build().unwrap();
        let mut builder = builder.runner();
        builder.set_public_inputs(&all_public_values).unwrap();
        let _ = builder.run()?;

        Ok(())
    }
}
