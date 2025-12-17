use alloc::vec;
use alloc::vec::Vec;

use hashbrown::HashMap;
use p3_field::Field;
use p3_uni_stark::{Entry, SymbolicExpression};

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
    /// Used when iterating through the DAG of expressions
    /// - `Eval` is used when visiting a node
    /// - `Build` is used to combine entries for a given `Op`
    enum Work<'a, F: Field> {
        Eval(&'a SymbolicExpression<F>),
        // Store a raw pointer instead of a reference because this removes lifetime handling
        // and its clear that we never dereference the node.
        // It binds the expression to the Op and its arity, so we can reuse the same node for different ops.
        Build(*const SymbolicExpression<F>, Op, usize),
    }

    /// Arithmetic ops applied when building parent nodes
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
        challenges,
        public_values,
        local_prep_values,
        next_prep_values,
        local_values,
        next_values,
    } = columns;

    let mut cache: HashMap<*const SymbolicExpression<F>, ExprId> = HashMap::new();
    let mut tasks = vec![Work::Eval(symbolic)];
    let mut stack = Vec::new();

    while let Some(work) = tasks.pop() {
        match work {
            Work::Eval(expr) => {
                let key = expr as *const _;
                if let Some(&cached) = cache.get(&key) {
                    stack.push(cached);
                    continue;
                }
                match expr {
                    SymbolicExpression::Constant(c) => {
                        let id = circuit.add_const(*c);
                        cache.insert(key, id);
                        stack.push(id);
                    }
                    SymbolicExpression::Variable(v) => {
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
                            Entry::Preprocessed { offset } => {
                                get_val(offset, v.index, local_prep_values, next_prep_values)
                            }
                            Entry::Main { offset } => {
                                get_val(offset, v.index, local_values, next_values)
                            }
                            Entry::Public => public_values[v.index],
                            Entry::Challenge => challenges[v.index],
                            _ => unimplemented!(),
                        };
                        cache.insert(key, id);
                        stack.push(id);
                    }
                    SymbolicExpression::IsFirstRow => stack.push(is_first_row),
                    SymbolicExpression::IsLastRow => stack.push(is_last_row),
                    SymbolicExpression::IsTransition => stack.push(is_transition),
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
                        let zero = circuit.add_const(F::ZERO);
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

/// Helper to pad trace values to power-of-two height with zeros
pub fn pad_to_power_of_two<F: Field>(values: &mut Vec<F>, width: usize, original_height: usize) {
    if original_height == 0 {
        // Empty trace - just ensure we have at least one row of zeros
        values.resize(width, F::ZERO);
        return;
    }

    let target_height = original_height.next_power_of_two();
    if target_height == original_height {
        return; // Already power of two
    }

    // Pad with zeroes
    for _ in original_height..target_height {
        values.extend_from_slice(&vec![F::ZERO; width]);
    }
}

#[cfg(test)]
mod tests {
    use p3_air::{Air, BaseAir};
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
    use rand::{RngCore, SeedableRng};

    use super::*;

    type F = BabyBear;
    const D: usize = 4;
    type Challenge = BinomialExtensionField<F, D>;
    type Dft = Radix2DitParallel<F>;
    type Perm = Poseidon2BabyBear<16>;
    type MyHash = PaddingFreeSponge<Perm, 16, 8, 8>;
    type MyCompress = TruncatedPermutation<Perm, 2, 8, 16>;
    type ValMmcs =
        MerkleTreeMmcs<<F as Field>::Packing, <F as Field>::Packing, MyHash, MyCompress, 8>;
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

        // Fold the constraints using random values for the trace and selectors.
        let mut folder: VerifierConstraintFolder<'_, MyConfig> = VerifierConstraintFolder {
            main,
            preprocessed: None,
            public_values: &pis,
            is_first_row: sels[0],
            is_last_row: sels[1],
            is_transition: sels[2],
            alpha,
            accumulator: Challenge::ZERO,
        };
        air.eval(&mut folder);
        let folded_constraints = folder.accumulator;

        // Get the symbolic constraints from `FibonacciAir`.
        let symbolic_constraints: Vec<p3_uni_stark::SymbolicExpression<Challenge>> =
            get_symbolic_constraints(&air, 0, pis.len());

        // Fold the symbolic constraints using `alpha`.
        let folded_symbolic_constraints = {
            let mut acc = SymbolicExpression::<Challenge>::Constant(Challenge::ZERO);
            let ch = SymbolicExpression::Constant(alpha);
            for s_c in symbolic_constraints.iter() {
                acc = ch.clone() * acc;
                acc += s_c.clone();
            }
            acc
        };

        // Build a circuit adding public inputs for `sels`, public values, local values and next values.
        let mut circuit = CircuitBuilder::new();
        let circuit_sels = [
            circuit.add_public_input(),
            circuit.add_public_input(),
            circuit.add_public_input(),
        ];
        let circuit_public_values = [
            circuit.add_public_input(),
            circuit.add_public_input(),
            circuit.add_public_input(),
        ];
        let mut circuit_local_values = Vec::with_capacity(NUM_FIBONACCI_COLS);
        let mut circuit_next_values = Vec::with_capacity(NUM_FIBONACCI_COLS);
        for _ in 0..NUM_FIBONACCI_COLS {
            circuit_local_values.push(circuit.add_public_input());
            circuit_next_values.push(circuit.add_public_input());
        }

        let row_selectors = RowSelectorsTargets {
            is_first_row: circuit_sels[0],
            is_last_row: circuit_sels[1],
            is_transition: circuit_sels[2],
        };

        let columns = ColumnsTargets {
            challenges: &[],
            public_values: &circuit_public_values,
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
        let final_result_const = circuit.add_const(folded_constraints);
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

    #[test]
    fn test_pad_to_power_of_two_basic() {
        // Test with 3 rows -> should pad to 4
        let mut values = vec![
            F::from_u64(1),
            F::from_u64(10), // row 0: [value=1, index=10]
            F::from_u64(2),
            F::from_u64(11), // row 1: [value=2, index=11]
            F::from_u64(3),
            F::from_u64(12), // row 2: [value=3, index=12]
        ];
        let width = 2;
        let original_height = 3;

        pad_to_power_of_two(&mut values, width, original_height);

        // Should be padded to 4 rows
        assert_eq!(values.len(), 4 * width);

        // Original rows should be unchanged
        assert_eq!(values[0], F::from_u64(1));
        assert_eq!(values[1], F::from_u64(10));
        assert_eq!(values[2], F::from_u64(2));
        assert_eq!(values[3], F::from_u64(11));
        assert_eq!(values[4], F::from_u64(3));
        assert_eq!(values[5], F::from_u64(12));

        // Padded row should be zero
        assert_eq!(values[6], F::ZERO); // same as row 2
        assert_eq!(values[7], F::ZERO); // same as row 2
    }

    #[test]
    fn test_pad_to_power_of_two_already_power_of_two() {
        // Test with 4 rows (already power of two) -> should not change
        let mut values = vec![
            F::from_u64(1),
            F::from_u64(2),
            F::from_u64(3),
            F::from_u64(4),
            F::from_u64(5),
            F::from_u64(6),
            F::from_u64(7),
            F::from_u64(8),
        ];
        let original = values.clone();
        let width = 2;
        let original_height = 4;

        pad_to_power_of_two(&mut values, width, original_height);

        // Should remain unchanged
        assert_eq!(values, original);
        assert_eq!(values.len(), 4 * width);
    }
}
