use core::array;

use p3_field::Field;
use p3_symmetric::PseudoCompressionFunction;
use p3_uni_stark::{Entry, SymbolicExpression};

use crate::config::MerkleVerifyConfig;
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
pub fn symbolic_to_circuit<F: Field, C: MerkleVerifyConfig>(
    row_selectors: RowSelectorsTargets,
    columns: &ColumnsTargets<'_>,
    symbolic: &SymbolicExpression<F>,
    circuit: &mut CircuitBuilder<F, C>,
) -> ExprId {
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

    let mut get_wire =
        |s: &SymbolicExpression<F>| symbolic_to_circuit(row_selectors, columns, s, circuit);

    match symbolic {
        SymbolicExpression::Constant(c) => circuit.add_const(*c),
        SymbolicExpression::Variable(v) => {
            let get_val =
                |offset: usize, index: usize, local_vals: &[ExprId], next_vals: &[ExprId]| {
                    match offset {
                        0 => local_vals[index],
                        1 => next_vals[index],
                        _ => panic!("Cannot have expressions involving more than two rows."),
                    }
                };

            match v.entry {
                Entry::Preprocessed { offset } => {
                    get_val(offset, v.index, local_prep_values, next_prep_values)
                }
                Entry::Main { offset } => get_val(offset, v.index, local_values, next_values),
                Entry::Public => public_values[v.index],
                Entry::Challenge => challenges[v.index],
                _ => unimplemented!(),
            }
        }
        SymbolicExpression::IsFirstRow => is_first_row,
        SymbolicExpression::IsLastRow => is_last_row,
        SymbolicExpression::IsTransition => is_transition,
        SymbolicExpression::Neg { x, .. } => {
            let x_wire = get_wire(x);
            let zero = circuit.add_const(F::ZERO);

            circuit.sub(zero, x_wire)
        }
        SymbolicExpression::Add { x, y, .. }
        | SymbolicExpression::Sub { x, y, .. }
        | SymbolicExpression::Mul { x, y, .. } => {
            let x_wire = get_wire(x);
            let y_wire = get_wire(y);

            match symbolic {
                SymbolicExpression::Add { .. } => circuit.add(x_wire, y_wire),
                SymbolicExpression::Mul { .. } => circuit.mul(x_wire, y_wire),
                SymbolicExpression::Sub { .. } => circuit.sub(x_wire, y_wire),
                _ => unreachable!(),
            }
        }
    }
}

#[derive(Clone)]
pub struct MockCompression {}

impl<F: Field, const DIGEST_ELEMS: usize> PseudoCompressionFunction<[F; DIGEST_ELEMS], 2>
    for MockCompression
{
    fn compress(&self, input: [[F; DIGEST_ELEMS]; 2]) -> [F; DIGEST_ELEMS] {
        array::from_fn(|i| input[0][i] - input[1][i])
    }
}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;

    use p3_air::{Air, BaseAir};
    use p3_baby_bear::{BabyBear, Poseidon2BabyBear};
    use p3_challenger::DuplexChallenger;
    use p3_commit::ExtensionMmcs;
    use p3_dft::Radix2DitParallel;
    use p3_field::Field;
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

    use crate::CircuitError;
    use crate::config::babybear_config::BabyBearQuarticExtensionCircuitBuilder;
    use crate::test_utils::{FibonacciAir, NUM_FIBONACCI_COLS};
    use crate::utils::{ColumnsTargets, RowSelectorsTargets, symbolic_to_circuit};

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
        let mut circuit = BabyBearQuarticExtensionCircuitBuilder::new();
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

        let runner = circuit.build().unwrap();
        let mut runner = runner.runner();
        runner.set_public_inputs(&all_public_values).unwrap();
        let _ = runner.run()?;

        Ok(())
    }
}
