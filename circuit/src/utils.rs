use alloc::vec::Vec;

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
pub fn symbolic_to_circuit<F: Field>(
    row_selectors: RowSelectorsTargets,
    columns: &ColumnsTargets<'_>,
    symbolic: &SymbolicExpression<F>,
    circuit: &mut CircuitBuilder<F>,
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

    let mut get_target =
        |s: &SymbolicExpression<F>| symbolic_to_circuit::<F>(row_selectors, columns, s, circuit);

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
            let x_target = get_target(x);
            let zero = circuit.add_const(F::ZERO);

            circuit.sub(zero, x_target)
        }
        SymbolicExpression::Add { x, y, .. }
        | SymbolicExpression::Sub { x, y, .. }
        | SymbolicExpression::Mul { x, y, .. } => {
            let x_target = get_target(x);
            let y_target = get_target(y);

            match symbolic {
                SymbolicExpression::Add { .. } => circuit.add(x_target, y_target),
                SymbolicExpression::Mul { .. } => circuit.mul(x_target, y_target),
                SymbolicExpression::Sub { .. } => circuit.sub(x_target, y_target),
                _ => unreachable!(),
            }
        }
    }
}

/// Reconstruct an integer (as a field element) from little-endian bits:
///   index = Σ b_i · 2^i
pub fn reconstruct_index_from_bits<F: Field>(
    builder: &mut CircuitBuilder<F>,
    bits: &[ExprId],
) -> ExprId {
    let mut acc = builder.add_const(F::ZERO);
    let mut pow2 = builder.add_const(F::ONE);
    for &b in bits {
        builder.assert_bool(b);
        let term = builder.mul(b, pow2);
        acc = builder.add(acc, term);
        pow2 = builder.add(pow2, pow2); // *= 2
    }
    acc
}

/// Decompose a field element into its little-endian bits.
///
/// For a given target `x`, this function creates `N_BITS` new boolean targets `b_i`
/// and adds constraints to enforce that:
///     x = Σ b_i · 2^i
pub fn decompose_to_bits<F: Field, const N_BITS: usize>(
    builder: &mut CircuitBuilder<F>,
    x: ExprId,
) -> Vec<ExprId> {
    let mut bits = Vec::with_capacity(N_BITS);

    // Create bit witness variables
    for _ in 0..N_BITS {
        let bit = builder.add_public_input(); // TODO: Should be witness
        builder.assert_bool(bit);
        bits.push(bit);
    }

    // Constrain that the bits reconstruct to the original element
    let reconstructed = reconstruct_index_from_bits(builder, &bits);
    builder.connect(x, reconstructed);

    bits
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
        let mut circuit = CircuitBuilder::<Challenge>::new();
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
        let sum = symbolic_to_circuit::<Challenge>(
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

    #[test]
    fn test_reconstruct_index_from_bits() {
        let mut builder = CircuitBuilder::<BabyBear>::new();

        // Test reconstructing the value 5 (binary: 101)
        let bit0 = builder.add_const(BabyBear::ONE); // 1
        let bit1 = builder.add_const(BabyBear::ZERO); // 0
        let bit2 = builder.add_const(BabyBear::ONE); // 1

        let bits = vec![bit0, bit1, bit2];
        let result = reconstruct_index_from_bits(&mut builder, &bits);

        // Connect result to a public input so we can verify its value
        let output = builder.add_public_input();
        builder.connect(result, output);

        // Build and run the circuit
        let circuit = builder.build().expect("Failed to build circuit");
        let mut runner = circuit.runner();

        // Set public inputs: the expected result value 5
        let expected_result = BabyBear::from_u64(5); // 1*1 + 0*2 + 1*4 = 5
        runner
            .set_public_inputs(&[expected_result])
            .expect("Failed to set public inputs");

        let traces = runner.run().expect("Failed to run circuit");

        // Just verify the calculation is correct - reconstruct gives us 5
        assert_eq!(traces.public_trace.values[0], BabyBear::from_u64(5));
    }

    #[test]
    fn test_decompose_to_bits() {
        let mut builder = CircuitBuilder::<BabyBear>::new();

        // Create a target representing the value we want to decompose
        let value = builder.add_const(BabyBear::from_u64(6)); // Binary: 110

        // Decompose into 3 bits - this creates its own public inputs for the bits
        let bits = decompose_to_bits::<BabyBear, 3>(&mut builder, value);

        // Build and run the circuit
        let circuit = builder.build().expect("Failed to build circuit");
        let mut runner = circuit.runner();

        // Set public inputs: expected bit decomposition of 6 (binary: 110) in little-endian
        let public_inputs = vec![
            BabyBear::ZERO, // bit 0: 0
            BabyBear::ONE,  // bit 1: 1
            BabyBear::ONE,  // bit 2: 1
        ];

        runner
            .set_public_inputs(&public_inputs)
            .expect("Failed to set public inputs");
        let traces = runner.run().expect("Failed to run circuit");

        // Verify the bits are correctly decomposed - 6 = [0,1,1] in little-endian
        assert_eq!(traces.public_trace.values[0], BabyBear::ZERO); // bit 0
        assert_eq!(traces.public_trace.values[1], BabyBear::ONE); // bit 1
        assert_eq!(traces.public_trace.values[2], BabyBear::ONE); // bit 2

        // Also verify that the returned bits have the expected length
        assert_eq!(bits.len(), 3);
    }
}
