//! Trait for recursive AIR constraint evaluation.

use p3_air::Air;
use p3_circuit::CircuitBuilder;
use p3_circuit::utils::{ColumnsTargets, symbolic_to_circuit};
use p3_field::Field;
use p3_uni_stark::{SymbolicAirBuilder, get_log_quotient_degree, get_symbolic_constraints};

use crate::Target;
use crate::types::RecursiveLagrangeSelectors;

/// Trait for evaluating AIR constraints within a recursive verification circuit.
///
/// This trait provides methods for computing constraint evaluations over circuit targets
/// rather than concrete field values.
pub trait RecursiveAir<F: Field> {
    /// Returns the number of columns in the AIR's execution trace.
    ///
    /// This corresponds to the width of the trace matrix.
    fn width(&self) -> usize;

    /// Evaluate all AIR constraints and fold them into a single target.
    ///
    /// This method:
    /// 1. Retrieves all symbolic constraints from the AIR
    /// 2. Converts them to circuit targets
    /// 3. Folds them using powers of alpha: acc = acc * alpha + constraint
    ///
    /// # Parameters
    /// - `builder`: Circuit builder for creating operations
    /// - `sels`: Row selectors and vanishing inverse for constraint evaluation
    /// - `alpha`: Challenge used for folding constraints
    /// - `columns`: Trace columns (local, next) and public values
    ///
    /// # Returns
    /// A single target representing the folded constraint evaluation
    fn eval_folded_circuit(
        &self,
        builder: &mut CircuitBuilder<F>,
        sels: &RecursiveLagrangeSelectors,
        alpha: &Target,
        columns: ColumnsTargets,
    ) -> Target;

    /// Compute the log of the quotient polynomial degree.
    ///
    /// The quotient polynomial is formed by dividing the constraint polynomial
    /// by the vanishing polynomial. Its degree depends on:
    /// - The maximum constraint degree
    /// - Number of public values
    /// - Whether ZK randomization is used
    ///
    /// # Parameters
    /// - `num_public_values`: Number of public input values
    /// - `is_zk`: Whether ZK mode is enabled (0 or 1)
    ///
    /// # Returns
    /// Log₂ of the quotient degree
    fn get_log_quotient_degree(
        &self,
        preprocessed_width: usize,
        num_public_values: usize,
        is_zk: usize,
    ) -> usize;
}

impl<F: Field, A> RecursiveAir<F> for A
where
    A: Air<SymbolicAirBuilder<F>>,
{
    fn width(&self) -> usize {
        Self::width(self)
    }

    fn eval_folded_circuit(
        &self,
        builder: &mut CircuitBuilder<F>,
        sels: &RecursiveLagrangeSelectors,
        alpha: &Target,
        columns: ColumnsTargets,
    ) -> Target {
        builder.push_scope("eval_folded_circuit");

        let num_preprocessed = columns.local_prep_values.len();
        // Get symbolic constraints from the AIR
        let symbolic_constraints =
            get_symbolic_constraints(self, num_preprocessed, columns.public_values.len());

        // Fold all constraints: result = c₀ + α·c₁ + α²·c₂ + ...
        let mut acc = builder.add_const(F::ZERO);
        for s_c in symbolic_constraints {
            let mul_prev = builder.mul(acc, *alpha);
            let constraints = symbolic_to_circuit(sels.row_selectors, &columns, &s_c, builder);
            acc = builder.add(mul_prev, constraints);
        }
        builder.pop_scope();
        acc
    }

    fn get_log_quotient_degree(
        &self,
        preprocessed_width: usize,
        num_public_values: usize,
        is_zk: usize,
    ) -> usize {
        get_log_quotient_degree(self, preprocessed_width, num_public_values, is_zk)
    }
}
