use alloc::vec::Vec;
use core::iter;

use p3_air::lookup::LookupEvaluator;
use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, PermutationAirBuilder};
use p3_lookup::lookup_traits::{Direction, Lookup, LookupData, LookupInput};
use p3_uni_stark::{SymbolicExpression, SymbolicVariable};

pub fn get_index_lookups<AB: PermutationAirBuilder + AirBuilderWithPublicValues, const D: usize>(
    main_start: usize,
    preprocessed_start: usize,
    num_lookups: usize,
    main: &[SymbolicVariable<<AB as AirBuilder>::F>],
    preprocessed: &[SymbolicVariable<<AB as AirBuilder>::F>],
    direction: Direction,
) -> Vec<LookupInput<AB::F>> {
    (0..num_lookups)
        .map(|i| {
            let idx = SymbolicExpression::from(preprocessed[1 + preprocessed_start + i]);

            let multiplicity = SymbolicExpression::from(preprocessed[preprocessed_start]);

            let values = (0..D).map(|j| SymbolicExpression::from(main[main_start + i * D + j]));
            let inps = iter::once(idx).chain(values).collect::<Vec<_>>();

            (inps, multiplicity, direction)
        })
        .collect()
}

/// Object‑safe gadget shim.
pub trait LookupEvaluatorDyn<AB: PermutationAirBuilder + AirBuilderWithPublicValues> {
    fn num_aux_cols(&self) -> usize;
    fn num_challenges(&self) -> usize;
    fn eval_with_lookups_dyn(
        &self,
        builder: &mut AB,
        contexts: &[Lookup<AB::F>],
        lookup_data: &[LookupData<AB::ExprEF>],
    );
}

/// Blanket: any concrete `LookupEvaluator` becomes object‑safe.
impl<AB, LE> LookupEvaluatorDyn<AB> for LE
where
    AB: PermutationAirBuilder + AirBuilderWithPublicValues,
    LE: LookupEvaluator,
{
    fn num_aux_cols(&self) -> usize {
        LE::num_aux_cols(self)
    }
    fn num_challenges(&self) -> usize {
        LE::num_challenges(self)
    }
    fn eval_with_lookups_dyn(
        &self,
        builder: &mut AB,
        contexts: &[Lookup<AB::F>],
        lookup_data: &[LookupData<AB::ExprEF>],
    ) {
        // forward to the generic method on the concrete handler
        LE::eval_lookups(self, builder, contexts, lookup_data);
    }
}

/// Object‑safe AIR shim.
pub trait AirDyn<AB>
where
    AB: PermutationAirBuilder + AirBuilderWithPublicValues,
{
    fn add_lookup_columns_dyn(&mut self) -> Vec<usize>;
    fn get_lookups_dyn(&mut self) -> Vec<Lookup<AB::F>>;
    fn eval_with_lookups_dyn<LE: LookupEvaluator>(
        &self,
        builder: &mut AB,
        contexts: &[Lookup<AB::F>],
        lookup_data: &[LookupData<AB::ExprEF>],
        lookup_evaluator: &LE,
    );
}

/// Blanket: any existing `Air` now satisfies the object‑safe shim.
impl<AB, T> AirDyn<AB> for T
where
    AB: PermutationAirBuilder + AirBuilderWithPublicValues,
    T: Air<AB>,
{
    fn add_lookup_columns_dyn(&mut self) -> Vec<usize> {
        self.add_lookup_columns()
    }
    fn get_lookups_dyn(&mut self) -> Vec<Lookup<AB::F>> {
        self.get_lookups()
    }
    fn eval_with_lookups_dyn<LE: LookupEvaluator>(
        &self,
        builder: &mut AB,
        contexts: &[Lookup<AB::F>],
        lookup_data: &[LookupData<AB::ExprEF>],
        lookup_evaluator: &LE,
    ) {
        Air::<AB>::eval_with_lookups(self, builder, contexts, lookup_data, lookup_evaluator);
    }
}
