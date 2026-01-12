use alloc::vec::Vec;
use core::iter;

use p3_air::{Air, AirBuilder, AirBuilderWithPublicValues, PairBuilder, PermutationAirBuilder};
use p3_lookup::lookup_traits::{
    AirLookupHandler, Direction, Lookup, LookupData, LookupGadget, LookupInput,
};
use p3_uni_stark::{SymbolicExpression, SymbolicVariable};

pub fn get_index_lookups<
    AB: PermutationAirBuilder + PairBuilder + AirBuilderWithPublicValues,
    const D: usize,
>(
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
pub trait LookupGadgetDyn<AB: PermutationAirBuilder + PairBuilder + AirBuilderWithPublicValues> {
    fn num_aux_cols(&self) -> usize;
    fn num_challenges(&self) -> usize;
    fn eval_lookups_dyn(
        &self,
        builder: &mut AB,
        contexts: &[Lookup<AB::F>],
        lookup_data: &[LookupData<AB::ExprEF>],
    );
}

/// Blanket: any concrete `LookupGadget` becomes object‑safe.
impl<AB, LG> LookupGadgetDyn<AB> for LG
where
    AB: PermutationAirBuilder + PairBuilder + AirBuilderWithPublicValues,
    LG: LookupGadget,
{
    fn num_aux_cols(&self) -> usize {
        LG::num_aux_cols(self)
    }
    fn num_challenges(&self) -> usize {
        LG::num_challenges(self)
    }
    fn eval_lookups_dyn(
        &self,
        builder: &mut AB,
        contexts: &[Lookup<AB::F>],
        lookup_data: &[LookupData<AB::ExprEF>],
    ) {
        // forward to the generic method on the concrete handler
        LG::eval_lookups(self, builder, contexts, lookup_data);
    }
}

/// Object‑safe AIR lookup handler shim.
pub trait AirLookupHandlerDyn<AB>
where
    AB: PermutationAirBuilder + PairBuilder + AirBuilderWithPublicValues,
{
    fn add_lookup_columns_dyn(&mut self) -> Vec<usize>;
    fn get_lookups_dyn(&mut self) -> Vec<Lookup<AB::F>>;
    fn eval_lookups_dyn(
        &self,
        builder: &mut AB,
        contexts: &[Lookup<AB::F>],
        lookup_data: &[LookupData<AB::ExprEF>],
        gadget: &dyn LookupGadgetDyn<AB>,
    );
}

/// Blanket: any existing `AirLookupHandler` now satisfies the object‑safe shim.
impl<AB, T> AirLookupHandlerDyn<AB> for T
where
    AB: PermutationAirBuilder + PairBuilder + AirBuilderWithPublicValues,
    T: AirLookupHandler<AB>,
{
    fn add_lookup_columns_dyn(&mut self) -> Vec<usize> {
        self.add_lookup_columns()
    }
    fn get_lookups_dyn(&mut self) -> Vec<Lookup<AB::F>> {
        self.get_lookups()
    }
    fn eval_lookups_dyn(
        &self,
        builder: &mut AB,
        contexts: &[Lookup<AB::F>],
        lookup_data: &[LookupData<AB::ExprEF>],
        gadget: &dyn LookupGadgetDyn<AB>,
    ) {
        Air::<AB>::eval(self, builder);
        if !lookup_data.is_empty() {
            gadget.eval_lookups_dyn(builder, contexts, lookup_data);
        }
    }
}
