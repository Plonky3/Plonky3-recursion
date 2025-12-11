use core::iter;

use alloc::vec::Vec;
use itertools::Itertools;
use p3_air::{Air, AirBuilder};
use p3_air::{AirBuilderWithPublicValues, PairBuilder, PermutationAirBuilder};
use p3_lookup::lookup_traits::{AirLookupHandler, Lookup, LookupData, LookupGadget};
use p3_lookup::lookup_traits::{Direction, LookupInput};
use p3_uni_stark::{SymbolicExpression, SymbolicVariable};

pub fn get_index_lookups<
    AB: PermutationAirBuilder + PairBuilder + AirBuilderWithPublicValues,
    const D: usize,
>(
    main_start: usize,
    preprocessed_start: usize,
    num_lookups: usize,
    multiplicities: &[SymbolicExpression<AB::F>],
    main: &[SymbolicVariable<<AB as AirBuilder>::F>],
    preprocessed: &[SymbolicVariable<<AB as AirBuilder>::F>],
    direction: Direction,
) -> Vec<Vec<LookupInput<AB::F>>> {
    // Chunk by 2 so we can maintain a constraint degree 3 at most.
    (0..num_lookups)
        .chunks(2)
        .into_iter()
        .map(|chunk| {
            chunk
                .map(|i| {
                    let idx = SymbolicExpression::from(preprocessed[preprocessed_start + i]);

                    let values =
                        (0..D).map(|j| SymbolicExpression::from(main[main_start + i * D + j]));
                    let inps = iter::once(idx).chain(values).collect::<Vec<_>>();

                    (inps, multiplicities[i].clone(), direction)
                })
                .collect::<Vec<_>>()
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
        lookup_data: &[LookupData<AB::EF>],
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
        lookup_data: &[LookupData<AB::EF>],
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
        lookup_data: &[LookupData<AB::EF>],
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
        lookup_data: &[LookupData<AB::EF>],
        gadget: &dyn LookupGadgetDyn<AB>,
    ) {
        Air::<AB>::eval(self, builder);
        if !lookup_data.is_empty() {
            gadget.eval_lookups_dyn(builder, contexts, lookup_data);
        }
    }
}
