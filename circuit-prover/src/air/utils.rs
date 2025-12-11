use core::iter;

use alloc::vec::Vec;
use itertools::Itertools;
use p3_air::AirBuilder;
use p3_air::{AirBuilderWithPublicValues, PairBuilder, PermutationAirBuilder};
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
