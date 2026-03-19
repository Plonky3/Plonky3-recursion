use alloc::vec::Vec;
use core::iter;

use p3_air::{AirBuilder, AirLayout};
use p3_field::Field;
use p3_lookup::lookup_traits::{Direction, LookupInput};
use p3_matrix::Matrix;
use p3_uni_stark::{SymbolicAirBuilder, SymbolicExpression, SymbolicVariable};

use super::alu_air::{
    PREP_A_IDX, PREP_A_IS_READER, PREP_C_IS_READER, PREP_MULT_A, PREP_MULT_B, PREP_MULT_OUT,
};

pub fn get_index_lookups<F: Field, const D: usize>(
    main_start: usize,
    preprocessed_start: usize,
    num_lookups: usize,
    main: &[SymbolicVariable<F>],
    preprocessed: &[SymbolicVariable<F>],
    direction: Direction,
) -> Vec<LookupInput<F>> {
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

/// Get ALU lookups for the 4 operands (a, b, c, out).
///
/// Uses the `PREP_*` constants from [`super::alu_air`] for column offsets.
pub fn get_alu_index_lookups<F: Field, const D: usize>(
    main_start: usize,
    preprocessed_start: usize,
    main: &[SymbolicVariable<F>],
    preprocessed: &[SymbolicVariable<F>],
) -> Vec<LookupInput<F>> {
    let mult_a = SymbolicExpression::from(preprocessed[preprocessed_start + PREP_MULT_A]);
    let mult_b = SymbolicExpression::from(preprocessed[preprocessed_start + PREP_MULT_B]);
    let mult_out = SymbolicExpression::from(preprocessed[preprocessed_start + PREP_MULT_OUT]);
    let a_is_reader = SymbolicExpression::from(preprocessed[preprocessed_start + PREP_A_IS_READER]);
    let c_is_reader = SymbolicExpression::from(preprocessed[preprocessed_start + PREP_C_IS_READER]);

    let eff_mult_a = mult_a.clone() * a_is_reader;
    let eff_mult_c = mult_a * c_is_reader;

    let multiplicities = [eff_mult_a, mult_b, eff_mult_c, mult_out];

    (0..4)
        .map(|i| {
            let idx = SymbolicExpression::from(preprocessed[preprocessed_start + PREP_A_IDX + i]);

            let values = (0..D).map(|j| SymbolicExpression::from(main[main_start + i * D + j]));
            let inps = iter::once(idx).chain(values).collect::<Vec<_>>();

            (inps, multiplicities[i].clone(), Direction::Receive)
        })
        .collect()
}

/// Helper to create symbolic air builder and extract symbolic variables for lookup generation.
///
/// Returns `(symbolic_main_local, preprocessed_local)` slices for use in lookup generation.
pub fn create_symbolic_variables<F: Field>(
    preprocessed_width: usize,
    main_width: usize,
    num_public_values: usize,
    num_permutation_cols: usize,
) -> (Vec<SymbolicVariable<F>>, Vec<SymbolicVariable<F>>) {
    let layout = AirLayout {
        preprocessed_width,
        main_width,
        num_public_values,
        permutation_width: num_permutation_cols,
        num_permutation_challenges: 0,
        num_permutation_values: 0,
        num_periodic_columns: 0,
    };
    let symbolic_air_builder = SymbolicAirBuilder::<F>::new(layout);

    let symbolic_main = symbolic_air_builder.main();
    let symbolic_main_local = symbolic_main.row_slice(0).unwrap().to_vec();

    let preprocessed = symbolic_air_builder.preprocessed().clone();
    let preprocessed_local = preprocessed
        .row_slice(0)
        .expect("The preprocessed matrix has only one row?")
        .to_vec();

    (symbolic_main_local, preprocessed_local)
}
