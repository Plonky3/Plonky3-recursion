#[cfg(test)]
mod tests {
    use alloc::vec;
    use alloc::vec::Vec;
    use hashbrown::HashMap;
    use p3_air::{Air, AirBuilder, BaseAir};
    use p3_circuit::CircuitBuilder;
    use p3_circuit_prover::air::{AddAir, MulAir};
    use p3_field::Field;

    use crate::{
        Target,
        lookup::{
            GlobalLookup, GlobalLookupColumns, LocalLookup, LocalLookupColumns, LookupColumnsCore,
            RecursiveLookupVerification, RecursivePermutationAir,
        },
        recursive_traits::RecursiveLagrangeSelectors,
    };

    /// A mock lookup gadget that computes the following unsound lookup:
    /// \sum_i m_i * x_i = \sum_j n_j * y_j
    /// where x_i, y_j are lookup and looked values, and m_i, n_j are their respective multiplicities.
    pub(crate) struct MockLookup {}

    impl<F: Field> RecursiveLookupVerification<F> for MockLookup {
        fn eval_global_update_constraints(
            &self,
            circuit: &mut CircuitBuilder<F>,
            _sels: &RecursiveLagrangeSelectors,
            // Folding challenge
            _alpha: &Target,
            // Permutation columns corresponding to the auxiliary columns used in the lookup argument, along with the looking and multiplicities columns.
            lookup_columns: &[GlobalLookupColumns],
            // Challenges used in the lookup argument.
            _global_lookup_challenges: &[Vec<Target>],
            // Initial value of the accumulator.
            acc_start: Target,
        ) -> Target {
            // In this mock lookup, we do not fold: we just assert that the constraints hold on each row.
            // Constraints:
            // - on the first row, cur = combined_lookups
            // - on other rows, next - cur = combined_lookups
            // - on the last row, the auxiliary column should be equal to the cumulative value

            let zero = circuit.add_const(F::ZERO);
            // In this mock implementation, we provide an entire column for every lookup.
            let trace_length = lookup_columns[0].core_lookup_columns.lookup_columns.len();

            for global_lookup in lookup_columns {
                let lookup_columns_slice = &global_lookup.core_lookup_columns.lookup_columns;
                let num_columns = lookup_columns_slice.len() / trace_length;

                for i in 0..trace_length {
                    let is_first = circuit.add_const(F::from_u64((i == 0) as u64));

                    let is_transition =
                        circuit.add_const(F::from_u64((i > 0 && i < trace_length - 1) as u64));

                    let is_last = circuit.add_const(F::from_u64((i == trace_length - 1) as u64));

                    let local = global_lookup.core_lookup_columns.local[i];
                    let next = global_lookup.core_lookup_columns.next[i];

                    // Extract the values for row i from all columns
                    let lookings: Vec<Target> = (0..num_columns)
                        .map(|col| lookup_columns_slice[col * trace_length + i])
                        .collect();

                    let multiplicity = global_lookup.core_lookup_columns.multiplicity;

                    let cumulative_sum = global_lookup.expected_cumulative;

                    // The mock lookup doesn't have any challenges, so we combine the lookups simply by adding.
                    let combined_lookups =
                        lookings.iter().fold(zero, |prev, x| circuit.add(prev, *x));

                    let combined_mul = circuit.mul(multiplicity, combined_lookups);
                    // Let us define the three constraints.
                    let sub = circuit.sub(local, combined_mul);

                    // Check first constraint.
                    let first_constr = circuit.mul(is_first.clone(), sub);
                    circuit.connect(first_constr, zero);

                    // Check second constraint.
                    let diff = circuit.sub(next, local);
                    let second_constr = circuit.sub(diff, combined_mul);
                    let second_constr = circuit.mul(is_transition.clone(), second_constr);
                    circuit.connect(second_constr, zero);

                    // Check last constraint
                    let sub = circuit.sub(local, cumulative_sum);
                    let last_constr = circuit.mul(is_last.clone(), sub);
                    circuit.connect(last_constr, zero);
                }
            }

            acc_start
        }

        fn eval_local_folded_circuit(
            &self,
            circuit: &mut p3_circuit::CircuitBuilder<F>,
            _sels: &RecursiveLagrangeSelectors,
            // Folding challenge
            _alpha: &Target,
            // Columns required to evaluate the constraints for the lookup argument.
            lookup_columns: &[LocalLookupColumns],
            // Challenges used in the lookup argument.
            _local_lookup_challenges: &[Vec<Target>],
            // Initial value of the accumulator.
            acc_start: Target,
        ) -> Target {
            // In this mock lookup, we do not fold: we just assert that the constraints hold on each row.
            // Constraints:
            // - on the first row, cur = sending_lookups - receiving_lookups
            // - on other rows, next - cur = sending_lookups - receiving_lookups
            // - on the last row, the auxiliary column should be 0

            let zero = circuit.add_const(F::ZERO);
            // In this mock implementation, we provide an entire column for every lookup.
            let trace_length = lookup_columns[0].core_lookup_columns.lookup_columns.len();

            for local_lookup in lookup_columns {
                let lookup_columns_slice = &local_lookup.core_lookup_columns.lookup_columns;
                let num_columns = lookup_columns_slice.len() / trace_length;

                let receiving_lookup_slice = local_lookup.receiving.clone();
                assert_eq!(num_columns, receiving_lookup_slice.len() / trace_length);

                for i in 0..trace_length {
                    let is_first = circuit.add_const(F::from_u64((i == 0) as u64));

                    let is_transition =
                        circuit.add_const(F::from_u64((i > 0 && i < trace_length - 1) as u64));

                    let is_last = circuit.add_const(F::from_u64((i == trace_length - 1) as u64));

                    let local = local_lookup.core_lookup_columns.local[i];
                    let next = local_lookup.core_lookup_columns.next[i];

                    // Extract the values for row i from all columns
                    let sending_lookups: Vec<Target> = (0..num_columns)
                        .map(|col| lookup_columns_slice[col * trace_length + i])
                        .collect();

                    let sending_multiplicity = local_lookup.core_lookup_columns.multiplicity;
                    let receiving_lookups: Vec<Target> = (0..num_columns)
                        .map(|col| receiving_lookup_slice[col * trace_length + i])
                        .collect();

                    let receiving_multiplicity = local_lookup.receiving_multiplicity;

                    // The mock lookup doesn't have any challenges, so we combine the lookups simply by adding.
                    // First, get the lookup combinations.
                    let sending_combined_lookups = sending_lookups
                        .iter()
                        .fold(zero, |prev, x| circuit.add(prev, *x));

                    let receiving_combined_lookups = receiving_lookups
                        .iter()
                        .fold(zero, |prev, x| circuit.add(prev, *x));

                    let sending_combined_mul =
                        circuit.mul(sending_multiplicity, sending_combined_lookups);

                    let receiving_combined_mul =
                        circuit.mul(receiving_multiplicity, receiving_combined_lookups);

                    // compute sending - receiving
                    let combined_mul = circuit.sub(sending_combined_mul, receiving_combined_mul);

                    // Let us define the three constraints.
                    let sub = circuit.sub(local, combined_mul);

                    // Check first constraint.
                    let first_constr = circuit.mul(is_first.clone(), sub);
                    circuit.connect(first_constr, zero);

                    // Check second constraint.
                    let diff = circuit.sub(next, local);
                    let second_constr = circuit.sub(diff, combined_mul);
                    let second_constr = circuit.mul(is_transition.clone(), second_constr);
                    circuit.connect(second_constr, zero);

                    // Check last constraint
                    let mul = circuit.mul(is_last.clone(), local);
                    circuit.connect(mul, zero);
                }
            }

            acc_start
        }

        fn eval_global_final_value(
            &self,
            circuit: &mut CircuitBuilder<F>,
            global_lookups: &[GlobalLookup],
            _challenges: &[Vec<Target>],
        ) {
            // First, group the global lookups together.
            let mut groups = HashMap::new();
            global_lookups.iter().for_each(|gl| {
                groups
                    .entry(gl.name.clone())
                    .or_insert(vec![])
                    .push(gl.expected_cumulative)
            });

            let zero = circuit.add_const(F::ZERO);
            for (_, values) in groups {
                let sum = values.iter().fold(zero, |acc, x| circuit.add(acc, *x));

                circuit.connect(sum, zero);
            }
        }

        fn get_local_lookup_challenges_circuit(
            &self,
            _circuit: &mut CircuitBuilder<F>,
            _local_lookups: &[LocalLookup],
        ) -> Vec<Vec<Target>> {
            vec![]
        }

        fn get_global_lookup_challenges_circuit(
            &self,
            _circuit: &mut CircuitBuilder<F>,
            _global_lookups: &[GlobalLookup],
        ) -> Vec<Vec<Target>> {
            vec![]
        }

        fn num_local_lookup_challenges(&self, _local_lookups: &[LocalLookup]) -> usize {
            0
        }

        fn num_global_lookup_challenges(&self, _global_lookups: &[GlobalLookup]) -> usize {
            0
        }

        fn generate_global_lookup_challenges<Challenger>(
            &self,
            _challenger: &mut Challenger,
            _global_lookups: &[GlobalLookup],
        ) -> Vec<Vec<F>> {
            vec![]
        }
    }

    struct PermutationAddAir<F: Field> {
        add_air: AddAir<F>,
        permutation_columns: [Vec<F>; 9],
    }

    impl<F: Field> BaseAir<F> for PermutationAddAir<F> {
        fn width(&self) -> usize {
            self.add_air.width()
        }
    }

    impl<AB: AirBuilder> Air<AB> for PermutationAddAir<AB::F>
    where
        AB::F: Field,
    {
        fn eval(&self, builder: &mut AB) {
            self.add_air.eval(builder);
        }
    }

    struct PermutationMulAir<F: Field> {
        mul_air: MulAir<F>,
        permutation_columns: [Vec<F>; 8],
    }

    impl<F: Field> BaseAir<F> for PermutationMulAir<F> {
        fn width(&self) -> usize {
            self.mul_air.width()
        }
    }

    impl<AB: AirBuilder> Air<AB> for PermutationMulAir<AB::F>
    where
        AB::F: Field,
    {
        fn eval(&self, builder: &mut AB) {
            self.mul_air.eval(builder);
        }
    }

    struct AllOutputsAir {}

    impl<F> BaseAir<F> for AllOutputsAir {
        fn width(&self) -> usize {
            5
        }
    }

    impl<AB: AirBuilder> Air<AB> for AllOutputsAir {
        fn eval(&self, _builder: &mut AB) {
            // No constraints
        }
    }

    struct PermutationAllOutputsAir<F: Field> {
        all_outputs_air: AllOutputsAir,
        permutation_columns: [Vec<F>; 8],
    }

    impl<F: Field> BaseAir<F> for PermutationAllOutputsAir<F> {
        fn width(&self) -> usize {
            5 + 2
        }
    }

    impl<AB: AirBuilder> Air<AB> for PermutationAllOutputsAir<AB::F>
    where
        AB::F: Field,
    {
        fn eval(&self, _builder: &mut AB) {
            // No constraints.
        }
    }

    trait MockPermutation<F> {
        fn get_permutation_columns(&self, col: usize) -> &[F];
    }

    impl<F: Field> MockPermutation<F> for PermutationAddAir<F> {
        fn get_permutation_columns(&self, col: usize) -> &[F] {
            &self.permutation_columns[col]
        }
    }

    impl<F: Field> MockPermutation<F> for PermutationMulAir<F> {
        fn get_permutation_columns(&self, col: usize) -> &[F] {
            &self.permutation_columns[col]
        }
    }

    impl<F: Field> MockPermutation<F> for PermutationAllOutputsAir<F> {
        fn get_permutation_columns(&self, col: usize) -> &[F] {
            &self.permutation_columns[col]
        }
    }

    fn get_permutation<F: Field, M: MockPermutation<F>>(
        permutation: &M,
        circuit: &mut CircuitBuilder<F>,
        col: usize,
        is_current: bool,
    ) -> Vec<Target> {
        if is_current {
            permutation
                .get_permutation_columns(col)
                .iter()
                .map(|row_val| circuit.add_const(*row_val))
                .collect()
        } else {
            let n = permutation.get_permutation_columns(col).len();
            (0..n)
                .map(|i| circuit.add_const(permutation.get_permutation_columns(col)[(i + 1) % n]))
                .collect()
        }
    }

    fn get_lookup_columns_from_all_cols<F: Field, M: MockPermutation<F>>(
        permutation: &M,
        circuit: &mut CircuitBuilder<F>,
        local_lookups: &[LocalLookup],
        global_lookups: &[GlobalLookup],
        air_width: usize,
        _columns: &p3_circuit::utils::ColumnsTargets,
    ) -> (Vec<LocalLookupColumns>, Vec<GlobalLookupColumns>) {
        let local_lookup_cols = local_lookups
            .iter()
            .enumerate()
            .map(|(i, local_lookup)| {
                // Get auxiliary permutation columns, at all rows.
                let local = get_permutation(permutation, circuit, air_width + i, true);
                // Get auxiliary permutation columns, at all rows, offset by one row.
                let next = get_permutation(permutation, circuit, air_width + i, false);

                // Get main matrix columns at all rows.
                let columns = (0..air_width)
                    .map(|col_idx| get_permutation(permutation, circuit, col_idx, true))
                    .collect::<Vec<_>>();

                // Get the lookup columns and multiplicities.
                let sending_local_lookups = local_lookup
                    .sending_column_indices
                    .iter()
                    .flat_map(|&idx| columns[idx].clone())
                    .collect::<Vec<_>>();
                let sending_multiplicity = columns[local_lookup.sending_multiplicity][0]; // In this mock example, we assume that all rows have the same multiplicity

                let receiving_local_lookups = local_lookup
                    .receiving_column_indices
                    .iter()
                    .flat_map(|&idx| columns[idx].clone())
                    .collect::<Vec<_>>();
                let receiving_multiplicity = columns[local_lookup.receiving_multiplicity][0]; // In this mock example, we assume that all rows have the same multiplicity

                let lookup_cols_core = LookupColumnsCore {
                    perm_idx: local_lookup.perm_idx,
                    local: local,
                    next: next,
                    lookup_columns: sending_local_lookups,
                    multiplicity: sending_multiplicity,
                    challenges: vec![],
                };
                LocalLookupColumns {
                    core_lookup_columns: lookup_cols_core,
                    receiving: receiving_local_lookups,
                    receiving_multiplicity,
                }
            })
            .collect::<Vec<LocalLookupColumns>>();

        let global_lookup_cols = global_lookups
            .iter()
            .enumerate()
            .map(|(i, global_lookup)| {
                let local = get_permutation(permutation, circuit, i, true);
                let next = get_permutation(permutation, circuit, i, false);

                // Get main matrix columns at all rows.
                let columns = (0..air_width)
                    .map(|col_idx| get_permutation(permutation, circuit, col_idx, true))
                    .collect::<Vec<_>>();

                let global_lookup_columns = global_lookup
                    .column_indices
                    .iter()
                    .flat_map(|&idx| columns[idx].clone())
                    .collect::<Vec<Target>>();
                let multiplicity = columns[global_lookup.multiplicity][0]; // In this mock example, we assume that all rows have the same multiplicity

                let lookup_cols_core = LookupColumnsCore {
                    perm_idx: global_lookup.perm_idx,
                    local: local,
                    next: next,
                    lookup_columns: global_lookup_columns,
                    multiplicity,
                    challenges: vec![],
                };

                GlobalLookupColumns {
                    core_lookup_columns: lookup_cols_core,
                    direction: global_lookup.direction,
                    expected_cumulative: global_lookup.expected_cumulative,
                }
            })
            .collect::<Vec<GlobalLookupColumns>>();

        (local_lookup_cols, global_lookup_cols)
    }

    impl<F: Field> RecursivePermutationAir<F> for PermutationAllOutputsAir<F> {
        fn permutation(
            &self,
            circuit: &mut CircuitBuilder<F>,
            col: usize,
            is_current: bool,
        ) -> Vec<Target> {
            get_permutation(self, circuit, col, is_current)
        }

        fn get_lookup_columns_from_all_cols(
            &self,
            circuit: &mut CircuitBuilder<F>,
            local_lookups: &[LocalLookup],
            global_lookups: &[GlobalLookup],
            columns: &p3_circuit::utils::ColumnsTargets,
        ) -> (Vec<LocalLookupColumns>, Vec<GlobalLookupColumns>) {
            get_lookup_columns_from_all_cols(
                self,
                circuit,
                local_lookups,
                global_lookups,
                self.width(),
                columns,
            )
        }
    }

    impl<F: Field> RecursivePermutationAir<F> for PermutationAddAir<F> {
        fn permutation(
            &self,
            circuit: &mut CircuitBuilder<F>,
            col: usize,
            is_current: bool,
        ) -> Vec<Target> {
            get_permutation(self, circuit, col, is_current)
        }

        fn get_lookup_columns_from_all_cols(
            &self,
            circuit: &mut CircuitBuilder<F>,
            local_lookups: &[LocalLookup],
            global_lookups: &[GlobalLookup],
            columns: &p3_circuit::utils::ColumnsTargets,
        ) -> (Vec<LocalLookupColumns>, Vec<GlobalLookupColumns>) {
            get_lookup_columns_from_all_cols(
                self,
                circuit,
                local_lookups,
                global_lookups,
                self.width(),
                columns,
            )
        }
    }

    impl<F: Field> RecursivePermutationAir<F> for PermutationMulAir<F> {
        fn permutation(
            &self,
            circuit: &mut CircuitBuilder<F>,
            col: usize,
            is_current: bool,
        ) -> Vec<Target> {
            get_permutation(self, circuit, col, is_current)
        }

        fn get_lookup_columns_from_all_cols(
            &self,
            circuit: &mut CircuitBuilder<F>,
            local_lookups: &[LocalLookup],
            global_lookups: &[GlobalLookup],
            columns: &p3_circuit::utils::ColumnsTargets,
        ) -> (Vec<LocalLookupColumns>, Vec<GlobalLookupColumns>) {
            get_lookup_columns_from_all_cols(
                self,
                circuit,
                local_lookups,
                global_lookups,
                self.width(),
                columns,
            )
        }
    }
}
