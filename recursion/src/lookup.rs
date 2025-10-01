use core::marker::PhantomData;

use alloc::vec;
use alloc::{string::String, vec::Vec};
use p3_circuit::CircuitBuilder;
use p3_circuit::utils::ColumnsTargets;
use p3_field::Field;

use crate::recursive_traits::RecursiveAir;
use crate::{
    Target,
    recursive_traits::{Recursive, RecursiveLagrangeSelectors},
};

enum Direction {
    Send,
    Receive,
}

struct Table {
    index: usize,
    name: String,
}

/// Structure representing global lookups. The information contained in this structure is provided by the prover.
pub struct GlobalLookup<'a> {
    table_idx: usize,                // table index
    perm_idx: usize,                 // index within the auxiliary lookup columns
    columns: &'a [Target],           // columns taking part in the lookup
    multiplicities: &'a [Target],    // multiplicities
    direction: Direction, // whether the multiplicities are positive (Receive) or negative (Send)
    expected_cumulative_sum: Target, // expected cumulative sum at the end of the trace
}

/// Structure representing local lookups. The information contained in this structure is provided by the prover.
pub struct LocalLookup<'a> {
    perm_idx: usize,                        // index within the auxiliary lookup columns
    sending_columns: &'a [Target],          // columns sending to the lookup table
    sending_multiplicities: &'a [Target],   // multiplicities of the sending columns
    receiving_columns: &'a [Target],        // columns receiving from the lookup table
    receiving_multiplicities: &'a [Target], // multiplicities of the receiving columns
}

/// Contains the columns required for a lookup constraint evaluation, both local and global.
/// This structure is created from `LocalLookup` and opening values.
pub struct LookupColumnsCore<'a> {
    /// Index within the auxiliary lookup columns.
    pub perm_idx: usize,
    // Evaluations of the auxiliary polynomials used for lookups at `zeta`.
    pub local: &'a [Target],
    // Evaluations of the auxiliary polynomials used for lookups at `next_zeta`.
    pub next: &'a [Target],
    // Lookup columns
    pub lookup_columns: &'a [Target],
    // Multiplicities columns
    pub multiplicities: &'a [Target],
    // Challenges used in the lookup argument.
    pub challenges: &'a [Target],
}

/// Contains the columns required for a local lookup constraint evaluation.
/// This structure is created from `LocalLookup` and opening values.
pub struct LocalLookupColumns<'a> {
    /// Core columns required for a lookup constraint evaluation. The `lookup_columns` and `multiplicities` fields contain the sending columns and their multiplicities.
    pub core_lookup_columns: LookupColumnsCore<'a>,
    /// Receiving columns, corresponding to the columns representing the lookup table (negative multiplicities).
    pub receiving: &'a [Target],
    /// Multiplicities (positive values) of the receiving columns.
    pub receiving_multiplicities: &'a [Target],
}

/// Contains the columns required for a global lookup constraint evaluation.
/// This structure is created from `LocalLookup` and opening values.
pub struct GlobalLookupColumns<'a> {
    /// Contains the core columns required for a lookup constraint evaluation.
    pub core_lookup_columns: LookupColumnsCore<'a>,
    /// Evaluation of the cumulative sum at the last row of the main trace.
    pub expected_cumulative_sum: Target,
}

/// Trait containing lookup methods, so that we can verify both local and global lookups.
/// Global lookups correspond to interactions between different tables, while local lookups correspond to
/// lookups within a single table.
pub trait RecursiveAirWithLookupVerification<F: Field, Comm: Recursive<F>>:
    RecursiveAir<F>
{
    /// Checks the update of the auxiliary lookup polynomials for global interations.
    /// It also checks that the final value of the auxiliary polynomial corresponds to the expected value.
    /// The method folds the associated constraints with the previously computed accumulator and returns the new accumulator.
    /// Note that global interactions correspond to interactions between different tables.
    fn eval_global_constraints(
        &self,
        circuit: &mut CircuitBuilder<F>,
        sels: &RecursiveLagrangeSelectors,
        // Folding challenge
        alpha: &Target,
        // Permutation columns corresponding to the auxiliary columns used in the lookup argument, along with the looking and multiplicities columns.
        lookup_columns: &[GlobalLookupColumns],
        // Initial value of the accumulator.
        acc_start: Target,
    ) -> Target;

    /// Evaluates the lookup constraints for a local lookup: the circuit checks that
    /// the auxiliary columns are updated correctly, and that the final auxiliary values are 0.
    /// The method folds the associated constraints with the previously computed accumulator and returns the new accumulator.
    fn eval_local_folded_circuit(
        &self,
        circuit: &mut CircuitBuilder<F>,
        sels: &RecursiveLagrangeSelectors,
        // Folding challenge
        alpha: &Target,
        // Columns required to evaluate the constraints for the lookup argument.
        lookup_columns: &[LocalLookupColumns],
        // Initial value of the accumulator.
        acc_start: Target,
    ) -> Target;

    fn eval_folded_circuit(
        &self,
        circuit: &mut CircuitBuilder<F>,
        sels: &RecursiveLagrangeSelectors,
        alpha: &Target,
        local_lookups: &[LocalLookup],
        global_lookups: &[GlobalLookup],
        columns: ColumnsTargets,
        acc_start: Target,
    ) -> Target {
        let mut folded_constraints = <Self as RecursiveAir<F>>::eval_folded_circuit(
            self, circuit, sels, alpha, &columns, acc_start,
        );
        let (local_lookup_columns, global_lookup_columns) =
            self.get_lookup_columns_from_all_cols(circuit, local_lookups, global_lookups, &columns);

        folded_constraints = self.eval_local_folded_circuit(
            circuit,
            sels,
            alpha,
            &local_lookup_columns,
            folded_constraints,
        );

        folded_constraints = self.eval_global_constraints(
            circuit,
            sels,
            alpha,
            &global_lookup_columns,
            folded_constraints,
        );

        folded_constraints
    }

    fn get_lookup_columns_from_all_cols(
        &self,
        circuit: &mut CircuitBuilder<F>,
        local_lookups: &[LocalLookup],
        global_lookups: &[GlobalLookup],
        columns: &ColumnsTargets,
    ) -> (Vec<LocalLookupColumns>, Vec<GlobalLookupColumns>);

    /// Returns the columns corresponding to the auxiliary lookup polynomials.
    /// `is_current` indicates whether to return the columns evaluated at `zeta` or `next_zeta`.
    fn permutation(&self, circuit: &mut CircuitBuilder<F>, is_current: bool) -> Vec<Target>;

    /// Creates the targets for the local lookup challenges in the circuit.
    fn get_challenges_circuit(
        &self,
        circuit: &mut CircuitBuilder<F>,
        local_lookups: &[LocalLookup],
    ) -> Vec<Vec<Target>>;
}

/// Structure for any AIR that does not use lookups. We use it to provide a default implementation of the
/// `RecursiveLookupVerification` trait.
pub struct AirWithoutLookup<F: Field, A: RecursiveAir<F>> {
    pub air: A,
    _phantom: PhantomData<F>,
}

impl<F: Field, A: RecursiveAir<F>> AirWithoutLookup<F, A> {
    pub fn new(air: A) -> Self {
        Self {
            air,
            _phantom: PhantomData,
        }
    }
}

impl<F: Field, A: RecursiveAir<F>> RecursiveAir<F> for AirWithoutLookup<F, A>
where
    F: Field,
    A: RecursiveAir<F>,
{
    fn width(&self) -> usize {
        self.air.width()
    }

    fn eval_folded_circuit(
        &self,
        builder: &mut CircuitBuilder<F>,
        sels: &RecursiveLagrangeSelectors,
        alpha: &Target,
        columns: &ColumnsTargets,
        acc_start: Target,
    ) -> Target {
        self.air
            .eval_folded_circuit(builder, sels, alpha, columns, acc_start)
    }

    fn get_log_quotient_degree(&self, num_public_values: usize, is_zk: usize) -> usize {
        self.air.get_log_quotient_degree(num_public_values, is_zk)
    }
}

impl<F: Field, Comm: Recursive<F>, A: RecursiveAir<F>> RecursiveAirWithLookupVerification<F, Comm>
    for AirWithoutLookup<F, A>
{
    fn eval_global_constraints(
        &self,
        circuit: &mut CircuitBuilder<F>,
        _sels: &RecursiveLagrangeSelectors,
        _alpha: &Target,
        _lookup_columns: &[GlobalLookupColumns],
        _acc_start: Target,
    ) -> Target {
        circuit.add_const(F::ZERO)
    }

    fn eval_local_folded_circuit(
        &self,
        circuit: &mut CircuitBuilder<F>,
        _sels: &RecursiveLagrangeSelectors,
        _alpha: &Target,
        _lookup_columns: &[LocalLookupColumns],
        _acc_start: Target,
    ) -> Target {
        circuit.add_const(F::ZERO)
    }

    fn get_lookup_columns_from_all_cols(
        &self,
        _circuit: &mut CircuitBuilder<F>,
        _local_lookups: &[LocalLookup],
        _global_lookups: &[GlobalLookup],
        _columns: &ColumnsTargets,
    ) -> (Vec<LocalLookupColumns>, Vec<GlobalLookupColumns>) {
        (vec![], vec![])
    }

    fn permutation(&self, _circuit: &mut CircuitBuilder<F>, _is_current: bool) -> Vec<Target> {
        vec![]
    }

    fn get_challenges_circuit(
        &self,
        _circuit: &mut CircuitBuilder<F>,
        _local_lookups: &[LocalLookup],
    ) -> Vec<Vec<Target>> {
        vec![]
    }
}
