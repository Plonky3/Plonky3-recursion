use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use p3_circuit::CircuitBuilder;
use p3_circuit::utils::ColumnsTargets;
use p3_field::Field;

use crate::Target;
use crate::recursive_traits::{RecursiveAir, RecursiveLagrangeSelectors};

#[derive(Clone, Copy)]
pub enum Direction {
    _Send,
    _Receive,
}

pub struct Table {
    _index: usize,
    _name: String,
}

/// Structure representing global lookups. The information contained in this structure is provided by the prover.
#[derive(Clone)]
pub struct GlobalLookup<'a> {
    _table_idx: usize,             // table index
    _perm_idx: usize,              // index within the auxiliary lookup columns
    _columns: &'a [Target],        // columns taking part in the lookup
    _multiplicities: &'a [Target], // multiplicities
    _direction: Direction, // whether the multiplicities are positive (Receive) or negative (Send)
    _expected_cumulative: Target, // target holding the expected cumulative value at the end of the trace
}

/// Structure representing local lookups. The information contained in this structure is provided by the prover.
pub struct LocalLookup<'a> {
    _perm_idx: usize,                        // index within the auxiliary lookup columns
    _sending_columns: &'a [Target],          // columns sending to the lookup table
    _sending_multiplicities: &'a [Target],   // multiplicities of the sending columns
    _receiving_columns: &'a [Target],        // columns receiving from the lookup table
    _receiving_multiplicities: &'a [Target], // multiplicities of the receiving columns
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
    // Indicates whether we should negate (Send) the multiplicities or not (Receive).
    pub direction: Direction,
    /// Contains the core columns required for a lookup constraint evaluation.
    pub core_lookup_columns: LookupColumnsCore<'a>,
    /// Evaluation of the cumulative value at the last row of the main trace.
    pub expected_cumulative: Target,
}

pub struct AllColumnTargets<'a> {
    pub local_lookups: &'a [LocalLookup<'a>],
    pub global_lookups: &'a [GlobalLookup<'a>],
    pub columns_targets: &'a ColumnsTargets<'a>,
    pub local_lookup_challenges: &'a [Vec<Target>],
    pub global_lookup_challenges: &'a [Vec<Target>],
}

/// Trait containing lookup methods, so that we can verify both local and global lookups.
/// Global lookups correspond to interactions between different tables, while local lookups correspond to
/// lookups within a single table.
pub trait RecursiveLookupVerification<F: Field> {
    /// Checks the update of the auxiliary lookup polynomials for global interations.
    /// It also checks that the final value of the auxiliary polynomial corresponds to the expected value.
    /// The method folds the associated constraints with the previously computed accumulator and returns the new accumulator.
    /// Note that global interactions correspond to interactions between different tables.
    fn eval_global_update_constraints(
        &self,
        circuit: &mut CircuitBuilder<F>,
        sels: &RecursiveLagrangeSelectors,
        // Folding challenge
        alpha: &Target,
        // Permutation columns corresponding to the auxiliary columns used in the lookup argument, along with the looking and multiplicities columns.
        lookup_columns: &[GlobalLookupColumns],
        // Challenges used in the lookup argument.
        global_lookup_challenges: &[Vec<Target>],
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
        // Challenges used in the lookup argument.
        local_lookup_challenges: &[Vec<Target>],
        // Initial value of the accumulator.
        acc_start: Target,
    ) -> Target;

    /// Evaluates the local constraints as well as the global update constraints for a given `air` and slices of local and global lookups.
    /// The method folds the associated constraints with the previously computed accumulator and returns the new accumulator.
    fn eval_lookup_constraints(
        &self,
        air: &dyn RecursivePermutationAir<F>,
        circuit: &mut CircuitBuilder<F>,
        sels: &RecursiveLagrangeSelectors,
        // Folding challenge
        alpha: &Target,
        // Columns required to evaluate the constraints for the lookup argument.
        all_columns_targets: AllColumnTargets,
        // Initial value of the accumulator.
        acc_start: Target,
    ) -> Target {
        let AllColumnTargets {
            local_lookups,
            global_lookups,
            columns_targets,
            local_lookup_challenges,
            global_lookup_challenges,
        } = all_columns_targets;

        let (local_lookup_columns, global_lookup_columns) = air.get_lookup_columns_from_all_cols(
            circuit,
            local_lookups,
            global_lookups,
            columns_targets,
        );

        let folded_constraints = self.eval_local_folded_circuit(
            circuit,
            sels,
            alpha,
            &local_lookup_columns,
            local_lookup_challenges,
            acc_start,
        );

        self.eval_global_update_constraints(
            circuit,
            sels,
            alpha,
            &global_lookup_columns,
            global_lookup_challenges,
            folded_constraints,
        )
    }

    /// This method computes the final value of all global lookup arguments, and ensures it is correct. For `LogUp`, the final value is 0.
    /// Since
    fn eval_global_final_value(
        &self,
        circuit: &mut CircuitBuilder<F>,
        global_lookups: &[GlobalLookup],
        challenges: &[Vec<Target>],
    );

    fn get_lookup_columns_from_all_cols(
        &self,
        circuit: &mut CircuitBuilder<F>,
        local_lookups: &[LocalLookup],
        global_lookups: &[GlobalLookup],
        columns: &ColumnsTargets,
    ) -> (Vec<LocalLookupColumns<'_>>, Vec<GlobalLookupColumns<'_>>);

    /// Returns the columns corresponding to the auxiliary lookup polynomials.
    /// `is_current` indicates whether to return the columns evaluated at `zeta` or `next_zeta`.
    fn permutation(&self, circuit: &mut CircuitBuilder<F>, is_current: bool) -> Vec<Target>;

    /// Creates the targets for the local lookup challenges in the circuit.
    fn get_local_lookup_challenges_circuit(
        &self,
        circuit: &mut CircuitBuilder<F>,
        local_lookups: &[LocalLookup],
    ) -> Vec<Vec<Target>>;

    /// Creates the targets for the global lookup challenges in the circuit.
    fn get_global_lookup_challenges_circuit(
        &self,
        circuit: &mut CircuitBuilder<F>,
        global_lookups: &[GlobalLookup],
    ) -> Vec<Vec<Target>>;
}

pub trait RecursivePermutationAir<F: Field>: RecursiveAir<F> {
    /// Returns the columns corresponding to the auxiliary permutation polynomials.
    /// `is_current` indicates whether to return the columns evaluated at `zeta` or `next_zeta`.
    fn permutation(&self, circuit: &mut CircuitBuilder<F>, is_current: bool) -> Vec<Target>;

    /// Given `LocalLookup` and `GlobalLookup` structures, returns the columns required to evaluate the lookup constraints.
    fn get_lookup_columns_from_all_cols(
        &self,
        circuit: &mut CircuitBuilder<F>,
        local_lookups: &[LocalLookup],
        global_lookups: &[GlobalLookup],
        columns: &ColumnsTargets,
    ) -> (Vec<LocalLookupColumns<'_>>, Vec<GlobalLookupColumns<'_>>);
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

pub struct NoLookup {}

impl<F: Field> RecursiveLookupVerification<F> for NoLookup {
    fn eval_global_update_constraints(
        &self,
        _circuit: &mut CircuitBuilder<F>,
        _sels: &RecursiveLagrangeSelectors,
        _alpha: &Target,
        lookup_columns: &[GlobalLookupColumns],
        _global_lookup_challenges: &[Vec<Target>],
        acc_start: Target,
    ) -> Target {
        assert!(
            lookup_columns.is_empty(),
            "There is no support for lookups when using NoLookup."
        );
        acc_start
    }

    fn eval_local_folded_circuit(
        &self,
        _circuit: &mut CircuitBuilder<F>,
        _sels: &RecursiveLagrangeSelectors,
        // Folding challenge
        _alpha: &Target,
        // Columns required to evaluate the constraints for the lookup argument.
        lookup_columns: &[LocalLookupColumns],
        _local_lookup_challenges: &[Vec<Target>],
        // Initial value of the accumulator.
        acc_start: Target,
    ) -> Target {
        assert!(
            lookup_columns.is_empty(),
            "There is no support for lookups when using NoLookup."
        );
        acc_start
    }

    fn eval_global_final_value(
        &self,
        _circuit: &mut CircuitBuilder<F>,
        global_lookups: &[GlobalLookup],
        _challenges: &[Vec<Target>],
    ) {
        // There are no lookups, so we do nothing.
        assert!(
            global_lookups.is_empty(),
            "There is no support for lookups when using NoLookup."
        );
    }

    fn get_lookup_columns_from_all_cols(
        &self,
        _circuit: &mut CircuitBuilder<F>,
        local_lookups: &[LocalLookup],
        global_lookups: &[GlobalLookup],
        _columns: &ColumnsTargets,
    ) -> (Vec<LocalLookupColumns<'_>>, Vec<GlobalLookupColumns<'_>>) {
        // There are no lookups, so we do nothing.
        assert!(
            global_lookups.is_empty(),
            "There is no support for lookups when using NoLookup."
        );
        assert!(
            local_lookups.is_empty(),
            "There is no support for lookups when using NoLookup."
        );
        (vec![], vec![])
    }

    fn permutation(&self, _circuit: &mut CircuitBuilder<F>, _is_current: bool) -> Vec<Target> {
        vec![]
    }

    fn get_local_lookup_challenges_circuit(
        &self,
        _circuit: &mut CircuitBuilder<F>,
        local_lookups: &[LocalLookup],
    ) -> Vec<Vec<Target>> {
        assert!(
            local_lookups.is_empty(),
            "There is no support for lookups when using NoLookup."
        );
        vec![]
    }

    fn get_global_lookup_challenges_circuit(
        &self,
        _circuit: &mut CircuitBuilder<F>,
        global_lookups: &[GlobalLookup],
    ) -> Vec<Vec<Target>> {
        assert!(
            global_lookups.is_empty(),
            "There is no support for lookups when using NoLookup."
        );
        vec![]
    }
}

impl<F: Field, A: RecursiveAir<F>> RecursivePermutationAir<F> for AirWithoutLookup<F, A> {
    fn permutation(&self, _circuit: &mut CircuitBuilder<F>, _is_current: bool) -> Vec<Target> {
        vec![]
    }

    fn get_lookup_columns_from_all_cols(
        &self,
        _circuit: &mut CircuitBuilder<F>,
        local_lookups: &[LocalLookup],
        global_lookups: &[GlobalLookup],
        _columns: &ColumnsTargets,
    ) -> (Vec<LocalLookupColumns<'_>>, Vec<GlobalLookupColumns<'_>>) {
        // There are no lookups, so we do nothing.
        assert!(
            global_lookups.is_empty(),
            "There is no support for lookups when using an AIR without lookups."
        );
        assert!(
            local_lookups.is_empty(),
            "There is no support for lookups when using an AIR without lookups."
        );
        (vec![], vec![])
    }
}
