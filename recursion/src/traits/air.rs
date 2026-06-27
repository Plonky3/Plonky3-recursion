//! Trait for recursive AIR constraint evaluation.

use alloc::vec::Vec;

use hashbrown::HashMap;
use p3_air::symbolic::AirLayout;
use p3_air::{Air, SymbolicExpressionExt};
use p3_batch_stark::symbolic::{get_log_num_quotient_chunks, get_symbolic_constraints};
use p3_circuit::CircuitBuilder;
use p3_circuit::symbolic::{ColumnsTargets, SymbolicCompiler};
use p3_field::{Algebra, ExtensionField, Field};
use p3_lookup::symbolic::InteractionSymbolicBuilder;
use p3_lookup::{Lookup, LookupProtocol};
use p3_uni_stark::SymbolicExpression;

use crate::Target;
use crate::types::RecursiveLagrangeSelectors;

/// Structure holding lookup verification data:
///
/// - `contexts`: Slice of lookup contexts used in the AIR.
pub struct LookupMetadata<'a, F: Field> {
    pub contexts: &'a [Lookup<F>],
}
/// Trait for evaluating AIR constraints within a recursive verification circuit.
///
/// This trait provides methods for computing constraint evaluations over circuit targets
/// rather than concrete field values.
pub trait RecursiveAir<F: Field, EF: ExtensionField<F>, LG: LookupProtocol> {
    /// Returns the number of columns in the AIR's execution trace.
    ///
    /// This corresponds to the width of the trace matrix.
    fn width(&self) -> usize;

    /// Returns the number of periodic columns the AIR declares.
    fn num_periodic_columns(&self) -> usize;

    /// Returns the AIR's periodic column tables.
    ///
    /// Each entry is the length-`period` evaluation vector of one periodic
    /// column. Periodic columns are verifier-recomputable AIR constants and are
    /// never committed; the verifier evaluates them at the opening point.
    fn periodic_columns(&self) -> Vec<Vec<F>>;

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
    /// - `contexts`: Lookup contexts used in the AIR
    /// - `lookup_data`: Data for global lookups
    /// - `columns`: Trace columns (local, next) and public values
    /// - `lookup_gadget`: Gadget for handling lookups in the circuit
    ///
    /// # Returns
    /// A single target representing the folded constraint evaluation
    fn eval_folded_circuit(
        &self,
        builder: &mut CircuitBuilder<EF>,
        sels: &RecursiveLagrangeSelectors,
        alpha: &Target,
        lookup_metadata: &LookupMetadata<'_, F>,
        columns: ColumnsTargets<'_>,
        lookup_gadget: &LG,
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
    /// Log₂ of the number of quotient chunks
    fn get_log_num_quotient_chunks(
        &self,
        preprocessed_width: usize,
        contexts: &[Lookup<F>],
        is_zk: usize,
        lookup_gadget: &LG,
    ) -> usize;

    /// Returns `true` if the AIR declares any lookup interactions (global or local).
    ///
    /// The recursive single-STARK verifier evaluates the AIR with empty lookup
    /// contexts and therefore does not enforce any lookup argument. An AIR that
    /// declares interactions must be rejected rather than silently verified with
    /// its lookups unenforced.
    fn declares_interactions(&self, preprocessed_width: usize) -> bool;

    /// Returns `true` if the AIR's constraints access the next trace row, so the
    /// trace must be opened at `zeta * g` in addition to `zeta`.
    ///
    /// This mirrors the native prover/verifier gating on
    /// [`p3_air::BaseAir::main_next_row_columns`]: AIRs with no inter-row constraints
    /// (e.g. constant, public, and recompose tables) omit the `trace_next` opening.
    fn opens_trace_next(&self) -> bool;
}

impl<F: Field, EF: ExtensionField<F>, A, LG: LookupProtocol> RecursiveAir<F, EF, LG> for A
where
    A: Air<InteractionSymbolicBuilder<F, EF>>,
    SymbolicExpressionExt<F, EF>: Algebra<SymbolicExpression<F>> + Algebra<EF>,
{
    fn width(&self) -> usize {
        Self::width(self)
    }

    fn num_periodic_columns(&self) -> usize {
        p3_air::BaseAir::<F>::num_periodic_columns(self)
    }

    fn periodic_columns(&self) -> Vec<Vec<F>> {
        p3_air::BaseAir::<F>::periodic_columns(self)
    }

    fn eval_folded_circuit(
        &self,
        builder: &mut CircuitBuilder<EF>,
        sels: &RecursiveLagrangeSelectors,
        alpha: &Target,
        lookup_metadata: &LookupMetadata<'_, F>,
        columns: ColumnsTargets<'_>,
        lookup_gadget: &LG,
    ) -> Target {
        builder.push_scope("eval_folded_circuit");

        let LookupMetadata { contexts } = lookup_metadata;

        let num_preprocessed = columns.local_prep_values.len();
        debug_assert_eq!(
            columns.periodic_values.len(),
            p3_air::BaseAir::<F>::num_periodic_columns(self),
            "periodic_values targets must match the AIR's declared periodic column count"
        );
        // Single-terminal layout: one permutation value (the AIR terminal) when it declares any
        // lookup, none otherwise. `get_symbolic_constraints` recomputes this from `contexts`.
        let num_permutation_values = usize::from(!contexts.is_empty());
        let layout = AirLayout {
            preprocessed_width: num_preprocessed,
            main_width: self.width(),
            num_public_values: self.num_public_values(),
            num_periodic_columns: p3_air::BaseAir::<F>::num_periodic_columns(self),
            num_permutation_values,
            ..Default::default()
        };
        let (base_symbolic_constraints, extension_symbolic_constraints) =
            get_symbolic_constraints(self, layout, contexts, lookup_gadget);

        // Fold all constraints: result = c₀ + α·c₁ + α²·c₂ + ...
        //
        // Converting directly the tree SymbolicExpression<F> → SymbolicExpression<EF>
        // destroys Arc-based sub-expression sharing and causes exponential blowup.
        // Instead, we lift F → EF constants directly.
        //
        // Additionally, the cache is shared across all constraint calls to reuse circuit
        // operations for sub-expressions shared between different constraints.
        let compiler = SymbolicCompiler::new(sels.row_selectors, &columns);
        let mut acc = builder.define_const(EF::ZERO);
        let mut base_cache = HashMap::new();
        for s_c in &base_symbolic_constraints {
            let constraints = compiler.compile_base(s_c, builder, &mut base_cache);
            acc = builder.mul_add(acc, *alpha, constraints);
        }

        let mut ext_cache = HashMap::new();
        for s_c in &extension_symbolic_constraints {
            let constraints = compiler.compile_ext(s_c, builder, &mut base_cache, &mut ext_cache);
            acc = builder.mul_add(acc, *alpha, constraints);
        }

        builder.pop_scope();
        acc
    }

    fn get_log_num_quotient_chunks(
        &self,
        preprocessed_width: usize,
        contexts: &[Lookup<F>],
        is_zk: usize,
        lookup_gadget: &LG,
    ) -> usize
    where
        F: Field,
        EF: ExtensionField<F>,
        SymbolicExpressionExt<F, EF>: Algebra<SymbolicExpression<F>>,
        LG: LookupProtocol,
    {
        let layout = AirLayout {
            preprocessed_width,
            main_width: self.width(),
            num_public_values: self.num_public_values(),
            num_periodic_columns: p3_air::BaseAir::<F>::num_periodic_columns(self),
            ..Default::default()
        };
        get_log_num_quotient_chunks(self, layout, contexts, is_zk, lookup_gadget)
    }

    fn declares_interactions(&self, preprocessed_width: usize) -> bool {
        let layout = AirLayout {
            preprocessed_width,
            main_width: self.width(),
            num_public_values: self.num_public_values(),
            ..Default::default()
        };
        let mut builder = InteractionSymbolicBuilder::<F, EF>::new(layout);
        self.eval(&mut builder);
        !builder.global_interactions().is_empty() || !builder.local_interactions().is_empty()
    }

    fn opens_trace_next(&self) -> bool {
        !p3_air::BaseAir::<F>::main_next_row_columns(self).is_empty()
    }
}

#[cfg(test)]
mod tests {
    use p3_air::{AirBuilder, BaseAir};
    use p3_baby_bear::BabyBear;
    use p3_field::PrimeCharacteristicRing;
    use p3_field::extension::BinomialExtensionField;
    use p3_lookup::logup::LogUpGadget;
    use p3_lookup::{Count, InteractionBuilder};

    use super::*;

    type F = BabyBear;
    type EF = BinomialExtensionField<BabyBear, 4>;
    type Builder = InteractionSymbolicBuilder<F, EF>;

    /// An AIR that emits no bus interactions.
    struct PlainAir;
    /// An AIR that emits one global bus interaction.
    struct BusAir;

    impl<T> BaseAir<T> for PlainAir {
        fn width(&self) -> usize {
            1
        }
    }

    impl<AB: AirBuilder> Air<AB> for PlainAir {
        fn eval(&self, _builder: &mut AB) {}
    }

    impl<T> BaseAir<T> for BusAir {
        fn width(&self) -> usize {
            1
        }
    }

    impl Air<Builder> for BusAir {
        fn eval(&self, builder: &mut Builder) {
            builder.push_interaction(
                "test_bus",
                core::iter::once(<Builder as AirBuilder>::Expr::ONE),
                Count::bounded(<Builder as AirBuilder>::Expr::ONE, 1),
            );
        }
    }

    #[test]
    fn plain_air_declares_no_interactions() {
        assert!(!RecursiveAir::<F, EF, LogUpGadget>::declares_interactions(
            &PlainAir, 0
        ));
    }

    #[test]
    fn interaction_air_is_detected() {
        assert!(RecursiveAir::<F, EF, LogUpGadget>::declares_interactions(
            &BusAir, 0
        ));
    }
}
