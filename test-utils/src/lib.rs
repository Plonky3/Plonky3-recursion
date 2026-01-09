//! Test utilities for Plonky3 recursion crates.

/// Maximum allowed constraint degree for AIR constraints.
/// Keeping this at 3 ensures efficient FRI proving.
pub const MAX_CONSTRAINT_DEGREE: usize = 3;

/// Macro to generate a constraint degree test for an AIR.
///
/// Usage: `assert_air_constraint_degree!(air, "AirName");`
#[macro_export]
macro_rules! assert_air_constraint_degree {
    ($air:expr, $air_name:expr) => {{
        use p3_air::BaseAir;
        use p3_batch_stark::symbolic::{get_symbolic_constraints, lookup_data_to_expr};
        use p3_field::PrimeCharacteristicRing;
        use p3_lookup::logup::LogUpGadget;
        use p3_lookup::lookup_traits::{AirLookupHandler, Kind, LookupData};
        use p3_matrix::Matrix;
        use p3_uni_stark::SymbolicAirBuilder;

        type F = p3_baby_bear::BabyBear;
        let mut air = $air;

        let preprocessed_width = air.preprocessed_trace().map(|m| m.width()).unwrap_or(0);

        let lookups = <_ as AirLookupHandler<SymbolicAirBuilder<F, F>>>::get_lookups(&mut air);
        let lookup_data = lookups
            .iter()
            .filter_map(|lookup| match &lookup.kind {
                Kind::Global(name) => Some(LookupData {
                    name: name.clone(),
                    aux_idx: lookup.columns[0],
                    expected_cumulated: F::ZERO,
                }),
                _ => None,
            })
            .collect::<Vec<_>>();
        let lookup_data = lookup_data_to_expr(&lookup_data);

        let lookup_gadget = LogUpGadget::new();
        let (base_constraints, extension_constraints) = get_symbolic_constraints(
            &air,
            preprocessed_width,
            0,
            &lookups,
            &lookup_data,
            &lookup_gadget,
        );

        for (i, constraint) in base_constraints.iter().enumerate() {
            let degree = constraint.degree_multiple();
            assert!(
                degree <= $crate::MAX_CONSTRAINT_DEGREE,
                "{} base constraint {} has degree {} which exceeds maximum of {}",
                $air_name,
                i,
                degree,
                $crate::MAX_CONSTRAINT_DEGREE
            );
        }

        for (i, constraint) in extension_constraints.iter().enumerate() {
            let degree = constraint.degree_multiple();
            assert!(
                degree <= $crate::MAX_CONSTRAINT_DEGREE,
                "{} extension constraint {} has degree {} which exceeds maximum of {}",
                $air_name,
                i,
                degree,
                $crate::MAX_CONSTRAINT_DEGREE
            );
        }
    }};
}
