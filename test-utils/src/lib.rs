//! Test utilities for Plonky3 recursion crates.

#![no_std]

/// Maximum allowed constraint degree for AIR constraints.
/// Keeping this at 3 ensures efficient FRI proving.
pub const MAX_CONSTRAINT_DEGREE: usize = 3;

pub use p3_air;
pub use p3_baby_bear;
pub use p3_batch_stark;
pub use p3_field;
pub use p3_lookup;
pub use p3_matrix;
pub use p3_uni_stark;

/// Macro to generate a constraint degree test for an AIR.
///
/// Usage: `assert_air_constraint_degree!(air, "AirName");`
#[macro_export]
macro_rules! assert_air_constraint_degree {
    ($air:expr, $air_name:expr) => {{
        use $crate::p3_air::{AirLayout, BaseAir};
        use $crate::p3_batch_stark::symbolic::get_symbolic_constraints;
        use $crate::p3_lookup::LookupAir;
        use $crate::p3_lookup::logup::LogUpGadget;

        type F = $crate::p3_baby_bear::BabyBear;
        type EF = $crate::p3_field::extension::BinomialExtensionField<F, 4>;
        let mut air = $air;

        let preprocessed_width = air.preprocessed_trace().map(|m| m.width()).unwrap_or(0);
        let lookups = LookupAir::get_lookups(&mut air);
        let lookup_gadget = LogUpGadget::new();
        let layout = AirLayout {
            preprocessed_width,
            main_width: BaseAir::<F>::width(&air),
            num_public_values: BaseAir::<F>::num_public_values(&air),
            permutation_width: 0,
            num_permutation_challenges: 0,
            num_permutation_values: 0,
            num_periodic_columns: 0,
        };

        let (base_constraints, extension_constraints) =
            get_symbolic_constraints::<F, EF, _, _>(&air, layout, &lookups, &lookup_gadget);

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
