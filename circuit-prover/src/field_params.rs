//! Utilities for extracting extension field parameters.
//!
//! Provides traits to dynamically determine binomial extension parameters
//! from field types at runtime, supporting both base fields and extension fields.

use p3_field::Field;
use p3_field::extension::{BinomialExtensionField, BinomiallyExtendable};

/// Extract binomial parameters from field types.
///
/// Enables runtime detection of extension field parameters without
/// requiring compile-time knowledge of the field structure.
pub trait ExtractWParameter<F: Field> {
    /// Extract the binomial parameter W for degree-4 extensions (x^4 = W).
    /// Returns None for base fields, Some(W) for extension fields.
    fn extract_w_d4() -> Option<F>;
}

/// Base fields have no extension parameter.
impl<F> ExtractWParameter<F> for F
where
    F: Field,
{
    fn extract_w_d4() -> Option<F> {
        None
    }
}

/// Degree-4 extension fields provide their binomial parameter W.
impl<F> ExtractWParameter<F> for BinomialExtensionField<F, 4>
where
    F: Field + BinomiallyExtendable<4>,
{
    fn extract_w_d4() -> Option<F> {
        Some(F::W)
    }
}
