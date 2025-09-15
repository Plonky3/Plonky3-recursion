//! Utilities for extracting extension field parameters.
//!
//! Glossary:
//! - `F`: Base field (BabyBear/KoalaBear/Goldilocks) that extension fields are built over.
//! - `EF`: Element field for circuit traces. If `EF = F`, there is no binomial parameter. If
//!   `EF = BinomialExtensionField<F, D>`, then there is a binomial parameter `W` with `x^D = W`.
//! - `D`: Element-field extension degree.
//!
//! Provides traits to dynamically determine binomial extension parameters
//! from field types at runtime, supporting both base fields and extension fields.

use p3_field::Field;
use p3_field::extension::{BinomialExtensionField, BinomiallyExtendable};

/// Extract binomial parameters from field types.
///
/// Enables runtime detection of extension field parameters without
/// requiring compile-time knowledge of the field structure.
pub trait ExtractBinomialW<F: Field> {
    /// Extract the binomial parameter W for the current extension degree (e.g., x^D = W).
    /// Returns None for base fields, Some(W) for supported binomial extensions.
    fn extract_w() -> Option<F>;
}

/// Base fields have no extension parameter.
impl<F> ExtractBinomialW<F> for F
where
    F: Field,
{
    fn extract_w() -> Option<F> {
        None
    }
}

/// Binomial extension fields (for any supported degree D) provide their parameter W.
impl<F, const D: usize> ExtractBinomialW<F> for BinomialExtensionField<F, D>
where
    F: Field + BinomiallyExtendable<D>,
{
    fn extract_w() -> Option<F> {
        Some(F::W)
    }
}
