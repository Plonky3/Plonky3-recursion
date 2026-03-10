//! Traits for recursive MMCS operations.

use alloc::vec::Vec;

use p3_commit::Mmcs;
use p3_field::{ExtensionField, Field};

use super::Recursive;

/// Trait for the recursive version of an MMCS operating over the base field.
///
/// Associates a non-recursive MMCS with its recursive commitment and proof types.
/// This is used for commitments to trace polynomials (which are over the base field).
pub trait RecursiveMmcs<F: Field, EF: ExtensionField<F>> {
    /// The non-recursive MMCS type this corresponds to.
    type Input: Mmcs<F>;

    /// The recursive commitment type (targets representing the commitment).
    ///
    /// Must implement `Recursive` with `Input` being the commitment type from `Self::Input`.
    type Commitment: Recursive<EF, Input = <Self::Input as Mmcs<F>>::Commitment>;

    /// The recursive proof type (targets representing the opening proof).
    ///
    /// Must implement `Recursive` with `Input` being the proof type from `Self::Input`.
    type Proof: Recursive<EF, Input = <Self::Input as Mmcs<F>>::Proof>;

    fn extract_sibling_values_from_proof(_proof: &<Self::Input as Mmcs<F>>::Proof) -> Vec<EF> {
        Vec::new()
    }
}

/// Trait for the recursive version of an MMCS operating over the extension field.
///
/// Associates a non-recursive MMCS with its recursive commitment and proof types.
/// This is used for commitments to quotient polynomials and FRI layers
/// (which are over the extension field).
pub trait RecursiveExtensionMmcs<F: Field, EF: ExtensionField<F>> {
    /// The non-recursive MMCS type this corresponds to.
    type Input: Mmcs<EF>;

    /// The recursive commitment type (targets representing the commitment).
    ///
    /// Must implement `Recursive` with `Input` being the commitment type from `Self::Input`.
    type Commitment: Recursive<EF, Input = <Self::Input as Mmcs<EF>>::Commitment>;

    /// The recursive proof type (targets representing the opening proof).
    ///
    /// Must implement `Recursive` with `Input` being the proof type from `Self::Input`.
    type Proof: Recursive<EF, Input = <Self::Input as Mmcs<EF>>::Proof>;

    /// Extract 4-ary sibling values from a Merkle proof for use as public inputs.
    fn extract_sibling_values_from_proof(_proof: &<Self::Input as Mmcs<EF>>::Proof) -> Vec<EF> {
        Vec::new()
    }
}
