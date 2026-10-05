//! Explicit byte/limb encodings for binary protocols in different circuit fields.
//!
//! A protocol word always has the same low-first bits. Prime carriers embed its
//! integer value; native binary carriers use their own raw coordinate basis.

use alloc::vec::Vec;
use core::hash::Hash;
use core::marker::PhantomData;

use p3_field::{ExtensionField, Field, PrimeField64};

use super::binary_native::BinaryCoordinateField;
use crate::{CircuitBuilder, CircuitBuilderError, ExprId};

mod sealed {
    pub trait Sealed {}
}

/// A checked encoding for the binary protocol's words of at most sixteen bits.
///
/// Implementations are sealed: changing this encoding changes the verifier
/// relation, not the protocol's serialization. Every expression must belong to
/// the supplied builder. Invalid widths and carriers fail before mutation.
pub trait BinaryCircuitEncoding<F: Field + Eq + Hash>: sealed::Sealed {
    fn check_carrier() -> Result<(), CircuitBuilderError>;

    fn encode_u16(word: u16) -> Result<F, CircuitBuilderError>;

    fn decompose_word(
        builder: &mut CircuitBuilder<F>,
        value: ExprId,
        n_bits: usize,
    ) -> Result<Vec<ExprId>, CircuitBuilderError>;

    fn recompose_word(
        builder: &mut CircuitBuilder<F>,
        bits: &[ExprId],
    ) -> Result<ExprId, CircuitBuilderError>;
}

/// Raw basis coordinates in an audited native binary carrier.
#[derive(Clone, Copy, Debug)]
pub struct NativeBinaryEncoding;

impl sealed::Sealed for NativeBinaryEncoding {}

impl<F: BinaryCoordinateField> BinaryCircuitEncoding<F> for NativeBinaryEncoding {
    fn check_carrier() -> Result<(), CircuitBuilderError> {
        if F::COORDINATE_BITS < 16 {
            return Err(CircuitBuilderError::BinaryDecompositionTooManyBits {
                expected: F::COORDINATE_BITS,
                n_bits: 16,
            });
        }
        Ok(())
    }

    fn encode_u16(word: u16) -> Result<F, CircuitBuilderError> {
        <Self as BinaryCircuitEncoding<F>>::check_carrier()?;
        Ok(F::from_raw_coordinates(word as u128).expect("validated native word width"))
    }

    fn decompose_word(
        builder: &mut CircuitBuilder<F>,
        value: ExprId,
        n_bits: usize,
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
        check_width(n_bits)?;
        <Self as BinaryCircuitEncoding<F>>::check_carrier()?;
        builder.binary_decompose_coordinates(value, n_bits)
    }

    fn recompose_word(
        builder: &mut CircuitBuilder<F>,
        bits: &[ExprId],
    ) -> Result<ExprId, CircuitBuilderError> {
        check_width(bits.len())?;
        <Self as BinaryCircuitEncoding<F>>::check_carrier()?;
        builder.binary_recompose_coordinates(bits)
    }
}

/// Integer words in a prime base field, also usable in its extension carrier.
#[derive(Clone, Copy, Debug)]
pub struct PrimeBinaryEncoding<BF>(PhantomData<BF>);

impl<BF> sealed::Sealed for PrimeBinaryEncoding<BF> {}

impl<BF, F> BinaryCircuitEncoding<F> for PrimeBinaryEncoding<BF>
where
    BF: PrimeField64,
    F: ExtensionField<BF> + Eq + Hash,
{
    fn check_carrier() -> Result<(), CircuitBuilderError> {
        if F::TWO == F::ZERO {
            return Err(CircuitBuilderError::CharacteristicTwoUnsupported {
                operation: "prime_binary_encoding",
            });
        }
        if BF::ORDER_U64 <= u64::from(u16::MAX) {
            return Err(CircuitBuilderError::BinaryDecompositionTooManyBits {
                expected: BF::ORDER_U64.ilog2() as usize,
                n_bits: 16,
            });
        }
        Ok(())
    }

    fn encode_u16(word: u16) -> Result<F, CircuitBuilderError> {
        <Self as BinaryCircuitEncoding<F>>::check_carrier()?;
        Ok(F::from_u16(word))
    }

    fn decompose_word(
        builder: &mut CircuitBuilder<F>,
        value: ExprId,
        n_bits: usize,
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
        check_width(n_bits)?;
        <Self as BinaryCircuitEncoding<F>>::check_carrier()?;
        if n_bits == 0 {
            builder.connect(value, ExprId::ZERO);
            return Ok(Vec::new());
        }
        builder.decompose_to_bits::<BF>(value, n_bits)
    }

    fn recompose_word(
        builder: &mut CircuitBuilder<F>,
        bits: &[ExprId],
    ) -> Result<ExprId, CircuitBuilderError> {
        check_width(bits.len())?;
        <Self as BinaryCircuitEncoding<F>>::check_carrier()?;
        builder.reconstruct_index_from_bits::<BF>(bits)
    }
}

fn check_width(n_bits: usize) -> Result<(), CircuitBuilderError> {
    if n_bits > 16 {
        Err(CircuitBuilderError::BinaryDecompositionTooManyBits {
            expected: 16,
            n_bits,
        })
    } else {
        Ok(())
    }
}
