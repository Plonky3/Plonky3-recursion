//! Checked raw-coordinate codecs for native binary circuit fields.
//!
//! Coordinate `i` has weight `from_raw_coordinates(1 << i)`, rather than the
//! integer ring embedding of `2^i`. Each field keeps its own basis: this module
//! does not convert between tower, GHASH and polynomial representations.

use alloc::{boxed::Box, format, vec, vec::Vec};
use core::hash::Hash;

use p3_binary_field::{
    BinaryField2, BinaryField4, BinaryField8, BinaryField16, BinaryField32, BinaryField64,
    BinaryField128, Gf2, Ghash128, Poly64, TowerLevel,
};
use p3_field::Field;

use crate::ops::HintExecutor;
use crate::{CircuitBuilder, CircuitBuilderError, CircuitError, ExprId, WitnessId};

mod sealed {
    pub trait Sealed {}
}

/// A native binary field with an explicit, injective raw coordinate encoding.
///
/// Implementations are sealed to audited field representations of at most 128
/// bits. `Poly192` instead consists of three `Poly64` coefficients and is not a
/// scalar coordinate field here. Ring integer constructors are not this codec.
pub trait BinaryCoordinateField: Field + Eq + Hash + sealed::Sealed {
    const COORDINATE_BITS: usize;

    /// Rejects coordinates outside the field's width, without masking them.
    fn from_raw_coordinates(raw: u128) -> Option<Self>;

    fn to_raw_coordinates(self) -> u128;
}

macro_rules! tower_coordinates {
    ($($field:ty => $bits:literal),* $(,)?) => {$(
        impl sealed::Sealed for $field {}
        impl BinaryCoordinateField for $field {
            const COORDINATE_BITS: usize = $bits;

            fn from_raw_coordinates(raw: u128) -> Option<Self> {
                if Self::COORDINATE_BITS < 128 && raw >> Self::COORDINATE_BITS != 0 {
                    return None;
                }
                Some(Self::from_repr(raw as <Self as TowerLevel>::Repr))
            }

            fn to_raw_coordinates(self) -> u128 {
                self.to_repr() as u128
            }
        }
    )*};
}

tower_coordinates!(
    Gf2 => 1, BinaryField2 => 2, BinaryField4 => 4, BinaryField8 => 8,
    BinaryField16 => 16, BinaryField32 => 32, BinaryField64 => 64,
    BinaryField128 => 128, Ghash128 => 128,
);

impl sealed::Sealed for Poly64 {}
impl BinaryCoordinateField for Poly64 {
    const COORDINATE_BITS: usize = 64;

    fn from_raw_coordinates(raw: u128) -> Option<Self> {
        u64::try_from(raw).ok().map(Self::new)
    }

    fn to_raw_coordinates(self) -> u128 {
        self.to_bits() as u128
    }
}

impl<F: BinaryCoordinateField> CircuitBuilder<F> {
    /// Decomposes a value into low-first Boolean raw coordinates.
    ///
    /// Reconstruction binds the hint to the input. A partial decomposition
    /// constrains the value to the span of the first `n_bits` basis vectors;
    /// requesting zero bits therefore constrains it to zero. IDs must belong
    /// to this builder's graph.
    pub fn binary_decompose_coordinates(
        &mut self,
        value: ExprId,
        n_bits: usize,
    ) -> Result<Vec<ExprId>, CircuitBuilderError> {
        check_width::<F>(n_bits)?;
        // A zero-output hint has no DAG anchor and is unnecessary.
        let bits = if n_bits == 0 {
            Vec::new()
        } else {
            self.push_unconstrained_op(
                vec![vec![value]],
                n_bits,
                CoordinateDecompositionHint,
                "binary_decompose_coordinates",
            )
            .2
            .into_iter()
            .collect::<Option<Vec<_>>>()
            .ok_or(CircuitBuilderError::MissingOutput)?
        };
        let reconstructed = self.binary_recompose_coordinates(&bits)?;
        self.connect(value, reconstructed);
        Ok(bits)
    }

    /// Reconstructs low-first coordinates and constrains every input Boolean.
    ///
    /// An empty slice represents zero. Oversized slices are rejected before
    /// any expressions or constraints are added.
    pub fn binary_recompose_coordinates(
        &mut self,
        bits: &[ExprId],
    ) -> Result<ExprId, CircuitBuilderError> {
        check_width::<F>(bits.len())?;
        let mut sum = ExprId::ZERO;
        for (i, &bit) in bits.iter().enumerate() {
            self.assert_bool(bit);
            let weight = self
                .define_const(F::from_raw_coordinates(1 << i).expect("validated coordinate width"));
            sum = self.mul_add(bit, weight, sum);
        }
        Ok(sum)
    }
}

fn check_width<F: BinaryCoordinateField>(n_bits: usize) -> Result<(), CircuitBuilderError> {
    if n_bits > F::COORDINATE_BITS {
        Err(CircuitBuilderError::BinaryDecompositionTooManyBits {
            expected: F::COORDINATE_BITS,
            n_bits,
        })
    } else {
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct CoordinateDecompositionHint;

impl<F: BinaryCoordinateField> HintExecutor<F> for CoordinateDecompositionHint {
    fn execute(
        &self,
        inputs: &[WitnessId],
        outputs: &[WitnessId],
        witness: &mut [Option<F>],
    ) -> Result<(), CircuitError> {
        if inputs.len() != 1 {
            return Err(CircuitError::UnconstrainedOpInputLengthMismatch {
                op: "CoordinateDecompositionHint".into(),
                expected: 1,
                got: inputs.len(),
            });
        }
        if outputs.len() > F::COORDINATE_BITS {
            return Err(CircuitError::BinaryDecompositionTooManyBits {
                expected: F::COORDINATE_BITS,
                n_bits: outputs.len(),
            });
        }
        let input = inputs[0];
        let value = witness
            .get(input.0 as usize)
            .ok_or(CircuitError::WitnessIdOutOfBounds { witness_id: input })?
            .ok_or(CircuitError::WitnessNotSet { witness_id: input })?
            .to_raw_coordinates();
        for (i, &output) in outputs.iter().enumerate() {
            let bit = F::from_bool(value >> i & 1 != 0);
            let slot = witness
                .get_mut(output.0 as usize)
                .ok_or(CircuitError::WitnessIdOutOfBounds { witness_id: output })?;
            if let Some(existing) = slot {
                if *existing != bit {
                    return Err(CircuitError::WitnessConflict {
                        witness_id: output,
                        existing: format!("{existing:?}"),
                        new: format!("{bit:?}"),
                        expr_ids: vec![],
                    });
                }
            } else {
                *slot = Some(bit);
            }
        }
        Ok(())
    }

    fn boxed(&self) -> Box<dyn HintExecutor<F>> {
        Box::new(self.clone())
    }
}
