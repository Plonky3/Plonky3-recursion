//! Scalar arithmetic in the exact native 128-bit Wiedemann tower carrier.
//!
//! A scalar remains one circuit expression through arithmetic. Bits are
//! materialized, constrained and reconstructed only at serialization boundaries.
//! GHASH and polynomial carriers must not use this field's multiplication.

use alloc::vec::Vec;

use p3_binary_field::{BinaryField128, TowerLevel};

use crate::{CircuitBuilder, CircuitBuilderError, ExprId};

/// A native Tower128 scalar belonging to one builder's expression graph.
///
/// Every native carrier value is a valid scalar. Unlike `BinaryTower128Target`,
/// this type does not store bits; extracting them needs a checked builder call.
/// Expression IDs themselves do not carry a graph identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NativeTower128Target {
    value: ExprId,
}

impl NativeTower128Target {
    pub const fn as_expr(&self) -> ExprId {
        self.value
    }
}

impl CircuitBuilder<BinaryField128> {
    pub const fn native_tower128_from_expr(&self, value: ExprId) -> NativeTower128Target {
        NativeTower128Target { value }
    }

    /// Uses raw Wiedemann coordinates, not the ring's integer embedding.
    pub fn native_tower128_constant(&mut self, raw: u128) -> NativeTower128Target {
        let value = self.define_const(BinaryField128::from_repr(raw));
        NativeTower128Target { value }
    }

    pub fn native_tower128_add(
        &mut self,
        a: &NativeTower128Target,
        b: &NativeTower128Target,
    ) -> NativeTower128Target {
        let value = self.add(a.value, b.value);
        NativeTower128Target { value }
    }

    pub fn native_tower128_mul(
        &mut self,
        a: &NativeTower128Target,
        b: &NativeTower128Target,
    ) -> NativeTower128Target {
        let value = self.mul(a.value, b.value);
        NativeTower128Target { value }
    }

    pub fn native_tower128_square(&mut self, a: &NativeTower128Target) -> NativeTower128Target {
        self.native_tower128_mul(a, a)
    }

    pub fn assert_native_tower128_inverse(
        &mut self,
        value: &NativeTower128Target,
        candidate: &NativeTower128Target,
    ) {
        let product = self.mul(value.value, candidate.value);
        let one = self.define_const(BinaryField128::from_repr(1));
        self.connect(product, one);
    }

    pub fn native_tower128_from_bits(
        &mut self,
        bits: [ExprId; 128],
    ) -> Result<NativeTower128Target, CircuitBuilderError> {
        let value = self.binary_recompose_coordinates(&bits)?;
        Ok(NativeTower128Target { value })
    }

    pub fn native_tower128_to_bits(
        &mut self,
        value: &NativeTower128Target,
    ) -> Result<[ExprId; 128], CircuitBuilderError> {
        Ok(self
            .binary_decompose_coordinates(value.value, 128)?
            .try_into()
            .expect("full native tower decomposition has 128 bits"))
    }

    /// Each word is a checked low-first raw sixteen-coordinate span.
    pub fn native_tower128_from_words(
        &mut self,
        words: [ExprId; 8],
    ) -> Result<NativeTower128Target, CircuitBuilderError> {
        let mut bits = Vec::with_capacity(128);
        for word in words {
            bits.extend(self.binary_decompose_coordinates(word, 16)?);
        }
        self.native_tower128_from_bits(bits.try_into().expect("eight words have 128 bits"))
    }

    pub fn native_tower128_to_words(
        &mut self,
        value: &NativeTower128Target,
    ) -> Result<[ExprId; 8], CircuitBuilderError> {
        let bits = self.native_tower128_to_bits(value)?;
        let words = bits
            .as_chunks::<16>()
            .0
            .iter()
            .map(|word| self.binary_recompose_coordinates(word))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(words.try_into().expect("128 bits have eight words"))
    }
}
